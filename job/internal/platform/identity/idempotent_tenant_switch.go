package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
	platformdb "github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/idempotency"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/audit"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/outbox"
)

const TenantSwitchOperation = "tenant.switch.v1"

var (
	ErrInvalidTenantSwitchCoordinatorConfig = errors.New("invalid tenant switch coordinator configuration")
	ErrInvalidTenantSwitchRequest           = errors.New("invalid tenant switch request")
	ErrInvalidTenantSwitchScope             = errors.New("invalid tenant switch scope")
	ErrInvalidTenantSwitchOutcome           = errors.New("invalid tenant switch outcome")
	ErrInvalidTenantSwitchPair              = errors.New("invalid tenant switch idempotency pair")
	ErrTenantSwitchScopeConflict            = errors.New("tenant switch idempotency scope conflict")
	ErrTenantSwitchInProgress               = errors.New("tenant switch idempotency operation in progress")
	ErrTenantSwitchStale                    = errors.New("tenant switch idempotency scope is stale")
	ErrUncertainTenantSwitchCommit          = errors.New("tenant switch commit outcome is uncertain; reauthentication required")
)

type TenantSwitchRequest struct {
	PresentedSessionToken string
	TargetTenantID        pgtype.UUID
	IdempotencyKey        string
	CorrelationID         pgtype.UUID
}

// TenantSwitchOutcome retains the compact mutation marker used by callers that
// only need the historical tenant/workspace and generation. The idempotency
// receipt itself stores the complete SessionContext projection below.
type TenantSwitchOutcome struct {
	ActiveTenantID    string    `json:"active_tenant_id"`
	ActiveWorkspaceID string    `json:"active_workspace_id"`
	SessionGeneration int64     `json:"session_generation"`
	SessionExpiresAt  time.Time `json:"session_expires_at"`
}

type TenantSwitchResult struct {
	Outcome           TenantSwitchOutcome
	ResponseBody      []byte
	ResponseStatus    int
	CorrelationID     pgtype.UUID
	Replay            bool
	ETag              string
	ActiveTenantID    pgtype.UUID
	ActiveWorkspaceID pgtype.UUID
	Generation        int64
	SessionExpiresAt  time.Time
	SessionToken      string
	CSRFToken         string
}

// tenantSwitchUnit is the complete set of transaction-bound operations used
// by the coordinator. All projection, receipt, audit, and outbox writes share
// the same unscoped transaction as the session mutation.
type tenantSwitchUnit interface {
	CreateSession(context.Context, sqlcgen.CreateSessionParams) (pgtype.UUID, error)
	GetActiveSession(context.Context, []byte) (sqlcgen.GetActiveSessionRow, error)
	RevokeSession(context.Context, []byte) error
	RotateSession(context.Context, sqlcgen.RotateSessionParams) (sqlcgen.RotateSessionRow, error)
	SwitchSessionContext(context.Context, sqlcgen.SwitchSessionContextParams) (sqlcgen.SwitchSessionContextRow, error)
	BindTenantSwitchIdempotency(context.Context, sqlcgen.BindTenantSwitchIdempotencyParams) (sqlcgen.BindTenantSwitchIdempotencyRow, error)
	FinishTenantSwitchIdempotency(context.Context, sqlcgen.FinishTenantSwitchIdempotencyParams) (sqlcgen.FinishTenantSwitchIdempotencyRow, error)
	ClaimIdempotencyKey(context.Context, sqlcgen.ClaimIdempotencyKeyParams) (sqlcgen.ClaimIdempotencyKeyRow, error)
	CompleteIdempotencyKey(context.Context, sqlcgen.CompleteIdempotencyKeyParams) (bool, error)
	GetSessionIdentity(context.Context, []byte) (sqlcgen.GetSessionIdentityRow, error)
	ListSessionTenants(context.Context, []byte) ([]sqlcgen.ListSessionTenantsRow, error)
	GetTenant(context.Context, pgtype.UUID) (sqlcgen.IamTenant, error)
	GetWorkspace(context.Context, sqlcgen.GetWorkspaceParams) (sqlcgen.IamWorkspace, error)
	GetActivePolicySnapshot(context.Context, pgtype.UUID) (sqlcgen.GetActivePolicySnapshotRow, error)
	SetTenantSwitchResponseETag(context.Context, sqlcgen.SetTenantSwitchResponseETagParams) (bool, error)
	GetTenantSwitchResponseETag(context.Context, sqlcgen.GetTenantSwitchResponseETagParams) (pgtype.Text, error)
	InsertAuditEvent(context.Context, sqlcgen.InsertAuditEventParams) error
	EnqueueOutboxEvent(context.Context, sqlcgen.EnqueueOutboxEventParams) error
}

type tenantSwitchTransactionRunner func(context.Context, func(context.Context, tenantSwitchUnit) error) error

type TenantSwitchCoordinator struct {
	run tenantSwitchTransactionRunner
}

// NewTenantSwitchCoordinator binds the coordinator to the fail-closed
// unscoped transaction boundary. No tenant-scoped query is available until
// the database binder has authorized the requested target.
func NewTenantSwitchCoordinator(scope *platformdb.Transactor) (*TenantSwitchCoordinator, error) {
	if scope == nil {
		return nil, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return newTenantSwitchCoordinator(func(ctx context.Context, fn func(context.Context, tenantSwitchUnit) error) error {
		return scope.WithinUnscoped(ctx, func(txCtx context.Context, queries *sqlcgen.Queries) error {
			return fn(txCtx, sqlTenantSwitchUnit{queries: queries})
		})
	})
}

func newTenantSwitchCoordinator(run tenantSwitchTransactionRunner) (*TenantSwitchCoordinator, error) {
	if run == nil {
		return nil, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return &TenantSwitchCoordinator{run: run}, nil
}

// Switch performs binding, idempotency claim, session mutation, projection,
// audit/outbox publication, completion, and scope finish in one transaction.
// Replacement secrets are copied into the returned result only after the
// runner reports a successful commit.
func (c *TenantSwitchCoordinator) Switch(ctx context.Context, request TenantSwitchRequest) (TenantSwitchResult, error) {
	if c == nil || c.run == nil {
		return TenantSwitchResult{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	if ctx == nil {
		return TenantSwitchResult{}, ErrInvalidTenantSwitchRequest
	}
	if err := validateTenantSwitchRequest(request); err != nil {
		return TenantSwitchResult{}, err
	}

	requestHash := tenantSwitchRequestHash(request.TargetTenantID)
	var pending TenantSwitchResult
	err := c.run(ctx, func(txCtx context.Context, unit tenantSwitchUnit) error {
		if txCtx == nil || isNilTenantSwitchUnit(unit) {
			return ErrInvalidTenantSwitchCoordinatorConfig
		}

		presentedHash := HashToken(request.PresentedSessionToken)
		bind, err := unit.BindTenantSwitchIdempotency(txCtx, sqlcgen.BindTenantSwitchIdempotencyParams{
			CurrentSessionTokenHash: presentedHash[:],
			IdempotencyKey:          request.IdempotencyKey,
			RequestHash:             requestHash,
			TargetTenantID:          request.TargetTenantID,
		})
		if err != nil {
			return fmt.Errorf("bind tenant-switch idempotency scope: %w", err)
		}
		if err := validateTenantSwitchBindRow(bind, request.TargetTenantID, requestHash); err != nil {
			return err
		}

		switch bind.MappingState {
		case "claimed":
			return c.claimAndSwitch(txCtx, unit, request, requestHash, bind, &pending)
		case "replay":
			return c.replay(txCtx, unit, request, requestHash, bind, &pending)
		case "conflict":
			return ErrTenantSwitchScopeConflict
		case "in_progress":
			return ErrTenantSwitchInProgress
		case "stale":
			return ErrTenantSwitchStale
		default:
			return ErrInvalidTenantSwitchScope
		}
	})
	if err != nil {
		// A failed commit may have committed remotely. Never publish generated
		// browser secrets in that ambiguous state; reauthentication is required.
		if errors.Is(err, platformdb.ErrTransactionCommit) {
			return TenantSwitchResult{}, fmt.Errorf("%w: %w", ErrUncertainTenantSwitchCommit, err)
		}
		return TenantSwitchResult{}, err
	}
	if !pending.CorrelationID.Valid {
		return TenantSwitchResult{}, ErrInvalidTenantSwitchOutcome
	}
	return pending, nil
}

func (c *TenantSwitchCoordinator) claimAndSwitch(
	ctx context.Context,
	unit tenantSwitchUnit,
	request TenantSwitchRequest,
	requestHash string,
	bind sqlcgen.BindTenantSwitchIdempotencyRow,
	pending *TenantSwitchResult,
) error {
	store, err := idempotency.NewStore(unit)
	if err != nil {
		return fmt.Errorf("create tenant-switch idempotency store: %w", err)
	}
	claim, err := store.Claim(ctx, idempotency.ClaimRequest{
		Key:           request.IdempotencyKey,
		Operation:     TenantSwitchOperation,
		RequestHash:   bind.ReceiptHash,
		CorrelationID: request.CorrelationID,
		ExpiresAt:     bind.ReceiptExpiresAt.Time.UTC(),
	})
	if err != nil {
		return fmt.Errorf("claim tenant-switch receipt: %w", err)
	}
	switch claim.State {
	case idempotency.StateClaimed:
		if claim.CorrelationID != request.CorrelationID {
			return ErrInvalidTenantSwitchPair
		}
	case idempotency.StateConflict:
		return ErrTenantSwitchScopeConflict
	case idempotency.StateInProgress:
		return ErrTenantSwitchInProgress
	default:
		return ErrInvalidTenantSwitchPair
	}

	switchService, err := NewSessionContextSwitchService(NewSessionStore(unit))
	if err != nil {
		return fmt.Errorf("create tenant-switch session service: %w", err)
	}
	switched, err := switchService.Switch(ctx, request.PresentedSessionToken, request.TargetTenantID)
	if err != nil {
		return fmt.Errorf("execute tenant-switch session mutation: %w", err)
	}
	if switched.ActiveTenantID != bind.ActiveTenantID || !switched.ActiveWorkspaceID.Valid ||
		!switched.ExpiresAt.Equal(bind.SessionExpiresAt.Time.UTC()) {
		return ErrInvalidTenantSwitchOutcome
	}

	response, responseBody, etag, err := buildTenantSwitchResponse(ctx, unit, switched, bind, request.TargetTenantID)
	if err != nil {
		return err
	}
	eventTime := time.Now().UTC()
	auditID, err := newTenantSwitchUUID()
	if err != nil {
		return fmt.Errorf("generate tenant-switch audit id: %w", err)
	}
	outboxID, err := newTenantSwitchUUID()
	if err != nil {
		return fmt.Errorf("generate tenant-switch outbox id: %w", err)
	}
	targetTenantText := uuidText(request.TargetTenantID)
	targetWorkspaceText := uuidText(switched.ActiveWorkspaceID)
	metadata := map[string]any{
		"target_tenant_id":    targetTenantText,
		"target_workspace_id": targetWorkspaceText,
		"session_generation": response.Active.SessionGeneration,
	}
	recorder, err := audit.NewRecorder(unit)
	if err != nil {
		return fmt.Errorf("create tenant-switch audit recorder: %w", err)
	}
	if err := recorder.Record(ctx, audit.Event{
		TenantID:       request.TargetTenantID,
		ID:             auditID,
		ActorSubjectID: response.Identity.ID,
		EventType:      "machina.tenant.switch.completed",
		Action:         "tenant.switch",
		Decision:       "allow",
		PolicyVersion:  response.Active.PolicyVersion,
		CorrelationID:  request.CorrelationID,
		SafeMetadata:   metadata,
		OccurredAt:     eventTime,
	}); err != nil {
		return err
	}
	publisher, err := outbox.NewPublisher(unit)
	if err != nil {
		return fmt.Errorf("create tenant-switch outbox publisher: %w", err)
	}
	if err := publisher.Publish(ctx, outbox.Envelope{
		EventID:       outboxID,
		EventType:     "machina.tenant.switch.completed",
		EventVersion:  1,
		OccurredAt:    eventTime,
		TenantID:      request.TargetTenantID,
		WorkspaceID:    switched.ActiveWorkspaceID,
		CorrelationID: request.CorrelationID,
		ActorID:       response.Identity.ID,
		Payload:       metadata,
	}); err != nil {
		return err
	}

	if err := store.Complete(ctx, idempotency.Completion{
		Key:            request.IdempotencyKey,
		Operation:      TenantSwitchOperation,
		RequestHash:    bind.ReceiptHash,
		ResponseStatus: 200,
		ResponseBody:   responseBody,
	}); err != nil {
		return fmt.Errorf("complete tenant-switch receipt: %w", err)
	}
	etagSet, err := unit.SetTenantSwitchResponseETag(ctx, sqlcgen.SetTenantSwitchResponseETagParams{
		IdempotencyKey: request.IdempotencyKey,
		RequestHash:    bind.ReceiptHash,
		ResponseETag:   etag,
	})
	if err != nil {
		return fmt.Errorf("persist tenant-switch response etag: %w", err)
	}
	if !etagSet {
		return ErrInvalidTenantSwitchOutcome
	}

	replacementHash := HashToken(switched.SessionToken)
	finished, err := unit.FinishTenantSwitchIdempotency(ctx, sqlcgen.FinishTenantSwitchIdempotencyParams{
		CurrentSessionTokenHash: replacementHash[:],
		IdempotencyKey:          request.IdempotencyKey,
		RequestHash:             requestHash,
	})
	if err != nil {
		return fmt.Errorf("finish tenant-switch idempotency scope: %w", err)
	}
	if !finished.Finished || !finished.SessionID.Valid || finished.SessionID != bind.SessionID ||
		finished.ResultGeneration != response.Active.SessionGeneration {
		return ErrInvalidTenantSwitchOutcome
	}

	*pending = TenantSwitchResult{
		Outcome:           response.outcome(),
		ResponseBody:      append([]byte(nil), responseBody...),
		ResponseStatus:    200,
		CorrelationID:     request.CorrelationID,
		ETag:              etag,
		ActiveTenantID:    switched.ActiveTenantID,
		ActiveWorkspaceID: switched.ActiveWorkspaceID,
		Generation:        response.Active.SessionGeneration,
		SessionExpiresAt:  response.ExpiresAt,
		SessionToken:      switched.SessionToken,
		CSRFToken:         switched.CSRFToken,
	}
	return nil
}

func (c *TenantSwitchCoordinator) replay(
	ctx context.Context,
	unit tenantSwitchUnit,
	request TenantSwitchRequest,
	requestHash string,
	bind sqlcgen.BindTenantSwitchIdempotencyRow,
	pending *TenantSwitchResult,
) error {
	store, err := idempotency.NewStore(unit)
	if err != nil {
		return fmt.Errorf("create tenant-switch idempotency store: %w", err)
	}
	claim, err := store.Claim(ctx, idempotency.ClaimRequest{
		Key:           request.IdempotencyKey,
		Operation:     TenantSwitchOperation,
		RequestHash:   bind.ReceiptHash,
		CorrelationID: request.CorrelationID,
		ExpiresAt:     bind.ReceiptExpiresAt.Time.UTC(),
	})
	if err != nil {
		return fmt.Errorf("read tenant-switch replay receipt: %w", err)
	}
	if claim.State != idempotency.StateReplay || claim.ResponseStatus != 200 {
		return ErrInvalidTenantSwitchPair
	}

	response, canonicalBody, err := unmarshalTenantSwitchResponse(claim.ResponseBody)
	if err != nil {
		return err
	}
	if response.Active.Tenant.ID != uuidText(bind.ActiveTenantID) ||
		!response.ExpiresAt.Equal(bind.SessionExpiresAt.Time.UTC()) {
		return ErrInvalidTenantSwitchOutcome
	}
	// Session generation is an internal scope marker, not an OpenAPI field.
	// The binder already checked the current generation; attach that marker only
	// after validating the immutable historical response.
	response.Active.SessionGeneration = bind.Generation
	storedETag, err := unit.GetTenantSwitchResponseETag(ctx, sqlcgen.GetTenantSwitchResponseETagParams{
		IdempotencyKey: request.IdempotencyKey,
		RequestHash:    bind.ReceiptHash,
	})
	if err != nil {
		return fmt.Errorf("load tenant-switch response etag: %w", err)
	}
	if !storedETag.Valid || storedETag.String != strongTenantSwitchETag(canonicalBody) {
		return ErrInvalidTenantSwitchOutcome
	}

	historicalTenantID, ok := parseUUIDText(response.Active.Tenant.ID)
	if !ok {
		return ErrInvalidTenantSwitchOutcome
	}
	historicalWorkspaceID, ok := parseUUIDText(response.Active.Workspace.ID)
	if !ok {
		return ErrInvalidTenantSwitchOutcome
	}
	*pending = TenantSwitchResult{
		Outcome:           response.outcome(),
		ResponseBody:      append([]byte(nil), canonicalBody...),
		ResponseStatus:    claim.ResponseStatus,
		CorrelationID:     claim.CorrelationID,
		Replay:            true,
		ETag:              storedETag.String,
		ActiveTenantID:    historicalTenantID,
		ActiveWorkspaceID: historicalWorkspaceID,
		Generation:        response.Active.SessionGeneration,
		SessionExpiresAt:  response.ExpiresAt,
	}
	return nil
}

type tenantSwitchIdentity struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

type tenantSwitchTenant struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

type tenantSwitchWorkspace struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

type tenantSwitchCapability struct {
	ID         string `json:"id"`
	Allowed    bool   `json:"allowed"`
	ReasonCode string `json:"reason_code,omitempty"`
}

type tenantSwitchAuthorizedContext struct {
	Identity      tenantSwitchIdentity     `json:"identity"`
	Tenant        tenantSwitchTenant       `json:"tenant"`
	Workspace     tenantSwitchWorkspace    `json:"workspace"`
	Capabilities  []tenantSwitchCapability `json:"capabilities"`
	PolicyVersion int64                   `json:"policy_version"`
	SessionGeneration int64               `json:"-"`
}

type tenantSwitchSessionContext struct {
	Identity          tenantSwitchIdentity          `json:"identity"`
	Active            tenantSwitchAuthorizedContext `json:"active"`
	AvailableTenants  []tenantSwitchTenant           `json:"available_tenants"`
	ExpiresAt         time.Time                     `json:"expires_at"`
}

func (response tenantSwitchSessionContext) outcome() TenantSwitchOutcome {
	return TenantSwitchOutcome{
		ActiveTenantID: response.Active.Tenant.ID,
		ActiveWorkspaceID: response.Active.Workspace.ID,
		SessionGeneration: response.Active.SessionGeneration,
		SessionExpiresAt: response.ExpiresAt.UTC(),
	}
}

func buildTenantSwitchResponse(
	ctx context.Context,
	unit tenantSwitchUnit,
	switched SwitchedSessionContext,
	bind sqlcgen.BindTenantSwitchIdempotencyRow,
	targetTenantID pgtype.UUID,
) (tenantSwitchSessionContext, []byte, string, error) {
	if !switched.ActiveTenantID.Valid || !switched.ActiveWorkspaceID.Valid || !switched.ExpiresAt.After(time.Now().UTC()) {
		return tenantSwitchSessionContext{}, nil, "", ErrInvalidTenantSwitchOutcome
	}
	sessionHash := HashToken(switched.SessionToken)
	identityRow, err := unit.GetSessionIdentity(ctx, sessionHash[:])
	if err != nil {
		return tenantSwitchSessionContext{}, nil, "", fmt.Errorf("load tenant-switch identity: %w", err)
	}
	tenantRows, err := unit.ListSessionTenants(ctx, sessionHash[:])
	if err != nil {
		return tenantSwitchSessionContext{}, nil, "", fmt.Errorf("load tenant-switch tenants: %w", err)
	}
	tenantRow, err := unit.GetTenant(ctx, targetTenantID)
	if err != nil {
		return tenantSwitchSessionContext{}, nil, "", fmt.Errorf("load tenant-switch target tenant: %w", err)
	}
	workspaceRow, err := unit.GetWorkspace(ctx, sqlcgen.GetWorkspaceParams{
		TenantID: targetTenantID,
		WorkspaceID: switched.ActiveWorkspaceID,
	})
	if err != nil {
		return tenantSwitchSessionContext{}, nil, "", fmt.Errorf("load tenant-switch target workspace: %w", err)
	}
	policyRow, err := unit.GetActivePolicySnapshot(ctx, targetTenantID)
	if err != nil {
		return tenantSwitchSessionContext{}, nil, "", fmt.Errorf("load tenant-switch policy snapshot: %w", err)
	}
	if !identityRow.ID.Valid || identityRow.DisplayName == "" || len(identityRow.DisplayName) > 160 ||
		!tenantRow.ID.Valid || tenantRow.ID != targetTenantID || tenantRow.Status != "active" ||
		!workspaceRow.TenantID.Valid || workspaceRow.TenantID != targetTenantID ||
		!workspaceRow.ID.Valid || workspaceRow.ID != switched.ActiveWorkspaceID ||
		policyRow.Version <= 0 || !validTenantSwitchRequestHash(policyRow.SnapshotHash) {
		return tenantSwitchSessionContext{}, nil, "", ErrInvalidTenantSwitchOutcome
	}
	var available []tenantSwitchTenant
	var targetRole string
	seen := make(map[string]struct{}, len(tenantRows))
	for _, row := range tenantRows {
		if !row.TenantID.Valid || row.Status != "active" || row.Slug == "" || row.DisplayName == "" ||
			len(row.DisplayName) > 160 {
			return tenantSwitchSessionContext{}, nil, "", ErrInvalidTenantSwitchOutcome
		}
		id := uuidText(row.TenantID)
		if _, exists := seen[id]; exists {
			return tenantSwitchSessionContext{}, nil, "", ErrInvalidTenantSwitchOutcome
		}
		seen[id] = struct{}{}
		available = append(available, tenantSwitchTenant{ID: id, Slug: row.Slug, DisplayName: row.DisplayName, Status: row.Status})
		if row.TenantID == targetTenantID {
			targetRole = row.StarterRole
		}
	}
	if targetRole != "owner" && targetRole != "member" {
		return tenantSwitchSessionContext{}, nil, "", ErrInvalidTenantSwitchOutcome
	}
	identity := tenantSwitchIdentity{ID: uuidText(identityRow.ID), DisplayName: identityRow.DisplayName}
	tenant := tenantSwitchTenant{ID: uuidText(tenantRow.ID), Slug: tenantRow.Slug, DisplayName: tenantRow.DisplayName, Status: tenantRow.Status}
	workspace := tenantSwitchWorkspace{ID: uuidText(workspaceRow.ID), TenantID: uuidText(workspaceRow.TenantID), Slug: workspaceRow.Slug, DisplayName: workspaceRow.DisplayName}
	capabilities := []tenantSwitchCapability{
		{ID: "session.read", Allowed: true},
		{ID: "tenant.create", Allowed: targetRole == "owner", ReasonCode: reasonForTenantCreate(targetRole)},
		{ID: "tenant.switch", Allowed: true},
		{ID: "workspace.read", Allowed: true},
		{ID: "context.read", Allowed: true},
		{ID: "ask.context.read", Allowed: true},
	}
	response := tenantSwitchSessionContext{
		Identity: identity,
		Active: tenantSwitchAuthorizedContext{
			Identity: identity, Tenant: tenant, Workspace: workspace,
			Capabilities: capabilities, PolicyVersion: policyRow.Version,
			SessionGeneration: bind.Generation + 1,
		},
		AvailableTenants: available,
		ExpiresAt: switched.ExpiresAt.UTC(),
	}
	body, err := marshalTenantSwitchResponse(response)
	if err != nil {
		return tenantSwitchSessionContext{}, nil, "", err
	}
	return response, body, strongTenantSwitchETag(body), nil
}

func reasonForTenantCreate(starterRole string) string {
	if starterRole == "owner" {
		return ""
	}
	return "owner_required"
}

func marshalTenantSwitchResponse(response tenantSwitchSessionContext) ([]byte, error) {
	if err := validateTenantSwitchResponse(response); err != nil {
		return nil, err
	}
	return canonicalJSON(response)
}

func unmarshalTenantSwitchResponse(body []byte) (tenantSwitchSessionContext, []byte, error) {
	if len(body) == 0 {
		return tenantSwitchSessionContext{}, nil, ErrInvalidTenantSwitchOutcome
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var response tenantSwitchSessionContext
	if err := decoder.Decode(&response); err != nil {
		return tenantSwitchSessionContext{}, nil, ErrInvalidTenantSwitchOutcome
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tenantSwitchSessionContext{}, nil, ErrInvalidTenantSwitchOutcome
	}
	canonical, err := marshalTenantSwitchResponse(response)
	if err != nil {
		return tenantSwitchSessionContext{}, nil, err
	}
	if !json.Valid(body) {
		return tenantSwitchSessionContext{}, nil, ErrInvalidTenantSwitchOutcome
	}
	return response, canonical, nil
}

func validateTenantSwitchResponse(response tenantSwitchSessionContext) error {
	if !validTenantSwitchIdentity(response.Identity) ||
		!validTenantSwitchAuthorizedContext(response.Active) ||
		response.Active.Identity != response.Identity ||
		response.ExpiresAt.IsZero() {
		return ErrInvalidTenantSwitchOutcome
	}
	seen := make(map[string]struct{}, len(response.AvailableTenants))
	for _, tenant := range response.AvailableTenants {
		if err := validateTenantSwitchTenant(tenant); err != nil {
			return err
		}
		if _, exists := seen[tenant.ID]; exists {
			return ErrInvalidTenantSwitchOutcome
		}
		seen[tenant.ID] = struct{}{}
	}
	if _, ok := seen[response.Active.Tenant.ID]; !ok {
		return ErrInvalidTenantSwitchOutcome
	}
	return nil
}

func validTenantSwitchIdentity(identity tenantSwitchIdentity) error {
	if _, ok := parseUUIDText(identity.ID); !ok || identity.DisplayName == "" || len(identity.DisplayName) > 160 {
		return ErrInvalidTenantSwitchOutcome
	}
	return nil
}

func validTenantSwitchTenant(tenant tenantSwitchTenant) error {
	if _, ok := parseUUIDText(tenant.ID); !ok || tenant.Slug == "" || len(tenant.Slug) < 3 ||
		len(tenant.Slug) > 63 || tenant.DisplayName == "" || len(tenant.DisplayName) > 160 ||
		tenant.Status != "active" {
		return ErrInvalidTenantSwitchOutcome
	}
	return nil
}

func validTenantSwitchAuthorizedContext(active tenantSwitchAuthorizedContext) error {
	if err := validTenantSwitchIdentity(active.Identity); err != nil {
		return err
	}
	if err := validTenantSwitchTenant(active.Tenant); err != nil {
		return err
	}
	if _, ok := parseUUIDText(active.Workspace.ID); !ok || active.Workspace.TenantID != active.Tenant.ID ||
		active.Workspace.Slug == "" || active.Workspace.DisplayName == "" ||
		len(active.Workspace.DisplayName) > 160 || active.PolicyVersion <= 0 {
		return ErrInvalidTenantSwitchOutcome
	}
	known := map[string]bool{
		"session.read": false, "tenant.create": false, "tenant.switch": false,
		"workspace.read": false, "context.read": false, "ask.context.read": false,
	}
	for _, capability := range active.Capabilities {
		if _, ok := known[capability.ID]; !ok || known[capability.ID] {
			return ErrInvalidTenantSwitchOutcome
		}
		known[capability.ID] = true
		if capability.ID == "tenant.create" && !capability.Allowed && capability.ReasonCode == "" {
			return ErrInvalidTenantSwitchOutcome
		}
	}
	for _, allowed := range known {
		if !allowed {
			return ErrInvalidTenantSwitchOutcome
		}
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidTenantSwitchOutcome
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, ErrInvalidTenantSwitchOutcome
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return nil, ErrInvalidTenantSwitchOutcome
	}
	return canonical, nil
}

func strongTenantSwitchETag(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%q", "sha256:"+hex.EncodeToString(sum[:]))
}

func validateTenantSwitchRequest(request TenantSwitchRequest) error {
	if request.PresentedSessionToken == "" || !request.TargetTenantID.Valid ||
		!validTenantSwitchKey(request.IdempotencyKey) || !request.CorrelationID.Valid {
		return ErrInvalidTenantSwitchRequest
	}
	return nil
}

func validateTenantSwitchBindRow(row sqlcgen.BindTenantSwitchIdempotencyRow, target pgtype.UUID, requestHash string) error {
	expectedReceiptHash := tenantSwitchReceiptHash(row.SessionID, requestHash)
	if !row.SessionID.Valid || !row.ActiveTenantID.Valid || !row.ActiveWorkspaceID.Valid ||
		!row.SessionExpiresAt.Valid || !row.ReceiptExpiresAt.Valid ||
		row.Generation <= 0 || !validTenantSwitchRequestHash(row.ReceiptHash) ||
		row.ReceiptHash != expectedReceiptHash || row.ActiveTenantID != target ||
		row.ReceiptExpiresAt.Time.IsZero() || row.SessionExpiresAt.Time.IsZero() ||
		row.ReceiptExpiresAt.Time.After(row.SessionExpiresAt.Time) {
		return ErrInvalidTenantSwitchScope
	}
	return nil
}

func validTenantSwitchKey(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= 16 && length <= 128
}

func validTenantSwitchRequestHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func tenantSwitchRequestHash(target pgtype.UUID) string {
	canonical := uuidText(target)
	sum := sha256.Sum256([]byte(TenantSwitchOperation + "\n" + canonical))
	return hex.EncodeToString(sum[:])
}

func tenantSwitchReceiptHash(sessionID pgtype.UUID, requestHash string) string {
	sum := sha256.Sum256([]byte(TenantSwitchOperation + "\n" + uuidText(sessionID) + "\n" + requestHash))
	return hex.EncodeToString(sum[:])
}

func uuidText(value pgtype.UUID) string {
	encoded := hex.EncodeToString(value.Bytes[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func parseUUIDText(value string) (pgtype.UUID, bool) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return pgtype.UUID{}, false
	}
	decoded, err := hex.DecodeString(value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:])
	if err != nil || len(decoded) != 16 {
		return pgtype.UUID{}, false
	}
	var bytes [16]byte
	copy(bytes[:], decoded)
	parsed := pgtype.UUID{Bytes: bytes, Valid: true}
	return parsed, uuidText(parsed) == value
}

func newTenantSwitchUUID() (pgtype.UUID, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return pgtype.UUID{}, err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return pgtype.UUID{Bytes: bytes, Valid: true}, nil
}

func isNilTenantSwitchUnit(unit tenantSwitchUnit) bool {
	if unit == nil {
		return true
	}
	value := reflect.ValueOf(unit)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

type sqlTenantSwitchUnit struct {
	queries *sqlcgen.Queries
}

func (u sqlTenantSwitchUnit) CreateSession(ctx context.Context, arg sqlcgen.CreateSessionParams) (pgtype.UUID, error) {
	if u.queries == nil { return pgtype.UUID{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.CreateSession(ctx, arg)
}
func (u sqlTenantSwitchUnit) GetActiveSession(ctx context.Context, arg []byte) (sqlcgen.GetActiveSessionRow, error) {
	if u.queries == nil { return sqlcgen.GetActiveSessionRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.GetActiveSession(ctx, arg)
}
func (u sqlTenantSwitchUnit) RevokeSession(ctx context.Context, arg []byte) error {
	if u.queries == nil { return ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.RevokeSession(ctx, arg)
}
func (u sqlTenantSwitchUnit) RotateSession(ctx context.Context, arg sqlcgen.RotateSessionParams) (sqlcgen.RotateSessionRow, error) {
	if u.queries == nil { return sqlcgen.RotateSessionRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.RotateSession(ctx, arg)
}
func (u sqlTenantSwitchUnit) SwitchSessionContext(ctx context.Context, arg sqlcgen.SwitchSessionContextParams) (sqlcgen.SwitchSessionContextRow, error) {
	if u.queries == nil { return sqlcgen.SwitchSessionContextRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.SwitchSessionContext(ctx, arg)
}
func (u sqlTenantSwitchUnit) BindTenantSwitchIdempotency(ctx context.Context, arg sqlcgen.BindTenantSwitchIdempotencyParams) (sqlcgen.BindTenantSwitchIdempotencyRow, error) {
	if u.queries == nil { return sqlcgen.BindTenantSwitchIdempotencyRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.BindTenantSwitchIdempotency(ctx, arg)
}
func (u sqlTenantSwitchUnit) FinishTenantSwitchIdempotency(ctx context.Context, arg sqlcgen.FinishTenantSwitchIdempotencyParams) (sqlcgen.FinishTenantSwitchIdempotencyRow, error) {
	if u.queries == nil { return sqlcgen.FinishTenantSwitchIdempotencyRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.FinishTenantSwitchIdempotency(ctx, arg)
}
func (u sqlTenantSwitchUnit) ClaimIdempotencyKey(ctx context.Context, arg sqlcgen.ClaimIdempotencyKeyParams) (sqlcgen.ClaimIdempotencyKeyRow, error) {
	if u.queries == nil { return sqlcgen.ClaimIdempotencyKeyRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.ClaimIdempotencyKey(ctx, arg)
}
func (u sqlTenantSwitchUnit) CompleteIdempotencyKey(ctx context.Context, arg sqlcgen.CompleteIdempotencyKeyParams) (bool, error) {
	if u.queries == nil { return false, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.CompleteIdempotencyKey(ctx, arg)
}
func (u sqlTenantSwitchUnit) GetSessionIdentity(ctx context.Context, arg []byte) (sqlcgen.GetSessionIdentityRow, error) {
	if u.queries == nil { return sqlcgen.GetSessionIdentityRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.GetSessionIdentity(ctx, arg)
}
func (u sqlTenantSwitchUnit) ListSessionTenants(ctx context.Context, arg []byte) ([]sqlcgen.ListSessionTenantsRow, error) {
	if u.queries == nil { return nil, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.ListSessionTenants(ctx, arg)
}
func (u sqlTenantSwitchUnit) GetTenant(ctx context.Context, arg pgtype.UUID) (sqlcgen.IamTenant, error) {
	if u.queries == nil { return sqlcgen.IamTenant{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.GetTenant(ctx, arg)
}
func (u sqlTenantSwitchUnit) GetWorkspace(ctx context.Context, arg sqlcgen.GetWorkspaceParams) (sqlcgen.IamWorkspace, error) {
	if u.queries == nil { return sqlcgen.IamWorkspace{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.GetWorkspace(ctx, arg)
}
func (u sqlTenantSwitchUnit) GetActivePolicySnapshot(ctx context.Context, arg pgtype.UUID) (sqlcgen.GetActivePolicySnapshotRow, error) {
	if u.queries == nil { return sqlcgen.GetActivePolicySnapshotRow{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.GetActivePolicySnapshot(ctx, arg)
}
func (u sqlTenantSwitchUnit) SetTenantSwitchResponseETag(ctx context.Context, arg sqlcgen.SetTenantSwitchResponseETagParams) (bool, error) {
	if u.queries == nil { return false, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.SetTenantSwitchResponseETag(ctx, arg)
}
func (u sqlTenantSwitchUnit) GetTenantSwitchResponseETag(ctx context.Context, arg sqlcgen.GetTenantSwitchResponseETagParams) (pgtype.Text, error) {
	if u.queries == nil { return pgtype.Text{}, ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.GetTenantSwitchResponseETag(ctx, arg)
}
func (u sqlTenantSwitchUnit) InsertAuditEvent(ctx context.Context, arg sqlcgen.InsertAuditEventParams) error {
	if u.queries == nil { return ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.InsertAuditEvent(ctx, arg)
}
func (u sqlTenantSwitchUnit) EnqueueOutboxEvent(ctx context.Context, arg sqlcgen.EnqueueOutboxEventParams) error {
	if u.queries == nil { return ErrInvalidTenantSwitchCoordinatorConfig }
	return u.queries.EnqueueOutboxEvent(ctx, arg)
}

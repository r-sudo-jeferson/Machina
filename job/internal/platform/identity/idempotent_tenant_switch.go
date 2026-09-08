package identity

import (
	"bytes"
	"context"
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

// TenantSwitchOutcome is the immutable, non-secret result stored for an
// idempotent tenant switch. It is deliberately independent of the current
// context resolver so a replay cannot combine historical and live facts.
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
	ActiveTenantID    pgtype.UUID
	ActiveWorkspaceID pgtype.UUID
	Generation        int64
	SessionExpiresAt  time.Time
	SessionToken      string
	CSRFToken         string
}

// tenantSwitchUnit is the complete set of transaction-bound operations used
// by the coordinator. Keeping the dependency narrow makes it possible to
// test the state machine without constructing a database driver fake that
// implements unrelated queries.
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

// Switch performs binding, idempotency claim, session mutation, completion,
// and scope finish in one transaction. Replacement secrets are copied into
// the returned result only after the runner reports a successful commit.
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
			return c.claimAndSwitch(txCtx, unit, request, bind, &pending)
		case "replay":
			return c.replay(txCtx, unit, request, bind, &pending)
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
		// browser secrets in that ambiguous state; the selected policy requires
		// reauthentication for recovery.
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
	if switched.ActiveTenantID != bind.ActiveTenantID || switched.ActiveWorkspaceID != bind.ActiveWorkspaceID || !switched.ExpiresAt.Equal(bind.SessionExpiresAt.Time.UTC()) {
		return ErrInvalidTenantSwitchOutcome
	}

	outcome := TenantSwitchOutcome{
		ActiveTenantID:    uuidText(switched.ActiveTenantID),
		ActiveWorkspaceID: uuidText(switched.ActiveWorkspaceID),
		SessionGeneration: bind.Generation + 1,
		SessionExpiresAt:  switched.ExpiresAt.UTC(),
	}
	responseBody, err := marshalTenantSwitchOutcome(outcome)
	if err != nil {
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

	replacementHash := HashToken(switched.SessionToken)
	finished, err := unit.FinishTenantSwitchIdempotency(ctx, sqlcgen.FinishTenantSwitchIdempotencyParams{
		CurrentSessionTokenHash: replacementHash[:],
		IdempotencyKey:          request.IdempotencyKey,
		RequestHash:             bind.ReceiptHash,
	})
	if err != nil {
		return fmt.Errorf("finish tenant-switch idempotency scope: %w", err)
	}
	if !finished.Finished || !finished.SessionID.Valid || finished.SessionID != bind.SessionID || finished.ResultGeneration != outcome.SessionGeneration {
		return ErrInvalidTenantSwitchOutcome
	}

	*pending = TenantSwitchResult{
		Outcome:           outcome,
		ResponseBody:      append([]byte(nil), responseBody...),
		ResponseStatus:    200,
		CorrelationID:     request.CorrelationID,
		ActiveTenantID:    switched.ActiveTenantID,
		ActiveWorkspaceID: switched.ActiveWorkspaceID,
		Generation:        outcome.SessionGeneration,
		SessionExpiresAt:  outcome.SessionExpiresAt,
		SessionToken:      switched.SessionToken,
		CSRFToken:         switched.CSRFToken,
	}
	return nil
}

func (c *TenantSwitchCoordinator) replay(
	ctx context.Context,
	unit tenantSwitchUnit,
	request TenantSwitchRequest,
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

	outcome, err := unmarshalTenantSwitchOutcome(claim.ResponseBody)
	if err != nil {
		return err
	}
	if outcome.ActiveTenantID != uuidText(bind.ActiveTenantID) ||
		outcome.SessionGeneration != bind.Generation ||
		!outcome.SessionExpiresAt.Equal(bind.SessionExpiresAt.Time.UTC()) {
		return ErrInvalidTenantSwitchOutcome
	}
	historicalTenantID, ok := parseUUIDText(outcome.ActiveTenantID)
	if !ok {
		return ErrInvalidTenantSwitchOutcome
	}
	historicalWorkspaceID, ok := parseUUIDText(outcome.ActiveWorkspaceID)
	if !ok {
		return ErrInvalidTenantSwitchOutcome
	}

	*pending = TenantSwitchResult{
		Outcome:           outcome,
		ResponseBody:      append([]byte(nil), claim.ResponseBody...),
		ResponseStatus:    claim.ResponseStatus,
		CorrelationID:     claim.CorrelationID,
		Replay:            true,
		ActiveTenantID:    historicalTenantID,
		ActiveWorkspaceID: historicalWorkspaceID,
		Generation:        outcome.SessionGeneration,
		SessionExpiresAt:  outcome.SessionExpiresAt,
	}
	return nil
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

func marshalTenantSwitchOutcome(outcome TenantSwitchOutcome) ([]byte, error) {
	if outcome.ActiveTenantID == "" || outcome.ActiveWorkspaceID == "" || outcome.SessionGeneration <= 0 || outcome.SessionExpiresAt.IsZero() {
		return nil, ErrInvalidTenantSwitchOutcome
	}
	body, err := json.Marshal(outcome)
	if err != nil {
		return nil, fmt.Errorf("marshal tenant-switch outcome: %w", err)
	}
	if !json.Valid(body) {
		return nil, ErrInvalidTenantSwitchOutcome
	}
	return body, nil
}

func unmarshalTenantSwitchOutcome(body []byte) (TenantSwitchOutcome, error) {
	if len(body) == 0 {
		return TenantSwitchOutcome{}, ErrInvalidTenantSwitchOutcome
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var outcome TenantSwitchOutcome
	if err := decoder.Decode(&outcome); err != nil {
		return TenantSwitchOutcome{}, ErrInvalidTenantSwitchOutcome
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return TenantSwitchOutcome{}, ErrInvalidTenantSwitchOutcome
	}
	if outcome.ActiveTenantID == "" || outcome.ActiveWorkspaceID == "" || outcome.SessionGeneration <= 0 || outcome.SessionExpiresAt.IsZero() {
		return TenantSwitchOutcome{}, ErrInvalidTenantSwitchOutcome
	}
	return outcome, nil
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
	if u.queries == nil {
		return pgtype.UUID{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.CreateSession(ctx, arg)
}

func (u sqlTenantSwitchUnit) GetActiveSession(ctx context.Context, arg []byte) (sqlcgen.GetActiveSessionRow, error) {
	if u.queries == nil {
		return sqlcgen.GetActiveSessionRow{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.GetActiveSession(ctx, arg)
}

func (u sqlTenantSwitchUnit) RevokeSession(ctx context.Context, arg []byte) error {
	if u.queries == nil {
		return ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.RevokeSession(ctx, arg)
}

func (u sqlTenantSwitchUnit) RotateSession(ctx context.Context, arg sqlcgen.RotateSessionParams) (sqlcgen.RotateSessionRow, error) {
	if u.queries == nil {
		return sqlcgen.RotateSessionRow{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.RotateSession(ctx, arg)
}

func (u sqlTenantSwitchUnit) SwitchSessionContext(ctx context.Context, arg sqlcgen.SwitchSessionContextParams) (sqlcgen.SwitchSessionContextRow, error) {
	if u.queries == nil {
		return sqlcgen.SwitchSessionContextRow{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.SwitchSessionContext(ctx, arg)
}

func (u sqlTenantSwitchUnit) BindTenantSwitchIdempotency(ctx context.Context, arg sqlcgen.BindTenantSwitchIdempotencyParams) (sqlcgen.BindTenantSwitchIdempotencyRow, error) {
	if u.queries == nil {
		return sqlcgen.BindTenantSwitchIdempotencyRow{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.BindTenantSwitchIdempotency(ctx, arg)
}

func (u sqlTenantSwitchUnit) FinishTenantSwitchIdempotency(ctx context.Context, arg sqlcgen.FinishTenantSwitchIdempotencyParams) (sqlcgen.FinishTenantSwitchIdempotencyRow, error) {
	if u.queries == nil {
		return sqlcgen.FinishTenantSwitchIdempotencyRow{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.FinishTenantSwitchIdempotency(ctx, arg)
}

func (u sqlTenantSwitchUnit) ClaimIdempotencyKey(ctx context.Context, arg sqlcgen.ClaimIdempotencyKeyParams) (sqlcgen.ClaimIdempotencyKeyRow, error) {
	if u.queries == nil {
		return sqlcgen.ClaimIdempotencyKeyRow{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.ClaimIdempotencyKey(ctx, arg)
}

func (u sqlTenantSwitchUnit) CompleteIdempotencyKey(ctx context.Context, arg sqlcgen.CompleteIdempotencyKeyParams) (bool, error) {
	if u.queries == nil {
		return false, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return u.queries.CompleteIdempotencyKey(ctx, arg)
}

package identity

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingTenantSwitchUnit struct {
	bindRow        sqlcgen.BindTenantSwitchIdempotencyRow
	bindErr        error
	finishRow      sqlcgen.FinishTenantSwitchIdempotencyRow
	finishErr      error
	claimRow       sqlcgen.ClaimIdempotencyKeyRow
	claimErr       error
	completeErr    error
	responseETag   string
	etagErr        error
	auditErr       error
	outboxErr      error
	auditCalls     int
	outboxCalls    int
	etagCalls      int
	switchRow      sqlcgen.SwitchSessionContextRow
	switchErr      error
	bindParams     sqlcgen.BindTenantSwitchIdempotencyParams
	finishParams   sqlcgen.FinishTenantSwitchIdempotencyParams
	claimParams    sqlcgen.ClaimIdempotencyKeyParams
	completeParams sqlcgen.CompleteIdempotencyKeyParams
	switchParams   sqlcgen.SwitchSessionContextParams
	bindCalls      int
	finishCalls    int
	claimCalls     int
	completeCalls  int
	switchCalls    int
}

func (u *recordingTenantSwitchUnit) BindTenantSwitchIdempotency(_ context.Context, arg sqlcgen.BindTenantSwitchIdempotencyParams) (sqlcgen.BindTenantSwitchIdempotencyRow, error) {
	u.bindCalls++
	u.bindParams = arg
	return u.bindRow, u.bindErr
}

func (u *recordingTenantSwitchUnit) CreateSession(_ context.Context, _ sqlcgen.CreateSessionParams) (pgtype.UUID, error) {
	return pgtype.UUID{}, nil
}

func (u *recordingTenantSwitchUnit) GetActiveSession(_ context.Context, _ []byte) (sqlcgen.GetActiveSessionRow, error) {
	return sqlcgen.GetActiveSessionRow{}, nil
}

func (u *recordingTenantSwitchUnit) RevokeSession(_ context.Context, _ []byte) error {
	return nil
}

func (u *recordingTenantSwitchUnit) RotateSession(_ context.Context, _ sqlcgen.RotateSessionParams) (sqlcgen.RotateSessionRow, error) {
	return sqlcgen.RotateSessionRow{}, nil
}

func (u *recordingTenantSwitchUnit) FinishTenantSwitchIdempotency(_ context.Context, arg sqlcgen.FinishTenantSwitchIdempotencyParams) (sqlcgen.FinishTenantSwitchIdempotencyRow, error) {
	u.finishCalls++
	u.finishParams = arg
	return u.finishRow, u.finishErr
}

func (u *recordingTenantSwitchUnit) ClaimIdempotencyKey(_ context.Context, arg sqlcgen.ClaimIdempotencyKeyParams) (sqlcgen.ClaimIdempotencyKeyRow, error) {
	u.claimCalls++
	u.claimParams = arg
	return u.claimRow, u.claimErr
}

func (u *recordingTenantSwitchUnit) CompleteIdempotencyKey(_ context.Context, arg sqlcgen.CompleteIdempotencyKeyParams) (bool, error) {
	u.completeCalls++
	u.completeParams = arg
	if u.completeErr != nil {
		return false, u.completeErr
	}
	return true, nil
}

func (u *recordingTenantSwitchUnit) GetSessionIdentity(_ context.Context, _ []byte) (sqlcgen.GetSessionIdentityRow, error) {
	return sqlcgen.GetSessionIdentityRow{ID: tenantSwitchUUID(2), DisplayName: "Subject A"}, nil
}

func (u *recordingTenantSwitchUnit) ListSessionTenants(_ context.Context, _ []byte) ([]sqlcgen.ListSessionTenantsRow, error) {
	return []sqlcgen.ListSessionTenantsRow{{TenantID: tenantSwitchUUID(2), Slug: "tenant-b", DisplayName: "Tenant B", Status: "active", StarterRole: "owner"}}, nil
}

func (u *recordingTenantSwitchUnit) GetTenant(_ context.Context, tenantID pgtype.UUID) (sqlcgen.IamTenant, error) {
	return sqlcgen.IamTenant{ID: tenantID, Slug: "tenant-b", DisplayName: "Tenant B", Status: "active"}, nil
}

func (u *recordingTenantSwitchUnit) GetWorkspace(_ context.Context, arg sqlcgen.GetWorkspaceParams) (sqlcgen.IamWorkspace, error) {
	return sqlcgen.IamWorkspace{TenantID: arg.TenantID, ID: arg.WorkspaceID, Slug: "main", DisplayName: "Main"}, nil
}

func (u *recordingTenantSwitchUnit) GetActivePolicySnapshot(_ context.Context, _ pgtype.UUID) (sqlcgen.GetActivePolicySnapshotRow, error) {
	return sqlcgen.GetActivePolicySnapshotRow{Version: 1, SnapshotHash: strings.Repeat("a", 64)}, nil
}

func (u *recordingTenantSwitchUnit) SetTenantSwitchResponseETag(_ context.Context, arg sqlcgen.SetTenantSwitchResponseETagParams) (bool, error) {
	u.etagCalls++
	if u.etagErr != nil {
		return false, u.etagErr
	}
	u.responseETag = arg.ResponseETag
	return true, nil
}

func (u *recordingTenantSwitchUnit) GetTenantSwitchResponseETag(_ context.Context, _ sqlcgen.GetTenantSwitchResponseETagParams) (string, error) {
	u.etagCalls++
	return u.responseETag, nil
}

func (u *recordingTenantSwitchUnit) InsertAuditEvent(_ context.Context, _ sqlcgen.InsertAuditEventParams) error {
	u.auditCalls++
	return u.auditErr
}

func (u *recordingTenantSwitchUnit) EnqueueOutboxEvent(_ context.Context, _ sqlcgen.EnqueueOutboxEventParams) error {
	u.outboxCalls++
	return u.outboxErr
}

func (u *recordingTenantSwitchUnit) SwitchSessionContext(_ context.Context, arg sqlcgen.SwitchSessionContextParams) (sqlcgen.SwitchSessionContextRow, error) {
	u.switchCalls++
	u.switchParams = arg
	return u.switchRow, u.switchErr
}

func tenantSwitchUUID(seed byte) pgtype.UUID {
	var bytes [16]byte
	bytes[15] = seed
	return pgtype.UUID{Bytes: bytes, Valid: true}
}

func validTenantSwitchRequest() TenantSwitchRequest {
	return TenantSwitchRequest{
		PresentedSessionToken: "old-session-secret",
		TargetTenantID:        tenantSwitchUUID(2),
		IdempotencyKey:        "tenant-switch-key-0001",
		CorrelationID:         tenantSwitchUUID(3),
	}
}

func validTenantSwitchBindRow() sqlcgen.BindTenantSwitchIdempotencyRow {
	return sqlcgen.BindTenantSwitchIdempotencyRow{
		MappingState:      "claimed",
		SessionID:         tenantSwitchUUID(1),
		Generation:        7,
		ActiveTenantID:    tenantSwitchUUID(2),
		ActiveWorkspaceID: tenantSwitchUUID(4),
		SessionExpiresAt:  pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC), Valid: true},
		ReceiptExpiresAt:  pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 11, 0, 0, 0, time.UTC), Valid: true},
		ReceiptHash:       tenantSwitchReceiptHash(tenantSwitchUUID(1), tenantSwitchRequestHash(tenantSwitchUUID(2))),
	}
}

func validTenantSwitchSwitchRow() sqlcgen.SwitchSessionContextRow {
	return sqlcgen.SwitchSessionContextRow{
		SessionID:         tenantSwitchUUID(1),
		ActiveTenantID:    tenantSwitchUUID(2),
		ActiveWorkspaceID: tenantSwitchUUID(4),
		ExpiresAt:         pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC), Valid: true},
	}
}

func claimedTenantSwitchUnit() *recordingTenantSwitchUnit {
	row := validTenantSwitchBindRow()
	_, canonical, err := unmarshalTenantSwitchResponse(tenantSwitchHTTPResponseBody())
	if err != nil {
		panic(err)
	}
	return &recordingTenantSwitchUnit{
		bindRow:       row,
		claimRow:      sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "claimed", CorrelationID: validTenantSwitchRequest().CorrelationID},
		finishRow:     sqlcgen.FinishTenantSwitchIdempotencyRow{Finished: true, SessionID: row.SessionID, ResultGeneration: row.Generation + 1},
		switchRow:     validTenantSwitchSwitchRow(),
		responseETag:  strongTenantSwitchETag(canonical),
	}
}

func newRecordingTenantSwitchCoordinator(unit *recordingTenantSwitchUnit, runnerErr error) *TenantSwitchCoordinator {
	coordinator, err := newTenantSwitchCoordinator(func(ctx context.Context, fn func(context.Context, tenantSwitchUnit) error) error {
		if runnerErr != nil {
			return runnerErr
		}
		return fn(ctx, unit)
	})
	if err != nil {
		panic(err)
	}
	return coordinator
}

func TestTenantSwitchCoordinatorClaimsMutatesCompletesAndPublishesOnlyAfterCommit(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
	got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if err != nil {
		t.Fatalf("Switch() error = %v", err)
	}
	if got.Replay {
		t.Fatal("claimed mutation was reported as replay")
	}
	if got.ResponseStatus != 200 || got.ActiveTenantID != unit.bindRow.ActiveTenantID || got.ActiveWorkspaceID != unit.bindRow.ActiveWorkspaceID || got.Generation != unit.finishRow.ResultGeneration || !got.SessionExpiresAt.Equal(unit.switchRow.ExpiresAt.Time) {
		t.Fatalf("result context = %#v", got)
	}
	if got.SessionToken == "" || got.CSRFToken == "" || got.SessionToken == got.CSRFToken {
		t.Fatalf("replacement secrets = %#v", got)
	}
	if unit.bindCalls != 1 || unit.claimCalls != 1 || unit.switchCalls != 1 || unit.completeCalls != 1 || unit.finishCalls != 1 {
		t.Fatalf("transaction calls = bind:%d claim:%d switch:%d complete:%d finish:%d", unit.bindCalls, unit.claimCalls, unit.switchCalls, unit.completeCalls, unit.finishCalls)
	}
	if unit.claimParams.Operation != TenantSwitchOperation || unit.claimParams.IdempotencyKey != validTenantSwitchRequest().IdempotencyKey || unit.claimParams.CorrelationID != validTenantSwitchRequest().CorrelationID {
		t.Fatalf("claim params = %#v", unit.claimParams)
	}
	if unit.claimParams.RequestHash != unit.bindRow.ReceiptHash || !unit.claimParams.ExpiresAt.Time.Equal(unit.bindRow.ReceiptExpiresAt.Time) {
		t.Fatalf("claim did not use authoritative receipt pair = %#v", unit.claimParams)
	}
	if unit.completeParams.RequestHash != unit.bindRow.ReceiptHash || string(unit.completeParams.ResponseBody) == "" {
		t.Fatalf("completion params = %#v", unit.completeParams)
	}
	if string(unit.completeParams.ResponseBody) == "" || containsSecret(unit.completeParams.ResponseBody, got.SessionToken) || containsSecret(unit.completeParams.ResponseBody, got.CSRFToken) {
		t.Fatalf("idempotency outcome contains browser secret: %q", unit.completeParams.ResponseBody)
	}
	if unit.finishParams.IdempotencyKey != validTenantSwitchRequest().IdempotencyKey || unit.finishParams.RequestHash != tenantSwitchRequestHash(validTenantSwitchRequest().TargetTenantID) {
		t.Fatalf("finish params = %#v", unit.finishParams)
	}
}

func TestTenantSwitchCoordinatorReplayDoesNotGenerateOrRotate(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	unit.bindRow.MappingState = "replay"
	unit.bindRow.Generation++
	unit.claimRow = sqlcgen.ClaimIdempotencyKeyRow{
		ClaimState:     "replay",
		ResponseStatus: 200,
		ResponseBody:   tenantSwitchHTTPResponseBody(),
		CorrelationID:  validTenantSwitchRequest().CorrelationID,
	}
	coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
	got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if err != nil {
		t.Fatalf("Switch() replay error = %v", err)
	}
	if !got.Replay || got.SessionToken != "" || got.CSRFToken != "" {
		t.Fatalf("replay result leaked mutation/cookies = %#v", got)
	}
	if got.ResponseStatus != 200 || got.CorrelationID != validTenantSwitchRequest().CorrelationID || got.Generation != 8 || got.ActiveTenantID != unit.bindRow.ActiveTenantID || got.ActiveWorkspaceID != unit.bindRow.ActiveWorkspaceID {
		t.Fatalf("replay result = %#v", got)
	}
	if unit.switchCalls != 0 || unit.completeCalls != 0 || unit.finishCalls != 0 {
		t.Fatalf("replay performed mutation calls: switch:%d complete:%d finish:%d", unit.switchCalls, unit.completeCalls, unit.finishCalls)
	}
}

func TestTenantSwitchCoordinatorMapsScopeStatesWithoutMutation(t *testing.T) {
	t.Parallel()

	for _, stateErr := range []struct {
		state string
		want  error
	}{
		{state: "conflict", want: ErrTenantSwitchScopeConflict},
		{state: "in_progress", want: ErrTenantSwitchInProgress},
		{state: "stale", want: ErrTenantSwitchStale},
	} {
		t.Run(stateErr.state, func(t *testing.T) {
			t.Parallel()
			unit := claimedTenantSwitchUnit()
			unit.bindRow.MappingState = stateErr.state
			coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
			got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
			if !errors.Is(err, stateErr.want) {
				t.Fatalf("Switch() error = %v, want errors.Is(_, %v)", err, stateErr.want)
			}
			if !reflect.DeepEqual(got, TenantSwitchResult{}) {
				t.Fatalf("failed scope returned result = %#v", got)
			}
			if unit.claimCalls != 0 || unit.switchCalls != 0 || unit.completeCalls != 0 || unit.finishCalls != 0 {
				t.Fatalf("scope state mutated: claim:%d switch:%d complete:%d finish:%d", unit.claimCalls, unit.switchCalls, unit.completeCalls, unit.finishCalls)
			}
		})
	}
}

func TestTenantSwitchCoordinatorMapsGenericClaimConflictsWithoutMutation(t *testing.T) {
	t.Parallel()

	for _, stateErr := range []struct {
		state string
		want  error
	}{
		{state: "conflict", want: ErrTenantSwitchScopeConflict},
		{state: "in_progress", want: ErrTenantSwitchInProgress},
	} {
		t.Run(stateErr.state, func(t *testing.T) {
			t.Parallel()
			unit := claimedTenantSwitchUnit()
			unit.claimRow = sqlcgen.ClaimIdempotencyKeyRow{ClaimState: stateErr.state, CorrelationID: tenantSwitchUUID(9)}
			coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
			got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
			if !errors.Is(err, stateErr.want) {
				t.Fatalf("Switch() error = %v, want errors.Is(_, %v)", err, stateErr.want)
			}
			if !reflect.DeepEqual(got, TenantSwitchResult{}) || unit.switchCalls != 0 || unit.completeCalls != 0 || unit.finishCalls != 0 {
				t.Fatalf("generic claim state mutated or leaked result: result=%#v calls=%d/%d/%d", got, unit.switchCalls, unit.completeCalls, unit.finishCalls)
			}
		})
	}
}

func TestTenantSwitchCoordinatorRejectsInvalidScopeAndMalformedReplayOutcome(t *testing.T) {
	t.Parallel()

	t.Run("unknown mapping state", func(t *testing.T) {
		unit := claimedTenantSwitchUnit()
		unit.bindRow.MappingState = "other"
		coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
		if _, err := coordinator.Switch(context.Background(), validTenantSwitchRequest()); !errors.Is(err, ErrInvalidTenantSwitchScope) {
			t.Fatalf("Switch() error = %v, want ErrInvalidTenantSwitchScope", err)
		}
	})

	for _, mutate := range []struct {
		name string
		fn   func(*sqlcgen.BindTenantSwitchIdempotencyRow)
	}{
		{name: "missing session", fn: func(row *sqlcgen.BindTenantSwitchIdempotencyRow) { row.SessionID = pgtype.UUID{} }},
		{name: "missing receipt hash", fn: func(row *sqlcgen.BindTenantSwitchIdempotencyRow) { row.ReceiptHash = "" }},
		{name: "wrong receipt hash", fn: func(row *sqlcgen.BindTenantSwitchIdempotencyRow) {
			row.ReceiptHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{name: "receipt after session", fn: func(row *sqlcgen.BindTenantSwitchIdempotencyRow) {
			row.ReceiptExpiresAt.Time = row.SessionExpiresAt.Time.Add(time.Minute)
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			unit := claimedTenantSwitchUnit()
			mutate.fn(&unit.bindRow)
			coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
			if _, err := coordinator.Switch(context.Background(), validTenantSwitchRequest()); !errors.Is(err, ErrInvalidTenantSwitchScope) {
				t.Fatalf("Switch() error = %v, want ErrInvalidTenantSwitchScope", err)
			}
			if unit.claimCalls != 0 || unit.switchCalls != 0 {
				t.Fatal("invalid scope reached idempotency or session mutation")
			}
		})
	}

	t.Run("malformed replay outcome", func(t *testing.T) {
		unit := claimedTenantSwitchUnit()
		unit.bindRow.MappingState = "replay"
		unit.claimRow = sqlcgen.ClaimIdempotencyKeyRow{
			ClaimState:     "replay",
			ResponseStatus: 200,
			ResponseBody:   []byte(`{"identity":{"id":"not-a-uuid"}}`),
			CorrelationID:  validTenantSwitchRequest().CorrelationID,
		}
		coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
		if _, err := coordinator.Switch(context.Background(), validTenantSwitchRequest()); !errors.Is(err, ErrInvalidTenantSwitchOutcome) {
			t.Fatalf("Switch() error = %v, want ErrInvalidTenantSwitchOutcome", err)
		}
		if unit.switchCalls != 0 || unit.completeCalls != 0 || unit.finishCalls != 0 {
			t.Fatal("malformed replay outcome reached mutation boundary")
		}
	})

	t.Run("replay status is immutable success", func(t *testing.T) {
		unit := claimedTenantSwitchUnit()
		unit.bindRow.MappingState = "replay"
		unit.bindRow.Generation++
		unit.claimRow = sqlcgen.ClaimIdempotencyKeyRow{
			ClaimState:     "replay",
			ResponseStatus: 201,
			ResponseBody:   []byte(`{"active_tenant_id":"00000000-0000-0000-0000-000000000002","active_workspace_id":"00000000-0000-0000-0000-000000000004","session_generation":8,"session_expires_at":"2026-09-09T12:00:00Z"}`),
			CorrelationID:  validTenantSwitchRequest().CorrelationID,
		}
		coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
		if _, err := coordinator.Switch(context.Background(), validTenantSwitchRequest()); !errors.Is(err, ErrInvalidTenantSwitchPair) {
			t.Fatalf("Switch() error = %v, want ErrInvalidTenantSwitchPair", err)
		}
	})

	t.Run("historical workspace is not replaced by a fresh selection", func(t *testing.T) {
		unit := claimedTenantSwitchUnit()
		unit.bindRow.MappingState = "replay"
		unit.bindRow.Generation++
		unit.bindRow.ActiveWorkspaceID = tenantSwitchUUID(5)
		unit.claimRow = sqlcgen.ClaimIdempotencyKeyRow{
			ClaimState:     "replay",
			ResponseStatus: 200,
			ResponseBody:   []byte(`{"active_tenant_id":"00000000-0000-0000-0000-000000000002","active_workspace_id":"00000000-0000-0000-0000-000000000004","session_generation":8,"session_expires_at":"2026-09-09T12:00:00Z"}`),
			CorrelationID:  validTenantSwitchRequest().CorrelationID,
		}
		coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
		got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
		if err != nil {
			t.Fatalf("Switch() historical replay error = %v", err)
		}
		if !got.Replay || got.ActiveWorkspaceID != tenantSwitchUUID(4) {
			t.Fatalf("historical workspace was not preserved: %#v", got)
		}
	})
}

func TestTenantSwitchCoordinatorRejectsGenerationMismatch(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	unit.finishRow.ResultGeneration++
	coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
	if _, err := coordinator.Switch(context.Background(), validTenantSwitchRequest()); !errors.Is(err, ErrInvalidTenantSwitchOutcome) {
		t.Fatalf("Switch() error = %v, want ErrInvalidTenantSwitchOutcome", err)
	}
}

func TestTenantSwitchCoordinatorValidatesRequestBeforeDatabase(t *testing.T) {
	t.Parallel()

	for _, mutate := range []struct {
		name string
		fn   func(*TenantSwitchRequest)
	}{
		{name: "missing token", fn: func(request *TenantSwitchRequest) { request.PresentedSessionToken = "" }},
		{name: "invalid tenant", fn: func(request *TenantSwitchRequest) { request.TargetTenantID = pgtype.UUID{} }},
		{name: "short key", fn: func(request *TenantSwitchRequest) { request.IdempotencyKey = "short" }},
		{name: "invalid correlation", fn: func(request *TenantSwitchRequest) { request.CorrelationID = pgtype.UUID{} }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			unit := claimedTenantSwitchUnit()
			request := validTenantSwitchRequest()
			mutate.fn(&request)
			coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
			if _, err := coordinator.Switch(context.Background(), request); !errors.Is(err, ErrInvalidTenantSwitchRequest) {
				t.Fatalf("Switch() error = %v, want ErrInvalidTenantSwitchRequest", err)
			}
			if unit.bindCalls != 0 {
				t.Fatal("invalid request reached database boundary")
			}
		})
	}
}

func TestTenantSwitchCoordinatorRollsBackWithoutLeakingSecrets(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	callbackErr := errors.New("completion failed")
	unit.completeErr = callbackErr
	coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
	got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if !errors.Is(err, callbackErr) {
		t.Fatalf("Switch() error = %v, want errors.Is(_, %v)", err, callbackErr)
	}
	if !reflect.DeepEqual(got, TenantSwitchResult{}) {
		t.Fatalf("failed transaction returned secrets/result = %#v", got)
	}
}

func TestTenantSwitchCoordinatorTreatsCommitUncertaintyAsReauthenticationBoundary(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	coordinator, coordinatorErr := newTenantSwitchCoordinator(func(ctx context.Context, fn func(context.Context, tenantSwitchUnit) error) error {
		if err := fn(ctx, unit); err != nil {
			return err
		}
		return db.ErrTransactionCommit
	})
	if coordinatorErr != nil {
		t.Fatalf("newTenantSwitchCoordinator() error = %v", coordinatorErr)
	}
	got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if !errors.Is(err, ErrUncertainTenantSwitchCommit) || !errors.Is(err, db.ErrTransactionCommit) {
		t.Fatalf("Switch() error = %v, want uncertain commit and underlying commit marker", err)
	}
	if !reflect.DeepEqual(got, TenantSwitchResult{}) {
		t.Fatalf("uncertain commit returned secrets/result = %#v", got)
	}
	if unit.switchCalls != 1 || unit.completeCalls != 1 || unit.finishCalls != 1 {
		t.Fatalf("commit uncertainty did not execute the callback before discarding pending result: switch:%d complete:%d finish:%d", unit.switchCalls, unit.completeCalls, unit.finishCalls)
	}
}

func containsSecret(body []byte, secret string) bool {
	if secret == "" {
		return false
	}
	return strings.Contains(string(body), secret)
}

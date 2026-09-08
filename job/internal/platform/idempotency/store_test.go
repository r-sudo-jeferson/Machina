package idempotency

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingQueries struct {
	claimParams    sqlcgen.ClaimIdempotencyKeyParams
	claimCalls     int
	claimRow       sqlcgen.ClaimIdempotencyKeyRow
	claimErr       error
	completeParams sqlcgen.CompleteIdempotencyKeyParams
	completeCalls  int
	completeResult bool
	completeErr    error
}

func (q *recordingQueries) ClaimIdempotencyKey(_ context.Context, arg sqlcgen.ClaimIdempotencyKeyParams) (sqlcgen.ClaimIdempotencyKeyRow, error) {
	q.claimCalls++
	q.claimParams = arg
	return q.claimRow, q.claimErr
}

func (q *recordingQueries) CompleteIdempotencyKey(_ context.Context, arg sqlcgen.CompleteIdempotencyKeyParams) (bool, error) {
	q.completeCalls++
	q.completeParams = arg
	q.completeParams.ResponseBody = append([]byte(nil), arg.ResponseBody...)
	return q.completeResult, q.completeErr
}

func TestStoreClaimMapsTypedStatesAndPreservesStoredCorrelation(t *testing.T) {
	t.Parallel()

	requestedCorrelation := uuid(1)
	storedCorrelation := uuid(2)
	expiresAt := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		row        sqlcgen.ClaimIdempotencyKeyRow
		wantState  State
		wantStatus int
		wantBody   []byte
		wantCorr   pgtype.UUID
	}{
		{
			name:      "claimed",
			row:       sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "claimed", CorrelationID: requestedCorrelation},
			wantState: StateClaimed,
			wantCorr:  requestedCorrelation,
		},
		{
			name:      "in progress",
			row:       sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "in_progress", CorrelationID: storedCorrelation},
			wantState: StateInProgress,
			wantCorr:  storedCorrelation,
		},
		{
			name:      "conflict",
			row:       sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "conflict", CorrelationID: storedCorrelation},
			wantState: StateConflict,
			wantCorr:  storedCorrelation,
		},
		{
			name:       "replay",
			row:        sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "replay", ResponseStatus: 200, ResponseBody: []byte(`{"ok":true}`), CorrelationID: storedCorrelation},
			wantState:  StateReplay,
			wantStatus: 200,
			wantBody:   []byte(`{"ok":true}`),
			wantCorr:   storedCorrelation,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			queries := &recordingQueries{claimRow: tc.row}
			store, err := NewStore(queries)
			if err != nil {
				t.Fatalf("NewStore() error = %v", err)
			}
			got, err := store.Claim(context.Background(), ClaimRequest{
				Key:           "tenant-switch-key-0001",
				Operation:     "tenant.switch",
				RequestHash:   hashA,
				CorrelationID: requestedCorrelation,
				ExpiresAt:     expiresAt,
			})
			if err != nil {
				t.Fatalf("Claim() error = %v", err)
			}
			if got.State != tc.wantState || got.ResponseStatus != tc.wantStatus || !reflect.DeepEqual(got.ResponseBody, tc.wantBody) || got.CorrelationID != tc.wantCorr {
				t.Fatalf("Claim() = %#v", got)
			}
			if queries.claimCalls != 1 {
				t.Fatalf("ClaimIdempotencyKey() calls = %d, want 1", queries.claimCalls)
			}
			if queries.claimParams.IdempotencyKey != "tenant-switch-key-0001" || queries.claimParams.Operation != "tenant.switch" || queries.claimParams.RequestHash != hashA || queries.claimParams.CorrelationID != requestedCorrelation || !queries.claimParams.ExpiresAt.Valid || !queries.claimParams.ExpiresAt.Time.Equal(expiresAt) {
				t.Fatalf("ClaimIdempotencyKey() params = %#v", queries.claimParams)
			}
		})
	}
}

func TestStoreClaimRejectsInvalidDatabaseStateFailClosed(t *testing.T) {
	t.Parallel()

	requestedCorrelation := uuid(3)
	storedCorrelation := uuid(4)
	valid := ClaimRequest{Key: "tenant-switch-key-0002", Operation: "tenant.switch", RequestHash: hashA, CorrelationID: requestedCorrelation, ExpiresAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}

	cases := []struct {
		name string
		row  sqlcgen.ClaimIdempotencyKeyRow
	}{
		{name: "unknown state", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "unknown", CorrelationID: storedCorrelation}},
		{name: "missing correlation", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "claimed"}},
		{name: "claimed correlation mismatch", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "claimed", CorrelationID: storedCorrelation}},
		{name: "claimed carries response status", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "claimed", ResponseStatus: 200, CorrelationID: requestedCorrelation}},
		{name: "in progress carries response status", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "in_progress", ResponseStatus: 200, CorrelationID: storedCorrelation}},
		{name: "conflict carries response status", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "conflict", ResponseStatus: 409, CorrelationID: storedCorrelation}},
		{name: "replay missing response status", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "replay", CorrelationID: storedCorrelation}},
		{name: "replay invalid low status", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "replay", ResponseStatus: 99, CorrelationID: storedCorrelation}},
		{name: "replay invalid high status", row: sqlcgen.ClaimIdempotencyKeyRow{ClaimState: "replay", ResponseStatus: 600, CorrelationID: storedCorrelation}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			queries := &recordingQueries{claimRow: tc.row}
			store, err := NewStore(queries)
			if err != nil {
				t.Fatalf("NewStore() error = %v", err)
			}
			if _, err := store.Claim(context.Background(), valid); !errors.Is(err, ErrInvalidClaimResult) {
				t.Fatalf("Claim() error = %v, want ErrInvalidClaimResult", err)
			}
		})
	}
}

func TestStoreRejectsInvalidClaimInputBeforeDatabase(t *testing.T) {
	t.Parallel()

	valid := ClaimRequest{Key: "tenant-switch-key-0003", Operation: "tenant.switch", RequestHash: hashA, CorrelationID: uuid(5), ExpiresAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
	cases := []struct {
		name   string
		mutate func(*ClaimRequest)
	}{
		{name: "short key", mutate: func(r *ClaimRequest) { r.Key = "short" }},
		{name: "long key", mutate: func(r *ClaimRequest) { r.Key = string(make([]byte, 129)) }},
		{name: "empty operation", mutate: func(r *ClaimRequest) { r.Operation = "" }},
		{name: "long operation", mutate: func(r *ClaimRequest) { r.Operation = string(make([]byte, 161)) }},
		{name: "short hash", mutate: func(r *ClaimRequest) { r.RequestHash = "abc" }},
		{name: "uppercase hash", mutate: func(r *ClaimRequest) {
			r.RequestHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}},
		{name: "invalid correlation", mutate: func(r *ClaimRequest) { r.CorrelationID = pgtype.UUID{} }},
		{name: "missing expiry", mutate: func(r *ClaimRequest) { r.ExpiresAt = time.Time{} }},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			request := valid
			tc.mutate(&request)
			queries := &recordingQueries{}
			store, err := NewStore(queries)
			if err != nil {
				t.Fatalf("NewStore() error = %v", err)
			}
			if _, err := store.Claim(context.Background(), request); !errors.Is(err, ErrInvalidClaimRequest) {
				t.Fatalf("Claim() error = %v, want ErrInvalidClaimRequest", err)
			}
			if queries.claimCalls != 0 {
				t.Fatal("invalid claim input reached database boundary")
			}
		})
	}
}

func TestStoreCompleteValidatesAndPreservesDatabaseFailure(t *testing.T) {
	t.Parallel()

	queries := &recordingQueries{completeResult: true}
	store, err := NewStore(queries)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	response := []byte(`{"active_tenant_id":"tenant-a"}`)
	if err := store.Complete(context.Background(), Completion{
		Key:            "tenant-switch-key-0004",
		Operation:      "tenant.switch",
		RequestHash:    hashA,
		ResponseStatus: 200,
		ResponseBody:   response,
	}); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if queries.completeCalls != 1 || queries.completeParams.IdempotencyKey != "tenant-switch-key-0004" || queries.completeParams.Operation != "tenant.switch" || queries.completeParams.RequestHash != hashA || queries.completeParams.ResponseStatus != 200 || !reflect.DeepEqual(queries.completeParams.ResponseBody, response) {
		t.Fatalf("CompleteIdempotencyKey() = %#v calls=%d", queries.completeParams, queries.completeCalls)
	}

	wantErr := errors.New("database unavailable")
	queries = &recordingQueries{completeErr: wantErr}
	store, _ = NewStore(queries)
	if err := store.Complete(context.Background(), Completion{Key: "tenant-switch-key-0005", Operation: "tenant.switch", RequestHash: hashA, ResponseStatus: 200, ResponseBody: response}); !errors.Is(err, wantErr) {
		t.Fatalf("Complete() error = %v, want errors.Is(_, %v)", err, wantErr)
	}
}

func TestStoreCompleteRejectsInvalidInputAndInvalidDatabaseResult(t *testing.T) {
	t.Parallel()

	valid := Completion{Key: "tenant-switch-key-0006", Operation: "tenant.switch", RequestHash: hashA, ResponseStatus: 200, ResponseBody: []byte(`{"ok":true}`)}
	cases := []struct {
		name   string
		mutate func(*Completion)
	}{
		{name: "short key", mutate: func(c *Completion) { c.Key = "short" }},
		{name: "empty operation", mutate: func(c *Completion) { c.Operation = "" }},
		{name: "invalid hash", mutate: func(c *Completion) { c.RequestHash = "invalid" }},
		{name: "status too low", mutate: func(c *Completion) { c.ResponseStatus = 99 }},
		{name: "status too high", mutate: func(c *Completion) { c.ResponseStatus = 600 }},
		{name: "invalid json body", mutate: func(c *Completion) { c.ResponseBody = []byte(`{"broken"`) }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			completion := valid
			tc.mutate(&completion)
			queries := &recordingQueries{}
			store, err := NewStore(queries)
			if err != nil {
				t.Fatalf("NewStore() error = %v", err)
			}
			if err := store.Complete(context.Background(), completion); !errors.Is(err, ErrInvalidCompletion) {
				t.Fatalf("Complete() error = %v, want ErrInvalidCompletion", err)
			}
			if queries.completeCalls != 0 {
				t.Fatal("invalid completion reached database boundary")
			}
		})
	}

	queries := &recordingQueries{completeResult: false}
	store, _ := NewStore(queries)
	if err := store.Complete(context.Background(), valid); !errors.Is(err, ErrInvalidCompletionResult) {
		t.Fatalf("Complete() error = %v, want ErrInvalidCompletionResult", err)
	}
}

func TestStorePreservesClaimDatabaseFailureAndRejectsNilConfiguration(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("database unavailable")
	queries := &recordingQueries{claimErr: wantErr}
	store, err := NewStore(queries)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	_, err = store.Claim(context.Background(), ClaimRequest{Key: "tenant-switch-key-0007", Operation: "tenant.switch", RequestHash: hashA, CorrelationID: uuid(7), ExpiresAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Claim() error = %v, want errors.Is(_, %v)", err, wantErr)
	}

	if _, err := NewStore(nil); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("NewStore(nil) error = %v, want ErrInvalidStoreConfig", err)
	}
}

func uuid(last byte) pgtype.UUID {
	var value [16]byte
	value[15] = last
	return pgtype.UUID{Bytes: value, Valid: true}
}

const hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type lifecycleRecordingTx struct {
	*recordingTx
	tenantContext       string
	commitErr           error
	commitCalls         int
	rollbackCalls       int
	rollbackContextErr  error
	rollbackDeadline    time.Time
	rollbackHasDeadline bool
}

func (tx *lifecycleRecordingTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := tx.recordingTx.Exec(ctx, sql, args...)
	if err == nil && sql == "SELECT set_config('app.tenant_id', '', true)" && len(args) == 0 {
		tx.tenantContext = ""
	}
	return tag, err
}

func (tx *lifecycleRecordingTx) Commit(ctx context.Context) error {
	tx.commitCalls++
	if tx.commitErr != nil {
		return tx.commitErr
	}
	return tx.recordingTx.Commit(ctx)
}

func (tx *lifecycleRecordingTx) Rollback(ctx context.Context) error {
	tx.rollbackCalls++
	tx.rollbackContextErr = ctx.Err()
	tx.rollbackDeadline, tx.rollbackHasDeadline = ctx.Deadline()
	return tx.recordingTx.Rollback(ctx)
}

type beginFunc func(context.Context) (transaction, error)

func (fn beginFunc) Begin(ctx context.Context) (transaction, error) {
	return fn(ctx)
}

func TestWithinUnscopedClearsInheritedTenantBeforeCallbackAndCommits(t *testing.T) {
	t.Parallel()

	tx := &lifecycleRecordingTx{
		recordingTx:   &recordingTx{},
		tenantContext: "00000000-0000-0000-0000-0000000000a1",
	}
	transactor := newTransactor(recordingBeginner{tx: tx})
	callbackCalls := 0

	err := transactor.WithinUnscoped(context.Background(), func(_ context.Context, q *sqlcgen.Queries) error {
		callbackCalls++
		if len(tx.execs) != 1 || tx.execs[0].sql != "SELECT set_config('app.tenant_id', '', true)" || len(tx.execs[0].args) != 0 {
			t.Fatalf("callback exposed before parameter-free transaction-local tenant clear: %#v", tx.execs)
		}
		if tx.tenantContext != "" {
			t.Fatalf("callback inherited tenant context %q", tx.tenantContext)
		}
		if q == nil {
			t.Fatal("callback received nil transaction queries")
		}
		if tx.commitCalls != 0 {
			t.Fatal("transaction committed before callback completed")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithinUnscoped() error = %v", err)
	}
	if callbackCalls != 1 || tx.commitCalls != 1 || !tx.committed || tx.rollbackCalls != 0 {
		t.Fatalf("lifecycle = callback %d, commit %d, committed %t, rollback %d", callbackCalls, tx.commitCalls, tx.committed, tx.rollbackCalls)
	}
}

func TestWithinUnscopedRollsBackCallbackFailure(t *testing.T) {
	t.Parallel()

	callbackErr := errors.New("callback failed")
	tx := &lifecycleRecordingTx{recordingTx: &recordingTx{}}
	transactor := newTransactor(recordingBeginner{tx: tx})

	err := transactor.WithinUnscoped(context.Background(), func(context.Context, *sqlcgen.Queries) error {
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatalf("WithinUnscoped() error = %v, want callback error", err)
	}
	if errors.Is(err, ErrTransactionCommit) {
		t.Fatal("callback failure incorrectly reported as a commit failure")
	}
	if tx.commitCalls != 0 || tx.rollbackCalls != 1 || !tx.rolledBack {
		t.Fatalf("failed callback lifecycle = commit %d, rollback %d, rolled back %t", tx.commitCalls, tx.rollbackCalls, tx.rolledBack)
	}
}

func TestWithinUnscopedFailsClosedWhenTenantClearFails(t *testing.T) {
	t.Parallel()

	clearErr := errors.New("tenant clear failed")
	tx := &lifecycleRecordingTx{
		recordingTx:   &recordingTx{execErr: clearErr},
		tenantContext: "00000000-0000-0000-0000-0000000000a1",
	}
	transactor := newTransactor(recordingBeginner{tx: tx})
	callbackCalled := false

	err := transactor.WithinUnscoped(context.Background(), func(context.Context, *sqlcgen.Queries) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, clearErr) {
		t.Fatalf("WithinUnscoped() error = %v, want clear error", err)
	}
	if callbackCalled || tx.commitCalls != 0 || tx.rollbackCalls != 1 {
		t.Fatalf("failed clear lifecycle = callback %t, commit %d, rollback %d", callbackCalled, tx.commitCalls, tx.rollbackCalls)
	}
}

func TestTransactionsIdentifyCommitFailureAndPreserveDriverCause(t *testing.T) {
	t.Parallel()

	for _, scope := range []string{"unscoped", "tenant"} {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()

			driverErr := &pgconn.PgError{Code: "08006", Message: "connection failure during commit"}
			tx := &lifecycleRecordingTx{recordingTx: &recordingTx{}, commitErr: driverErr}
			transactor := newTransactor(recordingBeginner{tx: tx})
			callback := func(context.Context, *sqlcgen.Queries) error { return nil }
			var err error
			if scope == "tenant" {
				err = transactor.WithinTenant(context.Background(), "00000000-0000-0000-0000-0000000000a1", callback)
			} else {
				err = transactor.WithinUnscoped(context.Background(), callback)
			}
			var gotDriverErr *pgconn.PgError
			if !errors.Is(err, ErrTransactionCommit) || !errors.Is(err, driverErr) || !errors.As(err, &gotDriverErr) || gotDriverErr != driverErr {
				t.Fatalf("commit error = %v, want commit classification and original driver cause", err)
			}
			if tx.commitCalls != 1 || tx.rollbackCalls != 1 {
				t.Fatalf("failed commit lifecycle = commit %d, rollback %d", tx.commitCalls, tx.rollbackCalls)
			}
		})
	}
}

func TestWithinUnscopedRollsBackWithIndependentBoundedContextAfterCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx := &lifecycleRecordingTx{recordingTx: &recordingTx{}}
	transactor := newTransactor(recordingBeginner{tx: tx})
	started := time.Now()

	err := transactor.WithinUnscoped(ctx, func(callbackCtx context.Context, _ *sqlcgen.Queries) error {
		cancel()
		return callbackCtx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WithinUnscoped() error = %v, want context cancellation", err)
	}
	if tx.rollbackCalls != 1 || tx.rollbackContextErr != nil {
		t.Fatalf("rollback calls = %d, context error = %v", tx.rollbackCalls, tx.rollbackContextErr)
	}
	if !tx.rollbackHasDeadline || !tx.rollbackDeadline.After(started) || tx.rollbackDeadline.After(time.Now().Add(5*time.Second)) {
		t.Fatalf("rollback deadline = %v, present = %t, want independent deadline bounded by 5 seconds", tx.rollbackDeadline, tx.rollbackHasDeadline)
	}
	if tx.commitCalls != 0 {
		t.Fatal("canceled callback attempted commit")
	}
}

func TestWithinUnscopedRejectsUnconfiguredTransactor(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		transactor *Transactor
	}{
		{name: "nil receiver"},
		{name: "zero transactor", transactor: &Transactor{}},
		{name: "nil pool", transactor: NewTransactor(nil)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			callbackCalled := false
			err := tt.transactor.WithinUnscoped(context.Background(), func(context.Context, *sqlcgen.Queries) error {
				callbackCalled = true
				return nil
			})
			if err == nil || callbackCalled {
				t.Fatalf("unconfigured transaction error = %v, callback called = %t", err, callbackCalled)
			}
		})
	}
}

func TestWithinUnscopedRejectsNilCallbackBeforeBegin(t *testing.T) {
	t.Parallel()

	beginCalls := 0
	transactor := newTransactor(beginFunc(func(context.Context) (transaction, error) {
		beginCalls++
		return &recordingTx{}, nil
	}))
	if err := transactor.WithinUnscoped(context.Background(), nil); err == nil || beginCalls != 0 {
		t.Fatalf("nil callback error = %v, begin calls = %d", err, beginCalls)
	}
}

func TestWithinUnscopedPreservesBeginFailureAndSkipsCallback(t *testing.T) {
	t.Parallel()

	beginErr := errors.New("begin failed")
	beginCalls := 0
	transactor := newTransactor(beginFunc(func(context.Context) (transaction, error) {
		beginCalls++
		return nil, beginErr
	}))
	callbackCalled := false
	err := transactor.WithinUnscoped(context.Background(), func(context.Context, *sqlcgen.Queries) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, beginErr) || beginCalls != 1 || callbackCalled {
		t.Fatalf("begin failure = %v, begin calls = %d, callback called = %t", err, beginCalls, callbackCalled)
	}
}

func TestWithinTenantPreservesUUIDCastAndRejectsMissingTenantBeforeBegin(t *testing.T) {
	t.Parallel()

	tx := &recordingTx{}
	transactor := newTransactor(recordingBeginner{tx: tx})
	err := transactor.WithinTenant(context.Background(), "00000000-0000-0000-0000-0000000000a1", func(context.Context, *sqlcgen.Queries) error {
		if len(tx.execs) != 1 || tx.execs[0].sql != "SELECT set_config('app.tenant_id', $1::uuid::text, true)" {
			t.Fatalf("tenant setup lost UUID validation or local scope: %#v", tx.execs)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithinTenant() error = %v", err)
	}
	beginCalls := 0
	transactor = newTransactor(beginFunc(func(context.Context) (transaction, error) {
		beginCalls++
		return &recordingTx{}, nil
	}))
	err = transactor.WithinTenant(context.Background(), "", func(context.Context, *sqlcgen.Queries) error { return nil })
	if err == nil || beginCalls != 0 {
		t.Fatalf("missing tenant error = %v, begin calls = %d", err, beginCalls)
	}
}

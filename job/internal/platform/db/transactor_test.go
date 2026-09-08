package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordedExec struct {
	sql  string
	args []any
}

type recordingTx struct {
	execs      []recordedExec
	committed  bool
	rolledBack bool
}

func (tx *recordingTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.execs = append(tx.execs, recordedExec{sql: sql, args: args})
	return pgconn.NewCommandTag("SELECT 1"), nil
}

func (*recordingTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (*recordingTx) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected QueryRow call")
}

func (tx *recordingTx) Commit(context.Context) error {
	tx.committed = true
	return nil
}

func (tx *recordingTx) Rollback(context.Context) error {
	tx.rolledBack = true
	return nil
}

type recordingBeginner struct {
	tx transaction
}

func (b recordingBeginner) Begin(context.Context) (transaction, error) {
	return b.tx, nil
}

func TestWithinTenantSetsTransactionLocalTenantBeforeCallbackAndCommits(t *testing.T) {
	t.Parallel()

	const tenantID = "00000000-0000-0000-0000-0000000000a1"
	tx := &recordingTx{}
	transactor := newTransactor(recordingBeginner{tx: tx})
	callbackCalled := false

	err := transactor.WithinTenant(context.Background(), tenantID, func(_ context.Context, _ *sqlcgen.Queries) error {
		callbackCalled = true
		if len(tx.execs) != 1 {
			t.Fatalf("tenant context exec count = %d, want 1", len(tx.execs))
		}
		if !strings.Contains(tx.execs[0].sql, "set_config('app.tenant_id'") {
			t.Fatalf("tenant context SQL = %q, want transaction-local app.tenant_id setup", tx.execs[0].sql)
		}
		if len(tx.execs[0].args) != 1 || tx.execs[0].args[0] != tenantID {
			t.Fatalf("tenant context args = %#v, want [%q]", tx.execs[0].args, tenantID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithinTenant() error = %v", err)
	}
	if !callbackCalled {
		t.Fatal("WithinTenant() did not execute callback")
	}
	if !tx.committed {
		t.Fatal("WithinTenant() did not commit successful transaction")
	}
	if tx.rolledBack {
		t.Fatal("WithinTenant() rolled back successful transaction")
	}
}

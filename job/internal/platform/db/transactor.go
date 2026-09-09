package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

const rollbackTimeout = 5 * time.Second

// ErrTransactionCommit marks a failed commit attempt whose underlying driver
// error remains available through errors.Is and errors.As. Callers must not
// assume that the transaction was rolled back when commit returns an error.
var ErrTransactionCommit = errors.New("database transaction commit failed")

type transaction interface {
	sqlcgen.DBTX
	Commit(context.Context) error
	Rollback(context.Context) error
}

type beginner interface {
	Begin(context.Context) (transaction, error)
}

type pgxPoolBeginner struct {
	pool *pgxpool.Pool
}

func (b pgxPoolBeginner) Begin(ctx context.Context) (transaction, error) {
	return b.pool.Begin(ctx)
}

type Transactor struct {
	begin beginner
}

func NewTransactor(pool *pgxpool.Pool) *Transactor {
	if pool == nil {
		return &Transactor{}
	}
	return newTransactor(pgxPoolBeginner{pool: pool})
}

func newTransactor(begin beginner) *Transactor {
	return &Transactor{begin: begin}
}

func (t *Transactor) WithinTenant(
	ctx context.Context,
	tenantID string,
	fn func(context.Context, *sqlcgen.Queries) error,
) error {
	if t == nil || t.begin == nil {
		return errors.New("database transactor is not configured")
	}
	if tenantID == "" {
		return errors.New("tenant id is required")
	}
	if fn == nil {
		return errors.New("tenant transaction callback is required")
	}

	return t.within(ctx, "tenant", func(tx transaction) error {
		if _, err := tx.Exec(
			ctx,
			"SELECT set_config('app.tenant_id', $1::uuid::text, true)",
			tenantID,
		); err != nil {
			return fmt.Errorf("set transaction tenant context: %w", err)
		}
		return nil
	}, fn)
}

// WithinUnscoped clears any inherited tenant context before exposing the
// transaction to fn. A trusted database boundary must establish an authorized
// tenant before fn can access tenant-scoped data.
func (t *Transactor) WithinUnscoped(
	ctx context.Context,
	fn func(context.Context, *sqlcgen.Queries) error,
) error {
	if t == nil || t.begin == nil {
		return errors.New("database transactor is not configured")
	}
	if fn == nil {
		return errors.New("unscoped transaction callback is required")
	}

	return t.within(ctx, "unscoped", func(tx transaction) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', '', true)"); err != nil {
			return fmt.Errorf("clear transaction tenant context: %w", err)
		}
		return nil
	}, fn)
}

func (t *Transactor) within(
	ctx context.Context,
	scope string,
	setup func(transaction) error,
	fn func(context.Context, *sqlcgen.Queries) error,
) error {
	tx, err := t.begin.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %s transaction: %w", scope, err)
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if err := setup(tx); err != nil {
		return err
	}

	if err := fn(ctx, sqlcgen.New(tx)); err != nil {
		return fmt.Errorf("execute %s transaction: %w", scope, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %s transaction: %w: %w", scope, ErrTransactionCommit, err)
	}
	committed = true
	return nil
}

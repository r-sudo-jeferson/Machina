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

	tx, err := t.begin.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
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

	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('app.tenant_id', $1::uuid::text, true)",
		tenantID,
	); err != nil {
		return fmt.Errorf("set transaction tenant context: %w", err)
	}

	if err := fn(ctx, sqlcgen.New(tx)); err != nil {
		return fmt.Errorf("execute tenant transaction: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	committed = true
	return nil
}

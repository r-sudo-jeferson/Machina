package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type PostgresCheckpointStore struct {
	transactor *db.Transactor
}

func NewPostgresCheckpointStore(transactor *db.Transactor) (*PostgresCheckpointStore, error) {
	if transactor == nil {
		return nil, ErrInvalidCheckpointer
	}
	return &PostgresCheckpointStore{transactor: transactor}, nil
}

func (s *PostgresCheckpointStore) Head(ctx context.Context, tenantID pgtype.UUID) (ChainHead, error) {
	if s == nil || s.transactor == nil || ctx == nil || !tenantID.Valid {
		return ChainHead{}, ErrInvalidCheckpoint
	}

	var row sqlcgen.GetAuditChainHeadRow
	err := s.transactor.WithinTenant(ctx, uuidText(tenantID), func(txCtx context.Context, q *sqlcgen.Queries) error {
		var err error
		row, err = q.GetAuditChainHead(txCtx, tenantID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoAuditEvents
		}
		if err != nil {
			return fmt.Errorf("query audit chain head: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNoAuditEvents) {
			return ChainHead{}, ErrNoAuditEvents
		}
		return ChainHead{}, fmt.Errorf("read audit chain head: %w", err)
	}
	if row.LastSequence <= 0 {
		return ChainHead{}, ErrNoAuditEvents
	}
	if len(row.LastChainHash) != len(ChainHead{}.Hash) {
		return ChainHead{}, ErrInvalidCheckpoint
	}

	head := ChainHead{TenantID: tenantID, Sequence: row.LastSequence}
	copy(head.Hash[:], row.LastChainHash)
	if err := validateChainHead(tenantID, head); err != nil {
		return ChainHead{}, err
	}
	return head, nil
}

func (s *PostgresCheckpointStore) Find(
	ctx context.Context,
	tenantID pgtype.UUID,
	chainSequence int64,
	keyID string,
) (StoredCheckpoint, error) {
	if s == nil || s.transactor == nil || ctx == nil || !tenantID.Valid || chainSequence <= 0 || !validCheckpointKeyID(keyID) {
		return StoredCheckpoint{}, ErrInvalidCheckpoint
	}

	var row sqlcgen.AuditCheckpoint
	err := s.transactor.WithinTenant(ctx, uuidText(tenantID), func(txCtx context.Context, q *sqlcgen.Queries) error {
		var err error
		row, err = q.GetAuditCheckpoint(txCtx, sqlcgen.GetAuditCheckpointParams{
			TenantID:      tenantID,
			ChainSequence: chainSequence,
			KeyID:         keyID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCheckpointNotFound
		}
		if err != nil {
			return fmt.Errorf("query audit checkpoint: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrCheckpointNotFound) {
			return StoredCheckpoint{}, ErrCheckpointNotFound
		}
		return StoredCheckpoint{}, fmt.Errorf("find audit checkpoint: %w", err)
	}

	checkpoint, err := storedCheckpointFromRow(row)
	if err != nil {
		return StoredCheckpoint{}, err
	}
	if checkpoint.TenantID != tenantID || checkpoint.ChainSequence != chainSequence || checkpoint.KeyID != keyID {
		return StoredCheckpoint{}, ErrInvalidCheckpoint
	}
	return checkpoint, nil
}

func (s *PostgresCheckpointStore) Insert(ctx context.Context, checkpoint StoredCheckpoint) (StoredCheckpoint, error) {
	if s == nil || s.transactor == nil || ctx == nil {
		return StoredCheckpoint{}, ErrInvalidCheckpoint
	}
	if err := validateStoredCheckpoint(checkpoint); err != nil {
		return StoredCheckpoint{}, err
	}

	var row sqlcgen.AuditCheckpoint
	err := s.transactor.WithinTenant(ctx, uuidText(checkpoint.TenantID), func(txCtx context.Context, q *sqlcgen.Queries) error {
		inserted, err := q.InsertAuditCheckpoint(txCtx, sqlcgen.InsertAuditCheckpointParams{
			TenantID:        checkpoint.TenantID,
			CheckpointID:    checkpoint.ID,
			ChainSequence:   checkpoint.ChainSequence,
			ChainHash:       append([]byte(nil), checkpoint.ChainHash[:]...),
			StatementDigest: append([]byte(nil), checkpoint.StatementDigest[:]...),
			Algorithm:       string(checkpoint.Algorithm),
			KeyID:           checkpoint.KeyID,
			Signature:       append([]byte(nil), checkpoint.Signature...),
			SignedAt: pgtype.Timestamptz{
				Time:  checkpoint.SignedAt.UTC(),
				Valid: true,
			},
		})
		if err == nil {
			row = inserted
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("insert audit checkpoint: %w", err)
		}

		winner, findErr := q.GetAuditCheckpoint(txCtx, sqlcgen.GetAuditCheckpointParams{
			TenantID:      checkpoint.TenantID,
			ChainSequence: checkpoint.ChainSequence,
			KeyID:         checkpoint.KeyID,
		})
		if errors.Is(findErr, pgx.ErrNoRows) {
			return fmt.Errorf("load audit checkpoint conflict winner: %w", ErrCheckpointNotFound)
		}
		if findErr != nil {
			return fmt.Errorf("load audit checkpoint conflict winner: %w", findErr)
		}
		row = winner
		return nil
	})
	if err != nil {
		return StoredCheckpoint{}, fmt.Errorf("persist audit checkpoint: %w", err)
	}

	persisted, err := storedCheckpointFromRow(row)
	if err != nil {
		return StoredCheckpoint{}, err
	}
	if persisted.TenantID != checkpoint.TenantID ||
		persisted.ChainSequence != checkpoint.ChainSequence ||
		persisted.KeyID != checkpoint.KeyID {
		return StoredCheckpoint{}, ErrInvalidCheckpoint
	}
	return persisted, nil
}

func storedCheckpointFromRow(row sqlcgen.AuditCheckpoint) (StoredCheckpoint, error) {
	if !row.TenantID.Valid || !row.ID.Valid || row.ChainSequence <= 0 ||
		len(row.ChainHash) != len(StoredCheckpoint{}.ChainHash) ||
		len(row.StatementDigest) != len(StoredCheckpoint{}.StatementDigest) ||
		!row.SignedAt.Valid {
		return StoredCheckpoint{}, ErrInvalidCheckpoint
	}

	checkpoint := StoredCheckpoint{
		TenantID:      row.TenantID,
		ID:            row.ID,
		ChainSequence: row.ChainSequence,
		Algorithm:     CheckpointAlgorithm(row.Algorithm),
		KeyID:         row.KeyID,
		Signature:     append([]byte(nil), row.Signature...),
		SignedAt:      row.SignedAt.Time.UTC(),
	}
	copy(checkpoint.ChainHash[:], row.ChainHash)
	copy(checkpoint.StatementDigest[:], row.StatementDigest)
	if err := validateStoredCheckpoint(checkpoint); err != nil {
		return StoredCheckpoint{}, err
	}
	return checkpoint, nil
}

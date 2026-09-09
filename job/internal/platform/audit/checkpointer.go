package audit

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrInvalidCheckpointer = errors.New("invalid audit checkpointer")
	ErrCheckpointNotFound = errors.New("audit checkpoint not found")
	ErrNoAuditEvents       = errors.New("audit chain has no events")
)

type ChainHead struct {
	TenantID pgtype.UUID
	Sequence int64
	Hash     [32]byte
}

type CheckpointResult struct {
	Checkpoint StoredCheckpoint
	Replay     bool
}

type CheckpointSigner interface {
	KeyID() string
	PublicKey(context.Context) (*ecdsa.PublicKey, error)
	SignSHA256(context.Context, [32]byte) ([]byte, error)
}

type CheckpointStore interface {
	Head(context.Context, pgtype.UUID) (ChainHead, error)
	Find(context.Context, pgtype.UUID, int64, string) (StoredCheckpoint, error)
	Insert(context.Context, StoredCheckpoint) (StoredCheckpoint, error)
}

type checkpointClock func() time.Time
type checkpointIDGenerator func() (pgtype.UUID, error)

type Checkpointer struct {
	store  CheckpointStore
	signer CheckpointSigner
	now    checkpointClock
	newID  checkpointIDGenerator
}

func NewCheckpointer(
	store CheckpointStore,
	signer CheckpointSigner,
	now func() time.Time,
	newID func() (pgtype.UUID, error),
) (*Checkpointer, error) {
	if store == nil || signer == nil || now == nil || newID == nil {
		return nil, ErrInvalidCheckpointer
	}
	if !validCheckpointKeyID(signer.KeyID()) {
		return nil, ErrInvalidCheckpointer
	}
	return &Checkpointer{store: store, signer: signer, now: now, newID: newID}, nil
}

func (c *Checkpointer) Checkpoint(ctx context.Context, tenantID pgtype.UUID) (CheckpointResult, error) {
	if c == nil || c.store == nil || c.signer == nil || c.now == nil || c.newID == nil || ctx == nil {
		return CheckpointResult{}, ErrInvalidCheckpointer
	}
	if !tenantID.Valid {
		return CheckpointResult{}, ErrInvalidCheckpoint
	}

	head, err := c.store.Head(ctx, tenantID)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("read audit chain head: %w", err)
	}
	if err := validateChainHead(tenantID, head); err != nil {
		return CheckpointResult{}, err
	}

	keyID := c.signer.KeyID()
	if !validCheckpointKeyID(keyID) {
		return CheckpointResult{}, ErrInvalidCheckpointer
	}

	existing, err := c.store.Find(ctx, tenantID, head.Sequence, keyID)
	switch {
	case err == nil:
		if err := validateCheckpointForHead(existing, head, keyID); err != nil {
			return CheckpointResult{}, err
		}
		publicKey, err := c.signer.PublicKey(ctx)
		if err != nil {
			return CheckpointResult{}, fmt.Errorf("load audit checkpoint public key: %w", err)
		}
		if err := VerifyCheckpointSignature(publicKey, existing); err != nil {
			return CheckpointResult{}, err
		}
		return CheckpointResult{Checkpoint: cloneCheckpoint(existing), Replay: true}, nil
	case !errors.Is(err, ErrCheckpointNotFound):
		return CheckpointResult{}, fmt.Errorf("find audit checkpoint: %w", err)
	}

	checkpointID, err := c.newID()
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("generate audit checkpoint id: %w", err)
	}
	if !checkpointID.Valid {
		return CheckpointResult{}, ErrInvalidCheckpoint
	}

	signedAt := c.now().UTC().Truncate(time.Microsecond)
	statement := CheckpointStatement{
		TenantID:      tenantID,
		CheckpointID:  checkpointID,
		ChainSequence: head.Sequence,
		ChainHash:     head.Hash,
		Algorithm:     CheckpointAlgorithmECDSAP256SHA256,
		KeyID:         keyID,
		SignedAt:      signedAt,
	}
	digest, err := DigestCheckpointStatement(statement)
	if err != nil {
		return CheckpointResult{}, err
	}

	signature, err := c.signer.SignSHA256(ctx, digest)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("sign audit checkpoint: %w", err)
	}
	publicKey, err := c.signer.PublicKey(ctx)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("load audit checkpoint public key: %w", err)
	}

	candidate := StoredCheckpoint{
		TenantID:        tenantID,
		ID:              checkpointID,
		ChainSequence:   head.Sequence,
		ChainHash:       head.Hash,
		StatementDigest: digest,
		Algorithm:       CheckpointAlgorithmECDSAP256SHA256,
		KeyID:           keyID,
		Signature:       append([]byte(nil), signature...),
		SignedAt:        signedAt,
	}
	if err := VerifyCheckpointSignature(publicKey, candidate); err != nil {
		return CheckpointResult{}, err
	}

	persisted, err := c.store.Insert(ctx, candidate)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("persist audit checkpoint: %w", err)
	}
	if err := validateCheckpointForHead(persisted, head, keyID); err != nil {
		return CheckpointResult{}, err
	}
	if err := VerifyCheckpointSignature(publicKey, persisted); err != nil {
		return CheckpointResult{}, err
	}

	replay := persisted.ID != candidate.ID || persisted.StatementDigest != candidate.StatementDigest
	return CheckpointResult{Checkpoint: cloneCheckpoint(persisted), Replay: replay}, nil
}

func validateChainHead(tenantID pgtype.UUID, head ChainHead) error {
	if !tenantID.Valid || !head.TenantID.Valid || head.TenantID != tenantID || head.Sequence <= 0 || allZero32(head.Hash) {
		return ErrInvalidCheckpoint
	}
	return nil
}

func validateCheckpointForHead(checkpoint StoredCheckpoint, head ChainHead, keyID string) error {
	if checkpoint.TenantID != head.TenantID || checkpoint.ChainSequence != head.Sequence || checkpoint.ChainHash != head.Hash || checkpoint.KeyID != keyID {
		return ErrInvalidCheckpoint
	}
	return nil
}

func cloneCheckpoint(checkpoint StoredCheckpoint) StoredCheckpoint {
	checkpoint.Signature = append([]byte(nil), checkpoint.Signature...)
	return checkpoint
}

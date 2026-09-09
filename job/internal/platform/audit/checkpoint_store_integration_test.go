package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

func TestPostgresCheckpointStoreRoundTripAndConflictWinner(t *testing.T) {
	databaseURL := os.Getenv("MACHINA_AUDIT_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("MACHINA_AUDIT_DATABASE_URL is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool.Ping() error = %v", err)
	}

	transactor := db.NewTransactor(pool)
	store, err := NewPostgresCheckpointStore(transactor)
	if err != nil {
		t.Fatalf("NewPostgresCheckpointStore() error = %v", err)
	}

	tenantA := auditIntegrationUUID(t, "00000000-0000-0000-0000-0000000000a1")
	tenantB := auditIntegrationUUID(t, "00000000-0000-0000-0000-0000000000b2")
	actorID := auditIntegrationUUID(t, "10000000-0000-0000-0000-0000000000a1")
	eventID := auditIntegrationUUID(t, "40000000-0000-0000-0000-0000000000e1")
	correlationID := auditIntegrationUUID(t, "50000000-0000-0000-0000-0000000000e1")
	metadata, err := NewAuthorizationDecisionMetadata("allow", 3*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
	}

	if err := transactor.WithinTenant(ctx, uuidText(tenantA), func(txCtx context.Context, q *sqlcgen.Queries) error {
		recorder, err := NewRecorder(q)
		if err != nil {
			return fmt.Errorf("create recorder: %w", err)
		}
		return recorder.Record(txCtx, Event{
			TenantID:       tenantA,
			ID:             eventID,
			ActorSubjectID: actorID,
			EventType:      "machina.audit.checkpoint.store.test",
			Action:         "audit.checkpoint.store",
			Decision:       "allow",
			PolicyVersion:  1,
			CorrelationID:  correlationID,
			SafeMetadata:   metadata,
			OccurredAt:     time.Date(2026, 9, 9, 12, 30, 0, 123456000, time.UTC),
		})
	}); err != nil {
		t.Fatalf("record committed audit event: %v", err)
	}

	head, err := store.Head(ctx, tenantA)
	if err != nil {
		t.Fatalf("Head() error = %v", err)
	}
	if head.TenantID != tenantA || head.Sequence <= 0 || allZero32(head.Hash) {
		t.Fatalf("Head() = %#v", head)
	}

	privateKey := mustCheckpointKey(t)
	keyID := "kms/test/postgres-v1"
	if _, err := store.Find(ctx, tenantA, head.Sequence, keyID); !errors.Is(err, ErrCheckpointNotFound) {
		t.Fatalf("Find(missing) error = %v, want ErrCheckpointNotFound", err)
	}

	first := signedCheckpointForHead(
		t,
		privateKey,
		head,
		auditIntegrationUUID(t, "60000000-0000-0000-0000-0000000000e1"),
		keyID,
	)
	inserted, err := store.Insert(ctx, first)
	if err != nil {
		t.Fatalf("Insert(first) error = %v", err)
	}
	if inserted.ID != first.ID || inserted.StatementDigest != first.StatementDigest || inserted.ChainHash != head.Hash {
		t.Fatalf("Insert(first) = %#v, want exact checkpoint", inserted)
	}
	if err := VerifyCheckpointSignature(&privateKey.PublicKey, inserted); err != nil {
		t.Fatalf("VerifyCheckpointSignature(inserted) error = %v", err)
	}

	found, err := store.Find(ctx, tenantA, head.Sequence, keyID)
	if err != nil {
		t.Fatalf("Find(persisted) error = %v", err)
	}
	if found.ID != first.ID || found.StatementDigest != first.StatementDigest {
		t.Fatalf("Find(persisted) = %#v, want first checkpoint", found)
	}

	competitor := signedCheckpointForHead(
		t,
		privateKey,
		head,
		auditIntegrationUUID(t, "60000000-0000-0000-0000-0000000000e2"),
		keyID,
	)
	winner, err := store.Insert(ctx, competitor)
	if err != nil {
		t.Fatalf("Insert(conflict) error = %v", err)
	}
	if winner.ID != first.ID || winner.StatementDigest != first.StatementDigest {
		t.Fatalf("Insert(conflict) winner = %#v, want original checkpoint %#v", winner, first)
	}
	if err := VerifyCheckpointSignature(&privateKey.PublicKey, winner); err != nil {
		t.Fatalf("VerifyCheckpointSignature(winner) error = %v", err)
	}

	if _, err := store.Find(ctx, tenantB, head.Sequence, keyID); !errors.Is(err, ErrCheckpointNotFound) {
		t.Fatalf("Find(other tenant) error = %v, want tenant-isolated ErrCheckpointNotFound", err)
	}
}

func TestNewPostgresCheckpointStoreRejectsNilTransactor(t *testing.T) {
	if _, err := NewPostgresCheckpointStore(nil); !errors.Is(err, ErrInvalidCheckpointer) {
		t.Fatalf("NewPostgresCheckpointStore(nil) error = %v, want ErrInvalidCheckpointer", err)
	}
}

package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

func TestPostgresAuditChainCheckpointerAndTamperEvidence(t *testing.T) {
	databaseURL := os.Getenv("MACHINA_AUDIT_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("MACHINA_AUDIT_DATABASE_URL is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	headBefore, err := store.Head(ctx, tenantA)
	if err != nil {
		t.Fatalf("Head(before) error = %v", err)
	}

	metadata, err := NewAuthorizationDecisionMetadata("deny", 7*time.Millisecond, []string{"explicit_forbid"})
	if err != nil {
		t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
	}
	events := []Event{
		{
			TenantID:       tenantA,
			ID:             auditIntegrationUUID(t, "40000000-0000-0000-0000-0000000000f1"),
			ActorSubjectID: actorID,
			EventType:      "machina.audit.integrity.checkpoint.test",
			Action:         "audit.integrity.verify",
			Decision:       "deny",
			PolicyVersion:  1,
			CorrelationID:  auditIntegrationUUID(t, "50000000-0000-0000-0000-0000000000f1"),
			SafeMetadata:   metadata,
			OccurredAt:     time.Date(2026, 9, 9, 13, 10, 0, 123456789, time.UTC),
		},
		{
			TenantID:       tenantA,
			ID:             auditIntegrationUUID(t, "40000000-0000-0000-0000-0000000000f2"),
			ActorSubjectID: actorID,
			EventType:      "machina.audit.integrity.checkpoint.test",
			Action:         "audit.integrity.verify",
			Decision:       "deny",
			PolicyVersion:  1,
			CorrelationID:  auditIntegrationUUID(t, "50000000-0000-0000-0000-0000000000f2"),
			SafeMetadata:   metadata,
			OccurredAt:     time.Date(2026, 9, 9, 13, 10, 0, 123457789, time.UTC),
		},
	}
	expectedParams := make([]sqlcgen.InsertAuditEventParams, len(events))
	for i, event := range events {
		expectedParams[i], err = Params(event)
		if err != nil {
			t.Fatalf("Params(event %d) error = %v", i, err)
		}
	}

	if err := transactor.WithinTenant(ctx, uuidText(tenantA), func(txCtx context.Context, q *sqlcgen.Queries) error {
		recorder, err := NewRecorder(q)
		if err != nil {
			return fmt.Errorf("create recorder: %w", err)
		}
		for _, event := range events {
			if err := recorder.Record(txCtx, event); err != nil {
				return fmt.Errorf("record event %s: %w", uuidText(event.ID), err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("record committed audit chain: %v", err)
	}

	rows := loadPersistedAuditChainRows(t, ctx, pool, tenantA, events[0].ID, events[1].ID)
	if len(rows) != 2 {
		t.Fatalf("persisted chain rows = %d, want 2", len(rows))
	}
	previous := headBefore.Hash
	for i, row := range rows {
		wantSequence := headBefore.Sequence + int64(i) + 1
		if row.Sequence != wantSequence {
			t.Fatalf("row %d sequence = %d, want %d", i, row.Sequence, wantSequence)
		}
		if !bytes.Equal(row.EventHash, expectedParams[i].EventHash) || !bytes.Equal(row.ChainEventHash, expectedParams[i].EventHash) {
			t.Fatalf("row %d event hash mismatch event=%x chain=%x want=%x", i, row.EventHash, row.ChainEventHash, expectedParams[i].EventHash)
		}
		if !bytes.Equal(row.PreviousChainHash, previous[:]) {
			t.Fatalf("row %d previous chain hash = %x, want %x", i, row.PreviousChainHash, previous)
		}
		wantChain := sha256.Sum256(append(append([]byte(nil), previous[:]...), row.EventHash...))
		if !bytes.Equal(row.ChainHash, wantChain[:]) {
			t.Fatalf("row %d chain hash = %x, want %x", i, row.ChainHash, wantChain)
		}
		stored := row.StoredEvent
		if err := VerifyStoredEventContentHash(stored); err != nil {
			t.Fatalf("VerifyStoredEventContentHash(row %d) error = %v", i, err)
		}
		tampered := stored
		tampered.SafeMetadata = []byte(`{"latency_ms":8,"reason_codes":["explicit_forbid"]}`)
		if err := VerifyStoredEventContentHash(tampered); !errors.Is(err, ErrInvalidEventContentHash) {
			t.Fatalf("VerifyStoredEventContentHash(tampered row %d) error = %v", i, err)
		}
		copy(previous[:], row.ChainHash)
	}

	head, err := store.Head(ctx, tenantA)
	if err != nil {
		t.Fatalf("Head(after) error = %v", err)
	}
	if head.Sequence != headBefore.Sequence+2 || !bytes.Equal(head.Hash[:], rows[1].ChainHash) {
		t.Fatalf("Head(after) = %#v, want sequence=%d hash=%x", head, headBefore.Sequence+2, rows[1].ChainHash)
	}
	assertTenantCannotSeeAuditEvents(t, ctx, pool, tenantB, events[0].ID, events[1].ID)

	privateKey := mustIntegrationCheckpointKey(t)
	signer := &integrationCheckpointSigner{key: privateKey, keyID: "kms/test/postgres-checkpointer-v1"}
	checkpointer := mustIntegrationCheckpointer(t, store, signer, auditIntegrationUUID(t, "60000000-0000-0000-0000-0000000000f1"))
	created, err := checkpointer.Checkpoint(ctx, tenantA)
	if err != nil {
		t.Fatalf("Checkpoint(create) error = %v", err)
	}
	if created.Replay || created.Checkpoint.ChainSequence != head.Sequence || created.Checkpoint.ChainHash != head.Hash {
		t.Fatalf("Checkpoint(create) = %#v", created)
	}
	if err := VerifyCheckpointSignature(&privateKey.PublicKey, created.Checkpoint); err != nil {
		t.Fatalf("VerifyCheckpointSignature(created) error = %v", err)
	}
	persisted, err := store.Find(ctx, tenantA, head.Sequence, signer.keyID)
	if err != nil {
		t.Fatalf("Find(created checkpoint) error = %v", err)
	}
	if persisted.ID != created.Checkpoint.ID || persisted.StatementDigest != created.Checkpoint.StatementDigest {
		t.Fatalf("persisted checkpoint = %#v, created = %#v", persisted, created.Checkpoint)
	}

	replayed, err := checkpointer.Checkpoint(ctx, tenantA)
	if err != nil {
		t.Fatalf("Checkpoint(replay) error = %v", err)
	}
	if !replayed.Replay || replayed.Checkpoint.ID != created.Checkpoint.ID || signer.signCalls.Load() != 1 {
		t.Fatalf("Checkpoint(replay) = %#v signCalls=%d", replayed, signer.signCalls.Load())
	}

	outage := errors.New("integration signer unavailable")
	outageSigner := &integrationCheckpointSigner{key: privateKey, keyID: "kms/test/postgres-outage-v1", signErr: outage}
	outageCheckpointer := mustIntegrationCheckpointer(t, store, outageSigner, auditIntegrationUUID(t, "60000000-0000-0000-0000-0000000000f2"))
	if _, err := outageCheckpointer.Checkpoint(ctx, tenantA); !errors.Is(err, outage) {
		t.Fatalf("Checkpoint(outage) error = %v, want injected outage", err)
	}
	if _, err := store.Find(ctx, tenantA, head.Sequence, outageSigner.keyID); !errors.Is(err, ErrCheckpointNotFound) {
		t.Fatalf("Find(after outage) error = %v, want ErrCheckpointNotFound", err)
	}
	headAfterOutage, err := store.Head(ctx, tenantA)
	if err != nil || headAfterOutage != head {
		t.Fatalf("Head(after outage) = %#v error=%v, want %#v", headAfterOutage, err, head)
	}
	outageSigner.signErr = nil
	retried, err := outageCheckpointer.Checkpoint(ctx, tenantA)
	if err != nil {
		t.Fatalf("Checkpoint(outage retry) error = %v", err)
	}
	if retried.Replay || retried.Checkpoint.ID != auditIntegrationUUID(t, "60000000-0000-0000-0000-0000000000f2") {
		t.Fatalf("Checkpoint(outage retry) = %#v", retried)
	}
	if err := VerifyCheckpointSignature(&privateKey.PublicKey, retried.Checkpoint); err != nil {
		t.Fatalf("VerifyCheckpointSignature(retried) error = %v", err)
	}

	assertCheckpointTamperDetected(t, &privateKey.PublicKey, created.Checkpoint)
	assertRacingCheckpointersConverge(t, ctx, store, tenantA, head, privateKey)
}

type persistedAuditChainRow struct {
	StoredEvent
	Sequence          int64
	ChainEventHash    []byte
	PreviousChainHash []byte
	ChainHash         []byte
}

func loadPersistedAuditChainRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, firstID, secondID pgtype.UUID) []persistedAuditChainRow {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("pool.Begin() error = %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- test cleanup
	var activeTenant string
	if err := tx.QueryRow(ctx, "SELECT set_config('app.tenant_id', $1, true)", uuidText(tenantID)).Scan(&activeTenant); err != nil {
		t.Fatalf("set tenant context: %v", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT e.tenant_id, e.id, e.actor_subject_id, e.event_type, e.action, e.decision,
		       e.policy_version, e.correlation_id, e.safe_metadata::text, e.previous_hash,
		       e.event_hash, e.occurred_at, c.sequence, c.event_hash,
		       c.previous_chain_hash, c.chain_hash
		FROM audit.events AS e
		JOIN audit.event_chain AS c ON c.tenant_id = e.tenant_id AND c.event_id = e.id
		WHERE e.tenant_id = $1 AND e.id IN ($2, $3)
		ORDER BY c.sequence
	`, tenantID, firstID, secondID)
	if err != nil {
		t.Fatalf("query persisted audit chain: %v", err)
	}
	defer rows.Close()

	var result []persistedAuditChainRow
	for rows.Next() {
		var row persistedAuditChainRow
		var metadata string
		if err := rows.Scan(
			&row.TenantID, &row.ID, &row.ActorSubjectID, &row.EventType, &row.Action, &row.Decision,
			&row.PolicyVersion, &row.CorrelationID, &metadata, &row.PreviousHash, &row.EventHash,
			&row.OccurredAt, &row.Sequence, &row.ChainEventHash, &row.PreviousChainHash, &row.ChainHash,
		); err != nil {
			t.Fatalf("scan persisted audit chain: %v", err)
		}
		row.SafeMetadata = []byte(metadata)
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate persisted audit chain: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("tx.Rollback() error = %v", err)
	}
	return result
}

func assertTenantCannotSeeAuditEvents(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, firstID, secondID pgtype.UUID) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("pool.Begin(other tenant) error = %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- test cleanup
	var activeTenant string
	if err := tx.QueryRow(ctx, "SELECT set_config('app.tenant_id', $1, true)", uuidText(tenantID)).Scan(&activeTenant); err != nil {
		t.Fatalf("set other tenant context: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE id IN ($1, $2)`, firstID, secondID).Scan(&count); err != nil {
		t.Fatalf("query other tenant audit visibility: %v", err)
	}
	if count != 0 {
		t.Fatalf("other tenant observed %d audit events, want 0", count)
	}
}

type integrationCheckpointSigner struct {
	key       *ecdsa.PrivateKey
	keyID     string
	signErr   error
	signCalls atomic.Int64
}

func (s *integrationCheckpointSigner) KeyID() string { return s.keyID }

func (s *integrationCheckpointSigner) PublicKey(context.Context) (*ecdsa.PublicKey, error) {
	return &s.key.PublicKey, nil
}

func (s *integrationCheckpointSigner) SignSHA256(_ context.Context, digest [32]byte) ([]byte, error) {
	s.signCalls.Add(1)
	if s.signErr != nil {
		return nil, s.signErr
	}
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func mustIntegrationCheckpointKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return key
}

func mustIntegrationCheckpointer(t *testing.T, store CheckpointStore, signer CheckpointSigner, id pgtype.UUID) *Checkpointer {
	t.Helper()
	checkpointer, err := NewCheckpointer(
		store,
		signer,
		func() time.Time { return time.Date(2026, 9, 9, 13, 15, 0, 987654321, time.UTC) },
		func() (pgtype.UUID, error) { return id, nil },
	)
	if err != nil {
		t.Fatalf("NewCheckpointer() error = %v", err)
	}
	return checkpointer
}

func assertCheckpointTamperDetected(t *testing.T, publicKey *ecdsa.PublicKey, checkpoint StoredCheckpoint) {
	t.Helper()
	cases := []struct {
		name   string
		mutate func(StoredCheckpoint) StoredCheckpoint
	}{
		{name: "chain sequence", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.ChainSequence++; return v }},
		{name: "chain hash", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.ChainHash[0] ^= 0xff; return v }},
		{name: "statement digest", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.StatementDigest[0] ^= 0xff; return v }},
		{name: "signature", mutate: func(v StoredCheckpoint) StoredCheckpoint {
			v.Signature = append([]byte(nil), v.Signature...)
			v.Signature[len(v.Signature)-1] ^= 0xff
			return v
		}},
		{name: "signed at", mutate: func(v StoredCheckpoint) StoredCheckpoint { v.SignedAt = v.SignedAt.Add(time.Microsecond); return v }},
	}
	for _, tc := range cases {
		t.Run("checkpoint tamper "+tc.name, func(t *testing.T) {
			if err := VerifyCheckpointSignature(publicKey, tc.mutate(checkpoint)); err == nil {
				t.Fatal("VerifyCheckpointSignature(tampered) unexpectedly succeeded")
			}
		})
	}
}

func assertRacingCheckpointersConverge(t *testing.T, ctx context.Context, store CheckpointStore, tenantID pgtype.UUID, head ChainHead, key *ecdsa.PrivateKey) {
	t.Helper()
	keyID := "kms/test/postgres-race-v1"
	signerA := &integrationCheckpointSigner{key: key, keyID: keyID}
	signerB := &integrationCheckpointSigner{key: key, keyID: keyID}
	checkpointerA := mustIntegrationCheckpointer(t, store, signerA, auditIntegrationUUID(t, "60000000-0000-0000-0000-0000000000f3"))
	checkpointerB := mustIntegrationCheckpointer(t, store, signerB, auditIntegrationUUID(t, "60000000-0000-0000-0000-0000000000f4"))

	start := make(chan struct{})
	results := make(chan CheckpointResult, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, checkpointer := range []*Checkpointer{checkpointerA, checkpointerB} {
		wg.Add(1)
		go func(c *Checkpointer) {
			defer wg.Done()
			<-start
			result, err := c.Checkpoint(ctx, tenantID)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}(checkpointer)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("racing Checkpoint() error = %v", err)
		}
	}

	var got []CheckpointResult
	for result := range results {
		got = append(got, result)
	}
	if len(got) != 2 {
		t.Fatalf("racing results = %d, want 2", len(got))
	}
	winner, err := store.Find(ctx, tenantID, head.Sequence, keyID)
	if err != nil {
		t.Fatalf("Find(race winner) error = %v", err)
	}
	if got[0].Checkpoint.ID != winner.ID || got[1].Checkpoint.ID != winner.ID {
		t.Fatalf("racing workers diverged: first=%#v second=%#v winner=%#v", got[0], got[1], winner)
	}
	if got[0].Replay == got[1].Replay {
		t.Fatalf("racing replay flags = %t/%t, want exactly one replay", got[0].Replay, got[1].Replay)
	}
	if winner.ChainSequence != head.Sequence || winner.ChainHash != head.Hash {
		t.Fatalf("race winner = %#v, want head %#v", winner, head)
	}
	if err := VerifyCheckpointSignature(&key.PublicKey, winner); err != nil {
		t.Fatalf("VerifyCheckpointSignature(race winner) error = %v", err)
	}
}

package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingSessionQueries struct {
	createParams  sqlcgen.CreateSessionParams
	createCalls   int
	lookupHash    []byte
	lookupCalls   int
	lookupRow     sqlcgen.GetActiveSessionRow
	lookupErr     error
	revokeHash    []byte
	revokeCalls   int
	upsertParams  sqlcgen.UpsertSubjectParams
	upsertCalls   int
}

func (q *recordingSessionQueries) CreateSession(_ context.Context, arg sqlcgen.CreateSessionParams) (pgtype.UUID, error) {
	q.createCalls++
	q.createParams = arg
	return arg.SessionID, nil
}

func (q *recordingSessionQueries) GetActiveSession(_ context.Context, sessionTokenHash []byte) (sqlcgen.GetActiveSessionRow, error) {
	q.lookupCalls++
	q.lookupHash = append([]byte(nil), sessionTokenHash...)
	return q.lookupRow, q.lookupErr
}

func (q *recordingSessionQueries) RevokeSession(_ context.Context, sessionTokenHash []byte) error {
	q.revokeCalls++
	q.revokeHash = append([]byte(nil), sessionTokenHash...)
	return nil
}

func (q *recordingSessionQueries) UpsertSubject(_ context.Context, arg sqlcgen.UpsertSubjectParams) (pgtype.UUID, error) {
	q.upsertCalls++
	q.upsertParams = arg
	return arg.SubjectID, nil
}

func TestSessionStoreCreatePersistsOnlyTokenHashes(t *testing.T) {
	t.Parallel()

	queries := &recordingSessionQueries{}
	store := NewSessionStore(queries)
	sessionID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	subjectID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	expiresAt := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)

	if err := store.Create(context.Background(), sessionID, subjectID, "presented-session-token", "presented-csrf-token", expiresAt); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if queries.createCalls != 1 {
		t.Fatalf("CreateSession() calls = %d, want 1", queries.createCalls)
	}
	wantSessionHash := HashToken("presented-session-token")
	wantCSRFHash := HashToken("presented-csrf-token")
	if string(queries.createParams.SessionTokenHash) != string(wantSessionHash[:]) {
		t.Fatal("Create() did not replace presented session token with its SHA-256 hash")
	}
	if string(queries.createParams.CsrfTokenHash) != string(wantCSRFHash[:]) {
		t.Fatal("Create() did not replace presented CSRF token with its SHA-256 hash")
	}
	if queries.createParams.SessionID != sessionID || queries.createParams.SubjectID != subjectID {
		t.Fatal("Create() changed session or subject identity")
	}
	if !queries.createParams.ExpiresAt.Valid || !queries.createParams.ExpiresAt.Time.Equal(expiresAt) {
		t.Fatalf("Create() expiry = %#v, want %v", queries.createParams.ExpiresAt, expiresAt)
	}
}

func TestSessionStoreLookupHashesPresentedSessionToken(t *testing.T) {
	t.Parallel()

	want := sqlcgen.GetActiveSessionRow{ID: pgtype.UUID{Bytes: [16]byte{3}, Valid: true}}
	queries := &recordingSessionQueries{lookupRow: want}
	store := NewSessionStore(queries)

	got, err := store.Lookup(context.Background(), "presented-session-token")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if got != want {
		t.Fatalf("Lookup() = %#v, want %#v", got, want)
	}
	wantHash := HashToken("presented-session-token")
	if string(queries.lookupHash) != string(wantHash[:]) {
		t.Fatal("Lookup() sent a value other than the session-token hash to the database boundary")
	}
}

func TestSessionStoreRevokeHashesPresentedSessionToken(t *testing.T) {
	t.Parallel()

	queries := &recordingSessionQueries{}
	store := NewSessionStore(queries)
	if err := store.Revoke(context.Background(), "presented-session-token"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	wantHash := HashToken("presented-session-token")
	if string(queries.revokeHash) != string(wantHash[:]) {
		t.Fatal("Revoke() sent a value other than the session-token hash to the database boundary")
	}
}

func TestSessionStoreFailsClosedOnMissingPresentedToken(t *testing.T) {
	t.Parallel()

	queries := &recordingSessionQueries{lookupErr: errors.New("must not be called")}
	store := NewSessionStore(queries)

	if _, err := store.Lookup(context.Background(), ""); err == nil {
		t.Fatal("Lookup() accepted empty presented session token")
	}
	if err := store.Revoke(context.Background(), ""); err == nil {
		t.Fatal("Revoke() accepted empty presented session token")
	}
	if queries.lookupCalls != 0 || queries.revokeCalls != 0 {
		t.Fatal("missing session token reached the database boundary")
	}
}

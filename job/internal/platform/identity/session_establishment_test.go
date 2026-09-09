package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingSubjectQueries struct {
	params sqlcgen.UpsertSubjectParams
	calls  int
	result pgtype.UUID
	err    error
}

func (q *recordingSubjectQueries) UpsertSubject(_ context.Context, arg sqlcgen.UpsertSubjectParams) (pgtype.UUID, error) {
	q.calls++
	q.params = arg
	if q.err != nil {
		return pgtype.UUID{}, q.err
	}
	if q.result.Valid {
		return q.result, nil
	}
	return arg.SubjectID, nil
}

func TestSubjectStoreMapsOnlyVerifiedIdentityClaims(t *testing.T) {
	t.Parallel()

	candidateID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	queries := &recordingSubjectQueries{}
	store := NewSubjectStore(queries)

	got, err := store.UpsertVerifiedIdentity(context.Background(), candidateID, VerifiedOIDCIdentity{
		Subject: "keycloak-subject-123",
		Name:    "  Machina User  ",
		Email:   "not-persisted@example.test",
	})
	if err != nil {
		t.Fatalf("UpsertVerifiedIdentity() error = %v", err)
	}
	if got != candidateID {
		t.Fatalf("subject ID = %#v, want %#v", got, candidateID)
	}
	if queries.calls != 1 {
		t.Fatalf("UpsertSubject() calls = %d, want 1", queries.calls)
	}
	if queries.params.SubjectID != candidateID || queries.params.ExternalSubject != "keycloak-subject-123" {
		t.Fatalf("subject mapping = %#v", queries.params)
	}
	if queries.params.DisplayName != "Machina User" {
		t.Fatalf("display name = %q, want trimmed verified name", queries.params.DisplayName)
	}
	if queries.params.DisplayName == "not-persisted@example.test" {
		t.Fatal("email was persisted as display name despite a verified name")
	}
}

func TestSubjectStoreUsesSubjectAsMinimalDisplayFallback(t *testing.T) {
	t.Parallel()

	candidateID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	queries := &recordingSubjectQueries{}
	store := NewSubjectStore(queries)

	_, err := store.UpsertVerifiedIdentity(context.Background(), candidateID, VerifiedOIDCIdentity{
		Subject: "subject-fallback",
		Email:   "not-needed@example.test",
	})
	if err != nil {
		t.Fatalf("UpsertVerifiedIdentity() error = %v", err)
	}
	if queries.params.DisplayName != "subject-fallback" {
		t.Fatalf("display name = %q, want subject fallback", queries.params.DisplayName)
	}
}

func TestSubjectStoreRejectsInvalidIdentityBeforeDatabase(t *testing.T) {
	t.Parallel()

	candidateID := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	for _, tc := range []struct {
		name     string
		identity VerifiedOIDCIdentity
	}{
		{name: "missing subject", identity: VerifiedOIDCIdentity{Name: "User"}},
		{name: "blank subject", identity: VerifiedOIDCIdentity{Subject: "   ", Name: "User"}},
		{name: "oversized display", identity: VerifiedOIDCIdentity{Subject: "subject", Name: string(make([]byte, 161))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := &recordingSubjectQueries{}
			store := NewSubjectStore(queries)
			if _, err := store.UpsertVerifiedIdentity(context.Background(), candidateID, tc.identity); err == nil {
				t.Fatalf("UpsertVerifiedIdentity() accepted %s", tc.name)
			}
			if queries.calls != 0 {
				t.Fatalf("invalid identity %s reached database boundary", tc.name)
			}
		})
	}
}

type recordingAuthenticatedSubjectStore struct {
	candidateID pgtype.UUID
	identity    VerifiedOIDCIdentity
	calls       int
	result      pgtype.UUID
	err         error
}

func (s *recordingAuthenticatedSubjectStore) UpsertVerifiedIdentity(_ context.Context, candidateID pgtype.UUID, identity VerifiedOIDCIdentity) (pgtype.UUID, error) {
	s.calls++
	s.candidateID = candidateID
	s.identity = identity
	return s.result, s.err
}

type recordingAuthenticatedSessionStore struct {
	sessionID    pgtype.UUID
	subjectID    pgtype.UUID
	sessionToken string
	csrfToken    string
	expiresAt    time.Time
	calls        int
	err          error
}

func (s *recordingAuthenticatedSessionStore) Create(_ context.Context, sessionID, subjectID pgtype.UUID, sessionToken, csrfToken string, expiresAt time.Time) error {
	s.calls++
	s.sessionID = sessionID
	s.subjectID = subjectID
	s.sessionToken = sessionToken
	s.csrfToken = csrfToken
	s.expiresAt = expiresAt
	return s.err
}

func TestAuthenticatedSessionServiceEstablishesServerOwnedSession(t *testing.T) {
	t.Parallel()

	subjectID := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}
	candidateSubjectID := pgtype.UUID{Bytes: [16]byte{8}, Valid: true}
	sessionID := pgtype.UUID{Bytes: [16]byte{7}, Valid: true}
	subjects := &recordingAuthenticatedSubjectStore{result: subjectID}
	sessions := &recordingAuthenticatedSessionStore{}
	service, err := NewAuthenticatedSessionService(subjects, sessions, 12*time.Hour)
	if err != nil {
		t.Fatalf("NewAuthenticatedSessionService() error = %v", err)
	}
	service.now = func() time.Time { return time.Date(2026, 9, 8, 5, 0, 0, 0, time.UTC) }
	ids := []pgtype.UUID{candidateSubjectID, sessionID}
	service.newUUID = func() (pgtype.UUID, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	tokens := []string{"raw-session-token", "raw-csrf-token"}
	service.newToken = func() (string, error) {
		token := tokens[0]
		tokens = tokens[1:]
		return token, nil
	}
	identity := VerifiedOIDCIdentity{Subject: "keycloak-subject-123", Name: "Machina User"}

	got, err := service.Establish(context.Background(), identity)
	if err != nil {
		t.Fatalf("Establish() error = %v", err)
	}
	if subjects.calls != 1 || subjects.candidateID != candidateSubjectID || subjects.identity != identity {
		t.Fatalf("subject establishment = %#v", subjects)
	}
	if sessions.calls != 1 || sessions.sessionID != sessionID || sessions.subjectID != subjectID {
		t.Fatalf("session persistence = %#v", sessions)
	}
	if sessions.sessionToken != "raw-session-token" || sessions.csrfToken != "raw-csrf-token" {
		t.Fatalf("session store received unexpected presented tokens: %#v", sessions)
	}
	wantExpiry := service.now().Add(12 * time.Hour)
	if !sessions.expiresAt.Equal(wantExpiry) {
		t.Fatalf("session expiry = %v, want %v", sessions.expiresAt, wantExpiry)
	}
	if got.SubjectID != subjectID || got.SessionToken != "raw-session-token" || got.CSRFToken != "raw-csrf-token" || !got.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("authenticated session = %#v", got)
	}
	if got.SessionCookie().Value != got.SessionToken || got.CSRFCookie().Value != got.CSRFToken {
		t.Fatal("authenticated session cookies do not carry the generated browser tokens")
	}
}

func TestAuthenticatedSessionServiceFailsClosedBeforeSessionWrite(t *testing.T) {
	t.Parallel()

	subjects := &recordingAuthenticatedSubjectStore{err: errors.New("subject mapping failed")}
	sessions := &recordingAuthenticatedSessionStore{}
	service, err := NewAuthenticatedSessionService(subjects, sessions, time.Hour)
	if err != nil {
		t.Fatalf("NewAuthenticatedSessionService() error = %v", err)
	}
	service.newUUID = func() (pgtype.UUID, error) {
		return pgtype.UUID{Bytes: [16]byte{1}, Valid: true}, nil
	}
	if _, err := service.Establish(context.Background(), VerifiedOIDCIdentity{Subject: "subject", Name: "User"}); err == nil {
		t.Fatal("Establish() accepted failed subject mapping")
	}
	if sessions.calls != 0 {
		t.Fatal("failed subject mapping still created a session")
	}
}

func TestAuthenticatedSessionServiceRejectsInvalidLifetime(t *testing.T) {
	t.Parallel()

	if _, err := NewAuthenticatedSessionService(&recordingAuthenticatedSubjectStore{}, &recordingAuthenticatedSessionStore{}, 0); err == nil {
		t.Fatal("NewAuthenticatedSessionService() accepted zero lifetime")
	}
	if _, err := NewAuthenticatedSessionService(&recordingAuthenticatedSubjectStore{}, &recordingAuthenticatedSessionStore{}, -time.Minute); err == nil {
		t.Fatal("NewAuthenticatedSessionService() accepted negative lifetime")
	}
}

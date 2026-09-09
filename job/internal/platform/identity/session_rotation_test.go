package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingSessionRotator struct {
	presentedSessionToken   string
	replacementSessionToken string
	replacementCSRFToken    string
	calls                   int
	row                     sqlcgen.RotateSessionRow
	err                     error
}

func (s *recordingSessionRotator) Rotate(_ context.Context, presentedSessionToken, replacementSessionToken, replacementCSRFToken string) (sqlcgen.RotateSessionRow, error) {
	s.calls++
	s.presentedSessionToken = presentedSessionToken
	s.replacementSessionToken = replacementSessionToken
	s.replacementCSRFToken = replacementCSRFToken
	return s.row, s.err
}

func TestSessionRotationServiceRotatesToFreshBrowserSecretsWithoutExtendingExpiry(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC)
	subjectID := pgtype.UUID{Bytes: [16]byte{6}, Valid: true}
	store := &recordingSessionRotator{row: sqlcgen.RotateSessionRow{
		ID:        pgtype.UUID{Bytes: [16]byte{7}, Valid: true},
		SubjectID: subjectID,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		RotatedAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 8, 4, 30, 0, 0, time.UTC), Valid: true},
	}}
	service, err := NewSessionRotationService(store)
	if err != nil {
		t.Fatalf("NewSessionRotationService() error = %v", err)
	}
	tokens := []string{"replacement-session", "replacement-csrf"}
	service.newToken = func() (string, error) {
		token := tokens[0]
		tokens = tokens[1:]
		return token, nil
	}

	got, err := service.Rotate(context.Background(), "presented-old-session")
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("session store Rotate() calls = %d, want 1", store.calls)
	}
	if store.presentedSessionToken != "presented-old-session" || store.replacementSessionToken != "replacement-session" || store.replacementCSRFToken != "replacement-csrf" {
		t.Fatalf("rotation material = %#v", store)
	}
	if got.SubjectID != subjectID || got.SessionToken != "replacement-session" || got.CSRFToken != "replacement-csrf" || !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("rotated authenticated session = %#v", got)
	}
	if got.SessionCookie().Value != got.SessionToken || !got.SessionCookie().Expires.Equal(expiresAt) {
		t.Fatal("rotated session cookie does not carry the replacement token with absolute expiry")
	}
	if got.CSRFCookie().Value != got.CSRFToken || !got.CSRFCookie().Expires.Equal(expiresAt) {
		t.Fatal("rotated CSRF cookie does not carry the replacement token with absolute expiry")
	}
}

func TestSessionRotationServiceRejectsGeneratedSecretCollisionBeforeDatabase(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		tokens []string
	}{
		{name: "replacement tokens collide", tokens: []string{"same-secret", "same-secret"}},
		{name: "replacement session reuses presented session", tokens: []string{"old-session", "new-csrf"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingSessionRotator{}
			service, err := NewSessionRotationService(store)
			if err != nil {
				t.Fatalf("NewSessionRotationService() error = %v", err)
			}
			tokens := append([]string(nil), tc.tokens...)
			service.newToken = func() (string, error) {
				token := tokens[0]
				tokens = tokens[1:]
				return token, nil
			}
			if _, err := service.Rotate(context.Background(), "old-session"); err == nil {
				t.Fatal("Rotate() accepted colliding or reused generated secret")
			}
			if store.calls != 0 {
				t.Fatal("invalid generated rotation material reached the database boundary")
			}
		})
	}
}

func TestSessionRotationServicePreservesStoreFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("session unavailable")
	store := &recordingSessionRotator{err: wantErr}
	service, err := NewSessionRotationService(store)
	if err != nil {
		t.Fatalf("NewSessionRotationService() error = %v", err)
	}
	tokens := []string{"replacement-session", "replacement-csrf"}
	service.newToken = func() (string, error) {
		token := tokens[0]
		tokens = tokens[1:]
		return token, nil
	}

	if _, err := service.Rotate(context.Background(), "old-session"); !errors.Is(err, wantErr) {
		t.Fatalf("Rotate() error = %v, want errors.Is(_, %v)", err, wantErr)
	}
}

func TestSessionRotationServiceRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewSessionRotationService(nil); err == nil {
		t.Fatal("NewSessionRotationService() accepted nil session store")
	}
}

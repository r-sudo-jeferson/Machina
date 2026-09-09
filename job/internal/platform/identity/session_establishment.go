package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrInvalidAuthenticatedSessionConfig = errors.New("invalid authenticated session configuration")
	ErrSessionSecretCollision            = errors.New("session secret collision")
)

type authenticatedSubjectStore interface {
	UpsertVerifiedIdentity(context.Context, pgtype.UUID, VerifiedOIDCIdentity) (pgtype.UUID, error)
}

type authenticatedSessionStore interface {
	Create(context.Context, pgtype.UUID, pgtype.UUID, string, string, time.Time) error
}

type AuthenticatedSessionService struct {
	subjects authenticatedSubjectStore
	sessions authenticatedSessionStore
	lifetime time.Duration
	now      func() time.Time
	newUUID  func() (pgtype.UUID, error)
	newToken func() (string, error)
}

type AuthenticatedSession struct {
	SubjectID    pgtype.UUID
	SessionToken string
	CSRFToken    string
	ExpiresAt    time.Time
}

func NewAuthenticatedSessionService(
	subjects authenticatedSubjectStore,
	sessions authenticatedSessionStore,
	lifetime time.Duration,
) (*AuthenticatedSessionService, error) {
	if subjects == nil || sessions == nil || lifetime <= 0 {
		return nil, ErrInvalidAuthenticatedSessionConfig
	}
	return &AuthenticatedSessionService{
		subjects: subjects,
		sessions: sessions,
		lifetime: lifetime,
		now:      time.Now,
		newUUID:  newRandomUUIDv4,
		newToken: newOpaqueTokenValue,
	}, nil
}

func (s *AuthenticatedSessionService) Establish(ctx context.Context, identity VerifiedOIDCIdentity) (AuthenticatedSession, error) {
	if s == nil || s.subjects == nil || s.sessions == nil || s.lifetime <= 0 || s.now == nil || s.newUUID == nil || s.newToken == nil {
		return AuthenticatedSession{}, ErrInvalidAuthenticatedSessionConfig
	}

	candidateSubjectID, err := s.newUUID()
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("generate subject ID: %w", err)
	}
	subjectID, err := s.subjects.UpsertVerifiedIdentity(ctx, candidateSubjectID, identity)
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("map verified OIDC subject: %w", err)
	}

	sessionID, err := s.newUUID()
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("generate session ID: %w", err)
	}
	sessionToken, err := s.newToken()
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("generate session token: %w", err)
	}
	csrfToken, err := s.newToken()
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("generate CSRF token: %w", err)
	}
	if sessionToken == csrfToken {
		return AuthenticatedSession{}, ErrSessionSecretCollision
	}

	expiresAt := s.now().UTC().Add(s.lifetime)
	if err := s.sessions.Create(ctx, sessionID, subjectID, sessionToken, csrfToken, expiresAt); err != nil {
		return AuthenticatedSession{}, fmt.Errorf("persist authenticated session: %w", err)
	}

	return AuthenticatedSession{
		SubjectID:    subjectID,
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s AuthenticatedSession) SessionCookie() *http.Cookie {
	return SessionCookie(s.SessionToken, s.ExpiresAt)
}

func (s AuthenticatedSession) CSRFCookie() *http.Cookie {
	return CSRFCookie(s.CSRFToken, s.ExpiresAt)
}

func newRandomUUIDv4() (pgtype.UUID, error) {
	var bytes [16]byte
	if _, err := io.ReadFull(rand.Reader, bytes[:]); err != nil {
		return pgtype.UUID{}, err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return pgtype.UUID{Bytes: bytes, Valid: true}, nil
}

func newOpaqueTokenValue() (string, error) {
	raw, _, err := NewOpaqueToken()
	return raw, err
}

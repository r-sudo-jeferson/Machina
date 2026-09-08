package identity

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrMissingSessionToken = errors.New("missing session token")
	ErrMissingCSRFToken    = errors.New("missing CSRF token")
)

type sessionQueries interface {
	CreateSession(context.Context, sqlcgen.CreateSessionParams) (pgtype.UUID, error)
	GetActiveSession(context.Context, []byte) (sqlcgen.GetActiveSessionRow, error)
	RevokeSession(context.Context, []byte) error
}

type SessionStore struct {
	queries sessionQueries
}

func NewSessionStore(queries sessionQueries) *SessionStore {
	return &SessionStore{queries: queries}
}

func (s *SessionStore) Create(
	ctx context.Context,
	sessionID pgtype.UUID,
	subjectID pgtype.UUID,
	presentedSessionToken string,
	presentedCSRFToken string,
	expiresAt time.Time,
) error {
	if presentedSessionToken == "" {
		return ErrMissingSessionToken
	}
	if presentedCSRFToken == "" {
		return ErrMissingCSRFToken
	}

	sessionHash := HashToken(presentedSessionToken)
	csrfHash := HashToken(presentedCSRFToken)
	_, err := s.queries.CreateSession(ctx, sqlcgen.CreateSessionParams{
		SessionID:        sessionID,
		SubjectID:        subjectID,
		SessionTokenHash: sessionHash[:],
		CsrfTokenHash:    csrfHash[:],
		ExpiresAt: pgtype.Timestamptz{
			Time:  expiresAt.UTC(),
			Valid: true,
		},
	})
	return err
}

func (s *SessionStore) Lookup(ctx context.Context, presentedSessionToken string) (sqlcgen.GetActiveSessionRow, error) {
	if presentedSessionToken == "" {
		return sqlcgen.GetActiveSessionRow{}, ErrMissingSessionToken
	}

	sessionHash := HashToken(presentedSessionToken)
	return s.queries.GetActiveSession(ctx, sessionHash[:])
}

func (s *SessionStore) Revoke(ctx context.Context, presentedSessionToken string) error {
	if presentedSessionToken == "" {
		return ErrMissingSessionToken
	}

	sessionHash := HashToken(presentedSessionToken)
	return s.queries.RevokeSession(ctx, sessionHash[:])
}

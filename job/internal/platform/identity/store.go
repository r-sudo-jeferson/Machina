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
	ErrSessionTokenReuse   = errors.New("session rotation requires a new session token")
	ErrInvalidTargetContext = errors.New("invalid target tenant or workspace")
)

type sessionQueries interface {
	CreateSession(context.Context, sqlcgen.CreateSessionParams) (pgtype.UUID, error)
	GetActiveSession(context.Context, []byte) (sqlcgen.GetActiveSessionRow, error)
	RevokeSession(context.Context, []byte) error
	RotateSession(context.Context, sqlcgen.RotateSessionParams) (sqlcgen.RotateSessionRow, error)
	SwitchSessionContext(context.Context, sqlcgen.SwitchSessionContextParams) (sqlcgen.SwitchSessionContextRow, error)
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

func (s *SessionStore) Rotate(
	ctx context.Context,
	presentedSessionToken string,
	replacementSessionToken string,
	replacementCSRFToken string,
) (sqlcgen.RotateSessionRow, error) {
	if presentedSessionToken == "" || replacementSessionToken == "" {
		return sqlcgen.RotateSessionRow{}, ErrMissingSessionToken
	}
	if replacementCSRFToken == "" {
		return sqlcgen.RotateSessionRow{}, ErrMissingCSRFToken
	}
	if presentedSessionToken == replacementSessionToken {
		return sqlcgen.RotateSessionRow{}, ErrSessionTokenReuse
	}
	if replacementSessionToken == replacementCSRFToken {
		return sqlcgen.RotateSessionRow{}, ErrSessionSecretCollision
	}

	presentedHash := HashToken(presentedSessionToken)
	replacementHash := HashToken(replacementSessionToken)
	replacementCSRFHash := HashToken(replacementCSRFToken)
	return s.queries.RotateSession(ctx, sqlcgen.RotateSessionParams{
		SessionTokenHash:    presentedHash[:],
		NewSessionTokenHash: replacementHash[:],
		NewCsrfTokenHash:    replacementCSRFHash[:],
	})
}

func (s *SessionStore) SwitchContext(
	ctx context.Context,
	presentedSessionToken string,
	replacementSessionToken string,
	replacementCSRFToken string,
	targetTenantID pgtype.UUID,
	targetWorkspaceID pgtype.UUID,
) (sqlcgen.SwitchSessionContextRow, error) {
	if presentedSessionToken == "" || replacementSessionToken == "" {
		return sqlcgen.SwitchSessionContextRow{}, ErrMissingSessionToken
	}
	if replacementCSRFToken == "" {
		return sqlcgen.SwitchSessionContextRow{}, ErrMissingCSRFToken
	}
	if presentedSessionToken == replacementSessionToken {
		return sqlcgen.SwitchSessionContextRow{}, ErrSessionTokenReuse
	}
	if replacementSessionToken == replacementCSRFToken {
		return sqlcgen.SwitchSessionContextRow{}, ErrSessionSecretCollision
	}
	if !targetTenantID.Valid || !targetWorkspaceID.Valid {
		return sqlcgen.SwitchSessionContextRow{}, ErrInvalidTargetContext
	}

	currentHash := HashToken(presentedSessionToken)
	replacementHash := HashToken(replacementSessionToken)
	replacementCSRFHash := HashToken(replacementCSRFToken)
	return s.queries.SwitchSessionContext(ctx, sqlcgen.SwitchSessionContextParams{
		CurrentSessionTokenHash:     currentHash[:],
		ReplacementSessionTokenHash: replacementHash[:],
		ReplacementCsrfTokenHash:    replacementCSRFHash[:],
		TargetTenantID:              targetTenantID,
		TargetWorkspaceID:           targetWorkspaceID,
	})
}

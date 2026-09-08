package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var ErrInvalidSessionRotationConfig = errors.New("invalid session rotation configuration")

type sessionRotator interface {
	Rotate(context.Context, string, string, string) (sqlcgen.RotateSessionRow, error)
}

type SessionRotationService struct {
	sessions sessionRotator
	newToken func() (string, error)
}

func NewSessionRotationService(sessions sessionRotator) (*SessionRotationService, error) {
	if sessions == nil {
		return nil, ErrInvalidSessionRotationConfig
	}
	return &SessionRotationService{
		sessions: sessions,
		newToken: newOpaqueTokenValue,
	}, nil
}

func (s *SessionRotationService) Rotate(ctx context.Context, presentedSessionToken string) (AuthenticatedSession, error) {
	if s == nil || s.sessions == nil || s.newToken == nil {
		return AuthenticatedSession{}, ErrInvalidSessionRotationConfig
	}

	replacementSessionToken, err := s.newToken()
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("generate replacement session token: %w", err)
	}
	replacementCSRFToken, err := s.newToken()
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("generate replacement CSRF token: %w", err)
	}
	if replacementSessionToken == presentedSessionToken {
		return AuthenticatedSession{}, ErrSessionTokenReuse
	}
	if replacementSessionToken == replacementCSRFToken {
		return AuthenticatedSession{}, ErrSessionSecretCollision
	}

	row, err := s.sessions.Rotate(ctx, presentedSessionToken, replacementSessionToken, replacementCSRFToken)
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("rotate authenticated session: %w", err)
	}
	if !row.SubjectID.Valid || !row.ExpiresAt.Valid {
		return AuthenticatedSession{}, ErrInvalidSessionRotationConfig
	}

	return AuthenticatedSession{
		SubjectID:    row.SubjectID,
		SessionToken: replacementSessionToken,
		CSRFToken:    replacementCSRFToken,
		ExpiresAt:    row.ExpiresAt.Time.UTC(),
	}, nil
}

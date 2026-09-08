package identity

import (
	"context"
	"errors"
	"fmt"
)

var ErrInvalidSessionLogoutConfig = errors.New("invalid session logout configuration")

type sessionRevoker interface {
	Revoke(context.Context, string) error
}

type SessionLogoutService struct {
	sessions sessionRevoker
}

func NewSessionLogoutService(sessions sessionRevoker) (*SessionLogoutService, error) {
	if sessions == nil {
		return nil, ErrInvalidSessionLogoutConfig
	}
	return &SessionLogoutService{sessions: sessions}, nil
}

func (s *SessionLogoutService) Logout(ctx context.Context, presentedSessionToken string) error {
	if s == nil || s.sessions == nil {
		return ErrInvalidSessionLogoutConfig
	}
	if presentedSessionToken == "" {
		return ErrMissingSessionToken
	}
	if err := s.sessions.Revoke(ctx, presentedSessionToken); err != nil {
		return fmt.Errorf("revoke authenticated session: %w", err)
	}
	return nil
}

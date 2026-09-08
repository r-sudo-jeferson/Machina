package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrInvalidSessionContextSwitchConfig = errors.New("invalid session context switch configuration")
	ErrInvalidSessionContextSwitchResult = errors.New("invalid session context switch result")
)

type sessionContextSwitcher interface {
	SwitchContext(context.Context, string, string, string, pgtype.UUID) (sqlcgen.SwitchSessionContextRow, error)
}

type SessionContextSwitchService struct {
	sessions sessionContextSwitcher
	newToken func() (string, error)
}

type SwitchedSessionContext struct {
	SessionToken      string
	CSRFToken         string
	ActiveTenantID    pgtype.UUID
	ActiveWorkspaceID pgtype.UUID
	ExpiresAt         time.Time
}

func NewSessionContextSwitchService(sessions sessionContextSwitcher) (*SessionContextSwitchService, error) {
	if sessions == nil {
		return nil, ErrInvalidSessionContextSwitchConfig
	}
	return &SessionContextSwitchService{
		sessions: sessions,
		newToken: newOpaqueTokenValue,
	}, nil
}

func (s *SessionContextSwitchService) Switch(
	ctx context.Context,
	presentedSessionToken string,
	targetTenantID pgtype.UUID,
) (SwitchedSessionContext, error) {
	if s == nil || s.sessions == nil || s.newToken == nil {
		return SwitchedSessionContext{}, ErrInvalidSessionContextSwitchConfig
	}
	if presentedSessionToken == "" {
		return SwitchedSessionContext{}, ErrMissingSessionToken
	}
	if !targetTenantID.Valid {
		return SwitchedSessionContext{}, ErrInvalidTargetContext
	}

	replacementSessionToken, err := s.newToken()
	if err != nil {
		return SwitchedSessionContext{}, fmt.Errorf("generate replacement session token: %w", err)
	}
	replacementCSRFToken, err := s.newToken()
	if err != nil {
		return SwitchedSessionContext{}, fmt.Errorf("generate replacement CSRF token: %w", err)
	}
	if replacementSessionToken == presentedSessionToken {
		return SwitchedSessionContext{}, ErrSessionTokenReuse
	}
	if replacementSessionToken == replacementCSRFToken || replacementCSRFToken == presentedSessionToken {
		return SwitchedSessionContext{}, ErrSessionSecretCollision
	}

	row, err := s.sessions.SwitchContext(
		ctx,
		presentedSessionToken,
		replacementSessionToken,
		replacementCSRFToken,
		targetTenantID,
	)
	if err != nil {
		return SwitchedSessionContext{}, fmt.Errorf("switch authenticated session context: %w", err)
	}
	if !row.SessionID.Valid || !row.ActiveTenantID.Valid || !row.ActiveWorkspaceID.Valid || !row.ExpiresAt.Valid ||
		row.ActiveTenantID != targetTenantID {
		return SwitchedSessionContext{}, ErrInvalidSessionContextSwitchResult
	}

	return SwitchedSessionContext{
		SessionToken:      replacementSessionToken,
		CSRFToken:         replacementCSRFToken,
		ActiveTenantID:    row.ActiveTenantID,
		ActiveWorkspaceID: row.ActiveWorkspaceID,
		ExpiresAt:         row.ExpiresAt.Time.UTC(),
	}, nil
}

func (s SwitchedSessionContext) SessionCookie() *http.Cookie {
	return SessionCookie(s.SessionToken, s.ExpiresAt)
}

func (s SwitchedSessionContext) CSRFCookie() *http.Cookie {
	return CSRFCookie(s.CSRFToken, s.ExpiresAt)
}

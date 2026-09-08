package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var ErrInvalidAuthenticatedContextConfig = errors.New("invalid authenticated context configuration")

type authenticatedContextSessionLookup interface {
	Lookup(context.Context, string) (sqlcgen.GetActiveSessionRow, error)
}

type authenticatedContextProjectionLoader interface {
	Load(context.Context, string) (ContextProjection, error)
}

type authenticatedContextTenantLoader interface {
	Load(context.Context, ActiveSelection) (TenantContext, error)
}

type AuthenticatedContextService struct {
	sessions    authenticatedContextSessionLookup
	projections authenticatedContextProjectionLoader
	tenants     authenticatedContextTenantLoader
}

type AuthenticatedContext struct {
	Session   sqlcgen.GetActiveSessionRow
	Selection ActiveSelection
	Context   TenantContext
}

func NewAuthenticatedContextService(
	sessions authenticatedContextSessionLookup,
	projections authenticatedContextProjectionLoader,
	tenants authenticatedContextTenantLoader,
) (*AuthenticatedContextService, error) {
	if sessions == nil || projections == nil || tenants == nil {
		return nil, ErrInvalidAuthenticatedContextConfig
	}
	return &AuthenticatedContextService{
		sessions:    sessions,
		projections: projections,
		tenants:     tenants,
	}, nil
}

func (s *AuthenticatedContextService) Resolve(ctx context.Context, presentedSessionToken string) (AuthenticatedContext, error) {
	if s == nil || s.sessions == nil || s.projections == nil || s.tenants == nil {
		return AuthenticatedContext{}, ErrInvalidAuthenticatedContextConfig
	}
	if presentedSessionToken == "" {
		return AuthenticatedContext{}, ErrMissingSessionToken
	}

	session, err := s.sessions.Lookup(ctx, presentedSessionToken)
	if err != nil {
		return AuthenticatedContext{}, fmt.Errorf("load active session: %w", err)
	}
	projection, err := s.projections.Load(ctx, presentedSessionToken)
	if err != nil {
		return AuthenticatedContext{}, fmt.Errorf("load session context projection: %w", err)
	}
	selection, err := SelectActiveContext(session, projection)
	if err != nil {
		return AuthenticatedContext{}, fmt.Errorf("select active server context: %w", err)
	}
	tenantContext, err := s.tenants.Load(ctx, selection)
	if err != nil {
		return AuthenticatedContext{}, fmt.Errorf("load tenant-local active context: %w", err)
	}

	return AuthenticatedContext{
		Session:   session,
		Selection: selection,
		Context:   tenantContext,
	}, nil
}

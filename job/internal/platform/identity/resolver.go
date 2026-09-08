package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type resolverSessions interface {
	Lookup(context.Context, string) (sqlcgen.GetActiveSessionRow, error)
}

type resolverContexts interface {
	Load(context.Context, string) (ContextProjection, error)
}

type resolverTenantContexts interface {
	Load(context.Context, ActiveSelection) (TenantContext, error)
}

type ResolvedContext struct {
	Identity         sqlcgen.GetSessionIdentityRow
	Tenant           sqlcgen.IamTenant
	Workspace        sqlcgen.IamWorkspace
	AvailableTenants []sqlcgen.ListSessionTenantsRow
	StarterRole      string
	ExpiresAt        time.Time
}

type Resolver struct {
	sessions       resolverSessions
	contexts       resolverContexts
	tenantContexts resolverTenantContexts
}

func NewResolver(sessions *SessionStore, contexts *ContextStore, tenantContexts *TenantContextStore) *Resolver {
	return newResolver(sessions, contexts, tenantContexts)
}

func newResolver(
	sessions resolverSessions,
	contexts resolverContexts,
	tenantContexts resolverTenantContexts,
) *Resolver {
	return &Resolver{
		sessions:       sessions,
		contexts:       contexts,
		tenantContexts: tenantContexts,
	}
}

func (r *Resolver) Resolve(ctx context.Context, presentedSessionToken string) (ResolvedContext, error) {
	if presentedSessionToken == "" {
		return ResolvedContext{}, ErrMissingSessionToken
	}
	if r == nil || r.sessions == nil || r.contexts == nil || r.tenantContexts == nil {
		return ResolvedContext{}, errors.New("identity resolver is not configured")
	}

	session, err := r.sessions.Lookup(ctx, presentedSessionToken)
	if err != nil {
		return ResolvedContext{}, fmt.Errorf("resolve active session: %w", err)
	}

	projection, err := r.contexts.Load(ctx, presentedSessionToken)
	if err != nil {
		return ResolvedContext{}, fmt.Errorf("resolve session context projection: %w", err)
	}

	selection, err := SelectActiveContext(session, projection)
	if err != nil {
		return ResolvedContext{}, fmt.Errorf("select active tenant context: %w", err)
	}

	tenantContext, err := r.tenantContexts.Load(ctx, selection)
	if err != nil {
		return ResolvedContext{}, fmt.Errorf("resolve tenant-local context: %w", err)
	}

	availableTenants := append([]sqlcgen.ListSessionTenantsRow(nil), projection.Tenants...)
	return ResolvedContext{
		Identity:         selection.Identity,
		Tenant:           tenantContext.Tenant,
		Workspace:        tenantContext.Workspace,
		AvailableTenants: availableTenants,
		StarterRole:      selection.Tenant.StarterRole,
		ExpiresAt:        selection.ExpiresAt,
	}, nil
}

package identity

import (
	"context"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type contextQueries interface {
	GetSessionIdentity(context.Context, []byte) (sqlcgen.GetSessionIdentityRow, error)
	ListSessionTenants(context.Context, []byte) ([]sqlcgen.ListSessionTenantsRow, error)
}

type ContextProjection struct {
	Identity sqlcgen.GetSessionIdentityRow
	Tenants  []sqlcgen.ListSessionTenantsRow
}

type ContextStore struct {
	queries contextQueries
}

func NewContextStore(queries contextQueries) *ContextStore {
	return &ContextStore{queries: queries}
}

func (s *ContextStore) Load(ctx context.Context, presentedSessionToken string) (ContextProjection, error) {
	if presentedSessionToken == "" {
		return ContextProjection{}, ErrMissingSessionToken
	}

	sessionHash := HashToken(presentedSessionToken)
	identityRow, err := s.queries.GetSessionIdentity(ctx, sessionHash[:])
	if err != nil {
		return ContextProjection{}, err
	}

	tenantRows, err := s.queries.ListSessionTenants(ctx, sessionHash[:])
	if err != nil {
		return ContextProjection{}, err
	}

	return ContextProjection{
		Identity: identityRow,
		Tenants:  tenantRows,
	}, nil
}

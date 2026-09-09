package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	platformdb "github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrMembershipContextMismatch = errors.New("membership context mismatch")
	ErrTenantContextMismatch     = errors.New("tenant context mismatch")
	ErrWorkspaceContextMismatch  = errors.New("workspace context mismatch")
)

type tenantContextQueries interface {
	GetMembership(context.Context, sqlcgen.GetMembershipParams) (sqlcgen.IamMembership, error)
	GetTenant(context.Context, pgtype.UUID) (sqlcgen.IamTenant, error)
	GetWorkspace(context.Context, sqlcgen.GetWorkspaceParams) (sqlcgen.IamWorkspace, error)
}

type tenantScope interface {
	WithinTenant(context.Context, string, func(context.Context, tenantContextQueries) error) error
}

type transactorTenantScope struct {
	transactor *platformdb.Transactor
}

func (s transactorTenantScope) WithinTenant(
	ctx context.Context,
	tenantID string,
	fn func(context.Context, tenantContextQueries) error,
) error {
	if s.transactor == nil {
		return errors.New("tenant context transactor is not configured")
	}
	return s.transactor.WithinTenant(ctx, tenantID, func(ctx context.Context, queries *sqlcgen.Queries) error {
		return fn(ctx, queries)
	})
}

type TenantContext struct {
	Tenant    sqlcgen.IamTenant
	Workspace sqlcgen.IamWorkspace
}

type TenantContextStore struct {
	scope tenantScope
}

func NewTenantContextStore(transactor *platformdb.Transactor) *TenantContextStore {
	return newTenantContextStore(transactorTenantScope{transactor: transactor})
}

func newTenantContextStore(scope tenantScope) *TenantContextStore {
	return &TenantContextStore{scope: scope}
}

func (s *TenantContextStore) Load(ctx context.Context, selection ActiveSelection) (TenantContext, error) {
	if s == nil || s.scope == nil {
		return TenantContext{}, errors.New("tenant context store is not configured")
	}
	if !selection.Identity.ID.Valid {
		return TenantContext{}, ErrSessionIdentityMismatch
	}
	if !selection.Tenant.TenantID.Valid {
		return TenantContext{}, ErrMissingActiveTenant
	}
	if !selection.WorkspaceID.Valid {
		return TenantContext{}, ErrMissingActiveWorkspace
	}

	tenantID := uuidString(selection.Tenant.TenantID)
	var loaded TenantContext
	err := s.scope.WithinTenant(ctx, tenantID, func(ctx context.Context, queries tenantContextQueries) error {
		membership, err := queries.GetMembership(ctx, sqlcgen.GetMembershipParams{
			TenantID:  selection.Tenant.TenantID,
			SubjectID: selection.Identity.ID,
		})
		if err != nil {
			return err
		}
		if !membership.TenantID.Valid || membership.TenantID != selection.Tenant.TenantID ||
			!membership.SubjectID.Valid || membership.SubjectID != selection.Identity.ID ||
			membership.Status != "active" || membership.StarterRole != selection.Tenant.StarterRole {
			return ErrMembershipContextMismatch
		}

		tenant, err := queries.GetTenant(ctx, selection.Tenant.TenantID)
		if err != nil {
			return err
		}
		if !tenant.ID.Valid || tenant.ID != selection.Tenant.TenantID || tenant.Status != "active" {
			return ErrTenantContextMismatch
		}

		workspace, err := queries.GetWorkspace(ctx, sqlcgen.GetWorkspaceParams{
			TenantID:    selection.Tenant.TenantID,
			WorkspaceID: selection.WorkspaceID,
		})
		if err != nil {
			return err
		}
		if !workspace.TenantID.Valid || workspace.TenantID != selection.Tenant.TenantID ||
			!workspace.ID.Valid || workspace.ID != selection.WorkspaceID {
			return ErrWorkspaceContextMismatch
		}

		loaded = TenantContext{Tenant: tenant, Workspace: workspace}
		return nil
	})
	if err != nil {
		return TenantContext{}, fmt.Errorf("load tenant-local context: %w", err)
	}

	return loaded, nil
}

func uuidString(id pgtype.UUID) string {
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		id.Bytes[0:4],
		id.Bytes[4:6],
		id.Bytes[6:8],
		id.Bytes[8:10],
		id.Bytes[10:16],
	)
}

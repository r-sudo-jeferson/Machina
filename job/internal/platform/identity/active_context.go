package identity

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrSessionIdentityMismatch  = errors.New("session identity mismatch")
	ErrMissingActiveTenant      = errors.New("active tenant is missing")
	ErrMissingActiveWorkspace   = errors.New("active workspace is missing")
	ErrActiveTenantUnavailable  = errors.New("active tenant is not available to the session")
	ErrInvalidSessionExpiration = errors.New("session expiration is invalid")
)

type ActiveSelection struct {
	Identity    sqlcgen.GetSessionIdentityRow
	Tenant      sqlcgen.ListSessionTenantsRow
	WorkspaceID pgtype.UUID
	ExpiresAt   time.Time
}

func SelectActiveContext(session sqlcgen.GetActiveSessionRow, projection ContextProjection) (ActiveSelection, error) {
	if !session.SubjectID.Valid || !projection.Identity.ID.Valid || session.SubjectID != projection.Identity.ID {
		return ActiveSelection{}, ErrSessionIdentityMismatch
	}
	if !session.ActiveTenantID.Valid {
		return ActiveSelection{}, ErrMissingActiveTenant
	}
	if !session.ActiveWorkspaceID.Valid {
		return ActiveSelection{}, ErrMissingActiveWorkspace
	}
	if !session.ExpiresAt.Valid {
		return ActiveSelection{}, ErrInvalidSessionExpiration
	}

	for _, tenant := range projection.Tenants {
		if !tenant.TenantID.Valid || tenant.TenantID != session.ActiveTenantID {
			continue
		}
		if tenant.Status != "active" {
			return ActiveSelection{}, ErrActiveTenantUnavailable
		}
		return ActiveSelection{
			Identity:    projection.Identity,
			Tenant:      tenant,
			WorkspaceID: session.ActiveWorkspaceID,
			ExpiresAt:   session.ExpiresAt.Time,
		}, nil
	}

	return ActiveSelection{}, ErrActiveTenantUnavailable
}

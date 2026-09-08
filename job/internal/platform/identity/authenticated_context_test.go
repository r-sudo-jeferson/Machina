package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingAuthenticatedContextSessionLookup struct {
	token string
	calls int
	row   sqlcgen.GetActiveSessionRow
	err   error
}

func (s *recordingAuthenticatedContextSessionLookup) Lookup(_ context.Context, token string) (sqlcgen.GetActiveSessionRow, error) {
	s.calls++
	s.token = token
	return s.row, s.err
}

type recordingProjectionLoader struct {
	token      string
	calls      int
	projection ContextProjection
	err        error
}

func (s *recordingProjectionLoader) Load(_ context.Context, token string) (ContextProjection, error) {
	s.calls++
	s.token = token
	return s.projection, s.err
}

type recordingTenantContextLoader struct {
	selection ActiveSelection
	calls     int
	loaded    TenantContext
	err       error
}

func (s *recordingTenantContextLoader) Load(_ context.Context, selection ActiveSelection) (TenantContext, error) {
	s.calls++
	s.selection = selection
	return s.loaded, s.err
}

func TestAuthenticatedContextServiceResolvesOnlyServerOwnedActiveContext(t *testing.T) {
	t.Parallel()

	subjectID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	tenantID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	workspaceID := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	expiresAt := time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC)

	session := sqlcgen.GetActiveSessionRow{
		ID:                pgtype.UUID{Bytes: [16]byte{4}, Valid: true},
		SubjectID:         subjectID,
		ActiveTenantID:    tenantID,
		ActiveWorkspaceID: workspaceID,
		ExpiresAt:         pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}
	projection := ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID, DisplayName: "Verified User"},
		Tenants: []sqlcgen.ListSessionTenantsRow{{
			TenantID:    tenantID,
			Slug:        "tenant-a",
			DisplayName: "Tenant A",
			Status:      "active",
			StarterRole: "owner",
		}},
	}
	loaded := TenantContext{
		Tenant: sqlcgen.IamTenant{ID: tenantID, Slug: "tenant-a", DisplayName: "Tenant A", Status: "active"},
		Workspace: sqlcgen.IamWorkspace{
			TenantID:    tenantID,
			ID:          workspaceID,
			Slug:        "main",
			DisplayName: "Main",
		},
	}

	sessions := &recordingAuthenticatedContextSessionLookup{row: session}
	projections := &recordingProjectionLoader{projection: projection}
	tenants := &recordingTenantContextLoader{loaded: loaded}
	service, err := NewAuthenticatedContextService(sessions, projections, tenants)
	if err != nil {
		t.Fatalf("NewAuthenticatedContextService() error = %v", err)
	}

	got, err := service.Resolve(context.Background(), "presented-session")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if sessions.calls != 1 || sessions.token != "presented-session" || projections.calls != 1 || projections.token != "presented-session" {
		t.Fatalf("session/projection resolution did not use exactly the presented session token: sessions=%#v projections=%#v", sessions, projections)
	}
	if tenants.calls != 1 || tenants.selection.Tenant.TenantID != tenantID || tenants.selection.WorkspaceID != workspaceID {
		t.Fatalf("tenant loader received non-server selection: %#v", tenants.selection)
	}
	if got.Session != session || got.Selection.Tenant.TenantID != tenantID || got.Context.Tenant.ID != tenantID || got.Context.Workspace.ID != workspaceID {
		t.Fatalf("resolved authenticated context = %#v", got)
	}
}

func TestAuthenticatedContextServiceRejectsUnavailableActiveTenantBeforeTenantQuery(t *testing.T) {
	t.Parallel()

	subjectID := pgtype.UUID{Bytes: [16]byte{5}, Valid: true}
	activeTenantID := pgtype.UUID{Bytes: [16]byte{6}, Valid: true}
	otherTenantID := pgtype.UUID{Bytes: [16]byte{7}, Valid: true}
	sessions := &recordingAuthenticatedContextSessionLookup{row: sqlcgen.GetActiveSessionRow{
		SubjectID:         subjectID,
		ActiveTenantID:    activeTenantID,
		ActiveWorkspaceID: pgtype.UUID{Bytes: [16]byte{8}, Valid: true},
		ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}}
	projections := &recordingProjectionLoader{projection: ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenants:  []sqlcgen.ListSessionTenantsRow{{TenantID: otherTenantID, Status: "active"}},
	}}
	tenants := &recordingTenantContextLoader{}
	service, err := NewAuthenticatedContextService(sessions, projections, tenants)
	if err != nil {
		t.Fatalf("NewAuthenticatedContextService() error = %v", err)
	}

	if _, err := service.Resolve(context.Background(), "presented-session"); !errors.Is(err, ErrActiveTenantUnavailable) {
		t.Fatalf("Resolve() error = %v, want ErrActiveTenantUnavailable", err)
	}
	if tenants.calls != 0 {
		t.Fatal("unavailable server-side active tenant reached tenant-local query boundary")
	}
}

func TestAuthenticatedContextServicePreservesDependencyFailures(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		sessionErr    error
		projectionErr error
		tenantErr     error
		wantErr       error
	}{
		{name: "session", sessionErr: errors.New("session lookup unavailable")},
		{name: "projection", projectionErr: errors.New("projection unavailable")},
		{name: "tenant", tenantErr: errors.New("tenant context unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subjectID := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}
			tenantID := pgtype.UUID{Bytes: [16]byte{10}, Valid: true}
			workspaceID := pgtype.UUID{Bytes: [16]byte{11}, Valid: true}
			sessions := &recordingAuthenticatedContextSessionLookup{row: sqlcgen.GetActiveSessionRow{
				SubjectID:         subjectID,
				ActiveTenantID:    tenantID,
				ActiveWorkspaceID: workspaceID,
				ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
			}, err: tc.sessionErr}
			projections := &recordingProjectionLoader{projection: ContextProjection{
				Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID},
				Tenants:  []sqlcgen.ListSessionTenantsRow{{TenantID: tenantID, Status: "active"}},
			}, err: tc.projectionErr}
			tenants := &recordingTenantContextLoader{loaded: TenantContext{
				Tenant:    sqlcgen.IamTenant{ID: tenantID, Status: "active"},
				Workspace: sqlcgen.IamWorkspace{TenantID: tenantID, ID: workspaceID},
			}, err: tc.tenantErr}
			service, err := NewAuthenticatedContextService(sessions, projections, tenants)
			if err != nil {
				t.Fatalf("NewAuthenticatedContextService() error = %v", err)
			}
			wantErr := tc.sessionErr
			if wantErr == nil {
				wantErr = tc.projectionErr
			}
			if wantErr == nil {
				wantErr = tc.tenantErr
			}
			if _, err := service.Resolve(context.Background(), "presented-session"); !errors.Is(err, wantErr) {
				t.Fatalf("Resolve() error = %v, want errors.Is(_, %v)", err, wantErr)
			}
		})
	}
}

func TestAuthenticatedContextServiceRejectsMissingTokenAndInvalidConfiguration(t *testing.T) {
	t.Parallel()

	sessions := &recordingAuthenticatedContextSessionLookup{}
	projections := &recordingProjectionLoader{}
	tenants := &recordingTenantContextLoader{}
	service, err := NewAuthenticatedContextService(sessions, projections, tenants)
	if err != nil {
		t.Fatalf("NewAuthenticatedContextService() error = %v", err)
	}
	if _, err := service.Resolve(context.Background(), ""); !errors.Is(err, ErrMissingSessionToken) {
		t.Fatalf("Resolve() error = %v, want ErrMissingSessionToken", err)
	}
	if sessions.calls != 0 || projections.calls != 0 || tenants.calls != 0 {
		t.Fatal("missing session token reached dependency boundary")
	}

	if _, err := NewAuthenticatedContextService(nil, projections, tenants); err == nil {
		t.Fatal("constructor accepted nil session store")
	}
	if _, err := NewAuthenticatedContextService(sessions, nil, tenants); err == nil {
		t.Fatal("constructor accepted nil projection store")
	}
	if _, err := NewAuthenticatedContextService(sessions, projections, nil); err == nil {
		t.Fatal("constructor accepted nil tenant context store")
	}
}

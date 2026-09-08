package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type fakeTenantContextQueries struct {
	membership       sqlcgen.IamMembership
	membershipErr    error
	tenant           sqlcgen.IamTenant
	tenantErr        error
	workspace        sqlcgen.IamWorkspace
	workspaceErr     error
	membershipCalls  int
	tenantCalls      int
	workspaceCalls   int
}

func (q *fakeTenantContextQueries) GetMembership(_ context.Context, _ sqlcgen.GetMembershipParams) (sqlcgen.IamMembership, error) {
	q.membershipCalls++
	return q.membership, q.membershipErr
}

func (q *fakeTenantContextQueries) GetTenant(_ context.Context, _ pgtype.UUID) (sqlcgen.IamTenant, error) {
	q.tenantCalls++
	return q.tenant, q.tenantErr
}

func (q *fakeTenantContextQueries) GetWorkspace(_ context.Context, _ sqlcgen.GetWorkspaceParams) (sqlcgen.IamWorkspace, error) {
	q.workspaceCalls++
	return q.workspace, q.workspaceErr
}

type fakeTenantScope struct {
	queries  tenantContextQueries
	err      error
	calls    int
	tenantID string
}

func (s *fakeTenantScope) WithinTenant(ctx context.Context, tenantID string, fn func(context.Context, tenantContextQueries) error) error {
	s.calls++
	s.tenantID = tenantID
	if s.err != nil {
		return s.err
	}
	return fn(ctx, s.queries)
}

func TestTenantContextStoreLoadsTenantAndWorkspaceInsideSelectedTenant(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	workspaceID := testUUID(3)
	queries := &fakeTenantContextQueries{
		membership: sqlcgen.IamMembership{TenantID: tenantID, SubjectID: subjectID, StarterRole: "owner", Status: "active"},
		tenant:     sqlcgen.IamTenant{ID: tenantID, Slug: "tenant-a", DisplayName: "Tenant A", Status: "active"},
		workspace:  sqlcgen.IamWorkspace{TenantID: tenantID, ID: workspaceID, Slug: "main", DisplayName: "Main"},
	}
	scope := &fakeTenantScope{queries: queries}
	store := newTenantContextStore(scope)

	got, err := store.Load(context.Background(), ActiveSelection{
		Identity:    sqlcgen.GetSessionIdentityRow{ID: subjectID, DisplayName: "Subject A"},
		Tenant:      sqlcgen.ListSessionTenantsRow{TenantID: tenantID, Status: "active", StarterRole: "owner"},
		WorkspaceID: workspaceID,
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Tenant.ID != tenantID || got.Workspace.ID != workspaceID || got.Workspace.TenantID != tenantID {
		t.Fatalf("Load() = %#v", got)
	}
	if scope.calls != 1 || scope.tenantID != "02000000-0000-0000-0000-000000000000" {
		t.Fatalf("tenant scope = calls:%d tenant:%q", scope.calls, scope.tenantID)
	}
	if queries.membershipCalls != 1 || queries.tenantCalls != 1 || queries.workspaceCalls != 1 {
		t.Fatalf("query calls = membership:%d tenant:%d workspace:%d, want 1 each", queries.membershipCalls, queries.tenantCalls, queries.workspaceCalls)
	}
}

func TestTenantContextStorePropagatesTenantScopeFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("tenant transaction failed")
	scope := &fakeTenantScope{err: wantErr}
	store := newTenantContextStore(scope)

	_, err := store.Load(context.Background(), ActiveSelection{
		Identity:    sqlcgen.GetSessionIdentityRow{ID: testUUID(1)},
		Tenant:      sqlcgen.ListSessionTenantsRow{TenantID: testUUID(2), Status: "active", StarterRole: "owner"},
		WorkspaceID: testUUID(3),
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Load() error = %v, want %v", err, wantErr)
	}
}

func TestTenantContextStoreRejectsRevokedMembershipBeforeTenantReads(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	queries := &fakeTenantContextQueries{
		membership: sqlcgen.IamMembership{TenantID: tenantID, SubjectID: subjectID, StarterRole: "owner", Status: "revoked"},
		tenant:     sqlcgen.IamTenant{ID: tenantID, Status: "active"},
		workspace:  sqlcgen.IamWorkspace{TenantID: tenantID, ID: testUUID(3)},
	}
	store := newTenantContextStore(&fakeTenantScope{queries: queries})

	_, err := store.Load(context.Background(), ActiveSelection{
		Identity:    sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenant:      sqlcgen.ListSessionTenantsRow{TenantID: tenantID, Status: "active", StarterRole: "owner"},
		WorkspaceID: testUUID(3),
	})
	if !errors.Is(err, ErrMembershipContextMismatch) {
		t.Fatalf("Load() error = %v, want ErrMembershipContextMismatch", err)
	}
	if queries.membershipCalls != 1 || queries.tenantCalls != 0 || queries.workspaceCalls != 0 {
		t.Fatalf("query calls = membership:%d tenant:%d workspace:%d, want 1,0,0", queries.membershipCalls, queries.tenantCalls, queries.workspaceCalls)
	}
}

func TestTenantContextStoreRejectsChangedMembershipRole(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	queries := &fakeTenantContextQueries{
		membership: sqlcgen.IamMembership{TenantID: tenantID, SubjectID: subjectID, StarterRole: "member", Status: "active"},
	}
	store := newTenantContextStore(&fakeTenantScope{queries: queries})

	_, err := store.Load(context.Background(), ActiveSelection{
		Identity:    sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenant:      sqlcgen.ListSessionTenantsRow{TenantID: tenantID, Status: "active", StarterRole: "owner"},
		WorkspaceID: testUUID(3),
	})
	if !errors.Is(err, ErrMembershipContextMismatch) {
		t.Fatalf("Load() error = %v, want ErrMembershipContextMismatch", err)
	}
}

func TestTenantContextStoreRejectsTenantRowMismatch(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	queries := &fakeTenantContextQueries{
		membership: sqlcgen.IamMembership{TenantID: tenantID, SubjectID: subjectID, StarterRole: "owner", Status: "active"},
		tenant:     sqlcgen.IamTenant{ID: testUUID(9), Status: "active"},
		workspace:  sqlcgen.IamWorkspace{TenantID: tenantID, ID: testUUID(3)},
	}
	store := newTenantContextStore(&fakeTenantScope{queries: queries})

	_, err := store.Load(context.Background(), ActiveSelection{
		Identity:    sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenant:      sqlcgen.ListSessionTenantsRow{TenantID: tenantID, Status: "active", StarterRole: "owner"},
		WorkspaceID: testUUID(3),
	})
	if !errors.Is(err, ErrTenantContextMismatch) {
		t.Fatalf("Load() error = %v, want ErrTenantContextMismatch", err)
	}
}

func TestTenantContextStoreRejectsNonActiveTenantRow(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	queries := &fakeTenantContextQueries{
		membership: sqlcgen.IamMembership{TenantID: tenantID, SubjectID: subjectID, StarterRole: "owner", Status: "active"},
		tenant:     sqlcgen.IamTenant{ID: tenantID, Status: "suspended"},
		workspace:  sqlcgen.IamWorkspace{TenantID: tenantID, ID: testUUID(3)},
	}
	store := newTenantContextStore(&fakeTenantScope{queries: queries})

	_, err := store.Load(context.Background(), ActiveSelection{
		Identity:    sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenant:      sqlcgen.ListSessionTenantsRow{TenantID: tenantID, Status: "active", StarterRole: "owner"},
		WorkspaceID: testUUID(3),
	})
	if !errors.Is(err, ErrTenantContextMismatch) {
		t.Fatalf("Load() error = %v, want ErrTenantContextMismatch", err)
	}
}

func TestTenantContextStoreRejectsWorkspaceOutsideSelectedTenant(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	workspaceID := testUUID(3)
	queries := &fakeTenantContextQueries{
		membership: sqlcgen.IamMembership{TenantID: tenantID, SubjectID: subjectID, StarterRole: "owner", Status: "active"},
		tenant:     sqlcgen.IamTenant{ID: tenantID, Status: "active"},
		workspace:  sqlcgen.IamWorkspace{TenantID: testUUID(9), ID: workspaceID},
	}
	store := newTenantContextStore(&fakeTenantScope{queries: queries})

	_, err := store.Load(context.Background(), ActiveSelection{
		Identity:    sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenant:      sqlcgen.ListSessionTenantsRow{TenantID: tenantID, Status: "active", StarterRole: "owner"},
		WorkspaceID: workspaceID,
	})
	if !errors.Is(err, ErrWorkspaceContextMismatch) {
		t.Fatalf("Load() error = %v, want ErrWorkspaceContextMismatch", err)
	}
}

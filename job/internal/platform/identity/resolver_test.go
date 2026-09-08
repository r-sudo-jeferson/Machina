package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type fakeResolverSessions struct {
	row   sqlcgen.GetActiveSessionRow
	err   error
	calls int
	token string
}

func (s *fakeResolverSessions) Lookup(_ context.Context, token string) (sqlcgen.GetActiveSessionRow, error) {
	s.calls++
	s.token = token
	return s.row, s.err
}

type fakeResolverContexts struct {
	projection ContextProjection
	err        error
	calls      int
	token      string
}

func (s *fakeResolverContexts) Load(_ context.Context, token string) (ContextProjection, error) {
	s.calls++
	s.token = token
	return s.projection, s.err
}

type fakeResolverTenantContexts struct {
	context   TenantContext
	err       error
	calls     int
	selection ActiveSelection
}

func (s *fakeResolverTenantContexts) Load(_ context.Context, selection ActiveSelection) (TenantContext, error) {
	s.calls++
	s.selection = selection
	return s.context, s.err
}

func TestResolverBuildsTrustedTenantContextInOrder(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	workspaceID := testUUID(3)
	expiresAt := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	sessions := &fakeResolverSessions{row: sqlcgen.GetActiveSessionRow{
		SubjectID:         subjectID,
		ActiveTenantID:    tenantID,
		ActiveWorkspaceID: workspaceID,
		ExpiresAt:         pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}}
	projection := ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID, DisplayName: "Subject A"},
		Tenants: []sqlcgen.ListSessionTenantsRow{
			{TenantID: tenantID, Slug: "tenant-a", DisplayName: "Tenant A", Status: "active", StarterRole: "owner"},
		},
	}
	contexts := &fakeResolverContexts{projection: projection}
	tenantContext := TenantContext{
		Tenant:    sqlcgen.IamTenant{ID: tenantID, Slug: "tenant-a", DisplayName: "Tenant A", Status: "active"},
		Workspace: sqlcgen.IamWorkspace{TenantID: tenantID, ID: workspaceID, Slug: "main", DisplayName: "Main"},
	}
	tenantContexts := &fakeResolverTenantContexts{context: tenantContext}
	resolver := newResolver(sessions, contexts, tenantContexts)

	got, err := resolver.Resolve(context.Background(), "presented-session-token")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Identity != projection.Identity {
		t.Fatalf("Resolve().Identity = %#v, want %#v", got.Identity, projection.Identity)
	}
	if got.Tenant != tenantContext.Tenant || got.Workspace != tenantContext.Workspace {
		t.Fatalf("Resolve() tenant context = %#v", got)
	}
	if !reflect.DeepEqual(got.AvailableTenants, projection.Tenants) {
		t.Fatalf("Resolve().AvailableTenants = %#v, want %#v", got.AvailableTenants, projection.Tenants)
	}
	if got.StarterRole != "owner" || !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Resolve() role/expiry = %q/%v", got.StarterRole, got.ExpiresAt)
	}
	if sessions.calls != 1 || contexts.calls != 1 || tenantContexts.calls != 1 {
		t.Fatalf("resolver calls = sessions:%d contexts:%d tenant:%d, want 1 each", sessions.calls, contexts.calls, tenantContexts.calls)
	}
	if sessions.token != "presented-session-token" || contexts.token != "presented-session-token" {
		t.Fatal("resolver changed the presented session token before handing it to secure stores")
	}
	if tenantContexts.selection.Identity.ID != subjectID || tenantContexts.selection.Tenant.TenantID != tenantID || tenantContexts.selection.WorkspaceID != workspaceID {
		t.Fatalf("tenant selection = %#v", tenantContexts.selection)
	}
}

func TestResolverRejectsMissingTokenBeforeAnyDependency(t *testing.T) {
	t.Parallel()

	sessions := &fakeResolverSessions{}
	contexts := &fakeResolverContexts{}
	tenantContexts := &fakeResolverTenantContexts{}
	resolver := newResolver(sessions, contexts, tenantContexts)

	if _, err := resolver.Resolve(context.Background(), ""); !errors.Is(err, ErrMissingSessionToken) {
		t.Fatalf("Resolve() error = %v, want ErrMissingSessionToken", err)
	}
	if sessions.calls != 0 || contexts.calls != 0 || tenantContexts.calls != 0 {
		t.Fatal("missing token reached a resolver dependency")
	}
}

func TestResolverStopsAfterSessionFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("session lookup failed")
	sessions := &fakeResolverSessions{err: wantErr}
	contexts := &fakeResolverContexts{}
	tenantContexts := &fakeResolverTenantContexts{}
	resolver := newResolver(sessions, contexts, tenantContexts)

	if _, err := resolver.Resolve(context.Background(), "token"); !errors.Is(err, wantErr) {
		t.Fatalf("Resolve() error = %v, want %v", err, wantErr)
	}
	if sessions.calls != 1 || contexts.calls != 0 || tenantContexts.calls != 0 {
		t.Fatalf("resolver calls = sessions:%d contexts:%d tenant:%d, want 1,0,0", sessions.calls, contexts.calls, tenantContexts.calls)
	}
}

func TestResolverStopsAfterContextFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("context lookup failed")
	sessions := &fakeResolverSessions{row: sqlcgen.GetActiveSessionRow{}}
	contexts := &fakeResolverContexts{err: wantErr}
	tenantContexts := &fakeResolverTenantContexts{}
	resolver := newResolver(sessions, contexts, tenantContexts)

	if _, err := resolver.Resolve(context.Background(), "token"); !errors.Is(err, wantErr) {
		t.Fatalf("Resolve() error = %v, want %v", err, wantErr)
	}
	if sessions.calls != 1 || contexts.calls != 1 || tenantContexts.calls != 0 {
		t.Fatalf("resolver calls = sessions:%d contexts:%d tenant:%d, want 1,1,0", sessions.calls, contexts.calls, tenantContexts.calls)
	}
}

func TestResolverStopsWhenSessionAndProjectionDisagree(t *testing.T) {
	t.Parallel()

	sessions := &fakeResolverSessions{row: sqlcgen.GetActiveSessionRow{
		SubjectID:         testUUID(1),
		ActiveTenantID:    testUUID(2),
		ActiveWorkspaceID: testUUID(3),
		ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}}
	contexts := &fakeResolverContexts{projection: ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: testUUID(9)},
		Tenants:  []sqlcgen.ListSessionTenantsRow{{TenantID: testUUID(2), Status: "active", StarterRole: "owner"}},
	}}
	tenantContexts := &fakeResolverTenantContexts{}
	resolver := newResolver(sessions, contexts, tenantContexts)

	if _, err := resolver.Resolve(context.Background(), "token"); !errors.Is(err, ErrSessionIdentityMismatch) {
		t.Fatalf("Resolve() error = %v, want ErrSessionIdentityMismatch", err)
	}
	if tenantContexts.calls != 0 {
		t.Fatal("inconsistent session/projection reached tenant-local loading")
	}
}

func TestResolverPropagatesTenantLocalFailureWithoutPartialContext(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	wantErr := errors.New("tenant-local load failed")
	sessions := &fakeResolverSessions{row: sqlcgen.GetActiveSessionRow{
		SubjectID:         subjectID,
		ActiveTenantID:    tenantID,
		ActiveWorkspaceID: testUUID(3),
		ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}}
	contexts := &fakeResolverContexts{projection: ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenants:  []sqlcgen.ListSessionTenantsRow{{TenantID: tenantID, Status: "active", StarterRole: "owner"}},
	}}
	tenantContexts := &fakeResolverTenantContexts{err: wantErr}
	resolver := newResolver(sessions, contexts, tenantContexts)

	got, err := resolver.Resolve(context.Background(), "token")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Resolve() error = %v, want %v", err, wantErr)
	}
	if !reflect.DeepEqual(got, ResolvedContext{}) {
		t.Fatalf("Resolve() returned partial context on failure: %#v", got)
	}
}

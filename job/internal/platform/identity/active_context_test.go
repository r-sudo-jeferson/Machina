package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

func testUUID(first byte) pgtype.UUID {
	var bytes [16]byte
	bytes[0] = first
	return pgtype.UUID{Bytes: bytes, Valid: true}
}

func TestSelectActiveContextAcceptsOnlySessionOwnedTenant(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	workspaceID := testUUID(3)
	expiresAt := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	session := sqlcgen.GetActiveSessionRow{
		SubjectID:         subjectID,
		ActiveTenantID:    tenantID,
		ActiveWorkspaceID: workspaceID,
		ExpiresAt:         pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}
	projection := ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID, DisplayName: "Subject A"},
		Tenants: []sqlcgen.ListSessionTenantsRow{
			{TenantID: testUUID(4), Slug: "other", DisplayName: "Other", Status: "active", StarterRole: "member"},
			{TenantID: tenantID, Slug: "tenant-a", DisplayName: "Tenant A", Status: "active", StarterRole: "owner"},
		},
	}

	got, err := SelectActiveContext(session, projection)
	if err != nil {
		t.Fatalf("SelectActiveContext() error = %v", err)
	}
	if got.Identity.ID != subjectID || got.Identity.DisplayName != "Subject A" {
		t.Fatalf("selected identity = %#v", got.Identity)
	}
	if got.Tenant.TenantID != tenantID || got.Tenant.StarterRole != "owner" {
		t.Fatalf("selected tenant = %#v", got.Tenant)
	}
	if got.WorkspaceID != workspaceID {
		t.Fatalf("selected workspace = %#v, want %#v", got.WorkspaceID, workspaceID)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("selected expiry = %v, want %v", got.ExpiresAt, expiresAt)
	}
}

func TestSelectActiveContextRejectsIdentityMismatch(t *testing.T) {
	t.Parallel()

	session := sqlcgen.GetActiveSessionRow{
		SubjectID:         testUUID(1),
		ActiveTenantID:    testUUID(2),
		ActiveWorkspaceID: testUUID(3),
		ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}
	projection := ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: testUUID(9), DisplayName: "Other Subject"},
		Tenants:  []sqlcgen.ListSessionTenantsRow{{TenantID: testUUID(2), Status: "active"}},
	}

	if _, err := SelectActiveContext(session, projection); !errors.Is(err, ErrSessionIdentityMismatch) {
		t.Fatalf("SelectActiveContext() error = %v, want ErrSessionIdentityMismatch", err)
	}
}

func TestSelectActiveContextRejectsMissingActiveCoordinates(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	projection := ContextProjection{Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID}}

	cases := []struct {
		name    string
		session sqlcgen.GetActiveSessionRow
		wantErr error
	}{
		{
			name: "tenant",
			session: sqlcgen.GetActiveSessionRow{
				SubjectID:         subjectID,
				ActiveWorkspaceID: testUUID(3),
				ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
			},
			wantErr: ErrMissingActiveTenant,
		},
		{
			name: "workspace",
			session: sqlcgen.GetActiveSessionRow{
				SubjectID:      subjectID,
				ActiveTenantID: testUUID(2),
				ExpiresAt:      pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
			},
			wantErr: ErrMissingActiveWorkspace,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := SelectActiveContext(tc.session, projection); !errors.Is(err, tc.wantErr) {
				t.Fatalf("SelectActiveContext() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestSelectActiveContextRejectsTenantNoLongerAvailable(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	session := sqlcgen.GetActiveSessionRow{
		SubjectID:         subjectID,
		ActiveTenantID:    testUUID(2),
		ActiveWorkspaceID: testUUID(3),
		ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}
	projection := ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenants:  []sqlcgen.ListSessionTenantsRow{{TenantID: testUUID(4), Status: "active"}},
	}

	if _, err := SelectActiveContext(session, projection); !errors.Is(err, ErrActiveTenantUnavailable) {
		t.Fatalf("SelectActiveContext() error = %v, want ErrActiveTenantUnavailable", err)
	}
}

func TestSelectActiveContextRejectsNonActiveTenantProjection(t *testing.T) {
	t.Parallel()

	subjectID := testUUID(1)
	tenantID := testUUID(2)
	session := sqlcgen.GetActiveSessionRow{
		SubjectID:         subjectID,
		ActiveTenantID:    tenantID,
		ActiveWorkspaceID: testUUID(3),
		ExpiresAt:         pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}
	projection := ContextProjection{
		Identity: sqlcgen.GetSessionIdentityRow{ID: subjectID},
		Tenants:  []sqlcgen.ListSessionTenantsRow{{TenantID: tenantID, Status: "suspended"}},
	}

	if _, err := SelectActiveContext(session, projection); !errors.Is(err, ErrActiveTenantUnavailable) {
		t.Fatalf("SelectActiveContext() error = %v, want ErrActiveTenantUnavailable", err)
	}
}

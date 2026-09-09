package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingContextQueries struct {
	identityHash  []byte
	identityCalls int
	identityRow   sqlcgen.GetSessionIdentityRow
	identityErr   error
	tenantHash    []byte
	tenantCalls   int
	tenantRows    []sqlcgen.ListSessionTenantsRow
	tenantErr     error
}

func (q *recordingContextQueries) GetSessionIdentity(_ context.Context, sessionTokenHash []byte) (sqlcgen.GetSessionIdentityRow, error) {
	q.identityCalls++
	q.identityHash = append([]byte(nil), sessionTokenHash...)
	return q.identityRow, q.identityErr
}

func (q *recordingContextQueries) ListSessionTenants(_ context.Context, sessionTokenHash []byte) ([]sqlcgen.ListSessionTenantsRow, error) {
	q.tenantCalls++
	q.tenantHash = append([]byte(nil), sessionTokenHash...)
	return q.tenantRows, q.tenantErr
}

func TestContextStoreLoadHashesPresentedTokenForEveryQuery(t *testing.T) {
	t.Parallel()

	identityRow := sqlcgen.GetSessionIdentityRow{
		ID:          pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
		DisplayName: "Subject A",
	}
	tenantRows := []sqlcgen.ListSessionTenantsRow{
		{
			TenantID:    pgtype.UUID{Bytes: [16]byte{2}, Valid: true},
			Slug:        "tenant-a",
			DisplayName: "Tenant A",
			Status:      "active",
			StarterRole: "owner",
		},
	}
	queries := &recordingContextQueries{identityRow: identityRow, tenantRows: tenantRows}
	store := NewContextStore(queries)

	got, err := store.Load(context.Background(), "presented-session-token")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got.Identity, identityRow) {
		t.Fatalf("Load().Identity = %#v, want %#v", got.Identity, identityRow)
	}
	if !reflect.DeepEqual(got.Tenants, tenantRows) {
		t.Fatalf("Load().Tenants = %#v, want %#v", got.Tenants, tenantRows)
	}
	wantHash := HashToken("presented-session-token")
	if string(queries.identityHash) != string(wantHash[:]) {
		t.Fatal("identity lookup received a value other than the session-token hash")
	}
	if string(queries.tenantHash) != string(wantHash[:]) {
		t.Fatal("tenant lookup received a value other than the session-token hash")
	}
	if queries.identityCalls != 1 || queries.tenantCalls != 1 {
		t.Fatalf("query calls = identity:%d tenants:%d, want 1 each", queries.identityCalls, queries.tenantCalls)
	}
}

func TestContextStoreLoadRejectsMissingPresentedTokenBeforeDatabase(t *testing.T) {
	t.Parallel()

	queries := &recordingContextQueries{}
	store := NewContextStore(queries)

	if _, err := store.Load(context.Background(), ""); !errors.Is(err, ErrMissingSessionToken) {
		t.Fatalf("Load() error = %v, want ErrMissingSessionToken", err)
	}
	if queries.identityCalls != 0 || queries.tenantCalls != 0 {
		t.Fatal("missing session token reached the database boundary")
	}
}

func TestContextStoreLoadFailsClosedWhenIdentityLookupFails(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("identity lookup failed")
	queries := &recordingContextQueries{identityErr: wantErr}
	store := NewContextStore(queries)

	if _, err := store.Load(context.Background(), "presented-session-token"); !errors.Is(err, wantErr) {
		t.Fatalf("Load() error = %v, want %v", err, wantErr)
	}
	if queries.identityCalls != 1 || queries.tenantCalls != 0 {
		t.Fatalf("query calls = identity:%d tenants:%d, want identity 1 and tenants 0", queries.identityCalls, queries.tenantCalls)
	}
}

func TestContextStoreLoadFailsClosedWhenTenantLookupFails(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("tenant lookup failed")
	queries := &recordingContextQueries{
		identityRow: sqlcgen.GetSessionIdentityRow{ID: pgtype.UUID{Bytes: [16]byte{1}, Valid: true}, DisplayName: "Subject A"},
		tenantErr:   wantErr,
	}
	store := NewContextStore(queries)

	if _, err := store.Load(context.Background(), "presented-session-token"); !errors.Is(err, wantErr) {
		t.Fatalf("Load() error = %v, want %v", err, wantErr)
	}
	if queries.identityCalls != 1 || queries.tenantCalls != 1 {
		t.Fatalf("query calls = identity:%d tenants:%d, want 1 each", queries.identityCalls, queries.tenantCalls)
	}
}

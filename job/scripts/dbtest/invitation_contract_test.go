package dbtest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInvitationAcceptanceMigrationIsNarrowAndFailClosed(t *testing.T) {
	root := jobRoot(t)
	migrationPath := filepath.Join(root, "db", "migrations", "0018_invitation_acceptance.sql")
	raw, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatalf("read invitation acceptance migration: %v", err)
	}
	migration := string(raw)

	required := []string{
		"CREATE FUNCTION iam.accept_invitation(",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog",
		"SET row_security = on",
		"octet_length(p_token_hash) <> 32",
		"FOR UPDATE",
		"status = 'suspended'",
		"invitation.status = 'revoked'",
		"invitation.status = 'expired'",
		"invitation.expires_at <= clock_timestamp()",
		"invitation.invited_subject_id <> p_subject_id",
		"membership.status = 'revoked'",
		"membership.starter_role <> invitation.starter_role",
		"GRANT EXECUTE ON FUNCTION iam.accept_invitation(bytea, uuid) TO machina_runtime",
	}
	for _, fragment := range required {
		if !strings.Contains(migration, fragment) {
			t.Fatalf("invitation acceptance migration is missing invariant %q", fragment)
		}
	}

	forbidden := []string{
		"GRANT SELECT ON TABLE iam.invitations TO machina_runtime",
		"GRANT UPDATE ON TABLE iam.invitations TO machina_runtime",
		"BYPASSRLS",
		"DISABLE ROW LEVEL SECURITY",
	}
	for _, fragment := range forbidden {
		if strings.Contains(migration, fragment) {
			t.Fatalf("invitation acceptance migration contains forbidden privilege escape %q", fragment)
		}
	}
}

func jobRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve dbtest path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

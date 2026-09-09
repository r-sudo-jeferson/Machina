package identity

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

func TestKeycloakOIDCInvitedUserAgainstPostgreSQL(t *testing.T) {
	if os.Getenv("MACHINA_RUN_KEYCLOAK_INTEGRATION") != "1" {
		t.Skip("MACHINA_RUN_KEYCLOAK_INTEGRATION is not enabled")
	}

	clientSecret := os.Getenv("MACHINA_KEYCLOAK_CLIENT_SECRET")
	adminUsername := os.Getenv(keycloakIntegrationAdminUsernameEnv)
	adminPassword := os.Getenv(keycloakIntegrationAdminPasswordEnv)
	runtimeDatabaseURL := os.Getenv(keycloakIntegrationDatabaseURLEnv)
	migratorDatabaseURL := os.Getenv(keycloakIntegrationMigratorDatabaseURLEnv)
	if clientSecret == "" || adminUsername == "" || adminPassword == "" || runtimeDatabaseURL == "" || migratorDatabaseURL == "" {
		t.Fatal("Keycloak/PostgreSQL integration credentials or runtime/migrator database URLs are not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	runtimeConfig, err := pgxpool.ParseConfig(runtimeDatabaseURL)
	if err != nil {
		t.Fatalf("parse runtime PostgreSQL integration URL: %v", err)
	}
	runtimeConfig.MaxConns = 2
	runtimePool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatalf("create runtime PostgreSQL integration pool: %v", err)
	}
	defer runtimePool.Close()
	if err := runtimePool.Ping(ctx); err != nil {
		t.Fatalf("ping runtime PostgreSQL integration database: %v", err)
	}

	var runtimeRole string
	var runtimeSuperuser, runtimeCreateDB, runtimeCreateRole, runtimeReplication, runtimeBypassRLS bool
	if err := runtimePool.QueryRow(ctx, `
		SELECT current_user, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
		FROM pg_roles
		WHERE rolname = current_user
	`).Scan(&runtimeRole, &runtimeSuperuser, &runtimeCreateDB, &runtimeCreateRole, &runtimeReplication, &runtimeBypassRLS); err != nil {
		t.Fatalf("read runtime PostgreSQL role flags: %v", err)
	}
	if runtimeRole != "machina_runtime" || runtimeSuperuser || runtimeCreateDB || runtimeCreateRole || runtimeReplication || runtimeBypassRLS {
		t.Fatalf("runtime PostgreSQL role is overprivileged: role=%q flags=%t:%t:%t:%t:%t", runtimeRole, runtimeSuperuser, runtimeCreateDB, runtimeCreateRole, runtimeReplication, runtimeBypassRLS)
	}

	var canSelectInvitations, canExecuteAcceptInvitation bool
	if err := runtimePool.QueryRow(ctx, `
		SELECT has_table_privilege(current_user, 'iam.invitations', 'SELECT'),
		       has_function_privilege(current_user, 'iam.accept_invitation(bytea,uuid)', 'EXECUTE')
	`).Scan(&canSelectInvitations, &canExecuteAcceptInvitation); err != nil {
		t.Fatalf("inspect runtime invitation privileges: %v", err)
	}
	if canSelectInvitations {
		t.Fatal("runtime role has direct SELECT privilege on iam.invitations")
	}
	if !canExecuteAcceptInvitation {
		t.Fatal("runtime role cannot execute the bounded invitation-acceptance function")
	}

	migratorConfig, err := pgxpool.ParseConfig(migratorDatabaseURL)
	if err != nil {
		t.Fatalf("parse migrator PostgreSQL integration URL: %v", err)
	}
	migratorConfig.MaxConns = 1
	migratorPool, err := pgxpool.NewWithConfig(ctx, migratorConfig)
	if err != nil {
		t.Fatalf("create migrator PostgreSQL fixture pool: %v", err)
	}
	defer migratorPool.Close()
	if err := migratorPool.Ping(ctx); err != nil {
		t.Fatalf("ping migrator PostgreSQL fixture database: %v", err)
	}

	tenantID, err := newRandomUUIDv4()
	if err != nil {
		t.Fatalf("generate invitation tenant ID: %v", err)
	}
	invitationID, err := newRandomUUIDv4()
	if err != nil {
		t.Fatalf("generate invitation ID: %v", err)
	}
	creatorSubjectID, err := newRandomUUIDv4()
	if err != nil {
		t.Fatalf("generate invitation creator subject ID: %v", err)
	}
	invitationToken, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate invitation token: %v", err)
	}
	invitationTokenHash := HashToken(invitationToken)
	tenantSlug := fmt.Sprintf("invite-%x", tenantID.Bytes[:8])
	creatorExternalSubject := fmt.Sprintf("ci-inviter-%x", creatorSubjectID.Bytes[:])

	fixtureTx, err := migratorPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin invitation fixture transaction: %v", err)
	}
	defer func() { _ = fixtureTx.Rollback(context.Background()) }()
	if _, err := fixtureTx.Exec(ctx, `SELECT set_config('app.tenant_id', $1::uuid::text, true)`, tenantID); err != nil {
		t.Fatalf("establish tenant-local context for invitation fixture: %v", err)
	}
	if _, err := fixtureTx.Exec(ctx, `
		INSERT INTO iam.subjects (id, external_subject, display_name)
		VALUES ($1, $2, 'Machina CI Inviter')
	`, creatorSubjectID, creatorExternalSubject); err != nil {
		t.Fatalf("create invitation fixture subject: %v", err)
	}
	if _, err := fixtureTx.Exec(ctx, `
		INSERT INTO iam.tenants (id, slug, display_name, status)
		VALUES ($1, $2, 'Machina CI Invitation Tenant', 'active')
	`, tenantID, tenantSlug); err != nil {
		t.Fatalf("create invitation fixture tenant: %v", err)
	}
	if _, err := fixtureTx.Exec(ctx, `
		INSERT INTO iam.invitations (
			tenant_id, id, token_hash, invited_subject_id, starter_role,
			status, expires_at, created_by_subject_id
		)
		VALUES ($1, $2, $3, NULL, 'member', 'pending', clock_timestamp() + interval '30 minutes', $4)
	`, tenantID, invitationID, invitationTokenHash[:], creatorSubjectID); err != nil {
		t.Fatalf("create pending invitation fixture: %v", err)
	}
	if err := fixtureTx.Commit(ctx); err != nil {
		t.Fatalf("commit pending invitation fixture: %v", err)
	}

	client, err := NewOIDCClient(ctx, OIDCClientConfig{
		IssuerURL:    keycloakIntegrationIssuer,
		ClientID:     keycloakIntegrationClientID,
		ClientSecret: clientSecret,
		RedirectURI:  keycloakIntegrationRedirect,
	})
	if err != nil {
		t.Fatalf("create real Keycloak OIDC client: %v", err)
	}
	allowlist, err := NewRedirectAllowlist([]string{keycloakIntegrationPostLoginRedirect})
	if err != nil {
		t.Fatalf("create post-login redirect allowlist: %v", err)
	}
	flow := NewOIDCFlow(newKeycloakOIDCTestAttemptStore(), client, allowlist)

	usernameToken, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate ephemeral Keycloak username: %v", err)
	}
	userPassword, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate ephemeral Keycloak password: %v", err)
	}
	username := "machina-ci-invited-" + strings.ToLower(usernameToken[:16])
	email := username + "@example.test"

	adminToken, err := keycloakAdminAccessToken(ctx, adminUsername, adminPassword)
	if err != nil {
		t.Fatalf("obtain ephemeral Keycloak admin access: %v", err)
	}
	if err := createEphemeralKeycloakUser(ctx, adminToken, username, userPassword, email); err != nil {
		t.Fatalf("create runtime-only Keycloak invited user: %v", err)
	}

	authorizationURL, err := flow.Begin(ctx, keycloakIntegrationPostLoginRedirect)
	if err != nil {
		t.Fatalf("begin invited-user OIDC authorization flow: %v", err)
	}
	callback, err := completeKeycloakBrowserLogin(ctx, authorizationURL, username, userPassword)
	if err != nil {
		t.Fatalf("complete invited-user browser login against Keycloak: %v", err)
	}
	authorization, err := flow.Complete(ctx, callback.state, callback.code)
	if err != nil {
		t.Fatalf("exchange and verify invited-user Keycloak callback: %v", err)
	}
	if authorization.Identity.Subject == "" || authorization.Identity.Email != email {
		t.Fatalf("verified invited-user identity is incomplete: subject=%t email_match=%t", authorization.Identity.Subject != "", authorization.Identity.Email == email)
	}

	queries := sqlcgen.New(runtimePool)
	sessions := NewSessionStore(queries)
	sessionService, err := NewAuthenticatedSessionService(NewSubjectStore(queries), sessions, 2*time.Hour)
	if err != nil {
		t.Fatalf("create invited-user authenticated session service: %v", err)
	}
	authenticatedSession, err := sessionService.Establish(ctx, authorization.Identity)
	if err != nil {
		t.Fatalf("establish invited-user application session: %v", err)
	}
	if !authenticatedSession.SubjectID.Valid {
		t.Fatal("invited-user application subject ID is invalid")
	}
	if _, err := sessions.Lookup(ctx, authenticatedSession.SessionToken); err != nil {
		t.Fatalf("invited-user application session is not active: %v", err)
	}

	invitations := NewInvitationStore(queries)
	accepted, err := invitations.Accept(ctx, invitationToken, authenticatedSession.SubjectID)
	if err != nil {
		t.Fatalf("runtime accept invited-user membership: %v", err)
	}
	if accepted.TenantID != tenantID || accepted.SubjectID != authenticatedSession.SubjectID || accepted.StarterRole != "member" || accepted.Status != "active" {
		t.Fatalf("accepted invitation row changed contract: tenant_match=%t subject_match=%t role=%q status=%q", accepted.TenantID == tenantID, accepted.SubjectID == authenticatedSession.SubjectID, accepted.StarterRole, accepted.Status)
	}

	replayed, err := invitations.Accept(ctx, invitationToken, authenticatedSession.SubjectID)
	if err != nil {
		t.Fatalf("replay invited-user acceptance: %v", err)
	}
	if replayed != accepted {
		t.Fatalf("invitation replay changed membership result: first=%#v replay=%#v", accepted, replayed)
	}

	inspectionTx, err := migratorPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin invitation inspection transaction: %v", err)
	}
	defer func() { _ = inspectionTx.Rollback(context.Background()) }()
	if _, err := inspectionTx.Exec(ctx, `SELECT set_config('app.tenant_id', $1::uuid::text, true)`, tenantID); err != nil {
		t.Fatalf("establish tenant-local context for invitation inspection: %v", err)
	}

	var storedInvitationStatus, storedInvitationRole string
	var storedInvitedSubjectID pgtype.UUID
	var storedTokenHash []byte
	var acceptedAtPresent bool
	if err := inspectionTx.QueryRow(ctx, `
		SELECT status, invited_subject_id, starter_role, token_hash, accepted_at IS NOT NULL
		FROM iam.invitations
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, invitationID).Scan(
		&storedInvitationStatus,
		&storedInvitedSubjectID,
		&storedInvitationRole,
		&storedTokenHash,
		&acceptedAtPresent,
	); err != nil {
		t.Fatalf("inspect accepted invitation fixture: %v", err)
	}
	if storedInvitationStatus != "accepted" || storedInvitationRole != "member" || storedInvitedSubjectID != authenticatedSession.SubjectID || !acceptedAtPresent {
		t.Fatalf("accepted invitation persistence changed contract: status=%q role=%q subject_match=%t accepted_at=%t", storedInvitationStatus, storedInvitationRole, storedInvitedSubjectID == authenticatedSession.SubjectID, acceptedAtPresent)
	}
	if !bytes.Equal(storedTokenHash, invitationTokenHash[:]) || bytes.Equal(storedTokenHash, []byte(invitationToken)) {
		t.Fatal("invitation persistence did not retain only the expected token hash")
	}

	var membershipCount int
	var membershipRole, membershipStatus string
	if err := inspectionTx.QueryRow(ctx, `
		SELECT count(*), min(starter_role), min(status)
		FROM iam.memberships
		WHERE tenant_id = $1 AND subject_id = $2
	`, tenantID, authenticatedSession.SubjectID).Scan(&membershipCount, &membershipRole, &membershipStatus); err != nil {
		t.Fatalf("inspect invited-user membership: %v", err)
	}
	if membershipCount != 1 || membershipRole != "member" || membershipStatus != "active" {
		t.Fatalf("invited-user membership = count:%d role:%q status:%q, want 1/member/active", membershipCount, membershipRole, membershipStatus)
	}
	if err := inspectionTx.Commit(ctx); err != nil {
		t.Fatalf("commit invitation inspection transaction: %v", err)
	}
}

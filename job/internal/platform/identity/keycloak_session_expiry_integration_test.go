package identity

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

const keycloakIntegrationMigratorDatabaseURLEnv = "MACHINA_KEYCLOAK_MIGRATOR_DATABASE_URL"

func TestKeycloakOIDCExpiredApplicationSessionAgainstPostgreSQL(t *testing.T) {
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
	username := "machina-ci-expiry-" + strings.ToLower(usernameToken[:16])
	email := username + "@example.test"

	adminToken, err := keycloakAdminAccessToken(ctx, adminUsername, adminPassword)
	if err != nil {
		t.Fatalf("obtain ephemeral Keycloak admin access: %v", err)
	}
	if err := createEphemeralKeycloakUser(ctx, adminToken, username, userPassword, email); err != nil {
		t.Fatalf("create runtime-only Keycloak user: %v", err)
	}

	authorizationURL, err := flow.Begin(ctx, keycloakIntegrationPostLoginRedirect)
	if err != nil {
		t.Fatalf("begin OIDC authorization flow: %v", err)
	}
	callback, err := completeKeycloakBrowserLogin(ctx, authorizationURL, username, userPassword)
	if err != nil {
		t.Fatalf("complete browser login against Keycloak: %v", err)
	}
	authorization, err := flow.Complete(ctx, callback.state, callback.code)
	if err != nil {
		t.Fatalf("exchange and verify real Keycloak callback: %v", err)
	}

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

	queries := sqlcgen.New(runtimePool)
	sessions := NewSessionStore(queries)
	sessionService, err := NewAuthenticatedSessionService(NewSubjectStore(queries), sessions, 2*time.Hour)
	if err != nil {
		t.Fatalf("create authenticated session service: %v", err)
	}
	authenticatedSession, err := sessionService.Establish(ctx, authorization.Identity)
	if err != nil {
		t.Fatalf("establish application session from verified Keycloak identity: %v", err)
	}
	if _, err := sessions.Lookup(ctx, authenticatedSession.SessionToken); err != nil {
		t.Fatalf("new application session was not active before expiry fixture: %v", err)
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

	sessionTokenHash := HashToken(authenticatedSession.SessionToken)
	tag, err := migratorPool.Exec(ctx, `
		UPDATE iam.sessions
		SET expires_at = clock_timestamp() - interval '1 second'
		WHERE session_token_hash = $1
	`, sessionTokenHash[:])
	if err != nil {
		t.Fatalf("expire application session with migrator-only fixture: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expired application sessions = %d, want 1", tag.RowsAffected())
	}

	if _, err := sessions.Lookup(ctx, authenticatedSession.SessionToken); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expired application session remained resolvable by runtime: %v", err)
	}

	replacementSessionToken, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate replacement session token: %v", err)
	}
	replacementCSRFToken, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate replacement CSRF token: %v", err)
	}
	if _, err := sessions.Rotate(ctx, authenticatedSession.SessionToken, replacementSessionToken, replacementCSRFToken); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expired application session remained rotatable by runtime: %v", err)
	}
}

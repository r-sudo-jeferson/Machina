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

const keycloakIntegrationDatabaseURLEnv = "MACHINA_KEYCLOAK_DATABASE_URL"

type keycloakConcurrentSessionResult struct {
	identity VerifiedOIDCIdentity
	session  AuthenticatedSession
}

func TestKeycloakOIDCConcurrentSessionsAgainstPostgreSQL(t *testing.T) {
	if os.Getenv("MACHINA_RUN_KEYCLOAK_INTEGRATION") != "1" {
		t.Skip("MACHINA_RUN_KEYCLOAK_INTEGRATION is not enabled")
	}

	clientSecret := os.Getenv("MACHINA_KEYCLOAK_CLIENT_SECRET")
	adminUsername := os.Getenv(keycloakIntegrationAdminUsernameEnv)
	adminPassword := os.Getenv(keycloakIntegrationAdminPasswordEnv)
	databaseURL := os.Getenv(keycloakIntegrationDatabaseURLEnv)
	if clientSecret == "" || adminUsername == "" || adminPassword == "" || databaseURL == "" {
		t.Fatal("Keycloak/PostgreSQL integration credentials or database URL are not configured")
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
	username := "machina-ci-concurrent-" + strings.ToLower(usernameToken[:16])
	email := username + "@example.test"

	adminToken, err := keycloakAdminAccessToken(ctx, adminUsername, adminPassword)
	if err != nil {
		t.Fatalf("obtain ephemeral Keycloak admin access: %v", err)
	}
	if err := createEphemeralKeycloakUser(ctx, adminToken, username, userPassword, email); err != nil {
		t.Fatalf("create runtime-only Keycloak user: %v", err)
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse PostgreSQL integration URL: %v", err)
	}
	poolConfig.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("create PostgreSQL integration pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL integration database: %v", err)
	}

	queries := sqlcgen.New(pool)
	subjects := NewSubjectStore(queries)
	sessions := NewSessionStore(queries)
	sessionService, err := NewAuthenticatedSessionService(subjects, sessions, 2*time.Hour)
	if err != nil {
		t.Fatalf("create authenticated session service: %v", err)
	}

	// Keep both OIDC attempts alive while avoiding overlapping password checks,
	// which Keycloak's brute-force protector intentionally guards against per user.
	authorizationURLs := make([]string, 2)
	for index := range authorizationURLs {
		authorizationURLs[index], err = flow.Begin(ctx, keycloakIntegrationPostLoginRedirect)
		if err != nil {
			t.Fatalf("begin concurrent OIDC authorization %d: %v", index+1, err)
		}
	}
	completed := make([]keycloakConcurrentSessionResult, 0, 2)
	for index, authorizationURL := range authorizationURLs {
		callback, err := completeKeycloakBrowserLogin(ctx, authorizationURL, username, userPassword)
		if err != nil {
			t.Fatalf("complete concurrent browser login %d against Keycloak: %v", index+1, err)
		}
		authorization, err := flow.Complete(ctx, callback.state, callback.code)
		if err != nil {
			t.Fatalf("complete concurrent OIDC authorization %d: %v", index+1, err)
		}
		authenticatedSession, err := sessionService.Establish(ctx, authorization.Identity)
		if err != nil {
			t.Fatalf("establish concurrent application session %d: %v", index+1, err)
		}
		completed = append(completed, keycloakConcurrentSessionResult{
			identity: authorization.Identity,
			session:  authenticatedSession,
		})
	}
	if len(completed) != 2 {
		t.Fatalf("concurrent session results = %d, want 2", len(completed))
	}
	first := completed[0]
	second := completed[1]
	if first.identity.Subject == "" || first.identity.Subject != second.identity.Subject {
		t.Fatal("concurrent logins did not resolve to the same verified Keycloak subject")
	}
	if first.identity.Nonce == second.identity.Nonce {
		t.Fatal("concurrent OIDC authorizations reused a nonce")
	}
	if first.session.SubjectID != second.session.SubjectID || !first.session.SubjectID.Valid {
		t.Fatal("concurrent session establishment did not map the same external subject to one application subject")
	}
	if first.session.SessionToken == second.session.SessionToken || first.session.CSRFToken == second.session.CSRFToken {
		t.Fatal("concurrent sessions collided on browser secrets")
	}
	if first.session.SessionToken == first.session.CSRFToken || second.session.SessionToken == second.session.CSRFToken {
		t.Fatal("a concurrent session reused its session token as CSRF token")
	}

	firstStored, err := sessions.Lookup(ctx, first.session.SessionToken)
	if err != nil {
		t.Fatalf("lookup first concurrent session: %v", err)
	}
	secondStored, err := sessions.Lookup(ctx, second.session.SessionToken)
	if err != nil {
		t.Fatalf("lookup second concurrent session: %v", err)
	}
	if firstStored.SubjectID != first.session.SubjectID || secondStored.SubjectID != second.session.SubjectID {
		t.Fatal("persisted concurrent sessions changed subject identity")
	}
	if firstStored.ID == secondStored.ID {
		t.Fatal("concurrent logins collapsed into one persisted session")
	}

	if err := sessions.Revoke(ctx, first.session.SessionToken); err != nil {
		t.Fatalf("revoke first concurrent session: %v", err)
	}
	if _, err := sessions.Lookup(ctx, first.session.SessionToken); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("revoked first concurrent session remained active: %v", err)
	}
	secondAfterRevoke, err := sessions.Lookup(ctx, second.session.SessionToken)
	if err != nil {
		t.Fatalf("revoking first concurrent session invalidated second: %v", err)
	}
	if secondAfterRevoke.SubjectID != second.session.SubjectID {
		t.Fatal("independent second session changed subject after sibling revocation")
	}
	if err := sessions.Revoke(ctx, second.session.SessionToken); err != nil {
		t.Fatalf("revoke second concurrent session: %v", err)
	}
}

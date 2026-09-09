package identity

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestKeycloakOIDCExpiredIDTokenIntegration(t *testing.T) {
	if os.Getenv("MACHINA_RUN_KEYCLOAK_INTEGRATION") != "1" {
		t.Skip("MACHINA_RUN_KEYCLOAK_INTEGRATION is not enabled")
	}

	clientSecret := os.Getenv("MACHINA_KEYCLOAK_CLIENT_SECRET")
	adminUsername := os.Getenv(keycloakIntegrationAdminUsernameEnv)
	adminPassword := os.Getenv(keycloakIntegrationAdminPasswordEnv)
	if clientSecret == "" || adminUsername == "" || adminPassword == "" {
		t.Fatal("Keycloak integration credentials are not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	usernameToken, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate ephemeral Keycloak username: %v", err)
	}
	userPassword, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate ephemeral Keycloak password: %v", err)
	}
	username := "machina-ci-token-expiry-" + strings.ToLower(usernameToken[:16])
	email := username + "@example.test"

	adminToken, err := keycloakAdminAccessToken(ctx, adminUsername, adminPassword)
	if err != nil {
		t.Fatalf("obtain ephemeral Keycloak admin access: %v", err)
	}
	if err := createEphemeralKeycloakUser(ctx, adminToken, username, userPassword, email); err != nil {
		t.Fatalf("create runtime-only Keycloak user: %v", err)
	}

	secrets, err := NewOIDCSecrets()
	if err != nil {
		t.Fatalf("generate OIDC authorization secrets: %v", err)
	}
	authorizationURL, err := client.AuthorizationURL(secrets.State, secrets.Nonce, secrets.PKCEChallenge)
	if err != nil {
		t.Fatalf("build Keycloak authorization URL: %v", err)
	}
	callback, err := completeKeycloakBrowserLogin(ctx, authorizationURL, username, userPassword)
	if err != nil {
		t.Fatalf("complete browser login against Keycloak: %v", err)
	}
	if callback.state != secrets.State {
		t.Fatal("Keycloak callback did not preserve authorization state")
	}

	oauth2Token, err := client.oauth2Config.Exchange(ctx, callback.code, oauth2.VerifierOption(secrets.PKCEVerifier))
	if err != nil {
		t.Fatalf("exchange real Keycloak authorization code: %v", err)
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		t.Fatal("real Keycloak token response omitted id_token")
	}

	verifiedNow, err := client.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		t.Fatalf("production OIDC verifier rejected fresh real Keycloak id_token: %v", err)
	}
	if verifiedNow.Nonce != secrets.Nonce {
		t.Fatal("fresh real Keycloak id_token did not preserve nonce")
	}
	if verifiedNow.Expiry.IsZero() || !time.Now().Before(verifiedNow.Expiry) {
		t.Fatalf("fresh real Keycloak id_token has invalid expiry: %v", verifiedNow.Expiry)
	}

	provider, err := oidc.NewProvider(ctx, keycloakIntegrationIssuer)
	if err != nil {
		t.Fatalf("rediscover real Keycloak provider for expiry evaluation: %v", err)
	}
	expiredVerifier := provider.Verifier(&oidc.Config{
		ClientID: keycloakIntegrationClientID,
		Now: func() time.Time {
			return verifiedNow.Expiry.Add(time.Nanosecond)
		},
	})
	_, err = expiredVerifier.Verify(ctx, rawIDToken)
	var tokenExpired *oidc.TokenExpiredError
	if !errors.As(err, &tokenExpired) {
		t.Fatalf("real Keycloak id_token was not rejected after signed expiry: %v", err)
	}
	if !tokenExpired.Expiry.Equal(verifiedNow.Expiry) {
		t.Fatalf("expired-token error expiry = %v, want signed expiry %v", tokenExpired.Expiry, verifiedNow.Expiry)
	}
}

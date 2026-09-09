package identity

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"
)

const (
	keycloakIntegrationIssuer   = "http://127.0.0.1:18080/realms/machina-preview"
	keycloakIntegrationClientID = "machina-web"
	keycloakIntegrationRedirect = "http://127.0.0.1:18081/auth/callback"
)

func TestKeycloakOIDCProviderIntegration(t *testing.T) {
	if os.Getenv("MACHINA_RUN_KEYCLOAK_INTEGRATION") != "1" {
		t.Skip("MACHINA_RUN_KEYCLOAK_INTEGRATION is not enabled")
	}

	clientSecret := os.Getenv("MACHINA_KEYCLOAK_CLIENT_SECRET")
	if clientSecret == "" {
		generated, _, err := NewOpaqueToken()
		if err != nil {
			t.Fatalf("generate ephemeral integration client secret: %v", err)
		}
		clientSecret = generated
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := NewOIDCClient(ctx, OIDCClientConfig{
		IssuerURL:    keycloakIntegrationIssuer,
		ClientID:     keycloakIntegrationClientID,
		ClientSecret: clientSecret,
		RedirectURI:  keycloakIntegrationRedirect,
	})
	if err != nil {
		t.Fatalf("discover real Keycloak provider: %v", err)
	}

	secrets, err := NewOIDCSecrets()
	if err != nil {
		t.Fatalf("generate OIDC integration secrets: %v", err)
	}
	authorizationURL, err := client.AuthorizationURL(secrets.State, secrets.Nonce, secrets.PKCEChallenge)
	if err != nil {
		t.Fatalf("build Keycloak authorization URL: %v", err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse Keycloak authorization URL: %v", err)
	}
	query := parsed.Query()
	if query.Get("client_id") != keycloakIntegrationClientID || query.Get("redirect_uri") != keycloakIntegrationRedirect {
		t.Fatalf("Keycloak authorization client/redirect = %q/%q", query.Get("client_id"), query.Get("redirect_uri"))
	}
	if query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != secrets.PKCEChallenge {
		t.Fatalf("Keycloak authorization flow = response:%q pkce:%q challenge:%q", query.Get("response_type"), query.Get("code_challenge_method"), query.Get("code_challenge"))
	}
	if query.Get("state") != secrets.State || query.Get("nonce") != secrets.Nonce {
		t.Fatal("Keycloak authorization URL did not preserve state/nonce")
	}
}

func TestKeycloakOIDCProviderUnavailableIntegration(t *testing.T) {
	if os.Getenv("MACHINA_RUN_KEYCLOAK_INTEGRATION") != "1" {
		t.Skip("MACHINA_RUN_KEYCLOAK_INTEGRATION is not enabled")
	}
	if os.Getenv("MACHINA_EXPECT_KEYCLOAK_UNAVAILABLE") != "1" {
		t.Skip("MACHINA_EXPECT_KEYCLOAK_UNAVAILABLE is not enabled")
	}

	clientSecret := os.Getenv("MACHINA_KEYCLOAK_CLIENT_SECRET")
	if clientSecret == "" {
		t.Fatal("Keycloak integration client secret is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := NewOIDCClient(ctx, OIDCClientConfig{
		IssuerURL:    keycloakIntegrationIssuer,
		ClientID:     keycloakIntegrationClientID,
		ClientSecret: clientSecret,
		RedirectURI:  keycloakIntegrationRedirect,
	})
	if err == nil {
		t.Fatalf("Keycloak OIDC discovery unexpectedly succeeded during required outage: client_configured=%t", client != nil)
	}
}

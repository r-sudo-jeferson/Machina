package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOIDCClientAuthorizationURLCarriesStateNonceAndPKCES256(t *testing.T) {
	t.Parallel()

	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}); err != nil {
			t.Errorf("encode discovery document: %v", err)
		}
	}))
	defer server.Close()
	issuer = server.URL

	client, err := NewOIDCClient(context.Background(), OIDCClientConfig{
		IssuerURL:    issuer,
		ClientID:     "machina-web",
		ClientSecret: "server-secret",
		RedirectURI:  "https://app.example.test/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDCClient() error = %v", err)
	}

	rawURL, err := client.AuthorizationURL("browser-state", "id-token-nonce", "pkce-challenge")
	if err != nil {
		t.Fatalf("AuthorizationURL() error = %v", err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if parsed.Scheme != "http" || parsed.Host != strings.TrimPrefix(issuer, "http://") || parsed.Path != "/authorize" {
		t.Fatalf("authorization endpoint = %s, want %s/authorize", parsed.String(), issuer)
	}

	query := parsed.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "machina-web",
		"redirect_uri":          "https://app.example.test/auth/callback",
		"state":                 "browser-state",
		"nonce":                 "id-token-nonce",
		"code_challenge":        "pkce-challenge",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("authorization query %s = %q, want %q", key, got, want)
		}
	}
	if !strings.Contains(" "+query.Get("scope")+" ", " openid ") {
		t.Fatalf("authorization scope = %q, want openid", query.Get("scope"))
	}
	if query.Has("code_verifier") || strings.Contains(rawURL, "server-secret") {
		t.Fatal("authorization URL leaked a server-side credential")
	}
}

func TestOIDCClientAuthorizationURLFailsClosedOnMissingSecurityInputs(t *testing.T) {
	t.Parallel()

	client := &OIDCClient{}
	for _, tc := range []struct {
		name      string
		state     string
		nonce     string
		challenge string
	}{
		{name: "state", state: "", nonce: "nonce", challenge: "challenge"},
		{name: "nonce", state: "state", nonce: "", challenge: "challenge"},
		{name: "challenge", state: "state", nonce: "nonce", challenge: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := client.AuthorizationURL(tc.state, tc.nonce, tc.challenge); err == nil {
				t.Fatalf("AuthorizationURL() accepted missing %s", tc.name)
			}
		})
	}
}

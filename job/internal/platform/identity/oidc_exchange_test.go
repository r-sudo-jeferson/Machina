package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

func TestOIDCClientExchangeAndVerifyUsesPKCEAndVerifiedIDToken(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}

	provider := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{
		PublicKey: privateKey.Public(),
		KeyID:     "test-key",
		Algorithm: oidc.RS256,
	}}}
	var issuer string
	var tokenForm url.Values
	var rawIDToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			provider.ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		tokenForm = r.Form.Clone()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     rawIDToken,
		}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	}))
	defer server.Close()
	issuer = server.URL
	provider.SetIssuer(issuer)

	claims, err := json.Marshal(map[string]any{
		"iss":   issuer,
		"aud":   "machina-web",
		"sub":   "subject-123",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nonce": "verified-nonce",
		"name":  "Machina User",
		"email": "user@example.test",
	})
	if err != nil {
		t.Fatalf("marshal ID token claims: %v", err)
	}
	rawIDToken = oidctest.SignIDToken(privateKey, "test-key", oidc.RS256, string(claims))

	client, err := NewOIDCClient(context.Background(), OIDCClientConfig{
		IssuerURL:    issuer,
		ClientID:     "machina-web",
		ClientSecret: "server-secret",
		RedirectURI:  "https://app.example.test/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDCClient() error = %v", err)
	}

	identity, err := client.ExchangeAndVerify(context.Background(), "authorization-code", "pkce-verifier")
	if err != nil {
		t.Fatalf("ExchangeAndVerify() error = %v", err)
	}
	if identity.Subject != "subject-123" || identity.Nonce != "verified-nonce" {
		t.Fatalf("verified identity = %#v, want subject and nonce from verified ID token", identity)
	}
	if identity.Name != "Machina User" || identity.Email != "user@example.test" {
		t.Fatalf("verified identity profile = %#v, want verified name/email claims", identity)
	}
	if tokenForm.Get("grant_type") != "authorization_code" || tokenForm.Get("code") != "authorization-code" {
		t.Fatalf("token request = %v, want authorization_code exchange", tokenForm)
	}
	if tokenForm.Get("code_verifier") != "pkce-verifier" {
		t.Fatalf("token request code_verifier = %q, want stored PKCE verifier", tokenForm.Get("code_verifier"))
	}
	if tokenForm.Get("redirect_uri") != "https://app.example.test/auth/callback" {
		t.Fatalf("token request redirect_uri = %q", tokenForm.Get("redirect_uri"))
	}
}

func TestOIDCClientExchangeAndVerifyRejectsMissingOrInvalidIDToken(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		audience string
		idToken  bool
	}{
		{name: "missing ID token", audience: "machina-web", idToken: false},
		{name: "wrong audience", audience: "other-client", idToken: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generate signing key: %v", err)
			}
			provider := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{
				PublicKey: privateKey.Public(),
				KeyID:     "test-key",
				Algorithm: oidc.RS256,
			}}}
			var rawIDToken string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/token" {
					provider.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				response := map[string]any{
					"access_token": "access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}
				if tc.idToken {
					response["id_token"] = rawIDToken
				}
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("encode token response: %v", err)
				}
			}))
			defer server.Close()
			provider.SetIssuer(server.URL)

			claims, err := json.Marshal(map[string]any{
				"iss":   server.URL,
				"aud":   tc.audience,
				"sub":   "subject-123",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"nonce": "nonce",
			})
			if err != nil {
				t.Fatalf("marshal ID token claims: %v", err)
			}
			rawIDToken = oidctest.SignIDToken(privateKey, "test-key", oidc.RS256, string(claims))

			client, err := NewOIDCClient(context.Background(), OIDCClientConfig{
				IssuerURL:    server.URL,
				ClientID:     "machina-web",
				ClientSecret: "server-secret",
				RedirectURI:  "https://app.example.test/auth/callback",
			})
			if err != nil {
				t.Fatalf("NewOIDCClient() error = %v", err)
			}
			if _, err := client.ExchangeAndVerify(context.Background(), "authorization-code", "pkce-verifier"); err == nil {
				t.Fatalf("ExchangeAndVerify() accepted %s", tc.name)
			}
		})
	}
}

func TestOIDCClientExchangeAndVerifyFailsClosedOnMissingCodeOrVerifier(t *testing.T) {
	t.Parallel()

	client := &OIDCClient{}
	if _, err := client.ExchangeAndVerify(context.Background(), "", "verifier"); err == nil {
		t.Fatal("ExchangeAndVerify() accepted missing authorization code")
	}
	if _, err := client.ExchangeAndVerify(context.Background(), "code", ""); err == nil {
		t.Fatal("ExchangeAndVerify() accepted missing PKCE verifier")
	}
}

package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestNewOIDCSecretsProducesIndependentStateNonceAndS256PKCE(t *testing.T) {
	t.Parallel()

	secrets, err := NewOIDCSecrets()
	if err != nil {
		t.Fatalf("NewOIDCSecrets() error = %v", err)
	}

	values := map[string]string{
		"state":         secrets.State,
		"nonce":         secrets.Nonce,
		"pkce_verifier": secrets.PKCEVerifier,
	}
	for name, value := range values {
		if len(value) != 43 {
			t.Fatalf("%s length = %d, want 43 raw-url characters for 32 random bytes", name, len(value))
		}
		if strings.ContainsAny(value, "+/=") {
			t.Fatalf("%s %q is not raw URL-safe base64", name, value)
		}
	}
	if secrets.State == secrets.Nonce || secrets.State == secrets.PKCEVerifier || secrets.Nonce == secrets.PKCEVerifier {
		t.Fatal("OIDC state, nonce, and PKCE verifier are not independently generated")
	}

	digest := sha256.Sum256([]byte(secrets.PKCEVerifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if secrets.PKCEChallenge != wantChallenge {
		t.Fatalf("PKCE challenge = %q, want S256 challenge %q", secrets.PKCEChallenge, wantChallenge)
	}
	if len(secrets.PKCEChallenge) != 43 || strings.ContainsAny(secrets.PKCEChallenge, "+/=") {
		t.Fatalf("PKCE challenge %q is not a 43-character raw URL-safe S256 challenge", secrets.PKCEChallenge)
	}
}

func TestRedirectAllowlistAllowsOnlyExactConfiguredURLs(t *testing.T) {
	t.Parallel()

	policy, err := NewRedirectAllowlist([]string{
		"https://app.example.com/auth/callback",
		"https://app.example.com/post-login?mode=compact",
		"http://127.0.0.1:8080/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewRedirectAllowlist() error = %v", err)
	}

	allowed := []string{
		"https://app.example.com/auth/callback",
		"https://app.example.com/post-login?mode=compact",
		"http://127.0.0.1:8080/auth/callback",
	}
	for _, rawURL := range allowed {
		rawURL := rawURL
		t.Run("allow_"+rawURL, func(t *testing.T) {
			t.Parallel()
			if err := policy.Validate(rawURL); err != nil {
				t.Fatalf("Validate(%q) error = %v", rawURL, err)
			}
		})
	}

	rejected := []string{
		"https://app.example.com/auth/callback/extra",
		"https://app.example.com/post-login",
		"https://app.example.com/post-login?mode=compact&next=https://evil.example",
		"https://app.example.com.evil.example/auth/callback",
		"https://app.example.com@evil.example/auth/callback",
		"//evil.example/auth/callback",
		"javascript:alert(1)",
		"http://app.example.com/auth/callback",
	}
	for _, rawURL := range rejected {
		rawURL := rawURL
		t.Run("reject_"+rawURL, func(t *testing.T) {
			t.Parallel()
			if err := policy.Validate(rawURL); !errors.Is(err, ErrRedirectNotAllowed) {
				t.Fatalf("Validate(%q) error = %v, want ErrRedirectNotAllowed", rawURL, err)
			}
		})
	}
}

func TestRedirectAllowlistRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		nil,
		{""},
		{"/relative/callback"},
		{"//evil.example/callback"},
		{"javascript:alert(1)"},
		{"https://user:pass@app.example.com/callback"},
		{"https://app.example.com/callback#fragment"},
		{"http://app.example.com/callback"},
		{"https://*.example.com/callback"},
	}
	for _, allowed := range cases {
		allowed := allowed
		t.Run(strings.Join(allowed, ","), func(t *testing.T) {
			t.Parallel()
			if _, err := NewRedirectAllowlist(allowed); err == nil {
				t.Fatalf("NewRedirectAllowlist(%q) accepted unsafe configuration", allowed)
			}
		})
	}
}

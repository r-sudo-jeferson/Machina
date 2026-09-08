package identity

import (
	"crypto/sha256"
	"encoding/base64"
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

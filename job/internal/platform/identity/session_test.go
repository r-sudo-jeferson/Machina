package identity

import (
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewOpaqueTokenProducesURLSafeHighEntropySecretAndHash(t *testing.T) {
	t.Parallel()

	raw, hash, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken() error = %v", err)
	}
	if len(raw) != 43 {
		t.Fatalf("opaque token length = %d, want 43 raw-url characters for 32 random bytes", len(raw))
	}
	if strings.ContainsAny(raw, "+/=") {
		t.Fatalf("opaque token %q is not raw URL-safe base64", raw)
	}
	wantHash := sha256.Sum256([]byte(raw))
	if hash != wantHash {
		t.Fatal("opaque token hash does not match SHA-256 of presented token")
	}
}

func TestVerifyCSRFRequiresHeaderCookieAndStoredHashToAgree(t *testing.T) {
	t.Parallel()

	raw, hash, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken() error = %v", err)
	}

	if !VerifyCSRF(raw, raw, hash[:]) {
		t.Fatal("VerifyCSRF() rejected matching header, cookie, and stored hash")
	}
	if VerifyCSRF(raw, raw+"x", hash[:]) {
		t.Fatal("VerifyCSRF() accepted mismatched CSRF cookie")
	}
	if VerifyCSRF(raw+"x", raw, hash[:]) {
		t.Fatal("VerifyCSRF() accepted mismatched CSRF header")
	}
	wrongHash := sha256.Sum256([]byte("different-token"))
	if VerifyCSRF(raw, raw, wrongHash[:]) {
		t.Fatal("VerifyCSRF() accepted token that does not match server-side session hash")
	}
	if VerifyCSRF("", "", hash[:]) {
		t.Fatal("VerifyCSRF() accepted empty tokens")
	}
}

func TestSessionCookieUsesHostPrefixAndBrowserHardening(t *testing.T) {
	t.Parallel()

	expires := time.Date(2026, 9, 8, 3, 0, 0, 0, time.UTC)
	cookie := SessionCookie("opaque-session", expires)

	if cookie.Name != "__Host-machina_session" {
		t.Fatalf("session cookie name = %q", cookie.Name)
	}
	if cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("session cookie host-prefix invariants not satisfied: %#v", cookie)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	if !cookie.Expires.Equal(expires) {
		t.Fatalf("session cookie expiry = %v, want %v", cookie.Expires, expires)
	}
}

func TestCSRFCookieIsHostScopedReadableAndStrictSameSite(t *testing.T) {
	t.Parallel()

	expires := time.Date(2026, 9, 8, 3, 0, 0, 0, time.UTC)
	cookie := CSRFCookie("opaque-csrf", expires)

	if cookie.Name != "__Host-machina_csrf" {
		t.Fatalf("CSRF cookie name = %q", cookie.Name)
	}
	if cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || cookie.HttpOnly {
		t.Fatalf("CSRF cookie host-prefix/readability invariants not satisfied: %#v", cookie)
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("CSRF cookie SameSite = %v, want Strict", cookie.SameSite)
	}
	if !cookie.Expires.Equal(expires) {
		t.Fatalf("CSRF cookie expiry = %v, want %v", cookie.Expires, expires)
	}
}

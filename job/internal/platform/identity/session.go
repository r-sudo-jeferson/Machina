package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"time"
)

const (
	SessionCookieName = "__Host-machina_session"
	CSRFCookieName    = "__Host-machina_csrf"
	opaqueTokenBytes  = 32
)

var entropySource io.Reader = rand.Reader

func NewOpaqueToken() (string, [sha256.Size]byte, error) {
	secret := make([]byte, opaqueTokenBytes)
	if _, err := io.ReadFull(entropySource, secret); err != nil {
		return "", [sha256.Size]byte{}, err
	}

	raw := base64.RawURLEncoding.EncodeToString(secret)
	return raw, sha256.Sum256([]byte(raw)), nil
}

func HashToken(raw string) [sha256.Size]byte {
	return sha256.Sum256([]byte(raw))
}

func VerifyCSRF(headerValue, cookieValue string, storedHash []byte) bool {
	if headerValue == "" || cookieValue == "" || len(storedHash) != sha256.Size {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(headerValue), []byte(cookieValue)) != 1 {
		return false
	}

	presentedHash := HashToken(headerValue)
	return subtle.ConstantTimeCompare(presentedHash[:], storedHash) == 1
}

func SessionCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires.UTC(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func CSRFCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     CSRFCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires.UTC(),
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	}
}

func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func ClearCSRFCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	}
}

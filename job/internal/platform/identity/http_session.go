package identity

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

const CSRFHeaderName = "X-CSRF-Token"

var ErrInvalidSessionHTTPConfig = errors.New("invalid session HTTP configuration")

type httpSessionLookup interface {
	Lookup(context.Context, string) (sqlcgen.GetActiveSessionRow, error)
}

type SessionHTTPMiddleware struct {
	sessions httpSessionLookup
}

type sessionContextKey struct{}

func NewSessionHTTPMiddleware(sessions httpSessionLookup) (*SessionHTTPMiddleware, error) {
	if sessions == nil {
		return nil, ErrInvalidSessionHTTPConfig
	}
	return &SessionHTTPMiddleware{sessions: sessions}, nil
}

func (m *SessionHTTPMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil || m.sessions == nil || next == nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}

		presentedSessionToken, ok := singleCookieValue(r, SessionCookieName)
		if !ok || presentedSessionToken == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		session, err := m.sessions.Lookup(r.Context(), presentedSessionToken)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}

		if requiresCSRF(r.Method) {
			headerValues := r.Header.Values(CSRFHeaderName)
			csrfCookie, cookieOK := singleCookieValue(r, CSRFCookieName)
			if len(headerValues) != 1 || headerValues[0] == "" || !cookieOK || csrfCookie == "" ||
				!VerifyCSRF(headerValues[0], csrfCookie, session.CsrfTokenHash) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SessionFromContext(ctx context.Context) (sqlcgen.GetActiveSessionRow, bool) {
	if ctx == nil {
		return sqlcgen.GetActiveSessionRow{}, false
	}
	session, ok := ctx.Value(sessionContextKey{}).(sqlcgen.GetActiveSessionRow)
	return session, ok
}

func singleCookieValue(r *http.Request, name string) (string, bool) {
	if r == nil || name == "" {
		return "", false
	}
	var value string
	found := false
	for _, cookie := range r.Cookies() {
		if cookie.Name != name {
			continue
		}
		if found {
			return "", false
		}
		found = true
		value = cookie.Value
	}
	return value, found
}

func requiresCSRF(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingHTTPSessionLookup struct {
	presentedToken string
	calls          int
	row            sqlcgen.GetActiveSessionRow
	err            error
}

func (s *recordingHTTPSessionLookup) Lookup(_ context.Context, presentedSessionToken string) (sqlcgen.GetActiveSessionRow, error) {
	s.calls++
	s.presentedToken = presentedSessionToken
	return s.row, s.err
}

func TestSessionHTTPMiddlewareAuthenticatesFromHostSessionCookie(t *testing.T) {
	t.Parallel()

	serverTenant := pgtype.UUID{Bytes: [16]byte{0xaa}, Valid: true}
	store := &recordingHTTPSessionLookup{row: sqlcgen.GetActiveSessionRow{
		ID:             pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
		SubjectID:      pgtype.UUID{Bytes: [16]byte{2}, Valid: true},
		ActiveTenantID: serverTenant,
	}}
	middleware, err := NewSessionHTTPMiddleware(store)
	if err != nil {
		t.Fatalf("NewSessionHTTPMiddleware() error = %v", err)
	}

	called := false
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		session, ok := SessionFromContext(r.Context())
		if !ok {
			t.Fatal("authenticated session missing from request context")
		}
		if session.ActiveTenantID != serverTenant {
			t.Fatalf("active tenant = %#v, want server-owned %#v", session.ActiveTenantID, serverTenant)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "presented-session"})
	req.Header.Set("X-Tenant-ID", "attacker-controlled-tenant")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("response status = %d, handler called = %v", recorder.Code, called)
	}
	if store.calls != 1 || store.presentedToken != "presented-session" {
		t.Fatalf("session lookup = %#v", store)
	}
}

func TestSessionHTTPMiddlewareRejectsMissingOrDuplicateSessionCookie(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		cookies []*http.Cookie
	}{
		{name: "missing"},
		{name: "duplicate", cookies: []*http.Cookie{{Name: SessionCookieName, Value: "one"}, {Name: SessionCookieName, Value: "two"}}},
		{name: "empty", cookies: []*http.Cookie{{Name: SessionCookieName, Value: ""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingHTTPSessionLookup{}
			middleware, err := NewSessionHTTPMiddleware(store)
			if err != nil {
				t.Fatalf("NewSessionHTTPMiddleware() error = %v", err)
			}
			called := false
			handler := middleware.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			for _, cookie := range tc.cookies {
				req.AddCookie(cookie)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusUnauthorized || called || store.calls != 0 {
				t.Fatalf("status=%d called=%v lookup_calls=%d", recorder.Code, called, store.calls)
			}
		})
	}
}

func TestSessionHTTPMiddlewareMapsMissingSessionToUnauthorizedAndStoreOutageToUnavailable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		lookupErr  error
		wantStatus int
	}{
		{name: "unknown expired or revoked session", lookupErr: pgx.ErrNoRows, wantStatus: http.StatusUnauthorized},
		{name: "session store outage", lookupErr: errors.New("database secret detail"), wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingHTTPSessionLookup{err: tc.lookupErr}
			middleware, err := NewSessionHTTPMiddleware(store)
			if err != nil {
				t.Fatalf("NewSessionHTTPMiddleware() error = %v", err)
			}
			called := false
			handler := middleware.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "presented-session"})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tc.wantStatus || called {
				t.Fatalf("status=%d want=%d called=%v", recorder.Code, tc.wantStatus, called)
			}
			if strings.Contains(recorder.Body.String(), "database secret detail") {
				t.Fatal("session store error detail leaked to HTTP response")
			}
		})
	}
}

func TestSessionHTTPMiddlewareRequiresDoubleSubmitCSRFForUnsafeMethods(t *testing.T) {
	t.Parallel()

	csrfHash := HashToken("csrf-secret")
	for _, tc := range []struct {
		name       string
		method     string
		header     []string
		cookies    []*http.Cookie
		wantStatus int
		wantCalled bool
	}{
		{name: "valid post", method: http.MethodPost, header: []string{"csrf-secret"}, cookies: []*http.Cookie{{Name: CSRFCookieName, Value: "csrf-secret"}}, wantStatus: http.StatusNoContent, wantCalled: true},
		{name: "get does not require csrf", method: http.MethodGet, wantStatus: http.StatusNoContent, wantCalled: true},
		{name: "missing header", method: http.MethodPost, cookies: []*http.Cookie{{Name: CSRFCookieName, Value: "csrf-secret"}}, wantStatus: http.StatusForbidden},
		{name: "mismatched header", method: http.MethodPost, header: []string{"wrong"}, cookies: []*http.Cookie{{Name: CSRFCookieName, Value: "csrf-secret"}}, wantStatus: http.StatusForbidden},
		{name: "duplicate header", method: http.MethodPost, header: []string{"csrf-secret", "csrf-secret"}, cookies: []*http.Cookie{{Name: CSRFCookieName, Value: "csrf-secret"}}, wantStatus: http.StatusForbidden},
		{name: "duplicate cookie", method: http.MethodPost, header: []string{"csrf-secret"}, cookies: []*http.Cookie{{Name: CSRFCookieName, Value: "csrf-secret"}, {Name: CSRFCookieName, Value: "csrf-secret"}}, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingHTTPSessionLookup{row: sqlcgen.GetActiveSessionRow{CsrfTokenHash: csrfHash[:]}}
			middleware, err := NewSessionHTTPMiddleware(store)
			if err != nil {
				t.Fatalf("NewSessionHTTPMiddleware() error = %v", err)
			}
			called := false
			handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(tc.method, "/resource", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "presented-session"})
			for _, value := range tc.header {
				req.Header.Add(CSRFHeaderName, value)
			}
			for _, cookie := range tc.cookies {
				req.AddCookie(cookie)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tc.wantStatus || called != tc.wantCalled {
				t.Fatalf("status=%d want=%d called=%v want_called=%v", recorder.Code, tc.wantStatus, called, tc.wantCalled)
			}
		})
	}
}

func TestSessionHTTPMiddlewareRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewSessionHTTPMiddleware(nil); err == nil {
		t.Fatal("NewSessionHTTPMiddleware() accepted nil session lookup")
	}
}

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingTenantSwitchExecutor struct {
	request TenantSwitchRequest
	result  TenantSwitchResult
	err     error
	calls   int
}

func (e *recordingTenantSwitchExecutor) Switch(_ context.Context, request TenantSwitchRequest) (TenantSwitchResult, error) {
	e.calls++
	e.request = request
	return e.result, e.err
}

func tenantSwitchHTTPResponseBody() []byte {
	return []byte(`{"identity":{"id":"10000000-0000-0000-0000-0000000000a1","display_name":"Subject A"},"active":{"identity":{"id":"10000000-0000-0000-0000-0000000000a1","display_name":"Subject A"},"tenant":{"id":"00000000-0000-0000-0000-0000000000b2","slug":"tenant-b","display_name":"Tenant B","status":"active"},"workspace":{"id":"20000000-0000-0000-0000-0000000000b2","tenant_id":"00000000-0000-0000-0000-0000000000b2","slug":"main","display_name":"Main"},"capabilities":[],"policy_version":1},"available_tenants":[{"id":"00000000-0000-0000-0000-0000000000b2","slug":"tenant-b","display_name":"Tenant B","status":"active"}],"expires_at":"2026-09-09T12:00:00Z"}`)
}

func tenantSwitchHTTPMiddleware(t *testing.T, next http.Handler) http.Handler {
	t.Helper()
	csrfHash := HashToken("csrf-secret")
	middleware, err := NewSessionHTTPMiddleware(&recordingHTTPSessionLookup{row: sqlcgen.GetActiveSessionRow{ID: tenantSwitchUUID(1), SubjectID: tenantSwitchUUID(2), CsrfTokenHash: csrfHash[:], ExpiresAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC), Valid: true}}})
	if err != nil {
		t.Fatalf("NewSessionHTTPMiddleware() error = %v", err)
	}
	return middleware.Wrap(next)
}

func tenantSwitchHTTPRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/tenant-switch", bytes.NewReader([]byte(`{"tenant_id":"00000000-0000-0000-0000-0000000000b2"}`)))
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "presented-session"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-secret"})
	req.Header.Set(CSRFHeaderName, "csrf-secret")
	req.Header.Set("Idempotency-Key", "tenant-switch-http-key-0001")
	return req
}

func TestTenantSwitchHTTPHandlerSuccessSetsCookiesAndStrongETag(t *testing.T) {
	t.Parallel()
	body := tenantSwitchHTTPResponseBody()
	executor := &recordingTenantSwitchExecutor{result: TenantSwitchResult{ResponseBody: body, ResponseStatus: 200, CorrelationID: tenantSwitchUUID(9), ETag: strongTenantSwitchETag(body), SessionToken: "replacement-session", CSRFToken: "replacement-csrf", SessionExpiresAt: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)}}
	handler, err := NewTenantSwitchHTTPHandler(executor)
	if err != nil {
		t.Fatalf("NewTenantSwitchHTTPHandler() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	tenantSwitchHTTPMiddleware(t, handler).ServeHTTP(recorder, tenantSwitchHTTPRequest())
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", recorder.Header().Get("Cache-Control"))
	}
	if recorder.Header().Get("ETag") != executor.result.ETag {
		t.Fatalf("ETag = %q, want %q", recorder.Header().Get("ETag"), executor.result.ETag)
	}
	if !bytes.Equal(recorder.Body.Bytes(), body) {
		t.Fatalf("response body = %s, want %s", recorder.Body.Bytes(), body)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != SessionCookieName || cookies[1].Name != CSRFCookieName {
		t.Fatalf("Set-Cookie = %#v, want session and csrf replacement cookies", cookies)
	}
	if cookies[0].Value != "replacement-session" || cookies[1].Value != "replacement-csrf" {
		t.Fatalf("replacement cookies = %#v", cookies)
	}
	if executor.calls != 1 || executor.request.PresentedSessionToken != "presented-session" || executor.request.TargetTenantID != tenantSwitchUUID(0xb2) || executor.request.IdempotencyKey != "tenant-switch-http-key-0001" || !executor.request.CorrelationID.Valid {
		t.Fatalf("executor request = %#v", executor.request)
	}
}

func TestTenantSwitchHTTPHandlerReplayNeverSetsCookies(t *testing.T) {
	t.Parallel()
	body := tenantSwitchHTTPResponseBody()
	executor := &recordingTenantSwitchExecutor{result: TenantSwitchResult{ResponseBody: body, ResponseStatus: 200, CorrelationID: tenantSwitchUUID(9), Replay: true, ETag: strongTenantSwitchETag(body)}}
	handler, err := NewTenantSwitchHTTPHandler(executor)
	if err != nil {
		t.Fatalf("NewTenantSwitchHTTPHandler() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	tenantSwitchHTTPMiddleware(t, handler).ServeHTTP(recorder, tenantSwitchHTTPRequest())
	if recorder.Code != http.StatusOK || len(recorder.Result().Cookies()) != 0 {
		t.Fatalf("replay response = status %d cookies %#v", recorder.Code, recorder.Result().Cookies())
	}
	if recorder.Header().Get("ETag") != executor.result.ETag || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("replay headers = %#v", recorder.Header())
	}
}

func TestTenantSwitchHTTPHandlerWritesRFC9457ProblemWithoutLeakingCause(t *testing.T) {
	t.Parallel()
	executor := &recordingTenantSwitchExecutor{err: errors.Join(ErrTenantSwitchScopeConflict, errors.New("database secret detail"))}
	handler, err := NewTenantSwitchHTTPHandler(executor)
	if err != nil {
		t.Fatalf("NewTenantSwitchHTTPHandler() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	tenantSwitchHTTPMiddleware(t, handler).ServeHTTP(recorder, tenantSwitchHTTPRequest())
	if recorder.Code != http.StatusConflict || recorder.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem response = %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	if len(recorder.Result().Cookies()) != 0 || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("problem response emitted cacheable/cookie state: headers=%#v cookies=%#v", recorder.Header(), recorder.Result().Cookies())
	}
	var problem map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
		t.Fatalf("problem JSON = %v", err)
	}
	for _, field := range []string{"type", "title", "status", "code", "correlation_id"} {
		if _, ok := problem[field]; !ok {
			t.Fatalf("problem missing %q: %#v", field, problem)
		}
	}
	if strings.Contains(recorder.Body.String(), "database secret detail") {
		t.Fatal("internal cause leaked in problem response")
	}
}

func TestTenantSwitchHTTPHandlerRejectsMalformedInputBeforeExecutor(t *testing.T) {
	t.Parallel()
	executor := &recordingTenantSwitchExecutor{}
	handler, err := NewTenantSwitchHTTPHandler(executor)
	if err != nil {
		t.Fatalf("NewTenantSwitchHTTPHandler() error = %v", err)
	}
	req := tenantSwitchHTTPRequest()
	req.Body = http.NoBody
	recorder := httptest.NewRecorder()
	tenantSwitchHTTPMiddleware(t, handler).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest || executor.calls != 0 {
		t.Fatalf("malformed input = status %d calls %d", recorder.Code, executor.calls)
	}
}

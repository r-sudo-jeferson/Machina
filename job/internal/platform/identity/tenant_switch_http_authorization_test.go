package identity

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/observability"
)

func TestTenantSwitchHTTPHandlerMapsAuthorizationFailuresFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantOutcome observability.Outcome
	}{
		{
			name:        "cedar deny",
			err:         errors.Join(ErrTenantSwitchForbidden, errors.New("sensitive cedar deny detail")),
			wantStatus:  http.StatusForbidden,
			wantCode:    "tenant_switch_forbidden",
			wantOutcome: observability.OutcomeDenied,
		},
		{
			name:        "authorization unavailable",
			err:         errors.Join(ErrTenantSwitchAuthorizationUnavailable, errors.New("sensitive authz transport detail")),
			wantStatus:  http.StatusServiceUnavailable,
			wantCode:    "tenant_switch_authorization_unavailable",
			wantOutcome: observability.OutcomeError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metrics, reader := tenantSwitchHTTPTestMetrics(t)
			clockCalls := 0
			base := time.Date(2026, 9, 8, 18, 0, 0, 0, time.UTC)
			clock := func() time.Time {
				current := base.Add(time.Duration(clockCalls) * 25 * time.Millisecond)
				clockCalls++
				return current
			}
			executor := &recordingTenantSwitchExecutor{err: tc.err}
			handler, err := newTenantSwitchHTTPHandler(executor, metrics, clock)
			if err != nil {
				t.Fatalf("newTenantSwitchHTTPHandler() error = %v", err)
			}

			recorder := httptest.NewRecorder()
			tenantSwitchHTTPMiddleware(t, handler).ServeHTTP(recorder, tenantSwitchHTTPRequest())

			if recorder.Code != tc.wantStatus || executor.calls != 1 || clockCalls != 2 {
				t.Fatalf("authorization failure response = status:%d executor_calls:%d clock_calls:%d, want status:%d calls:1 clock_calls:2", recorder.Code, executor.calls, clockCalls, tc.wantStatus)
			}
			if recorder.Header().Get("Content-Type") != "application/problem+json" || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("ETag") != "" {
				t.Fatalf("authorization problem headers = %#v", recorder.Header())
			}
			if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("authorization failure emitted cookies = %#v", cookies)
			}
			var problem map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
				t.Fatalf("problem JSON = %v", err)
			}
			if problem["code"] != tc.wantCode {
				t.Fatalf("problem code = %v, want %q", problem["code"], tc.wantCode)
			}
			if strings.Contains(recorder.Body.String(), "sensitive") {
				t.Fatal("authorization failure leaked internal cause")
			}
			assertTenantSwitchHTTPMetric(t, reader, tc.wantOutcome, 25*time.Millisecond)
		})
	}
}

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTenantSwitchHTTPEmitsClosedRootSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	previousProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("TracerProvider.Shutdown() error = %v", err)
		}
	})

	executor := &recordingTenantSwitchExecutor{err: ErrTenantSwitchForbidden}
	handler, err := NewTenantSwitchHTTPHandler(executor)
	if err != nil {
		t.Fatalf("NewTenantSwitchHTTPHandler() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	tenantSwitchHTTPMiddleware(t, handler).ServeHTTP(recorder, tenantSwitchHTTPRequest())

	if recorder.Code != http.StatusForbidden || recorder.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem response = status:%d content_type:%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("ETag") != "" || len(recorder.Result().Cookies()) != 0 {
		t.Fatalf("failure response state = cache:%q etag:%q cookies:%#v", recorder.Header().Get("Cache-Control"), recorder.Header().Get("ETag"), recorder.Result().Cookies())
	}
	var problem map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
		t.Fatalf("problem JSON = %v", err)
	}
	if problem["code"] != "tenant_switch_forbidden" {
		t.Fatalf("problem code = %v, want tenant_switch_forbidden", problem["code"])
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported spans = %d, want exactly 1 tenant-switch HTTP root span", len(spans))
	}
	span := spans[0]
	if span.Name != "tenant.switch.http" || span.Parent.IsValid() {
		t.Fatalf("span identity = name:%q parent:%s", span.Name, span.Parent.SpanID())
	}
	if len(span.Attributes) != 2 {
		t.Fatalf("span attributes = %#v, want exactly correlation and outcome", span.Attributes)
	}
	attributes := make(map[string]string, len(span.Attributes))
	for _, item := range span.Attributes {
		attributes[string(item.Key)] = item.Value.AsString()
	}
	if attributes["machina.correlation_id"] != uuidText(executor.request.CorrelationID) || attributes["machina.outcome"] != "denied" {
		t.Fatalf("span attributes = %#v", attributes)
	}
}

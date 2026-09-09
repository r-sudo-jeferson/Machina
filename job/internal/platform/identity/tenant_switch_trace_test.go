package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/observability"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTenantSwitchHTTPEmitsClosedRootSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("TracerProvider.Shutdown() error = %v", err)
		}
	})
	tracing, err := newTenantSwitchTracing(provider.Tracer("machina-tenant-switch-http-trace-test"))
	if err != nil {
		t.Fatalf("newTenantSwitchTracing() error = %v", err)
	}
	metrics, _ := tenantSwitchHTTPTestMetrics(t)

	executor := &recordingTenantSwitchExecutor{err: ErrTenantSwitchForbidden}
	handler, err := newTenantSwitchHTTPHandlerWithTracing(
		executor,
		metrics,
		tracing,
		time.Now,
		func() (pgtype.UUID, error) { return tenantSwitchUUID(0x44), nil },
	)
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

func TestTenantSwitchTracingRejectsUnsafeInputs(t *testing.T) {
	if _, err := newTenantSwitchTracing(nil); !errors.Is(err, ErrInvalidTenantSwitchCoordinatorConfig) {
		t.Fatalf("newTenantSwitchTracing(nil) error = %v, want ErrInvalidTenantSwitchCoordinatorConfig", err)
	}

	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("TracerProvider.Shutdown() error = %v", err)
		}
	})
	tracing, err := newTenantSwitchTracing(provider.Tracer("machina-tenant-switch-trace-test"))
	if err != nil {
		t.Fatalf("newTenantSwitchTracing() error = %v", err)
	}

	_, span := tracing.start(nil, tenantSwitchSpanAuthorization, tenantSwitchUUID(0x44))
	finishTenantSwitchSpan(span, observability.OutcomeDenied)
	_, span = tracing.start(context.Background(), tenantSwitchSpanName("tenant.switch.dynamic-secret"), tenantSwitchUUID(0x44))
	finishTenantSwitchSpan(span, observability.OutcomeDenied)
	_, span = (&tenantSwitchTracing{}).start(context.Background(), tenantSwitchSpanAuthorization, tenantSwitchUUID(0x44))
	finishTenantSwitchSpan(span, observability.OutcomeDenied)
	finishTenantSwitchSpan(nil, observability.OutcomeDenied)
	if spans := exporter.GetSpans(); len(spans) != 0 {
		t.Fatalf("unsafe adapter inputs exported spans = %#v", spans)
	}

	_, span = tracing.start(context.Background(), tenantSwitchSpanAuthorization, pgtype.UUID{})
	finishTenantSwitchSpan(span, observability.OutcomeDenied)
	spans := exporter.GetSpans()
	if len(spans) != 1 || len(spans[0].Attributes) != 1 || string(spans[0].Attributes[0].Key) != "machina.outcome" || spans[0].Attributes[0].Value.AsString() != "denied" {
		t.Fatalf("invalid correlation span = %#v", spans)
	}

	_, span = tracing.start(context.Background(), tenantSwitchSpanAuthorization, tenantSwitchUUID(0x44))
	finishTenantSwitchSpan(span, observability.Outcome("dynamic-secret"))
	spans = exporter.GetSpans()
	if len(spans) != 2 || len(spans[1].Attributes) != 1 || string(spans[1].Attributes[0].Key) != "machina.correlation_id" {
		t.Fatalf("invalid outcome span = %#v", spans)
	}
}

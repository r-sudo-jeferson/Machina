package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestTenantSwitchTraceLinksHTTPAuthorizationTransactionAuditAndOutbox(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("TracerProvider.Shutdown() error = %v", err)
		}
	})
	tracing, err := newTenantSwitchTracing(provider.Tracer("machina-tenant-switch-full-trace-test"))
	if err != nil {
		t.Fatalf("newTenantSwitchTracing() error = %v", err)
	}

	unit := claimedTenantSwitchUnit()
	authorizer := allowTenantSwitchAuthorizer()
	authorizer.observe = func() [4]int {
		return [4]int{unit.claimCalls, unit.switchCalls, unit.auditCalls, unit.outboxCalls}
	}
	coordinator, err := newTenantSwitchCoordinatorWithTracing(func(ctx context.Context, fn func(context.Context, tenantSwitchUnit) error) error {
		return fn(ctx, unit)
	}, authorizer, tracing)
	if err != nil {
		t.Fatalf("newTenantSwitchCoordinatorWithTracing() error = %v", err)
	}
	metrics, _ := tenantSwitchHTTPTestMetrics(t)
	handler, err := newTenantSwitchHTTPHandlerWithTracing(
		coordinator,
		metrics,
		tracing,
		time.Now,
		func() (pgtype.UUID, error) { return tenantSwitchUUID(3), nil },
	)
	if err != nil {
		t.Fatalf("newTenantSwitchHTTPHandlerWithTracing() error = %v", err)
	}

	request := tenantSwitchHTTPRequest()
	request.Body = io.NopCloser(strings.NewReader(`{"tenant_id":"00000000-0000-0000-0000-000000000002"}`))
	recorder := httptest.NewRecorder()
	tenantSwitchHTTPMiddleware(t, handler).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("tenant switch response = status:%d body:%s", recorder.Code, recorder.Body.Bytes())
	}
	if authorizer.atCall != [4]int{} {
		t.Fatalf("mutation happened before authorization: claim/switch/audit/outbox = %v", authorizer.atCall)
	}
	if unit.claimCalls != 1 || unit.switchCalls != 1 || unit.auditCalls != 1 || unit.outboxCalls != 1 {
		t.Fatalf("transaction effects = claim:%d switch:%d audit:%d outbox:%d", unit.claimCalls, unit.switchCalls, unit.auditCalls, unit.outboxCalls)
	}

	spans := exporter.GetSpans()
	wantNames := []string{
		"tenant.switch.http",
		"tenant.switch.transaction",
		"tenant.switch.authorization",
		"tenant.switch.audit",
		"tenant.switch.outbox",
	}
	if len(spans) != len(wantNames) {
		t.Fatalf("exported spans = %d, want %d linked tenant-switch spans", len(spans), len(wantNames))
	}
	spanIndex := make(map[string]int, len(spans))
	for index, span := range spans {
		if _, duplicate := spanIndex[span.Name]; duplicate {
			t.Fatalf("duplicate span name %q", span.Name)
		}
		spanIndex[span.Name] = index
	}
	for _, name := range wantNames {
		if _, ok := spanIndex[name]; !ok {
			t.Fatalf("missing span %q: %#v", name, spanIndex)
		}
	}

	httpSpan := spans[spanIndex["tenant.switch.http"]]
	transactionSpan := spans[spanIndex["tenant.switch.transaction"]]
	if !httpSpan.SpanContext.TraceID().IsValid() || httpSpan.Parent.IsValid() {
		t.Fatalf("HTTP span context = span:%s parent:%s", httpSpan.SpanContext.SpanID(), httpSpan.Parent.SpanID())
	}
	if transactionSpan.Parent.SpanID() != httpSpan.SpanContext.SpanID() {
		t.Fatalf("transaction parent = %s, want HTTP span %s", transactionSpan.Parent.SpanID(), httpSpan.SpanContext.SpanID())
	}
	for _, name := range []string{"tenant.switch.authorization", "tenant.switch.audit", "tenant.switch.outbox"} {
		span := spans[spanIndex[name]]
		if span.Parent.SpanID() != transactionSpan.SpanContext.SpanID() || span.SpanContext.TraceID() != httpSpan.SpanContext.TraceID() {
			t.Fatalf("%s lineage = trace:%s parent:%s, want trace:%s parent:%s", name, span.SpanContext.TraceID(), span.Parent.SpanID(), httpSpan.SpanContext.TraceID(), transactionSpan.SpanContext.SpanID())
		}
	}

	wantCorrelation := "00000000-0000-0000-0000-000000000003"
	for _, span := range spans {
		if len(span.Attributes) != 2 {
			t.Fatalf("%s attributes = %#v, want exactly correlation and outcome", span.Name, span.Attributes)
		}
		attributes := make(map[string]string, len(span.Attributes))
		for _, item := range span.Attributes {
			attributes[string(item.Key)] = item.Value.AsString()
		}
		if attributes["machina.correlation_id"] != wantCorrelation || attributes["machina.outcome"] != "success" {
			t.Fatalf("%s attributes = %#v", span.Name, attributes)
		}
	}
	if uuidText(unit.claimParams.CorrelationID) != wantCorrelation || uuidText(unit.auditParams.CorrelationID) != wantCorrelation || uuidText(unit.outboxParams.CorrelationID) != wantCorrelation {
		t.Fatalf("persisted correlation = claim:%s audit:%s outbox:%s", uuidText(unit.claimParams.CorrelationID), uuidText(unit.auditParams.CorrelationID), uuidText(unit.outboxParams.CorrelationID))
	}
}

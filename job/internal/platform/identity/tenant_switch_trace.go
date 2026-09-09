package identity

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const (
	tenantSwitchTraceInstrumentationName = "github.com/r-sudo-jeferson/Machina/job/internal/platform/identity"
	tenantSwitchTraceCorrelationKey      = "machina.correlation_id"
)

type tenantSwitchSpanName string

const (
	tenantSwitchSpanHTTP          tenantSwitchSpanName = "tenant.switch.http"
	tenantSwitchSpanTransaction   tenantSwitchSpanName = "tenant.switch.transaction"
	tenantSwitchSpanAuthorization tenantSwitchSpanName = "tenant.switch.authorization"
	tenantSwitchSpanAudit         tenantSwitchSpanName = "tenant.switch.audit"
	tenantSwitchSpanOutbox        tenantSwitchSpanName = "tenant.switch.outbox"
)

type tenantSwitchTracing struct {
	tracer trace.Tracer
}

func newTenantSwitchTracing(tracer trace.Tracer) (*tenantSwitchTracing, error) {
	if tracer == nil {
		return nil, ErrInvalidTenantSwitchCoordinatorConfig
	}
	return &tenantSwitchTracing{tracer: tracer}, nil
}

func (t *tenantSwitchTracing) start(ctx context.Context, name tenantSwitchSpanName, correlationID pgtype.UUID) (context.Context, trace.Span) {
	if t == nil || t.tracer == nil || ctx == nil || !validTenantSwitchSpanName(name) {
		return tenantSwitchNoopSpan()
	}
	ctx, span := t.tracer.Start(ctx, string(name))
	if correlationID.Valid {
		span.SetAttributes(attribute.String(tenantSwitchTraceCorrelationKey, uuidText(correlationID)))
	}
	return ctx, span
}

func finishTenantSwitchSpan(span trace.Span, outcome observability.Outcome) {
	if span == nil {
		return
	}
	if !validTenantSwitchTraceOutcome(outcome) {
		span.End()
		return
	}
	span.SetAttributes(attribute.String(observability.MetricOutcome, string(outcome)))
	if outcome == observability.OutcomeError {
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

func validTenantSwitchSpanName(name tenantSwitchSpanName) bool {
	switch name {
	case tenantSwitchSpanHTTP,
		tenantSwitchSpanTransaction,
		tenantSwitchSpanAuthorization,
		tenantSwitchSpanAudit,
		tenantSwitchSpanOutbox:
		return true
	default:
		return false
	}
}

func validTenantSwitchTraceOutcome(outcome observability.Outcome) bool {
	switch outcome {
	case observability.OutcomeSuccess,
		observability.OutcomeReplay,
		observability.OutcomeDenied,
		observability.OutcomeConflict,
		observability.OutcomeError:
		return true
	default:
		return false
	}
}

func tenantSwitchNoopSpan() (context.Context, trace.Span) {
	return noop.NewTracerProvider().Tracer(tenantSwitchTraceInstrumentationName).Start(context.Background(), string(tenantSwitchSpanHTTP))
}

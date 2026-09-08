package observability

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestSafeMetricAttributesAcceptsOnlyBoundedVocabulary(t *testing.T) {
	t.Parallel()

	got, err := SafeMetricAttributes(
		MetricLabel{Key: MetricOperation, Value: string(OperationTenantSwitch)},
		MetricLabel{Key: MetricOutcome, Value: string(OutcomeSuccess)},
	)
	if err != nil {
		t.Fatalf("SafeMetricAttributes() error = %v", err)
	}
	if len(got) != 2 || string(got[0].Key) != MetricOperation || got[0].Value.AsString() != string(OperationTenantSwitch) ||
		string(got[1].Key) != MetricOutcome || got[1].Value.AsString() != string(OutcomeSuccess) {
		t.Fatalf("SafeMetricAttributes() = %#v", got)
	}
}

func TestSafeMetricAttributesRejectsSensitiveUnknownAndUnboundedLabels(t *testing.T) {
	t.Parallel()

	const sensitiveValue = "sensitive-value-should-not-escape"
	tests := []struct {
		name   string
		labels []MetricLabel
	}{
		{name: "raw email", labels: []MetricLabel{{Key: "user.email", Value: sensitiveValue}}},
		{name: "raw name", labels: []MetricLabel{{Key: "user.name", Value: sensitiveValue}}},
		{name: "raw prompt", labels: []MetricLabel{{Key: "ai.prompt", Value: sensitiveValue}}},
		{name: "tenant slug", labels: []MetricLabel{{Key: "tenant.slug", Value: sensitiveValue}}},
		{name: "tenant id", labels: []MetricLabel{{Key: "tenant.id", Value: sensitiveValue}}},
		{name: "workspace id", labels: []MetricLabel{{Key: "workspace.id", Value: sensitiveValue}}},
		{name: "session id", labels: []MetricLabel{{Key: "session.id", Value: sensitiveValue}}},
		{name: "correlation id", labels: []MetricLabel{{Key: "correlation_id", Value: sensitiveValue}}},
		{name: "idempotency key", labels: []MetricLabel{{Key: "idempotency_key", Value: sensitiveValue}}},
		{name: "unknown key", labels: []MetricLabel{{Key: "custom", Value: sensitiveValue}}},
		{name: "missing labels"},
		{name: "duplicate key", labels: []MetricLabel{
			{Key: MetricOperation, Value: string(OperationTenantSwitch)},
			{Key: MetricOperation, Value: string(OperationAuthzEvaluate)},
		}},
		{name: "too many labels", labels: []MetricLabel{
			{Key: MetricOperation, Value: string(OperationTenantSwitch)},
			{Key: MetricOutcome, Value: string(OutcomeSuccess)},
			{Key: MetricOutcome, Value: string(OutcomeError)},
		}},
		{name: "empty value", labels: []MetricLabel{{Key: MetricOperation}}},
		{name: "unknown operation", labels: []MetricLabel{{Key: MetricOperation, Value: sensitiveValue}}},
		{name: "unknown outcome", labels: []MetricLabel{{Key: MetricOutcome, Value: sensitiveValue}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := SafeMetricAttributes(test.labels...)
			if !errors.Is(err, ErrUnsafeMetricAttribute) {
				t.Fatalf("SafeMetricAttributes() error = %v, want ErrUnsafeMetricAttribute", err)
			}
			if got != nil {
				t.Fatalf("rejected attributes = %#v, want nil", got)
			}
			if err.Error() != ErrUnsafeMetricAttribute.Error() {
				t.Fatalf("rejected metric error disclosed input: %q", err)
			}
		})
	}
}

func TestOperationMetricsRecordsBoundedCountAndDuration(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("MeterProvider.Shutdown() error = %v", err)
		}
	})
	metrics, err := NewOperationMetrics(provider.Meter("machina-observability-test"))
	if err != nil {
		t.Fatalf("NewOperationMetrics() error = %v", err)
	}
	if err := metrics.Record(context.Background(), OperationTenantSwitch, OutcomeSuccess, 25*time.Millisecond); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	collected := collectOperationMetrics(t, reader)
	count, ok := collected["machina.operation.count"].(metricdata.Sum[int64])
	if !ok || len(count.DataPoints) != 1 || count.DataPoints[0].Value != 1 {
		t.Fatalf("operation count = %#v", collected["machina.operation.count"])
	}
	duration, ok := collected["machina.operation.duration"].(metricdata.Histogram[float64])
	if !ok || len(duration.DataPoints) != 1 || duration.DataPoints[0].Count != 1 || duration.DataPoints[0].Sum != 0.025 {
		t.Fatalf("operation duration = %#v", collected["machina.operation.duration"])
	}
	for name, labels := range map[string][]any{
		"machina.operation.count":    metricLabels(count.DataPoints[0].Attributes),
		"machina.operation.duration": metricLabels(duration.DataPoints[0].Attributes),
	} {
		if len(labels) != 4 || labels[0] != MetricOperation || labels[1] != string(OperationTenantSwitch) ||
			labels[2] != MetricOutcome || labels[3] != string(OutcomeSuccess) {
			t.Fatalf("%s labels = %#v", name, labels)
		}
	}
}

func TestOperationMetricsRejectsInvalidMeasurementsBeforeEmission(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("MeterProvider.Shutdown() error = %v", err)
		}
	})
	metrics, err := NewOperationMetrics(provider.Meter("machina-observability-invalid-test"))
	if err != nil {
		t.Fatalf("NewOperationMetrics() error = %v", err)
	}

	var missing *OperationMetrics
	if err := missing.Record(context.Background(), OperationTenantSwitch, OutcomeSuccess, time.Millisecond); !errors.Is(err, ErrInvalidMetricRecorder) {
		t.Fatalf("nil Record() error = %v, want ErrInvalidMetricRecorder", err)
	}
	if err := metrics.Record(context.Background(), OperationTenantSwitch, OutcomeSuccess, -time.Nanosecond); !errors.Is(err, ErrInvalidMetricMeasurement) {
		t.Fatalf("negative duration error = %v, want ErrInvalidMetricMeasurement", err)
	}
	if err := metrics.Record(context.Background(), Operation("unbounded-operation"), OutcomeSuccess, time.Millisecond); !errors.Is(err, ErrUnsafeMetricAttribute) {
		t.Fatalf("unknown operation error = %v, want ErrUnsafeMetricAttribute", err)
	}
	if err := metrics.Record(context.Background(), OperationTenantSwitch, Outcome("unbounded-outcome"), time.Millisecond); !errors.Is(err, ErrUnsafeMetricAttribute) {
		t.Fatalf("unknown outcome error = %v, want ErrUnsafeMetricAttribute", err)
	}

	for name, aggregation := range collectOperationMetrics(t, reader) {
		switch data := aggregation.(type) {
		case metricdata.Sum[int64]:
			if len(data.DataPoints) != 0 {
				t.Fatalf("invalid measurement reached %s: %#v", name, data.DataPoints)
			}
		case metricdata.Histogram[float64]:
			if len(data.DataPoints) != 0 {
				t.Fatalf("invalid measurement reached %s: %#v", name, data.DataPoints)
			}
		default:
			t.Fatalf("unexpected aggregation for %s: %T", name, aggregation)
		}
	}
}

func collectOperationMetrics(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Aggregation {
	t.Helper()
	var resourceMetrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &resourceMetrics); err != nil {
		t.Fatalf("ManualReader.Collect() error = %v", err)
	}
	got := make(map[string]metricdata.Aggregation)
	for _, scope := range resourceMetrics.ScopeMetrics {
		for _, measurement := range scope.Metrics {
			got[measurement.Name] = measurement.Data
		}
	}
	return got
}

func metricLabels(set attribute.Set) []any {
	labels := (&set).ToSlice()
	got := make([]any, 0, len(labels)*2)
	for _, label := range labels {
		got = append(got, string(label.Key), label.Value.AsString())
	}
	return got
}

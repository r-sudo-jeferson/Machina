package observability

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	ErrUnsafeMetricAttribute    = errors.New("unsafe metric attribute")
	ErrInvalidMetricRecorder    = errors.New("invalid metric recorder")
	ErrInvalidMetricMeasurement = errors.New("invalid metric measurement")
)

const (
	MetricOperation = "machina.operation"
	MetricOutcome   = "machina.outcome"
)

type Operation string

const (
	OperationTenantSwitch  Operation = "tenant.switch"
	OperationAuthzEvaluate Operation = "authz.evaluate"
	OperationOutboxPublish Operation = "outbox.publish"
)

type Outcome string

const (
	OutcomeSuccess  Outcome = "success"
	OutcomeReplay   Outcome = "replay"
	OutcomeDenied   Outcome = "denied"
	OutcomeConflict Outcome = "conflict"
	OutcomeError    Outcome = "error"
)

type MetricLabel struct {
	Key   string
	Value string
}

type OperationMetrics struct {
	count    metric.Int64Counter
	duration metric.Float64Histogram
}

var metricVocabulary = map[string]map[string]struct{}{
	MetricOperation: {
		string(OperationTenantSwitch):  {},
		string(OperationAuthzEvaluate): {},
		string(OperationOutboxPublish): {},
	},
	MetricOutcome: {
		string(OutcomeSuccess):  {},
		string(OutcomeReplay):   {},
		string(OutcomeDenied):   {},
		string(OutcomeConflict): {},
		string(OutcomeError):    {},
	},
}

// SafeMetricAttributes is the only boundary for caller-supplied Machina metric
// labels. Rejections are intentionally opaque so unsafe input cannot leak
// through an error, log, or test diagnostic.
func SafeMetricAttributes(labels ...MetricLabel) ([]attribute.KeyValue, error) {
	if len(labels) == 0 || len(labels) > len(metricVocabulary) {
		return nil, ErrUnsafeMetricAttribute
	}

	seen := make(map[string]struct{}, len(labels))
	attributes := make([]attribute.KeyValue, 0, len(labels))
	for _, label := range labels {
		values, keyAllowed := metricVocabulary[label.Key]
		_, valueAllowed := values[label.Value]
		_, duplicate := seen[label.Key]
		if !keyAllowed || !valueAllowed || duplicate {
			return nil, ErrUnsafeMetricAttribute
		}
		seen[label.Key] = struct{}{}
		attributes = append(attributes, attribute.String(label.Key, label.Value))
	}

	return attributes, nil
}

func NewOperationMetrics(meter metric.Meter) (*OperationMetrics, error) {
	if meter == nil {
		return nil, ErrInvalidMetricRecorder
	}
	count, err := meter.Int64Counter(
		"machina.operation.count",
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidMetricRecorder, err)
	}
	duration, err := meter.Float64Histogram(
		"machina.operation.duration",
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidMetricRecorder, err)
	}
	return &OperationMetrics{count: count, duration: duration}, nil
}

func (m *OperationMetrics) Record(ctx context.Context, operation Operation, outcome Outcome, elapsed time.Duration) error {
	if m == nil || m.count == nil || m.duration == nil {
		return ErrInvalidMetricRecorder
	}
	if ctx == nil || elapsed < 0 {
		return ErrInvalidMetricMeasurement
	}
	attributes, err := SafeMetricAttributes(
		MetricLabel{Key: MetricOperation, Value: string(operation)},
		MetricLabel{Key: MetricOutcome, Value: string(outcome)},
	)
	if err != nil {
		return err
	}
	options := metric.WithAttributes(attributes...)
	m.count.Add(ctx, 1, options)
	m.duration.Record(ctx, elapsed.Seconds(), options)
	return nil
}

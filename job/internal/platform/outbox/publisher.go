package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrInvalidEnvelope = errors.New("invalid outbox envelope")
	ErrInvalidWriter   = errors.New("invalid outbox writer")
)

type Envelope struct {
	EventID       pgtype.UUID    `json:"event_id"`
	EventType     string         `json:"event_type"`
	EventVersion  int32          `json:"event_version"`
	OccurredAt    time.Time      `json:"occurred_at"`
	TenantID      pgtype.UUID    `json:"tenant_id"`
	WorkspaceID   pgtype.UUID    `json:"workspace_id,omitempty"`
	CorrelationID pgtype.UUID    `json:"correlation_id"`
	ActorID       pgtype.UUID    `json:"actor_id"`
	Payload       map[string]any `json:"payload"`
}

type Writer interface {
	EnqueueOutboxEvent(context.Context, sqlcgen.EnqueueOutboxEventParams) error
}

type Publisher struct {
	writer Writer
}

func NewPublisher(writer Writer) (*Publisher, error) {
	if writer == nil {
		return nil, ErrInvalidWriter
	}
	return &Publisher{writer: writer}, nil
}

func (p *Publisher) Publish(ctx context.Context, envelope Envelope) error {
	if p == nil || p.writer == nil {
		return ErrInvalidWriter
	}
	params, err := Params(envelope)
	if err != nil {
		return err
	}
	if err := p.writer.EnqueueOutboxEvent(ctx, params); err != nil {
		return fmt.Errorf("enqueue outbox event: %w", err)
	}
	return nil
}

func Params(envelope Envelope) (sqlcgen.EnqueueOutboxEventParams, error) {
	if !envelope.EventID.Valid || !envelope.TenantID.Valid || !envelope.CorrelationID.Valid ||
		!envelope.ActorID.Valid || envelope.EventVersion <= 0 ||
		len(envelope.EventType) < 3 || len(envelope.EventType) > 160 ||
		envelope.OccurredAt.IsZero() || envelope.Payload == nil {
		return sqlcgen.EnqueueOutboxEventParams{}, ErrInvalidEnvelope
	}
	payload, err := json.Marshal(envelope)
	if err != nil || !json.Valid(payload) {
		return sqlcgen.EnqueueOutboxEventParams{}, ErrInvalidEnvelope
	}
	return sqlcgen.EnqueueOutboxEventParams{
		TenantID: envelope.TenantID, EventID: envelope.EventID, EventType: envelope.EventType,
		EventVersion: envelope.EventVersion, CorrelationID: envelope.CorrelationID,
		Payload: payload, OccurredAt: pgtype.Timestamptz{Time: envelope.OccurredAt.UTC(), Valid: true},
	}, nil
}

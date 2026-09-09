package outbox

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestParamsNormalizesOccurredAtToPostgreSQLTimestamptzPrecision(t *testing.T) {
	occurredAt := time.Date(2026, 9, 9, 12, 45, 30, 123456789, time.UTC)
	envelope := Envelope{
		EventID:       outboxTestUUID(0x11),
		EventType:     "machina.test.event",
		EventVersion:  1,
		OccurredAt:    occurredAt,
		TenantID:      outboxTestUUID(0x22),
		WorkspaceID:   outboxTestUUID(0x33),
		CorrelationID: outboxTestUUID(0x44),
		ActorID:       outboxTestUUID(0x55),
		Payload:       map[string]any{"status": "ok"},
	}

	params, err := Params(envelope)
	if err != nil {
		t.Fatalf("Params() error = %v", err)
	}
	want := occurredAt.UTC().Truncate(time.Microsecond)
	if !params.OccurredAt.Valid || !params.OccurredAt.Time.Equal(want) {
		t.Fatalf("Params().OccurredAt = %#v, want %v", params.OccurredAt, want)
	}

	var payload struct {
		OccurredAt time.Time `json:"occurred_at"`
	}
	if err := json.Unmarshal(params.Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	if !payload.OccurredAt.Equal(want) {
		t.Fatalf("payload occurred_at = %v, want %v", payload.OccurredAt, want)
	}
}

func outboxTestUUID(fill byte) pgtype.UUID {
	var value pgtype.UUID
	for i := range value.Bytes {
		value.Bytes[i] = fill
	}
	value.Valid = true
	return value
}

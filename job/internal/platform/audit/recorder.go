package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrInvalidEvent  = errors.New("invalid audit event")
	ErrInvalidWriter = errors.New("invalid audit writer")
)

type Event struct {
	TenantID       pgtype.UUID
	ID             pgtype.UUID
	ActorSubjectID pgtype.UUID
	EventType      string
	Action         string
	Decision       string
	PolicyVersion  int64
	CorrelationID  pgtype.UUID
	SafeMetadata   map[string]any
	PreviousHash   []byte
	OccurredAt     time.Time
}

type Writer interface {
	InsertAuditEvent(context.Context, sqlcgen.InsertAuditEventParams) error
}

type Recorder struct {
	writer Writer
}

func NewRecorder(writer Writer) (*Recorder, error) {
	if writer == nil {
		return nil, ErrInvalidWriter
	}
	return &Recorder{writer: writer}, nil
}

func (r *Recorder) Record(ctx context.Context, event Event) error {
	if r == nil || r.writer == nil {
		return ErrInvalidWriter
	}
	params, err := Params(event)
	if err != nil {
		return err
	}
	if err := r.writer.InsertAuditEvent(ctx, params); err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func Params(event Event) (sqlcgen.InsertAuditEventParams, error) {
	if !event.TenantID.Valid || !event.ID.Valid || !event.ActorSubjectID.Valid ||
		!event.CorrelationID.Valid || event.PolicyVersion <= 0 ||
		len(event.EventType) < 3 || len(event.EventType) > 160 ||
		len(event.Action) < 1 || len(event.Action) > 160 ||
		(event.Decision != "allow" && event.Decision != "deny") ||
		event.OccurredAt.IsZero() {
		return sqlcgen.InsertAuditEventParams{}, ErrInvalidEvent
	}
	if len(event.PreviousHash) != 0 && len(event.PreviousHash) != sha256.Size {
		return sqlcgen.InsertAuditEventParams{}, ErrInvalidEvent
	}
	if event.SafeMetadata == nil {
		event.SafeMetadata = map[string]any{}
	}
	metadata, err := json.Marshal(event.SafeMetadata)
	if err != nil || !json.Valid(metadata) {
		return sqlcgen.InsertAuditEventParams{}, ErrInvalidEvent
	}
	hashInput := struct {
		TenantID       string          `json:"tenant_id"`
		ID             string          `json:"id"`
		ActorSubjectID string          `json:"actor_subject_id"`
		EventType      string          `json:"event_type"`
		Action         string          `json:"action"`
		Decision       string          `json:"decision"`
		PolicyVersion  int64           `json:"policy_version"`
		CorrelationID  string          `json:"correlation_id"`
		SafeMetadata   json.RawMessage `json:"safe_metadata"`
		PreviousHash   string          `json:"previous_hash,omitempty"`
		OccurredAt     string          `json:"occurred_at"`
	}{
		TenantID: uuidText(event.TenantID), ID: uuidText(event.ID), ActorSubjectID: uuidText(event.ActorSubjectID),
		EventType: event.EventType, Action: event.Action, Decision: event.Decision, PolicyVersion: event.PolicyVersion,
		CorrelationID: uuidText(event.CorrelationID), SafeMetadata: metadata,
		PreviousHash: hex.EncodeToString(event.PreviousHash), OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano),
	}
	canonical, err := json.Marshal(hashInput)
	if err != nil {
		return sqlcgen.InsertAuditEventParams{}, ErrInvalidEvent
	}
	sum := sha256.Sum256(canonical)
	return sqlcgen.InsertAuditEventParams{
		TenantID: event.TenantID, EventID: event.ID, ActorSubjectID: event.ActorSubjectID,
		EventType: event.EventType, Action: event.Action, Decision: event.Decision,
		PolicyVersion: event.PolicyVersion, CorrelationID: event.CorrelationID, SafeMetadata: metadata,
		PreviousHash: append([]byte(nil), event.PreviousHash...), EventHash: sum[:],
		OccurredAt: pgtype.Timestamptz{Time: event.OccurredAt.UTC(), Valid: true},
	}, nil
}

func uuidText(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}
	encoded := hex.EncodeToString(value.Bytes[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

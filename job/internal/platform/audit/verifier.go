package audit

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

var ErrInvalidEventContentHash = errors.New("invalid audit event content hash")

type StoredEvent struct {
	TenantID       pgtype.UUID
	ID             pgtype.UUID
	ActorSubjectID pgtype.UUID
	EventType      string
	Action         string
	Decision       string
	PolicyVersion  int64
	CorrelationID  pgtype.UUID
	SafeMetadata   []byte
	PreviousHash   []byte
	EventHash      []byte
	OccurredAt     time.Time
}

type eventContent struct {
	TenantID       pgtype.UUID
	ID             pgtype.UUID
	ActorSubjectID pgtype.UUID
	EventType      string
	Action         string
	Decision       string
	PolicyVersion  int64
	CorrelationID  pgtype.UUID
	SafeMetadata   []byte
	OccurredAt     time.Time
}

func VerifyStoredEventContentHash(stored StoredEvent) error {
	content := eventContent{
		TenantID:       stored.TenantID,
		ID:             stored.ID,
		ActorSubjectID: stored.ActorSubjectID,
		EventType:      stored.EventType,
		Action:         stored.Action,
		Decision:       stored.Decision,
		PolicyVersion:  stored.PolicyVersion,
		CorrelationID:  stored.CorrelationID,
		SafeMetadata:   stored.SafeMetadata,
		OccurredAt:     stored.OccurredAt,
	}
	if !validEventContentShape(content) || len(stored.PreviousHash) != 0 || len(stored.EventHash) != sha256.Size {
		return ErrInvalidEventContentHash
	}

	digest, _, _, err := hashEventContent(content)
	if err != nil || subtle.ConstantTimeCompare(digest[:], stored.EventHash) != 1 {
		return ErrInvalidEventContentHash
	}
	return nil
}

func hashEventContent(content eventContent) ([sha256.Size]byte, []byte, time.Time, error) {
	if !validEventContentShape(content) {
		return [sha256.Size]byte{}, nil, time.Time{}, ErrInvalidEventContentHash
	}
	metadata, err := canonicalizeAuditMetadata(content.SafeMetadata)
	if err != nil {
		return [sha256.Size]byte{}, nil, time.Time{}, ErrInvalidEventContentHash
	}
	occurredAt := content.OccurredAt.UTC().Truncate(time.Microsecond)
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
		TenantID:       uuidText(content.TenantID),
		ID:             uuidText(content.ID),
		ActorSubjectID: uuidText(content.ActorSubjectID),
		EventType:      content.EventType,
		Action:         content.Action,
		Decision:       content.Decision,
		PolicyVersion:  content.PolicyVersion,
		CorrelationID:  uuidText(content.CorrelationID),
		SafeMetadata:   metadata,
		PreviousHash:   "",
		OccurredAt:     occurredAt.Format(time.RFC3339Nano),
	}
	canonical, err := json.Marshal(hashInput)
	if err != nil {
		return [sha256.Size]byte{}, nil, time.Time{}, ErrInvalidEventContentHash
	}
	return sha256.Sum256(canonical), metadata, occurredAt, nil
}

func validEventContentShape(content eventContent) bool {
	return content.TenantID.Valid && content.ID.Valid && content.ActorSubjectID.Valid &&
		content.CorrelationID.Valid && content.PolicyVersion > 0 &&
		len(content.EventType) >= 3 && len(content.EventType) <= 160 &&
		len(content.Action) >= 1 && len(content.Action) <= 160 &&
		(content.Decision == "allow" || content.Decision == "deny") &&
		!content.OccurredAt.IsZero() && len(content.SafeMetadata) > 0
}

func canonicalizeAuditMetadata(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, ErrInvalidEventContentHash
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, ErrInvalidEventContentHash
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidEventContentHash
	}
	canonical, err := json.Marshal(value)
	if err != nil || !json.Valid(canonical) {
		return nil, ErrInvalidEventContentHash
	}
	return canonical, nil
}

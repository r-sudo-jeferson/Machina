package audit

import (
	"bytes"
	"testing"
	"time"
)

func TestParamsNormalizesOccurredAtToPostgreSQLTimestamptzPrecision(t *testing.T) {
	metadata, err := NewAuthorizationDecisionMetadata("allow", 25*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
	}

	original := decisionTestEvent("allow", metadata)
	original.OccurredAt = time.Date(2026, 9, 9, 12, 45, 30, 123456789, time.UTC)
	normalized := original
	normalized.OccurredAt = original.OccurredAt.Truncate(time.Microsecond)

	originalParams, err := Params(original)
	if err != nil {
		t.Fatalf("Params(original) error = %v", err)
	}
	normalizedParams, err := Params(normalized)
	if err != nil {
		t.Fatalf("Params(normalized) error = %v", err)
	}

	if !originalParams.OccurredAt.Valid || !originalParams.OccurredAt.Time.Equal(normalized.OccurredAt) {
		t.Fatalf("Params(original).OccurredAt = %v, want PostgreSQL-persistable %v", originalParams.OccurredAt.Time, normalized.OccurredAt)
	}
	if !bytes.Equal(originalParams.EventHash, normalizedParams.EventHash) {
		t.Fatalf("event hash changes across PostgreSQL timestamptz precision normalization: original=%x normalized=%x", originalParams.EventHash, normalizedParams.EventHash)
	}
}

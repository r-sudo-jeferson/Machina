package audit

import (
	"errors"
	"testing"
	"time"
)

func TestVerifyStoredEventContentHashAcceptsJSONBNormalizationAndRejectsTampering(t *testing.T) {
	metadata, err := NewAuthorizationDecisionMetadata("deny", 25*time.Millisecond, []string{"explicit_forbid"})
	if err != nil {
		t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
	}
	params, err := Params(decisionTestEvent("deny", metadata))
	if err != nil {
		t.Fatalf("Params() error = %v", err)
	}
	stored := StoredEvent{
		TenantID:       params.TenantID,
		ID:             params.EventID,
		ActorSubjectID: params.ActorSubjectID,
		EventType:      params.EventType,
		Action:         params.Action,
		Decision:       params.Decision,
		PolicyVersion:  params.PolicyVersion,
		CorrelationID:  params.CorrelationID,
		SafeMetadata:   []byte(`{"reason_codes": ["explicit_forbid"], "latency_ms": 25}`),
		PreviousHash:   append([]byte(nil), params.PreviousHash...),
		EventHash:      append([]byte(nil), params.EventHash...),
		OccurredAt:     params.OccurredAt.Time,
	}
	if err := VerifyStoredEventContentHash(stored); err != nil {
		t.Fatalf("VerifyStoredEventContentHash(valid JSONB-normalized event) error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(StoredEvent) StoredEvent
	}{
		{name: "action", mutate: func(v StoredEvent) StoredEvent { v.Action = "tenant.read.tampered"; return v }},
		{name: "policy version", mutate: func(v StoredEvent) StoredEvent { v.PolicyVersion++; return v }},
		{name: "correlation", mutate: func(v StoredEvent) StoredEvent { v.CorrelationID = auditTestUUID(0x7a); return v }},
		{name: "metadata", mutate: func(v StoredEvent) StoredEvent { v.SafeMetadata = []byte(`{"latency_ms":26,"reason_codes":["explicit_forbid"]}`); return v }},
		{name: "occurred at", mutate: func(v StoredEvent) StoredEvent { v.OccurredAt = v.OccurredAt.Add(time.Microsecond); return v }},
		{name: "stored event hash", mutate: func(v StoredEvent) StoredEvent {
			v.EventHash = append([]byte(nil), v.EventHash...)
			v.EventHash[0] ^= 0xff
			return v
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyStoredEventContentHash(tc.mutate(stored)); !errors.Is(err, ErrInvalidEventContentHash) {
				t.Fatalf("VerifyStoredEventContentHash(tampered) error = %v, want ErrInvalidEventContentHash", err)
			}
		})
	}
}

func TestVerifyStoredEventContentHashFailsClosedOnMalformedStoredState(t *testing.T) {
	metadata, err := NewAuthorizationDecisionMetadata("allow", time.Millisecond, nil)
	if err != nil {
		t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
	}
	params, err := Params(decisionTestEvent("allow", metadata))
	if err != nil {
		t.Fatalf("Params() error = %v", err)
	}
	stored := StoredEvent{
		TenantID:       params.TenantID,
		ID:             params.EventID,
		ActorSubjectID: params.ActorSubjectID,
		EventType:      params.EventType,
		Action:         params.Action,
		Decision:       params.Decision,
		PolicyVersion:  params.PolicyVersion,
		CorrelationID:  params.CorrelationID,
		SafeMetadata:   append([]byte(nil), params.SafeMetadata...),
		EventHash:      append([]byte(nil), params.EventHash...),
		OccurredAt:     params.OccurredAt.Time,
	}

	cases := []struct {
		name   string
		mutate func(StoredEvent) StoredEvent
	}{
		{name: "previous hash became caller owned", mutate: func(v StoredEvent) StoredEvent { v.PreviousHash = make([]byte, 32); return v }},
		{name: "malformed metadata", mutate: func(v StoredEvent) StoredEvent { v.SafeMetadata = []byte(`{"latency_ms":`); return v }},
		{name: "non object metadata", mutate: func(v StoredEvent) StoredEvent { v.SafeMetadata = []byte(`[]`); return v }},
		{name: "short event hash", mutate: func(v StoredEvent) StoredEvent { v.EventHash = []byte{1, 2, 3}; return v }},
		{name: "zero occurred at", mutate: func(v StoredEvent) StoredEvent { v.OccurredAt = time.Time{}; return v }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyStoredEventContentHash(tc.mutate(stored)); !errors.Is(err, ErrInvalidEventContentHash) {
				t.Fatalf("VerifyStoredEventContentHash(invalid) error = %v, want ErrInvalidEventContentHash", err)
			}
		})
	}
}

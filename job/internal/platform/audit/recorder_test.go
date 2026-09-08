package audit

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestReconstructDecisionRecoversAllowedAndDeniedEvidence(t *testing.T) {
	cases := []struct {
		name        string
		decision    string
		reasons     []string
		wantReasons []string
	}{
		{name: "allowed", decision: "allow"},
		{name: "denied", decision: "deny", reasons: []string{"explicit_forbid", "stale_policy_version"}, wantReasons: []string{"explicit_forbid", "stale_policy_version"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := NewAuthorizationDecisionMetadata(tc.decision, 25*time.Millisecond, tc.reasons)
			if err != nil {
				t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
			}
			event := decisionTestEvent(tc.decision, metadata)
			params, err := Params(event)
			if err != nil {
				t.Fatalf("Params() error = %v", err)
			}
			stored := StoredDecision{
				TenantID:       params.TenantID,
				ActorSubjectID: params.ActorSubjectID,
				Action:         params.Action,
				Decision:       params.Decision,
				PolicyVersion:  params.PolicyVersion,
				CorrelationID:  params.CorrelationID,
				SafeMetadata:   params.SafeMetadata,
			}
			got, err := ReconstructDecision(stored)
			if err != nil {
				t.Fatalf("ReconstructDecision() error = %v", err)
			}
			if got.TenantID != event.TenantID || got.ActorSubjectID != event.ActorSubjectID || got.Action != event.Action || got.Decision != tc.decision || got.PolicyVersion != event.PolicyVersion || got.CorrelationID != event.CorrelationID || got.Latency != 25*time.Millisecond || !reflect.DeepEqual(got.ReasonCodes, tc.wantReasons) {
				t.Fatalf("DecisionEvidence = %#v", got)
			}
		})
	}
}

func TestParamsRejectsMetadataDecisionMismatch(t *testing.T) {
	metadata, err := NewAuthorizationDecisionMetadata("allow", time.Millisecond, nil)
	if err != nil {
		t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
	}
	event := decisionTestEvent("deny", metadata)
	if _, err := Params(event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("Params() error = %v, want ErrInvalidEvent", err)
	}
}

func TestReconstructDecisionFailsClosed(t *testing.T) {
	valid := StoredDecision{
		TenantID:       auditTestUUID(0x11),
		ActorSubjectID: auditTestUUID(0x22),
		Action:         "tenant.read",
		Decision:       "deny",
		PolicyVersion:  7,
		CorrelationID:  auditTestUUID(0x44),
		SafeMetadata:   []byte(`{"latency_ms":25,"reason_codes":["explicit_forbid"]}`),
	}

	cases := []struct {
		name   string
		mutate func(StoredDecision) StoredDecision
	}{
		{name: "unknown field", mutate: func(v StoredDecision) StoredDecision { v.SafeMetadata = []byte(`{"latency_ms":25,"reason_codes":["explicit_forbid"],"raw_prompt":"forbidden"}`); return v }},
		{name: "malformed json", mutate: func(v StoredDecision) StoredDecision { v.SafeMetadata = []byte(`{"latency_ms":`); return v }},
		{name: "allow with deny reasons", mutate: func(v StoredDecision) StoredDecision { v.Decision = "allow"; return v }},
		{name: "deny without reasons", mutate: func(v StoredDecision) StoredDecision { v.SafeMetadata = []byte(`{"latency_ms":25}`); return v }},
		{name: "invalid tenant", mutate: func(v StoredDecision) StoredDecision { v.TenantID = pgtype.UUID{}; return v }},
		{name: "invalid actor", mutate: func(v StoredDecision) StoredDecision { v.ActorSubjectID = pgtype.UUID{}; return v }},
		{name: "invalid correlation", mutate: func(v StoredDecision) StoredDecision { v.CorrelationID = pgtype.UUID{}; return v }},
		{name: "invalid policy version", mutate: func(v StoredDecision) StoredDecision { v.PolicyVersion = 0; return v }},
		{name: "negative latency", mutate: func(v StoredDecision) StoredDecision { v.SafeMetadata = []byte(`{"latency_ms":-1,"reason_codes":["explicit_forbid"]}`); return v }},
		{name: "overflow latency", mutate: func(v StoredDecision) StoredDecision { v.SafeMetadata = []byte(`{"latency_ms":9223372036854775808,"reason_codes":["explicit_forbid"]}`); return v }},
		{name: "unknown reason", mutate: func(v StoredDecision) StoredDecision { v.SafeMetadata = []byte(`{"latency_ms":25,"reason_codes":["unbounded-input"]}`); return v }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReconstructDecision(tc.mutate(valid)); !errors.Is(err, ErrInvalidDecisionEvidence) {
				t.Fatalf("ReconstructDecision() error = %v, want ErrInvalidDecisionEvidence", err)
			}
		})
	}
}

func decisionTestEvent(decision string, metadata SafeMetadata) Event {
	return Event{
		TenantID:       auditTestUUID(0x11),
		ID:             auditTestUUID(0x12),
		ActorSubjectID: auditTestUUID(0x22),
		EventType:      "machina.authz.decision",
		Action:         "tenant.read",
		Decision:       decision,
		PolicyVersion:  7,
		CorrelationID:  auditTestUUID(0x44),
		SafeMetadata:   metadata,
		OccurredAt:     time.Date(2026, 9, 8, 19, 30, 0, 0, time.UTC),
	}
}

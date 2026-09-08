package audit

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestSafeMetadataTenantSwitchExactShape(t *testing.T) {
	metadata, err := NewTenantSwitchMetadata(auditTestUUID(0xb2), auditTestUUID(0xc3), 7)
	if err != nil {
		t.Fatalf("NewTenantSwitchMetadata() error = %v", err)
	}
	got, err := metadata.marshal()
	if err != nil {
		t.Fatalf("SafeMetadata.marshal() error = %v", err)
	}
	want := []byte(`{"session_generation":7,"target_tenant_id":"00000000-0000-0000-0000-0000000000b2","target_workspace_id":"00000000-0000-0000-0000-0000000000c3"}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("tenant-switch metadata = %s, want %s", got, want)
	}
}

func TestSafeMetadataAuthorizationDecisionExactShapes(t *testing.T) {
	allow, err := NewAuthorizationDecisionMetadata("allow", 25*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("allow metadata error = %v", err)
	}
	allowJSON, err := allow.marshal()
	if err != nil {
		t.Fatalf("allow metadata marshal error = %v", err)
	}
	if want := []byte(`{"latency_ms":25}`); !bytes.Equal(allowJSON, want) {
		t.Fatalf("allow metadata = %s, want %s", allowJSON, want)
	}

	deny, err := NewAuthorizationDecisionMetadata("deny", 25*time.Millisecond, []string{"explicit_forbid", "stale_policy_version"})
	if err != nil {
		t.Fatalf("deny metadata error = %v", err)
	}
	denyJSON, err := deny.marshal()
	if err != nil {
		t.Fatalf("deny metadata marshal error = %v", err)
	}
	if want := []byte(`{"latency_ms":25,"reason_codes":["explicit_forbid","stale_policy_version"]}`); !bytes.Equal(denyJSON, want) {
		t.Fatalf("deny metadata = %s, want %s", denyJSON, want)
	}
}

func TestSafeMetadataRejectsInvalidInputsWithoutEcho(t *testing.T) {
	const sentinel = "sensitive-value-should-not-escape"
	validTenant := auditTestUUID(0xb2)
	validWorkspace := auditTestUUID(0xc3)

	cases := []struct {
		name string
		call func() error
	}{
		{name: "invalid tenant", call: func() error { _, err := NewTenantSwitchMetadata(pgtype.UUID{}, validWorkspace, 1); return err }},
		{name: "invalid workspace", call: func() error { _, err := NewTenantSwitchMetadata(validTenant, pgtype.UUID{}, 1); return err }},
		{name: "zero generation", call: func() error { _, err := NewTenantSwitchMetadata(validTenant, validWorkspace, 0); return err }},
		{name: "negative latency", call: func() error { _, err := NewAuthorizationDecisionMetadata("allow", -time.Nanosecond, nil); return err }},
		{name: "unknown decision", call: func() error { _, err := NewAuthorizationDecisionMetadata(sentinel, time.Millisecond, nil); return err }},
		{name: "allow with reasons", call: func() error { _, err := NewAuthorizationDecisionMetadata("allow", time.Millisecond, []string{"explicit_forbid"}); return err }},
		{name: "deny without reasons", call: func() error { _, err := NewAuthorizationDecisionMetadata("deny", time.Millisecond, nil); return err }},
		{name: "unknown reason", call: func() error { _, err := NewAuthorizationDecisionMetadata("deny", time.Millisecond, []string{sentinel}); return err }},
		{name: "duplicate reason", call: func() error { _, err := NewAuthorizationDecisionMetadata("deny", time.Millisecond, []string{"explicit_forbid", "explicit_forbid"}); return err }},
		{name: "too many reasons", call: func() error { _, err := NewAuthorizationDecisionMetadata("deny", time.Millisecond, []string{"default_deny", "evaluation_error", "explicit_forbid", "policy_unavailable", "stale_policy_version", "default_deny"}); return err }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if !errors.Is(err, ErrInvalidSafeMetadata) {
				t.Fatalf("error = %v, want ErrInvalidSafeMetadata", err)
			}
			if bytes.Contains([]byte(err.Error()), []byte(sentinel)) {
				t.Fatal("rejected metadata value leaked through error text")
			}
		})
	}
}

func auditTestUUID(last byte) pgtype.UUID {
	var value pgtype.UUID
	value.Valid = true
	value.Bytes[15] = last
	return value
}

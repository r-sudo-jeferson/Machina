package audit

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

var ErrInvalidSafeMetadata = errors.New("invalid safe audit metadata")

type safeMetadataKind uint8

const (
	safeMetadataUnknown safeMetadataKind = iota
	safeMetadataTenantSwitch
	safeMetadataAuthorizationDecision
)

// SafeMetadata is an opaque, package-owned audit payload. Callers can only
// obtain populated values through constructors that enforce a closed schema.
type SafeMetadata struct {
	kind     safeMetadataKind
	decision string
	encoded  []byte
}

type tenantSwitchMetadataPayload struct {
	SessionGeneration  int64  `json:"session_generation"`
	TargetTenantID     string `json:"target_tenant_id"`
	TargetWorkspaceID  string `json:"target_workspace_id"`
}

type authorizationDecisionMetadataPayload struct {
	LatencyMS   int64    `json:"latency_ms"`
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

func NewTenantSwitchMetadata(tenantID, workspaceID pgtype.UUID, sessionGeneration int64) (SafeMetadata, error) {
	if !tenantID.Valid || !workspaceID.Valid || sessionGeneration <= 0 {
		return SafeMetadata{}, ErrInvalidSafeMetadata
	}
	payload := tenantSwitchMetadataPayload{
		SessionGeneration: sessionGeneration,
		TargetTenantID:    uuidText(tenantID),
		TargetWorkspaceID: uuidText(workspaceID),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return SafeMetadata{}, ErrInvalidSafeMetadata
	}
	return SafeMetadata{kind: safeMetadataTenantSwitch, encoded: encoded}, nil
}

func NewAuthorizationDecisionMetadata(decision string, latency time.Duration, reasonCodes []string) (SafeMetadata, error) {
	if latency < 0 || !validAuthorizationMetadataDecision(decision, reasonCodes) {
		return SafeMetadata{}, ErrInvalidSafeMetadata
	}
	payload := authorizationDecisionMetadataPayload{
		LatencyMS:   latency.Milliseconds(),
		ReasonCodes: append([]string(nil), reasonCodes...),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return SafeMetadata{}, ErrInvalidSafeMetadata
	}
	return SafeMetadata{
		kind:     safeMetadataAuthorizationDecision,
		decision: decision,
		encoded:  encoded,
	}, nil
}

func (m SafeMetadata) marshal() ([]byte, error) {
	if m.kind == safeMetadataUnknown || len(m.encoded) == 0 || !json.Valid(m.encoded) {
		return nil, ErrInvalidSafeMetadata
	}
	return append([]byte(nil), m.encoded...), nil
}

func validAuthorizationMetadataDecision(decision string, reasonCodes []string) bool {
	switch decision {
	case "allow":
		return len(reasonCodes) == 0
	case "deny":
		if len(reasonCodes) == 0 || len(reasonCodes) > 5 {
			return false
		}
		seen := make(map[string]struct{}, len(reasonCodes))
		for _, reason := range reasonCodes {
			if !validAuthorizationDenyReason(reason) {
				return false
			}
			if _, exists := seen[reason]; exists {
				return false
			}
			seen[reason] = struct{}{}
		}
		return true
	default:
		return false
	}
}

func validAuthorizationDenyReason(reason string) bool {
	switch reason {
	case "default_deny", "evaluation_error", "explicit_forbid", "policy_unavailable", "stale_policy_version":
		return true
	default:
		return false
	}
}

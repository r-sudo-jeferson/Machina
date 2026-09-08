package authz

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidRequest        = errors.New("invalid authorization request")
	ErrInvalidResponse       = errors.New("invalid authorization response")
	ErrPolicyVersionMismatch = errors.New("authorization policy version mismatch")
)

type Request struct {
	SubjectID             string
	TenantID              string
	WorkspaceID           string
	Action                string
	ResourceType          string
	ResourceID            string
	RequiredPolicyVersion uint64
	CorrelationID         string
	Context               map[string]string
}

type Response struct {
	DecisionID         string
	Allowed            bool
	PolicyVersion      uint64
	ReasonCodes        []string
	DiagnosticRef      string
	PolicySnapshotHash string
}

type Decision struct {
	DecisionID         string
	Allowed            bool
	PolicyVersion      uint64
	ReasonCodes        []string
	DiagnosticRef      string
	PolicySnapshotHash string
}

type Transport interface {
	Decide(context.Context, Request) (Response, error)
}

type Client struct {
	transport Transport
	timeout   time.Duration
}

func NewClient(transport Transport, timeout time.Duration) *Client {
	return &Client{transport: transport, timeout: timeout}
}

func (c *Client) Authorize(ctx context.Context, request Request) (Decision, error) {
	if c == nil || c.transport == nil || c.timeout <= 0 {
		return Decision{}, fmt.Errorf("%w: authorization client is not configured", ErrInvalidRequest)
	}
	if !validRequest(request) {
		return Decision{}, ErrInvalidRequest
	}

	request.Context = cloneContext(request.Context)
	decisionCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	response, err := c.transport.Decide(decisionCtx, request)
	if err != nil {
		return Decision{}, fmt.Errorf("authorization decision transport failed: %w", err)
	}

	if response.DecisionID == "" || response.DecisionID != request.CorrelationID {
		return Decision{}, ErrInvalidResponse
	}

	if response.Allowed {
		if response.PolicyVersion != request.RequiredPolicyVersion {
			return Decision{}, ErrPolicyVersionMismatch
		}
		if response.PolicySnapshotHash == "" || len(response.ReasonCodes) != 0 || response.DiagnosticRef != "" {
			return Decision{}, ErrInvalidResponse
		}
	} else if !validDenyReasons(response.ReasonCodes) {
		return Decision{}, ErrInvalidResponse
	}

	return Decision{
		DecisionID:         response.DecisionID,
		Allowed:            response.Allowed,
		PolicyVersion:      response.PolicyVersion,
		ReasonCodes:        append([]string(nil), response.ReasonCodes...),
		DiagnosticRef:      response.DiagnosticRef,
		PolicySnapshotHash: response.PolicySnapshotHash,
	}, nil
}

func validRequest(request Request) bool {
	return isCanonicalUUID(request.SubjectID) &&
		isCanonicalUUID(request.TenantID) &&
		isCanonicalUUID(request.WorkspaceID) &&
		request.Action != "" &&
		request.ResourceType != "" &&
		request.ResourceID != "" &&
		request.RequiredPolicyVersion != 0 &&
		request.CorrelationID != ""
}

func validDenyReasons(reasons []string) bool {
	if len(reasons) == 0 {
		return false
	}
	for _, reason := range reasons {
		switch reason {
		case "default_deny", "evaluation_error", "explicit_forbid", "policy_unavailable", "stale_policy_version":
		default:
			return false
		}
	}
	return true
}

func cloneContext(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value[index] != '-' {
				return false
			}
			continue
		}
		if !isHex(value[index]) {
			return false
		}
	}
	return true
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

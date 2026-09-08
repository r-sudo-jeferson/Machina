package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeTransport struct {
	response Response
	err      error
	calls    int
	request  Request
	block    bool
}

func (t *fakeTransport) Decide(ctx context.Context, request Request) (Response, error) {
	t.calls++
	t.request = request
	if t.block {
		<-ctx.Done()
		return Response{}, ctx.Err()
	}
	return t.response, t.err
}

func validRequest() Request {
	return Request{
		SubjectID:            "01000000-0000-0000-0000-000000000000",
		TenantID:             "02000000-0000-0000-0000-000000000000",
		WorkspaceID:          "03000000-0000-0000-0000-000000000000",
		Action:               "context.read",
		ResourceType:         "Workspace",
		ResourceID:           "03000000-0000-0000-0000-000000000000",
		RequiredPolicyVersion: 7,
		CorrelationID:        "decision-correlation-1",
		Context:              map[string]string{"starter_role": "owner"},
	}
}

func TestClientAllowsOnlyCoherentExactPolicyDecision(t *testing.T) {
	t.Parallel()

	transport := &fakeTransport{response: Response{
		DecisionID:         "decision-correlation-1",
		Allowed:            true,
		PolicyVersion:      7,
		PolicySnapshotHash: "sha256:policy-snapshot",
	}}
	client := NewClient(transport, time.Second)

	decision, err := client.Authorize(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !decision.Allowed || decision.PolicyVersion != 7 || decision.DecisionID != "decision-correlation-1" {
		t.Fatalf("Authorize() = %#v", decision)
	}
	if transport.calls != 1 {
		t.Fatalf("transport calls = %d, want 1", transport.calls)
	}
}

func TestClientPreservesValidDeny(t *testing.T) {
	t.Parallel()

	transport := &fakeTransport{response: Response{
		DecisionID:    "decision-correlation-1",
		Allowed:       false,
		PolicyVersion: 7,
		ReasonCodes:   []string{"explicit_forbid"},
	}}
	client := NewClient(transport, time.Second)

	decision, err := client.Authorize(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Allowed || !reflect.DeepEqual(decision.ReasonCodes, []string{"explicit_forbid"}) {
		t.Fatalf("Authorize() = %#v", decision)
	}
}

func TestClientRejectsInvalidRequestBeforeTransport(t *testing.T) {
	t.Parallel()

	request := validRequest()
	request.TenantID = "not-a-uuid"
	transport := &fakeTransport{}
	client := NewClient(transport, time.Second)

	decision, err := client.Authorize(context.Background(), request)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Authorize() error = %v, want ErrInvalidRequest", err)
	}
	if decision.Allowed || transport.calls != 0 {
		t.Fatalf("invalid request reached transport or allowed: decision=%#v calls=%d", decision, transport.calls)
	}
}

func TestClientFailsClosedOnTransportError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("transport unavailable")
	transport := &fakeTransport{err: wantErr}
	client := NewClient(transport, time.Second)

	decision, err := client.Authorize(context.Background(), validRequest())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Authorize() error = %v, want wrapped transport error", err)
	}
	if decision.Allowed {
		t.Fatal("transport failure produced allow")
	}
}

func TestClientFailsClosedOnCorrelationMismatch(t *testing.T) {
	t.Parallel()

	transport := &fakeTransport{response: Response{
		DecisionID:         "different-correlation",
		Allowed:            true,
		PolicyVersion:      7,
		PolicySnapshotHash: "sha256:policy-snapshot",
	}}
	client := NewClient(transport, time.Second)

	decision, err := client.Authorize(context.Background(), validRequest())
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Authorize() error = %v, want ErrInvalidResponse", err)
	}
	if decision.Allowed {
		t.Fatal("correlation mismatch produced allow")
	}
}

func TestClientFailsClosedOnAllowedPolicyVersionMismatch(t *testing.T) {
	t.Parallel()

	transport := &fakeTransport{response: Response{
		DecisionID:         "decision-correlation-1",
		Allowed:            true,
		PolicyVersion:      6,
		PolicySnapshotHash: "sha256:older-policy",
	}}
	client := NewClient(transport, time.Second)

	decision, err := client.Authorize(context.Background(), validRequest())
	if !errors.Is(err, ErrPolicyVersionMismatch) {
		t.Fatalf("Authorize() error = %v, want ErrPolicyVersionMismatch", err)
	}
	if decision.Allowed {
		t.Fatal("stale policy response produced allow")
	}
}

func TestClientFailsClosedOnMalformedAllow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		response Response
	}{
		{
			name: "missing snapshot hash",
			response: Response{
				DecisionID:    "decision-correlation-1",
				Allowed:       true,
				PolicyVersion: 7,
			},
		},
		{
			name: "allow with deny reasons",
			response: Response{
				DecisionID:         "decision-correlation-1",
				Allowed:            true,
				PolicyVersion:      7,
				PolicySnapshotHash: "sha256:policy-snapshot",
				ReasonCodes:        []string{"evaluation_error"},
			},
		},
		{
			name: "allow with diagnostic",
			response: Response{
				DecisionID:         "decision-correlation-1",
				Allowed:            true,
				PolicyVersion:      7,
				PolicySnapshotHash: "sha256:policy-snapshot",
				DiagnosticRef:      "unexpected-diagnostic",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := NewClient(&fakeTransport{response: tc.response}, time.Second)
			decision, err := client.Authorize(context.Background(), validRequest())
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Authorize() error = %v, want ErrInvalidResponse", err)
			}
			if decision.Allowed {
				t.Fatal("malformed response produced allow")
			}
		})
	}
}

func TestClientUsesDefensiveContextCopy(t *testing.T) {
	t.Parallel()

	request := validRequest()
	transport := &fakeTransport{response: Response{
		DecisionID:         request.CorrelationID,
		Allowed:            true,
		PolicyVersion:      request.RequiredPolicyVersion,
		PolicySnapshotHash: "sha256:policy-snapshot",
	}}
	client := NewClient(transport, time.Second)

	if _, err := client.Authorize(context.Background(), request); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	transport.request.Context["starter_role"] = "mutated"
	if request.Context["starter_role"] != "owner" {
		t.Fatal("transport mutation changed caller context map")
	}
}

func TestClientFailsClosedWhenDecisionTimesOut(t *testing.T) {
	t.Parallel()

	client := NewClient(&fakeTransport{block: true}, time.Millisecond)
	decision, err := client.Authorize(context.Background(), validRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Authorize() error = %v, want context.DeadlineExceeded", err)
	}
	if decision.Allowed {
		t.Fatal("timeout produced allow")
	}
}

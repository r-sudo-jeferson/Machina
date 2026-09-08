package authz

import (
	"context"
	"errors"
	"testing"

	authzv1 "github.com/r-sudo-jeferson/Machina/job/gen/authz/v1"
	"google.golang.org/grpc"
)

type fakeAuthorizationServiceClient struct {
	response *authzv1.DecisionResponse
	err      error
	request  *authzv1.DecisionRequest
	mutate   bool
}

func (f *fakeAuthorizationServiceClient) Decide(
	_ context.Context,
	request *authzv1.DecisionRequest,
	_ ...grpc.CallOption,
) (*authzv1.DecisionResponse, error) {
	f.request = request
	if f.mutate && request.Context != nil {
		request.Context["scope"] = "mutated-by-rpc"
	}
	return f.response, f.err
}

func TestGRPCTransportMapsDecisionRequestAndResponse(t *testing.T) {
	t.Parallel()

	client := &fakeAuthorizationServiceClient{response: &authzv1.DecisionResponse{
		DecisionId:         "correlation-1",
		Allowed:            true,
		PolicyVersion:      7,
		ReasonCodes:        []string{"reason-a"},
		DiagnosticRef:      "diag-1",
		PolicySnapshotHash: "snapshot-1",
	}}
	transport := NewGRPCTransport(client)
	request := Request{
		SubjectID:             "10000000-0000-0000-0000-000000000001",
		TenantID:              "20000000-0000-0000-0000-000000000002",
		WorkspaceID:           "30000000-0000-0000-0000-000000000003",
		Action:                "workspace.read",
		ResourceType:          "Workspace",
		ResourceID:            "resource-1",
		RequiredPolicyVersion: 7,
		CorrelationID:         "correlation-1",
		Context:               map[string]string{"scope": "trusted"},
	}

	got, err := transport.Decide(context.Background(), request)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if client.request == nil {
		t.Fatal("Decide() did not call generated client")
	}
	if client.request.SubjectId != request.SubjectID ||
		client.request.TenantId != request.TenantID ||
		client.request.WorkspaceId != request.WorkspaceID ||
		client.request.Action != request.Action ||
		client.request.ResourceType != request.ResourceType ||
		client.request.ResourceId != request.ResourceID ||
		client.request.RequiredPolicyVersion != request.RequiredPolicyVersion ||
		client.request.CorrelationId != request.CorrelationID ||
		client.request.Context["scope"] != "trusted" {
		t.Fatalf("generated request = %#v", client.request)
	}
	if got.DecisionID != "correlation-1" || !got.Allowed || got.PolicyVersion != 7 ||
		len(got.ReasonCodes) != 1 || got.ReasonCodes[0] != "reason-a" ||
		got.DiagnosticRef != "diag-1" || got.PolicySnapshotHash != "snapshot-1" {
		t.Fatalf("Decide() = %#v", got)
	}
}

func TestGRPCTransportCopiesContextBeforeRPC(t *testing.T) {
	t.Parallel()

	client := &fakeAuthorizationServiceClient{
		response: &authzv1.DecisionResponse{DecisionId: "correlation-1"},
		mutate:   true,
	}
	transport := NewGRPCTransport(client)
	request := Request{Context: map[string]string{"scope": "trusted"}}

	_, err := transport.Decide(context.Background(), request)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if request.Context["scope"] != "trusted" {
		t.Fatalf("caller context mutated: %#v", request.Context)
	}
}

func TestGRPCTransportPropagatesRPCFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("rpc unavailable")
	transport := NewGRPCTransport(&fakeAuthorizationServiceClient{err: wantErr})

	_, err := transport.Decide(context.Background(), Request{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Decide() error = %v, want %v", err, wantErr)
	}
}

func TestGRPCTransportRejectsNilResponse(t *testing.T) {
	t.Parallel()

	transport := NewGRPCTransport(&fakeAuthorizationServiceClient{})

	_, err := transport.Decide(context.Background(), Request{})
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Decide() error = %v, want ErrInvalidResponse", err)
	}
}

func TestGRPCTransportRejectsNilGeneratedClient(t *testing.T) {
	t.Parallel()

	transport := NewGRPCTransport(nil)

	_, err := transport.Decide(context.Background(), Request{})
	if err == nil {
		t.Fatal("Decide() error = nil, want fail-closed configuration error")
	}
}

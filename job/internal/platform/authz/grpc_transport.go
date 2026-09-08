package authz

import (
	"context"
	"errors"

	authzv1 "github.com/r-sudo-jeferson/Machina/job/gen/authz/v1"
)

var ErrGRPCTransportNotConfigured = errors.New("authorization gRPC transport is not configured")

type GRPCTransport struct {
	client authzv1.AuthorizationServiceClient
}

func NewGRPCTransport(client authzv1.AuthorizationServiceClient) *GRPCTransport {
	return &GRPCTransport{client: client}
}

func (t *GRPCTransport) Decide(ctx context.Context, request Request) (Response, error) {
	if t == nil || t.client == nil {
		return Response{}, ErrGRPCTransportNotConfigured
	}

	message := &authzv1.DecisionRequest{
		SubjectId:             request.SubjectID,
		TenantId:              request.TenantID,
		WorkspaceId:           request.WorkspaceID,
		Action:                request.Action,
		ResourceType:          request.ResourceType,
		ResourceId:            request.ResourceID,
		RequiredPolicyVersion: request.RequiredPolicyVersion,
		CorrelationId:         request.CorrelationID,
		Context:               cloneContext(request.Context),
	}

	response, err := t.client.Decide(ctx, message)
	if err != nil {
		return Response{}, err
	}
	if response == nil {
		return Response{}, ErrInvalidResponse
	}

	return Response{
		DecisionID:         response.DecisionId,
		Allowed:            response.Allowed,
		PolicyVersion:      response.PolicyVersion,
		ReasonCodes:        append([]string(nil), response.ReasonCodes...),
		DiagnosticRef:      response.DiagnosticRef,
		PolicySnapshotHash: response.PolicySnapshotHash,
	}, nil
}

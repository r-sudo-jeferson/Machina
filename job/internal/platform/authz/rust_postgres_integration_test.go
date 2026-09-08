package authz

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	authzv1 "github.com/r-sudo-jeferson/Machina/job/gen/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	goIntegrationDatabaseEnv = "MACHINA_AUTHZ_GO_INTEGRATION_DATABASE_URL"
	goIntegrationBinaryEnv   = "MACHINA_AUTHZ_GO_INTEGRATION_BINARY"
	integrationTenantID      = "00000000-0000-0000-0000-0000000000a1"
	integrationInvalidTenant = "00000000-0000-0000-0000-0000000000b2"
	integrationSnapshotHash  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestGoClientAuthorizesAgainstRustPostgres(t *testing.T) {
	databaseURL := os.Getenv(goIntegrationDatabaseEnv)
	binary := os.Getenv(goIntegrationBinaryEnv)
	if databaseURL == "" || binary == "" {
		t.Skip("requires Rust authorization binary and PostgreSQL policy-source harness")
	}

	grpcAddr := reserveIntegrationAddress(t)
	probeAddr := reserveIntegrationAddress(t)
	for probeAddr == grpcAddr {
		probeAddr = reserveIntegrationAddress(t)
	}

	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"MACHINA_AUTHZ_GRPC_ADDR="+grpcAddr,
		"MACHINA_AUTHZ_PROBE_ADDR="+probeAddr,
		"MACHINA_AUTHZ_DATABASE_URL="+databaseURL,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Rust authorization service: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	awaitIntegrationTCP(t, grpcAddr)

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := NewClient(NewGRPCTransport(authzv1.NewAuthorizationServiceClient(conn)), 2*time.Second)

	allowed, err := client.Authorize(context.Background(), integrationRequest(integrationTenantID, 1, "corr-go-rust-allow"))
	if err != nil {
		t.Fatalf("allow decision error = %v", err)
	}
	if !allowed.Allowed || allowed.PolicyVersion != 1 || allowed.PolicySnapshotHash != integrationSnapshotHash ||
		allowed.DecisionID != "corr-go-rust-allow" || len(allowed.ReasonCodes) != 0 || allowed.DiagnosticRef != "" {
		t.Fatalf("allow decision = %#v", allowed)
	}

	invalidPolicy, err := client.Authorize(context.Background(), integrationRequest(integrationInvalidTenant, 1, "corr-go-rust-invalid-policy"))
	if err != nil {
		t.Fatalf("invalid-policy decision error = %v", err)
	}
	if invalidPolicy.Allowed || len(invalidPolicy.ReasonCodes) != 1 || invalidPolicy.ReasonCodes[0] != "policy_unavailable" {
		t.Fatalf("invalid-policy decision = %#v", invalidPolicy)
	}

	stale, err := client.Authorize(context.Background(), integrationRequest(integrationTenantID, 2, "corr-go-rust-stale"))
	if err != nil {
		t.Fatalf("stale-policy decision error = %v", err)
	}
	if stale.Allowed || stale.PolicyVersion != 1 || stale.PolicySnapshotHash != integrationSnapshotHash ||
		len(stale.ReasonCodes) != 1 || stale.ReasonCodes[0] != "stale_policy_version" {
		t.Fatalf("stale-policy decision = %#v", stale)
	}

	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("stop Rust authorization service: %v", err)
	}
	stopped = true
}

func integrationRequest(tenantID string, requiredVersion uint64, correlationID string) Request {
	return Request{
		SubjectID:             "10000000-0000-0000-0000-0000000000a1",
		TenantID:              tenantID,
		WorkspaceID:           "20000000-0000-0000-0000-0000000000a1",
		Action:                "context.read",
		ResourceType:          "PlatformContext",
		ResourceID:            "active",
		RequiredPolicyVersion: requiredVersion,
		CorrelationID:         correlationID,
		Context: map[string]string{
			"starter_role":      "owner",
			"membership_status": "active",
		},
	}
}

func reserveIntegrationAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release reserved loopback address: %v", err)
	}
	return addr
}

func awaitIntegrationTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Rust authorization gRPC listener %s did not become reachable", addr)
}

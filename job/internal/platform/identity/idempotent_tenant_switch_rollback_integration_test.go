package identity_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	authzv1 "github.com/r-sudo-jeferson/Machina/job/gen/authz/v1"
	platformauthz "github.com/r-sudo-jeferson/Machina/job/internal/platform/authz"
	platformdb "github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestTenantSwitchRollbackWithoutCheckpointerAgainstPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("MACHINA_TENANT_SWITCH_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("MACHINA_TENANT_SWITCH_DATABASE_URL is not configured")
	}
	adminDatabaseURL := os.Getenv("MACHINA_TENANT_SWITCH_ADMIN_DATABASE_URL")
	if adminDatabaseURL == "" {
		t.Fatal("MACHINA_TENANT_SWITCH_ADMIN_DATABASE_URL is not configured")
	}
	authzGRPCAddr := os.Getenv("MACHINA_TENANT_SWITCH_AUTHZ_GRPC_ADDR")
	if authzGRPCAddr == "" {
		t.Fatal("MACHINA_TENANT_SWITCH_AUTHZ_GRPC_ADDR is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	runtimePool := tenantSwitchIntegrationPool(t, ctx, databaseURL, 4)
	defer runtimePool.Close()
	adminPool := tenantSwitchIntegrationPool(t, ctx, adminDatabaseURL, 2)
	defer adminPool.Close()
	authzConn, err := grpc.NewClient(authzGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create tenant-switch authorization gRPC client: %v", err)
	}
	defer func() { _ = authzConn.Close() }()
	authorizer := platformauthz.NewClient(
		platformauthz.NewGRPCTransport(authzv1.NewAuthorizationServiceClient(authzConn)),
		2*time.Second,
	)

	const (
		subjectID      = "10000000-0000-0000-0000-0000000000b2"
		sessionID      = "3e000000-0000-0000-0000-000000000003"
		sessionToken   = "go-integration-chain-fault-session"
		csrfToken      = "go-integration-chain-fault-csrf"
		idempotencyKey = "tenant-switch-chain-fault-0001"
	)
	targetTenantID := integrationUUID(0xb2)
	correlationID := integrationUUID(0x41)
	sessionHash := identity.HashToken(sessionToken)
	csrfHash := identity.HashToken(csrfToken)
	if _, err := runtimePool.Exec(ctx, `
		SELECT iam.create_session($1::uuid, $2::uuid, $3::bytea, $4::bytea, clock_timestamp() + interval '2 hours')
	`, sessionID, subjectID, sessionHash[:], csrfHash[:]); err != nil {
		t.Fatalf("create audit-chain rollback session: %v", err)
	}

	// The API mutation intentionally has no Checkpointer or checkpoint worker in
	// its dependency graph. Audit insertion and database-owned chain append must
	// remain mandatory even when periodic checkpoint scheduling is absent.
	coordinator, err := identity.NewTenantSwitchCoordinator(platformdb.NewTransactor(runtimePool), authorizer)
	if err != nil {
		t.Fatalf("NewTenantSwitchCoordinator() error = %v", err)
	}

	installTenantSwitchChainFailureTrigger(t, ctx, adminPool)
	triggerInstalled := true
	defer func() {
		if !triggerInstalled {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if err := removeTenantSwitchChainFailureTrigger(cleanupCtx, adminPool); err != nil {
			t.Errorf("remove audit-chain fault trigger: %v", err)
		}
	}()

	request := identity.TenantSwitchRequest{
		PresentedSessionToken: sessionToken,
		TargetTenantID:        targetTenantID,
		IdempotencyKey:        idempotencyKey,
		CorrelationID:         correlationID,
	}
	failed, err := coordinator.Switch(ctx, request)
	if err == nil {
		t.Fatal("audit-chain fault-injected tenant switch unexpectedly succeeded")
	}
	var postgresErr *pgconn.PgError
	if !errors.As(err, &postgresErr) || postgresErr.Code != "55000" {
		t.Fatalf("audit-chain fault error = %v, want PostgreSQL 55000", err)
	}
	if failed.CorrelationID.Valid || failed.SessionToken != "" || failed.CSRFToken != "" || len(failed.ResponseBody) != 0 {
		t.Fatalf("audit-chain fault leaked result = %#v", failed)
	}
	assertTenantSwitchSessionActive(t, ctx, runtimePool, sessionHash[:], true)
	assertTenantSwitchRollbackPersistence(t, ctx, adminPool, targetTenantID, idempotencyKey, correlationID, 0)

	if err := removeTenantSwitchChainFailureTrigger(ctx, adminPool); err != nil {
		t.Fatalf("restore audit-chain append persistence: %v", err)
	}
	triggerInstalled = false

	committed, err := coordinator.Switch(ctx, request)
	if err != nil {
		t.Fatalf("retry after restoring audit chain: %v", err)
	}
	if committed.Replay || committed.SessionToken == "" || committed.CSRFToken == "" || committed.CorrelationID != correlationID {
		t.Fatalf("retry did not commit exactly once = %#v", committed)
	}
	assertTenantSwitchSessionActive(t, ctx, runtimePool, sessionHash[:], false)
	assertTenantSwitchRollbackPersistence(t, ctx, adminPool, targetTenantID, idempotencyKey, correlationID, 1)

	committedSessionHash := identity.HashToken(committed.SessionToken)
	replay, err := coordinator.Switch(ctx, identity.TenantSwitchRequest{
		PresentedSessionToken: committed.SessionToken,
		TargetTenantID:        targetTenantID,
		IdempotencyKey:        idempotencyKey,
		CorrelationID:         integrationUUID(0x42),
	})
	if err != nil {
		t.Fatalf("replay after successful audit-chain retry: %v", err)
	}
	if !replay.Replay || replay.SessionToken != "" || replay.CSRFToken != "" || replay.CorrelationID != correlationID || replay.Generation != committed.Generation {
		t.Fatalf("audit-chain retry replay = %#v", replay)
	}
	assertTenantSwitchSessionActive(t, ctx, runtimePool, committedSessionHash[:], true)
	assertTenantSwitchRollbackPersistence(t, ctx, adminPool, targetTenantID, idempotencyKey, correlationID, 1)
}

func installTenantSwitchChainFailureTrigger(t *testing.T, ctx context.Context, adminPool *pgxpool.Pool) {
	t.Helper()
	if _, err := adminPool.Exec(ctx, `
		DROP TRIGGER IF EXISTS machina_test_reject_event_chain_insert ON audit.event_chain;
		DROP FUNCTION IF EXISTS audit.machina_test_reject_event_chain_insert();
		CREATE FUNCTION audit.machina_test_reject_event_chain_insert()
		RETURNS trigger
		LANGUAGE plpgsql
		SET search_path = pg_catalog
		AS $function$
		BEGIN
			RAISE EXCEPTION 'injected audit event_chain failure'
				USING ERRCODE = '55000';
		END;
		$function$;
		REVOKE ALL ON FUNCTION audit.machina_test_reject_event_chain_insert() FROM PUBLIC;
		CREATE TRIGGER machina_test_reject_event_chain_insert
			BEFORE INSERT ON audit.event_chain
			FOR EACH ROW
			EXECUTE FUNCTION audit.machina_test_reject_event_chain_insert();
	`); err != nil {
		t.Fatalf("install audit-chain fault trigger: %v", err)
	}
}

func removeTenantSwitchChainFailureTrigger(ctx context.Context, adminPool *pgxpool.Pool) error {
	_, err := adminPool.Exec(ctx, `
		DROP TRIGGER IF EXISTS machina_test_reject_event_chain_insert ON audit.event_chain;
		DROP FUNCTION IF EXISTS audit.machina_test_reject_event_chain_insert();
	`)
	return err
}

func assertTenantSwitchRollbackPersistence(
	t *testing.T,
	ctx context.Context,
	adminPool *pgxpool.Pool,
	tenantID pgtype.UUID,
	idempotencyKey string,
	correlationID pgtype.UUID,
	want int,
) {
	t.Helper()
	var receiptCount int
	if err := adminPool.QueryRow(ctx, `
		SELECT count(*)
		FROM ops.idempotency_keys
		WHERE tenant_id = $1
		  AND idempotency_key = $2
		  AND correlation_id = $3
		  AND response_status = 200
		  AND response_body IS NOT NULL
	`, tenantID, idempotencyKey, correlationID).Scan(&receiptCount); err != nil {
		t.Fatalf("count completed tenant-switch receipt: %v", err)
	}
	var auditCount int
	if err := adminPool.QueryRow(ctx, `
		SELECT count(*)
		FROM audit.events
		WHERE tenant_id = $1
		  AND correlation_id = $2
		  AND event_type = 'machina.tenant.switch.completed'
	`, tenantID, correlationID).Scan(&auditCount); err != nil {
		t.Fatalf("count tenant-switch audit events: %v", err)
	}
	var chainCount int
	if err := adminPool.QueryRow(ctx, `
		SELECT count(*)
		FROM audit.event_chain AS chain
		JOIN audit.events AS event
		  ON event.tenant_id = chain.tenant_id
		 AND event.id = chain.event_id
		WHERE event.tenant_id = $1
		  AND event.correlation_id = $2
		  AND event.event_type = 'machina.tenant.switch.completed'
	`, tenantID, correlationID).Scan(&chainCount); err != nil {
		t.Fatalf("count tenant-switch audit-chain rows: %v", err)
	}
	var outboxCount int
	if err := adminPool.QueryRow(ctx, `
		SELECT count(*)
		FROM ops.outbox
		WHERE tenant_id = $1
		  AND correlation_id = $2
		  AND event_type = 'machina.tenant.switch.completed'
	`, tenantID, correlationID).Scan(&outboxCount); err != nil {
		t.Fatalf("count tenant-switch outbox rows: %v", err)
	}
	if receiptCount != want || auditCount != want || chainCount != want || outboxCount != want {
		t.Fatalf(
			"tenant-switch rollback persistence = receipt:%d audit:%d chain:%d outbox:%d, want %d/%d/%d/%d",
			receiptCount,
			auditCount,
			chainCount,
			outboxCount,
			want,
			want,
			want,
			want,
		)
	}
}

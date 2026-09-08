package identity_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	platformdb "github.com/r-sudo-jeferson/Machina/job/internal/platform/db"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/identity"
)

func TestTenantSwitchCoordinatorAgainstPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("MACHINA_TENANT_SWITCH_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("MACHINA_TENANT_SWITCH_DATABASE_URL is not configured")
	}
	adminDatabaseURL := os.Getenv("MACHINA_TENANT_SWITCH_ADMIN_DATABASE_URL")
	if adminDatabaseURL == "" {
		t.Fatal("MACHINA_TENANT_SWITCH_ADMIN_DATABASE_URL is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	pool := tenantSwitchIntegrationPool(t, ctx, databaseURL, 8)
	defer pool.Close()
	adminPool := tenantSwitchIntegrationPool(t, ctx, adminDatabaseURL, 2)
	defer adminPool.Close()

	const (
		subjectID = "10000000-0000-0000-0000-0000000000a1"
		sessionID = "3d000000-0000-0000-0000-000000000001"
		key       = "tenant-switch-go-integration-0001"
	)
	oldSessionToken := "go-integration-old-session"
	oldCSRFToken := "go-integration-old-csrf"
	targetTenantID := integrationUUID(0xb2)
	oldSessionHash := identity.HashToken(oldSessionToken)
	oldCSRFHash := identity.HashToken(oldCSRFToken)
	if _, err := pool.Exec(ctx, `
		SELECT iam.create_session($1::uuid, $2::uuid, $3::bytea, $4::bytea, clock_timestamp() + interval '2 hours')
	`, sessionID, subjectID, oldSessionHash[:], oldCSRFHash[:]); err != nil {
		t.Fatalf("create integration session: %v", err)
	}

	coordinator, err := identity.NewTenantSwitchCoordinator(platformdb.NewTransactor(pool))
	if err != nil {
		t.Fatalf("NewTenantSwitchCoordinator() error = %v", err)
	}
	requests := []identity.TenantSwitchRequest{
		{PresentedSessionToken: oldSessionToken, TargetTenantID: targetTenantID, IdempotencyKey: key, CorrelationID: integrationUUID(0x04)},
		{PresentedSessionToken: oldSessionToken, TargetTenantID: targetTenantID, IdempotencyKey: key, CorrelationID: integrationUUID(0x05)},
	}
	type switchCall struct {
		result identity.TenantSwitchResult
		err    error
	}
	results := make(chan switchCall, len(requests))
	var waitGroup sync.WaitGroup
	for _, request := range requests {
		request := request
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			result, err := coordinator.Switch(ctx, request)
			results <- switchCall{result: result, err: err}
		}()
	}
	waitGroup.Wait()
	close(results)

	var winner identity.TenantSwitchResult
	var failures []error
	for call := range results {
		if call.err == nil {
			if winner.CorrelationID.Valid {
				t.Fatal("two concurrent old-cookie requests both committed")
			}
			winner = call.result
			continue
		}
		failures = append(failures, call.err)
	}
	if !winner.CorrelationID.Valid || len(failures) != 1 {
		t.Fatalf("concurrent coordinator results = winner=%#v failures=%v", winner, failures)
	}
	var unauthorized *pgconn.PgError
	if !errors.As(failures[0], &unauthorized) || unauthorized.Code != "42501" {
		t.Fatalf("old-cookie waiter error = %v, want PostgreSQL authorization failure", failures[0])
	}
	if winner.Replay || winner.SessionToken == "" || winner.CSRFToken == "" || winner.Generation != 2 {
		t.Fatalf("concurrent winner result = %#v", winner)
	}

	var activeOld int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM iam.get_active_session($1::bytea)", oldSessionHash[:]).Scan(&activeOld); err != nil {
		t.Fatalf("check old session: %v", err)
	}
	if activeOld != 0 {
		t.Fatalf("old session remained active after coordinator winner: %d", activeOld)
	}

	replay, err := coordinator.Switch(ctx, identity.TenantSwitchRequest{
		PresentedSessionToken: winner.SessionToken,
		TargetTenantID:        targetTenantID,
		IdempotencyKey:        key,
		CorrelationID:         integrationUUID(0x06),
	})
	if err != nil {
		t.Fatalf("current-cookie replay error = %v", err)
	}
	if !replay.Replay || replay.SessionToken != "" || replay.CSRFToken != "" || replay.CorrelationID != winner.CorrelationID || replay.Generation != winner.Generation {
		t.Fatalf("current-cookie replay result = %#v", replay)
	}
	if bytes.Contains(replay.ResponseBody, []byte(winner.SessionToken)) || bytes.Contains(replay.ResponseBody, []byte(winner.CSRFToken)) {
		t.Fatal("replayed outcome contains browser secrets")
	}

	nextSessionToken := "go-integration-next-session"
	nextCSRFToken := "go-integration-next-csrf"
	nextSessionHash := identity.HashToken(nextSessionToken)
	nextCSRFHash := identity.HashToken(nextCSRFToken)
	winnerSessionHash := identity.HashToken(winner.SessionToken)
	var rotatedSessionID pgtype.UUID
	if err := pool.QueryRow(ctx, `
		SELECT id FROM iam.rotate_session($1::bytea, $2::bytea, $3::bytea)
	`, winnerSessionHash[:], nextSessionHash[:], nextCSRFHash[:]).Scan(&rotatedSessionID); err != nil {
		t.Fatalf("later session rotation: %v", err)
	}
	if !rotatedSessionID.Valid {
		t.Fatal("later session rotation returned an invalid session id")
	}
	if _, err := coordinator.Switch(ctx, identity.TenantSwitchRequest{
		PresentedSessionToken: nextSessionToken,
		TargetTenantID:        targetTenantID,
		IdempotencyKey:        key,
		CorrelationID:         integrationUUID(0x07),
	}); !errors.Is(err, identity.ErrTenantSwitchStale) {
		t.Fatalf("later-generation switch error = %v, want ErrTenantSwitchStale", err)
	}

	testTenantSwitchTransactionalFaultRecovery(t, ctx, pool, adminPool, coordinator, tenantSwitchFaultCase{
		name:           "audit insert failure",
		table:          "audit.events",
		sessionID:      "3e000000-0000-0000-0000-000000000001",
		sessionToken:   "go-integration-audit-fault-session",
		csrfToken:      "go-integration-audit-fault-csrf",
		idempotencyKey: "tenant-switch-audit-fault-0001",
		correlationID:  integrationUUID(0x21),
	})
	testTenantSwitchTransactionalFaultRecovery(t, ctx, pool, adminPool, coordinator, tenantSwitchFaultCase{
		name:           "outbox insert failure",
		table:          "ops.outbox",
		sessionID:      "3e000000-0000-0000-0000-000000000002",
		sessionToken:   "go-integration-outbox-fault-session",
		csrfToken:      "go-integration-outbox-fault-csrf",
		idempotencyKey: "tenant-switch-outbox-fault-0001",
		correlationID:  integrationUUID(0x31),
	})
}

type tenantSwitchFaultCase struct {
	name           string
	table          string
	sessionID      string
	sessionToken   string
	csrfToken      string
	idempotencyKey string
	correlationID  pgtype.UUID
}

func testTenantSwitchTransactionalFaultRecovery(
	t *testing.T,
	ctx context.Context,
	runtimePool *pgxpool.Pool,
	adminPool *pgxpool.Pool,
	coordinator *identity.TenantSwitchCoordinator,
	tc tenantSwitchFaultCase,
) {
	t.Helper()
	t.Run(tc.name, func(t *testing.T) {
		const subjectID = "10000000-0000-0000-0000-0000000000b2"
		targetTenantID := integrationUUID(0xb2)
		sessionHash := identity.HashToken(tc.sessionToken)
		csrfHash := identity.HashToken(tc.csrfToken)
		if _, err := runtimePool.Exec(ctx, `
			SELECT iam.create_session($1::uuid, $2::uuid, $3::bytea, $4::bytea, clock_timestamp() + interval '2 hours')
		`, tc.sessionID, subjectID, sessionHash[:], csrfHash[:]); err != nil {
			t.Fatalf("create fault-injection session: %v", err)
		}

		setTenantSwitchRuntimeInsertPrivilege(t, ctx, adminPool, tc.table, false)
		restored := false
		defer func() {
			if restored {
				return
			}
			if _, err := adminPool.Exec(context.Background(), tenantSwitchPrivilegeStatement(tc.table, true)); err != nil {
				t.Errorf("restore runtime INSERT on %s: %v", tc.table, err)
			}
		}()

		request := identity.TenantSwitchRequest{
			PresentedSessionToken: tc.sessionToken,
			TargetTenantID:        targetTenantID,
			IdempotencyKey:        tc.idempotencyKey,
			CorrelationID:         tc.correlationID,
		}
		failed, err := coordinator.Switch(ctx, request)
		if err == nil {
			t.Fatal("fault-injected tenant switch unexpectedly succeeded")
		}
		if failed.CorrelationID.Valid || failed.SessionToken != "" || failed.CSRFToken != "" || len(failed.ResponseBody) != 0 {
			t.Fatalf("fault-injected transaction leaked result = %#v", failed)
		}
		assertTenantSwitchSessionActive(t, ctx, runtimePool, sessionHash[:], true)
		assertTenantSwitchSideEffectCounts(t, ctx, adminPool, targetTenantID, tc.idempotencyKey, tc.correlationID, 0, 0, 0)

		setTenantSwitchRuntimeInsertPrivilege(t, ctx, adminPool, tc.table, true)
		restored = true

		committed, err := coordinator.Switch(ctx, request)
		if err != nil {
			t.Fatalf("retry after restoring %s INSERT: %v", tc.table, err)
		}
		if committed.Replay || committed.SessionToken == "" || committed.CSRFToken == "" || committed.CorrelationID != tc.correlationID {
			t.Fatalf("retry did not commit exactly once = %#v", committed)
		}
		assertTenantSwitchSessionActive(t, ctx, runtimePool, sessionHash[:], false)
		assertTenantSwitchSideEffectCounts(t, ctx, adminPool, targetTenantID, tc.idempotencyKey, tc.correlationID, 1, 1, 1)

		committedSessionHash := identity.HashToken(committed.SessionToken)
		replay, err := coordinator.Switch(ctx, identity.TenantSwitchRequest{
			PresentedSessionToken: committed.SessionToken,
			TargetTenantID:        targetTenantID,
			IdempotencyKey:        tc.idempotencyKey,
			CorrelationID:         integrationUUID(tc.correlationID.Bytes[15] + 1),
		})
		if err != nil {
			t.Fatalf("replay after successful retry: %v", err)
		}
		if !replay.Replay || replay.SessionToken != "" || replay.CSRFToken != "" || replay.CorrelationID != committed.CorrelationID || replay.Generation != committed.Generation {
			t.Fatalf("successful retry replay = %#v", replay)
		}
		assertTenantSwitchSessionActive(t, ctx, runtimePool, committedSessionHash[:], true)
		assertTenantSwitchSideEffectCounts(t, ctx, adminPool, targetTenantID, tc.idempotencyKey, tc.correlationID, 1, 1, 1)
	})
}

func tenantSwitchIntegrationPool(t *testing.T, ctx context.Context, databaseURL string, maxConns int32) *pgxpool.Pool {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig() error = %v", err)
	}
	poolConfig.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig() error = %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("pool.Ping() error = %v", err)
	}
	return pool
}

func setTenantSwitchRuntimeInsertPrivilege(t *testing.T, ctx context.Context, adminPool *pgxpool.Pool, table string, grant bool) {
	t.Helper()
	if _, err := adminPool.Exec(ctx, tenantSwitchPrivilegeStatement(table, grant)); err != nil {
		action := "revoke"
		if grant {
			action = "grant"
		}
		t.Fatalf("%s runtime INSERT on %s: %v", action, table, err)
	}
}

func tenantSwitchPrivilegeStatement(table string, grant bool) string {
	var statement string
	switch table {
	case "audit.events":
		statement = "INSERT ON TABLE audit.events"
	case "ops.outbox":
		statement = "INSERT ON TABLE ops.outbox"
	default:
		panic("unsupported tenant-switch fault table")
	}
	if grant {
		return "GRANT " + statement + " TO machina_runtime"
	}
	return "REVOKE " + statement + " FROM machina_runtime"
}

func assertTenantSwitchSessionActive(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sessionHash []byte, want bool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM iam.get_active_session($1::bytea)", sessionHash).Scan(&count); err != nil {
		t.Fatalf("check active session: %v", err)
	}
	wantCount := 0
	if want {
		wantCount = 1
	}
	if count != wantCount {
		t.Fatalf("active session count = %d, want %d", count, wantCount)
	}
}

func assertTenantSwitchSideEffectCounts(
	t *testing.T,
	ctx context.Context,
	adminPool *pgxpool.Pool,
	tenantID pgtype.UUID,
	idempotencyKey string,
	correlationID pgtype.UUID,
	wantReceipt int,
	wantAudit int,
	wantOutbox int,
) {
	t.Helper()
	var receiptCount int
	if err := adminPool.QueryRow(ctx, `SELECT count(*) FROM ops.idempotency_keys WHERE tenant_id=$1 AND idempotency_key=$2`, tenantID, idempotencyKey).Scan(&receiptCount); err != nil {
		t.Fatalf("count tenant-switch receipts: %v", err)
	}
	var auditCount int
	if err := adminPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE tenant_id=$1 AND correlation_id=$2`, tenantID, correlationID).Scan(&auditCount); err != nil {
		t.Fatalf("count tenant-switch audit events: %v", err)
	}
	var outboxCount int
	if err := adminPool.QueryRow(ctx, `SELECT count(*) FROM ops.outbox WHERE tenant_id=$1 AND correlation_id=$2`, tenantID, correlationID).Scan(&outboxCount); err != nil {
		t.Fatalf("count tenant-switch outbox events: %v", err)
	}
	if receiptCount != wantReceipt || auditCount != wantAudit || outboxCount != wantOutbox {
		t.Fatalf("tenant-switch side-effect counts = receipt:%d audit:%d outbox:%d, want %d/%d/%d", receiptCount, auditCount, outboxCount, wantReceipt, wantAudit, wantOutbox)
	}
}

func integrationUUID(last byte) pgtype.UUID {
	var bytes [16]byte
	bytes[15] = last
	return pgtype.UUID{Bytes: bytes, Valid: true}
}

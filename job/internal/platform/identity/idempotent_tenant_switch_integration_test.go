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

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig() error = %v", err)
	}
	poolConfig.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig() error = %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool.Ping() error = %v", err)
	}

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
}

func integrationUUID(last byte) pgtype.UUID {
	var bytes [16]byte
	bytes[15] = last
	return pgtype.UUID{Bytes: bytes, Valid: true}
}

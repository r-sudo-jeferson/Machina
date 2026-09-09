package identity

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestTenantSwitchCoordinatorDoesNotRejectDatabaseAcceptedExpiryOnAppClockSkew(t *testing.T) {
	unit := claimedTenantSwitchUnit()

	// The PostgreSQL switch function is the authoritative expiry gate and only
	// returns a session after checking expires_at > now() inside the transaction.
	// Model a small positive application-clock skew after that DB acceptance: the
	// application must not independently reject the already-validated result.
	databaseAcceptedExpiry := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	unit.bindRow.SessionExpiresAt = pgtype.Timestamptz{Time: databaseAcceptedExpiry, Valid: true}
	unit.switchRow.ExpiresAt = pgtype.Timestamptz{Time: databaseAcceptedExpiry, Valid: true}

	coordinator := newRecordingTenantSwitchCoordinator(unit, nil)
	result, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if err != nil {
		t.Fatalf("Switch() error = %v; application clock revalidated a database-accepted session expiry", err)
	}
	if !result.SessionExpiresAt.Equal(databaseAcceptedExpiry) {
		t.Fatalf("SessionExpiresAt = %s, want database-accepted %s", result.SessionExpiresAt, databaseAcceptedExpiry)
	}
}

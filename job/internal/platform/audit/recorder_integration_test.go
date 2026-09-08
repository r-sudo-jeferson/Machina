package audit

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

func TestDecisionEvidenceRoundTripPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("MACHINA_AUDIT_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("MACHINA_AUDIT_DATABASE_URL is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool.Ping() error = %v", err)
	}

	tenantID := auditIntegrationUUID(t, "00000000-0000-0000-0000-0000000000a1")
	actorID := auditIntegrationUUID(t, "10000000-0000-0000-0000-0000000000a1")
	cases := []struct {
		name          string
		decision      string
		eventID       string
		correlationID string
		reasonCodes   []string
	}{
		{
			name:          "allowed",
			decision:      "allow",
			eventID:       "40000000-0000-0000-0000-0000000000a1",
			correlationID: "50000000-0000-0000-0000-0000000000a1",
		},
		{
			name:          "denied",
			decision:      "deny",
			eventID:       "40000000-0000-0000-0000-0000000000a2",
			correlationID: "50000000-0000-0000-0000-0000000000a2",
			reasonCodes:   []string{"explicit_forbid", "stale_policy_version"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eventID := auditIntegrationUUID(t, tc.eventID)
			correlationID := auditIntegrationUUID(t, tc.correlationID)
			metadata, err := NewAuthorizationDecisionMetadata(tc.decision, 25*time.Millisecond, tc.reasonCodes)
			if err != nil {
				t.Fatalf("NewAuthorizationDecisionMetadata() error = %v", err)
			}
			event := Event{
				TenantID:       tenantID,
				ID:             eventID,
				ActorSubjectID: actorID,
				EventType:      "machina.authz.decision",
				Action:         "tenant.read",
				Decision:       tc.decision,
				PolicyVersion:  1,
				CorrelationID:  correlationID,
				SafeMetadata:   metadata,
				OccurredAt:     time.Date(2026, 9, 8, 20, 0, 0, 0, time.UTC),
			}
			params, err := Params(event)
			if err != nil {
				t.Fatalf("Params() error = %v", err)
			}

			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("pool.Begin() error = %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck -- cleanup after assertions
			var activeTenant string
			if err := tx.QueryRow(ctx, "SELECT set_config('app.tenant_id', $1, true)", "00000000-0000-0000-0000-0000000000a1").Scan(&activeTenant); err != nil {
				t.Fatalf("set tenant context: %v", err)
			}
			if activeTenant != "00000000-0000-0000-0000-0000000000a1" {
				t.Fatalf("active tenant = %q", activeTenant)
			}

			recorder, err := NewRecorder(sqlcgen.New(tx))
			if err != nil {
				t.Fatalf("NewRecorder() error = %v", err)
			}
			if err := recorder.Record(ctx, event); err != nil {
				t.Fatalf("Record() error = %v", err)
			}

			var stored StoredDecision
			var storedMetadata string
			if err := tx.QueryRow(ctx, `
				SELECT tenant_id, actor_subject_id, action, decision, policy_version, correlation_id, safe_metadata::text
				FROM audit.events
				WHERE tenant_id = $1 AND id = $2
			`, tenantID, eventID).Scan(
				&stored.TenantID,
				&stored.ActorSubjectID,
				&stored.Action,
				&stored.Decision,
				&stored.PolicyVersion,
				&stored.CorrelationID,
				&storedMetadata,
			); err != nil {
				t.Fatalf("read persisted audit event: %v", err)
			}
			stored.SafeMetadata = []byte(storedMetadata)
			if bytes.Equal(bytes.TrimSpace(stored.SafeMetadata), params.SafeMetadata) {
				t.Fatalf("PostgreSQL jsonb did not exercise normalized representation: %q", storedMetadata)
			}

			evidence, err := ReconstructDecision(stored)
			if err != nil {
				t.Fatalf("ReconstructDecision() error = %v; persisted metadata = %q", err, storedMetadata)
			}
			if evidence.TenantID != tenantID || evidence.ActorSubjectID != actorID || evidence.Action != "tenant.read" ||
				evidence.Decision != tc.decision || evidence.PolicyVersion != 1 || evidence.CorrelationID != correlationID ||
				evidence.Latency != 25*time.Millisecond || !reflect.DeepEqual(evidence.ReasonCodes, tc.reasonCodes) {
				t.Fatalf("DecisionEvidence = %#v", evidence)
			}

			if err := tx.Rollback(ctx); err != nil {
				t.Fatalf("tx.Rollback() error = %v", err)
			}
		})
	}
}

func auditIntegrationUUID(t *testing.T, value string) pgtype.UUID {
	t.Helper()
	var parsed pgtype.UUID
	if err := parsed.Scan(value); err != nil || !parsed.Valid {
		t.Fatalf("parse UUID %q: %v", value, err)
	}
	return parsed
}

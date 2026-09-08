-- name: InsertAuditEvent :exec
INSERT INTO audit.events (
  tenant_id,
  id,
  actor_subject_id,
  event_type,
  action,
  decision,
  policy_version,
  correlation_id,
  safe_metadata,
  previous_hash,
  event_hash,
  occurred_at
) VALUES (
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(event_id)::uuid,
  sqlc.arg(actor_subject_id)::uuid,
  sqlc.arg(event_type)::text,
  sqlc.arg(action)::text,
  sqlc.arg(decision)::text,
  sqlc.arg(policy_version)::bigint,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(safe_metadata)::jsonb,
  sqlc.arg(previous_hash)::bytea,
  sqlc.arg(event_hash)::bytea,
  sqlc.arg(occurred_at)::timestamptz
);

-- name: EnqueueOutboxEvent :exec
INSERT INTO ops.outbox (
  tenant_id,
  id,
  event_type,
  event_version,
  correlation_id,
  payload,
  occurred_at
) VALUES (
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(event_id)::uuid,
  sqlc.arg(event_type)::text,
  sqlc.arg(event_version)::int,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(payload)::jsonb,
  sqlc.arg(occurred_at)::timestamptz
);

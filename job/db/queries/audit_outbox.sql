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

-- name: GetAuditChainHead :one
SELECT last_sequence, last_chain_hash
FROM audit.chain_heads
WHERE tenant_id = sqlc.arg(tenant_id)::uuid;

-- name: GetAuditCheckpoint :one
SELECT tenant_id, id, chain_sequence, chain_hash, statement_digest,
       algorithm, key_id, signature, signed_at
FROM audit.checkpoints
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND chain_sequence = sqlc.arg(chain_sequence)::bigint
  AND key_id = sqlc.arg(key_id)::text;

-- name: InsertAuditCheckpoint :one
INSERT INTO audit.checkpoints (
  tenant_id,
  id,
  chain_sequence,
  chain_hash,
  statement_digest,
  algorithm,
  key_id,
  signature,
  signed_at
) VALUES (
  sqlc.arg(tenant_id)::uuid,
  sqlc.arg(checkpoint_id)::uuid,
  sqlc.arg(chain_sequence)::bigint,
  sqlc.arg(chain_hash)::bytea,
  sqlc.arg(statement_digest)::bytea,
  sqlc.arg(algorithm)::text,
  sqlc.arg(key_id)::text,
  sqlc.arg(signature)::bytea,
  sqlc.arg(signed_at)::timestamptz
)
ON CONFLICT (tenant_id, chain_sequence, key_id) DO NOTHING
RETURNING tenant_id, id, chain_sequence, chain_hash, statement_digest,
          algorithm, key_id, signature, signed_at;

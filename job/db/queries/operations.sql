-- name: ClaimIdempotencyKey :one
SELECT
  claim.claim_state::text AS claim_state,
  claim.response_status::integer AS response_status,
  claim.response_body::jsonb AS response_body,
  claim.correlation_id::uuid AS correlation_id
FROM ops.claim_idempotency_key(
  sqlc.arg(idempotency_key)::text,
  sqlc.arg(operation)::text,
  sqlc.arg(request_hash)::text,
  sqlc.arg(correlation_id)::uuid,
  sqlc.arg(expires_at)::timestamptz
) AS claim(
  claim_state,
  response_status,
  response_body,
  correlation_id
);

-- name: CompleteIdempotencyKey :one
SELECT ops.complete_idempotency_key(
  sqlc.arg(idempotency_key)::text,
  sqlc.arg(operation)::text,
  sqlc.arg(request_hash)::text,
  sqlc.arg(response_status)::integer,
  sqlc.arg(response_body)::jsonb
)::boolean AS completed;

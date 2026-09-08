-- name: BindTenantSwitchIdempotency :one
SELECT
  bind.mapping_state::text AS mapping_state,
  bind.session_id::uuid AS session_id,
  bind.generation::bigint AS generation,
  bind.active_tenant_id::uuid AS active_tenant_id,
  bind.active_workspace_id::uuid AS active_workspace_id,
  bind.session_expires_at::timestamptz AS session_expires_at,
  bind.receipt_expires_at::timestamptz AS receipt_expires_at,
  bind.receipt_hash::text AS receipt_hash
FROM iam.bind_tenant_switch_idempotency(
  sqlc.arg(current_session_token_hash)::bytea,
  sqlc.arg(idempotency_key)::text,
  sqlc.arg(request_hash)::text,
  sqlc.arg(target_tenant_id)::uuid
) AS bind(
  mapping_state,
  session_id,
  generation,
  active_tenant_id,
  active_workspace_id,
  session_expires_at,
  receipt_expires_at,
  receipt_hash
);

-- name: FinishTenantSwitchIdempotency :one
SELECT
  finished::boolean AS finished,
  session_id::uuid AS session_id,
  result_generation::bigint AS result_generation
FROM iam.finish_tenant_switch_idempotency(
  sqlc.arg(current_session_token_hash)::bytea,
  sqlc.arg(idempotency_key)::text,
  sqlc.arg(request_hash)::text
) AS finished_scope(
  finished,
  session_id,
  result_generation
);

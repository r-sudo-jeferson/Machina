-- name: SetTenantSwitchResponseETag :one
SELECT ops.set_tenant_switch_response_etag(
  sqlc.arg(idempotency_key)::text,
  sqlc.arg(request_hash)::text,
  sqlc.arg(response_etag)::text
)::boolean AS set_response_etag;

-- name: GetTenantSwitchResponseETag :one
SELECT ops.get_tenant_switch_response_etag(
  sqlc.arg(idempotency_key)::text,
  sqlc.arg(request_hash)::text
)::text AS response_etag;

-- name: UpsertSubject :one
SELECT iam.upsert_subject(
  sqlc.arg(subject_id)::uuid,
  sqlc.arg(external_subject)::text,
  sqlc.arg(display_name)::text
)::uuid AS subject_id;

-- name: CreateSession :one
SELECT iam.create_session(
  sqlc.arg(session_id)::uuid,
  sqlc.arg(subject_id)::uuid,
  sqlc.arg(session_token_hash)::bytea,
  sqlc.arg(csrf_token_hash)::bytea,
  sqlc.arg(expires_at)::timestamptz
)::uuid AS session_id;

-- name: GetActiveSession :one
SELECT
  active_session.id::uuid AS id,
  active_session.subject_id::uuid AS subject_id,
  active_session.csrf_token_hash::bytea AS csrf_token_hash,
  active_session.active_tenant_id::uuid AS active_tenant_id,
  active_session.active_workspace_id::uuid AS active_workspace_id,
  active_session.expires_at::timestamptz AS expires_at,
  active_session.rotated_at::timestamptz AS rotated_at
FROM iam.get_active_session(sqlc.arg(session_token_hash)::bytea) AS active_session(
  id,
  subject_id,
  csrf_token_hash,
  active_tenant_id,
  active_workspace_id,
  expires_at,
  rotated_at
);

-- name: GetSessionIdentity :one
SELECT
  session_identity.id::uuid AS id,
  session_identity.display_name::text AS display_name
FROM iam.get_session_identity(sqlc.arg(session_token_hash)::bytea) AS session_identity(
  id,
  display_name
);

-- name: ListSessionTenants :many
SELECT
  session_tenant.tenant_id::uuid AS tenant_id,
  session_tenant.slug::text AS slug,
  session_tenant.display_name::text AS display_name,
  session_tenant.status::text AS status,
  session_tenant.starter_role::text AS starter_role
FROM iam.list_session_tenants(sqlc.arg(session_token_hash)::bytea) AS session_tenant(
  tenant_id,
  slug,
  display_name,
  status,
  starter_role
);

-- name: RevokeSession :exec
SELECT iam.revoke_session(sqlc.arg(session_token_hash)::bytea);

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
  id,
  subject_id,
  csrf_token_hash,
  active_tenant_id,
  active_workspace_id,
  expires_at,
  rotated_at
FROM iam.get_active_session(sqlc.arg(session_token_hash)::bytea);

-- name: RevokeSession :exec
SELECT iam.revoke_session(sqlc.arg(session_token_hash)::bytea);

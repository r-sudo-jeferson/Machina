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
  active_session.id,
  active_session.subject_id,
  active_session.csrf_token_hash,
  active_session.active_tenant_id,
  active_session.active_workspace_id,
  active_session.expires_at,
  active_session.rotated_at
FROM iam.get_active_session(sqlc.arg(session_token_hash)::bytea) AS active_session(
  id,
  subject_id,
  csrf_token_hash,
  active_tenant_id,
  active_workspace_id,
  expires_at,
  rotated_at
);

-- name: RevokeSession :exec
SELECT iam.revoke_session(sqlc.arg(session_token_hash)::bytea);

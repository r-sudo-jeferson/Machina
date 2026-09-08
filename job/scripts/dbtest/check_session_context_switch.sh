#!/usr/bin/env bash
set -euo pipefail

readonly SWITCH_SESSION_ID='39000000-0000-0000-0000-00000000cb01'
readonly REVOKED_SESSION_ID='39000000-0000-0000-0000-00000000cb02'
readonly SUSPENDED_SESSION_ID='39000000-0000-0000-0000-00000000cb03'
readonly MISMATCH_SESSION_ID='39000000-0000-0000-0000-00000000cb04'
readonly EXPIRED_SESSION_ID='39000000-0000-0000-0000-00000000cb05'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.memberships
SET status = 'active', starter_role = 'member', updated_at = now()
WHERE tenant_id = '${TENANT_B}' AND subject_id = '${SUBJECT_A}';

INSERT INTO iam.sessions (id, subject_id, session_token_hash, csrf_token_hash, expires_at) VALUES
  ('${SWITCH_SESSION_ID}', '${SUBJECT_A}', decode(repeat('e1', 32), 'hex'), decode(repeat('d1', 32), 'hex'), now() + interval '2 hours'),
  ('${REVOKED_SESSION_ID}', '${SUBJECT_A}', decode(repeat('e4', 32), 'hex'), decode(repeat('d4', 32), 'hex'), now() + interval '2 hours'),
  ('${SUSPENDED_SESSION_ID}', '${SUBJECT_A}', decode(repeat('e5', 32), 'hex'), decode(repeat('d5', 32), 'hex'), now() + interval '2 hours'),
  ('${MISMATCH_SESSION_ID}', '${SUBJECT_A}', decode(repeat('e6', 32), 'hex'), decode(repeat('d6', 32), 'hex'), now() + interval '2 hours'),
  ('${EXPIRED_SESSION_ID}', '${SUBJECT_A}', decode(repeat('e7', 32), 'hex'), decode(repeat('d7', 32), 'hex'), now() - interval '1 minute');
SQL

switch_result="$(query_as "$RUNTIME_ROLE" "SELECT session_id::text || ':' || active_tenant_id::text || ':' || active_workspace_id::text FROM iam.switch_session_context(decode(repeat('e1', 32), 'hex'), decode(repeat('e2', 32), 'hex'), decode(repeat('d2', 32), 'hex'), '${TENANT_B}', '${WORKSPACE_B}')")"
expect_equals "${SWITCH_SESSION_ID}:${TENANT_B}:${WORKSPACE_B}" "$switch_result" 'valid session context switch did not return authoritative target context'

old_token_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode(repeat('e1', 32), 'hex'))")"
expect_equals '0' "$old_token_count" 'session context switch left the pre-switch token active'

new_context="$(query_as "$RUNTIME_ROLE" "SELECT active_tenant_id::text || ':' || active_workspace_id::text FROM iam.get_active_session(decode(repeat('e2', 32), 'hex'))")"
expect_equals "${TENANT_B}:${WORKSPACE_B}" "$new_context" 'rotated session does not carry the validated server-side context'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.memberships
SET status = 'revoked', updated_at = now()
WHERE tenant_id = '${TENANT_B}' AND subject_id = '${SUBJECT_A}';
SQL
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode(repeat('e4', 32), 'hex'), decode(repeat('e8', 32), 'hex'), decode(repeat('d8', 32), 'hex'), '${TENANT_B}', '${WORKSPACE_B}')" 'revoked membership selected a tenant'
revoked_old_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode(repeat('e4', 32), 'hex'))")"
expect_equals '1' "$revoked_old_count" 'failed revoked-membership switch mutated the existing session'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.memberships
SET status = 'active', updated_at = now()
WHERE tenant_id = '${TENANT_B}' AND subject_id = '${SUBJECT_A}';
UPDATE iam.tenants
SET status = 'suspended', updated_at = now()
WHERE id = '${TENANT_B}';
SQL
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode(repeat('e5', 32), 'hex'), decode(repeat('e9', 32), 'hex'), decode(repeat('d9', 32), 'hex'), '${TENANT_B}', '${WORKSPACE_B}')" 'suspended tenant became active session context'
suspended_old_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode(repeat('e5', 32), 'hex'))")"
expect_equals '1' "$suspended_old_count" 'failed suspended-tenant switch mutated the existing session'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.tenants
SET status = 'active', updated_at = now()
WHERE id = '${TENANT_B}';
SQL

expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode(repeat('e6', 32), 'hex'), decode(repeat('ea', 32), 'hex'), decode(repeat('da', 32), 'hex'), '${TENANT_B}', '${WORKSPACE_A}')" 'workspace from another tenant was accepted as active context'
mismatch_old_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode(repeat('e6', 32), 'hex'))")"
expect_equals '1' "$mismatch_old_count" 'failed workspace-mismatch switch mutated the existing session'

expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode(repeat('e7', 32), 'hex'), decode(repeat('eb', 32), 'hex'), decode(repeat('db', 32), 'hex'), '${TENANT_B}', '${WORKSPACE_B}')" 'expired session switched tenant context'

printf 'dbtest: atomic server-validated session context switch boundary passed\n'

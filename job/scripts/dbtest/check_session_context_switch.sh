#!/usr/bin/env bash
set -euo pipefail

readonly SWITCH_SESSION_ID='39000000-0000-0000-0000-00000000cb01'
readonly REVOKED_SESSION_ID='39000000-0000-0000-0000-00000000cb02'
readonly SUSPENDED_SESSION_ID='39000000-0000-0000-0000-00000000cb03'
readonly MISMATCH_SESSION_ID='39000000-0000-0000-0000-00000000cb04'
readonly EXPIRED_SESSION_ID='39000000-0000-0000-0000-00000000cb05'

readonly SWITCH_OLD_HASH='a2556aa0788174716d1c163dbeca1e3217bd32d00cf7f582e8d80580e7757868'
readonly SWITCH_OLD_CSRF_HASH='096c58047951b112b3ecd3164e860dc3b435075f026fa23399fe8d27a26bcdce'
readonly SWITCH_NEW_HASH='97733d9252ef7aae9cc0105f580b43146c343933dd6602190a744f8f4ba2c51c'
readonly SWITCH_NEW_CSRF_HASH='1dee43b7222d69616fcf2b77ef612a761a8b606257fc8dfc244a36d00e168af3'

readonly REVOKED_OLD_HASH='084e11173d6de8bb8d581439ad397c400df80e9941c78f85050783674f11214e'
readonly REVOKED_OLD_CSRF_HASH='30041a8935800a706aa8f0437ffe54094a9720074d0c27b3802883791b351ba8'
readonly REVOKED_NEW_HASH='24e49f294e4658c4402422778555d34494f0bf749c74022b5d1032944ce97a20'
readonly REVOKED_NEW_CSRF_HASH='159ef90990b4d5100e804da26565052f3d4ac68e9b4ca0c1c82e78f91c162272'

readonly SUSPENDED_OLD_HASH='900934cde097d975a5982d8db40d9922de38c06b5408ff04e91f46fae9962f7d'
readonly SUSPENDED_OLD_CSRF_HASH='6fb8e36feeea5db28a5b94c12f9f2654e1a7cdfa038a6730c451b9b05e792de8'
readonly SUSPENDED_NEW_HASH='da40ab5545b7b83ae1108d45252162e86f4b40fcd698047e3e8403789a85704b'
readonly SUSPENDED_NEW_CSRF_HASH='fa3be0da1e25dd50fe60d5b3d25e313830c77ce333b975fb8ee6c1acb0ddfb08'

readonly MISMATCH_OLD_HASH='e61dc1704ed90030254b988670be472a655f5c7e13c08e79e6376d096beb84e2'
readonly MISMATCH_OLD_CSRF_HASH='02c9787205719361e33536e3cc468b360a0bb6fbd1e269b05a7db103f5f22656'
readonly MISMATCH_NEW_HASH='93d2df9a8116fddcd12af57cbd6c8c54b5d1dcda3e0368acc957ba9cd24072a1'
readonly MISMATCH_NEW_CSRF_HASH='66af13d4a17231d6f02c54be5c5a3a21fcdc309cd9f7972938e29596c4a8cbad'

readonly EXPIRED_OLD_HASH='9df9b49ab1fe24294f51e35ab791bec7b8e831b2f72bcbf311ed8e0d21d9819d'
readonly EXPIRED_OLD_CSRF_HASH='9df9838d2f8dee0db0fa4111c489bfbb194b9eb38785a79ddc745df4785d6a34'
readonly EXPIRED_NEW_HASH='a530bc222d71dfa9823758ec610e2706189b207b61fb402ea55abd83764f34e5'
readonly EXPIRED_NEW_CSRF_HASH='1dabb021cb7e016e68a2ce0836eaf05f46e5f13f3161d483e01d29e772f2b844'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.memberships
SET status = 'active', starter_role = 'member', updated_at = now()
WHERE tenant_id = '${TENANT_B}' AND subject_id = '${SUBJECT_A}';

INSERT INTO iam.sessions (id, subject_id, session_token_hash, csrf_token_hash, expires_at) VALUES
  ('${SWITCH_SESSION_ID}', '${SUBJECT_A}', decode('${SWITCH_OLD_HASH}', 'hex'), decode('${SWITCH_OLD_CSRF_HASH}', 'hex'), now() + interval '2 hours'),
  ('${REVOKED_SESSION_ID}', '${SUBJECT_A}', decode('${REVOKED_OLD_HASH}', 'hex'), decode('${REVOKED_OLD_CSRF_HASH}', 'hex'), now() + interval '2 hours'),
  ('${SUSPENDED_SESSION_ID}', '${SUBJECT_A}', decode('${SUSPENDED_OLD_HASH}', 'hex'), decode('${SUSPENDED_OLD_CSRF_HASH}', 'hex'), now() + interval '2 hours'),
  ('${MISMATCH_SESSION_ID}', '${SUBJECT_A}', decode('${MISMATCH_OLD_HASH}', 'hex'), decode('${MISMATCH_OLD_CSRF_HASH}', 'hex'), now() + interval '2 hours'),
  ('${EXPIRED_SESSION_ID}', '${SUBJECT_A}', decode('${EXPIRED_OLD_HASH}', 'hex'), decode('${EXPIRED_OLD_CSRF_HASH}', 'hex'), now() - interval '1 minute');
SQL

switch_result="$(query_as "$RUNTIME_ROLE" "SELECT session_id::text || ':' || active_tenant_id::text || ':' || active_workspace_id::text FROM iam.switch_session_context(decode('${SWITCH_OLD_HASH}', 'hex'), decode('${SWITCH_NEW_HASH}', 'hex'), decode('${SWITCH_NEW_CSRF_HASH}', 'hex'), '${TENANT_B}', '${WORKSPACE_B}')")"
expect_equals "${SWITCH_SESSION_ID}:${TENANT_B}:${WORKSPACE_B}" "$switch_result" 'valid session context switch did not return authoritative target context'

old_token_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${SWITCH_OLD_HASH}', 'hex'))")"
expect_equals '0' "$old_token_count" 'session context switch left the pre-switch token active'

new_context="$(query_as "$RUNTIME_ROLE" "SELECT active_tenant_id::text || ':' || active_workspace_id::text FROM iam.get_active_session(decode('${SWITCH_NEW_HASH}', 'hex'))")"
expect_equals "${TENANT_B}:${WORKSPACE_B}" "$new_context" 'rotated session does not carry the validated server-side context'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.memberships
SET status = 'revoked', updated_at = now()
WHERE tenant_id = '${TENANT_B}' AND subject_id = '${SUBJECT_A}';
SQL
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode('${REVOKED_OLD_HASH}', 'hex'), decode('${REVOKED_NEW_HASH}', 'hex'), decode('${REVOKED_NEW_CSRF_HASH}', 'hex'), '${TENANT_B}', '${WORKSPACE_B}')" 'revoked membership selected a tenant'
revoked_old_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${REVOKED_OLD_HASH}', 'hex'))")"
expect_equals '1' "$revoked_old_count" 'failed revoked-membership switch mutated the existing session'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.memberships
SET status = 'active', updated_at = now()
WHERE tenant_id = '${TENANT_B}' AND subject_id = '${SUBJECT_A}';
UPDATE iam.tenants
SET status = 'suspended', updated_at = now()
WHERE id = '${TENANT_B}';
SQL
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode('${SUSPENDED_OLD_HASH}', 'hex'), decode('${SUSPENDED_NEW_HASH}', 'hex'), decode('${SUSPENDED_NEW_CSRF_HASH}', 'hex'), '${TENANT_B}', '${WORKSPACE_B}')" 'suspended tenant became active session context'
suspended_old_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${SUSPENDED_OLD_HASH}', 'hex'))")"
expect_equals '1' "$suspended_old_count" 'failed suspended-tenant switch mutated the existing session'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.tenants
SET status = 'active', updated_at = now()
WHERE id = '${TENANT_B}';
SQL

expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode('${MISMATCH_OLD_HASH}', 'hex'), decode('${MISMATCH_NEW_HASH}', 'hex'), decode('${MISMATCH_NEW_CSRF_HASH}', 'hex'), '${TENANT_B}', '${WORKSPACE_A}')" 'workspace from another tenant was accepted as active context'
mismatch_old_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${MISMATCH_OLD_HASH}', 'hex'))")"
expect_equals '1' "$mismatch_old_count" 'failed workspace-mismatch switch mutated the existing session'

expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode('${EXPIRED_OLD_HASH}', 'hex'), decode('${EXPIRED_NEW_HASH}', 'hex'), decode('${EXPIRED_NEW_CSRF_HASH}', 'hex'), '${TENANT_B}', '${WORKSPACE_B}')" 'expired session switched tenant context'

printf 'dbtest: atomic server-validated session context switch boundary passed\n'

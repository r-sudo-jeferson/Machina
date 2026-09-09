#!/usr/bin/env bash

readonly CONTEXT_SESSION='30000000-0000-0000-0000-0000000000e1'
readonly CONTEXT_SESSION_HASH="$(printf '33%.0s' {1..32})"
readonly CONTEXT_CSRF_HASH="$(printf '44%.0s' {1..32})"

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
INSERT INTO iam.memberships (tenant_id, subject_id, starter_role, status)
VALUES ('${TENANT_B}', '${SUBJECT_A}', 'member', 'active');
SQL

runtime_guc_bypass_count="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.session_context_lookup','on',true); SELECT count(*) FROM iam.memberships; COMMIT;" | tail -n 1)"
expect_equals '0' "$runtime_guc_bypass_count" 'runtime forged session-context GUC and bypassed tenant RLS'

context_session_id="$(query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${CONTEXT_SESSION}'::uuid, '${SUBJECT_A}'::uuid, decode('${CONTEXT_SESSION_HASH}','hex'), decode('${CONTEXT_CSRF_HASH}','hex'), now() + interval '30 minutes')::text")"
expect_equals "$CONTEXT_SESSION" "$context_session_id" 'context test session was not created'

identity="$(query_as "$RUNTIME_ROLE" "SELECT id::text || ':' || display_name FROM iam.get_session_identity(decode('${CONTEXT_SESSION_HASH}','hex'))")"
expect_equals "${SUBJECT_A}:Subject A" "$identity" 'session-bound identity lookup returned the wrong subject'

invalid_identity_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_session_identity(decode('$(printf '55%.0s' {1..32})','hex'))")"
expect_equals '0' "$invalid_identity_count" 'unknown session hash exposed an identity'

available_tenants="$(query_as "$RUNTIME_ROLE" "SELECT string_agg(tenant_id::text || ':' || starter_role, ',' ORDER BY tenant_id) FROM iam.list_session_tenants(decode('${CONTEXT_SESSION_HASH}','hex'))")"
expect_equals "${TENANT_A}:owner,${TENANT_B}:member" "$available_tenants" 'session-bound tenant listing did not return exactly the active memberships'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
UPDATE iam.memberships
SET status = 'revoked', updated_at = now()
WHERE tenant_id = '${TENANT_B}' AND subject_id = '${SUBJECT_A}';
SQL

available_after_revoke="$(query_as "$RUNTIME_ROLE" "SELECT string_agg(tenant_id::text || ':' || starter_role, ',' ORDER BY tenant_id) FROM iam.list_session_tenants(decode('${CONTEXT_SESSION_HASH}','hex'))")"
expect_equals "${TENANT_A}:owner" "$available_after_revoke" 'revoked membership remained available to the session'

query_as "$RUNTIME_ROLE" "SELECT iam.revoke_session(decode('${CONTEXT_SESSION_HASH}','hex'))" >/dev/null

revoked_identity_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_session_identity(decode('${CONTEXT_SESSION_HASH}','hex'))")"
expect_equals '0' "$revoked_identity_count" 'revoked session still exposed identity context'

revoked_tenant_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.list_session_tenants(decode('${CONTEXT_SESSION_HASH}','hex'))")"
expect_equals '0' "$revoked_tenant_count" 'revoked session still exposed tenant context'

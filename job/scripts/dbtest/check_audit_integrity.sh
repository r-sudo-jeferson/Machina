#!/usr/bin/env bash

readonly AUDIT_EVENT_A='40000000-0000-0000-0000-0000000000c1'
readonly AUDIT_CORRELATION_A='50000000-0000-0000-0000-0000000000c1'
readonly AUDIT_EVENT_HASH_A_HEX='1111111111111111111111111111111111111111111111111111111111111111'
readonly ZERO_HASH_HEX='0000000000000000000000000000000000000000000000000000000000000000'

query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
INSERT INTO audit.events (
  tenant_id, id, actor_subject_id, event_type, action, decision,
  policy_version, correlation_id, safe_metadata, previous_hash, event_hash, occurred_at
) VALUES (
  '${TENANT_A}', '${AUDIT_EVENT_A}', '${SUBJECT_A}',
  'machina.audit.integrity.test', 'audit.integrity.test', 'allow',
  1, '${AUDIT_CORRELATION_A}', '{}'::jsonb, NULL,
  decode('${AUDIT_EVENT_HASH_A_HEX}', 'hex'), '2026-09-09T11:15:00Z'::timestamptz
);
COMMIT;
" >/dev/null

expect_failure "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
UPDATE audit.events
SET action = 'tampered.action'
WHERE tenant_id = '${TENANT_A}' AND id = '${AUDIT_EVENT_A}';
COMMIT;
" 'runtime updated immutable audit history'

expect_failure "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
DELETE FROM audit.events
WHERE tenant_id = '${TENANT_A}' AND id = '${AUDIT_EVENT_A}';
COMMIT;
" 'runtime deleted immutable audit history'

runtime_event_privileges="$(query_as postgres "
SELECT COALESCE(string_agg(privilege_type, ',' ORDER BY privilege_type), '')
FROM information_schema.role_table_grants
WHERE grantee = '${RUNTIME_ROLE}'
  AND table_schema = 'audit'
  AND table_name = 'events'
")"
expect_equals 'INSERT,SELECT' "$runtime_event_privileges" 'runtime audit.events privileges are not append-only'

chain_regclass="$(query_as postgres "SELECT COALESCE(to_regclass('audit.event_chain')::text, '')")"
expect_equals 'audit.event_chain' "$chain_regclass" 'authoritative audit event chain table is missing'

chain_row="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
SELECT sequence::text || ':' || encode(previous_chain_hash, 'hex') || ':' ||
       octet_length(event_hash)::text || ':' || octet_length(chain_hash)::text
FROM audit.event_chain
WHERE tenant_id = '${TENANT_A}' AND event_id = '${AUDIT_EVENT_A}';
COMMIT;
" | tail -n 1)"
expect_equals "1:${ZERO_HASH_HEX}:32:32" "$chain_row" 'first audit event was not chained from the zero genesis'

printf 'dbtest: audit append-only RED/GREEN boundary passed\n'

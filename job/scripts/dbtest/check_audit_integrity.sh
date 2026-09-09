#!/usr/bin/env bash

readonly AUDIT_EVENT_A1='40000000-0000-0000-0000-0000000000c1'
readonly AUDIT_EVENT_A2='40000000-0000-0000-0000-0000000000c2'
readonly AUDIT_EVENT_A3='40000000-0000-0000-0000-0000000000c3'
readonly AUDIT_EVENT_A4='40000000-0000-0000-0000-0000000000c4'
readonly AUDIT_EVENT_B1='40000000-0000-0000-0000-0000000000d1'
readonly AUDIT_EVENT_B2='40000000-0000-0000-0000-0000000000d2'
readonly AUDIT_CORRELATION_A='50000000-0000-0000-0000-0000000000c1'
readonly AUDIT_CORRELATION_B='50000000-0000-0000-0000-0000000000d1'
readonly AUDIT_EVENT_HASH_A1_HEX='1111111111111111111111111111111111111111111111111111111111111111'
readonly AUDIT_EVENT_HASH_A2_HEX='2222222222222222222222222222222222222222222222222222222222222222'
readonly AUDIT_EVENT_HASH_A3_HEX='3333333333333333333333333333333333333333333333333333333333333333'
readonly AUDIT_EVENT_HASH_A4_HEX='4444444444444444444444444444444444444444444444444444444444444444'
readonly AUDIT_EVENT_HASH_B1_HEX='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly AUDIT_EVENT_HASH_B2_HEX='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly ZERO_HASH_HEX='0000000000000000000000000000000000000000000000000000000000000000'

insert_audit_event() {
  local tenant_id="$1"
  local subject_id="$2"
  local event_id="$3"
  local correlation_id="$4"
  local event_hash_hex="$5"
  local occurred_at="$6"

  query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${tenant_id}',true);
INSERT INTO audit.events (
  tenant_id, id, actor_subject_id, event_type, action, decision,
  policy_version, correlation_id, safe_metadata, previous_hash, event_hash, occurred_at
) VALUES (
  '${tenant_id}', '${event_id}', '${subject_id}',
  'machina.audit.integrity.test', 'audit.integrity.test', 'allow',
  1, '${correlation_id}', '{}'::jsonb, NULL,
  decode('${event_hash_hex}', 'hex'), '${occurred_at}'::timestamptz
);
COMMIT;
" >/dev/null
}

insert_audit_event \
  "$TENANT_A" "$SUBJECT_A" "$AUDIT_EVENT_A1" "$AUDIT_CORRELATION_A" \
  "$AUDIT_EVENT_HASH_A1_HEX" '2026-09-09T11:15:00Z'

expect_failure "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
UPDATE audit.events
SET action = 'tampered.action'
WHERE tenant_id = '${TENANT_A}' AND id = '${AUDIT_EVENT_A1}';
COMMIT;
" 'runtime updated immutable audit history'

expect_failure "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
DELETE FROM audit.events
WHERE tenant_id = '${TENANT_A}' AND id = '${AUDIT_EVENT_A1}';
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

for table_name in chain_heads event_chain checkpoints; do
  table_regclass="$(query_as postgres "SELECT COALESCE(to_regclass('audit.${table_name}')::text, '')")"
  expect_equals "audit.${table_name}" "$table_regclass" "required audit.${table_name} table is missing"
done

runtime_head_privileges="$(query_as postgres "
SELECT COALESCE(string_agg(privilege_type, ',' ORDER BY privilege_type), '')
FROM information_schema.role_table_grants
WHERE grantee = '${RUNTIME_ROLE}' AND table_schema = 'audit' AND table_name = 'chain_heads'
")"
expect_equals 'SELECT' "$runtime_head_privileges" 'runtime audit.chain_heads privileges are not read-only'

runtime_chain_privileges="$(query_as postgres "
SELECT COALESCE(string_agg(privilege_type, ',' ORDER BY privilege_type), '')
FROM information_schema.role_table_grants
WHERE grantee = '${RUNTIME_ROLE}' AND table_schema = 'audit' AND table_name = 'event_chain'
")"
expect_equals 'SELECT' "$runtime_chain_privileges" 'runtime audit.event_chain privileges are not read-only'

runtime_checkpoint_privileges="$(query_as postgres "
SELECT COALESCE(string_agg(privilege_type, ',' ORDER BY privilege_type), '')
FROM information_schema.role_table_grants
WHERE grantee = '${RUNTIME_ROLE}' AND table_schema = 'audit' AND table_name = 'checkpoints'
")"
expect_equals 'INSERT,SELECT' "$runtime_checkpoint_privileges" 'runtime audit.checkpoints privileges are not append-only'

chain_row="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
SELECT sequence::text || ':' || encode(previous_chain_hash, 'hex') || ':' ||
       octet_length(event_hash)::text || ':' || octet_length(chain_hash)::text
FROM audit.event_chain
WHERE tenant_id = '${TENANT_A}' AND event_id = '${AUDIT_EVENT_A1}';
COMMIT;
" | tail -n 1)"
expect_equals "1:${ZERO_HASH_HEX}:32:32" "$chain_row" 'first audit event was not chained from the zero genesis'

first_chain_hash="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
SELECT encode(chain_hash, 'hex') FROM audit.event_chain
WHERE tenant_id = '${TENANT_A}' AND event_id = '${AUDIT_EVENT_A1}';
COMMIT;
" | tail -n 1)"
expected_first_chain_hash="$(query_as postgres "SELECT encode(sha256(decode('${ZERO_HASH_HEX}', 'hex') || decode('${AUDIT_EVENT_HASH_A1_HEX}', 'hex')), 'hex')")"
expect_equals "$expected_first_chain_hash" "$first_chain_hash" 'first audit chain hash does not match PostgreSQL recomputation'

insert_audit_event \
  "$TENANT_A" "$SUBJECT_A" "$AUDIT_EVENT_A2" "$AUDIT_CORRELATION_A" \
  "$AUDIT_EVENT_HASH_A2_HEX" '2026-09-09T11:15:01Z'

second_chain_row="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
SELECT sequence::text || ':' || encode(previous_chain_hash, 'hex') || ':' || encode(chain_hash, 'hex')
FROM audit.event_chain
WHERE tenant_id = '${TENANT_A}' AND event_id = '${AUDIT_EVENT_A2}';
COMMIT;
" | tail -n 1)"
expected_second_hash="$(query_as postgres "SELECT encode(sha256(decode('${first_chain_hash}', 'hex') || decode('${AUDIT_EVENT_HASH_A2_HEX}', 'hex')), 'hex')")"
expect_equals "2:${first_chain_hash}:${expected_second_hash}" "$second_chain_row" 'second audit event did not extend the tenant chain'

insert_audit_event \
  "$TENANT_B" "$SUBJECT_B" "$AUDIT_EVENT_B1" "$AUDIT_CORRELATION_B" \
  "$AUDIT_EVENT_HASH_B1_HEX" '2026-09-09T11:15:00Z'

tenant_b_first="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_B}',true);
SELECT sequence::text || ':' || encode(previous_chain_hash, 'hex')
FROM audit.event_chain
WHERE tenant_id = '${TENANT_B}' AND event_id = '${AUDIT_EVENT_B1}';
COMMIT;
" | tail -n 1)"
expect_equals "1:${ZERO_HASH_HEX}" "$tenant_b_first" 'tenant B did not receive an independent chain genesis'

cross_tenant_visible="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
SELECT count(*) FROM audit.event_chain WHERE tenant_id = '${TENANT_B}';
COMMIT;
" | tail -n 1)"
expect_equals '0' "$cross_tenant_visible" 'tenant A observed tenant B audit chain rows'

missing_chain_context="$(query_as "$RUNTIME_ROLE" "SELECT (SELECT count(*) FROM audit.chain_heads)::text || ':' || (SELECT count(*) FROM audit.event_chain)::text || ':' || (SELECT count(*) FROM audit.checkpoints)::text")"
expect_equals '0:0:0' "$missing_chain_context" 'missing tenant context observed audit integrity state'

expect_failure "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
INSERT INTO audit.chain_heads (tenant_id,last_sequence,last_chain_hash)
VALUES ('${TENANT_A}',99,decode('${ZERO_HASH_HEX}','hex'));
COMMIT;
" 'runtime directly inserted an audit chain head'

expect_failure "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
INSERT INTO audit.event_chain (tenant_id,sequence,event_id,event_hash,previous_chain_hash,chain_hash)
VALUES ('${TENANT_A}',99,'40000000-0000-0000-0000-000000000099',decode('${AUDIT_EVENT_HASH_A1_HEX}','hex'),decode('${ZERO_HASH_HEX}','hex'),decode('${ZERO_HASH_HEX}','hex'));
COMMIT;
" 'runtime directly inserted an audit chain row'

# Same-tenant appenders must serialize through the tenant head without forking.
# Tenant B runs concurrently to prove there is no single global chain head.
insert_audit_event "$TENANT_A" "$SUBJECT_A" "$AUDIT_EVENT_A3" "$AUDIT_CORRELATION_A" "$AUDIT_EVENT_HASH_A3_HEX" '2026-09-09T11:15:02Z' &
pid_a3=$!
insert_audit_event "$TENANT_A" "$SUBJECT_A" "$AUDIT_EVENT_A4" "$AUDIT_CORRELATION_A" "$AUDIT_EVENT_HASH_A4_HEX" '2026-09-09T11:15:03Z' &
pid_a4=$!
insert_audit_event "$TENANT_B" "$SUBJECT_B" "$AUDIT_EVENT_B2" "$AUDIT_CORRELATION_B" "$AUDIT_EVENT_HASH_B2_HEX" '2026-09-09T11:15:01Z' &
pid_b2=$!
wait "$pid_a3"
wait "$pid_a4"
wait "$pid_b2"

sequence_integrity="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
WITH ordered AS (
  SELECT sequence, previous_chain_hash, chain_hash,
         lag(chain_hash) OVER (ORDER BY sequence) AS prior_chain_hash
  FROM audit.event_chain
  WHERE tenant_id = '${TENANT_A}'
), violations AS (
  SELECT 1
  FROM ordered
  WHERE (sequence = 1 AND previous_chain_hash <> decode('${ZERO_HASH_HEX}','hex'))
     OR (sequence > 1 AND previous_chain_hash IS DISTINCT FROM prior_chain_hash)
)
SELECT (SELECT count(*) FROM ordered)::text || ':' ||
       (SELECT min(sequence) FROM ordered)::text || ':' ||
       (SELECT max(sequence) FROM ordered)::text || ':' ||
       (SELECT count(*) FROM violations)::text;
COMMIT;
" | tail -n 1)"
expect_equals '4:1:4:0' "$sequence_integrity" 'concurrent tenant-A audit appends forked or skipped the chain'

tenant_b_sequence_integrity="$(query_as "$RUNTIME_ROLE" "
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_B}',true);
SELECT count(*)::text || ':' || min(sequence)::text || ':' || max(sequence)::text
FROM audit.event_chain
WHERE tenant_id = '${TENANT_B}';
COMMIT;
" | tail -n 1)"
expect_equals '2:1:2' "$tenant_b_sequence_integrity" 'tenant-B chain was coupled to tenant-A sequence state'

head_consistency="$(query_as postgres "
SELECT count(*)
FROM audit.chain_heads AS head
WHERE head.last_sequence <> (
        SELECT count(*) FROM audit.event_chain AS chain WHERE chain.tenant_id = head.tenant_id
      )
   OR head.last_chain_hash <> (
        SELECT chain.chain_hash
        FROM audit.event_chain AS chain
        WHERE chain.tenant_id = head.tenant_id
        ORDER BY chain.sequence DESC
        LIMIT 1
      )
")"
expect_equals '0' "$head_consistency" 'audit chain head diverged from immutable chain rows'

printf 'dbtest: audit append-only chain isolation and concurrency boundary passed\n'

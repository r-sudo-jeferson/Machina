#!/usr/bin/env bash
set -euo pipefail

readonly SCOPE_OPERATION='tenant.switch.v1'
readonly SCOPE_KEY='tenant-switch-scope-0001'
readonly SCOPE_KEY_SECOND='tenant-switch-scope-0002'
readonly SCOPE_KEY_INCOMPLETE='tenant-switch-scope-incomplete'
readonly SCOPE_CORRELATION='4b000000-0000-0000-0000-000000000001'
readonly SCOPE_REPLAY_CORRELATION='4b000000-0000-0000-0000-000000000002'
readonly SCOPE_SECOND_CORRELATION='4b000000-0000-0000-0000-000000000003'

readonly SCOPE_SESSION_ID='3b000000-0000-0000-0000-000000000001'
readonly SCOPE_SECOND_SESSION_ID='3b000000-0000-0000-0000-000000000002'
readonly SCOPE_INCOMPLETE_SESSION_ID='3b000000-0000-0000-0000-000000000003'
readonly SCOPE_OLD_HASH="$(printf 'b1%.0s' {1..32})"
readonly SCOPE_OLD_CSRF="$(printf 'b2%.0s' {1..32})"
readonly SCOPE_NEW_HASH="$(printf 'b3%.0s' {1..32})"
readonly SCOPE_NEW_CSRF="$(printf 'b4%.0s' {1..32})"
readonly SCOPE_SECOND_HASH="$(printf 'b5%.0s' {1..32})"
readonly SCOPE_SECOND_CSRF="$(printf 'b6%.0s' {1..32})"
readonly SCOPE_INCOMPLETE_HASH="$(printf 'b7%.0s' {1..32})"
readonly SCOPE_INCOMPLETE_CSRF="$(printf 'b8%.0s' {1..32})"
readonly SCOPE_ROTATED_HASH="$(printf 'bc%.0s' {1..32})"
readonly SCOPE_ROTATED_CSRF="$(printf 'bd%.0s' {1..32})"

scope_body_hash() {
  local tenant_id="$1"
  query_as postgres "SELECT encode(sha256(convert_to('${SCOPE_OPERATION}' || chr(10) || lower('${tenant_id}'), 'UTF8')), 'hex')"
}

readonly SCOPE_BODY_HASH_B="$(scope_body_hash "$TENANT_B")"
readonly SCOPE_BODY_HASH_A="$(scope_body_hash "$TENANT_A")"
scope_receipt_hash() {
  query_as postgres "SELECT encode(sha256(convert_to('${SCOPE_OPERATION}' || chr(10) || '${SCOPE_SESSION_ID}' || chr(10) || '${SCOPE_BODY_HASH_B}', 'UTF8')), 'hex')"
}
readonly SCOPE_RECEIPT_HASH="$(scope_receipt_hash)"

expect_equals '1' "$(query_as postgres "SELECT count(*) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='iam' AND class.relname='tenant_switch_idempotency_scopes' AND class.relrowsecurity AND class.relforcerowsecurity")" 'tenant-switch scope table is not protected by FORCE RLS'
expect_equals 'machina_migrator' "$(query_as postgres "SELECT owner.rolname FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace JOIN pg_roles AS owner ON owner.oid=class.relowner WHERE namespace.nspname='iam' AND class.relname='tenant_switch_idempotency_scopes'")" 'tenant-switch scope table has an unexpected owner'
expect_equals '0' "$(query_as postgres "SELECT count(*) FROM pg_attribute AS attribute JOIN pg_class AS class ON class.oid=attribute.attrelid JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='iam' AND class.relname='tenant_switch_idempotency_scopes' AND attribute.attnum > 0 AND attribute.attname IN ('session_token','session_token_hash','csrf_token','csrf_token_hash','encrypted_session_token','encrypted_csrf_token')")" 'tenant-switch scope table contains a raw-secret column'

# The runtime can invoke the narrow functions but cannot inspect or mutate the
# identity-owned scope relation. This is intentionally checked before any
# successful mapping is created.
expect_failure "$RUNTIME_ROLE" 'SELECT * FROM iam.tenant_switch_idempotency_scopes' 'runtime retained direct scope-table SELECT'
expect_failure "$RUNTIME_ROLE" "INSERT INTO iam.tenant_switch_idempotency_scopes (session_id,idempotency_key,operation,request_hash,tenant_id,claim_generation,expires_at) VALUES ('${SCOPE_SESSION_ID}','${SCOPE_KEY_SECOND}','${SCOPE_OPERATION}','${SCOPE_BODY_HASH_B}','${TENANT_B}',1,clock_timestamp()+interval '1 hour')" 'runtime retained direct scope-table INSERT'

# An incomplete scope cannot become durable. The deferred pair trigger must
# reject the commit and leave neither side of the pair behind.
query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${SCOPE_INCOMPLETE_SESSION_ID}','${SUBJECT_A}',decode('${SCOPE_INCOMPLETE_HASH}','hex'),decode('${SCOPE_INCOMPLETE_CSRF}','hex'),clock_timestamp()+interval '2 hours')" >/dev/null
expect_failure "$RUNTIME_ROLE" "BEGIN; SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_INCOMPLETE_HASH}','hex'),'${SCOPE_KEY_INCOMPLETE}','${SCOPE_BODY_HASH_B}','${TENANT_B}'); COMMIT;" 'incomplete tenant-switch scope committed without a receipt'
expect_equals '0' "$(query_as postgres "SELECT count(*) FROM iam.tenant_switch_idempotency_scopes WHERE session_id='${SCOPE_INCOMPLETE_SESSION_ID}' AND idempotency_key='${SCOPE_KEY_INCOMPLETE}'")" 'failed incomplete bind left a durable scope'

query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${SCOPE_SESSION_ID}','${SUBJECT_A}',decode('${SCOPE_OLD_HASH}','hex'),decode('${SCOPE_OLD_CSRF}','hex'),clock_timestamp()+interval '2 hours')" >/dev/null

# First selection starts with no active tenant. Bind, claim the receipt with
# the exact returned deadline, rotate through the existing server-validated
# switch boundary, complete the receipt, and finish the pair in one commit.
first_flow_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-scope-first.XXXXXX")"
set +e
docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" >"$first_flow_log" 2>&1 <<SQL
BEGIN;
SELECT * FROM iam.bind_tenant_switch_idempotency(
  decode('${SCOPE_OLD_HASH}','hex'),
  '${SCOPE_KEY}',
  '${SCOPE_BODY_HASH_B}',
  '${TENANT_B}'
) \gset bind_
SELECT claim_state, correlation_id, response_status, response_body
FROM ops.claim_idempotency_key(
  '${SCOPE_KEY}',
  '${SCOPE_OPERATION}',
  :'bind_receipt_hash',
  '${SCOPE_CORRELATION}',
  :'bind_receipt_expires_at'::timestamptz
) \gset claim_
SELECT * FROM iam.switch_session_context(
  decode('${SCOPE_OLD_HASH}','hex'),
  decode('${SCOPE_NEW_HASH}','hex'),
  decode('${SCOPE_NEW_CSRF}','hex'),
  '${TENANT_B}'
) \gset switched_
SELECT ops.complete_idempotency_key(
  '${SCOPE_KEY}',
  '${SCOPE_OPERATION}',
  :'bind_receipt_hash',
  200,
  jsonb_build_object(
    'active_tenant_id', :'bind_active_tenant_id',
    'active_workspace_id', :'bind_active_workspace_id',
    'generation', :'bind_generation'::bigint,
    'session_expires_at', :'bind_session_expires_at'
  )
) \gset completed_
SELECT * FROM iam.finish_tenant_switch_idempotency(
  decode('${SCOPE_NEW_HASH}','hex'),
  '${SCOPE_KEY}',
  '${SCOPE_BODY_HASH_B}'
) \gset finished_
SELECT 'first:' || :'bind_mapping_state' || ':' || :'claim_claim_state' || ':' || :'switched_session_id' || ':' || :'finished_finished';
COMMIT;
SQL
first_flow_exit=$?
set -e
if [[ "$first_flow_exit" -ne 0 ]]; then
  cat "$first_flow_log" >&2
  rm -f "$first_flow_log"
  fail "first tenant-switch scope transaction failed with exit ${first_flow_exit}"
fi
first_flow_result="$(tail -n 1 "$first_flow_log")"
if [[ "$first_flow_result" != "first:claimed:claimed:${SCOPE_SESSION_ID}:t" ]]; then
  cat "$first_flow_log" >&2
  rm -f "$first_flow_log"
  fail "first tenant-switch scope flow produced unexpected result: ${first_flow_result}"
fi
rm -f "$first_flow_log"

expect_equals '0' "$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${SCOPE_OLD_HASH}','hex'))")" 'successful scope switch left the old session token active'
expect_equals "${TENANT_B}:${WORKSPACE_B}" "$(query_as "$RUNTIME_ROLE" "SELECT active_tenant_id::text || ':' || active_workspace_id::text FROM iam.get_active_session(decode('${SCOPE_NEW_HASH}','hex'))")" 'successful scope switch did not preserve server-selected target context'
expect_equals "${SCOPE_RECEIPT_HASH}:${SCOPE_SESSION_ID}:2" "$(query_as postgres "SELECT receipt.request_hash || ':' || scope.session_id::text || ':' || scope.result_generation::text FROM ops.idempotency_keys AS receipt JOIN iam.tenant_switch_idempotency_scopes AS scope ON scope.tenant_id=receipt.tenant_id AND scope.idempotency_key=receipt.idempotency_key WHERE receipt.tenant_id='${TENANT_B}' AND receipt.idempotency_key='${SCOPE_KEY}'")" 'scope and receipt were not paired with the expected generation'
expect_equals '1' "$(query_as postgres "SELECT count(*) FROM ops.idempotency_keys AS receipt JOIN iam.tenant_switch_idempotency_scopes AS scope ON scope.tenant_id=receipt.tenant_id AND scope.idempotency_key=receipt.idempotency_key WHERE receipt.tenant_id='${TENANT_B}' AND receipt.idempotency_key='${SCOPE_KEY}' AND receipt.operation='${SCOPE_OPERATION}' AND receipt.request_hash=encode(sha256(convert_to('${SCOPE_OPERATION}' || chr(10) || '${SCOPE_SESSION_ID}' || chr(10) || '${SCOPE_BODY_HASH_B}','UTF8')),'hex') AND receipt.expires_at=scope.expires_at AND scope.claim_generation=1 AND scope.result_generation=2")" 'scope/receipt deadline or canonical receipt hash mismatch'

# The function clears its private capability before returning, while leaving
# the authorized target tenant available for the following generic claim.
capability_state="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_switch_scope','on',true); SELECT mapping_state FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_NEW_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_B}','${TENANT_B}'); SELECT COALESCE(NULLIF(current_setting('app.tenant_switch_scope',true),''),'<empty>'); ROLLBACK;" | tail -n 1)"
expect_equals '<empty>' "$capability_state" 'binder leaked its private scope capability'

# A current-cookie retry returns the historical pair and does not rotate
# again. The original correlation and deadline must survive the replay.
replay_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-scope-replay.XXXXXX")"
docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" >"$replay_log" 2>&1 <<SQL
BEGIN;
SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_NEW_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_B}','${TENANT_B}') \gset bind_
SELECT claim_state, correlation_id, response_status, response_body
FROM ops.claim_idempotency_key('${SCOPE_KEY}','${SCOPE_OPERATION}',:'bind_receipt_hash','${SCOPE_REPLAY_CORRELATION}',:'bind_receipt_expires_at'::timestamptz) \gset claim_
SELECT :'bind_mapping_state' || ':' || :'claim_claim_state' || ':' || :'claim_correlation_id' || ':' || :'bind_receipt_expires_at';
COMMIT;
SQL
replay_result="$(tail -n 1 "$replay_log")"
rm -f "$replay_log"
[[ "$replay_result" == replay:replay:${SCOPE_CORRELATION}:* ]] || fail "current-session replay was not immutable: ${replay_result}"
expect_equals '2' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${SCOPE_SESSION_ID}'")" 'current-cookie replay rotated the session again'
expect_equals '1' "$(query_as postgres "SELECT count(*) FROM ops.idempotency_keys WHERE tenant_id='${TENANT_B}' AND idempotency_key='${SCOPE_KEY}'")" 'current-cookie replay changed the receipt row'

# The same session/key cannot target another authorized tenant while live.
expect_equals 'conflict' "$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT mapping_state FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_NEW_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_A}','${TENANT_A}'); ROLLBACK;" | tail -n 1)" 'live same-session key with a different target did not conflict'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_NEW_HASH}','hex'),'${SCOPE_KEY_SECOND}','${SCOPE_BODY_HASH_B}','${TENANT_B}')" 'binder committed an incomplete scope in an uncoordinated statement'

# Another session can bind its own identity-stable mapping, but the tenant
# receipt key serializes it as a conflict and never discloses the winner body.
query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${SCOPE_SECOND_SESSION_ID}','${SUBJECT_A}',decode('${SCOPE_SECOND_HASH}','hex'),decode('${SCOPE_SECOND_CSRF}','hex'),clock_timestamp()+interval '2 hours')" >/dev/null
second_flow_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-scope-second.XXXXXX")"
docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" >"$second_flow_log" 2>&1 <<SQL
BEGIN;
SELECT bind.mapping_state || ':' || claim.claim_state || ':' || COALESCE(claim.response_status,0)::text || ':' || COALESCE(claim.response_body::text,'<null>')
FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_SECOND_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_B}','${TENANT_B}') AS bind
CROSS JOIN LATERAL ops.claim_idempotency_key('${SCOPE_KEY}','${SCOPE_OPERATION}',bind.receipt_hash,'${SCOPE_SECOND_CORRELATION}',bind.receipt_expires_at) AS claim;
ROLLBACK;
SQL
second_flow_result="$(tail -n 1 "$second_flow_log")"
rm -f "$second_flow_log"
expect_equals 'claimed:conflict:0:<null>' "$second_flow_result" 'cross-session same-key claim did not fail closed without a response body'
expect_equals '0' "$(query_as postgres "SELECT count(*) FROM iam.tenant_switch_idempotency_scopes WHERE session_id='${SCOPE_SECOND_SESSION_ID}' AND idempotency_key='${SCOPE_KEY}'")" 'rolled-back cross-session conflict left a scope mapping'

# A receipt deadline mismatch in either direction is an invalid paired state.
expect_failure postgres "BEGIN; UPDATE ops.idempotency_keys SET expires_at=scope.expires_at+interval '1 second' FROM iam.tenant_switch_idempotency_scopes AS scope WHERE ops.idempotency_keys.tenant_id='${TENANT_B}' AND ops.idempotency_keys.idempotency_key='${SCOPE_KEY}' AND scope.tenant_id=ops.idempotency_keys.tenant_id AND scope.idempotency_key=ops.idempotency_keys.idempotency_key; SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_NEW_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_B}','${TENANT_B}'); COMMIT;" 'binder accepted a receipt deadline mismatch'
expect_failure postgres "BEGIN; UPDATE iam.tenant_switch_idempotency_scopes SET expires_at=expires_at+interval '1 second' WHERE session_id='${SCOPE_SESSION_ID}' AND idempotency_key='${SCOPE_KEY}'; SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_NEW_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_B}','${TENANT_B}'); COMMIT;" 'binder accepted a scope deadline mismatch'

# Target deletion is restricted while the stable mapping exists. The FK action
# itself is asserted so another unrelated tenant reference cannot mask this
# invariant.
expect_equals 'r' "$(query_as postgres "SELECT fk.confdeltype FROM pg_constraint AS fk JOIN pg_class AS class ON class.oid=fk.conrelid JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname='iam' AND class.relname='tenant_switch_idempotency_scopes' AND fk.contype='f' AND fk.confrelid='iam.tenants'::regclass")" 'scope target FK does not use restrictive deletion semantics'
expect_failure postgres "DELETE FROM iam.tenants WHERE id='${TENANT_B}'" 'tenant deletion bypassed a live tenant-switch mapping'
expect_equals '1' "$(query_as postgres "SELECT count(*) FROM iam.tenant_switch_idempotency_scopes WHERE tenant_id='${TENANT_B}' AND idempotency_key='${SCOPE_KEY}'")" 'failed target deletion removed the stable mapping'

# A later rotation invalidates replay of the historical scope. The old cookie
# remains strictly unauthorized, and the new generation sees stale rather than
# reusing the old response.
query_as "$RUNTIME_ROLE" "SELECT * FROM iam.rotate_session(decode('${SCOPE_NEW_HASH}','hex'),decode('${SCOPE_ROTATED_HASH}','hex'),decode('${SCOPE_ROTATED_CSRF}','hex'))" >/dev/null
expect_equals '3' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${SCOPE_SESSION_ID}'")" 'later session rotation did not advance generation'
expect_equals 'stale' "$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT mapping_state FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_ROTATED_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_B}','${TENANT_B}'); ROLLBACK;" | tail -n 1)" 'later generation replayed a stale historical scope'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_NEW_HASH}','hex'),'${SCOPE_KEY}','${SCOPE_BODY_HASH_B}','${TENANT_B}')" 'old session token remained a strict invalidation failure'

# Revoked membership and suspended target are denied before any new mapping is
# durable; fixtures are restored for later database checks.
readonly SCOPE_REVOKED_SESSION_ID='3b000000-0000-0000-0000-000000000004'
readonly SCOPE_REVOKED_HASH="$(printf 'b9%.0s' {1..32})"
readonly SCOPE_REVOKED_CSRF="$(printf 'ba%.0s' {1..32})"
query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${SCOPE_REVOKED_SESSION_ID}','${SUBJECT_A}',decode('${SCOPE_REVOKED_HASH}','hex'),decode('${SCOPE_REVOKED_CSRF}','hex'),clock_timestamp()+interval '2 hours')" >/dev/null
query_as postgres "UPDATE iam.memberships SET status='revoked',updated_at=clock_timestamp() WHERE tenant_id='${TENANT_B}' AND subject_id='${SUBJECT_A}'" >/dev/null
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_REVOKED_HASH}','hex'),'${SCOPE_KEY_SECOND}','${SCOPE_BODY_HASH_B}','${TENANT_B}')" 'revoked membership bound a tenant-switch scope'
query_as postgres "UPDATE iam.memberships SET status='active',updated_at=clock_timestamp() WHERE tenant_id='${TENANT_B}' AND subject_id='${SUBJECT_A}'" >/dev/null
query_as postgres "UPDATE iam.tenants SET status='suspended',updated_at=clock_timestamp() WHERE id='${TENANT_B}'" >/dev/null
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${SCOPE_REVOKED_HASH}','hex'),'${SCOPE_KEY_SECOND}','${SCOPE_BODY_HASH_B}','${TENANT_B}')" 'suspended tenant bound a tenant-switch scope'
query_as postgres "UPDATE iam.tenants SET status='active',updated_at=clock_timestamp() WHERE id='${TENANT_B}'" >/dev/null

# Two requests carrying the same old cookie must serialize on the session
# row. The winner commits one rotation; the waiter rechecks the now-revoked
# token after its lock wait and is denied instead of rotating a second time.
readonly CONCURRENT_SWITCH_SESSION_ID='3c000000-0000-0000-0000-000000000001'
readonly CONCURRENT_SWITCH_OLD_HASH="$(printf 'c1%.0s' {1..32})"
readonly CONCURRENT_SWITCH_OLD_CSRF="$(printf 'c2%.0s' {1..32})"
readonly CONCURRENT_SWITCH_NEW_HASH="$(printf 'c3%.0s' {1..32})"
readonly CONCURRENT_SWITCH_NEW_CSRF="$(printf 'c4%.0s' {1..32})"
readonly CONCURRENT_SWITCH_ROTATED_HASH="$(printf 'c5%.0s' {1..32})"
readonly CONCURRENT_SWITCH_ROTATED_CSRF="$(printf 'c6%.0s' {1..32})"
readonly CONCURRENT_SWITCH_KEY='tenant-switch-concurrent-0001'
readonly CONCURRENT_SWITCH_CORRELATION='4b000000-0000-0000-0000-000000000004'
readonly CONCURRENT_SWITCH_REPLAY_CORRELATION='4b000000-0000-0000-0000-000000000005'
readonly CONCURRENT_SWITCH_BODY_HASH="$(scope_body_hash "$TENANT_B")"
readonly CONCURRENT_SWITCH_HOLDER_APP='tenant-switch-concurrent-holder'
readonly CONCURRENT_SWITCH_WAITER_APP='tenant-switch-concurrent-waiter'

query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${CONCURRENT_SWITCH_SESSION_ID}','${SUBJECT_A}',decode('${CONCURRENT_SWITCH_OLD_HASH}','hex'),decode('${CONCURRENT_SWITCH_OLD_CSRF}','hex'),clock_timestamp()+interval '2 hours')" >/dev/null

concurrent_holder_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-scope-concurrent-holder.XXXXXX")"
concurrent_waiter_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-scope-concurrent-waiter.XXXXXX")"
docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" >"$concurrent_holder_log" 2>&1 <<SQL &
SET application_name = '${CONCURRENT_SWITCH_HOLDER_APP}';
BEGIN;
SELECT * FROM iam.bind_tenant_switch_idempotency(
  decode('${CONCURRENT_SWITCH_OLD_HASH}','hex'),
  '${CONCURRENT_SWITCH_KEY}',
  '${CONCURRENT_SWITCH_BODY_HASH}',
  '${TENANT_B}'
) \gset bind_
SELECT claim_state, correlation_id, response_status, response_body
FROM ops.claim_idempotency_key(
  '${CONCURRENT_SWITCH_KEY}',
  '${SCOPE_OPERATION}',
  :'bind_receipt_hash',
  '${CONCURRENT_SWITCH_CORRELATION}',
  :'bind_receipt_expires_at'::timestamptz
) \gset claim_
SELECT pg_sleep(3);
SELECT * FROM iam.switch_session_context(
  decode('${CONCURRENT_SWITCH_OLD_HASH}','hex'),
  decode('${CONCURRENT_SWITCH_NEW_HASH}','hex'),
  decode('${CONCURRENT_SWITCH_NEW_CSRF}','hex'),
  '${TENANT_B}'
) \gset switched_
SELECT ops.complete_idempotency_key(
  '${CONCURRENT_SWITCH_KEY}',
  '${SCOPE_OPERATION}',
  :'bind_receipt_hash',
  200,
  jsonb_build_object(
    'active_tenant_id', :'bind_active_tenant_id',
    'active_workspace_id', :'bind_active_workspace_id',
    'session_generation', (:'bind_generation'::bigint + 1),
    'session_expires_at', :'bind_session_expires_at'
  )
) \gset completed_
SELECT * FROM iam.finish_tenant_switch_idempotency(
  decode('${CONCURRENT_SWITCH_NEW_HASH}','hex'),
  '${CONCURRENT_SWITCH_KEY}',
  '${CONCURRENT_SWITCH_BODY_HASH}'
) \gset finished_
SELECT 'holder:' || :'bind_mapping_state' || ':' || :'claim_claim_state' || ':' || :'switched_session_id' || ':' || :'finished_finished';
COMMIT;
SQL
concurrent_holder_pid=$!

holder_sleep_seen='0'
for _ in $(seq 1 60); do
  if [[ "$(query_as postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name='${CONCURRENT_SWITCH_HOLDER_APP}' AND wait_event='PgSleep'")" == '1' ]]; then
    holder_sleep_seen='1'
    break
  fi
  sleep 0.1
done
[[ "$holder_sleep_seen" == '1' ]] || { cat "$concurrent_holder_log" >&2; fail 'concurrent switch holder never acquired the session lock'; }

set +e
docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" >"$concurrent_waiter_log" 2>&1 <<SQL &
SET application_name = '${CONCURRENT_SWITCH_WAITER_APP}';
BEGIN;
SELECT * FROM iam.bind_tenant_switch_idempotency(
  decode('${CONCURRENT_SWITCH_OLD_HASH}','hex'),
  '${CONCURRENT_SWITCH_KEY}',
  '${CONCURRENT_SWITCH_BODY_HASH}',
  '${TENANT_B}'
) \gset bind_
COMMIT;
SQL
concurrent_waiter_pid=$!
set -e

waiter_lock_seen='0'
for _ in $(seq 1 60); do
  if [[ "$(query_as postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name='${CONCURRENT_SWITCH_WAITER_APP}' AND wait_event_type='Lock'")" == '1' ]]; then
    waiter_lock_seen='1'
    break
  fi
  sleep 0.1
done
[[ "$waiter_lock_seen" == '1' ]] || { cat "$concurrent_waiter_log" >&2; fail 'concurrent switch waiter did not wait on the session lock'; }

if wait "$concurrent_holder_pid"; then
  concurrent_holder_result="$(tail -n 1 "$concurrent_holder_log")"
else
  cat "$concurrent_holder_log" >&2
  rm -f "$concurrent_holder_log" "$concurrent_waiter_log"
  fail 'concurrent switch holder failed'
fi
expect_equals "holder:claimed:claimed:${CONCURRENT_SWITCH_SESSION_ID}:t" "$concurrent_holder_result" 'concurrent switch winner did not commit exactly once'

set +e
wait "$concurrent_waiter_pid"
concurrent_waiter_exit=$?
set -e
[[ "$concurrent_waiter_exit" -ne 0 ]] || { cat "$concurrent_waiter_log" >&2; rm -f "$concurrent_holder_log" "$concurrent_waiter_log"; fail 'concurrent old-cookie waiter unexpectedly committed'; }
grep -q 'active session unavailable' "$concurrent_waiter_log" || { cat "$concurrent_waiter_log" >&2; rm -f "$concurrent_holder_log" "$concurrent_waiter_log"; fail 'concurrent waiter did not fail as an unauthorized old token'; }
rm -f "$concurrent_holder_log" "$concurrent_waiter_log"

expect_equals '0' "$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SWITCH_OLD_HASH}','hex'))")" 'concurrent winner left the old cookie active'
expect_equals '1' "$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SWITCH_NEW_HASH}','hex'))")" 'concurrent winner did not create one replacement session'
expect_equals '2' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${CONCURRENT_SWITCH_SESSION_ID}'")" 'concurrent old-cookie requests advanced generation more than once'

# The current replacement cookie replays the immutable outcome without a
# second rotation, while a later generation makes the old key stale.
concurrent_replay="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${CONCURRENT_SWITCH_NEW_HASH}','hex'),'${CONCURRENT_SWITCH_KEY}','${CONCURRENT_SWITCH_BODY_HASH}','${TENANT_B}') \\gset bind_ SELECT claim_state || ':' || correlation_id FROM ops.claim_idempotency_key('${CONCURRENT_SWITCH_KEY}','${SCOPE_OPERATION}',:'bind_receipt_hash','${CONCURRENT_SWITCH_REPLAY_CORRELATION}',:'bind_receipt_expires_at'::timestamptz); COMMIT;" | tail -n 1)"
expect_equals "replay:${CONCURRENT_SWITCH_CORRELATION}" "$concurrent_replay" 'current-cookie retry did not replay the original correlation'
expect_equals '2' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${CONCURRENT_SWITCH_SESSION_ID}'")" 'current-cookie retry rotated the session a second time'

query_as "$RUNTIME_ROLE" "SELECT * FROM iam.rotate_session(decode('${CONCURRENT_SWITCH_NEW_HASH}','hex'),decode('${CONCURRENT_SWITCH_ROTATED_HASH}','hex'),decode('${CONCURRENT_SWITCH_ROTATED_CSRF}','hex'))" >/dev/null
expect_equals '3' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${CONCURRENT_SWITCH_SESSION_ID}'")" 'later rotation did not advance the concurrent session generation'
expect_equals 'stale' "$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT mapping_state FROM iam.bind_tenant_switch_idempotency(decode('${CONCURRENT_SWITCH_ROTATED_HASH}','hex'),'${CONCURRENT_SWITCH_KEY}','${CONCURRENT_SWITCH_BODY_HASH}','${TENANT_B}'); ROLLBACK;" | tail -n 1)" 'later generation replayed the concurrent historical key'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.bind_tenant_switch_idempotency(decode('${CONCURRENT_SWITCH_NEW_HASH}','hex'),'${CONCURRENT_SWITCH_KEY}','${CONCURRENT_SWITCH_BODY_HASH}','${TENANT_B}')" 'pre-rotation concurrent cookie remained active after strict invalidation'

printf 'dbtest: stable tenant-switch scope, paired receipt, strict replay and generation invalidation passed\n'

#!/usr/bin/env bash
set -euo pipefail

readonly GENERATION_SESSION='3a000000-0000-0000-0000-000000000001'
readonly GENERATION_ROTATE_WAIT='3a000000-0000-0000-0000-000000000002'
readonly GENERATION_SWITCH_WAIT='3a000000-0000-0000-0000-000000000003'

query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${GENERATION_SESSION}', '${SUBJECT_A}', decode(repeat('c1',32),'hex'), decode(repeat('d1',32),'hex'), now() + interval '2 hours')" >/dev/null
expect_equals '1' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${GENERATION_SESSION}'")" 'new session has incorrect generation'

query_as "$RUNTIME_ROLE" "SELECT * FROM iam.rotate_session(decode(repeat('c1',32),'hex'),decode(repeat('c2',32),'hex'),decode(repeat('d2',32),'hex'))" >/dev/null
expect_equals '2' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${GENERATION_SESSION}'")" 'rotation did not advance generation exactly once'
expect_equals '0' "$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode(repeat('c1',32),'hex'))")" 'generation rotation left old token active'

query_as "$RUNTIME_ROLE" "BEGIN; SELECT * FROM iam.rotate_session(decode(repeat('c2',32),'hex'),decode(repeat('c3',32),'hex'),decode(repeat('d3',32),'hex')); ROLLBACK" >/dev/null
expect_equals '2' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${GENERATION_SESSION}'")" 'rollback advanced generation'
expect_equals '1' "$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode(repeat('c2',32),'hex'))")" 'rollback invalidated current session'

query_as "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode(repeat('c2',32),'hex'),decode(repeat('c4',32),'hex'),decode(repeat('d4',32),'hex'),'${TENANT_B}')" >/dev/null
expect_equals "3:${TENANT_B}:${WORKSPACE_B}" "$(query_as postgres "SELECT generation::text || ':' || active_tenant_id::text || ':' || active_workspace_id::text FROM iam.sessions WHERE id='${GENERATION_SESSION}'")" 'switch did not advance generation with authoritative context'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode(repeat('c4',32),'hex'),decode(repeat('c5',32),'hex'),decode(repeat('d5',32),'hex'),'00000000-0000-0000-0000-00000000ffff')" 'unauthorized switch accepted'
expect_equals '3' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${GENERATION_SESSION}'")" 'denied switch advanced generation'
expect_failure postgres "UPDATE iam.sessions SET generation=1 WHERE id='${GENERATION_SESSION}'" 'session generation could move backwards'
expect_failure "$RUNTIME_ROLE" 'SELECT generation FROM iam.sessions' 'generation exposed session-table access'
query_as "$RUNTIME_ROLE" "SELECT iam.revoke_session(decode(repeat('c4',32),'hex'))" >/dev/null
expect_equals '0' "$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode(repeat('c4',32),'hex'))")" 'logout left generation active'

# Seed a session-level tenant deliberately. BEGIN alone does not hide these rows.
seeded_context="$(query_as "$RUNTIME_ROLE" "SELECT set_config('app.tenant_id','${TENANT_A}',false); BEGIN; SELECT set_config('app.tenant_id','',true); SELECT count(*) FROM iam.workspaces; ROLLBACK" | tail -n 1)"
expect_equals '0' "$seeded_context" 'explicit unscoped setup did not hide inherited tenant rows'

# The holder changes expiry while owning the row lock. The waiter starts before
# expiry, waits past it, then must evaluate current time on the locked row.
generation_expiry_wait() {
  local session_id="$1" token_byte="$2" next_byte="$3" csrf_byte="$4" operation="$5"
  local app_name="generation-expiry-${operation}" holder_pid holder_log waiter_result
  query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${session_id}','${SUBJECT_A}',decode(repeat('${token_byte}',32),'hex'),decode(repeat('da',32),'hex'),now()+interval '1 hour')" >/dev/null
  holder_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-generation-holder.XXXXXX")"
  docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" >"$holder_log" 2>&1 <<SQL &
SET application_name = '${app_name}';
BEGIN;
UPDATE iam.sessions SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id='${session_id}';
SELECT pg_sleep(4);
COMMIT;
SQL
  holder_pid=$!
  local ready='0'
  for _ in $(seq 1 100); do
    ready="$(query_as postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name='${app_name}' AND wait_event='PgSleep'")"
    [[ "$ready" == '1' ]] && break
    sleep 0.02
  done
  [[ "$ready" == '1' ]] || fail 'expiry holder never acquired session lock'
  if [[ "$operation" == 'rotate' ]]; then
    waiter_result="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.rotate_session(decode(repeat('${token_byte}',32),'hex'),decode(repeat('${next_byte}',32),'hex'),decode(repeat('${csrf_byte}',32),'hex'))")"
    expect_equals '0' "$waiter_result" 'rotation accepted a session expired during lock wait'
  else
    expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.switch_session_context(decode(repeat('${token_byte}',32),'hex'),decode(repeat('${next_byte}',32),'hex'),decode(repeat('${csrf_byte}',32),'hex'),'${TENANT_B}')" 'switch accepted a session expired during lock wait'
  fi
  if ! wait "$holder_pid"; then
    cat "$holder_log" >&2
    fail 'expiry holder failed'
  fi
  rm -f "$holder_log"
  expect_equals '1' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${session_id}'")" 'expired lock waiter mutated generation'
  expect_equals "$token_byte" "$(query_as postgres "SELECT left(encode(session_token_hash,'hex'),2) FROM iam.sessions WHERE id='${session_id}'")" 'expired lock waiter rotated credentials'
}

generation_expiry_wait "$GENERATION_ROTATE_WAIT" 'e1' 'e2' 'f2' 'rotate'
generation_expiry_wait "$GENERATION_SWITCH_WAIT" 'e3' 'e4' 'f4' 'switch'

printf 'dbtest: session generation, rollback, strict invalidation and lock-wait expiry passed\n'

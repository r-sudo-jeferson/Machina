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

# Authorization rows are locked after the session row. These cases deliberately
# keep one of those locks until the waiter must either observe a concurrent
# revocation/suspension or cross the session's absolute expiry. The waiter is
# required to be visible in pg_stat_activity waiting on a row lock; otherwise a
# fast failure could make this test pass without exercising the linearization
# boundary.
authorization_lock_wait() {
  local session_id="$1" token_hex="$2" next_hex="$3" csrf_hex="$4"
  local app_name="$5" lock_sql="$6" expected="$7" expiry="$8"
  local holder_log waiter_log holder_pid waiter_pid waiter_ready waiter_status

  query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${session_id}','${SUBJECT_A}',decode('${token_hex}','hex'),decode('ab${token_hex:2}','hex'),now()+interval '${expiry}')" >/dev/null
  holder_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-authz-holder.XXXXXX")"
  waiter_log="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-authz-waiter.XXXXXX")"

  docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" >"$holder_log" 2>&1 <<SQL &
SET application_name = '${app_name}-holder';
BEGIN;
${lock_sql}
SELECT pg_sleep(4);
COMMIT;
SQL
  holder_pid=$!

  local holder_ready='0'
  for _ in $(seq 1 200); do
    holder_ready="$(query_as postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name='${app_name}-holder' AND wait_event='PgSleep'")"
    [[ "$holder_ready" == '1' ]] && break
    sleep 0.02
  done
  [[ "$holder_ready" == '1' ]] || { cat "$holder_log" >&2; fail "${app_name}: authorization-lock holder never reached sleep"; }

  set +e
  docker exec -i "$CONTAINER" env PGAPPNAME="${app_name}-waiter" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" \
    -c "SELECT * FROM iam.switch_session_context(decode('${token_hex}', 'hex'), decode('${next_hex}', 'hex'), decode('${csrf_hex}', 'hex'), '${TENANT_B}')" \
    >"$waiter_log" 2>&1 &
  waiter_pid=$!
  set -e

  waiter_ready='0'
  for _ in $(seq 1 250); do
    waiter_status="$(query_as postgres "SELECT COALESCE(wait_event_type,'') || ':' || COALESCE(wait_event,'') FROM pg_stat_activity WHERE application_name='${app_name}-waiter' AND state='active' LIMIT 1")"
    if [[ "$waiter_status" == Lock:* ]]; then
      waiter_ready='1'
      break
    fi
    if ! kill -0 "$waiter_pid" 2>/dev/null; then
      break
    fi
    sleep 0.02
  done
  [[ "$waiter_ready" == '1' ]] || { cat "$waiter_log" >&2; fail "${app_name}: switch did not wait on the authorization row lock"; }

  if wait "$waiter_pid"; then
    cat "$waiter_log" >&2
    fail "${app_name}: switch unexpectedly succeeded"
  fi
  if [[ "$expected" == 'expiry' ]]; then
    grep -q 'active session unavailable' "$waiter_log" || { cat "$waiter_log" >&2; fail "${app_name}: expiry rejection did not identify the inactive session"; }
  else
    grep -q 'requested context is unavailable' "$waiter_log" || { cat "$waiter_log" >&2; fail "${app_name}: authorization rejection did not fail closed"; }
  fi

  if ! wait "$holder_pid"; then
    cat "$holder_log" >&2
    fail "${app_name}: authorization-lock holder failed"
  fi
  rm -f "$holder_log" "$waiter_log"
  expect_equals "$token_hex" "$(query_as postgres "SELECT encode(session_token_hash, 'hex') FROM iam.sessions WHERE id='${session_id}'")" "${app_name}: failed switch mutated the original session"
  expect_equals '1' "$(query_as postgres "SELECT generation FROM iam.sessions WHERE id='${session_id}'")" "${app_name}: failed switch advanced generation"
}

# A tenant lock wait can cross the absolute session expiry. This specifically
# exercises the second clock_timestamp() check after tenant authorization.
authorization_lock_wait \
  '3a000000-0000-0000-0000-000000000004' \
  'a401a401a401a401a401a401a401a401a401a401a401a401a401a401a401a401' \
  'a402a402a402a402a402a402a402a402a402a402a402a402a402a402a402a402' \
  'a403a403a403a403a403a403a403a403a403a403a403a403a403a403a403a403' \
  'generation-tenant-expiry' \
  "SELECT 1 FROM iam.tenants WHERE id='${TENANT_B}' FOR UPDATE;" \
  'expiry' '2 seconds'

# A concurrent suspension must linearize before the switch can mutate the
# session. The waiter sees the committed suspended state after the lock opens.
authorization_lock_wait \
  '3a000000-0000-0000-0000-000000000005' \
  'a501a501a501a501a501a501a501a501a501a501a501a501a501a501a501a501' \
  'a502a502a502a502a502a502a502a502a502a502a502a502a502a502a502a502' \
  'a503a503a503a503a503a503a503a503a503a503a503a503a503a503a503a503' \
  'generation-tenant-suspension' \
  "UPDATE iam.tenants SET status='suspended', updated_at=clock_timestamp() WHERE id='${TENANT_B}';" \
  'authorization' '1 hour'
query_as postgres "UPDATE iam.tenants SET status='active', updated_at=clock_timestamp() WHERE id='${TENANT_B}'" >/dev/null

# A concurrent membership revocation is serialized by the membership FOR
# SHARE lock and must deny the switch without rotating credentials.
authorization_lock_wait \
  '3a000000-0000-0000-0000-000000000006' \
  'a601a601a601a601a601a601a601a601a601a601a601a601a601a601a601a601' \
  'a602a602a602a602a602a602a602a602a602a602a602a602a602a602a602a602' \
  'a603a603a603a603a603a603a603a603a603a603a603a603a603a603a603a603' \
  'generation-membership-revocation' \
  "UPDATE iam.memberships SET status='revoked', updated_at=clock_timestamp() WHERE tenant_id='${TENANT_B}' AND subject_id='${SUBJECT_A}';" \
  'authorization' '1 hour'
query_as postgres "UPDATE iam.memberships SET status='active', updated_at=clock_timestamp() WHERE tenant_id='${TENANT_B}' AND subject_id='${SUBJECT_A}'" >/dev/null

# A workspace lock is the final authorization lock. Crossing expiry here must
# still be rejected by the post-lock session check, even though tenant and
# membership authorization already succeeded.
authorization_lock_wait \
  '3a000000-0000-0000-0000-000000000007' \
  'a701a701a701a701a701a701a701a701a701a701a701a701a701a701a701a701' \
  'a702a702a702a702a702a702a702a702a702a702a702a702a702a702a702a702' \
  'a703a703a703a703a703a703a703a703a703a703a703a703a703a703a703a703' \
  'generation-workspace-expiry' \
  "SELECT 1 FROM iam.workspaces WHERE tenant_id='${TENANT_B}' AND id='${WORKSPACE_B}' FOR UPDATE;" \
  'expiry' '2 seconds'

printf 'dbtest: session generation, rollback, strict invalidation and lock-wait expiry passed\n'

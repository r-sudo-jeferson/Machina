#!/usr/bin/env bash

readonly ROTATE_SESSION_ID='30000000-0000-0000-0000-0000000000a1'
readonly ROTATE_OLD_HASH="$(printf '91%.0s' {1..32})"
readonly ROTATE_OLD_CSRF="$(printf '92%.0s' {1..32})"
readonly ROTATE_NEW_HASH="$(printf '93%.0s' {1..32})"
readonly ROTATE_NEW_CSRF="$(printf '94%.0s' {1..32})"
readonly ROTATE_RACE_ID='30000000-0000-0000-0000-0000000000b2'
readonly ROTATE_RACE_OLD_HASH="$(printf 'a5%.0s' {1..32})"
readonly ROTATE_RACE_OLD_CSRF="$(printf 'a6%.0s' {1..32})"
readonly ROTATE_RACE_NEW_HASH_A="$(printf 'b5%.0s' {1..32})"
readonly ROTATE_RACE_NEW_CSRF_A="$(printf 'b6%.0s' {1..32})"
readonly ROTATE_RACE_NEW_HASH_B="$(printf 'c5%.0s' {1..32})"
readonly ROTATE_RACE_NEW_CSRF_B="$(printf 'c6%.0s' {1..32})"
readonly ROTATE_REVOKED_ID='30000000-0000-0000-0000-0000000000c3'
readonly ROTATE_REVOKED_HASH="$(printf 'd5%.0s' {1..32})"
readonly ROTATE_REVOKED_CSRF="$(printf 'd6%.0s' {1..32})"
readonly ROTATE_REVOKED_NEW_HASH="$(printf 'd7%.0s' {1..32})"
readonly ROTATE_REVOKED_NEW_CSRF="$(printf 'd8%.0s' {1..32})"
readonly ROTATE_EXPIRED_ID='30000000-0000-0000-0000-0000000000d4'
readonly ROTATE_EXPIRED_HASH="$(printf 'e5%.0s' {1..32})"
readonly ROTATE_EXPIRED_CSRF="$(printf 'e6%.0s' {1..32})"
readonly ROTATE_EXPIRED_NEW_HASH="$(printf 'e7%.0s' {1..32})"
readonly ROTATE_EXPIRED_NEW_CSRF="$(printf 'e8%.0s' {1..32})"
readonly ROTATE_REPLAY_NEW_HASH="$(printf 'f1%.0s' {1..32})"
readonly ROTATE_REPLAY_NEW_CSRF="$(printf 'f2%.0s' {1..32})"
readonly ROTATE_UNCHANGED_NEW_CSRF="$(printf 'f3%.0s' {1..32})"

query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${ROTATE_SESSION_ID}', '${SUBJECT_A}', decode('${ROTATE_OLD_HASH}','hex'), decode('${ROTATE_OLD_CSRF}','hex'), now() + interval '1 hour')" >/dev/null

before_expiry="$(query_as "$RUNTIME_ROLE" "SELECT extract(epoch FROM expires_at)::bigint FROM iam.get_active_session(decode('${ROTATE_OLD_HASH}','hex'))")"
rotated="$(query_as "$RUNTIME_ROLE" "SELECT id::text || ':' || subject_id::text || ':' || extract(epoch FROM expires_at)::bigint FROM iam.rotate_session(decode('${ROTATE_OLD_HASH}','hex'), decode('${ROTATE_NEW_HASH}','hex'), decode('${ROTATE_NEW_CSRF}','hex'))")"
expect_equals "${ROTATE_SESSION_ID}:${SUBJECT_A}:${before_expiry}" "$rotated" 'session rotation changed identity or absolute expiry'

old_active_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${ROTATE_OLD_HASH}','hex'))")"
expect_equals '0' "$old_active_count" 'old session token remained active after rotation'

new_session="$(query_as "$RUNTIME_ROLE" "SELECT id::text || ':' || subject_id::text || ':' || encode(csrf_token_hash,'hex') || ':' || extract(epoch FROM expires_at)::bigint FROM iam.get_active_session(decode('${ROTATE_NEW_HASH}','hex'))")"
expect_equals "${ROTATE_SESSION_ID}:${SUBJECT_A}:${ROTATE_NEW_CSRF}:${before_expiry}" "$new_session" 'rotated session did not expose the new token/CSRF pair with unchanged expiry'

replay_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.rotate_session(decode('${ROTATE_OLD_HASH}','hex'), decode('${ROTATE_REPLAY_NEW_HASH}','hex'), decode('${ROTATE_REPLAY_NEW_CSRF}','hex'))")"
expect_equals '0' "$replay_count" 'old session token could rotate a second time'

expect_failure "$RUNTIME_ROLE" \
  "SELECT * FROM iam.rotate_session(decode('${ROTATE_NEW_HASH}','hex'), decode('${ROTATE_NEW_HASH}','hex'), decode('${ROTATE_UNCHANGED_NEW_CSRF}','hex'))" \
  'session rotation accepted an unchanged session token hash'

query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${ROTATE_RACE_ID}', '${SUBJECT_A}', decode('${ROTATE_RACE_OLD_HASH}','hex'), decode('${ROTATE_RACE_OLD_CSRF}','hex'), now() + interval '1 hour')" >/dev/null

race_one="$(mktemp)"
race_two="$(mktemp)"
race_cleanup() {
  rm -f "$race_one" "$race_two"
}
trap race_cleanup RETURN

query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.rotate_session(decode('${ROTATE_RACE_OLD_HASH}','hex'), decode('${ROTATE_RACE_NEW_HASH_A}','hex'), decode('${ROTATE_RACE_NEW_CSRF_A}','hex'))" >"$race_one" &
race_pid_one=$!
query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.rotate_session(decode('${ROTATE_RACE_OLD_HASH}','hex'), decode('${ROTATE_RACE_NEW_HASH_B}','hex'), decode('${ROTATE_RACE_NEW_CSRF_B}','hex'))" >"$race_two" &
race_pid_two=$!
wait "$race_pid_one"
wait "$race_pid_two"

race_total=$(( $(cat "$race_one") + $(cat "$race_two") ))
expect_equals '1' "$race_total" 'concurrent session rotation did not produce exactly one winner'
race_cleanup
trap - RETURN

race_active_total="$(query_as "$RUNTIME_ROLE" "SELECT (SELECT count(*) FROM iam.get_active_session(decode('${ROTATE_RACE_NEW_HASH_A}','hex'))) + (SELECT count(*) FROM iam.get_active_session(decode('${ROTATE_RACE_NEW_HASH_B}','hex')))")"
expect_equals '1' "$race_active_total" 'concurrent session rotation produced an invalid number of active replacement tokens'

query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${ROTATE_REVOKED_ID}', '${SUBJECT_A}', decode('${ROTATE_REVOKED_HASH}','hex'), decode('${ROTATE_REVOKED_CSRF}','hex'), now() + interval '1 hour')" >/dev/null
query_as "$RUNTIME_ROLE" "SELECT iam.revoke_session(decode('${ROTATE_REVOKED_HASH}','hex'))" >/dev/null
revoked_rotation_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.rotate_session(decode('${ROTATE_REVOKED_HASH}','hex'), decode('${ROTATE_REVOKED_NEW_HASH}','hex'), decode('${ROTATE_REVOKED_NEW_CSRF}','hex'))")"
expect_equals '0' "$revoked_rotation_count" 'revoked session could be rotated back into service'

query_as postgres "INSERT INTO iam.sessions (id, subject_id, session_token_hash, csrf_token_hash, expires_at) VALUES ('${ROTATE_EXPIRED_ID}', '${SUBJECT_A}', decode('${ROTATE_EXPIRED_HASH}','hex'), decode('${ROTATE_EXPIRED_CSRF}','hex'), now() - interval '1 second')" >/dev/null
expired_rotation_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.rotate_session(decode('${ROTATE_EXPIRED_HASH}','hex'), decode('${ROTATE_EXPIRED_NEW_HASH}','hex'), decode('${ROTATE_EXPIRED_NEW_CSRF}','hex'))")"
expect_equals '0' "$expired_rotation_count" 'expired session could be rotated back into service'

#!/usr/bin/env bash

readonly TASK5_SUBJECT='10000000-0000-0000-0000-0000000000d1'
readonly TASK5_SESSION='30000000-0000-0000-0000-0000000000d1'
readonly TASK5_SESSION_HASH="$(printf '11%.0s' {1..32})"
readonly TASK5_CSRF_HASH="$(printf '22%.0s' {1..32})"

expect_failure "$RUNTIME_ROLE" \
  'SELECT count(*) FROM iam.subjects' \
  'runtime gained direct read access to global subjects'

expect_failure "$RUNTIME_ROLE" \
  'SELECT count(*) FROM iam.sessions' \
  'runtime gained direct read access to global sessions'

subject_id="$(query_as "$RUNTIME_ROLE" "SELECT iam.upsert_subject('${TASK5_SUBJECT}'::uuid, 'https://issuer.example.test|task5-subject', 'Task 5 Subject')::text")"
expect_equals "$TASK5_SUBJECT" "$subject_id" 'narrow subject upsert did not return the expected subject id'

session_id="$(query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${TASK5_SESSION}'::uuid, '${TASK5_SUBJECT}'::uuid, decode('${TASK5_SESSION_HASH}','hex'), decode('${TASK5_CSRF_HASH}','hex'), now() + interval '30 minutes')::text")"
expect_equals "$TASK5_SESSION" "$session_id" 'narrow session creation did not return the expected session id'

active_session="$(query_as "$RUNTIME_ROLE" "SELECT id::text || ':' || subject_id::text FROM iam.get_active_session(decode('${TASK5_SESSION_HASH}','hex'))")"
expect_equals "${TASK5_SESSION}:${TASK5_SUBJECT}" "$active_session" 'active session lookup did not resolve through the narrow boundary'

query_as "$RUNTIME_ROLE" "SELECT iam.revoke_session(decode('${TASK5_SESSION_HASH}','hex'))" >/dev/null

revoked_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${TASK5_SESSION_HASH}','hex'))")"
expect_equals '0' "$revoked_count" 'revoked session remained active'

query_as "$RUNTIME_ROLE" "SELECT iam.revoke_session(decode('${TASK5_SESSION_HASH}','hex'))" >/dev/null

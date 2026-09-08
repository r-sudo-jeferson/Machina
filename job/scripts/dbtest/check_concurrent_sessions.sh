#!/usr/bin/env bash

readonly CONCURRENT_SESSION_A_ID='39000000-0000-0000-0000-00000000ca01'
readonly CONCURRENT_SESSION_B_ID='39000000-0000-0000-0000-00000000ca02'
readonly CONCURRENT_SESSION_A_HASH="$(printf '91%.0s' {1..32})"
readonly CONCURRENT_SESSION_A_CSRF="$(printf '92%.0s' {1..32})"
readonly CONCURRENT_SESSION_A_ROTATED_HASH="$(printf '93%.0s' {1..32})"
readonly CONCURRENT_SESSION_A_ROTATED_CSRF="$(printf '94%.0s' {1..32})"
readonly CONCURRENT_SESSION_B_HASH="$(printf '95%.0s' {1..32})"
readonly CONCURRENT_SESSION_B_CSRF="$(printf '96%.0s' {1..32})"

query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${CONCURRENT_SESSION_A_ID}', '${SUBJECT_A}', decode('${CONCURRENT_SESSION_A_HASH}','hex'), decode('${CONCURRENT_SESSION_A_CSRF}','hex'), now() + interval '1 hour')" >/dev/null
query_as "$RUNTIME_ROLE" "SELECT iam.create_session('${CONCURRENT_SESSION_B_ID}', '${SUBJECT_A}', decode('${CONCURRENT_SESSION_B_HASH}','hex'), decode('${CONCURRENT_SESSION_B_CSRF}','hex'), now() + interval '1 hour')" >/dev/null

initial_active="$(query_as "$RUNTIME_ROLE" "SELECT (SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_A_HASH}','hex'))) + (SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_B_HASH}','hex')))")"
expect_equals '2' "$initial_active" 'same subject could not hold two independent active sessions'

rotated_a="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.rotate_session(decode('${CONCURRENT_SESSION_A_HASH}','hex'), decode('${CONCURRENT_SESSION_A_ROTATED_HASH}','hex'), decode('${CONCURRENT_SESSION_A_ROTATED_CSRF}','hex'))")"
expect_equals '1' "$rotated_a" 'rotating concurrent session A did not produce one replacement'

old_a_active="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_A_HASH}','hex'))")"
expect_equals '0' "$old_a_active" 'old token for concurrent session A remained active after rotation'

rotated_a_active="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_A_ROTATED_HASH}','hex'))")"
expect_equals '1' "$rotated_a_active" 'rotated concurrent session A is not active'

session_b_after_a_rotation="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_B_HASH}','hex'))")"
expect_equals '1' "$session_b_after_a_rotation" 'rotating session A invalidated independent session B'

query_as "$RUNTIME_ROLE" "SELECT iam.revoke_session(decode('${CONCURRENT_SESSION_A_ROTATED_HASH}','hex'))" >/dev/null

session_a_after_revoke="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_A_ROTATED_HASH}','hex'))")"
expect_equals '0' "$session_a_after_revoke" 'revoked concurrent session A remained active'

session_b_after_a_revoke="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_B_HASH}','hex'))")"
expect_equals '1' "$session_b_after_a_revoke" 'revoking session A invalidated independent session B'

query_as "$RUNTIME_ROLE" "SELECT iam.revoke_session(decode('${CONCURRENT_SESSION_B_HASH}','hex'))" >/dev/null

session_b_after_revoke="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.get_active_session(decode('${CONCURRENT_SESSION_B_HASH}','hex'))")"
expect_equals '0' "$session_b_after_revoke" 'revoked concurrent session B remained active'

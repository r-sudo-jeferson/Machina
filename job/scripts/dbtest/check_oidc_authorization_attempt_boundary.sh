#!/usr/bin/env bash

readonly OIDC_STATE_HASH="$(printf 'a1%.0s' {1..32})"
readonly OIDC_NONCE_HASH="$(printf 'b2%.0s' {1..32})"
readonly OIDC_RACE_STATE_HASH="$(printf 'c3%.0s' {1..32})"
readonly OIDC_RACE_NONCE_HASH="$(printf 'd4%.0s' {1..32})"
readonly OIDC_VERIFIER='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234'
readonly OIDC_REDIRECT='https://app.example.test/auth/callback'

expect_failure "$RUNTIME_ROLE" \
  'SELECT count(*) FROM iam.oidc_authorization_attempts' \
  'runtime gained direct read access to OIDC authorization attempts'

expect_failure "$RUNTIME_ROLE" \
  "INSERT INTO iam.oidc_authorization_attempts (state_hash, nonce_hash, pkce_verifier, redirect_uri, expires_at) VALUES (decode('${OIDC_STATE_HASH}','hex'), decode('${OIDC_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() + interval '5 minutes')" \
  'runtime gained direct insert access to OIDC authorization attempts'

query_as "$RUNTIME_ROLE" "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'), decode('${OIDC_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() + interval '5 minutes')" >/dev/null

expect_failure "$RUNTIME_ROLE" \
  "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'), decode('${OIDC_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() + interval '5 minutes')" \
  'duplicate OIDC state was accepted'

consumed="$(query_as "$RUNTIME_ROLE" "SELECT encode(nonce_hash,'hex') || ':' || pkce_verifier || ':' || redirect_uri FROM iam.consume_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'))")"
expect_equals "${OIDC_NONCE_HASH}:${OIDC_VERIFIER}:${OIDC_REDIRECT}" "$consumed" 'OIDC authorization attempt did not return the expected server-side material'

replay_count="$(query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.consume_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'))")"
expect_equals '0' "$replay_count" 'consumed OIDC authorization state was reusable'

expect_failure "$RUNTIME_ROLE" \
  "SELECT iam.create_oidc_authorization_attempt(decode('aa','hex'), decode('${OIDC_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() + interval '5 minutes')" \
  'OIDC authorization attempt accepted a malformed state hash'

expect_failure "$RUNTIME_ROLE" \
  "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'), decode('bb','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() + interval '5 minutes')" \
  'OIDC authorization attempt accepted a malformed nonce hash'

expect_failure "$RUNTIME_ROLE" \
  "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'), decode('${OIDC_NONCE_HASH}','hex'), 'too-short', '${OIDC_REDIRECT}', now() + interval '5 minutes')" \
  'OIDC authorization attempt accepted a malformed PKCE verifier'

expect_failure "$RUNTIME_ROLE" \
  "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'), decode('${OIDC_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '', now() + interval '5 minutes')" \
  'OIDC authorization attempt accepted an empty redirect URI'

expect_failure "$RUNTIME_ROLE" \
  "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'), decode('${OIDC_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() - interval '1 second')" \
  'OIDC authorization attempt accepted an expired lifetime'

expect_failure "$RUNTIME_ROLE" \
  "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_STATE_HASH}','hex'), decode('${OIDC_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() + interval '16 minutes')" \
  'OIDC authorization attempt accepted an excessive lifetime'

query_as "$RUNTIME_ROLE" "SELECT iam.create_oidc_authorization_attempt(decode('${OIDC_RACE_STATE_HASH}','hex'), decode('${OIDC_RACE_NONCE_HASH}','hex'), '${OIDC_VERIFIER}', '${OIDC_REDIRECT}', now() + interval '5 minutes')" >/dev/null

race_one="$(mktemp)"
race_two="$(mktemp)"
race_cleanup() {
  rm -f "$race_one" "$race_two"
}
trap race_cleanup RETURN

query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.consume_oidc_authorization_attempt(decode('${OIDC_RACE_STATE_HASH}','hex'))" >"$race_one" &
race_pid_one=$!
query_as "$RUNTIME_ROLE" "SELECT count(*) FROM iam.consume_oidc_authorization_attempt(decode('${OIDC_RACE_STATE_HASH}','hex'))" >"$race_two" &
race_pid_two=$!
wait "$race_pid_one"
wait "$race_pid_two"

race_total=$(( $(cat "$race_one") + $(cat "$race_two") ))
expect_equals '1' "$race_total" 'concurrent OIDC callback consumption did not produce exactly one winner'
race_cleanup
trap - RETURN

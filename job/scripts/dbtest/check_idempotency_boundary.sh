#!/usr/bin/env bash
set -euo pipefail

readonly IDEMPOTENCY_KEY='tenant-switch-key-0001'
readonly IDEMPOTENCY_KEY_EXPIRED='tenant-switch-key-expired-0001'
readonly IDEMPOTENCY_KEY_CONCURRENT='tenant-switch-key-concurrent-0001'
readonly REQUEST_HASH_A='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly REQUEST_HASH_B='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly REQUEST_HASH_CONCURRENT='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
readonly CORRELATION_A='4a000000-0000-0000-0000-000000000001'
readonly CORRELATION_B='4a000000-0000-0000-0000-000000000002'
readonly CORRELATION_CONCURRENT_A='4a000000-0000-0000-0000-000000000003'
readonly CORRELATION_CONCURRENT_B='4a000000-0000-0000-0000-000000000004'

claim_state="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT claim_state FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY}','tenant.switch','${REQUEST_HASH_A}','${CORRELATION_A}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"
expect_equals 'claimed' "$claim_state" 'first idempotency claim was not acquired'

complete_result="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT ops.complete_idempotency_key('${IDEMPOTENCY_KEY}','tenant.switch','${REQUEST_HASH_A}',200,'{\"active_tenant_id\":\"${TENANT_A}\"}'::jsonb); COMMIT;" | tail -n 1)"
expect_equals 't' "$complete_result" 'idempotency completion did not persist the response'

replay_result="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT claim_state || ':' || response_status::text || ':' || (response_body->>'active_tenant_id') || ':' || correlation_id::text FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY}','tenant.switch','${REQUEST_HASH_A}','${CORRELATION_B}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"
expect_equals "replay:200:${TENANT_A}:${CORRELATION_A}" "$replay_result" 'same idempotency key/request did not replay the original completed response and correlation'

conflict_result="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT claim_state FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY}','tenant.switch','${REQUEST_HASH_B}','${CORRELATION_B}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"
expect_equals 'conflict' "$conflict_result" 'same idempotency key with a different request hash did not conflict'

operation_conflict="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT claim_state FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY}','tenant.create','${REQUEST_HASH_A}','${CORRELATION_B}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"
expect_equals 'conflict' "$operation_conflict" 'same idempotency key reused for a different operation did not conflict'

tenant_b_claim="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_B}',true); SELECT claim_state FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY}','tenant.switch','${REQUEST_HASH_B}','${CORRELATION_B}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"
expect_equals 'claimed' "$tenant_b_claim" 'same idempotency key was not isolated by tenant'

expired_claim="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT claim_state FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY_EXPIRED}','tenant.switch','${REQUEST_HASH_A}','${CORRELATION_A}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"
expect_equals 'claimed' "$expired_claim" 'expiring idempotency fixture was not claimed'
query_as postgres "UPDATE ops.idempotency_keys SET expires_at = now() - interval '1 second' WHERE tenant_id='${TENANT_A}' AND idempotency_key='${IDEMPOTENCY_KEY_EXPIRED}'" >/dev/null
expired_reuse="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT claim_state || ':' || correlation_id::text FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY_EXPIRED}','tenant.switch','${REQUEST_HASH_B}','${CORRELATION_B}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"
expect_equals "claimed:${CORRELATION_B}" "$expired_reuse" 'expired idempotency key was not safely reset for a new request'

expect_failure "$RUNTIME_ROLE" "SELECT * FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY}','tenant.switch','${REQUEST_HASH_A}','${CORRELATION_A}',now() + interval '1 hour')" 'idempotency claim succeeded without transaction-local tenant context'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM ops.idempotency_keys" 'runtime retained direct SELECT on idempotency storage'
expect_failure "$RUNTIME_ROLE" "INSERT INTO ops.idempotency_keys (tenant_id,idempotency_key,operation,request_hash,correlation_id,expires_at) VALUES ('${TENANT_A}','direct-write-key-0001','tenant.switch','${REQUEST_HASH_A}','${CORRELATION_A}',now() + interval '1 hour')" 'runtime retained direct INSERT on idempotency storage'

expect_failure "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT ops.complete_idempotency_key('${IDEMPOTENCY_KEY}','tenant.switch','${REQUEST_HASH_B}',200,'{}'::jsonb); COMMIT;" 'idempotency completion accepted a mismatched request hash'

first_out="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-idempotency-first.XXXXXX")"
first_err="$(mktemp "${RUNNER_TEMP:-/tmp}/machina-idempotency-first-err.XXXXXX")"
docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" >"$first_out" 2>"$first_err" <<SQL &
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
SELECT claim_state || ':' || correlation_id::text
FROM ops.claim_idempotency_key(
  '${IDEMPOTENCY_KEY_CONCURRENT}',
  'tenant.switch',
  '${REQUEST_HASH_CONCURRENT}',
  '${CORRELATION_CONCURRENT_A}',
  now() + interval '1 hour'
);
SELECT pg_sleep(2);
SELECT ops.complete_idempotency_key(
  '${IDEMPOTENCY_KEY_CONCURRENT}',
  'tenant.switch',
  '${REQUEST_HASH_CONCURRENT}',
  200,
  '{"winner":"first"}'::jsonb
);
COMMIT;
SQL
first_pid=$!
sleep 0.25

second_result="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT claim_state || ':' || response_status::text || ':' || (response_body->>'winner') || ':' || correlation_id::text FROM ops.claim_idempotency_key('${IDEMPOTENCY_KEY_CONCURRENT}','tenant.switch','${REQUEST_HASH_CONCURRENT}','${CORRELATION_CONCURRENT_B}',now() + interval '1 hour'); COMMIT;" | tail -n 1)"

if ! wait "$first_pid"; then
  cat "$first_err" >&2
  rm -f "$first_out" "$first_err"
  fail 'first concurrent idempotency transaction failed'
fi
first_claim="$(grep '^claimed:' "$first_out" | tail -n 1 || true)"
rm -f "$first_out" "$first_err"
expect_equals "claimed:${CORRELATION_CONCURRENT_A}" "$first_claim" 'first concurrent transaction did not acquire the only claim'
expect_equals "replay:200:first:${CORRELATION_CONCURRENT_A}" "$second_result" 'concurrent retry did not wait for atomic completion and replay the winner response'

concurrent_row_count="$(query_as postgres "SELECT count(*) FROM ops.idempotency_keys WHERE tenant_id='${TENANT_A}' AND idempotency_key='${IDEMPOTENCY_KEY_CONCURRENT}'")"
expect_equals '1' "$concurrent_row_count" 'concurrent idempotency race created more than one durable key row'

printf 'dbtest: tenant-scoped idempotency claim/replay/complete and concurrency boundary passed\n'

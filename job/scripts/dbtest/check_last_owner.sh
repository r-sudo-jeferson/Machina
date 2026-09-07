#!/usr/bin/env bash

expect_failure "$RUNTIME_ROLE" \
  "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); DELETE FROM iam.memberships WHERE tenant_id='${TENANT_A}' AND subject_id='${SUBJECT_A}'; ROLLBACK;" \
  'last active owner could be deleted'

expect_failure "$RUNTIME_ROLE" \
  "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); UPDATE iam.memberships SET starter_role='member', updated_at=now() WHERE tenant_id='${TENANT_A}' AND subject_id='${SUBJECT_A}'; ROLLBACK;" \
  'last active owner could be demoted'

expect_failure "$RUNTIME_ROLE" \
  "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); UPDATE iam.memberships SET status='revoked', updated_at=now() WHERE tenant_id='${TENANT_A}' AND subject_id='${SUBJECT_A}'; ROLLBACK;" \
  'last active owner could be revoked'

owner_race_tenant='00000000-0000-0000-0000-0000000000c3'
owner_race_subject_a='10000000-0000-0000-0000-0000000000c1'
owner_race_subject_b='10000000-0000-0000-0000-0000000000c2'

query_as postgres "INSERT INTO iam.subjects (id, external_subject, display_name) VALUES ('${owner_race_subject_a}','oidc-c1','Race Owner A'),('${owner_race_subject_b}','oidc-c2','Race Owner B'); INSERT INTO iam.tenants (id,slug,display_name,status) VALUES ('${owner_race_tenant}','same-slug','Same Tenant Name','active'); INSERT INTO iam.memberships (tenant_id,subject_id,starter_role,status) VALUES ('${owner_race_tenant}','${owner_race_subject_a}','owner','active'),('${owner_race_tenant}','${owner_race_subject_b}','owner','active');" >/dev/null

owner_race_barrier="$(mktemp -d)"

run_owner_demotion_race() {
  local subject_id="$1"
  local ready_file="$2"
  local peer_ready_file="$3"

  : > "$ready_file"
  for _ in $(seq 1 500); do
    [[ -f "$peer_ready_file" ]] && break
    sleep 0.01
  done
  [[ -f "$peer_ready_file" ]] || return 98

  query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${owner_race_tenant}',true); SELECT pg_sleep(0.75); UPDATE iam.memberships SET starter_role='member', updated_at=now() WHERE tenant_id='${owner_race_tenant}' AND subject_id='${subject_id}'; SELECT pg_sleep(1.5); COMMIT;" >/dev/null
}

run_owner_demotion_race "$owner_race_subject_a" "$owner_race_barrier/a.ready" "$owner_race_barrier/b.ready" >"$owner_race_barrier/a.log" 2>&1 &
owner_race_pid_a=$!
run_owner_demotion_race "$owner_race_subject_b" "$owner_race_barrier/b.ready" "$owner_race_barrier/a.ready" >"$owner_race_barrier/b.log" 2>&1 &
owner_race_pid_b=$!

if wait "$owner_race_pid_a"; then owner_race_status_a=0; else owner_race_status_a=$?; fi
if wait "$owner_race_pid_b"; then owner_race_status_b=0; else owner_race_status_b=$?; fi

if [[ "$owner_race_status_a" -eq 0 && "$owner_race_status_b" -eq 0 ]]; then
  cat "$owner_race_barrier/a.log" "$owner_race_barrier/b.log" >&2 || true
  rm -rf "$owner_race_barrier"
  fail 'concurrent owner demotions both committed and orphaned the tenant'
fi
if [[ "$owner_race_status_a" -ne 0 && "$owner_race_status_b" -ne 0 ]]; then
  cat "$owner_race_barrier/a.log" "$owner_race_barrier/b.log" >&2 || true
  rm -rf "$owner_race_barrier"
  fail "concurrent owner demotions both failed; exactly one must remain possible (statuses ${owner_race_status_a}/${owner_race_status_b})"
fi

remaining_owner_count="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${owner_race_tenant}',true); SELECT count(*) FROM iam.memberships WHERE starter_role='owner' AND status='active'; COMMIT;" | tail -n 1)"
rm -rf "$owner_race_barrier"
expect_equals '1' "$remaining_owner_count" 'concurrent owner mutation did not preserve exactly one active owner'

#!/usr/bin/env bash
set -euo pipefail

readonly INVITE_SUBJECT_C='10000000-0000-0000-0000-0000000000c3'
readonly INVITE_SUBJECT_D='10000000-0000-0000-0000-0000000000d4'
readonly INVITE_SUBJECT_E='10000000-0000-0000-0000-0000000000e5'
readonly INVITE_SUBJECT_F='10000000-0000-0000-0000-0000000000f6'
readonly SUSPENDED_TENANT='00000000-0000-0000-0000-0000000000c3'

invitation_function="$(query_as postgres "SELECT to_regprocedure('iam.accept_invitation(bytea,uuid)') IS NOT NULL")"
expect_equals 't' "$invitation_function" 'invitation acceptance function is missing'

runtime_execute="$(query_as postgres "SELECT has_function_privilege('${RUNTIME_ROLE}','iam.accept_invitation(bytea,uuid)','EXECUTE')")"
expect_equals 't' "$runtime_execute" 'runtime role cannot execute invitation acceptance boundary'

# Runtime retains ordinary tenant-scoped invitation access only; without a
# transaction-local tenant it must not discover invitations by table scan.
expect_equals '0' "$(query_as "$RUNTIME_ROLE" 'SELECT count(*) FROM iam.invitations')" 'runtime without tenant context observed invitation rows'

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
INSERT INTO iam.subjects (id, external_subject, display_name) VALUES
  ('${INVITE_SUBJECT_C}', 'oidc-invite-c', 'Invited C'),
  ('${INVITE_SUBJECT_D}', 'oidc-invite-d', 'Invited D'),
  ('${INVITE_SUBJECT_E}', 'oidc-invite-e', 'Invited E'),
  ('${INVITE_SUBJECT_F}', 'oidc-invite-f', 'Invited F');

INSERT INTO iam.tenants (id, slug, display_name, status) VALUES
  ('${SUSPENDED_TENANT}', 'suspended-invite', 'Suspended Invite Tenant', 'suspended');

INSERT INTO iam.invitations (
  tenant_id, id, token_hash, invited_subject_id, starter_role, status,
  expires_at, created_by_subject_id
) VALUES
  ('${TENANT_A}', '30000000-0000-0000-0000-000000000011', decode(repeat('11',32),'hex'), NULL, 'member', 'pending', clock_timestamp() + interval '1 hour', '${SUBJECT_A}'),
  ('${TENANT_A}', '30000000-0000-0000-0000-000000000022', decode(repeat('22',32),'hex'), NULL, 'member', 'pending', clock_timestamp() - interval '1 second', '${SUBJECT_A}'),
  ('${TENANT_A}', '30000000-0000-0000-0000-000000000033', decode(repeat('33',32),'hex'), NULL, 'member', 'revoked', clock_timestamp() + interval '1 hour', '${SUBJECT_A}'),
  ('${TENANT_A}', '30000000-0000-0000-0000-000000000044', decode(repeat('44',32),'hex'), '${INVITE_SUBJECT_D}', 'member', 'pending', clock_timestamp() + interval '1 hour', '${SUBJECT_A}'),
  ('${SUSPENDED_TENANT}', '30000000-0000-0000-0000-000000000055', decode(repeat('55',32),'hex'), NULL, 'member', 'pending', clock_timestamp() + interval '1 hour', '${SUBJECT_A}'),
  ('${TENANT_A}', '30000000-0000-0000-0000-000000000066', decode(repeat('66',32),'hex'), '${INVITE_SUBJECT_D}', 'member', 'pending', clock_timestamp() + interval '1 hour', '${SUBJECT_A}'),
  ('${TENANT_A}', '30000000-0000-0000-0000-000000000077', decode(repeat('77',32),'hex'), '${INVITE_SUBJECT_E}', 'owner', 'pending', clock_timestamp() + interval '1 hour', '${SUBJECT_A}'),
  ('${TENANT_A}', '30000000-0000-0000-0000-000000000088', decode(repeat('88',32),'hex'), '${INVITE_SUBJECT_F}', 'member', 'pending', clock_timestamp() + interval '1 hour', '${SUBJECT_A}');

INSERT INTO iam.memberships (tenant_id, subject_id, starter_role, status) VALUES
  ('${TENANT_A}', '${INVITE_SUBJECT_D}', 'member', 'revoked'),
  ('${TENANT_A}', '${INVITE_SUBJECT_E}', 'member', 'active'),
  ('${TENANT_A}', '${INVITE_SUBJECT_F}', 'member', 'active');
SQL

accepted="$(query_as "$RUNTIME_ROLE" "SELECT tenant_id::text || ':' || subject_id::text || ':' || starter_role || ':' || status FROM iam.accept_invitation(decode(repeat('11',32),'hex'),'${INVITE_SUBJECT_C}')")"
expect_equals "${TENANT_A}:${INVITE_SUBJECT_C}:member:active" "$accepted" 'first invitation acceptance returned the wrong membership'

accepted_state="$(query_as postgres "SELECT status || ':' || invited_subject_id::text || ':' || (accepted_at IS NOT NULL)::text FROM iam.invitations WHERE token_hash=decode(repeat('11',32),'hex')")"
expect_equals "accepted:${INVITE_SUBJECT_C}:true" "$accepted_state" 'invitation acceptance was not committed atomically'
expect_equals '1' "$(query_as postgres "SELECT count(*) FROM iam.memberships WHERE tenant_id='${TENANT_A}' AND subject_id='${INVITE_SUBJECT_C}' AND starter_role='member' AND status='active'")" 'invitation acceptance did not create exactly one active membership'

replayed="$(query_as "$RUNTIME_ROLE" "SELECT tenant_id::text || ':' || subject_id::text || ':' || starter_role || ':' || status FROM iam.accept_invitation(decode(repeat('11',32),'hex'),'${INVITE_SUBJECT_C}')")"
expect_equals "$accepted" "$replayed" 'same-subject invitation replay was not idempotent'
expect_equals '1' "$(query_as postgres "SELECT count(*) FROM iam.memberships WHERE tenant_id='${TENANT_A}' AND subject_id='${INVITE_SUBJECT_C}'")" 'idempotent replay duplicated membership state'

expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.accept_invitation(decode(repeat('11',32),'hex'),'${INVITE_SUBJECT_D}')" 'accepted invitation was reusable by another subject'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.accept_invitation(decode(repeat('22',32),'hex'),'${INVITE_SUBJECT_C}')" 'expired invitation timestamp was accepted'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.accept_invitation(decode(repeat('33',32),'hex'),'${INVITE_SUBJECT_C}')" 'revoked invitation was accepted'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.accept_invitation(decode(repeat('44',32),'hex'),'${INVITE_SUBJECT_C}')" 'subject-bound invitation was accepted by the wrong subject'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.accept_invitation(decode(repeat('55',32),'hex'),'${INVITE_SUBJECT_C}')" 'suspended tenant invitation was accepted'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.accept_invitation(decode(repeat('66',32),'hex'),'${INVITE_SUBJECT_D}')" 'revoked membership was resurrected by invitation'
expect_failure "$RUNTIME_ROLE" "SELECT * FROM iam.accept_invitation(decode(repeat('77',32),'hex'),'${INVITE_SUBJECT_E}')" 'invitation silently elevated an existing membership role'

same_role="$(query_as "$RUNTIME_ROLE" "SELECT tenant_id::text || ':' || subject_id::text || ':' || starter_role || ':' || status FROM iam.accept_invitation(decode(repeat('88',32),'hex'),'${INVITE_SUBJECT_F}')")"
expect_equals "${TENANT_A}:${INVITE_SUBJECT_F}:member:active" "$same_role" 'same-role existing membership did not complete invitation idempotently'
expect_equals "accepted:${INVITE_SUBJECT_F}" "$(query_as postgres "SELECT status || ':' || invited_subject_id::text FROM iam.invitations WHERE token_hash=decode(repeat('88',32),'hex')")" 'same-role invitation did not transition to accepted'

# The SECURITY DEFINER function may temporarily select the target tenant but it
# must restore the caller's pre-existing transaction-local tenant context.
context_restore="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_B}',true); SELECT count(*) FROM iam.accept_invitation(decode(repeat('11',32),'hex'),'${INVITE_SUBJECT_C}'); SELECT current_setting('app.tenant_id',true); COMMIT;" | tail -n 1)"
expect_equals "${TENANT_B}" "$context_restore" 'invitation acceptance leaked its target tenant into caller context'

printf 'dbtest: invitation acceptance fail-closed/idempotent boundary passed\n'

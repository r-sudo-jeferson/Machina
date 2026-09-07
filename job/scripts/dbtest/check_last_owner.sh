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

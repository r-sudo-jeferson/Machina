#!/usr/bin/env bash
set -euo pipefail

readonly POSTGRES_IMAGE='postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af'
readonly DB_NAME='machina_test'
readonly MIGRATOR_ROLE='machina_migrator'
readonly RUNTIME_ROLE='machina_runtime'
readonly TENANT_A='00000000-0000-0000-0000-0000000000a1'
readonly TENANT_B='00000000-0000-0000-0000-0000000000b2'
readonly SUBJECT_A='10000000-0000-0000-0000-0000000000a1'
readonly SUBJECT_B='10000000-0000-0000-0000-0000000000b2'
readonly WORKSPACE_A='20000000-0000-0000-0000-0000000000a1'
readonly WORKSPACE_B='20000000-0000-0000-0000-0000000000b2'
readonly CONTAINER="machina-pg-${GITHUB_RUN_ID:-local}-$$"
readonly AUTHZ_SCHEMA_FIXTURE="services/authz/tests/fixtures/starter-schema.json"
readonly AUTHZ_POLICY_FIXTURE="services/authz/tests/fixtures/starter.cedar"
TENANT_SWITCH_INTEGRATION_DIR=''
AUDIT_INTEGRATION_DIR=''

readonly MIGRATIONS=(
  db/migrations/0001_schemas.sql
  db/migrations/0002_identity_tenancy.sql
  db/migrations/0003_authorization.sql
  db/migrations/0004_audit_outbox.sql
  db/migrations/0005_ai.sql
  db/migrations/0006_rls.sql
  db/migrations/0007_integrity.sql
  db/migrations/0008_identity_session_access.sql
  db/migrations/0009_session_context_access.sql
  db/migrations/0010_oidc_authorization_attempts.sql
  db/migrations/0011_session_rotation.sql
  db/migrations/0012_session_context_switch.sql
  db/migrations/0013_idempotency_boundary.sql
  db/migrations/0014_session_generation.sql
  db/migrations/0015_tenant_switch_idempotency_scope.sql
  db/migrations/0016_tenant_switch_response_etag.sql
  db/migrations/0017_audit_integrity_checkpoints.sql
)

fail() {
  printf 'dbtest: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TENANT_SWITCH_INTEGRATION_DIR" ]]; then
    rm -rf -- "$TENANT_SWITCH_INTEGRATION_DIR"
  fi
  if [[ -n "$AUDIT_INTEGRATION_DIR" ]]; then
    rm -rf -- "$AUDIT_INTEGRATION_DIR"
  fi
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for migration in "${MIGRATIONS[@]}"; do
  [[ -f "$migration" ]] || fail "required migration is missing: $migration"
done

source scripts/dbtest/check_migration_recovery.sh

docker run --detach --rm \
  --name "$CONTAINER" \
  --network none \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  "$POSTGRES_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -q -U postgres -d postgres; then
    break
  fi
  sleep 1
done
docker exec "$CONTAINER" pg_isready -q -U postgres -d postgres || fail 'PostgreSQL did not become ready'

actual_version_num="$(docker exec "$CONTAINER" psql -XAtq -U postgres -d postgres -c 'SHOW server_version_num')"
actual_version="$(docker exec "$CONTAINER" psql -XAtq -U postgres -d postgres -c 'SHOW server_version')"
[[ "$actual_version_num" == '180006' ]] || fail "unexpected PostgreSQL server_version_num: $actual_version_num ($actual_version)"

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres <<SQL
CREATE ROLE ${MIGRATOR_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE ${RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE ${DB_NAME} OWNER ${MIGRATOR_ROLE};
SQL

for migration in "${MIGRATIONS[@]}"; do
  docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U "$MIGRATOR_ROLE" -d "$DB_NAME" < "$migration"
done

query_as() {
  local role="$1"
  local sql="$2"
  docker exec "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$role" -d "$DB_NAME" -c "$sql"
}

expect_equals() {
  local want="$1"
  local got="$2"
  local message="$3"
  [[ "$got" == "$want" ]] || fail "$message: got '$got', want '$want'"
}

expect_failure() {
  local role="$1"
  local sql="$2"
  local message="$3"
  if query_as "$role" "$sql" >/dev/null 2>&1; then
    fail "$message: statement unexpectedly succeeded"
  fi
}

role_flags="$(query_as postgres "SELECT rolsuper::int || ':' || rolbypassrls::int || ':' || rolcreatedb::int || ':' || rolcreaterole::int FROM pg_roles WHERE rolname = '${RUNTIME_ROLE}'")"
expect_equals '0:0:0:0' "$role_flags" 'runtime role has elevated PostgreSQL capabilities'

owner_violations="$(query_as postgres "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE c.relkind='r' AND n.nspname IN ('iam','authz','audit','ops','ai') AND r.rolname <> '${MIGRATOR_ROLE}'")"
expect_equals '0' "$owner_violations" 'Slice tables are not owned exclusively by migration role'

rls_violations="$(query_as postgres "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN ('iam','authz','audit','ops','ai') AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity) AND (n.nspname,c.relname) NOT IN (('iam','subjects'),('iam','sessions'))")"
expect_equals '0' "$rls_violations" 'tenant tables are missing ENABLE/FORCE ROW LEVEL SECURITY'

tenant_key_violations="$(query_as postgres "WITH expected(schema_name, table_name) AS (VALUES ('iam','workspaces'),('iam','memberships'),('iam','invitations'),('iam','preferences'),('authz','policy_snapshots'),('audit','events'),('audit','chain_heads'),('audit','event_chain'),('audit','checkpoints'),('ops','outbox'),('ops','idempotency_keys'),('ai','interactions')) SELECT count(*) FROM expected e WHERE NOT EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace CROSS JOIN LATERAL unnest(c.conkey) AS key(attnum) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key.attnum WHERE c.contype='p' AND n.nspname=e.schema_name AND t.relname=e.table_name AND a.attname='tenant_id')")"
expect_equals '0' "$tenant_key_violations" 'tenant-owned tables have primary keys not qualified by tenant_id'

printf 'dbtest: introspection runtime_role_flags=%s owner_violations=%s rls_violations=%s tenant_key_violations=%s\n' \
  "$role_flags" "$owner_violations" "$rls_violations" "$tenant_key_violations"

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
INSERT INTO iam.subjects (id, external_subject, display_name) VALUES
  ('${SUBJECT_A}', 'oidc-a', 'Subject A'),
  ('${SUBJECT_B}', 'oidc-b', 'Subject B');
INSERT INTO iam.tenants (id, slug, display_name, status) VALUES
  ('${TENANT_A}', 'same-slug', 'Same Tenant Name', 'active'),
  ('${TENANT_B}', 'same-slug', 'Same Tenant Name', 'active');
INSERT INTO iam.workspaces (tenant_id, id, slug, display_name) VALUES
  ('${TENANT_A}', '${WORKSPACE_A}', 'main', 'Main'),
  ('${TENANT_B}', '${WORKSPACE_B}', 'main', 'Main');
INSERT INTO iam.memberships (tenant_id, subject_id, starter_role, status) VALUES
  ('${TENANT_A}', '${SUBJECT_A}', 'owner', 'active'),
  ('${TENANT_B}', '${SUBJECT_B}', 'owner', 'active');
INSERT INTO authz.policy_snapshots (
  tenant_id, version, snapshot_hash, cedar_schema, cedar_policies,
  status, created_by_subject_id, activated_at
) VALUES
  ('${TENANT_A}', 1, repeat('a', 64), '{}'::jsonb, 'permit(principal, action, resource);', 'active', '${SUBJECT_A}', clock_timestamp()),
  ('${TENANT_B}', 1, repeat('b', 64), '{}'::jsonb, 'permit(principal, action, resource);', 'active', '${SUBJECT_B}', clock_timestamp());
SQL

source scripts/dbtest/check_audit_integrity.sh

missing_context_count="$(query_as "$RUNTIME_ROLE" 'SELECT count(*) FROM iam.workspaces')"
expect_equals '0' "$missing_context_count" 'runtime without tenant context observed tenant rows'
expect_failure "$RUNTIME_ROLE" "INSERT INTO iam.workspaces (tenant_id,id,slug,display_name) VALUES ('${TENANT_A}','20000000-0000-0000-0000-0000000000ff','blocked','Blocked')" 'runtime without tenant context mutated tenant data'

tenant_a_count="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); SELECT count(*) FROM iam.workspaces; COMMIT;" | tail -n 1)"
expect_equals '1' "$tenant_a_count" 'tenant A context did not isolate workspace reads'

tenant_b_count="$(query_as "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_B}',true); SELECT count(*) FROM iam.workspaces; COMMIT;" | tail -n 1)"
expect_equals '1' "$tenant_b_count" 'tenant B context did not isolate workspace reads'

expect_failure "$RUNTIME_ROLE" "BEGIN; SELECT set_config('app.tenant_id','${TENANT_A}',true); INSERT INTO iam.workspaces (tenant_id,id,slug,display_name) VALUES ('${TENANT_B}','20000000-0000-0000-0000-0000000000ee','cross','Cross'); COMMIT;" 'tenant A context wrote tenant B data'

pool_reset="$(docker exec -i "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U "$RUNTIME_ROLE" -d "$DB_NAME" <<SQL
BEGIN;
SELECT set_config('app.tenant_id','${TENANT_A}',true);
SELECT count(*) FROM iam.workspaces;
COMMIT;
BEGIN;
SELECT CASE WHEN NULLIF(current_setting('app.tenant_id', true), '') IS NULL THEN '<cleared>' ELSE current_setting('app.tenant_id', true) END;
SELECT count(*) FROM iam.workspaces;
COMMIT;
SQL
)"
mapfile -t pool_lines <<< "$pool_reset"
[[ "${pool_lines[*]}" == *"${TENANT_A}"* ]] || fail 'transaction-local tenant context was never established'
expect_equals '<cleared>' "${pool_lines[-2]}" 'transaction-local tenant context did not clear after commit'
expect_equals '0' "${pool_lines[-1]}" 'same backend connection leaked previous tenant rows after commit'

run_go_tenant_switch_integration() {
  [[ "${MACHINA_RUN_TENANT_SWITCH_GO_INTEGRATION:-0}" == '1' ]] || return 0
  command -v go >/dev/null 2>&1 || fail 'Go is required for the tenant-switch integration boundary'

  local authz_binary="${MACHINA_TENANT_SWITCH_AUTHZ_BINARY:-}"
  [[ -n "$authz_binary" && -x "$authz_binary" ]] || fail 'MACHINA_TENANT_SWITCH_AUTHZ_BINARY must reference an executable Rust authorization service'
  [[ -f "$AUTHZ_SCHEMA_FIXTURE" ]] || fail "tenant-switch Cedar schema fixture is missing: $AUTHZ_SCHEMA_FIXTURE"
  [[ -f "$AUTHZ_POLICY_FIXTURE" ]] || fail "tenant-switch Cedar policy fixture is missing: $AUTHZ_POLICY_FIXTURE"

  local schema_json cedar_policies
  schema_json="$(<"$AUTHZ_SCHEMA_FIXTURE")"
  cedar_policies="$(<"$AUTHZ_POLICY_FIXTURE")"
  docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" \
    -v schema_json="$schema_json" \
    -v cedar_policies="$cedar_policies" <<'SQL'
UPDATE authz.policy_snapshots
SET cedar_schema = :'schema_json'::jsonb,
    cedar_policies = :'cedar_policies'
WHERE tenant_id IN (
  '00000000-0000-0000-0000-0000000000a1'::uuid,
  '00000000-0000-0000-0000-0000000000b2'::uuid
)
  AND version = 1
  AND status = 'active';
SQL
  expect_equals '2' "$(query_as postgres "SELECT count(*) FROM authz.policy_snapshots WHERE tenant_id IN ('${TENANT_A}','${TENANT_B}') AND version=1 AND status='active' AND cedar_schema <> '{}'::jsonb AND cedar_policies LIKE '%tenant.switch%'")" 'tenant-switch integration did not install the real Cedar fixtures'

  local integration_binary
  TENANT_SWITCH_INTEGRATION_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/machina-tenant-switch-go.XXXXXX")"
  integration_binary="${TENANT_SWITCH_INTEGRATION_DIR}/identity.test"
  go test -c -o "$integration_binary" ./internal/platform/identity
  docker cp "$integration_binary" "$CONTAINER:/tmp/machina-tenant-switch-identity.test" >/dev/null
  docker cp "$authz_binary" "$CONTAINER:/tmp/machina-authz" >/dev/null
  docker exec "$CONTAINER" chmod 0555 /tmp/machina-authz

  docker exec -d "$CONTAINER" bash -c "echo \$\$ >/tmp/machina-authz.pid; exec env MACHINA_AUTHZ_GRPC_ADDR=127.0.0.1:50051 MACHINA_AUTHZ_PROBE_ADDR=127.0.0.1:50052 MACHINA_AUTHZ_DATABASE_URL='postgresql://${RUNTIME_ROLE}@127.0.0.1:5432/${DB_NAME}?sslmode=disable&connect_timeout=2' /tmp/machina-authz >/tmp/machina-authz.log 2>&1"

  local ready=0
  for _ in $(seq 1 100); do
    if docker exec "$CONTAINER" bash -c 'exec 3<>/dev/tcp/127.0.0.1/50051' >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! docker exec "$CONTAINER" bash -c 'test -s /tmp/machina-authz.pid && kill -0 "$(cat /tmp/machina-authz.pid)"' >/dev/null 2>&1; then
      docker exec "$CONTAINER" cat /tmp/machina-authz.log >&2 || true
      fail 'Rust authorization service exited before becoming ready'
    fi
    sleep 0.05
  done
  if [[ "$ready" != '1' ]]; then
    docker exec "$CONTAINER" cat /tmp/machina-authz.log >&2 || true
    fail 'Rust authorization gRPC listener did not become ready on loopback'
  fi

  local integration_exit
  set +e
  docker exec "$CONTAINER" env \
    MACHINA_TENANT_SWITCH_DATABASE_URL="postgresql://${RUNTIME_ROLE}@127.0.0.1:5432/${DB_NAME}?sslmode=disable&connect_timeout=2" \
    MACHINA_TENANT_SWITCH_ADMIN_DATABASE_URL="postgresql://postgres@127.0.0.1:5432/${DB_NAME}?sslmode=disable&connect_timeout=2" \
    MACHINA_TENANT_SWITCH_AUTHZ_GRPC_ADDR="127.0.0.1:50051" \
    /tmp/machina-tenant-switch-identity.test \
    -test.run '^TestTenantSwitchCoordinatorAgainstPostgreSQL$' \
    -test.v
  integration_exit=$?
  set -e

  docker exec "$CONTAINER" bash -c 'kill -TERM "$(cat /tmp/machina-authz.pid)"' >/dev/null 2>&1 || true
  if [[ "$integration_exit" -ne 0 ]]; then
    docker exec "$CONTAINER" cat /tmp/machina-authz.log >&2 || true
    fail "tenant-switch Go/Rust/PostgreSQL integration failed with exit ${integration_exit}"
  fi

  rm -rf -- "$TENANT_SWITCH_INTEGRATION_DIR"
  TENANT_SWITCH_INTEGRATION_DIR=''
}

run_go_audit_integration() {
  [[ "${MACHINA_RUN_AUDIT_GO_INTEGRATION:-0}" == '1' ]] || return 0
  command -v go >/dev/null 2>&1 || fail 'Go is required for the audit integration boundary'

  local integration_binary
  AUDIT_INTEGRATION_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/machina-audit-go.XXXXXX")"
  integration_binary="${AUDIT_INTEGRATION_DIR}/audit.test"
  go test -c -o "$integration_binary" ./internal/platform/audit
  docker cp "$integration_binary" "$CONTAINER:/tmp/machina-audit.test" >/dev/null
  docker exec "$CONTAINER" env \
    MACHINA_AUDIT_DATABASE_URL="postgresql://${RUNTIME_ROLE}@127.0.0.1:5432/${DB_NAME}?sslmode=disable&connect_timeout=2" \
    /tmp/machina-audit.test \
    -test.run '^(TestDecisionEvidenceRoundTripPostgreSQL|TestPostgresCheckpointStoreRoundTripAndConflictWinner|TestPostgresAuditChainCheckpointerAndTamperEvidence)$' \
    -test.v
  rm -rf -- "$AUDIT_INTEGRATION_DIR"
  AUDIT_INTEGRATION_DIR=''
}

source scripts/dbtest/check_last_owner.sh
source scripts/dbtest/check_identity_session_boundary.sh
source scripts/dbtest/check_session_context_boundary.sh
source scripts/dbtest/check_oidc_authorization_attempt_boundary.sh
source scripts/dbtest/check_session_rotation_boundary.sh
source scripts/dbtest/check_concurrent_sessions.sh
source scripts/dbtest/check_session_context_switch.sh
source scripts/dbtest/check_session_generation.sh
source scripts/dbtest/check_tenant_switch_idempotency_scope.sh
run_go_tenant_switch_integration
run_go_audit_integration
source scripts/dbtest/check_idempotency_boundary.sh

printf 'dbtest: PostgreSQL %s tenancy/RLS kernel passed\n' "$actual_version"

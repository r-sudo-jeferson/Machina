#!/usr/bin/env bash
set -euo pipefail

readonly POSTGRES_IMAGE='postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af'
readonly DB_NAME='machina_authz_test'
readonly MIGRATOR_ROLE='machina_migrator'
readonly RUNTIME_ROLE='machina_runtime'
readonly TENANT_ID='00000000-0000-0000-0000-0000000000a1'
readonly INVALID_POLICY_TENANT_ID='00000000-0000-0000-0000-0000000000b2'
readonly SUBJECT_ID='10000000-0000-0000-0000-0000000000a1'
readonly SNAPSHOT_HASH='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
readonly INVALID_POLICY_SNAPSHOT_HASH='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
readonly CONTAINER="machina-authz-pg-${GITHUB_RUN_ID:-local}-$$"
readonly SCHEMA_FIXTURE='services/authz/tests/fixtures/starter-schema.json'
readonly POLICY_FIXTURE='services/authz/tests/fixtures/starter.cedar'
readonly MIGRATIONS=(
  db/migrations/0001_schemas.sql
  db/migrations/0002_identity_tenancy.sql
  db/migrations/0003_authorization.sql
  db/migrations/0004_audit_outbox.sql
  db/migrations/0005_ai.sql
  db/migrations/0006_rls.sql
  db/migrations/0007_integrity.sql
)

fail() {
  printf 'authztest: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for migration in "${MIGRATIONS[@]}"; do
  [[ -f "$migration" ]] || fail "required migration is missing: $migration"
done
[[ -f "$SCHEMA_FIXTURE" ]] || fail "schema fixture is missing: $SCHEMA_FIXTURE"
[[ -f "$POLICY_FIXTURE" ]] || fail "policy fixture is missing: $POLICY_FIXTURE"

docker run --detach --rm \
  --name "$CONTAINER" \
  --publish '127.0.0.1::5432' \
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

schema_json="$(<"$SCHEMA_FIXTURE")"
cedar_policies="$(<"$POLICY_FIXTURE")"
docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" \
  -v tenant_id="$TENANT_ID" \
  -v invalid_policy_tenant_id="$INVALID_POLICY_TENANT_ID" \
  -v subject_id="$SUBJECT_ID" \
  -v snapshot_hash="$SNAPSHOT_HASH" \
  -v invalid_policy_snapshot_hash="$INVALID_POLICY_SNAPSHOT_HASH" \
  -v schema_json="$schema_json" \
  -v cedar_policies="$cedar_policies" <<'SQL'
INSERT INTO iam.subjects (id, external_subject, display_name)
VALUES (:'subject_id'::uuid, 'oidc-authz-source', 'Authz Source Subject');

INSERT INTO iam.tenants (id, slug, display_name, status)
VALUES
    (:'tenant_id'::uuid, 'authz-source', 'Authz Source Tenant', 'active'),
    (:'invalid_policy_tenant_id'::uuid, 'authz-invalid-policy', 'Authz Invalid Policy Tenant', 'active');

INSERT INTO authz.policy_snapshots (
    tenant_id,
    version,
    snapshot_hash,
    cedar_schema,
    cedar_policies,
    status,
    created_by_subject_id,
    activated_at
) VALUES (
    :'tenant_id'::uuid,
    1,
    :'snapshot_hash',
    :'schema_json'::jsonb,
    :'cedar_policies',
    'active',
    :'subject_id'::uuid,
    now()
), (
    :'invalid_policy_tenant_id'::uuid,
    1,
    :'invalid_policy_snapshot_hash',
    :'schema_json'::jsonb,
    'this is not valid cedar policy syntax',
    'active',
    :'subject_id'::uuid,
    now()
);
SQL

role_flags="$(docker exec "$CONTAINER" psql -XAtq -v ON_ERROR_STOP=1 -U postgres -d postgres -c "SELECT rolsuper::int || ':' || rolbypassrls::int FROM pg_roles WHERE rolname = '${RUNTIME_ROLE}'")"
[[ "$role_flags" == '0:0' ]] || fail "runtime role is privileged: $role_flags"

mapped_endpoint="$(docker port "$CONTAINER" 5432/tcp | head -n 1)"
host_port="${mapped_endpoint##*:}"
[[ "$host_port" =~ ^[0-9]+$ ]] || fail "could not resolve PostgreSQL host port from: $mapped_endpoint"

readonly DATABASE_URL="postgresql://${RUNTIME_ROLE}@127.0.0.1:${host_port}/${DB_NAME}?sslmode=disable&connect_timeout=2"
printf 'authztest: PostgreSQL %s policy source fixture ready on loopback\n' "$actual_version"

MACHINA_AUTHZ_TEST_DATABASE_URL="$DATABASE_URL" \
  cargo +1.98.1 test --locked --test process_database -- --ignored --nocapture

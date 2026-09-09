#!/usr/bin/env bash
set -euo pipefail

readonly POSTGRES_IMAGE='postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af'
readonly DB_NAME='machina_invitation_test'
readonly MIGRATOR_ROLE='machina_migrator'
readonly RUNTIME_ROLE='machina_runtime'
readonly TENANT_A='00000000-0000-0000-0000-0000000000a1'
readonly TENANT_B='00000000-0000-0000-0000-0000000000b2'
readonly SUBJECT_A='10000000-0000-0000-0000-0000000000a1'
readonly CONTAINER="machina-pg-invitation-${GITHUB_RUN_ID:-local}-$$"

fail() {
  printf 'invitation-dbtest: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null 2>&1 || fail 'docker is required'

migrations=(db/migrations/[0-9][0-9][0-9][0-9]_*.sql)
[[ ${#migrations[@]} -gt 0 && -f "${migrations[0]}" ]] || fail 'database migrations are missing'
[[ "${migrations[-1]}" == 'db/migrations/0019_invitation_privilege_hardening.sql' ]] || fail "latest migration is not 0019_invitation_privilege_hardening.sql: ${migrations[-1]}"

docker pull "$POSTGRES_IMAGE" >/dev/null
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
[[ "$actual_version_num" == '180006' ]] || fail "unexpected PostgreSQL server_version_num: $actual_version_num"

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres <<SQL
CREATE ROLE ${MIGRATOR_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE ${RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE ${DB_NAME} OWNER ${MIGRATOR_ROLE};
SQL

for migration in "${migrations[@]}"; do
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

docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" <<SQL
INSERT INTO iam.subjects (id, external_subject, display_name)
VALUES ('${SUBJECT_A}', 'oidc-invitation-owner', 'Invitation Owner');
INSERT INTO iam.tenants (id, slug, display_name, status) VALUES
  ('${TENANT_A}', 'invitation-a', 'Invitation Tenant A', 'active'),
  ('${TENANT_B}', 'invitation-b', 'Invitation Tenant B', 'active');
INSERT INTO iam.memberships (tenant_id, subject_id, starter_role, status)
VALUES ('${TENANT_A}', '${SUBJECT_A}', 'owner', 'active');
SQL

source scripts/dbtest/check_invitation_acceptance.sh

printf 'invitation-dbtest: PostgreSQL 18.6 invitation profile boundary passed\n'

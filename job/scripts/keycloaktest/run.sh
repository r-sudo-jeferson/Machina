#!/usr/bin/env bash
set -euo pipefail

readonly REALM_FILE='deploy/keycloak/machina-preview-realm.json'
readonly REDIRECT_URI='http://127.0.0.1:18081/auth/callback'
readonly DISCOVERY_URL='http://127.0.0.1:18080/realms/machina-preview/.well-known/openid-configuration'
readonly CONTAINER="machina-keycloak-${GITHUB_RUN_ID:-local}-$$"
readonly ADMIN_USERNAME='machina-ci-admin'
readonly POSTGRES_IMAGE='postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af'
readonly POSTGRES_CONTAINER="machina-keycloak-pg-${GITHUB_RUN_ID:-local}-$$"
readonly POSTGRES_DB='machina_test'
readonly POSTGRES_MIGRATOR_ROLE='machina_migrator'
readonly POSTGRES_RUNTIME_ROLE='machina_runtime'
readonly POSTGRES_DATABASE_URL="postgresql://${POSTGRES_RUNTIME_ROLE}@127.0.0.1:15432/${POSTGRES_DB}?sslmode=disable&connect_timeout=2"

fail() {
  printf 'keycloaktest: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
  docker rm -fv "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_for_keycloak_ready() {
  local phase="$1"
  local ready=0
  for _ in $(seq 1 120); do
    if curl --fail --silent --show-error "$DISCOVERY_URL" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! docker inspect "$CONTAINER" --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
      docker logs "$CONTAINER" >&2 || true
      fail "Keycloak exited before OIDC discovery became ready during ${phase}"
    fi
    sleep 1
  done
  if [[ "$ready" != '1' ]]; then
    docker logs "$CONTAINER" >&2 || true
    fail "Keycloak OIDC discovery did not become ready within the bounded ${phase} window"
  fi
}

command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v docker >/dev/null 2>&1 || fail 'docker is required'
command -v go >/dev/null 2>&1 || fail 'Go is required'
command -v openssl >/dev/null 2>&1 || fail 'openssl is required for ephemeral credentials'
[[ -f "$REALM_FILE" ]] || fail "preview realm is missing: $REALM_FILE"
[[ -f 'toolchains.lock.json' ]] || fail 'toolchains.lock.json is missing'

image_ref="$(go run ./scripts/keycloaktest/cmd/imageref toolchains.lock.json)"
[[ "$image_ref" == *':26.7.3@sha256:'* ]] || fail "unexpected locked Keycloak reference: $image_ref"
expected_digest="${image_ref##*@}"

client_secret="$(openssl rand -hex 32)"
admin_password="$(openssl rand -hex 32)"
[[ ${#client_secret} -eq 64 && ${#admin_password} -eq 64 ]] || fail 'ephemeral credential generation failed'

# The exact tag+digest is the executable identity. Pulling this reference must
# fail if the registry no longer maps the selected bytes to the lock.
docker pull "$image_ref" >/dev/null
repo_digests="$(docker image inspect "$image_ref" --format '{{join .RepoDigests "\n"}}')"
grep -Fq "@${expected_digest}" <<<"$repo_digests" || fail 'pulled Keycloak image does not expose the expected RepoDigest'

version_output="$(docker run --rm "$image_ref" --version 2>&1)"
grep -Fq '26.7.3' <<<"$version_output" || fail "locked image did not report Keycloak 26.7.3: $version_output"

# start-dev is intentionally confined to this disposable CI integration
# harness. Task 11 owns production-shaped preview deployment. This container is
# explicitly removed by the trap instead of --rm so the same container can be
# stopped and restarted for dependency-recovery evidence.
docker run --detach \
  --name "$CONTAINER" \
  --memory 1g \
  --publish 127.0.0.1:18080:8080 \
  --env KC_BOOTSTRAP_ADMIN_USERNAME="$ADMIN_USERNAME" \
  --env KC_BOOTSTRAP_ADMIN_PASSWORD="$admin_password" \
  --env KC_HOSTNAME=http://127.0.0.1:18080 \
  --env MACHINA_KEYCLOAK_CLIENT_SECRET="$client_secret" \
  --env MACHINA_KEYCLOAK_REDIRECT_URI="$REDIRECT_URI" \
  --volume "$PWD/$REALM_FILE:/opt/keycloak/data/import/machina-preview-realm.json:ro" \
  "$image_ref" \
  start-dev --import-realm >/dev/null

wait_for_keycloak_ready 'startup'
container_id="$(docker inspect "$CONTAINER" --format '{{.Id}}')"
[[ -n "$container_id" ]] || fail 'Keycloak container identity is empty'

# Concurrent application sessions are proven against the same PostgreSQL 18.6
# identity/session kernel used by the database harness, exposed only on loopback.
docker pull "$POSTGRES_IMAGE" >/dev/null
docker run --detach --rm \
  --name "$POSTGRES_CONTAINER" \
  --memory 512m \
  --publish 127.0.0.1:15432:5432 \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  "$POSTGRES_IMAGE" >/dev/null

postgres_ready=0
for _ in $(seq 1 60); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -q -U postgres -d postgres; then
    postgres_ready=1
    break
  fi
  if ! docker inspect "$POSTGRES_CONTAINER" --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
    docker logs "$POSTGRES_CONTAINER" >&2 || true
    fail 'PostgreSQL exited before becoming ready'
  fi
  sleep 1
done
[[ "$postgres_ready" == '1' ]] || fail 'PostgreSQL did not become ready within the bounded startup window'

postgres_version_num="$(docker exec "$POSTGRES_CONTAINER" psql -XAtq -U postgres -d postgres -c 'SHOW server_version_num')"
[[ "$postgres_version_num" == '180006' ]] || fail "unexpected PostgreSQL server_version_num: $postgres_version_num"

docker exec -i "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres <<SQL
CREATE ROLE ${POSTGRES_MIGRATOR_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE ${POSTGRES_RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_MIGRATOR_ROLE};
SQL

migrations=(db/migrations/[0-9][0-9][0-9][0-9]_*.sql)
[[ ${#migrations[@]} -gt 0 && -f "${migrations[0]}" ]] || fail 'database migrations are missing'
for migration in "${migrations[@]}"; do
  docker exec -i "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_MIGRATOR_ROLE" -d "$POSTGRES_DB" < "$migration"
done

MACHINA_RUN_KEYCLOAK_INTEGRATION=1 \
MACHINA_KEYCLOAK_CLIENT_SECRET="$client_secret" \
MACHINA_KEYCLOAK_ADMIN_USERNAME="$ADMIN_USERNAME" \
MACHINA_KEYCLOAK_ADMIN_PASSWORD="$admin_password" \
MACHINA_KEYCLOAK_DATABASE_URL="$POSTGRES_DATABASE_URL" \
  go test -race -count=1 -run '^TestKeycloakOIDC(ProviderIntegration|AuthorizationCodePKCEIntegration|ConcurrentSessionsAgainstPostgreSQL)$' -v ./internal/platform/identity

# Stop the exact provider container and prove discovery fails closed rather than
# silently accepting a stale or synthetic provider boundary.
docker stop --timeout 15 "$CONTAINER" >/dev/null
if curl --fail --silent --show-error "$DISCOVERY_URL" >/dev/null 2>&1; then
  fail 'Keycloak OIDC discovery remained reachable after the provider container stopped'
fi
MACHINA_RUN_KEYCLOAK_INTEGRATION=1 \
MACHINA_EXPECT_KEYCLOAK_UNAVAILABLE=1 \
MACHINA_KEYCLOAK_CLIENT_SECRET="$client_secret" \
  go test -race -count=1 -run '^TestKeycloakOIDCProviderUnavailableIntegration$' -v ./internal/platform/identity

# Restart the same container identity; recreating a new container would not
# prove dependency restart recovery for the already-selected provider instance.
docker start "$CONTAINER" >/dev/null
restarted_container_id="$(docker inspect "$CONTAINER" --format '{{.Id}}')"
[[ "$restarted_container_id" == "$container_id" ]] || fail 'Keycloak restart changed container identity'
wait_for_keycloak_ready 'restart'

# Re-run real discovery and Authorization Code + PKCE against the restarted
# provider. These tests create fresh ephemeral user/login material.
MACHINA_RUN_KEYCLOAK_INTEGRATION=1 \
MACHINA_KEYCLOAK_CLIENT_SECRET="$client_secret" \
MACHINA_KEYCLOAK_ADMIN_USERNAME="$ADMIN_USERNAME" \
MACHINA_KEYCLOAK_ADMIN_PASSWORD="$admin_password" \
  go test -race -count=1 -run '^TestKeycloakOIDC(ProviderIntegration|AuthorizationCodePKCEIntegration)$' -v ./internal/platform/identity

printf 'keycloaktest: locked Keycloak 26.7.3 OIDC authorization-code/session outage-restart boundary passed\n'

#!/usr/bin/env bash
set -euo pipefail

readonly REALM_FILE='deploy/keycloak/machina-preview-realm.json'
readonly REDIRECT_URI='http://127.0.0.1:18081/auth/callback'
readonly DISCOVERY_URL='http://127.0.0.1:18080/realms/machina-preview/.well-known/openid-configuration'
readonly CONTAINER="machina-keycloak-${GITHUB_RUN_ID:-local}-$$"
readonly ADMIN_USERNAME='machina-ci-admin'

fail() {
  printf 'keycloaktest: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

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
# harness. Task 11 owns production-shaped preview deployment.
docker run --detach --rm \
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

ready=0
for _ in $(seq 1 120); do
  if curl --fail --silent --show-error "$DISCOVERY_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! docker inspect "$CONTAINER" --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
    docker logs "$CONTAINER" >&2 || true
    fail 'Keycloak exited before OIDC discovery became ready'
  fi
  sleep 1
done
if [[ "$ready" != '1' ]]; then
  docker logs "$CONTAINER" >&2 || true
  fail 'Keycloak OIDC discovery did not become ready within the bounded startup window'
fi

MACHINA_RUN_KEYCLOAK_INTEGRATION=1 \
MACHINA_KEYCLOAK_CLIENT_SECRET="$client_secret" \
MACHINA_KEYCLOAK_ADMIN_USERNAME="$ADMIN_USERNAME" \
MACHINA_KEYCLOAK_ADMIN_PASSWORD="$admin_password" \
  go test -count=1 -run '^TestKeycloakOIDC(ProviderIntegration|AuthorizationCodePKCEIntegration)$' -v ./internal/platform/identity

printf 'keycloaktest: locked Keycloak 26.7.3 OIDC authorization-code boundary passed\n'

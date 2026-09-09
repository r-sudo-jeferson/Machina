#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
JOB_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd -- "$JOB_ROOT/.." && pwd)"

fail() {
  printf 'secretstest: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${scan_tmp:-}" && -d "$scan_tmp" ]]; then
    rm -rf "$scan_tmp"
  fi
}
trap cleanup EXIT INT TERM

for command_name in docker git go grep id mktemp tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "${command_name} is required"
done

git -C "$REPO_ROOT" rev-parse --is-inside-work-tree | grep -qx true || fail 'repository root is not a Git work tree'
shallow="$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository)"
[[ "$shallow" == 'false' ]] || fail 'full Git history is required for repository secret scanning'

[[ ! -e "$REPO_ROOT/.gitleaksignore" ]] || fail '.gitleaksignore is not permitted for MCH-S001 secret evidence'
[[ ! -e "$REPO_ROOT/.gitleaks.toml" ]] || fail '.gitleaks.toml is not permitted for MCH-S001 secret evidence'

image_ref="$(cd "$JOB_ROOT" && go run ./scripts/secretstest/cmd/imageref toolchains.lock.json)"
[[ "$image_ref" == 'ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:'* ]] || fail "unexpected locked Gitleaks reference: $image_ref"
expected_digest="${image_ref##*@}"

docker pull "$image_ref" >/dev/null
repo_digests="$(docker image inspect "$image_ref" --format '{{join .RepoDigests "\n"}}')"
grep -Fq "@${expected_digest}" <<<"$repo_digests" || fail 'pulled Gitleaks image does not expose the expected RepoDigest'

version_output="$(docker run --rm "$image_ref" version 2>&1)"
grep -Fq '8.30.1' <<<"$version_output" || fail "locked image did not report Gitleaks 8.30.1: $version_output"

scan_tmp="$(mktemp -d)"
mkdir -p "$scan_tmp/tree"
git -C "$REPO_ROOT" archive --format=tar HEAD | tar -xf - -C "$scan_tmp/tree"

printf 'secretstest: running gitleaks dir current-tree scan\n'
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --volume "$scan_tmp/tree:/scan:ro" \
  "$image_ref" \
  dir --redact --no-banner /scan

printf 'secretstest: running gitleaks git full-history scan\n'
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --volume "$REPO_ROOT:/repo:ro" \
  --workdir /repo \
  "$image_ref" \
  git --redact --no-banner --log-opts='--all' /repo

printf 'secretstest: current tree and full Git history contain no detected secrets\n'

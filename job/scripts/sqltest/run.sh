#!/usr/bin/env bash
set -euo pipefail

readonly SQLC_VERSION='1.31.1'
readonly SQLC_ARCHIVE='sqlc_1.31.1_linux_amd64.tar.gz'
readonly SQLC_SHA256='497ae4fcdfa64c5b0c311ffe4c2bd991e43991e82e5367792ed78bc2dca27354'
readonly SQLC_URL="https://github.com/sqlc-dev/sqlc/releases/download/v${SQLC_VERSION}/${SQLC_ARCHIVE}"
readonly GENERATED_DIR='internal/platform/db/sqlcgen'

fail() {
  printf 'sqltest: %s\n' "$*" >&2
  exit 1
}

[[ -f sqlc.yaml ]] || fail 'required sqlc config is missing: sqlc.yaml'
[[ -d db/queries ]] || fail 'required sqlc query directory is missing: db/queries'
find db/queries -type f -name '*.sql' -print -quit | grep -q . || fail 'db/queries contains no SQL query contracts'
if grep -RniE 'select[[:space:]]+\*' db/queries --include='*.sql'; then
  fail 'SELECT * is forbidden in database query contracts'
fi

if [[ -d "$GENERATED_DIR" && -n "$(git status --porcelain -- "$GENERATED_DIR")" ]]; then
  fail 'generated sqlc package is dirty before verification'
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

curl --fail --location --silent --show-error \
  --proto '=https' --tlsv1.2 \
  --retry 3 --retry-all-errors \
  --output "$tmpdir/$SQLC_ARCHIVE" \
  "$SQLC_URL"
printf '%s  %s\n' "$SQLC_SHA256" "$tmpdir/$SQLC_ARCHIVE" | sha256sum --check --status || fail 'sqlc release archive checksum mismatch'
tar -xzf "$tmpdir/$SQLC_ARCHIVE" -C "$tmpdir" sqlc
[[ "$($tmpdir/sqlc version)" == "v${SQLC_VERSION}" ]] || fail 'sqlc binary version mismatch'

"$tmpdir/sqlc" vet -f sqlc.yaml
"$tmpdir/sqlc" generate -f sqlc.yaml

if [[ -n "$(git status --porcelain -- "$GENERATED_DIR")" ]]; then
  git status --short -- "$GENERATED_DIR" >&2
  while IFS= read -r file; do
    printf 'SQLC_GENERATED_FILE_BEGIN %s\n' "$file" >&2
    cat "$file" >&2
    printf '\nSQLC_GENERATED_FILE_END %s\n' "$file" >&2
  done < <(find "$GENERATED_DIR" -maxdepth 1 -type f -print | sort)
  fail 'checked-in sqlc output is missing, stale, or non-deterministic'
fi

go test -count=1 ./internal/platform/db/sqlcgen/...
printf 'sqltest: sqlc %s query contract passed\n' "$SQLC_VERSION"

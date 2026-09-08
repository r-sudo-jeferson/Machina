#!/usr/bin/env bash
set -euo pipefail

mode="${1:-generate}"
case "$mode" in
  generate|--check) ;;
  *)
    printf 'usage: %s [generate|--check]\n' "$0" >&2
    exit 64
    ;;
esac

job_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
repo_root="$(cd "$job_root/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

protoc_version="36.1"
protoc_gen_go_version="v1.36.12"
protoc_gen_go_grpc_version="v1.6.2"
module_path="github.com/r-sudo-jeferson/Machina/job"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

base64_single_line() {
  if base64 --help 2>&1 | grep -q -- '-w'; then
    base64 -w0 "$1"
  else
    base64 "$1" | tr -d '\n'
  fi
}

os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
  Linux/x86_64|Linux/amd64)
    protoc_asset="protoc-${protoc_version}-linux-x86_64.zip"
    protoc_sha256="c4bc672d9d49214dc8cafdceadf4df92182d6ca8e3ec65a56b2d7de5602669b4"
    ;;
  Linux/aarch64|Linux/arm64)
    protoc_asset="protoc-${protoc_version}-linux-aarch_64.zip"
    protoc_sha256="237a68856edf1bd28b6204bddd0596c1cf46d298bc29c620012540b2e44c73e7"
    ;;
  Darwin/arm64)
    protoc_asset="protoc-${protoc_version}-osx-aarch_64.zip"
    protoc_sha256="de56d57afe30c5d191b11d24ff93dd4025728d7fb43b773886b2d3613e0bdbb2"
    ;;
  Darwin/x86_64)
    protoc_asset="protoc-${protoc_version}-osx-x86_64.zip"
    protoc_sha256="ee2c5496e4af0aa6a224894bc0f7025145260e004d890487d510725ce8b473eb"
    ;;
  *)
    printf 'unsupported protoc platform: %s/%s\n' "$os" "$arch" >&2
    exit 69
    ;;
esac

archive="$tmp_dir/$protoc_asset"
protoc_url="https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/${protoc_asset}"
curl --fail --location --silent --show-error --retry 3 --retry-all-errors \
  --output "$archive" "$protoc_url"

actual_sha256="$(sha256_file "$archive")"
if [[ "$actual_sha256" != "$protoc_sha256" ]]; then
  printf 'protoc archive checksum mismatch: got %s want %s\n' "$actual_sha256" "$protoc_sha256" >&2
  exit 70
fi

mkdir -p "$tmp_dir/protoc" "$tmp_dir/bin"
unzip -q "$archive" -d "$tmp_dir/protoc"

GOBIN="$tmp_dir/bin" go install "google.golang.org/protobuf/cmd/protoc-gen-go@${protoc_gen_go_version}"
GOBIN="$tmp_dir/bin" go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${protoc_gen_go_grpc_version}"

cd "$job_root"
"$tmp_dir/protoc/bin/protoc" \
  -I contracts/proto \
  --plugin="protoc-gen-go=$tmp_dir/bin/protoc-gen-go" \
  --plugin="protoc-gen-go-grpc=$tmp_dir/bin/protoc-gen-go-grpc" \
  --go_out=. \
  --go_opt="module=${module_path}" \
  --go-grpc_out=. \
  --go-grpc_opt="module=${module_path}" \
  contracts/proto/authz/v1/authz.proto

if [[ "$mode" == "--check" ]]; then
  git -C "$repo_root" diff --exit-code -- job/gen/authz/v1
  untracked="$(git -C "$repo_root" ls-files --others --exclude-standard -- job/gen/authz/v1)"
  if [[ -n "$untracked" ]]; then
    printf 'generated protobuf files are not versioned:\n%s\n' "$untracked" >&2
    while IFS= read -r file; do
      [[ -n "$file" ]] || continue
      absolute="$repo_root/$file"
      printf 'GENERATED_FILE path=%s sha256=%s base64=' "$file" "$(sha256_file "$absolute")"
      base64_single_line "$absolute"
      printf '\n'
    done <<<"$untracked"
    exit 1
  fi
fi

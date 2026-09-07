#!/usr/bin/env bash

readonly RECOVERY_CONTRACT='db/MIGRATION-RECOVERY.md'

[[ -f "$RECOVERY_CONTRACT" ]] || fail "migration recovery contract is missing: ${RECOVERY_CONTRACT}"

for required_term in 'forward-only' 'preview' 'restore' 'snapshot' 'rollback'; do
  grep -Fqi "$required_term" "$RECOVERY_CONTRACT" || fail "migration recovery contract is missing required term: ${required_term}"
done

if grep -RniE '^[[:space:]]*(DROP[[:space:]]+(TABLE|SCHEMA)|TRUNCATE[[:space:]]+|DELETE[[:space:]]+FROM[[:space:]]+|ALTER[[:space:]]+TABLE[^;]*(DROP[[:space:]]+(COLUMN|CONSTRAINT)|ALTER[[:space:]]+COLUMN[^;]*TYPE))' \
  db/migrations --include='*.sql'; then
  fail 'S001 migration set contains destructive DDL/DML and is not eligible for forward-only recovery'
fi

# MCH-S001 Task 7 Convergence Plan

**Binding:** `FORGE-OPS-HIGHEND-v1.0.0`  
**Slice:** `MCH-S001@1.0.0`  
**GAUNTLET:** `GNT-MCH-S001-001`  
**Authorized GitLab base:** `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`

## Goal

Close only the remaining evidence requirements of Task 7 without absorbing Task 11: secret-free repository evidence, explicitly clean Keycloak integration execution, and destroy/recreate recovery of the preview provider from the versioned realm template.

## Non-regression surface

- Real Authorization Code + PKCE against Keycloak 26.7.3.
- State/nonce single-consume and strict redirect allowlist.
- Concurrent persisted sessions under non-owner PostgreSQL runtime role.
- Expired application-session rejection.
- Signed ID-token expiry rejection.
- Provider outage/restart recovery using the same container identity.
- Runtime-generated client/admin credentials only; no committed credentials.
- Existing Go/PostgreSQL/Rust/format gates remain green.

## Task A — Fail-closed secret scan

1. Add Gitleaks v8.30.1 to `job/toolchains.lock.json`, pinned by immutable OCI digest.
2. Add `job/scripts/secretstest/**` that validates the lock and executes both current-tree and Git-history scans with redacted output.
3. Add `.github/workflows/verify-secrets.yml` as glue only, with `contents: read`, full history checkout, exact SHA identity assertion, and the locked scanner script.
4. Do not add a baseline merely to manufacture PASS. Any finding must be classified and fixed at root cause; public-history findings remain evidence even when deleting a current file cannot erase prior exposure.

## Task B — Explicit clean-environment Keycloak evidence

1. Make `.github/workflows/verify-keycloak.yml` invoke the integration harness through an explicit `env -i` boundary preserving only the minimum process environment required to execute Go/Docker on the hosted runner.
2. Keep Keycloak client/admin secrets generated inside the harness; no GitHub repository secret is required.
3. Add static harness/workflow assertions so future changes cannot silently depend on inherited secret variables.

## Task C — Destroy/recreate from versioned template

1. Extend `job/scripts/keycloaktest/run.sh` after same-container restart evidence: destroy the provider container, recreate a new container from the same locked OCI image and `job/deploy/keycloak/machina-preview-realm.json`, and prove the new container ID differs.
2. Re-run discovery plus real Authorization Code + PKCE after recreation.
3. Preserve runtime-injected client secret and loopback-only preview binding; do not persist Keycloak state outside the disposable container.
4. Add static assertions in `job/scripts/keycloaktest/config_test.go` that distinguish restart evidence from destroy/recreate evidence.

## Verification

- Exact-SHA `verify-secrets` succeeds with zero findings.
- Exact-SHA `verify-keycloak` proves clean-env startup, fresh signed-token expiry, expired session rejection, outage, same-container restart, destroy/recreate, and post-recreate PKCE.
- `verify-go`, `verify-postgres`, `verify-authz`, and formatting remain green when triggered by changed paths.
- Update the canonical implementation checklist only for claims supported by exact-SHA run/job evidence.
- Final state after this plan remains `IN_PROGRESS` unless new/invited/existing user lifecycle coverage is also proven and later GAUNTLET/candidate/promotion stages complete.

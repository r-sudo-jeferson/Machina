# MCH-S001 Tenant-Switch Cedar Authorization Implementation Plan

> **Execution:** use superpowers:executing-plans with test-driven-development. Preserve exact-SHA evidence. Local ChatGPT clone is NOT_VERIFIED because outbound DNS is unavailable.

**Goal:** Add mandatory, fail-closed Cedar application authorization to `tenant.switch` while preserving PostgreSQL binder/RLS as an independent second defense and preserving existing idempotency, response, audit/outbox, cookie, and replay semantics.

**Authority:** `MCH-S001@1.0.0`, `GNT-MCH-S001-001`, AC-S001-05/06/10/11/12. Active binding `FORGE-OPS-HIGHEND-v1.0.0`; canonical legacy slash serialization is equivalent under `MCH-BINDING-001@1.0.0`. Current authorized Canon base rebind: `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`.

## Invariants

- Product code remains under `job/**`; existing root workflows stay provider glue only.
- No Python.
- Cedar never replaces PostgreSQL/RLS; PostgreSQL/RLS never replaces Cedar.
- Authorization occurs after `BindTenantSwitchIdempotency` establishes the locked server-side target and before receipt claim, session mutation, audit/outbox publication, or replay return.
- Replays require a fresh current authorization decision.
- Missing/invalid/stale policy, explicit deny, transport outage, error, and timeout fail closed.
- No browser secret is emitted on deny/error; replay still emits no replacement secret.
- Authorization request data is limited to server-resolved subject/tenant/workspace, closed action/resource, active policy version, correlation ID, and closed role/membership context.
- Metrics remain closed/low-cardinality; no tenant/subject/slug/email/prompt labels.
- Existing `audit.SafeMetadata` is the only metadata boundary; no arbitrary map is introduced into audit.

## Task A — Cedar starter schema/policy TDD

**Files**
- Modify: `job/services/authz/src/starter.rs`
- Create: `job/services/authz/tests/starter.rs`
- Modify: `job/services/authz/tests/fixtures/starter-schema.json`
- Modify: `job/services/authz/tests/fixtures/starter.cedar`

1. RED: tests require active owner/member `tenant.switch` on `Tenant` to allow; inactive/invalid context, wrong action/resource to deny; existing `context.read` to remain valid; schema parse/strict policy validation to remain warning-free.
2. GREEN: add `Tenant` and `tenant.switch` with the same active owner/member starter rule, preserving `context.read`.
3. Reuse existing policy snapshot/version machinery; do not create a new policy engine or migration.

## Task B — Go coordinator TDD

**Files**
- Modify: `job/internal/platform/identity/idempotent_tenant_switch.go`
- Create or extend focused tests under `job/internal/platform/identity/*tenant_switch*_test.go`
- Reuse: `job/internal/platform/authz/client.go`

1. RED: require a mandatory authorizer; constructor must reject absent/typed-nil authorizer.
2. RED: after binder, load current identity, target membership role, and active policy snapshot from the same transaction and issue exactly:
   - action `tenant.switch`
   - resource `Tenant::<target tenant UUID>` through `ResourceType=Tenant`, `ResourceID=<target tenant UUID>`
   - subject/tenant/workspace from server-side DB state
   - required active policy version
   - request correlation ID
   - context `{starter_role, membership_status=active}` only.
3. RED: explicit deny, invalid/stale response, authz error, and timeout must prevent receipt claim/session mutation/audit/outbox; success proceeds exactly once.
4. RED: replay performs current authz before reading/returning historical receipt and emits no new browser secrets.
5. GREEN: `TenantSwitchCoordinator` owns a mandatory authorizer interface satisfied by `*authz.Client`; public construction cannot bypass Cedar.
6. Carry the authorized policy version into success validation/audit so the response cannot silently report a different active policy version.

## Task C — HTTP fail-closed semantics

**Files**
- Modify: `job/internal/platform/identity/tenant_switch_http.go`
- Extend: `job/internal/platform/identity/tenant_switch_http_test.go`

1. Explicit Cedar deny -> HTTP 403 with a stable safe problem code and metric outcome `denied`.
2. Authz unavailable/error/timeout/missing policy -> HTTP 503 fail closed with metric outcome `error`.
3. Deny/error responses must contain zero `Set-Cookie` headers.
4. Existing success/replay body, status, ETag, no-store, and cookie behavior must not regress.

## Task D — Real Go↔Rust↔PostgreSQL integration

**Files**
- Modify existing `job/scripts/authztest/run.sh` and/or existing authz integration tests only as needed.
- Reuse `.github/workflows/verify-authz.yml`; do not create a parallel workflow.

Prove Go request -> Rust gRPC -> PostgreSQL policy source -> Cedar for `tenant.switch`: allow, stale-version deny, missing-policy deny, and unavailable fail-closed where the existing harness can exercise it. Then rerun PostgreSQL tenant-switch integration to prove DB/RLS remains independently effective.

## Task E — Mutation and convergence

1. After first GREEN, temporarily mutate a critical guard (preferred: treat Cedar deny as allow or ignore authz error).
2. Require exact-SHA CI FAILURE for the intended test.
3. Restore production blobs exactly; verify the mutant is absent.
4. Same-SHA convergence must include Go, Rust authz, and PostgreSQL gates required by the handoff.
5. Run separate technical critique against AC-S001-05/06/10 and regression surfaces.
6. Update only evidence/checklists actually proven. Do not mark Gate I, GAUNTLET, candidate freeze, promotion, or COMPLETE.

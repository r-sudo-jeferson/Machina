# MCH-S001 Secure AI-First Tenant Entry Implementation Plan

> For agentic workers: implement task-by-task with TDD, independent review between material tasks, and fresh verification before any PASS claim.

**Goal:** Deliver MCH-S001@1.0.0 as a complete vertical journey: secure identity, tenant/workspace establishment, independently enforced tenant isolation and authorization, accessible Machina Alloy shell, and real read-only ASK AI First context with citations.

**Architecture:** A Go modular monolith provides BFF/API and worker responsibilities, PostgreSQL 18 is the system of record with forced RLS, a narrow Rust Cedar authorization service is the policy boundary, Keycloak owns authentication, and React 19.2/Vite 8.1 provides the web experience. The slice is constructed in GitHub under `/job`, verified against the canonical GitLab base `0ad4f8d69846818792853586fdded0a8636e42e996c531849483c7d53908efcd`, then frozen and promoted exactly after GNT-MCH-S001-001 PASS.

**Tech Stack:** Go 1.27.1, Rust 1.98.1, PostgreSQL 18, Keycloak 26.x pinned patch, React 19.2, TypeScript strict, Vite 8.1, React Aria Components, pnpm, Cedar, pgx/v5, sqlc, OpenTelemetry, OpenAPI 3.1.1, Protobuf, GitHub Actions, OCI/OpenTofu. No Python.

**Spec:** GitLab `job/docs/slices/MCH-S001.md`, `job/docs/architecture/SAAS-PLATFORM-2026-2027.md`, `job/docs/operations/PRODUCTION-SYSTEM.md`, handoff `MCH-HANDOFF-S001@1.0.1`, and Founder amendment `MCH-BINDING-001@1.0.0`.

## Global constraints

- Active Slice only: `MCH-S001@1.0.0`.
- GAUNTLET: `GNT-MCH-S001-001`.
- Canon base: `0ad4f8d69846818792853586fdded0a8636e42e996c531849483c7d53908efcd`.
- GitHub workspace base: `ce39af8f955536d270a43e03714c5057dbd33e36`.
- All product artifacts live under `/job/**`; root is limited to AGENTS/README/provider-required metadata.
- No Python source, runtime, image, CI job, script, migration or test harness.
- Runtime DB role is never owner/superuser; `FORCE ROW LEVEL SECURITY` is mandatory on tenant tables.
- Missing/invalid/stale/errored/unavailable authorization always denies.
- AI has no arbitrary SQL, HTTP, shell, repository write or direct database access.
- Project tests run before Machina tests and GAUNTLET.
- Public GitHub receives no credentials, customer data, private evidence, private strategy or unredacted production material.

---

## File map

### Repository verification and toolchain
- `job/go.mod`, `job/go.sum`: Go workspace root.
- `job/Cargo.toml`, `job/Cargo.lock`: Rust workspace root.
- `job/package.json`, `job/pnpm-workspace.yaml`, `job/pnpm-lock.yaml`: Node/web workspace.
- `job/toolchains.lock.json`: pinned toolchain versions and image/action digests.
- `job/scripts/verify/main.go`: repository policy verifier entrypoint.
- `job/scripts/verify/binding.go`: strict binding parser/comparator.
- `job/scripts/verify/boundary.go`: `/job` and root metadata policy.
- `job/scripts/verify/nopython.go`: prohibited Python artifact/runtime detector.
- `job/scripts/verify/*_test.go`: fail-closed regression tests.
- `.github/workflows/ci.yml`: minimal root orchestration calling `/job/scripts`.

### Contracts
- `job/contracts/openapi/platform.yaml`: session, tenants, workspaces, memberships, context and Ask endpoints.
- `job/contracts/proto/authz/v1/authz.proto`: Go↔Rust authorization contract.
- `job/contracts/events/v1/envelope.json`: event/outbox envelope.
- `job/contracts/ai/context-tool.schema.json`: strict read-only Ask tool schema.
- `job/contracts/modules/core.manifest.json`: S001 platform/core capability manifest.

### Database
- `job/db/migrations/0001_schemas.sql`
- `job/db/migrations/0002_identity_tenancy.sql`
- `job/db/migrations/0003_authorization.sql`
- `job/db/migrations/0004_audit_outbox.sql`
- `job/db/migrations/0005_ai.sql`
- `job/db/migrations/0006_rls.sql`
- `job/db/migrations/0007_integrity.sql`
- `job/db/queries/*.sql`, `job/sqlc.yaml`

### Go runtime
- `job/cmd/api/main.go`, `job/cmd/worker/main.go`
- `job/internal/platform/db/*`
- `job/internal/platform/identity/*`
- `job/internal/platform/tenancy/*`
- `job/internal/platform/authz/*`
- `job/internal/platform/audit/*`
- `job/internal/platform/outbox/*`
- `job/internal/platform/ai/*`
- `job/internal/platform/observability/*`
- `job/internal/platform/httpx/*`

### Rust authorization
- `job/services/authz/Cargo.toml`
- `job/services/authz/src/{main,server,evaluator,policy_store,cache,explain,telemetry}.rs`
- `job/services/authz/policy/schema.json`
- `job/services/authz/policy/starter.cedar`
- `job/services/authz/tests/*`

### Web and Alloy
- `job/packages/alloy/tokens/**`
- `job/packages/alloy/src/**`
- `job/apps/web/src/app/**`
- `job/apps/web/src/features/{auth,onboarding,tenant,workspace,context,ask,preferences}/**`
- `job/apps/web/src/i18n/**`

### Deployment and verification
- `job/deploy/keycloak/**`
- `job/deploy/opentofu/**`
- `job/deploy/containers/**`
- `job/deploy/otel/**`
- `job/tests/{integration,isolation,security,e2e,accessibility,ai,performance,resilience}/**`

---

## Task 1: Repository contract and fail-closed binding verification

**Files:** create `job/scripts/verify/main.go`, `binding.go`, `binding_test.go`, `boundary.go`, `boundary_test.go`, `nopython.go`, `nopython_test.go`; create initial workspace manifests and `toolchains.lock.json`.

**Produces:** `ParseBinding(string) (Binding, error)`, `EquivalentBinding(a,b string) bool`, `VerifyRepository(root string) error`.

- [ ] Write tests proving both approved bindings resolve to `{Family:"FORGE-OPS-HIGHEND", Version:"1.0.0"}`.
- [ ] Write tests rejecting case variants, changed family/version, prefix/substring, wildcard, missing version and unknown separator.
- [ ] Write tests with synthetic trees proving product outside `/job`, `.py`, Python shebang, `python`/`python3` CI invocation and Python base images fail closed.
- [ ] Run `go test ./scripts/verify/...` and confirm RED before implementation.
- [ ] Implement strict parser with two explicit accepted serializations only; do not use fuzzy matching.
- [ ] Implement root allowlist and repository scan.
- [ ] Run `go test ./scripts/verify/...` and `go test ./...`.
- [ ] Evidence: test output plus enumerated repository tree.
- [ ] Rollback: revert this task commit only; no schema/runtime dependency exists yet.

## Task 2: Versioned API, authz, event and AI contracts

**Files:** create the OpenAPI, Protobuf, event, tool-schema and core manifest files listed above; add contract validators under `job/scripts/contracts/`.

**Produces:** stable endpoint/resource names, gRPC request/response fields, strict Ask tool arguments/result projection, event envelope and capability IDs.

- [ ] Define tests that reject arbitrary `tenant_id` in the AI tool input.
- [ ] Define authz protobuf fields: subject, action, resource, tenant, workspace, required policy version, decision ID, allow/deny, reason codes and diagnostics reference.
- [ ] Define RFC9457-compatible error schema and ETag/idempotency headers for mutations.
- [ ] Validate OpenAPI/JSON Schema/Protobuf deterministically using Go/Rust/Node tooling only.
- [ ] Evidence: generated/validated contract checksum manifest.
- [ ] Rollback: revert contracts before dependent generated/runtime code is merged.

## Task 3: PostgreSQL tenancy kernel and RLS

**Files:** create migrations `0001` through `0007`, sqlc queries/config and DB integration harness.

**Produces:** schemas `iam`, `authz`, `audit`, `ops`, `ai`; tenant/workspace/membership/invitation/session/preference/policy/audit/outbox/idempotency/AI tables.

- [ ] Write integration tests using a real non-owner runtime role and a separate migration owner.
- [ ] Prove two tenants with colliding names/slugs cannot read/write each other.
- [ ] Prove missing `SET LOCAL app.tenant_id` yields no tenant rows and cannot mutate tenant data.
- [ ] Prove pooled connection reuse cannot retain previous tenant context.
- [ ] Prove every tenant table has `ENABLE` and `FORCE ROW LEVEL SECURITY` and tenant-qualified keys.
- [ ] Protect last-owner removal with transactional locking/invariant checks and concurrency tests.
- [ ] Evidence: SQL test matrix and role/ownership introspection output.
- [ ] Rollback: migrations have explicit down/restore strategy in preview; destructive contract migration is forbidden in this Slice.

## Task 4: Rust Cedar authorization service

**Files:** create `job/services/authz/**`.

**Produces:** gRPC `Check`, `ValidatePolicySet`, health/readiness; version-aware policy loading and safe explanation metadata.

- [ ] Write Rust tests for empty store, permit, forbid-over-permit, invalid schema, evaluation diagnostic, stale version, timeout simulation and cache invalidation.
- [ ] Confirm every uncertainty returns deny at service boundary.
- [ ] Implement starter owner/member policies without introducing S002 policy UI.
- [ ] Benchmark local evaluator separately from gRPC overhead; target p95 <10 ms at documented S001 load.
- [ ] Evidence: `cargo test`, property tests where useful, benchmark/load report with hardware.
- [ ] Rollback: Go client remains fail-closed if service is absent.

## Task 5: Go transaction, identity, tenant and session foundation

**Files:** `job/internal/platform/db`, `identity`, `tenancy`, `authz`, `httpx`; `job/cmd/api`.

**Produces:** mandatory transaction wrapper, trusted active-context resolver, server-side sessions, OIDC callback/session lifecycle, tenant create/join/switch APIs.

- [ ] Write tests for Authorization Code + PKCE state/nonce handling, callback allowlist, secure cookie configuration, logout, expiry, revoked membership, CSRF, replay and open redirect.
- [ ] Write tenant-switch tests that manipulate URL/header/body and stale browser state.
- [ ] Implement active tenant derivation from server session plus membership; never trust raw tenant header as authority.
- [ ] Create tenant + initial owner membership + workspace in one transaction with idempotency.
- [ ] Accept invitations idempotently through token-hash locator followed by tenant-scoped authorization.
- [ ] Evidence: unit + real Keycloak integration tests.
- [ ] Rollback: session/data migrations are additive; old preview environment can be destroyed and recreated.

## Task 6: Audit, outbox and OpenTelemetry minimum

**Files:** `job/internal/platform/audit`, `outbox`, `observability`; worker composition.

**Produces:** atomic domain/audit/outbox transaction, correlation IDs, traces/metrics/logs, hash-chained audit checkpoints.

- [ ] Write crash-injection tests between mutation, audit insert and outbox publication.
- [ ] Prove retries do not duplicate effects.
- [x] Prove metrics reject raw email/name/prompt/tenant-slug labels.
  - Evidence (2026-09-08): `OperationMetrics` exposes only the closed `machina.operation` and `machina.outcome` attribute vocabulary, and the tenant-switch HTTP wiring records only `tenant.switch` plus a closed terminal outcome.
  - RED: test-only SHA `bf097d18bcb06e1b3fdad6fe5a9e1ecf832b21d9`; Go workflow `34265006427` / job `102192043395` failed specifically because `newTenantSwitchHTTPHandler` was still undefined after module/format checks.
  - Mutation kill: SHA `81ac5f8f38af7a3238985f4f27febce4dde5f533`; Go workflow `34265511792` / job `102193744785` failed exactly because replay was mutated to emit `success`.
  - Restored implementation SHA `03ae1a913ce8f85a4f2fe6d6749ef44f0e8aa35d`: Go workflow `34265685051` / job `102194331109`, PostgreSQL workflow `34265684912` / job `102194331039`, and formatting workflow `34265684916` all succeeded.
  - Verification SHA `dac86be3dffff91624cb967d5a8a0a6852d70e74`: Go workflow `34265797509` / job `102194712088` succeeded, including `go mod tidy -diff`, gofmt, `go vet ./...`, repository verification, `go test -count=1 ./...`, and `go test -race -count=1 ./internal/platform/observability ./internal/platform/identity`.
  - Local execution in the ChatGPT runtime is NOT_VERIFIED because outbound DNS prevented repository cloning; no local PASS is claimed. Exact-SHA GitHub Actions is the execution evidence above.
- [ ] Reconstruct one allowed and one denied decision from safe metadata.
- [ ] Evidence: trace IDs linking HTTP→authz→DB→audit/outbox and redaction assertions.
- [ ] Rollback: additive tables and worker can be disabled without bypassing audit on API mutations.

## Task 7: Keycloak preview integration

**Files:** `job/deploy/keycloak/**`, integration tests.

**Produces:** pinned preview realm/client configuration and startup contract with no committed secrets.

- [ ] Test new, invited, existing and concurrent-session users.
- [ ] Test Keycloak outage/restart and expired tokens/sessions.
- [ ] Verify client secrets are injected by environment/secret reference, never repository content.
- [ ] Evidence: clean-environment integration run and secret scan.
- [ ] Rollback: destroy preview realm/container and recreate from versioned safe template.

## Task 8: Machina Alloy design system foundation

**Files:** `job/packages/alloy/**`.

**Produces:** DTCG tokens, Silver/Space Black themes, material surfaces, focus/state primitives and foundational controls based on React Aria.

- [ ] Encode approved Silver/Space Black and semantic high-saturation tokens.
- [ ] Test token generation determinism and contrast pairs.
- [ ] Implement forced-colors and reduced-motion behavior before decorative depth.
- [ ] Add Storybook/component tests for keyboard/focus/disabled/loading/error/selected states.
- [ ] Evidence: visual snapshots plus automated accessibility results; manual AT remains required before PASS.
- [ ] Rollback: token/component commit can be reverted without backend impact.

## Task 9: Complete web entry journey

**Files:** `job/apps/web/src/**`.

**Produces:** login/onboarding, tenant/workspace context shell, theme selection, authorized tenant switching, deterministic context UI, logout and full state handling.

- [ ] Write Playwright journeys for new user and invited user at mobile and desktop in both themes.
- [ ] Include loading, empty, denied, partial, error, reconnect, success and recovery states where applicable.
- [ ] Verify keyboard-only completion, visible focus, 200% zoom and forced-colors comprehension.
- [ ] Evidence: E2E artifacts and manual accessibility checklist.
- [ ] Rollback: web artifact digest rollback; backend contracts remain compatible.

## Task 10: Real read-only ASK AI First path

**Files:** `job/internal/platform/ai/**`, `job/apps/web/src/features/ask/**`, AI eval fixtures.

**Produces:** provider-neutral AI interface, initial OpenAI Responses adapter, SSE stream, `context.read` tool, citations, budget/cancel/timeout/fallback and audit.

- [ ] Write unit tests with fake provider for deterministic orchestration behavior only.
- [ ] Write integration test requiring a real configured provider for Gate E evidence; fake output must never satisfy GAUNTLET.
- [ ] Inject adversarial instructions into user, tenant, workspace and conversation fields and prove they remain untrusted data.
- [ ] Prove tool input cannot choose arbitrary tenant and result projection contains only allowed fields.
- [ ] Prove unsupported requests for SQL/HTTP/shell/policy mutation/other tenant are rejected or answered safely.
- [ ] Record model ID, prompt/tool versions, token/cost/latency metadata without raw sensitive prompt logging.
- [ ] Evidence: live-provider run metadata + golden/red-team evaluation report.
- [ ] Rollback: deterministic manual context UI remains complete if provider is disabled/unavailable.

## Task 11: CI, supply chain and isolated preview

**Files:** `.github/workflows/ci.yml`, `.github/workflows/preview.yml`, `.github/workflows/candidate.yml`; `job/deploy/**`; `job/scripts/ci/**`.

**Produces:** fresh-run pipeline, scans, SBOM, provenance, keyless signing, OIDC preview deployment and candidate digest chain.

- [ ] Pin every third-party GitHub Action by full commit SHA.
- [ ] Set minimal workflow permissions and no privileged execution for untrusted fork code.
- [ ] Run boundary/binding/no-Python first, then format/lint/static/security/contracts/tests.
- [ ] Build reproducible OCI artifacts, generate SBOM, scan and attest/sign by OIDC identity.
- [ ] Deploy isolated preview from exact candidate and run runtime smoke/security checks.
- [ ] Evidence: workflow run IDs, candidate SHA, image digests, SBOM/provenance/signature verification.
- [ ] Rollback: destroy candidate preview and redeploy prior accepted digest; no mutable `latest` release dependency.

## Task 12: Cross-cutting GAUNTLET convergence and candidate freeze

**Files:** `job/tests/**`, `job/docs/engineering/MCH-S001-verification-map.md`.

**Produces:** evidence map from AC-S001-01..12 and Gates A..K to reproducible checks.

- [ ] Gate A: binding semantic comparator, base SHA, repository boundary, no Python.
- [ ] Gates B-D: identity/session, tenant isolation and authorization adversarial matrices.
- [ ] Gate E: real-provider AI safety/product truth.
- [ ] Gate F: concurrency/idempotency/atomicity/migrations.
- [ ] Gate G: complete responsive/accessibility/visual review.
- [ ] Gate H: documented load plus dependency fault injection.
- [ ] Gate I: trace/audit reconstruction and redaction.
- [ ] Gate J: clean CI/supply-chain/preview/candidate mutation invalidation.
- [ ] Gate K: all project tests first, then Machina tests, independent critique and full GAUNTLET.
- [ ] Freeze exact GitHub SHA/artifact digests only after all mandatory checks PASS.
- [ ] Promotion is a separate transaction; do not mark COMPLETE until GitLab content identity is verified.

## Acceptance coverage

- AC-S001-01 → Task 1 plus Founder compatibility amendment.
- AC-S001-02 → Tasks 1 and 11.
- AC-S001-03 → Tasks 7-9.
- AC-S001-04 → Tasks 5 and 7.
- AC-S001-05 → Tasks 3-5 and 10.
- AC-S001-06 → Task 4 and Go fail-closed client in Task 5.
- AC-S001-07 → Task 10.
- AC-S001-08 → Task 10.
- AC-S001-09 → Tasks 8-9.
- AC-S001-10 → Tasks 6 and 10.
- AC-S001-11 → Tasks 11-12.
- AC-S001-12 → Task 12 plus separate promotion verification.

## Commit discipline

Each task lands as one or more coherent commits only after its RED→GREEN verification. No task may weaken a legitimate test to achieve GREEN. Candidate-changing fixes after a GAUNTLET PASS invalidate that PASS and require applicable verification again.
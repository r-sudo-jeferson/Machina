# MCH-S001 Keycloak Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the reliability portion of MCH-S001 Task 7 by proving the pinned Keycloak preview boundary fails closed during outage, recovers after an actual container restart, and rejects expired application sessions without weakening the existing Authorization Code + PKCE and concurrent persisted-session evidence.

**Architecture:** Keep Keycloak as an external OIDC dependency and the Go BFF server session as application authority. The disposable CI harness owns dependency lifecycle fault injection; production identity code remains unchanged unless a failing behavioral test demonstrates a real contract miss. PostgreSQL remains the persistence authority for application sessions, and session expiry is asserted through the same non-owner runtime role used by integration tests.

**Tech Stack:** Go 1.27.1, Keycloak 26.7.3 locked by OCI digest, PostgreSQL 18.6, Bash CI harness, GitHub Actions.

**Spec:** `job/docs/engineering/MCH-S001-implementation-plan.md` Task 7; `GNT-MCH-S001-001` Gate B/J/K requirements carried by the authorized MCH-S001@1.0.0 contract.

## Global Constraints

- FORGE binding: `FORGE-OPS-HIGHEND-v1.0.0`.
- Slice: `MCH-S001@1.0.0`; GAUNTLET: `GNT-MCH-S001-001`.
- Authorized GitLab base: `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`.
- GitLab `machina-group/machina` is Canon; GitHub `r-sudo-jeferson/Machina` is construction only.
- Product changes remain under `job/**`; `.github/**` is glue only.
- No Python.
- Never commit client secrets, admin credentials, generated browser/session secrets, or runtime customer data.
- Do not replace the real Keycloak/PostgreSQL integration with mocks for GAUNTLET evidence.
- Existing Authorization Code + PKCE, nonce/state single-consume, redirect allowlist, session independence, RLS, and secret-injection checks are non-regression surfaces.
- RED must fail for the intended missing behavior; GREEN changes the harness/runtime behavior, never the assertion to manufacture PASS.

---

### Task 1: Real Keycloak outage and restart recovery

**Files:**
- Modify: `job/internal/platform/identity/keycloak_integration_test.go`
- Modify: `job/scripts/keycloaktest/run.sh`
- Test: `job/scripts/keycloaktest/config_test.go`

**Interfaces:**
- Consumes: `NewOIDCClient(context.Context, OIDCClientConfig) (*OIDCClient, error)` and the existing locked Keycloak container in `run.sh`.
- Produces: `TestKeycloakOIDCProviderUnavailableIntegration`, plus a harness sequence that proves discovery fails while the actual container is stopped and succeeds again after the same container is restarted.

- [ ] **Step 1: Write the failing outage assertion.** Add `TestKeycloakOIDCProviderUnavailableIntegration` gated by `MACHINA_RUN_KEYCLOAK_INTEGRATION=1` and `MACHINA_EXPECT_KEYCLOAK_UNAVAILABLE=1`. It creates a bounded context, calls `NewOIDCClient` with the same issuer/client/redirect contract, and fails if provider discovery succeeds.
- [ ] **Step 2: Force RED without faking the dependency.** Invoke that test from `run.sh` with `MACHINA_EXPECT_KEYCLOAK_UNAVAILABLE=1` while the existing Keycloak container is still healthy. Expected exact-SHA `verify-keycloak` failure: provider discovery unexpectedly succeeds while outage is required.
- [ ] **Step 3: Implement the minimum real fault injection.** Make the disposable Keycloak container restartable by relying on explicit trap cleanup rather than Docker `--rm`; after the existing healthy integration phase, stop the exact container, assert discovery is unavailable, run the outage test, start the same container again, wait for bounded OIDC discovery readiness, and rerun real provider + Authorization Code/PKCE integration.
- [ ] **Step 4: Add static harness invariants.** Extend `config_test.go` to require bounded stop/start/readiness recovery commands and to reject a restart path that changes image identity or injects a repository credential.
- [ ] **Step 5: Verify GREEN.** Exact-SHA `verify-keycloak` must show: healthy real Keycloak tests PASS; outage test PASS while container is stopped; post-restart discovery and real browser Authorization Code + PKCE PASS. `verify-go`, `verify-postgres`, Rust authz and formatting checks must remain green.
- [ ] **Step 6: Commit evidence only after exact-SHA results are known.** Record run/job IDs in the Task 7 evidence section without claiming GAUNTLET PASS.

### Task 2: Expired server-side session rejection on the real persistence boundary

**Files:**
- Modify: `job/internal/platform/identity/keycloak_concurrent_sessions_integration_test.go` or create a focused `job/internal/platform/identity/keycloak_session_expiry_integration_test.go` if that keeps one behavior per test file.
- Read/retain: `job/internal/platform/identity/store.go`, `job/db/queries/identity.sql`, and the migration implementing `iam.get_active_session`.

**Interfaces:**
- Consumes: `SessionStore.Create`, `SessionStore.Lookup`, `AuthenticatedSessionService`, and PostgreSQL `iam.get_active_session` through the runtime role.
- Produces: a deterministic real-PostgreSQL assertion that an expired server-side session is not returned as active; no sleep-based timing race is allowed.

- [ ] **Step 1: Inspect the SQL expiry invariant.** Confirm the current `iam.get_active_session` function filters expiry at the database authority and determine whether an already-expired timestamp is accepted by `iam.create_session`.
- [ ] **Step 2: Write a deterministic RED only if coverage is absent.** Construct an expired session using a past `expires_at` through the real runtime-access path or a transactionally controlled database clock fixture; `SessionStore.Lookup` must return `pgx.ErrNoRows`. If the current database function already passes this new test immediately, do not call it RED or modify production; instead prove mutation sensitivity by temporarily removing/bypassing the expiry predicate on a test-only SHA and require the test to fail.
- [ ] **Step 3: Correct only a demonstrated contract miss.** If the mutation proves the test and current implementation is already correct, restore production unchanged. If a genuine implementation miss exists, fix the SQL function/migration additively and regenerate sqlc outputs using the repository’s locked workflow; never weaken the test.
- [ ] **Step 4: Verify exact-SHA integration.** `verify-keycloak` and `verify-postgres` must both exercise the session expiry assertion under the non-owner/no-bypass runtime role; all existing identity and tenancy checks remain green.

### Task 3: Task 7 evidence convergence and independent attack

**Files:**
- Modify: `job/docs/engineering/MCH-S001-implementation-plan.md`
- Modify: `job/docs/handoffs/CHATGPT-CONTINUATION-2026-09-08.md` only when a new safe checkpoint is established.

**Interfaces:**
- Consumes: exact commit SHAs and GitHub Actions run/job IDs from Tasks 1-2.
- Produces: auditable Task 7 evidence status; does not produce candidate freeze or GAUNTLET PASS.

- [ ] **Step 1: Attack the evidence.** Check restart identity, timeout bounds, fail-closed behavior, stale state/code replay, secret leakage, application-session authority, database role flags, and whether any test can silently skip in the required CI workflow.
- [ ] **Step 2: Run an independent Critic review.** Search for Critical/Important misses across identity, security, session lifecycle, fault recovery, tenancy, concurrency and public-repository secret boundaries. Fix root causes and reverify any changed candidate.
- [ ] **Step 3: Update only proven checklist items.** Mark outage/restart, session-expiry and runtime secret-injection evidence complete only when exact-SHA CI supports each claim. Leave new/invited user lifecycle requirements open until separately implemented and evidenced.
- [ ] **Step 4: Preserve status semantics.** Final state after this plan remains `IN_PROGRESS` unless every remaining MCH-S001 task, independent review and `GNT-MCH-S001-001` has passed and the exact candidate is frozen/promoted/verified in GitLab.

## Self-review

- Spec coverage: this plan covers only the still-open reliability/expiry portion of Task 7; it intentionally does not absorb Task 8+, candidate freeze, promotion, or future roadmap work.
- Placeholder scan: no deferred implementation placeholders are used; every behavior has an explicit file, failure mode and verification path.
- Type consistency: all referenced production interfaces exist at current construction HEAD; no new production abstraction is introduced without a demonstrated RED.

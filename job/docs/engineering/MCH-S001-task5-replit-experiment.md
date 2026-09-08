# MCH-S001 Task 5 — Replit Experiment Checkpoint

Status: IN_PROGRESS
Experiment type: reversible development-environment trial
Rules changed: NONE

## Authority and invariants

- FORGE binding family/version: FORGE-OPS-HIGHEND v1.0.0.
- Canon: GitLab `machina-group/machina`.
- Construction repository: GitHub `r-sudo-jeferson/Machina`.
- Product root: `/job` only.
- Active Slice: `MCH-S001@1.0.0`.
- GAUNTLET: `GNT-MCH-S001-001`.
- Effective authorized GitLab base from canonical handoff: `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`.
- Existing construction branch remains `forge/mch-s001-1.0.0`.
- Exact verified pre-experiment GitHub SHA: `48349d0387c61e0b9057deaebfff706c7fecc87f`.
- Rollback branch: `checkpoint/mch-s001-task5-pre-replit-48349d`, pointing exactly to the verified SHA above.
- Experimental branch: `experiment/replit-mch-s001-task5`.
- No repository/project rules, AGENTS contracts, Slice, GAUNTLET, Stack Lock, or promotion semantics are changed by this experiment.

## Verified work that must not regress

Task 4 Rust authorization is verified within its own construction scope at SHA `48349d0387c61e0b9057deaebfff706c7fecc87f`.

Exact push verification evidence:

- Rust authorization workflow run: `34174811921` — SUCCESS.
- Repository contract workflow run: `34174811866` — SUCCESS.
- Exact checked SHA in workflow: `48349d0387c61e0b9057deaebfff706c7fecc87f`.

Verified Task 4 behavior includes:

- Cedar evaluator and starter owner/member policies.
- Forbid precedence and fail-closed evaluation behavior.
- Version-aware PostgreSQL policy source.
- Tenant/version policy cache.
- Protection against stale policy-cache downgrade races.
- Tonic gRPC `Decide` service.
- Health/readiness and process lifecycle.
- Real PostgreSQL policy-source harness.
- Strict Rust formatting, clippy, workspace tests.
- Exact-candidate performance harness.

Performance evidence on the verified SHA:

- Evaluator hot-cache p95: `5.811 µs`, 20,000 measured samples, 0 errors.
- gRPC hot-cache p95: `911.317 µs` (`0.911 ms`), 16,000 measured samples, 0 errors.
- Task 4 strict p95 target `<10ms`: PASS for this scoped benchmark.

Do not reinterpret this as complete Gate D, complete Gate H, full GAUNTLET PASS, candidate freeze, promotion, or COMPLETE.

## Task 5 current state

Task 5 is IN_PROGRESS at analysis/preflight stage. No Task 5 production implementation existed at the pre-experiment verified SHA.

Task 5 plan authority is the existing file-level plan under `/job/docs/engineering/MCH-S001-implementation-plan.md` and the existing premortem. Continue from those documents; do not replan the Slice from zero.

Task 5 objective:

- Go transaction, identity, tenant and session foundation.
- Mandatory transaction wrapper.
- Trusted active-context resolver.
- Server-side sessions.
- OIDC Authorization Code + PKCE callback/session lifecycle.
- Tenant create/join/switch APIs.
- Go fail-closed authorization client to the Rust authz service.

## Canonical Task 5 security/behavior constraints

Preserve all of the following:

- Browser OIDC flow uses Authorization Code + PKCE.
- PKCE S256, state, nonce, redirect/callback allowlist and session rotation are mandatory.
- Session and refresh material remain server-side.
- Browser receives secure HTTP-only SameSite cookies.
- Active identity/tenant/workspace is derived from trusted server session plus membership state, never from a raw tenant header, URL, request body, or stale browser state.
- Rust authorization receives subject/action/resource/context plus required policy version.
- Authorization uncertainty, timeout, transport failure, stale policy, crash or unavailable dependency denies access.
- Tenant-scoped database work runs in a PostgreSQL transaction with transaction-local tenant/identity context and RLS.
- Application runtime DB role is not owner or superuser.
- Transaction-local context must not leak through the pool after commit/rollback.
- No localStorage bearer/session tokens.
- CSRF defenses, replay defenses and open-redirect defenses are required.
- All mutations preserve the existing required Idempotency-Key and X-CSRF-Token OpenAPI contracts where applicable.

## Existing API contract to preserve

`/job/contracts/openapi/platform.yaml` already defines:

- cookie security scheme `__Host-machina_session`;
- required `Idempotency-Key` on mutations;
- required `X-CSRF-Token`;
- `GET /v1/session`;
- `POST /v1/tenants`;
- `POST /v1/tenant-switch`;
- `POST /v1/invitations/{token}/accept`;
- `GET /v1/context`;
- `POST /v1/ask/context`;
- RFC9457 Problem responses.

Do not redefine these contracts to make implementation easier.

## Existing database/security constraints to preserve

Key migrations already provide:

- subjects, tenants, workspaces, memberships, invitations, sessions and preferences;
- invitation token hashes and session token hashes as 32-byte values;
- tenant RLS using transaction-local `app.tenant_id`;
- FORCE RLS on tenant-owned tables;
- runtime role restrictions;
- last-owner protection through a SECURITY DEFINER membership function;
- audit/outbox/idempotency foundations.

Critical invariant: the runtime DB role currently has no generic direct CRUD permission on `iam.subjects` or `iam.sessions`. Do not weaken this by granting broad direct table access. If Task 5 requires runtime session/identity operations, use narrowly scoped, reviewed database interfaces/functions with strict grants and safe search_path rather than weakening default-deny boundaries.

## Recommended Task 5 execution order

1. Re-read both AGENTS contracts, this checkpoint, the existing implementation plan and premortem before making changes.
2. Inspect the real current GitHub experimental branch; never assume a generated architecture.
3. Verify current Go/OIDC dependency versions before pinning.
4. Start security-first with the transaction and narrow identity/session persistence boundary.
5. Use TDD for behavioral/security changes. First useful proof should demonstrate either:
   - transaction-local tenant context setup/cleanup under real PostgreSQL; or
   - runtime role cannot directly read sessions but can use an intentionally narrow session interface.
6. Implement OIDC state/nonce/PKCE primitives and server-side transient login state without exposing secrets.
7. Implement server-side session lookup/rotation/revocation and CSRF verification.
8. Implement trusted active tenant/workspace resolution from session plus live membership.
9. Implement Go authz client with strict deadlines and fail-closed semantics.
10. Implement tenant create/switch/invitation acceptance according to the frozen OpenAPI and database contracts.
11. Add API process/bootstrap only after underlying boundaries are tested.
12. Run project tests first, then repository/Machina verification. Do not weaken tests or expected behavior to manufacture green.

Real Keycloak integration/deployment is also covered by the later Keycloak preview task. Task 5 protocol/unit/component work may use deterministic test infrastructure, but Task 5 must not be declared fully verified until the required real Keycloak evidence exists.

## Replit experiment rules

Replit is being tested only as an additional development workspace.

During the experiment:

- Replit is NOT Canon.
- Replit is NOT a replacement for GitHub Actions evidence.
- Replit local/checkpoint state is NOT GAUNTLET evidence.
- Replit must operate from the experimental GitHub branch and must not rewrite from scratch.
- Do not modify root/product placement rules.
- Do not modify AGENTS, Slice, GAUNTLET, Stack Lock or authority files as part of this experiment.
- Never place production credentials, customer data, PII or private evidence into the Replit workspace.
- Development/preview-only secrets may be configured only through Replit secret facilities, never committed.
- Product changes must remain under `/job`.
- Every accepted change must be represented by a Git commit that can be rebuilt and retested by GitHub Actions.
- Candidate freeze, PASS, promotion and COMPLETE still depend on the existing FORGE flow, not on Replit success.

## Success criteria for the experiment

The Replit trial is useful only if it can:

- consume the existing codebase without rewriting architecture;
- respect the repository AGENTS and `/job` boundary;
- work on the experimental branch without polluting the verified construction branch;
- run the relevant Go/Rust/Node tooling without weakening contracts;
- produce reviewable Git commits;
- allow GitHub Actions to reproduce and verify those commits from a fresh runner;
- preserve public-boundary and secret-management requirements.

If those conditions fail, stop the experiment and resume from the rollback branch/SHA without changing the existing project architecture.

## Recovery procedure

If Replit import, Agent behavior, environment setup, dependency resolution, Git synchronization, tests, security boundaries or workflow reproduction do not behave as planned:

1. Stop accepting Replit-originated changes.
2. Treat every unverified experimental commit as disposable.
3. Return to `checkpoint/mch-s001-task5-pre-replit-48349d` / SHA `48349d0387c61e0b9057deaebfff706c7fecc87f`.
4. Confirm Task 4 exact evidence remains the runs recorded above.
5. Resume Task 5 from the Task 5 current-state and execution-order sections of this checkpoint.
6. Do not alter Slice/GAUNTLET criteria to accommodate the experiment.
7. Continue on the original construction model unless a future explicit Founder decision adopts Replit permanently.

## Current overall truth

- Slice: MCH-S001@1.0.0 — IN_PROGRESS.
- Task 4: VERIFIED in its scoped construction state at the checkpoint SHA.
- Task 5: IN_PROGRESS, pre-implementation at the checkpoint SHA.
- GAUNTLET: NOT_VERIFIED.
- Independent final critic: NOT_VERIFIED.
- Candidate freeze: not done.
- Promotion: not done.
- GitLab result SHA: none.
- Overall final state: IN_PROGRESS.

# MCH-S001 Task 6/7 Convergence Evidence — 2026-09-09

**Binding:** `FORGE-OPS-HIGHEND-v1.0.0`  
**Slice:** `MCH-S001@1.0.0`  
**GAUNTLET:** `GNT-MCH-S001-001`  
**Authorized GitLab base:** `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`  
**Construction branch:** `forge/mch-s001-1.0.0`

This file records task-level construction evidence only. It is not a GAUNTLET PASS, candidate freeze, promotion record, production-readiness claim, or Slice completion claim.

## Task 6 rollback evidence

The remaining Task 6 rollback requirement is supported by the real PostgreSQL/Rust/Go integration on construction SHA `96da7647b93caba8d61a1e8de9070236f802530a`:

- PostgreSQL workflow `34390156897`, job `102596596592`: `success`.
- Runtime introspection: `runtime_role_flags=0:0:0:0`, `owner_violations=0`, `rls_violations=0`, `tenant_key_violations=0`.
- `TestTenantSwitchRollbackWithoutCheckpointerAgainstPostgreSQL`: PASS. The API coordinator is intentionally constructed without a Checkpointer/checkpoint worker. Audit insertion and the database-owned chain remain mandatory.
- Injected audit-chain failure returns PostgreSQL `55000` and rolls back receipt/audit/chain/outbox state to zero while retaining the original session.
- After the chain is restored, the same request commits exactly once; replay returns the committed historical result without duplicating receipt/audit/chain/outbox state.
- `TestTenantSwitchCoordinatorAgainstPostgreSQL/audit_insert_failure` and `/outbox_insert_failure`: PASS on the same final kernel run.

**Critic result:** disabling asynchronous checkpoint scheduling does not bypass mandatory audit/chain enforcement on API mutations. The rollback model remains forward-only: application/worker rollback may disable checkpoint scheduling, but must not reverse audit privilege hardening or chain enforcement.

## Task 7 Keycloak preview convergence

### Real identity lifecycle and reliability

Construction SHA `60d7b3610eb2da9a993ef411d1ae31434d35befa`:

- Keycloak workflow `34390112377`, job `102596064181`: `success`.
- Go workflow `34390112582`, job `102596065825`: `success`, including module integrity, gofmt, `go vet`, repository contracts, normal tests and race safety selected by the workflow.

The clean-environment Keycloak run passed all of these real-provider cases:

- Authorization Code + PKCE browser login.
- Existing subject convergence and concurrent independent PostgreSQL sessions.
- Real invited-user login, server-side subject/session establishment and invitation acceptance.
- Signed ID-token expiry rejection using the actual Keycloak-signed token.
- Expired server-side application-session rejection and non-rotatability.
- Provider outage detection while the exact container is stopped.
- Recovery after restart of that same container identity.
- Full provider destroy/recreate from the locked Keycloak 26.7.3 OCI image and repository-versioned realm template, with a different container ID.
- Real Authorization Code + PKCE again after recreation.

The invited-user test also verifies that the runtime role is `machina_runtime` with no superuser/createdb/createrole/replication/bypass-RLS flags, that the runtime has no direct `SELECT` on `iam.invitations`, and that acceptance is available only through the bounded function.

### Invitation security RED and correction

Security RED SHA `72d835e675d5b4f82fd8b898151c3af8730f5191`:

- Keycloak workflow `34388445879` failed in `TestKeycloakOIDCInvitedUserAgainstPostgreSQL` because `machina_runtime` still had direct `SELECT` on `iam.invitations`.
- Root cause: historical `0007_integrity.sql` table grants predated the narrow invitation-acceptance boundary.

Correction:

- Added forward-only migration `0019_invitation_privilege_hardening.sql` rather than rewriting migration history.
- `0019` revokes all direct table privileges on `iam.invitations` from `machina_runtime` and preserves only `EXECUTE` on `iam.accept_invitation(bytea, uuid)`.
- The focused PostgreSQL test now requires direct `SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER` privileges to be `0:0:0:0:0:0:0` and requires a direct runtime table read to fail.
- The aggregate PostgreSQL kernel now executes migrations `0018` and `0019` and reruns the same invitation boundary.

Final database evidence on SHA `96da7647b93caba8d61a1e8de9070236f802530a`:

- PostgreSQL workflow `34390156897`, job `102596596592`: `success`.
- Focused result: `invitation acceptance fail-closed/idempotent boundary passed` and `PostgreSQL 18.6 invitation profile boundary passed`.
- Aggregate result: final invitation boundary passed again and `PostgreSQL 18.6 tenancy/RLS kernel passed`.
- Rust 1.98.1 authorization binary build and the Go/Rust/PostgreSQL tenant-switch integrations also passed inside that workflow.

### Token and tenancy boundary

- The application store hashes the presented invitation token with the existing SHA-256 `HashToken` boundary before calling sqlc; the database receives only a 32-byte hash plus authenticated subject UUID.
- `iam.accept_invitation(bytea, uuid)` is `SECURITY DEFINER` with `search_path=pg_catalog` and `row_security=on`.
- The function resolves the opaque hash, establishes transaction-local tenant context, serializes on the tenant row, re-reads and locks the canonical invitation, then rejects expired/revoked/wrong-subject/suspended/conflicting membership state.
- Same-subject replay is idempotent and cannot duplicate membership state.
- A second subject cannot reuse an accepted invitation.
- Migrator-only test fixtures now establish transaction-local tenant context and therefore continue to obey FORCE RLS; no superuser/bypass role was introduced to make tests pass.

### Secrets and clean environment

- Keycloak workflow invokes the harness through `env -i` and passes only the minimal process environment required by the runner.
- Keycloak client/admin credentials are generated ephemerally inside the harness with `openssl rand -hex 32`; committed realm configuration contains placeholders and no users/credentials.
- Repository secret scan on SHA `b01a5684f127cab103b59281250ba61a2450ec1e`, workflow `34389398201`: `success`. Later changes through `96da7647...` are test-fixture/test-harness changes only; exact-candidate secret scan remains mandatory before GAUNTLET/candidate freeze.

### CI dependency correction

The Keycloak workflow path filter was strengthened so changes to `job/db/migrations/**`, `job/internal/platform/db/**`, `job/internal/platform/identity/**`, `job/go.mod`, and `job/go.sum` re-run the real Keycloak integration. This prevents a database/identity change from leaving the lifecycle gate stale.

## Separated Critic review

Reviewed the Task 7 construction surface for tenancy/RLS bypass, SECURITY DEFINER misuse, raw-token persistence, replay, wrong-subject reuse, direct table privilege bypass, provider outage/recovery, committed secrets, test-only privilege escalation, and product-contract regression.

**Critical findings:** none unresolved.  
**Important findings:** none unresolved.

The one material finding during review/execution was the direct runtime `iam.invitations` privilege. It was preserved as failing evidence, corrected at the privilege boundary with additive migration `0019`, and reverified by both catalog-level PostgreSQL checks and the real Keycloak invited-user integration.

A possible future strengthening is to assert PUBLIC function privilege explicitly in the focused catalog test. The migration already executes `REVOKE ALL ON FUNCTION iam.accept_invitation(bytea, uuid) FROM PUBLIC`; no demonstrated bypass remains, so this is not classified as a Slice-blocking finding.

## State

- Task 6 rollback requirement: evidence-supported for checklist closure.
- Task 7 five implementation-plan requirements: evidence-supported for checklist closure.
- Full Slice: `IN_PROGRESS`.
- GAUNTLET `GNT-MCH-S001-001`: `NOT_VERIFIED` in this evidence record.
- GitHub candidate: not frozen.
- GitLab promotion: not performed.
- `COMPLETE`: not applicable.

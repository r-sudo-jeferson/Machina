# MCH-S001 Task 7 Identity Profiles Plan

**Binding:** `FORGE-OPS-HIGHEND-v1.0.0`  
**Slice:** `MCH-S001@1.0.0`  
**GAUNTLET:** `GNT-MCH-S001-001`  
**Authorized GitLab base:** `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`

## Goal

Close the remaining Task 7 identity-profile evidence for new, existing, invited, and concurrent-session users using the real Keycloak + PostgreSQL boundaries already built. Preserve the existing OpenAPI invitation contract and tenant/session architecture; do not pull Task 9 UI work forward.

## Existing contracts and invariants

- `POST /v1/invitations/{token}/accept` already requires authenticated session, CSRF, and idempotency key and returns `Membership`.
- `iam.invitations` stores only a 32-byte token hash and states `pending|accepted|revoked|expired`.
- `iam.memberships` permits `owner|member` and `active|revoked`; revoked membership must never be silently reactivated.
- `AuthenticatedSessionService` generates a candidate subject UUID per login, while `iam.upsert_subject` canonicalizes by verified OIDC `external_subject`.
- Runtime direct access to `iam.subjects` and session tables is revoked. Tenant-scoped data is FORCE RLS.
- Invitation resolution starts from an opaque token before tenant context exists, so cross-tenant token lookup must stay behind a narrow `SECURITY DEFINER` function. Runtime must never receive unscoped invitation-table access.

## Task A — Invitation acceptance database boundary

**Files:**
- Add migration `job/db/migrations/0018_invitation_acceptance.sql`.
- Add query contract in `job/db/queries/tenancy.sql` or a focused `job/db/queries/invitations.sql`.
- Regenerate `job/internal/platform/db/sqlcgen/**` with locked sqlc 1.31.1.
- Add `job/scripts/dbtest/check_invitation_acceptance.sh` and wire it into `job/scripts/dbtest/run.sh`.

**Behavior:**
1. RED: database integration test requires a runtime-callable invitation acceptance boundary; it must fail because the function does not yet exist.
2. Implement a narrow `iam.accept_invitation(token_hash, subject_id)` function with immutable token-hash validation, row locking, tenant-status check, expiry/revocation checks, expected-subject binding, and transaction-local tenant context before membership mutation.
3. First valid acceptance creates one active membership and marks the invitation accepted atomically.
4. Replay by the same subject returns the same membership without duplicate writes.
5. Replay by another subject fails closed.
6. Suspended tenant, revoked/expired invitation, expired timestamp, pre-bound invitation for another subject, revoked existing membership, and conflicting active role all fail closed.
7. Existing active membership with the same invited role may complete the invitation idempotently; role escalation is never inferred from an invitation replay.
8. Runtime gets EXECUTE only. No runtime cross-tenant SELECT/UPDATE privilege is introduced.

## Task B — Go invitation store/service

**Files:**
- Add `job/internal/platform/identity/invitation_store.go` plus tests.
- Use the generated sqlc call; hash raw invitation token in Go before database access.

**Behavior:**
1. Reject empty/invalid subject IDs and token inputs before database calls.
2. Never log, persist, or return raw invitation tokens.
3. Return only the Membership fields required by OpenAPI.
4. Preserve database error identity sufficiently for HTTP/problem mapping later; do not hide authorization/conflict failures as success.

## Task C — Real Keycloak new/existing/invited profile evidence

**Files:**
- Add focused integration coverage under `job/internal/platform/identity/keycloak_*_integration_test.go`.
- Extend `job/scripts/keycloaktest/run.sh` only to select the new integration tests; keep clean-env, secret generation, outage/restart/recreate evidence unchanged.

**Behavior:**
1. New user: create ephemeral Keycloak user, complete Authorization Code + PKCE, establish application session, and assert a real internal subject is created.
2. Existing user: log in again as the same Keycloak `sub`; assert the same internal `subject_id` is reused while the session token/CSRF token remain independent.
3. Invited user: create a pending invitation fixture under migrator authority using only a hashed opaque token; authenticate a separate real Keycloak user, establish its application subject/session, accept through the runtime invitation boundary, and assert the expected active membership.
4. Replay the invitation with the same subject and assert stable membership; attempt reuse from a different authenticated subject and require fail-closed behavior.
5. Confirm `ListSessionTenants` sees the invited tenant only after acceptance and tenant status remains active.
6. Preserve existing concurrent-session evidence; do not substitute mocks for Keycloak or PostgreSQL.

## Verification and attack

- Exact-SHA `verify-postgres`, `verify-sqlc`, `verify-go`, `verify-keycloak`, `verify-secrets`, Rust authz, and formatting checks must be green when triggered.
- Attack token replay, subject mismatch, role escalation, revoked membership resurrection, suspended tenant acceptance, expiry races, cross-tenant token lookup, direct runtime table access, and duplicate concurrent acceptance.
- Independent Critic must review the completed Task 7 surface before its checklist is marked complete.
- Task 7 PASS does not imply GAUNTLET PASS, candidate freeze, promotion, or Slice COMPLETE.

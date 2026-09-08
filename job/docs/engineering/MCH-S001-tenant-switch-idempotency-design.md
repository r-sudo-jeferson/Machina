# MCH-S001 Tenant-Switch Idempotency Design

**Status:** Approved direction; design review incorporated; implementation pending  
**Slice:** `MCH-S001@1.0.0`  
**Binding:** `FORGE-OPS-HIGHEND-v1.0.0`  
**Decision:** strict session-token invalidation with reauthentication after a lost cookie response

## Context

Tenant switch already rotates the session and CSRF secrets atomically. The old
session token becomes invalid as soon as the transaction commits. The generic
idempotency boundary is tenant-scoped, but a session may have no active tenant
before its first selection and its active tenant changes during a successful
switch.

A naive `Claim -> Switch -> Complete` under either the source or requested
tenant is therefore unsafe:

- the source tenant can be absent and changes after the switch;
- using the requested tenant before membership validation makes untrusted input
  an authority boundary;
- the same session could reuse one key against another target tenant and escape
  a tenant-local conflict;
- a lost response cannot be replayed with the old token because that token must
  remain invalid;
- storing raw replacement cookies in an idempotency response would undermine
  the hashed-session design.

## Decision

Keep strict invalidation. A stale request carrying the pre-switch cookie never
recovers or replays replacement credentials. It fails authentication and the
user recovers by authenticating again.

For authenticated retries, add a non-secret, session-stable mapping between the
session and the tenant-scoped idempotency record. The stable scope is
`session_id + idempotency_key`; the session ID does not change when secrets are
rotated. The existing `ops.idempotency_keys` table remains the sole store of the
completed mutation outcome and original correlation ID.

No raw session token, raw CSRF token, token ciphertext, or token-derived
recovery capability is persisted in either record.

## Data boundary

Migration `0014` will add `iam.tenant_switch_idempotency_scopes` with:

- `session_id` and `idempotency_key` as the primary key;
- the canonical operation name and request-body hash;
- the validated target tenant ID;
- the session generation at claim and the generation produced by completion;
- creation and expiry timestamps;
- foreign keys to the session and target tenant. Target deletion is restricted
  while any mapping remains; a narrow cleanup deletes expired mappings before a
  future tenant-deletion workflow proceeds.

Migration `0014` will also add a monotonic `generation` to `iam.sessions`.
Session rotation and tenant switch increment it atomically and return the new
value. A completed mapping is replayable only while its recorded result
generation is still the current session generation. Logout, expiry, revocation,
or any later rotation/switch invalidates replay of the historical outcome.

Runtime receives no direct table privileges. A narrow `SECURITY DEFINER`
function will:

1. locate and lock the active session using the presented token hash;
2. revalidate the target tenant, active membership, and existence of the
   server-selected workspace;
3. insert, reuse, or reject the stable session/key mapping;
4. reject the same session/key with a different operation, body hash, or target;
5. set transaction-local `app.tenant_id` only after successful validation;
6. return the stable session ID, mapping state, session generation, one
   authoritative expiry, and validated target context without exposing stored
   secret hashes.

The function will use the existing transaction-local cross-tenant capability
only inside its security-definer body. Direct runtime reads remain revoked.
The binder chooses one immutable deadline for each claim generation:
`min(database wall-clock + 24 hours, session expiry)`. It returns that exact
deadline, and `idempotency.Store.Claim` must use it unchanged. The generic claim
result will expose the database record's expiry so the coordinator can require
exact equality. A live mapping paired with a missing, newly claimed, expired, or
differently expiring tenant receipt is an invalid state and fails closed.

Retries never extend the deadline. After it expires, the same active session
may reuse the key, including for a different target, only when both the mapping
and tenant receipt are expired and rewritten atomically. A mismatch in either
expiry direction rolls back the attempted rebind. Target deletion is blocked by
the mapping foreign key until expired mappings are removed; deletion never
cascades a live mapping and silently frees its key.

## Canonical request identity

The endpoint operation is `tenant.switch.v1`.

The request-body hash is lowercase SHA-256 over a versioned canonical encoding
of the tenant-only request. After the binder returns the authoritative session
ID, the tenant-local idempotency hash is lowercase SHA-256 over:

```text
tenant.switch.v1\n<session-id>\n<request-body-hash>
```

Binding the session ID into the tenant-local hash prevents another session in
the same tenant from replaying a response created for a different identity.
The idempotency key itself is not part of either hash.

## Transaction flow

The Go database transactor will gain a fail-closed unscoped transaction method.
Immediately after `BEGIN`, it executes
`set_config('app.tenant_id', '', true)` and rolls back if clearing fails. Only
then may it expose transaction-bound queries to the callback. Tenant RLS rows
are therefore unavailable inside this controlled callback until the
tenant-switch binder establishes a validated target. This guarantee does not
authorize arbitrary queries outside a transaction or replace pool hygiene.

Within one PostgreSQL transaction:

1. clear any inherited tenant GUC;
2. bind the active session and idempotency key to the authorized target;
3. recheck the locked session token, revocation state, and absolute expiry
   against database wall-clock time after any lock wait;
4. lock the membership, tenant, and selected workspace rows for shared access,
   making authorization linearize against concurrent revocation, suspension, or
   deletion;
5. create a transaction-bound `idempotency.Store`;
6. claim the tenant-local idempotency key using the binder's exact deadline;
7. validate that mapping state, claim state, and stored expiry form an allowed
   pair;
8. on `claimed`, generate independent replacement secrets, execute the existing
   server-validated session switch, serialize the non-secret mutation outcome,
   record the resulting session generation, and complete the idempotency record;
9. on `replay`, validate and return the stored non-secret historical outcome
   without rotating secrets again;
10. on `in_progress`, `conflict`, `stale`, an impossible paired state, or any
    mutation or completion error, fail closed and roll back;
11. commit only after scope binding, claim, switch, generation binding, and
    completion all succeed.

The initial response publishes replacement cookies only after a confirmed
commit. A replay made with the current session returns the original non-secret
outcome and does not emit replacement cookies.

If commit outcome is uncertain, no replacement cookie is published. Because the
database may nevertheless have committed, recovery is reauthentication. This
is intentional for the selected strict-invalidation policy.

## Go boundaries

- Keep `idempotency.Store` generic and transaction-bound through its narrow
  queries interface.
- Keep `SessionStore.SwitchContext` tenant-only and reuse its existing hashing
  and database mapping.
- Add an identity-owned transaction coordinator for tenant switch. It owns
  canonical hashing, state handling, token generation timing, outcome
  serialization, and post-commit cookie eligibility.
- Distinguish `claimed` from `replay` in the result so the HTTP layer cannot set
  new cookies on replay.
- Preserve `errors.Is` through every wrapper and use typed errors for scope
  conflict, in-progress work, invalid replay, and uncertain commit.

The stored outcome contains only the authoritative active tenant ID, active
workspace ID, session generation, and session expiry. It never contains browser
secrets. It is explicitly a historical mutation outcome and must not be enriched
with the live authenticated-context resolver, which could combine facts from
different points in time. Before the HTTP endpoint can claim exact replay, it
must store and replay one immutable full non-secret OpenAPI response and ETag
snapshot, or adopt another separately approved and tested stale-response policy.

## Observable retry behavior

| Request state | Result |
|---|---|
| First valid request | Switch once, commit outcome, then set replacement cookies |
| Same key/body with current replacement cookies | Replay outcome, no rotation, no `Set-Cookie` |
| Same key with another target/body | Conflict, no mutation |
| Same key from another session in the same target tenant while unexpired | Conflict at tenant-local claim, no response leak |
| Old session cookie after committed switch | Unauthorized; reauthentication required |
| Old/new cookie or CSRF mixture | Unauthorized or forbidden; never a recovery path |
| Old key after another successful rotation/switch | Stale-generation failure; never replay old context |
| Revoked/expired session or membership | Denied before mutation |
| Suspended target tenant | Denied before mutation |
| Failure before commit | Full rollback; original session remains valid |
| Uncertain commit | No cookies emitted; reauthentication required |

## Verification contract

Implementation proceeds test-first and must cover:

- first selection when the session has no active tenant;
- successful tenant-only switch and authoritative workspace selection;
- atomic scope, claim, rotation, and completion;
- rollback at every injected failure point;
- same-key current-session replay without token generation or rotation;
- same key with changed target, operation, or request hash;
- cross-session key reuse without response disclosure;
- same-key concurrency and exactly one committed switch;
- two concurrent requests with the old cookie: one commit and a waiter that
  rechecks the token after its lock wait and fails authentication;
- a lock wait that crosses absolute session expiry;
- stale old cookie and every old/new session/CSRF combination;
- revoked membership, suspended tenant, expired/revoked session, and logout;
- pooled connection reuse with no retained tenant context;
- a deliberately pre-seeded session-level tenant GUC that is cleared before the
  unscoped callback;
- exact mapping/receipt expiry equality, both mismatch directions, immutable
  retry deadline, and rollback of attempted live-key rebinds;
- session-generation invalidation after a later switch or rotation;
- target deletion blocked while a mapping is live and allowed only after
  explicit expired-mapping cleanup;
- request-hash canonicalization and malformed stored outcome rejection;
- absence of raw session/CSRF material in idempotency tables, audit, logs, and
  test evidence;
- sqlc regeneration zero-diff, real PostgreSQL runtime-role tests, Go race tests,
  and the existing repository verification workflows.

This design does not declare the tenant-switch HTTP endpoint or Gate B/F
complete. Those claims require the full handler, audit/outbox integration,
OpenAPI response behavior, real database concurrency evidence, and GAUNTLET.

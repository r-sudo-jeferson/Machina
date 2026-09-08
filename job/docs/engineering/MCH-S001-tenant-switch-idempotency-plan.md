# Tenant-Switch Transaction Boundary Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans or superpowers:subagent-driven-development to execute each task with its own RED/GREEN and independent review.

**Goal:** Implement the approved strict-invalidation tenant-switch retry policy.

**Architecture:** The Go coordinator uses one database transaction whose initial tenant context is explicitly empty. A session-owned scope binds the key to the validated tenant; the existing tenant idempotency store holds the non-secret outcome. A session generation prevents replay after later rotations.

**Tech Stack:** Go 1.27.1, pgx/v5, sqlc 1.31.1, PostgreSQL 18.6.

**Spec:** `job/docs/engineering/MCH-S001-tenant-switch-idempotency-design.md`.

## Global constraints

- `MCH-S001@1.0.0`, `FORGE-OPS-HIGHEND-v1.0.0`.
- All files below are under `job`; existing workflow glue remains minimal.
- No Python, no secrets in stored outcomes, no direct runtime receipt CRUD.
- Old credentials fail authentication after commit; lost cookies require reauthentication.
- Do not publish cookies on callback failure, commit failure, or replay.
- Preserve tenant-only caller input and server-owned workspace selection.
- Construction checks do not constitute `GNT-MCH-S001-001` PASS.

## Task 1: Transaction with explicitly empty tenant context

**Files:** modify `internal/platform/db/transactor.go`; create `internal/platform/db/unscoped_transaction_test.go`.

**Produces:** `(*Transactor).WithinUnscoped(context.Context, func(context.Context, *sqlcgen.Queries) error) error`; typed `ErrTransactionCommit` preserving the underlying database error.

- [ ] Write tests using the package's `recordingTx`, extended only as needed in the new test file. Seed an inherited tenant value; require a local clear before the callback; verify callback failure, context-clear failure, commit failure, cancellation-independent rollback, nil config, nil callback, and begin failure.

```go
err := transactor.WithinUnscoped(ctx, func(ctx context.Context, q *sqlcgen.Queries) error {
    if len(tx.execs) != 1 || tx.execs[0].sql != "SELECT set_config('app.tenant_id', '', true)" {
        t.Fatal("callback exposed before tenant context was cleared")
    }
    return callbackErr
})
if !errors.Is(err, callbackErr) || !tx.rolledBack || tx.committed {
    t.Fatal("callback failure did not roll back")
}
```

- [ ] Run `go test -count=1 ./internal/platform/db`; observe missing-method RED.
- [ ] Implement by sharing the existing begin/callback/commit/rollback lifecycle while preserving `WithinTenant`'s UUID cast and validation. The unscoped setup statement has no caller parameters.

```go
if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', '', true)"); err != nil {
    return fmt.Errorf("clear transaction tenant context: %w", err)
}
// On commit error, preserve both the stage and driver cause.
return fmt.Errorf("%w: %w", ErrTransactionCommit, err)
```

- [ ] Run db race tests, full Go tests, vet, and repository guards; commit the tested change and observe the exact GitHub run.

## Task 2: Session generation and expiry after lock waits

**Files:** create `db/migrations/0014_session_generation.sql`, `scripts/dbtest/check_session_generation.sh`; modify `scripts/dbtest/run.sh`.

**Consumes:** existing `iam.rotate_session` and `iam.switch_session_context`.
**Produces:** internal monotonic `iam.sessions.generation bigint`; same existing function signatures and result shapes, so prior callers remain compatible. The new scope binder reads the generation from the locked session without exposing credential hashes.

- [ ] Add real runtime-role tests before adding the migration. Assert generation starts at 1, successful rotation/switch increments exactly once, failed switches and rollback preserve generation, old tokens stay inactive, and a lock wait crossing absolute expiry denies mutation.

```sql
SELECT generation FROM iam.sessions WHERE id = :'session_id';
BEGIN;
SELECT * FROM iam.rotate_session(:'current_hash', :'next_hash', :'next_csrf');
ROLLBACK;
-- The migration-owner/superuser observation must equal the original generation.
```

- [ ] Publish the test-only commit, require PostgreSQL RED for missing generation, then add an additive migration. Use a `BEFORE UPDATE` trigger for generation changes on credential/context changes so every mutation path increments it. Reject manual generation changes without a corresponding credential/context change and require finite future session expiry after lock acquisition.
- [ ] Replace the two security-definer function bodies without changing their return types. Recheck session expiry using `clock_timestamp()` after row locking; retain all input validation. In tenant switch, lock tenant then membership then workspace for shared access so revocation/suspension cannot race the authorized mutation.
- [ ] Run unchanged db tests plus new tests, sqlc zero-diff, and Go checks. The trigger adds no generated-query result fields and avoids return-type compatibility changes.

## Task 3: Stable session/key scope and receipt consistency

**Files:** create `db/migrations/0015_tenant_switch_idempotency_scope.sql`, `db/queries/tenant_switch.sql`, `scripts/dbtest/check_tenant_switch_idempotency_scope.sh`; regenerate `internal/platform/db/sqlcgen`; modify the design's migration-number references.

**Produces:** `iam.bind_tenant_switch_idempotency(current_hash bytea, key text, request_hash text, target uuid)` returning mapping state, session ID, generation, selected workspace, session expiry, and receipt expiry; `iam.finish_tenant_switch_idempotency(current_hash bytea, key text, request_hash text)` verifying completed tenant receipt and recording current generation. Operation is fixed server-side to `tenant.switch.v1`.

- [ ] Write runtime-role tests for no initial tenant, same key/changed target conflict, revoked membership, suspended tenant, active-session proof, no CRUD, RLS, deadline mismatch, no refresh, foreign-key deletion protection, and generation invalidation. Publish RED before the migration.
- [ ] Implement binder under the active-session lock. Clear capability settings on return; establish target tenant only after authorization. Bind deadline to `least(clock_timestamp() + interval '24 hours', session.expires_at)`; reuse exactly the stored deadline. Check the old mapping's paired receipt under its recorded tenant before allowing expired-target rebind. Do not expose unrelated receipt contents.
- [ ] Verify the receipt in the security-definer boundary as well as the coordinator. Pair state and expiry are checked before returning an existing scope and again during finish. A deferred constraint trigger rejects committing an incomplete new scope or a scope whose completed receipt/deadline does not match.
- [ ] Generate sqlc with the repository-pinned binary and require zero-diff on CI. Keep narrow explicit column lists.

```text
bodyHash = sha256("tenant.switch.v1\n" + canonicalLowercaseTenantUUID)
receiptHash = sha256("tenant.switch.v1\n" + sessionUUID + "\n" + bodyHash)
new scope + claimed receipt -> mutate, complete, finish
completed scope + replay receipt + same generation/deadline -> replay
every other pair -> rollback
```

## Task 4: Go mutation coordinator

**Files:** create `internal/platform/identity/idempotent_tenant_switch.go` and its test file; add scope adapter using `WithinUnscoped` and generated queries.

**Produces:** a result with the immutable non-secret outcome, original correlation, replay flag, and cookie material only for a newly committed switch. The coordinator uses `idempotency.NewStore(q)` and `NewSessionContextSwitchService(NewSessionStore(q))` inside the same callback.

- [ ] Write tests for claimed/replay/conflict/in-progress/invalid scope, malformed outcome, generation mismatch, key/hash validation, callback rollback and uncertain commit. Token generation is forbidden on replay; no result with secrets may escape a failed transaction.

```go
var pending SwitchResult
err := scope.WithinUnscoped(ctx, func(ctx context.Context, q *sqlcgen.Queries) error {
    // Bind, claim, validate state pair, mutate only on claimed, complete, finish.
    return nil
})
if err != nil { return SwitchResult{}, err }
return pending, nil
```

- [ ] Observe RED, implement those states, then run identity/idempotency/db race tests and full Go workflow.
- [ ] Add real concurrency tests: two old-cookie requests yield one commit and one unauthorized waiter; current-cookie retry does not rotate; later generation invalidates the older key.

## Task 5: HTTP response, audit/outbox, and full integration

**Files:** tenant-switch HTTP handler/tests, existing OpenAPI contract, identity coordinator response adapter, audit/outbox packages according to the parent Slice plan.

- [ ] Persist the complete non-secret OpenAPI response and ETag snapshot inside the mutation transaction. Resolve all identity/context/policy facts using transaction-bound dependencies; never merge replayed coordinates with a fresh context resolver.
- [ ] Insert correlated audit/outbox events in that transaction; replay does not duplicate mutation events. Failure of either insertion rolls back session rotation and receipt.
- [ ] Test old/new session-CSRF combinations through the real middleware, RFC9457 failures, original correlation, no-store responses, and absent `Set-Cookie` on replay/errors.
- [ ] Independent critique maps each design requirement to Go/SQL/HTTP evidence. Run full Slice verification and GAUNTLET only after the remaining parent-plan requirements are implemented.

## Execution record

No task is complete merely because its files exist. Record test-only and implementation commits and exact workflow results when each task closes. Continue with the existing parent Slice plan after this boundary; no candidate freeze or promotion precedes the real GAUNTLET.

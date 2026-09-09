# MCH-S001 Immutable Audit Chain and Signed Checkpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the MCH-S001 minimum audit-integrity boundary by making every runtime audit append database-enforced and tamper-evident, then producing provider-neutral signed checkpoints over immutable tenant-scoped chain heads without holding a database transaction open during signing.

**Architecture:** Keep the existing atomic domain → audit → outbox transaction and existing `audit.events.event_hash` content commitment. Add a PostgreSQL-owned per-tenant append chain whose authoritative `previous_chain_hash`, sequence, and `chain_hash` are allocated by an `AFTER INSERT` trigger under a serialized per-tenant head row; runtime cannot update/delete audit history or write chain state directly. A Go checkpointer reads an immutable chain head, closes that database transaction, signs a versioned SHA-256 checkpoint statement through a narrow context-aware signer interface, verifies the signature before persistence, then stores an immutable checkpoint in a new tenant transaction. Signing is asynchronous from API mutations: checkpoint/signing failure can delay anchoring but can never make an API mutation skip its mandatory audit insert or chain append.

**Tech Stack:** Go 1.27.1 standard `crypto`, `crypto/ecdsa`, `crypto/sha256`, `encoding/binary`; pgx/v5; sqlc; PostgreSQL 18.6 built-in `sha256(bytea)` and `bytea` concatenation; existing RLS/non-owner runtime model. Signature contract is fixed to ECDSA P-256 over SHA-256 (`ecdsa-p256-sha256`) and exposes no private key material. No Python and no provider SDK are introduced by this plan.

**Spec:** Canonical GitLab `job/docs/slices/MCH-S001.md` AC-S001-10 and Gate I; `job/docs/architecture/SAAS-PLATFORM-2026-2027.md` requirements for immutable audit events, signed checkpoints, KMS/secret-manager workload identity, and Go-worker audit checkpointing; `job/docs/engineering/MCH-S001-implementation-plan.md` Task 6; `job/docs/engineering/MCH-S001-premortem.md`; `job/db/MIGRATION-RECOVERY.md`.

## Global Constraints

- Active Slice remains exactly `MCH-S001@1.0.0`; GAUNTLET remains `GNT-MCH-S001-001`; active binding remains `FORGE-OPS-HIGHEND-v1.0.0`.
- Authorized GitLab product base remains `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`; GitLab remains the only Canon.
- Construction remains GitHub `r-sudo-jeferson/Machina` branch `forge/mch-s001-1.0.0`; all product/test/docs changes remain under `job/**` except provider-required root workflow glue.
- Preserve the verified tenant-switch ordering: Cedar authorization → idempotency claim → session mutation → audit insert → outbox insert → receipt completion → scope finish → commit.
- Audit/chain failure inside an API mutation remains transaction-fatal; checkpoint signer/worker failure after committed audit data must not roll back or bypass an already-audited API mutation.
- Runtime database role remains non-owner, non-superuser, non-`BYPASSRLS`, and never receives migration-owner credentials.
- `audit.events`, chain rows, and checkpoints are append-only history. Runtime must not have `UPDATE`, `DELETE`, `TRUNCATE`, `TRIGGER`, or `REFERENCES` privilege over them.
- Tenant RLS and tenant-qualified keys remain mandatory on every new tenant-owned audit table.
- `event_hash` remains the existing SHA-256 content commitment. Authoritative chain linkage is new database-owned state; callers no longer control chain linkage.
- Chain genesis is exactly 32 zero bytes. For event N, `chain_hash = SHA256(previous_chain_hash || event_hash)`.
- Same-tenant concurrent appends must serialize without forks or duplicate sequence numbers; different tenants must not share head state or block on one shared global chain lock.
- A checkpoint signs one immutable prefix. New events committed after head acquisition do not invalidate that checkpoint.
- Checkpoint statement version, algorithm, tenant UUID, checkpoint UUID, chain sequence, chain hash, UTC signed timestamp, and key ID are all committed by the signature.
- Signing key IDs are bounded non-secret identifiers only; no private key, secret, credential, `.env`, customer data, KMS token, or private evidence enters the public GitHub repository.
- Do not add AWS/GCP/Azure KMS SDKs in this Slice. The production seam is provider-neutral; target-provider/OIDC adapter wiring belongs to the deployment boundary that actually selects the provider.
- Never keep a PostgreSQL transaction or per-tenant chain lock open while performing external signing or public-key retrieval.
- No generic job framework, audit search/export product, retention engine, privacy portal, legal hold, or S009 capability is introduced here.
- Migrations remain forward-only/additive according to `job/db/MIGRATION-RECOVERY.md`; no down migration, historical DELETE, TRUNCATE, or destructive rewrite is allowed.
- Project tests run before Machina/GAUNTLET. This plan may close only Task 6 audit-chain/checkpoint/rollback evidence; it does not complete Gate I, Task 6 globally, GAUNTLET, candidate freeze, promotion, or Slice completion.

---

## File Map

### Database integrity

- Create `job/db/migrations/0017_audit_integrity_checkpoints.sql`: append-only privileges/triggers, per-tenant chain head, immutable event-chain rows, immutable checkpoint rows, RLS, backfill, and safe comments.
- Modify `job/db/queries/audit_outbox.sql`: add chain-head and checkpoint read/insert queries; existing audit/outbox insert remains the API mutation boundary.
- Regenerate `job/internal/platform/db/sqlcgen/**` deterministically through the existing sqlc workflow.
- Modify `job/scripts/dbtest/run.sh`: include migration `0017` and run the new audit-integrity PostgreSQL test cases.
- Create `job/scripts/dbtest/check_audit_integrity.sh`: direct PostgreSQL permission/RLS/tamper/concurrency assertions that do not depend on Go mocks.
- Modify `job/db/MIGRATION-RECOVERY.md`: document compatible rollback/disable semantics for checkpointing while preserving non-optional audit chaining.

### Go audit package

- Modify `job/internal/platform/audit/recorder.go`: stop exposing caller-controlled `PreviousHash`; keep existing event-content hashing stable for the current empty previous-hash representation.
- Modify `job/internal/platform/audit/recorder_test.go`: prove callers cannot provide authoritative linkage and existing content-hash behavior remains deterministic.
- Create `job/internal/platform/audit/checkpoint.go`: statement model, fixed binary encoding, digest calculation, structural validation, ECDSA P-256 verification, and stored-checkpoint verification.
- Create `job/internal/platform/audit/checkpoint_test.go`: deterministic statement/digest and tamper/fail-closed unit tests.
- Create `job/internal/platform/audit/checkpointer.go`: provider-neutral signer/store contracts plus read → sign → verify → persist orchestration with idempotent replay.
- Create `job/internal/platform/audit/checkpointer_test.go`: ordering, signer-failure, concurrent-writer, conflict/replay, and no-transaction-during-sign tests.
- Modify `job/internal/platform/audit/recorder_integration_test.go`: real PostgreSQL chain/checkpoint integration under `machina_runtime`.

### Durable engineering evidence

- Modify `job/docs/engineering/MCH-S001-implementation-plan.md` only after exact-SHA GREEN and independent critique.
- Modify `job/docs/handoffs/CHATGPT-CONTINUATION-2026-09-08.md` only after exact-SHA GREEN and independent critique.
- Mark this plan only with evidence actually produced.

---

## Task 1: Prove the Current Audit History Is Mutable and Unchained

**Files:**
- Create: `job/scripts/dbtest/check_audit_integrity.sh`
- Modify: `job/scripts/dbtest/run.sh`

**Interfaces:**
- Consumes the existing PostgreSQL 18.6 harness, `machina_runtime`, `audit.events`, tenant fixtures, and current migration set through `0016`.
- Produces a behavioral RED gate that demonstrates the exact missing invariants before migration `0017` exists.

- [ ] **Step 1: Add a direct runtime immutability assertion**

Create `check_audit_integrity.sh` using the existing `query_as`, `expect_equals`, and `expect_failure` helpers. Insert one valid audit row as `machina_runtime` inside tenant A, then require both of these statements to fail:

```sql
BEGIN;
SELECT set_config('app.tenant_id', :'tenant_a', true);
UPDATE audit.events
SET action = 'tampered.action'
WHERE tenant_id = :'tenant_a' AND id = :'event_id';
COMMIT;
```

```sql
BEGIN;
SELECT set_config('app.tenant_id', :'tenant_a', true);
DELETE FROM audit.events
WHERE tenant_id = :'tenant_a' AND id = :'event_id';
COMMIT;
```

Also inspect `information_schema.role_table_grants` and require `machina_runtime` to have no `UPDATE` or `DELETE` grant on `audit.events`.

- [ ] **Step 2: Add a database-owned chain assertion without referencing future Go symbols**

After the event insert, query PostgreSQL catalog state and require the authoritative S001 chain table to exist and contain exactly one tenant-A row with sequence `1`, a 32-byte zero previous hash, the persisted event hash, and a 32-byte chain hash. Do not create a fallback in the test when the table is absent.

Expected future shape:

```sql
SELECT sequence,
       encode(previous_chain_hash, 'hex'),
       octet_length(event_hash),
       octet_length(chain_hash)
FROM audit.event_chain
WHERE tenant_id = :'tenant_a' AND event_id = :'event_id';
```

- [ ] **Step 3: Publish only the failing security test and observe behavioral RED**

Add `source scripts/dbtest/check_audit_integrity.sh` after base tenant fixtures are created and before Go integration tests. Do **not** add migration `0017` yet.

Valid RED requires the existing database setup and earlier RLS checks to succeed, then fail because at least one current invariant is demonstrably false: runtime mutation succeeds and/or `audit.event_chain` is absent. A shell syntax error, missing fixture, PostgreSQL readiness failure, or unrelated migration failure is not valid RED.

- [ ] **Step 4: Preserve the exact RED SHA/workflow/job IDs**

Record only exact GitHub Actions evidence. Do not call the test PASS until the same assertions later succeed without being weakened.

---

## Task 2: Enforce Append-Only Audit History and a Serialized Tenant Chain

**Files:**
- Create: `job/db/migrations/0017_audit_integrity_checkpoints.sql`
- Modify: `job/db/queries/audit_outbox.sql`
- Modify: `job/scripts/dbtest/run.sh`
- Modify: `job/scripts/dbtest/check_audit_integrity.sh`
- Modify generated: `job/internal/platform/db/sqlcgen/**`
- Modify: `job/internal/platform/audit/recorder.go`
- Modify: `job/internal/platform/audit/recorder_test.go`

**Interfaces:**
- Existing application call remains `InsertAuditEvent(context.Context, sqlcgen.InsertAuditEventParams) error`.
- Produces database tables `audit.chain_heads`, `audit.event_chain`, `audit.checkpoints` and trigger-owned chain allocation.
- Produces sqlc queries `GetAuditChainHead`, `GetAuditCheckpoint`, and `InsertAuditCheckpoint` for later tasks.

- [ ] **Step 1: Strengthen the RED test for privilege and mutation bypasses**

Require all of the following after `0017` is eventually present:

```text
machina_runtime audit.events privileges = SELECT,INSERT only
machina_runtime audit.event_chain privileges = SELECT only
machina_runtime audit.chain_heads privileges = SELECT only
machina_runtime audit.checkpoints privileges = SELECT,INSERT only
```

Require runtime `UPDATE`/`DELETE` on `audit.events` and runtime `INSERT`/`UPDATE`/`DELETE` on `audit.event_chain`/`audit.chain_heads` to fail. Require `TRUNCATE` to be absent from runtime grants. Keep the test RED now.

- [ ] **Step 2: Add the forward-only migration**

Create `0017_audit_integrity_checkpoints.sql` with these exact data invariants:

```sql
CREATE TABLE audit.chain_heads (
    tenant_id uuid PRIMARY KEY REFERENCES iam.tenants(id) ON DELETE RESTRICT,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    last_chain_hash bytea NOT NULL CHECK (octet_length(last_chain_hash) = 32)
);

CREATE TABLE audit.event_chain (
    tenant_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL,
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    previous_chain_hash bytea NOT NULL CHECK (octet_length(previous_chain_hash) = 32),
    chain_hash bytea NOT NULL CHECK (octet_length(chain_hash) = 32),
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, sequence, chain_hash),
    FOREIGN KEY (tenant_id, event_id) REFERENCES audit.events(tenant_id, id) ON DELETE RESTRICT
);
```

Create `audit.checkpoints` now so its FK and privilege boundary are migration-owned, but do not yet add Go signing behavior:

```sql
CREATE TABLE audit.checkpoints (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    chain_sequence bigint NOT NULL CHECK (chain_sequence > 0),
    chain_hash bytea NOT NULL CHECK (octet_length(chain_hash) = 32),
    statement_digest bytea NOT NULL CHECK (octet_length(statement_digest) = 32),
    algorithm text NOT NULL CHECK (algorithm = 'ecdsa-p256-sha256'),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 200),
    signature bytea NOT NULL CHECK (octet_length(signature) BETWEEN 64 AND 256),
    signed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, chain_sequence, key_id),
    FOREIGN KEY (tenant_id, chain_sequence, chain_hash)
      REFERENCES audit.event_chain(tenant_id, sequence, chain_hash) ON DELETE RESTRICT
);
```

All three tables must `ENABLE` and `FORCE ROW LEVEL SECURITY` with tenant policy for `machina_runtime` and `machina_migrator`. Runtime permissions must be explicit and minimal as listed in Step 1. Runtime must never own these tables.

- [ ] **Step 3: Add unconditional history-mutation rejection**

Create a `SECURITY DEFINER`-free `BEFORE UPDATE OR DELETE` trigger function that always raises SQLSTATE `42501` for `audit.events`, `audit.event_chain`, and `audit.checkpoints`. It must use `SET search_path = pg_catalog`, be non-public, and contain no secret or role-dependent bypass. This is defense in depth beyond privilege revocation; future schema evolution must append/derive rather than rewrite signed history.

- [ ] **Step 4: Add serialized chain allocation**

Create `audit.append_event_chain()` as an `AFTER INSERT ON audit.events` trigger. It must:

1. require `NEW.event_hash IS NOT NULL` and exactly 32 bytes;
2. require `ops.current_tenant_id() = NEW.tenant_id`;
3. create the tenant head if absent with sequence `0` and 32 zero bytes using `INSERT ... ON CONFLICT DO NOTHING`;
4. lock exactly that tenant head row `FOR UPDATE`;
5. set `next_sequence = last_sequence + 1`;
6. compute `next_hash = sha256(last_chain_hash || NEW.event_hash)` using PostgreSQL 18 built-ins;
7. insert one immutable `audit.event_chain` row;
8. update the internal head to the exact new sequence/hash;
9. return `NEW`.

The trigger function is `SECURITY DEFINER`, owned by `machina_migrator`, uses `SET search_path = pg_catalog`, and `SET row_security = on`. Revoke function execution from `PUBLIC`; the trigger invokes it implicitly.

- [ ] **Step 5: Backfill pre-existing S001 events deterministically**

Within the same migration transaction, before enabling the live append trigger, scan existing `audit.events` ordered by `(tenant_id, occurred_at, id)`. Fail the migration if any historical `event_hash` is NULL or not 32 bytes. For each tenant, build `audit.event_chain` from 32 zero-byte genesis and populate `audit.chain_heads`. The migration must not UPDATE or DELETE historical `audit.events` rows.

After backfill, enable the append trigger and assert each tenant head sequence equals its chain-row count. Because S001 is pre-production construction, no special dual-write compatibility layer is introduced.

- [ ] **Step 6: Remove caller-owned linkage from Go**

Remove `PreviousHash []byte` from `audit.Event`. In `Params`, keep the current content-hash serialization stable by encoding an empty `previous_hash` string in the existing hash-input struct and always set `InsertAuditEventParams.PreviousHash` to nil. The database chain, not caller input, becomes authoritative linkage.

Add a unit test that two identical events produce identical `event_hash`, and that no public/package caller field can supply chain state.

- [ ] **Step 7: Add sqlc checkpoint/head queries and regenerate**

Append to `audit_outbox.sql`:

```sql
-- name: GetAuditChainHead :one
SELECT last_sequence, last_chain_hash
FROM audit.chain_heads
WHERE tenant_id = sqlc.arg(tenant_id)::uuid;

-- name: GetAuditCheckpoint :one
SELECT tenant_id, id, chain_sequence, chain_hash, statement_digest,
       algorithm, key_id, signature, signed_at
FROM audit.checkpoints
WHERE tenant_id = sqlc.arg(tenant_id)::uuid
  AND chain_sequence = sqlc.arg(chain_sequence)::bigint
  AND key_id = sqlc.arg(key_id)::text;

-- name: InsertAuditCheckpoint :one
INSERT INTO audit.checkpoints (...)
VALUES (...)
ON CONFLICT (tenant_id, chain_sequence, key_id) DO NOTHING
RETURNING tenant_id, id, chain_sequence, chain_hash, statement_digest,
          algorithm, key_id, signature, signed_at;
```

Use the repository's existing sqlc generation command/workflow. Generated files are outputs, never hand-edited to bypass sqlc.

- [ ] **Step 8: Expand PostgreSQL GREEN coverage for chain correctness**

In `check_audit_integrity.sh` prove:

- first event uses zero genesis and sequence 1;
- second event uses first `chain_hash` as `previous_chain_hash` and sequence 2;
- PostgreSQL independently recomputes `sha256(previous_chain_hash || event_hash)` equal to persisted `chain_hash`;
- tenant B starts at sequence 1 with zero genesis, independent from tenant A;
- tenant A runtime context cannot read tenant B chain/head/checkpoint rows;
- missing tenant context reads zero chain/checkpoint rows;
- direct runtime mutation attempts fail.

- [ ] **Step 9: Add same-tenant concurrency proof**

Launch at least two concurrent runtime transactions that insert valid audit events into the same tenant. After both commit, require a contiguous sequence with no duplicate/fork, and verify every row's `previous_chain_hash` equals the immediately preceding row's `chain_hash`. Run a tenant-B insert concurrently and prove its chain remains independent.

- [ ] **Step 10: Verify exact-SHA GREEN**

Require formatting, Go/race, sqlc consistency, and PostgreSQL 18.6 workflows on the exact SHA. Any migration failure, RLS regression, lock hang, chain fork, or generated-file diff is a real failure to debug, not a gate to weaken.

---

## Task 3: Versioned Checkpoint Statement and Cryptographic Verification

**Files:**
- Create: `job/internal/platform/audit/checkpoint.go`
- Create: `job/internal/platform/audit/checkpoint_test.go`

**Interfaces:**
- Produces `CheckpointAlgorithm` with exactly `ecdsa-p256-sha256`.
- Produces `CheckpointStatement`, `CheckpointDigest`, `StoredCheckpoint`.
- Produces `DigestCheckpointStatement(CheckpointStatement) ([32]byte, error)`.
- Produces `VerifyCheckpointSignature(*ecdsa.PublicKey, StoredCheckpoint) error`.

- [ ] **Step 1: Write deterministic statement/digest RED tests**

Define the intended statement fields:

```go
type CheckpointStatement struct {
    TenantID     pgtype.UUID
    CheckpointID pgtype.UUID
    ChainSequence int64
    ChainHash    [32]byte
    Algorithm    CheckpointAlgorithm
    KeyID        string
    SignedAt     time.Time
}
```

Require invalid UUIDs, sequence ≤0, zero/invalid algorithm, empty/oversized/invalid-UTF8 key ID, zero chain hash, non-UTC/zero timestamp handling according to the canonical encoder contract, and malformed stored signatures to fail closed.

- [ ] **Step 2: Define one versioned binary encoding**

Use this byte order exactly:

```text
ASCII "MCH-AUDIT-CHECKPOINT" | 0x00 | version 0x01 |
tenant UUID 16 bytes |
checkpoint UUID 16 bytes |
chain sequence uint64 big-endian |
chain hash 32 bytes |
algorithm length uint16 + UTF-8 algorithm bytes |
key ID length uint16 + UTF-8 key ID bytes |
signed_at UnixNano int64 big-endian
```

`DigestCheckpointStatement` returns SHA-256 of those bytes. Convert `SignedAt` to UTC before encoding. No JSON canonicalization dependency is introduced.

- [ ] **Step 3: Observe behavioral RED**

Publish only the tests first. Valid RED is missing checkpoint production symbols or absent validation; module/import/format failures are invalid RED.

- [ ] **Step 4: Implement minimum statement/digest code**

Use only Go standard library plus existing `pgtype.UUID`. Keep all accepted algorithms closed to one constant in S001. Copy byte slices defensively and reject invalid UTF-8 or key IDs longer than 200 Unicode code points/bytes according to the database bound chosen in Task 2.

- [ ] **Step 5: Add ECDSA P-256 signature verification tests**

Generate an ephemeral P-256 key inside the test with `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`. Sign the digest using ASN.1 ECDSA. Require verification success for the original row, then failure after independently flipping each committed field: tenant ID, checkpoint ID, chain sequence, chain hash, algorithm, key ID, signed timestamp, digest, and signature.

- [ ] **Step 6: Implement verification fail-closed**

`VerifyCheckpointSignature` must require:

- non-nil public key;
- exact P-256 curve;
- structurally valid stored checkpoint;
- recomputed statement digest equals stored `statement_digest` using constant-time comparison;
- `ecdsa.VerifyASN1` succeeds for the recomputed digest.

Do not accept RSA, Ed25519, alternate curves, raw `(r,s)` encodings, algorithm aliases, or caller-supplied hash functions in S001.

- [ ] **Step 7: Verify unit GREEN and race**

Run package tests and the existing audit race selection on the exact SHA. Preserve exact RED/GREEN evidence.

---

## Task 4: Provider-Neutral Checkpointer With No Database Transaction Across Signing

**Files:**
- Create: `job/internal/platform/audit/checkpointer.go`
- Create: `job/internal/platform/audit/checkpointer_test.go`

**Interfaces:**
- Produces:

```go
type CheckpointSigner interface {
    KeyID() string
    PublicKey(context.Context) (*ecdsa.PublicKey, error)
    SignSHA256(context.Context, [32]byte) ([]byte, error)
}

type CheckpointStore interface {
    Head(context.Context, pgtype.UUID) (ChainHead, error)
    Find(context.Context, pgtype.UUID, int64, string) (StoredCheckpoint, error)
    Insert(context.Context, StoredCheckpoint) (StoredCheckpoint, error)
}

type Checkpointer struct { ... }
func NewCheckpointer(store CheckpointStore, signer CheckpointSigner, now func() time.Time, newID func() (pgtype.UUID, error)) (*Checkpointer, error)
func (c *Checkpointer) Checkpoint(context.Context, pgtype.UUID) (CheckpointResult, error)
```

`CheckpointStore` methods are separate short tenant-scoped transactions in the production adapter; the signer is never called from inside a store callback/transaction.

- [ ] **Step 1: Write orchestration RED test with a recording store/signer**

Require strict call order for a new checkpoint:

```text
Head -> Find -> SignSHA256 -> PublicKey -> Insert -> Verify persisted row
```

The signer recording fake must fail the test if invoked while the store marks any transaction/callback active. This test proves the architecture seam, not merely elapsed time.

- [ ] **Step 2: Write signer-failure and public-key-failure RED tests**

For signer failure or public-key retrieval failure require:

- returned error wraps the injected cause;
- zero `Insert` calls;
- no mutation of the chain/head fixture;
- a later retry may succeed without any API/audit rollback concept.

- [ ] **Step 3: Write replay/idempotency RED tests**

If `Find` returns an existing checkpoint for current `(tenant, sequence, keyID)`, verify it and return `Replay=true` without signing or inserting. If the existing row fails signature/digest verification, fail closed; never overwrite it.

For an `Insert` race where another worker wins the unique key, production store must return/load the winner and the checkpointer verifies that exact stored checkpoint before accepting replay.

- [ ] **Step 4: Implement the minimum checkpointer**

`Checkpoint` must:

1. validate tenant and signer key ID;
2. read current immutable `ChainHead`;
3. return typed `ErrNoAuditEvents` for sequence 0/missing head;
4. check for existing valid checkpoint at that head/key;
5. allocate checkpoint UUID and UTC `SignedAt`;
6. build statement and digest;
7. call `SignSHA256` with no database transaction held;
8. obtain trusted public key and verify the signature locally;
9. persist via `Insert` in a fresh transaction;
10. verify the exact persisted/winning row before returning success/replay.

A newer event committed between Step 2 and Step 9 is allowed: the checkpoint is a valid signed prefix because `(tenant, sequence, chain_hash)` is immutable and FK-protected.

- [ ] **Step 5: Add production PostgreSQL store adapter without a generic repository framework**

Implement the concrete store adjacent to the checkpointer using the existing `db.Transactor.WithinTenant`. Each `Head`, `Find`, and `Insert` method owns one short transaction and returns before the signer is invoked. Map `pgx.ErrNoRows` to package-owned typed not-found semantics. Do not create a second transaction abstraction.

- [ ] **Step 6: Verify exact-SHA Go/race GREEN**

Require all Go tests plus audit race. A checkpointer that holds a transaction around the signer, accepts an unverifiable checkpoint, overwrites a conflict, or silently ignores signer failure is not GREEN.

---

## Task 5: Real PostgreSQL Signed-Checkpoint and Tamper Evidence

**Files:**
- Modify: `job/internal/platform/audit/recorder_integration_test.go`
- Modify: `job/scripts/dbtest/run.sh`

**Interfaces:**
- Consumes real PostgreSQL 18.6, `machina_runtime`, `db.Transactor`, generated sqlc queries, and the checkpointer.
- Uses an ephemeral in-test ECDSA P-256 key only as synthetic verification material; no repository secret or provider credential.

- [ ] **Step 1: Add a committed real-chain integration case**

Under tenant A runtime context, record at least two audit events through `Recorder`, commit them, and read `audit.event_chain`. Assert contiguous sequence, event-hash equality, previous-link equality, chain recomputation, and RLS isolation from tenant B.

- [ ] **Step 2: Add a real signed-checkpoint integration case**

Construct the PostgreSQL `CheckpointStore` plus an in-test signer backed by an ephemeral P-256 private key. Run `Checkpointer.Checkpoint`. Query the persisted checkpoint under `machina_runtime` and require `VerifyCheckpointSignature` success against the ephemeral public key.

Run the checkpointer again at the unchanged head and require replay with no second row.

- [ ] **Step 3: Add signer outage evidence**

Inject a signer error. Require no new checkpoint row while the already committed audit chain remains intact and queryable. Restore signer behavior and require a later run to create exactly one valid checkpoint.

- [ ] **Step 4: Add tamper-detection evidence without weakening runtime permissions**

Do not UPDATE the real immutable table to fabricate a passing test. Read one valid checkpoint/event-chain record into Go and mutate an isolated copy field-by-field. Require verification/recomputation to fail for changed sequence/hash/digest/signature/key/time. Separately prove direct runtime SQL UPDATE/DELETE remains denied in `check_audit_integrity.sh`.

- [ ] **Step 5: Verify PostgreSQL exact-SHA GREEN**

Update `run_go_audit_integration` to execute both the existing decision roundtrip and the new chain/checkpoint integration tests. Require PostgreSQL introspection still reports `runtime_role_flags=0:0:0:0`, zero owner/RLS/tenant-key violations, and all new audit-integrity checks green.

---

## Task 6: Prove Rollback/Disable Cannot Bypass API Audit

**Files:**
- Modify: `job/internal/platform/identity/idempotent_tenant_switch_integration_test.go`
- Modify: `job/db/MIGRATION-RECOVERY.md`
- Modify: `job/docs/engineering/MCH-S001-implementation-plan.md` only after GREEN

**Interfaces:**
- Consumes the existing tenant-switch atomicity integration and new database append trigger.
- Produces the remaining Task 6 rollback evidence without making checkpoint signing part of the synchronous API transaction.

- [ ] **Step 1: Add a no-checkpointer tenant-switch regression test**

Run the existing successful tenant-switch mutation with no `Checkpointer` constructed or invoked. Require domain/session change, audit row, event-chain row, outbox row, idempotency completion, and trace correlation all commit exactly once.

This proves checkpoint worker disablement cannot disable mandatory audit/chain behavior because the chain is an `audit.events` database trigger in the API transaction.

- [ ] **Step 2: Add a chain-trigger-failure mutation test**

Using the existing test-admin fault-injection boundary, temporarily revoke/deny only the trigger's ability to persist the chain or otherwise inject a chain append failure without changing product code. Require the tenant-switch transaction to roll back: no committed session mutation, receipt completion, audit event, chain row, or outbox effect.

Restore the database permission/state and require the same request to succeed exactly once. Do not convert chain failure into an asynchronous warning.

- [ ] **Step 3: Document forward-only rollback semantics**

Extend `MIGRATION-RECOVERY.md` with these exact rules:

- migration `0017` is additive schema plus privilege hardening; no down migration restores audit mutability;
- an application rollback may omit/disable checkpoint scheduling while retaining `audit.events` append trigger and chain tables;
- checkpoint signer/KMS unavailability degrades periodic anchoring only; it never makes API audit optional;
- rollback to any application artifact that cannot tolerate the additive schema is blocked rather than solved by destructive DDL;
- restore verification includes audit privilege immutability, chain continuity, RLS, and checkpoint FK/signature verification.

- [ ] **Step 4: Close only the proven Task 6 rollback checkbox**

After exact-SHA verification and critique, mark:

```markdown
- [x] Rollback: additive tables and worker can be disabled without bypassing audit on API mutations.
```

Attach exact SHA, workflow/job IDs, fault-injection behavior, and explicit `NOT_VERIFIED` items. Do not mark complete Gate I or the entire Slice.

---

## Task 7: Independent Critique, Mutation Sensitivity, and Exact-SHA Convergence

**Files:**
- Modify: this plan
- Modify: `job/docs/engineering/MCH-S001-implementation-plan.md`
- Modify: `job/docs/handoffs/CHATGPT-CONTINUATION-2026-09-08.md`

**Interfaces:**
- Produces durable evidence only after product-code convergence.

- [ ] **Step 1: Run a separated Critic review**

Review the exact product SHA for at least:

- runtime UPDATE/DELETE/TRUNCATE bypass;
- migrator/owner assumptions and public trigger execution;
- RLS on chain/head/checkpoint tables;
- same-tenant chain forks, lost updates, deadlocks, and cross-tenant lock coupling;
- invalid/null legacy event hashes and migration backfill ordering;
- event-hash/chain-hash canonicalization ambiguity;
- signer invoked under an open transaction;
- signing private-key/public-key trust leakage;
- key-ID injection/unbounded values;
- signature algorithm confusion or alternate-curve acceptance;
- checkpoint replay/concurrent writers;
- checkpoint row tampering and stale-prefix semantics;
- API rollback semantics when chain fails;
- API behavior when checkpoint signing fails;
- public GitHub secret/private-data exposure;
- unnecessary S009/job-framework scope expansion;
- performance impact on audited API mutations.

- [ ] **Step 2: Perform mutation sensitivity for one critical integrity guard**

Temporarily mutate one production guard on a normal fast-forward commit, without changing tests. Preferred mutation: re-grant runtime `UPDATE` on `audit.events` or bypass the chain-hash linkage. Require the corresponding PostgreSQL security test to fail for the exact intended reason. Restore the safe blob/behavior and re-run all affected gates. Never force-push or rewrite mutation evidence.

- [ ] **Step 3: Correct every real Critical/Important finding through RED→GREEN**

Preserve failing evidence, find root cause, implement the smallest contract-consistent correction, and rerun affected exact-SHA workflows. Repeat separated review until no unresolved Critical/Important issue remains.

- [ ] **Step 4: Run exact-SHA convergence gates**

At minimum require on the same final product SHA:

- formatter/gofmt;
- `go mod tidy -diff`;
- `go vet ./...`;
- repository boundary/binding/no-Python verification;
- `go test -count=1 ./...`;
- `go test -race -count=1 ./internal/platform/audit ./internal/platform/identity ./internal/platform/observability`;
- sqlc generated-file consistency;
- PostgreSQL 18.6 database workflow including new audit-integrity and signed-checkpoint integration;
- Rust authorization workflow only if path selection or affected integration requires it.

If a selected workflow does not run, state it as `NOT_VERIFIED` rather than assuming equivalence.

- [ ] **Step 5: Update durable evidence without overclaiming**

Record exact RED/GREEN/mutation SHAs, workflow/job IDs, PostgreSQL role/RLS evidence, Critic findings, and remaining unverified work. Keep Task 7+, complete Gate I, full GAUNTLET, candidate freeze, promotion, and Slice completion open unless separately proven.

---

## Pre-Mortem Attack

1. **Runtime can still rewrite history through forgotten grants.** Control: catalog-level privilege assertions plus unconditional UPDATE/DELETE rejection triggers; direct runtime tamper tests.
2. **Two concurrent inserts fork the chain.** Control: per-tenant head row created idempotently and locked `FOR UPDATE`; contiguous sequence and link tests under concurrency.
3. **One global lock serializes every tenant.** Control: lock one `audit.chain_heads` tenant row only; concurrent tenant-B insert included in tests.
4. **Caller fabricates `PreviousHash`.** Control: remove caller-owned field; authoritative linkage exists only in DB trigger state.
5. **Existing rows disappear from the chain after migration.** Control: deterministic migration backfill ordered by tenant/time/id, fail closed on invalid/null existing `event_hash`.
6. **Database owner can rewrite chain undetected.** Control: immutable triggers raise for ordinary history mutation and signed external checkpoints make post-checkpoint chain tampering cryptographically detectable; no claim that a DB superuser is physically incapable of disabling triggers.
7. **KMS/network latency holds an API/DB lock.** Control: checkpoint store operations are discrete transactions; signer call is structurally between store calls and tested while no transaction marker is active.
8. **Signer outage breaks user mutations.** Control: checkpointing is asynchronous from mutation; API still performs mandatory audit+chain atomically. Signer failure creates no checkpoint and retries later.
9. **Disabling checkpoint worker disables audit.** Control: chain trigger lives on `audit.events` in the API transaction and does not depend on checkpointer construction.
10. **Algorithm/key confusion lets forged rows verify.** Control: one exact algorithm string, P-256 curve enforcement, recomputed statement digest, trusted external public key, fail-closed verification.
11. **Concurrent checkpointers create duplicates.** Control: unique `(tenant, chain_sequence, key_id)`, read-before-sign replay, conflict winner read-and-verify.
12. **A later event makes a checkpoint look stale/invalid.** Control: checkpoints intentionally sign immutable prefixes; FK pins sequence/hash, not “latest forever”.
13. **Public GitHub leaks a key.** Control: only interfaces, key IDs, and ephemeral test-generated keys; no provider credentials/private keys/env values committed.
14. **This accidentally implements S009.** Control: no audit UI/search/export/retention/legal hold/privacy lifecycle; only S001 Gate-I minimum chain/checkpoint integrity.
15. **Migration rollback reopens mutable audit history.** Control: forward-only migration; application rollback may disable checkpoint scheduling but never reverse privilege hardening or chain enforcement.

## Plan Self-Review

- **Spec coverage:** MCH-S001 Gate I signed checkpoint behavior maps to Tasks 2-5 and 7; immutable audit requirement maps to Tasks 1-2; Task 6 rollback evidence maps to Task 6; tenant isolation and runtime-role guarantees map to Tasks 2/5/7; public-GitHub/KMS secret boundary maps to Global Constraints and Tasks 3-5.
- **Scope boundary:** S009 product capabilities remain excluded; this plan implements only the security primitive explicitly required by S001/architecture.
- **Placeholder scan:** no TBD/TODO/“similar to” implementation step is used. Every production change names concrete files, interfaces, behavior, and verification.
- **Type consistency:** `CheckpointStatement`, `StoredCheckpoint`, `CheckpointSigner`, `CheckpointStore`, `Checkpointer`, and `CheckpointResult` are defined before later-task use. Algorithm is one closed value throughout database and Go.
- **Migration consistency:** `0017` is additive tables/functions/triggers plus permission hardening and backfill into new tables; it does not update/delete historical audit events and remains compatible with the existing direct `InsertAuditEvent` application call.
- **Transaction consistency:** API mutation audit/chain remains one transaction; checkpoint signing is never inside that transaction or any checkpoint store transaction.

## Execution Mode

Execute task-by-task on the existing `forge/mch-s001-1.0.0` branch using TDD and exact-SHA GitHub Actions evidence. The Founder/user has already instructed continuous continuation inside the authorized Slice, so execution proceeds inline with `superpowers:executing-plans`; no additional execution-choice prompt is required. Builder claims are not final evidence; separated Critic review remains mandatory before closing durable state.

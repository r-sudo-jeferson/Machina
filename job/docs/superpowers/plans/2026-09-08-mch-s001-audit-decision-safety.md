# MCH-S001 Audit Decision Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace arbitrary audit `safe_metadata` maps with a package-owned typed boundary and prove one allowed and one denied authorization decision can be reconstructed deterministically without raw sensitive content.

**Architecture:** `internal/platform/audit` owns an opaque `SafeMetadata` value whose payload can only be created by package constructors. Tenant-switch metadata preserves the existing three-field JSON shape, while authorization-decision metadata contains only non-negative latency and closed deny reason codes. `Params` validates metadata/decision consistency before hashing or persistence; a reconstruction function strictly decodes persisted authorization metadata and rejects unknown fields or unsafe reason values.

**Tech Stack:** Go 1.27.1, standard-library `encoding/json`, `time`, `crypto/sha256`, pgx `pgtype`, existing sqlc-generated insert parameters. No Python.

**Spec:** `job/docs/engineering/MCH-S001-implementation-plan.md` Task 6; `job/docs/engineering/MCH-S001-premortem.md` risk 15; canonical `MCH-S001@1.0.0` AC-S001-10 and Gate I.

## Global Constraints

- Slice remains exactly `MCH-S001@1.0.0` under binding `FORGE-OPS-HIGHEND-v1.0.0` / canonical equivalent `FORGE-OPS-HIGHEND/v1.0.0`.
- All product changes remain under `job`; existing root workflow glue is unchanged by this plan.
- Do not mark Gate I, GAUNTLET, candidate freeze, promotion, or Slice completion.
- Audit metadata and operational metrics remain separate boundaries.
- No prompt, email, display name, cookie, CSRF value, session token, idempotency key, arbitrary context map, or caller-defined metadata key may enter `audit.SafeMetadata`.
- Tenant/workspace/actor/correlation identifiers remain first-class audit/event fields where already required by the Slice; they are not metric labels.
- Existing tenant-switch audit JSON and outbox payload semantics must remain unchanged.
- Authorization deny reasons are limited to the existing closed vocabulary: `default_deny`, `evaluation_error`, `explicit_forbid`, `policy_unavailable`, `stale_policy_version`.
- Builder verification is not independent critique and does not complete Gate I.

---

### Task 1: Package-owned safe audit metadata

**Files:**
- Create: `job/internal/platform/audit/metadata.go`
- Create: `job/internal/platform/audit/metadata_test.go`

**Interfaces:**
- Produces: `type SafeMetadata` with no exported fields.
- Produces: `func NewTenantSwitchMetadata(pgtype.UUID, pgtype.UUID, int64) (SafeMetadata, error)`.
- Produces: `func NewAuthorizationDecisionMetadata(string, time.Duration, []string) (SafeMetadata, error)`.
- Produces package-private `marshal() ([]byte, error)` and decision-consistency validation used by `Params`.

- [ ] **Step 1: Write failing metadata tests**

Require tenant-switch metadata to serialize exactly:

```json
{"session_generation":7,"target_tenant_id":"00000000-0000-0000-0000-0000000000b2","target_workspace_id":"20000000-0000-0000-0000-0000000000b2"}
```

Require authorization allow metadata with `25*time.Millisecond` to serialize exactly:

```json
{"latency_ms":25}
```

Require authorization deny metadata to serialize only `latency_ms` and a deduplicated ordered `reason_codes` array. Reject invalid UUIDs, non-positive session generation, negative latency, unknown decision, allow-with-reasons, deny-without-reasons, unknown reason, duplicate reason, and more than five reasons. Error text must be opaque and must not repeat rejected input.

- [ ] **Step 2: Observe RED on exact-SHA CI**

Push the test-only commit before production implementation. The Go workflow must fail because the planned `SafeMetadata` constructors do not exist. Record workflow run/job IDs; do not accept a formatting-only or unrelated failure as RED evidence.

- [ ] **Step 3: Implement the opaque metadata boundary**

`SafeMetadata` stores only package-private kind/decision/payload state. Constructors build typed private structs and marshal them internally. Callers cannot pass arbitrary maps or JSON bytes. Authorization reason validation uses only the five existing reason codes above; rejected values are never interpolated into errors.

- [ ] **Step 4: Verify focused tests**

Run through exact-SHA GitHub Actions and require `go test -count=1 ./internal/platform/audit` plus the repository Go gate to pass. Local execution may remain `NOT_VERIFIED` if the ChatGPT runtime still cannot clone the repository.

### Task 2: Recorder consistency and deterministic decision reconstruction

**Files:**
- Modify: `job/internal/platform/audit/recorder.go`
- Create: `job/internal/platform/audit/recorder_test.go`

**Interfaces:**
- `Event.SafeMetadata` changes from `map[string]any` to `SafeMetadata`.
- Produces: `type StoredDecision struct { TenantID pgtype.UUID; ActorSubjectID pgtype.UUID; Action string; Decision string; PolicyVersion int64; CorrelationID pgtype.UUID; SafeMetadata []byte }`.
- Produces: `type DecisionEvidence struct { TenantID pgtype.UUID; ActorSubjectID pgtype.UUID; Action string; Decision string; PolicyVersion int64; CorrelationID pgtype.UUID; Latency time.Duration; ReasonCodes []string }`.
- Produces: `func ReconstructDecision(StoredDecision) (DecisionEvidence, error)`.

- [ ] **Step 1: Write failing recorder/reconstruction tests**

Create one allow event and one deny event using deterministic UUIDs. Call `Params`, then build `StoredDecision` from the returned first-class fields plus `SafeMetadata` bytes and require `ReconstructDecision` to recover actor, tenant, action, decision, policy version, correlation, latency and deny reasons exactly. Require unknown JSON fields, malformed JSON, mismatched decision metadata, invalid first-class UUIDs, invalid policy version, negative/overflowing latency representation, and unknown reason codes to fail closed.

- [ ] **Step 2: Observe RED before implementation**

Commit only the tests and require exact-SHA Go CI to fail because `StoredDecision`, `DecisionEvidence`, `ReconstructDecision`, and the typed `Event.SafeMetadata` path are absent.

- [ ] **Step 3: Implement recorder validation and reconstruction**

`Params` must call `SafeMetadata.marshalForDecision(event.Decision)` before hashing/persistence. `ReconstructDecision` uses `json.Decoder.DisallowUnknownFields`, verifies complete EOF, validates the same closed reason vocabulary and decision rules, and returns copied reason slices. It must never synthesize or infer actor/tenant/correlation IDs from metadata; those remain first-class fields.

- [ ] **Step 4: Mutation check**

Temporarily bypass either unknown-field rejection or decision/reason validation. Require the focused audit test to fail, restore production code exactly, and rerun the focused package test. Record mutation SHA and failing workflow evidence; never leave the mutant as the safe checkpoint.

### Task 3: Preserve tenant-switch audit and outbox behavior

**Files:**
- Modify: `job/internal/platform/identity/idempotent_tenant_switch.go`
- Modify existing tenant-switch tests only as required to assert exact audit metadata bytes; do not weaken existing assertions.

**Interfaces:**
- Tenant switch obtains `audit.SafeMetadata` from `audit.NewTenantSwitchMetadata` for the audit event.
- Outbox keeps its existing payload object and serialized envelope semantics.

- [ ] **Step 1: Write/extend failing tenant-switch assertion**

Require the audit insert to contain exactly the same three keys and values previously emitted: `target_tenant_id`, `target_workspace_id`, and `session_generation`. Require the outbox payload to remain byte/semantic equivalent to the existing contract and contain no newly introduced fields.

- [ ] **Step 2: Implement the typed audit call site**

Replace the audit map with `audit.NewTenantSwitchMetadata`. Construct the existing outbox payload separately so the audit type boundary does not force an outbox API rewrite. Propagate constructor validation failure before any audit/outbox write.

- [ ] **Step 3: Verify non-regression**

Require exact-SHA Go CI and the path-selected PostgreSQL workflow to pass. Existing tenant-switch HTTP status/body/ETag/cache/cookie behavior and transaction atomicity must remain unchanged.

### Task 4: Evidence and parent-plan update

**Files:**
- Modify: `job/docs/engineering/MCH-S001-implementation-plan.md`
- Modify: this plan file

**Interfaces:**
- Produces durable evidence only for `Reconstruct one allowed and one denied decision from safe metadata`.

- [ ] **Step 1: Run the complete Go gate**

Require exact-SHA GitHub Actions to execute and pass:

```bash
go mod tidy -diff
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./scripts/verify/...
go test -count=1 ./...
go test -race -count=1 ./internal/platform/audit ./internal/platform/identity ./internal/platform/observability
```

If the durable Go workflow does not yet include `audit` in the race command, strengthen the same existing workflow rather than creating a duplicate pipeline.

- [ ] **Step 2: Independent critique**

Review only the resulting diff against AC-S001-10, Gate I and pre-mortem risk 15. Search specifically for arbitrary-map escape hatches, unknown-field acceptance, duplicated/inconsistent decision state, sensitive raw content, changed tenant-switch/outbox semantics, and accidental Gate-I overclaim.

- [ ] **Step 3: Update only proven checkboxes**

After exact-SHA CI and independent critique have no unresolved Critical/Important finding, mark only the parent-plan checkbox `Reconstruct one allowed and one denied decision from safe metadata` complete and record the exact implementation/restoration SHA plus Go/PostgreSQL run/job IDs. Keep Task 6 heading, trace-link evidence, signed audit checkpoint, Gate I, GAUNTLET, candidate freeze and promotion open.

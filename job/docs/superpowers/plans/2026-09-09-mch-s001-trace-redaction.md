# MCH-S001 Tenant-Switch Trace and Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove one tenant-switch request carries a single OpenTelemetry trace through HTTP, Cedar authorization, the database transaction, audit insertion, and outbox enqueue while persisting the same correlation ID and never exporting browser secrets, internal error causes, subject IDs, tenant IDs, workspace IDs, policy hashes, or idempotency keys as trace attributes.

**Architecture:** Keep the approved Go modular-monolith and transaction boundary unchanged. Add a tenant-switch-specific tracing adapter with a closed span-name vocabulary and only two trace attributes: the server-generated correlation ID and the existing closed `machina.outcome`; wire it around existing calls without moving authorization, mutation, audit, outbox, or commit ordering. Use an injected OpenTelemetry tracer in tests and the global provider only in public construction paths.

**Tech Stack:** Go 1.27.1, OpenTelemetry Go v1.46.0, `go.opentelemetry.io/otel/sdk/trace/tracetest`, existing pgx/sqlc transaction code, PostgreSQL 18.6. No Python.

**Spec:** Canonical GitLab `job/docs/slices/MCH-S001.md` AC-S001-10, Slice invariant “Every tenant, policy, Ask, and session event has trace/audit correlation”, Gate I; `job/docs/engineering/MCH-S001-implementation-plan.md` Task 6; `job/docs/engineering/MCH-S001-premortem.md` risk 15.

## Global Constraints

- Slice remains exactly `MCH-S001@1.0.0`; GAUNTLET remains `GNT-MCH-S001-001`; binding remains `FORGE-OPS-HIGHEND-v1.0.0`.
- All product and test changes remain under `job/**`; provider-required workflow glue may only invoke or select `/job` checks.
- Preserve HTTP 403/503 authorization semantics, `Cache-Control: no-store`, zero failure cookies, replay-without-cookies, strong ETags, and RFC 9457 bodies.
- Cedar authorization remains before claim, session mutation, audit insertion, outbox enqueue, completion, and finish.
- The same server-generated correlation ID must reach the authorization request, idempotency receipt, audit row, outbox row, HTTP problem/success path, and every tenant-switch span.
- Trace attributes are not metric labels. Metrics keep their existing bounded two-label vocabulary and must never receive correlation IDs.
- Trace instrumentation must not record or interpolate raw errors. Do not call `span.RecordError`; error status descriptions stay empty.
- Trace attributes must never contain session/CSRF tokens, cookies, idempotency keys, subject IDs, tenant IDs, workspace IDs, display names, emails, prompts, policy hashes, diagnostic references, database errors, or transport errors.
- Tracing failure or a no-op provider must not alter authorization, transaction, response, cookie, ETag, audit, or outbox behavior.
- This plan does not establish signed audit checkpoints, complete Gate I, GAUNTLET, candidate freeze, promotion, or Slice completion.

---

## File Map

- Create `job/internal/platform/identity/tenant_switch_trace.go`: closed tracing adapter, span names, correlation formatting, and outcome finalization without raw errors.
- Create `job/internal/platform/identity/tenant_switch_trace_test.go`: in-memory span assertions for success, deny, unavailable, parentage, correlation, and redaction.
- Modify `job/internal/platform/identity/tenant_switch_http.go`: construct/inject the closed adapter, start the HTTP span after correlation generation, and pass its context to the coordinator.
- Modify `job/internal/platform/identity/idempotent_tenant_switch.go`: inject/start transaction, audit, and outbox spans without changing call order.
- Modify `job/internal/platform/identity/tenant_switch_authorization.go`: wrap the existing Cedar call in the authorization span without changing request fields or decisions.
- Modify `job/go.mod` and `job/go.sum` only as produced by `go mod tidy` for direct test use of `otel/sdk/trace`.
- Modify `job/internal/platform/identity/idempotent_tenant_switch_integration_test.go`: prove persisted audit/outbox correlation matches the trace in PostgreSQL under `machina_runtime`.
- Modify `job/docs/engineering/MCH-S001-implementation-plan.md`, this plan, and the continuation handoff only after exact-SHA verification and independent critique.

### Task 1: Closed Tenant-Switch Tracing Adapter

**Files:**
- Create: `job/internal/platform/identity/tenant_switch_trace.go`
- Create: `job/internal/platform/identity/tenant_switch_trace_test.go`
- Modify: `job/internal/platform/identity/tenant_switch_http.go`
- Modify: `job/go.mod`
- Modify: `job/go.sum`

**Interfaces:**
- Produces `type tenantSwitchSpanName string` with exactly `tenant.switch.http`, `tenant.switch.transaction`, `tenant.switch.authorization`, `tenant.switch.audit`, and `tenant.switch.outbox`.
- Produces `type tenantSwitchTracing struct { tracer trace.Tracer }`.
- Produces `newTenantSwitchTracing(trace.Tracer) (*tenantSwitchTracing, error)`.
- Produces `(*tenantSwitchTracing).start(context.Context, tenantSwitchSpanName, pgtype.UUID) (context.Context, trace.Span)`.
- Produces `finishTenantSwitchSpan(trace.Span, observability.Outcome)`.

- [ ] **Step 1: Write the failing HTTP root-span test against existing constructors**

Use a synchronous in-memory exporter and temporarily install its provider as the OpenTelemetry global before constructing the existing handler. Restore the previous global provider in cleanup. Exercise a valid tenant-switch HTTP request with an existing recording switcher that captures the server-generated correlation ID and returns an explicit forbidden result. Do not reference any not-yet-defined tracing production symbol in this RED commit.

```go
exporter := tracetest.NewInMemoryExporter()
provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
spans := exporter.GetSpans()
if len(spans) != 1 || spans[0].Name != "tenant.switch.http" {
	t.Fatalf("spans = %#v", spans)
}
```

Require HTTP 403 and the existing `tenant_switch_forbidden` RFC 9457 response without cookies or ETag. Assert one root span with only `machina.correlation_id` and `machina.outcome`; its correlation value equals the UUID captured from the server-owned request and its outcome is `denied`.

- [ ] **Step 2: Publish only the root-span test and observe exact-SHA behavioral RED**

Require `go mod tidy -diff`, repository-wide gofmt, `go vet ./...`, and all pre-existing tests to succeed before the new assertion. The valid RED is exactly zero exported spans where one closed HTTP span is required; a compilation, import, module, format, fixture, or harness failure is invalid.

- [ ] **Step 3: Implement the minimum closed adapter**

Use package-private constants and do not accept arbitrary attribute keys or values. `NewTenantSwitchHTTPHandler` and the existing private constructor must acquire the global tracer only during construction; add a further package-private tracing-aware constructor for deterministic tests without changing either existing signature. Start the HTTP span only after the correlation ID is generated, pass its context to `Switch`, and finish it on every result branch with the same closed outcome already used by metrics.

The adapter itself is:

```go
const (
	tenantSwitchTraceInstrumentationName = "github.com/r-sudo-jeferson/Machina/job/internal/platform/identity"
	tenantSwitchTraceCorrelationKey      = "machina.correlation_id"
)

type tenantSwitchTracing struct {
	tracer trace.Tracer
}

func (t *tenantSwitchTracing) start(ctx context.Context, name tenantSwitchSpanName, correlationID pgtype.UUID) (context.Context, trace.Span) {
	if t == nil || t.tracer == nil || ctx == nil || !validTenantSwitchSpanName(name) {
		return tenantSwitchNoopSpan()
	}
	ctx, span := t.tracer.Start(ctx, string(name))
	if correlationID.Valid {
		span.SetAttributes(attribute.String(tenantSwitchTraceCorrelationKey, uuidText(correlationID)))
	}
	return ctx, span
}

func finishTenantSwitchSpan(span trace.Span, outcome observability.Outcome) {
	if span == nil {
		return
	}
	if !validTenantSwitchTraceOutcome(outcome) {
		span.End()
		return
	}
	span.SetAttributes(attribute.String(observability.MetricOutcome, string(outcome)))
	if outcome == observability.OutcomeError {
		span.SetStatus(codes.Error, "")
	}
	span.End()
}
```

`tenantSwitchNoopSpan` must use OpenTelemetry's no-op tracer provider and return `context.Background()` plus a non-nil no-op span. `validTenantSwitchSpanName` must enumerate exactly the five constants above; `validTenantSwitchTraceOutcome` must enumerate exactly the five existing observability outcomes. Validate constructor inputs and keep the name/outcome arguments private typed enums so no request value can become a span name or attribute. Add direct GREEN assertions for nil tracer rejection, nil context/unknown-name no-op behavior, invalid-correlation omission, and nil-span/invalid-outcome safety. Do not record error values, events, stacks, tenant coordinates, policy hashes, or diagnostic references.

- [ ] **Step 4: Verify adapter GREEN on the exact SHA**

Require the complete Go workflow, including the existing audit/identity/observability race command. Inspect the exported HTTP span directly; a passing no-op-only test is insufficient.

### Task 2: Link HTTP, Authorization, Transaction, Audit, and Outbox

**Files:**
- Modify: `job/internal/platform/identity/tenant_switch_http.go`
- Modify: `job/internal/platform/identity/idempotent_tenant_switch.go`
- Modify: `job/internal/platform/identity/tenant_switch_authorization.go`
- Modify: `job/internal/platform/identity/tenant_switch_trace_test.go`

**Interfaces:**
- `TenantSwitchHTTPHandler` already has the package-private `tracing *tenantSwitchTracing` field from Task 1; `TenantSwitchCoordinator` gains the same field here.
- Existing public constructor signatures remain unchanged.
- Consume the private `newTenantSwitchHTTPHandlerWithTracing` from Task 1 and produce `newTenantSwitchCoordinatorWithTracing` for deterministic tests.
- `TenantSwitchHTTPHandler` already has a package-private correlation generator initialized to `newTenantSwitchUUID`; production behavior stays cryptographically random.

- [ ] **Step 1: Write the full-chain failing test**

Use the existing HTTP middleware/request helpers, `recordingTenantSwitchUnit`, and allow authorizer. Configure the recording unit so its claim returns the correlation received in `ClaimIdempotencyKeyParams`. Inject the same `tenantSwitchTracing` from Task 1 into handler and coordinator, then send one valid POST.

Assert:

```go
wantNames := []string{
	"tenant.switch.http",
	"tenant.switch.transaction",
	"tenant.switch.authorization",
	"tenant.switch.audit",
	"tenant.switch.outbox",
}
```

Require exactly one span of each name; one non-zero trace ID across all five; HTTP as root; transaction as HTTP child; authorization, audit, and outbox as transaction children; the same canonical `machina.correlation_id` on every span; and equality with `unit.auditParams.CorrelationID`, `unit.outboxParams.CorrelationID`, and `unit.claimParams.CorrelationID`. Reassert authorization occurred before claim/mutation and audit/outbox remained inside the transaction.

- [ ] **Step 2: Publish only the full-chain test and observe behavioral RED**

Module, format, vet, existing tests, and adapter tests must pass. The new test must fail because production emits fewer than the five linked spans. A compile/harness failure is not valid RED.

- [ ] **Step 3: Wire spans without moving behavior**

In the HTTP handler, generate the correlation ID first, start the HTTP span with it, and pass the returned context into `Switch`. In `Switch`, start the transaction span before `c.run` and pass that context to the runner. In `authorizeTenantSwitch`, start/end the authorization span around the existing `Authorize` call. In `claimAndSwitch`, start/end audit and outbox spans immediately around the existing `Record` and `Publish` calls.

Do not move any call across the Cedar, claim, session mutation, audit, outbox, completion, finish, or commit boundaries. End spans on every branch with only the closed outcome. Map explicit Cedar deny to `denied`, idempotency conflicts to `conflict`, replay to `replay`, successful mutation to `success`, and uncertainty/transport/policy/integrity failures to `error`.

- [ ] **Step 4: Verify full-chain GREEN on the exact SHA**

Require formatter, complete Go/race, PostgreSQL 18.6 plus Rust musl integration, and the Rust authorization/interoperability/performance workflow because identity authorization changes are path-selected into that workflow.

### Task 3: Failure-Path Redaction and Mutation Sensitivity

**Files:**
- Modify: `job/internal/platform/identity/tenant_switch_trace_test.go`

**Interfaces:**
- Consumes the closed tracing adapter and production wiring from Tasks 1-2.
- Produces deny/error redaction evidence without changing public API or response contracts.

- [ ] **Step 1: Write failing deny and unavailable trace assertions**

For `errors.Join(ErrTenantSwitchForbidden, errors.New("trace-secret-forbidden"))` require HTTP 403, problem code `tenant_switch_forbidden`, no cookies/ETag, HTTP span outcome `denied`, and no exported string containing the sentinel. For `errors.Join(ErrTenantSwitchAuthorizationUnavailable, errors.New("trace-secret-unavailable"))` require HTTP 503, code `tenant_switch_authorization_unavailable`, outcome `error`, and the same redaction.

Inspect span names, attribute keys/values, events, status descriptions, and links. Require zero subject/tenant/workspace/policy/idempotency attributes and zero audit/outbox spans on pre-mutation authorization failure.

- [ ] **Step 2: Observe behavioral RED if failure outcomes/redaction are incomplete**

Accept RED only after formatting, vet, and existing behavior pass. If the initial implementation already satisfies the new assertions, perform the mutation in Step 3 rather than weakening or inventing a failure.

- [ ] **Step 3: Prove redaction sensitivity with a temporary mutation**

Temporarily add exactly one forbidden production call:

```go
span.RecordError(err)
```

or set a span status description from `err.Error()`. Publish the mutation on a normal fast-forward commit, require the redaction test to fail because the sentinel appears, then restore the production blob byte-for-byte. Do not change the test during the mutation cycle.

- [ ] **Step 4: Reverify the restored exact SHA**

Prove zero diff for the restored production file against the pre-mutation safe blob. Run formatter, full Go/race, PostgreSQL, and Rust authorization workflows on the same restored SHA.

### Task 4: Real PostgreSQL Correlation Evidence

**Files:**
- Modify: `job/internal/platform/identity/idempotent_tenant_switch_integration_test.go`
- Modify provider-required database workflow only if its existing path selection does not execute this test.

**Interfaces:**
- Consumes the real `machina_runtime` role, PostgreSQL 18.6, Rust Cedar process, and existing tenant-switch integration harness.
- Produces one committed trace whose correlation attribute equals the idempotency receipt, audit row, and outbox row correlation IDs.

- [ ] **Step 1: Add the PostgreSQL-backed trace assertion**

Install the in-memory exporter on the coordinator used by the existing successful PostgreSQL tenant switch. Query receipt, `audit.events`, and `ops.outbox` by their tenant-scoped keys using the existing admin inspection connection. Assert their correlation UUIDs are identical to the five-span trace correlation and that runtime role introspection remains `0:0:0:0`.

- [ ] **Step 2: Publish the integration test before any harness change**

Require a behavioral RED only if product instrumentation is incomplete. If the test passes with existing production instrumentation, retain it as new evidence and do not manufacture RED by altering a correct harness.

- [ ] **Step 3: Verify clean-environment exact-SHA integration**

Require static Rust 1.98.1 musl build, PostgreSQL 18.6, non-owner runtime role, FORCE RLS checks, successful tenant switch, audit/outbox atomicity, and trace correlation in the same job. Preserve and debug any infrastructure retry; do not hide attempts.

### Task 5: Independent Critique and Evidence Update

**Files:**
- Modify: `job/docs/engineering/MCH-S001-implementation-plan.md`
- Modify: `job/docs/handoffs/CHATGPT-CONTINUATION-2026-09-08.md`
- Modify: this plan

**Interfaces:**
- Produces durable evidence only for Task 6 trace-link/redaction work.

- [ ] **Step 1: Obtain independent critique**

Review the exact resulting SHA for contract coverage, parent/trace integrity, authorization ordering, transaction atomicity, replay, error classification, unbounded attributes, PII/secrets, raw error events/descriptions, trace failure side effects, RLS, concurrency, performance overhead, and unjustified abstraction.

- [ ] **Step 2: Correct every real finding through RED→GREEN**

Preserve each finding and failing evidence, implement the smallest root cause, rerun all affected exact-SHA gates, and repeat critique until no Critical/Important finding remains.

- [ ] **Step 3: Update only proven state**

Mark only `Evidence: trace IDs linking HTTP→authz→DB→audit/outbox and redaction assertions` complete after the exact-SHA gates and critique. Keep signed audit checkpoint behavior, complete Gate I, Task 7+, GAUNTLET, candidate freeze, promotion, and Slice completion open.

## Plan Self-Review

- Spec coverage: success and authorization failure trace paths, correlation persistence, redaction, runtime-role/RLS integration, replay outcome, and exact-SHA convergence are assigned to Tasks 1-5.
- Scope exclusions: no generic tracing platform, exporter deployment, log pipeline, profile pipeline, signed checkpoint, Keycloak, web, AI, or future Slice behavior is introduced here.
- Placeholder scan: this plan contains no TBD/TODO/“similar to” step; every RED, GREEN, mutation, and gate has a concrete expected behavior.
- Type consistency: all constructor and method names are defined in Task 1 or Task 2 before use; outcomes reuse `observability.Outcome`; correlation remains `pgtype.UUID`.

## Execution Mode

Execute task-by-task in the current construction branch with fresh independent review between material tasks. The Founder instructed continuous autonomous execution, so no additional execution-choice prompt is required.

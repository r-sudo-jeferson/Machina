# MCH-S001 Metric Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a small OpenTelemetry metrics boundary that can emit bounded operation telemetry while structurally rejecting PII, prompts, tenant slugs, identifiers, unknown dimensions, and unbounded values.

**Architecture:** `internal/platform/observability` owns a closed metric-label vocabulary and the only constructor for Machina operation instruments. Callers submit typed operation/outcome values; validation runs before any OpenTelemetry call and errors never repeat rejected values. The tenant-switch HTTP boundary records count and duration through an injected recorder while preserving its existing public constructor and response behavior.

**Tech Stack:** Go 1.27.1, OpenTelemetry Go 1.46.0 stable API/SDK, standard-library `net/http` and `time`. No Python.

**Spec:** `job/docs/engineering/MCH-S001-implementation-plan.md`, Task 6; `job/docs/engineering/MCH-S001-premortem.md`, risks 15–16.

## Global Constraints

- Slice is exactly `MCH-S001@1.0.0` under binding `FORGE-OPS-HIGHEND-v1.0.0`.
- All product files remain under `job`; root changes are limited to existing workflow glue.
- Pin stable OpenTelemetry Go modules to exactly `v1.46.0`; do not use the `v1.47.0-rc.1` prerelease.
- Metric attributes use a closed allowlist and bounded enum values. Raw prompt, email, name, tenant slug, subject/user/session/tenant/workspace IDs, idempotency keys, correlation IDs, and arbitrary caller labels are forbidden.
- Rejected values must not be repeated in error text, logs, test names, or failure diagnostics.
- Telemetry failure cannot authorize a request, change tenant-switch status/body/cookies, or bypass audit/outbox.
- Construction checks are not GAUNTLET evidence and do not complete Gate I or the Slice.

---

### Task 1: Closed metric attribute vocabulary

**Files:**
- Create: `job/internal/platform/observability/metrics.go`
- Create: `job/internal/platform/observability/metrics_test.go`
- Modify: `job/go.mod`
- Modify: `job/go.sum`

**Interfaces:**
- Consumes: `go.opentelemetry.io/otel/attribute` at `v1.46.0`.
- Produces: `type Operation string`, `type Outcome string`, `type MetricLabel struct`, `func SafeMetricAttributes(...MetricLabel) ([]attribute.KeyValue, error)`, and sentinel `ErrUnsafeMetricAttribute`.

- [x] **Step 1: Pin the stable OpenTelemetry API and test SDK**

Run from `job`:

```bash
go get go.opentelemetry.io/otel@v1.46.0 go.opentelemetry.io/otel/sdk/metric@v1.46.0
go mod tidy
```

Expected: `go.mod` and `go.sum` contain exact `v1.46.0` module requirements; no release candidate appears.

- [x] **Step 2: Write failing safety-boundary tests**

Create table-driven tests that require the known-safe pair to pass:

```go
got, err := SafeMetricAttributes(
	MetricLabel{Key: MetricOperation, Value: string(OperationTenantSwitch)},
	MetricLabel{Key: MetricOutcome, Value: string(OutcomeSuccess)},
)
if err != nil || len(got) != 2 {
	t.Fatalf("SafeMetricAttributes() = %#v, %v", got, err)
}
```

Require each of these keys to return `ErrUnsafeMetricAttribute`: `user.email`, `user.name`, `ai.prompt`, `tenant.slug`, `tenant.id`, `workspace.id`, `session.id`, `correlation_id`, `idempotency_key`, and `custom`. Also reject no labels, duplicate keys, more than two labels, empty values, and unknown values for an allowed key. Use an opaque sentinel such as `sensitive-value-should-not-escape` and assert it is absent from `err.Error()`.

- [x] **Step 3: Run the focused test and observe RED**

Run:

```bash
go test -count=1 ./internal/platform/observability
```

Expected: FAIL because the package API is not implemented.

- [x] **Step 4: Implement the minimal closed vocabulary**

Use these public values and keep validation tables package-private:

```go
var ErrUnsafeMetricAttribute = errors.New("unsafe metric attribute")

const (
	MetricOperation = "machina.operation"
	MetricOutcome   = "machina.outcome"
)

type Operation string

const (
	OperationTenantSwitch Operation = "tenant.switch"
	OperationAuthzEvaluate Operation = "authz.evaluate"
	OperationOutboxPublish Operation = "outbox.publish"
)

type Outcome string

const (
	OutcomeSuccess  Outcome = "success"
	OutcomeReplay   Outcome = "replay"
	OutcomeDenied   Outcome = "denied"
	OutcomeConflict Outcome = "conflict"
	OutcomeError    Outcome = "error"
)

type MetricLabel struct {
	Key   string
	Value string
}
```

`SafeMetricAttributes` must accept one or two unique labels, require every key/value pair to be present in a package-owned `map[string]map[string]struct{}`, and return only the sentinel error without interpolating rejected input. Preserve caller order for deterministic tests.

- [x] **Step 5: Run safety and dependency checks**

Run:

```bash
go test -count=1 ./internal/platform/observability
go mod tidy -diff
gofmt -l internal/platform/observability
```

Expected: PASS and no output from the last two commands.

### Task 2: OpenTelemetry operation counter and duration histogram

**Files:**
- Modify: `job/internal/platform/observability/metrics.go`
- Modify: `job/internal/platform/observability/metrics_test.go`

**Interfaces:**
- Consumes: `metric.Meter`, `SafeMetricAttributes`, `Operation`, and `Outcome` from Task 1.
- Produces: `type OperationMetrics`, `func NewOperationMetrics(metric.Meter) (*OperationMetrics, error)`, and `func (*OperationMetrics) Record(context.Context, Operation, Outcome, time.Duration) error`.

- [x] **Step 1: Write a failing in-memory SDK test**

Use `sdkmetric.NewManualReader` and `sdkmetric.NewMeterProvider` to record one tenant-switch success. Collect `metricdata.ResourceMetrics` and require:

- counter `machina.operation.count` equals `1`;
- histogram `machina.operation.duration` has one point with a non-negative seconds value;
- both points contain only `machina.operation=tenant.switch` and `machina.outcome=success`.

Add validation cases for nil receiver, negative duration, unknown operation, and unknown outcome. A zero duration is valid; no invalid measurement may reach the reader.

- [ ] **Step 2: Run the recorder test and observe RED**

Not claimed retrospectively: the test was written before the implementation,
but this exact command was not captured until after GREEN. Step 4's mutation
check independently proved that the unsafe-operation assertion fails when the
validation call is removed.

Run:

```bash
go test -count=1 ./internal/platform/observability -run TestOperationMetrics -v
```

Expected: FAIL because `OperationMetrics` is undefined.

- [x] **Step 3: Implement the two fixed instruments**

Construct instruments with fixed names and units:

```go
count, err := meter.Int64Counter(
	"machina.operation.count",
	metric.WithUnit("{operation}"),
)
duration, err := meter.Float64Histogram(
	"machina.operation.duration",
	metric.WithUnit("s"),
)
```

`Record` calls `SafeMetricAttributes` before either instrument. It returns `ErrInvalidMetricRecorder` for a nil receiver, `ErrInvalidMetricMeasurement` for a negative duration, and preserves `ErrUnsafeMetricAttribute` for unknown enums. Only after validation may it call `count.Add` and `duration.Record` with `metric.WithAttributes`.

- [x] **Step 4: Run tests and a mutation check**

Run the focused tests, then temporarily bypass `SafeMetricAttributes` in `Record`; confirm the unknown-operation test fails because an invalid point becomes observable. Restore the production file exactly and rerun:

```bash
go test -count=1 ./internal/platform/observability
git diff --check
```

Expected after restoration: PASS.

### Task 3: Tenant-switch HTTP metric wiring

**Files:**
- Modify: `job/internal/platform/identity/tenant_switch_http.go`
- Modify: `job/internal/platform/identity/tenant_switch_http_test.go`

**Interfaces:**
- Consumes: `*observability.OperationMetrics`; existing `NewTenantSwitchHTTPHandler(tenantSwitchExecutor)` remains source-compatible.
- Produces: a package-private constructor `newTenantSwitchHTTPHandler(tenantSwitchExecutor, *observability.OperationMetrics, func() time.Time)` for deterministic tests.

- [ ] **Step 1: Write failing handler metric tests**

Create an SDK manual reader and injected operation metrics. Require one point for each executor-reached terminal class:

| HTTP behavior | Outcome |
|---|---|
| committed switch | `success` |
| immutable replay | `replay` |
| idempotency conflict/in-progress/stale | `conflict` |
| PostgreSQL `42501` | `denied` |
| internal/unavailable/invalid result | `error` |

Use a deterministic clock that advances by `25*time.Millisecond`. Existing status, body, ETag, `Cache-Control`, and cookie assertions remain unchanged.

- [ ] **Step 2: Run the handler tests and observe RED**

Run:

```bash
go test -count=1 ./internal/platform/identity -run 'TestTenantSwitchHTTPHandler.*Metric' -v
```

Expected: FAIL because the injection constructor and recording are absent.

- [ ] **Step 3: Add metric recording without changing HTTP authority**

The public constructor obtains `otel.Meter("github.com/r-sudo-jeferson/Machina/job/internal/platform/identity")` and delegates to the private constructor. The private constructor rejects nil executor, metrics, or clock. Start timing only after session/CSRF/body validation and immediately before `switcher.Switch`. Record exactly once after the executor or result validation returns. Derive outcome exclusively from typed errors, HTTP status, and `result.Replay`; never use request data as a label.

Metric recording errors are safe to ignore at the HTTP layer because validation prevents emission; they must not change the business response. Add a comment documenting that invariant.

- [ ] **Step 4: Re-run existing and new HTTP tests**

Run:

```bash
go test -count=1 ./internal/platform/identity -run TestTenantSwitchHTTPHandler -v
go test -race -count=1 ./internal/platform/identity ./internal/platform/observability
```

Expected: PASS with unchanged HTTP responses and cookies.

### Task 4: Repository verification and durable evidence

**Files:**
- Modify: `job/docs/engineering/MCH-S001-implementation-plan.md`
- Modify: this plan file

**Interfaces:**
- Consumes: Tasks 1–3 and the construction workflows.
- Produces: a durable evidence record for only the metric-label requirement; Task 6, Gate I, GAUNTLET, candidate freeze, and GitLab promotion remain open.

- [x] **Step 1: Run the complete local Go gate**

Run from `job`:

```bash
go mod tidy -diff
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./scripts/verify/...
go test -count=1 ./...
go test -race -count=1 ./internal/platform/observability ./internal/platform/identity
```

Expected: every command passes.

- [x] **Step 2: Publish one atomic implementation commit and observe exact-SHA CI**

Safe code checkpoint `318260aeebbef6f0796ce52f195ba68b16194f51`
passed Go run/job `34262739613` / `102184487586`, protobuf
`34262739662` / `102184487915`, PostgreSQL `34262739623` /
`102184487864`, Rust authorization/performance `34262739609` /
`102184487491`, and formatting `34262739631` / `102184486932`.

Commit message:

```text
feat(mch-s001): enforce safe operation metrics
```

Require the Go construction workflow and any path-selected database workflow to finish successfully on the exact implementation SHA. Record run and job IDs.

- [ ] **Step 3: Update only the proven parent-plan checkbox**

Mark `Prove metrics reject raw email/name/prompt/tenant-slug labels` complete and append the exact implementation SHA, local race result, workflow run ID, and job ID. Do not mark the Task 6 heading, Gate I, full Slice verification, GAUNTLET, candidate freeze, or promotion complete.

- [ ] **Step 4: Self-review the plan execution**

Confirm the final diff contains no placeholders, prerelease dependencies, arbitrary metric-label API, raw sensitive examples beyond synthetic test sentinels, or changes outside `job`. A separate independent critic still owns final acceptance.

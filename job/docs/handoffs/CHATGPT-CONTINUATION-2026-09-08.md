# ChatGPT Continuation Handoff — 2026-09-08

## State

- Status: `IN_PROGRESS`.
- Slice: `MCH-S001@1.0.0`.
- Binding: `FORGE-OPS-HIGHEND-v1.0.0` (exact match required).
- Canonical repository: GitLab `machina-group/machina`.
- Construction repository: GitHub `r-sudo-jeferson/Machina`.
- Construction branch: `forge/mch-s001-1.0.0`.
- Safe code checkpoint: `318260aeebbef6f0796ce52f195ba68b16194f51`.
- The commit containing this handoff is documentation-only and is a child of
  the safe code checkpoint.
- Authorized GitLab base recorded by the canonical handoff:
  `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`.
- GitLab main observed during reconciliation:
  `9c2728079fce4cbaceeef9224f0cd18835483e75d2c07bd516fadafdd38761b0`.
- GAUNTLET: `GNT-MCH-S001-001`; not run and not passed.
- Candidate freeze and exact GitLab promotion: not started.

## Completed and verified

Tenant-switch Task 5 executor-side work is implemented and recorded through
`debc419be254e6619f4f8af8becb26e8668553a2`; its documentation record is
`5b81b7b746b72f44a434a6e8e92a6e2888c17270`. The first three Task 5 checklist
items are complete. Independent critique, full Slice verification, GAUNTLET,
candidate freeze, and GitLab promotion remain open.

The Task 5 continuation fixed the inherited coordinator fixture mismatch,
proved audit/outbox correlation and secret exclusion, proved that audit/outbox
failures stop receipt completion, proved replay emits no duplicate events, and
covered old/new session-CSRF pairs through the real middleware.

The safe code checkpoint begins Task 6 with a self-contained metrics foundation:

- OpenTelemetry Go is pinned to stable `v1.46.0`; the `v1.47.0-rc.1`
  prerelease is not used.
- `job/internal/platform/observability/metrics.go` exposes a closed vocabulary
  for `machina.operation` and `machina.outcome`.
- Raw email, name, prompt, tenant slug, identifiers, unknown keys/values,
  duplicates, and excessive labels are rejected with an opaque error.
- `OperationMetrics` emits only fixed `machina.operation.count` and
  `machina.operation.duration` instruments.
- SDK/manual-reader tests prove valid emission and prove invalid measurements
  never reach the collector.
- A mutation that bypassed `SafeMetricAttributes` made
  `TestOperationMetricsRejectsInvalidMeasurementsBeforeEmission` fail; the
  production file was restored before the full gate.

One procedural checkbox is intentionally not claimed: the Task 2 recorder test
was written before implementation, but its exact pre-implementation RED command
was not captured. The later mutation check provides sensitivity evidence; do
not rewrite history by marking that RED step complete.

## Exact-SHA evidence for `318260aeebbef6f0796ce52f195ba68b16194f51`

| Workflow | Run | Job | Result |
|---|---:|---:|---|
| Verify Go construction | `34262739613` | `102184487586` | PASS |
| Verify authz Go protobuf generation | `34262739662` | `102184487915` | PASS |
| Verify PostgreSQL construction | `34262739623` | `102184487864` | PASS |
| Verify Rust authorization and performance | `34262739609` | `102184487491` | PASS |
| Debug gofmt | `34262739631` | `102184486932` | PASS |

The local full Go gate also passed: `go mod tidy -diff`, repository-wide
`gofmt`, `go vet ./...`, `go test -count=1 ./scripts/verify/...`,
`go test -count=1 ./...`, and race tests for `observability` plus `identity`.

## Resume point

1. Clone or fetch GitHub `r-sudo-jeferson/Machina` and check out
   `forge/mch-s001-1.0.0` at the actual remote HEAD. Confirm it is a descendant
   of safe code checkpoint `318260aeebbef6f0796ce52f195ba68b16194f51`.
2. Read both applicable `AGENTS.md` files completely, then read:
   - `job/docs/engineering/MCH-S001-implementation-plan.md`;
   - `job/docs/engineering/MCH-S001-premortem.md`;
   - `job/docs/superpowers/plans/2026-09-08-mch-s001-metric-safety.md`;
   - this handoff.
3. Continue inline at **Task 3: Tenant-switch HTTP metric wiring** in the
   metric-safety plan. Write the failing SDK/manual-reader handler tests first.
4. Preserve the public `NewTenantSwitchHTTPHandler` signature. Use the planned
   private constructor for deterministic metric/clock injection.
5. Derive metric outcomes only from typed server results; never place request
   values, tenant coordinates, correlation IDs, idempotency keys, cookies, CSRF
   tokens, names, emails, prompts, or slugs in metric attributes.
6. After Task 3, run the complete local gate and exact-SHA GitHub Actions. Only
   then update the Task 6 metric-label checkbox and evidence record.

## Non-negotiable boundaries

- No Python.
- All product work remains under `job`.
- Do not trust tenant identifiers from URL/header/body as authority.
- Do not publish cookies on replay, callback failure, or uncertain commit.
- Do not call construction CI, self-review, or executor testing a GAUNTLET PASS.
- Do not declare the Slice complete until the frozen candidate is verified,
  independently accepted, and promoted exactly to canonical GitLab.
- Preserve unrelated user changes and re-read the actual remote HEAD before any
  write.

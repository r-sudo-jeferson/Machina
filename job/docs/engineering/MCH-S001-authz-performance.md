# MCH-S001 Task 4 Authorization Performance Model

Status: ENGINEERING VERIFICATION MODEL. This document defines the Task 4 authorization-specific measurement only. It is not a claim that Gate H or the complete Slice load model has passed.

## Contract

- Slice: `MCH-S001@1.0.0`
- Authorization objective: p95 below 10 ms.
- The Rust evaluator and gRPC transport overhead are measured separately, as required by the implementation plan.
- A result is valid only for the exact GitHub candidate SHA that produced the workflow log.

## Normal-path model

The normal authorization path is an exact required-policy-version cache hit. PostgreSQL-backed cold loads occur on cache miss/version change and are verified separately from this latency objective.

### Evaluator measurement

- One tenant context.
- Starter policy snapshot already parsed and strictly validated.
- One subject, one action, one resource and the starter owner context.
- 1,000 warmup decisions.
- 20,000 timed decisions.
- Sequential in-process evaluation to isolate Cedar/evaluator cost from transport.
- Report p50, p95, p99, throughput and error count.

### gRPC measurement

- One tenant with the exact starter policy version preloaded in the service cache.
- Real tonic server and generated tonic client over loopback HTTP/2.
- 256 warmup requests.
- 16 concurrent workers.
- 1,000 measured requests per worker, 16,000 measured requests total.
- Every measured response must be an allow for the known-valid starter request; any transport or decision error fails the harness.
- Report p50, p95, p99, aggregate throughput and error count.
- p95 must remain strictly below 10 ms.

## Runtime evidence

`job/scripts/authzperf/run.sh` records the pinned Rust version, operating system/kernel, logical CPU count, CPU model and total memory before running the release-profile benchmark. The GitHub Actions run therefore supplies the runtime/hardware evidence for the exact candidate without committing mutable runner-specific results into the public repository.

## Boundaries

This Task 4 model intentionally does not claim final Slice saturation or fault-injection evidence. Gate H must still expand the load model to documented tenant/user/data volume and include high-cardinality tenants and policy sets, policy-version churn, PostgreSQL latency, authz restart, provider failures, saturation, errors and cross-tenant impact. Cold policy refresh latency is also tracked separately because it is not the steady-state exact-version cache-hit path measured here.

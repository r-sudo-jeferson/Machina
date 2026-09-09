# MCH-S001 Database Migration Recovery Contract

This document is an executable companion to the MCH-S001 database gates. It defines how the S001 PostgreSQL schema may be advanced and how preview environments must recover if a migration or application candidate is rejected.

## Migration policy

The S001 migration set is **forward-only** and additive. Migrations `0001` through `0017` create schemas, tables, indexes, functions, policies, triggers, grants, constraints, session/idempotency boundaries, and audit-integrity/checkpoint structures required by the authorized Slice. They must not contain destructive `DROP`, `TRUNCATE`, bulk `DELETE`, column-type rewrite, or equivalent data-loss operations.

A deployment rollback does not run reverse DDL. Application rollback and database restore are separate operations: reverting an application artifact must never attempt to infer or execute a destructive down migration against a database that may already contain newer data.

## Audit, outbox, and checkpoint rollback boundary

Audit integrity is part of the API mutation transaction and is not optional during rollback. A tenant mutation that cannot persist its required `audit.events` row, database-owned `audit.event_chain` linkage, idempotency receipt, and outbox row must fail and roll back rather than commit an unaudited partial mutation.

The additive audit structures introduced through migration `0017` remain in place across an application rollback. They do not require destructive reverse DDL:

- `audit.events` remains append-only and required for audited API mutations;
- `audit.event_chain` and `audit.chain_heads` remain database-owned integrity state maintained by the audit append trigger in the same transaction as `audit.events`;
- `audit.checkpoints` remains additive immutable evidence and may receive no new rows while checkpoint generation is disabled;
- outbox delivery/consumption may be paused or disabled operationally, but API mutations must continue to enqueue their transactional outbox row before commit;
- disabling checkpoint generation or outbox consumption must never disable, bypass, or weaken the API audit write path.

The PostgreSQL integration boundary proves this fail-closed behavior against the non-owner runtime role: a test-only failure injected at `audit.event_chain` causes the complete tenant-switch transaction to roll back, leaving the original session active and receipt/audit/chain/outbox effects absent; after removing the failure, the same request commits exactly once and replay produces no duplicate side effects. The API coordinator is exercised without a checkpointer in that rollback proof, demonstrating that checkpoint generation is outside the mutation critical path while audit chaining remains mandatory.

## Preview recovery

Preview is disposable infrastructure, but recovery must still be deterministic and evidence-producing.

1. Record the exact GitHub candidate SHA, migration file digests, PostgreSQL image digest, and schema version being tested.
2. Before applying a migration to any persistent preview database, create or verify a restorable **snapshot** or provider-supported point-in-time restore boundary. Ephemeral test databases created from scratch do not require a pre-migration snapshot because they contain only synthetic fixtures.
3. If migration application fails, stop the candidate. Do not retry with altered SQL against the same partially understood state.
4. Preserve logs and the failed database state when practical for root-cause analysis; do not expose secrets, customer data, or private evidence in public GitHub artifacts.
5. Recover preview either by creating a fresh database from the last accepted migration set or by **restore** from the validated pre-migration snapshot/PITR point.
6. Redeploy the last accepted application artifact against the recovered database.
7. Re-run schema ownership, non-`BYPASSRLS` runtime-role, `ENABLE/FORCE RLS`, missing-context deny, cross-tenant isolation, pooled-context reset, last-owner concurrency, audit-chain integrity, tenant-switch transactional rollback/retry, and runtime smoke checks before preview is considered healthy again.

## Promotion and production boundary

MCH-S001 does not authorize a production release. Before any future production promotion, the selected managed PostgreSQL service must have a separately verified backup/PITR policy, retention, encryption, restore permissions, RPO/RTO, regional recovery behavior, and tested restore procedure. No provider capability is assumed merely because it exists in documentation or a connected plugin.

A production migration candidate may proceed only when the exact database backup/restore controls required by its release contract are proven for the target environment. If that evidence is absent, the database state is `NOT_VERIFIED` and promotion is blocked.

## Failed migration handling

- Transactional migration failure: allow PostgreSQL to roll back the migration transaction, preserve the error, fix the root cause in a new candidate, and rerun from a known-good database.
- Failure after a migration committed but before application rollout completed: keep the additive schema, roll back the application artifact if it remains compatible, or restore the database snapshot/PITR point if the release contract requires schema rollback.
- Data-corruption suspicion: stop writes, preserve forensic evidence, restore into an isolated validation target first, verify integrity and tenant isolation there, then perform controlled cutover. Never repair by ad-hoc destructive SQL in the canonical environment.

## Recovery verification

A recovery is not successful merely because PostgreSQL starts. Before reopening writes, verification must establish:

- exact expected migration set and artifact identity;
- migration ownership remains with the migration role;
- runtime remains non-owner, non-superuser, and without `BYPASSRLS`;
- tenant-qualified constraints and `ENABLE/FORCE ROW LEVEL SECURITY` remain present;
- missing tenant context observes zero tenant rows and cannot mutate tenant data;
- two-tenant adversarial isolation still passes;
- transaction-local tenant context does not leak through pooled connection reuse;
- last-owner sequential and concurrent protections still pass;
- audit event append-only rules, database-owned chain continuity, tamper evidence, and checkpoint constraints still pass;
- tenant-switch audit-chain failure still rolls back every mutation/receipt/audit/chain/outbox effect and the retry still commits exactly once;
- application/runtime smoke checks use the restored database without bypass credentials.

Only after those checks pass may the recovered preview be treated as usable. This recovery contract does not convert Task PASS into Slice COMPLETE; GAUNTLET, candidate freeze, exact GitLab promotion, and promotion verification remain separate gates.

# ChatGPT Continuation Handoff — 2026-09-09

## State

- Status: `IN_PROGRESS`.
- Slice: `MCH-S001@1.0.0`.
- Binding: `FORGE-OPS-HIGHEND-v1.0.0` (exact match required).
- Canonical repository: GitLab `machina-group/machina`; it remains the only Canon.
- Construction repository: GitHub `r-sudo-jeferson/Machina`.
- Construction branch: `forge/mch-s001-1.0.0`.
- Safe reviewed product-code checkpoint: `a00e7c8f79369dcc7ca74af4b065043ab83a7813`.
- Evidence/documentation commits after that checkpoint are normal fast-forward descendants and do not change the reviewed product-code tree unless explicitly stated.
- Authorized GitLab base recorded by the canonical handoff: `fa55084ea42a40b35d80d081e658c502df709b37e61f75dba2635d986009f469`.
- GitLab main observed during reconciliation: `9c2728079fce4cbaceeef9224f0cd18835483e75d2c07bd516fadafdd38761b0`.
- GAUNTLET: `GNT-MCH-S001-001`; `OPEN`, not run and not passed.
- Candidate: not frozen. Promotion: not started.

## Completed and verified since the prior handoff

The earlier Task 5 transaction/audit/outbox work and Task 6 bounded metrics foundation remain intact. Subsequent verified work added:

- Policy-snapshot pinning at `8afc0722376cbe64def050840f9c0fcdfb9435d1`. Go run `34287177592`, formatter run `34287177574`, and PostgreSQL run `34287177594` succeeded on the exact SHA.
- HTTP authorization semantics at `bbd68cf74c903b541f80f1049adc48c3f2b5bb7f`: explicit Cedar deny maps to 403 / `tenant_switch_forbidden` / `denied`; authorization uncertainty maps to 503 / `tenant_switch_authorization_unavailable` / `error`; both remain RFC 9457, `no-store`, without cookies, ETag, or exposed internal cause. Exact Go run `34289343772`, formatter run `34289344604`, and PostgreSQL run `34289344093` attempt 2 succeeded; attempt 1 had a preserved transient readiness failure.
- Cedar mutation sensitivity and durable path selection at restored SHA `298015a22e034d535b99057fea123c95325d7c2b`. Go run `34290874612`, formatter run `34290874643`, PostgreSQL run `34290874663`, and Rust authorization run `34290874634` succeeded. Mutation SHA `9ad784eaf3e48cc58d03066471ace8a2bd33ca92` was killed by explicit-deny and replay-authorization tests.
- Strict safe-metadata reconstruction at `2d7215e784346695022126752533aacb8254d1d9`. Formatter run `34295107864` / job `102289916036`, Go run `34295107785` / job `102289918300`, and PostgreSQL run `34295107770` / job `102289918652` succeeded. The PostgreSQL job reconstructed real allowed and denied rows under `machina_runtime`, reported `runtime_role_flags=0:0:0:0`, and found zero owner, RLS, or tenant-key violations.
- Independent critique of `2d7215e784346695022126752533aacb8254d1d9` found no Critical or Important issue. Its only Minor observed that deny-plus-null-reasons lacks a dedicated case; the common strict-null boundary already rejects it before decision-specific validation.
- Tenant-switch trace/redaction evidence at `a00e7c8f79369dcc7ca74af4b065043ab83a7813`: exactly one trace links `tenant.switch.http` → transaction → authorization/audit/outbox with only server-generated correlation plus the closed outcome vocabulary. The PostgreSQL integration proves the same correlation persists in the idempotency receipt, audit row, and outbox row under the real non-owner `machina_runtime` role.
- Exact final trace gates on `a00e7c8f79369dcc7ca74af4b065043ab83a7813`: formatter run `34339654546`, Go run `34339654533` / job `102427186129`, PostgreSQL run `34339654525` / job `102427187365`, and Rust authorization run `34339654545` all succeeded. PostgreSQL reported `runtime_role_flags=0:0:0:0` with zero owner, RLS, or tenant-key violations.
- Trace TDD/adversarial evidence is preserved. Root-span RED `9a86be0decae958820f508ccc5c778c4d105e4f7` failed because zero spans were exported where one was required. Full-chain RED `ce4cbaa60cb23c918f6250df884221eb72af6d3c` failed because one span existed where five were required. Redaction mutation `4ad9690a6ce04f59893e9ee4429a702c5ec7a408` failed because forbidden `span.RecordError` exported `exception.message` containing the injected secret sentinels; safe production was restored at `d0f004268855eede7b2aee56c43edc442ec214de` without weakening the assertions.
- Separated Critic review of `a00e7c8f79369dcc7ca74af4b065043ab83a7813` found no unresolved Critical or Important issue across trace parentage, authorization ordering, transaction atomicity, replay, outcome classification, redaction/cardinality, RLS, trace-failure side effects, concurrency/performance impact, or abstraction scope. Replay already has behavioral proof of no session rotation, no new browser secrets, and no audit/outbox mutation; a dedicated replay exporter-tree assertion is optional strengthening, not a demonstrated contract miss.

Behavioral RED evidence for the final decoder strengthening is also preserved: `ccf6692ca30e4fdce80f2eaf0148d74e38f01a32` accepted `latency_ms:null`, and `27b84a9ec160761d0a734cf5e98133f83ef39c18` accepted allow-side `reason_codes:null`; both failed only at the intended assertions after module, formatting, and vet checks.

## Resume point

1. Fetch GitHub `r-sudo-jeferson/Machina`, check out `forge/mch-s001-1.0.0`, and require its head to equal or descend normally from reviewed product-code checkpoint `a00e7c8f79369dcc7ca74af4b065043ab83a7813`.
2. Re-read the applicable `AGENTS.md`, canonical Slice/Gate I language, Task 6 in the implementation plan, audit/outbox code, migrations/queries, production-system architecture, and pre-mortem before the next write.
3. Plan and attack the remaining Task 6 boundary: tamper-evident/hash-chained signed audit checkpoint behavior plus rollback/disable proof that cannot bypass audit on API mutations. Do not select signing/key-management mechanics from preference; derive them from the current code, deployment contracts, public-GitHub boundary, and canonical security requirements.
4. Implement the authorized remainder with TDD, preserve real RED evidence, run path-selected exact-SHA gates, and perform separated Critic review before marking any additional Task 6/Gate I state complete.
5. Keep complete Gate I, Task 7+, GAUNTLET, candidate freeze, promotion, and Slice completion open until separately proven. The trace-link evidence checkbox alone is now closed.

## Non-negotiable boundaries

- No Python, history rewrite, force push, or dual-master behavior.
- All product artifacts remain under `job`; root changes are limited to provider-required glue selecting `/job` checks.
- Cedar authorization remains before any effective mutation, claim, audit, or outbox operation; RLS remains an independent defense.
- Do not trust tenant, workspace, subject, or policy authority from client input.
- Do not publish cookies on replay, authorization failure, callback failure, or uncertain commit.
- Do not export raw errors, secrets, identifiers other than the server-generated trace correlation, policy hashes, or unbounded attributes.
- Signing keys, credentials, private evidence, production/customer data, or secret material must never be committed to the public construction repository.
- Construction CI and independent critique are not a GAUNTLET PASS. Do not freeze or promote until the complete Slice and exact candidate satisfy the authorized process.
- Local execution in the current ChatGPT runtime remains `NOT_VERIFIED` unless fresh local execution evidence is explicitly produced; exact-SHA CI/integration evidence above remains valid for its named product SHA only.

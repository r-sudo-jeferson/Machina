# MCH-S001 Pre-Mortem Attack

Status: completed before production implementation. This is a separated Critic pass; no claim is made that a separate human or separate model authored it.

## Attack findings incorporated into the plan

1. **Binding serialization fragility — resolved before build.** A punctuation-only `/v` versus `-v` difference could stop construction despite identical binding family/version. Founder amendment MCH-BINDING-001 makes only the two explicit 1.0.0 serializations equivalent; all other forms still fail closed. CI must encode this rule.
2. **GitLab/GitHub commit algorithms differ.** Never compare provider commit SHAs for content identity. Promotion verification must use deterministic path/mode/content SHA-256 manifests plus provider-native candidate/base SHAs for traceability.
3. **Canonical private docs must not be deleted or leaked.** GitHub public candidate ownership must be explicit. Promotion must update candidate-owned public `/job` product paths while preserving Canon-only private control/handoff material; no blind whole-tree replacement.
4. **Tenant bootstrap can accidentally require an RLS bypass.** Design bootstrap around a prospective server-owned tenant context and one transaction; do not introduce a generic SECURITY DEFINER escape hatch.
5. **Last-owner safety is race-prone if checked only in Go.** Use database locking/invariant enforcement plus concurrent tests.
6. **Invitation lookup can become a cross-tenant oracle.** Use a minimal global token-hash locator; resolve tenant context before returning tenant-owned invitation data.
7. **RLS can produce false confidence when tests use owner credentials.** Isolation tests must run with the actual non-owner runtime role and `FORCE ROW LEVEL SECURITY`.
8. **Connection pooling can leak tenant state.** Use transaction-local context only and explicitly test pooled connection reuse/missing context.
9. **Cedar cache can produce stale allow.** Every request carries `required_policy_version`; inability to satisfy it returns deny.
10. **Authz outage cannot have a permissive fallback.** Go client and BFF remain fail-closed for timeout/crash/restart/invalid response.
11. **AI tests can fake product truth.** Unit fakes are allowed for orchestration tests but Gate E requires a real configured provider and run metadata.
12. **Prompt injection can arrive through first-party display fields.** User/tenant/workspace names and tool/retrieval output are always untrusted data; no retrieved content can expand tool authority.
13. **AI tenant selection must be server-owned.** The tool schema does not accept an arbitrary tenant ID; tenant context is injected after session/membership resolution.
14. **AI provider/model drift invalidates evidence.** Record exact provider/model/prompt/tool versions; model changes require affected evals again.
15. **Audit is not equivalent to ordinary logs.** Privileged/session/tenant/Ask decisions need reconstructible audit metadata and tamper-evident checkpoints, with redaction boundaries separate from operational telemetry.
16. **Metrics can leak PII or explode cardinality.** Raw prompt/email/name/slug/user identifiers are prohibited metric labels; bounded pseudonymous dimensions only.
17. **Public GitHub supply chain is an attack boundary.** Third-party actions use full commit SHAs, fork code receives no privileged identity, and OIDC replaces long-lived cloud keys.
18. **No-Python can regress through tooling rather than source files.** Scan file extensions, shebangs, workflow commands, container bases and repository-owned tool manifests.
19. **Neumorphism can erase affordances when shadows disappear.** Forced-colors, focus, labels, structure and state must remain clear with shadows disabled.
20. **Automated accessibility is insufficient.** GAUNTLET requires keyboard, screen-reader, zoom, forced-colors and reduced-motion evidence in addition to automated checks.
21. **Performance objectives are meaningless without a load model.** Every latency report must state tenant/user/data volumes, concurrency, region/runtime resources and saturation/error data.
22. **Preview infrastructure can become premature platform sprawl.** S001 uses the smallest production-grade cell; no Kubernetes/microservice proliferation without measured need.
23. **Invited-user journey does not justify building S006 notifications.** S001 owns secure invite creation/acceptance and a deterministic share/copy path; outbound notification platform remains excluded.
24. **Candidate PASS can become detached from promotion.** Freeze SHA and artifact digests after final PASS; any candidate modification invalidates prior PASS.

## Plan changes caused by the attack

- Binding comparator and tests moved to Task 1 before any application foundation.
- Promotion identity explicitly uses content manifests rather than cross-provider commit SHA equality.
- Runtime DB role/RLS/pool-leak tests are mandatory, not optional integration coverage.
- Required policy version is part of the authz contract.
- Real-provider AI evidence is separated from unit fake-provider testing.
- Audit checkpointing, telemetry label policy and public-repository supply-chain controls are part of S001 rather than deferred polish.
- Accessibility manual evidence and explicit load model are GAUNTLET prerequisites.

No Slice objective, security invariant, acceptance criterion other than the Founder-authorized binding serialization comparison, or GAUNTLET attack was removed or weakened.

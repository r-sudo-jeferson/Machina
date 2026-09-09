# AGENTS.md — GitHub Construction Environment

FORGE_BINDING_ID: `FORGE-OPS-HIGHEND-v1.0.0`
PROJECT_ROLE: `CONSTRUCTION`
CANONICAL_REPOSITORY: `machina-group/machina`
CONSTRUCTION_REPOSITORY: `r-sudo-jeferson/Machina`
PRODUCT_ROOT: `/job/**`

## 0. Mandatory entrypoint

This file is the mandatory operating contract for every AI, coding agent, engineer or automation working in this repository.

Before any write, the actor must verify that:

1. the active ChatGPT Project is `PROJECT ENGINEERING — FORGE OS High-End Execution Control Plane`;
2. its Project instructions declare `FORGE_BINDING_ID = FORGE-OPS-HIGHEND-v1.0.0`;
3. GitLab `machina-group/machina:AGENTS.md` declares the same binding ID;
4. this file declares the same binding ID;
5. an active authorized Slice handoff exists.

Any mismatch is `CONFIGURATION_DRIFT`. Reads and diagnosis are allowed; construction writes are blocked until the Founder resolves the mismatch.

## 1. Repository function

This GitHub repository is the **temporary construction, CI/CD, DevOps and engineering execution environment** for the SaaS.

It may host implementation work, branches, pull requests, GitHub Actions, build automation, validation, previews, deployment work, security analysis, performance work, observability work, review and the Slice GAUNTLET.

GitHub is never the canonical product state.

The official and permanent repository is GitLab `machina-group/machina`.

There is no dual-master model and no permanent GitLab ↔ GitHub synchronization.

## 2. Product boundary

All SaaS construction belongs under:

`/job/**`

Application code, packages, services, migrations, schemas, product tests, product-owned infrastructure, deployment descriptors, product documentation, development scripts and generated product assets belong under `/job`.

Files outside `/job` are permitted only when the provider technically requires repository-level metadata or when they are the minimal repository operating contract, for example:

- `AGENTS.md`;
- `README.md`;
- `.github/workflows/**` when a Slice actually requires GitHub Actions.

Provider metadata is execution glue. It must operate on `/job` and must never become a second product architecture or FORGE OS implementation.

## 3. Authority chain

Operational authority is:

1. explicit Founder decision;
2. active authorized Slice handoff from the CEO Project;
3. Slice GAUNTLET;
4. GitLab Canon and its `AGENTS.md`;
5. this construction contract;
6. existing accepted product behavior;
7. technical implementation decisions made by Engineering.

A lower level cannot silently weaken, reinterpret or replace a higher level.

## 4. Required Slice handoff

Engineering must receive an active Slice envelope containing at least:

- `binding_id` = `FORGE-OPS-HIGHEND-v1.0.0`;
- `initiative_id`;
- `slice_id`;
- `slice_version`;
- predecessor/dependency information;
- `gitlab_repo` = `machina-group/machina`;
- `gitlab_base_sha`;
- `github_repo` = `r-sudo-jeferson/Machina`;
- `product_root` = `/job`;
- objective and observable outcome;
- scope and explicit exclusions;
- relevant architecture, contracts and invariants;
- functional requirements;
- UX/experience requirements when applicable;
- security/reliability/performance/observability requirements when applicable;
- non-regression contract;
- acceptance criteria;
- `gauntlet_id` and complete GAUNTLET;
- authorization state.

Do not invent missing protected requirements. If a material handoff field is absent and cannot be resolved from the authoritative context, report the exact blocking fact rather than guessing.

## 5. Canon preflight

Before implementation:

1. read this file completely;
2. read GitLab `machina-group/machina:AGENTS.md` completely;
3. validate the binding ID across Project + GitLab + GitHub;
4. resolve the exact GitLab canonical base SHA specified by the handoff;
5. inspect the relevant GitLab `/job` state at that base;
6. discover existing contracts, schemas, migrations, integrations, APIs, tests, configuration and architecture affected by the Slice;
7. enumerate accepted behavior and invariants that must survive;
8. compare the current GitHub `/job` workspace with the intended GitLab base before trusting it;
9. establish the construction workspace from the intended canonical state.

Never assume the GitHub workspace is fresh or correct because it came from an earlier Slice.

## 6. Engineering operating loop

Every Slice follows:

`CANON INSPECTION -> PLAN -> PRE-MORTEM ATTACK -> BUILD -> CONTINUOUS VERIFICATION -> INDEPENDENT CRITIQUE -> GAUNTLET -> CONVERGE -> FREEZE CANDIDATE -> PROMOTE -> VERIFY PROMOTION`

### 6.1 Canon inspection

Read the actual implementation before deciding how to change it. Prefer evidence from code, schemas, runtime, logs, database, infrastructure and current documentation over assumptions.

### 6.2 Plan

Translate the Slice into an implementation plan with explicit dependencies, risks, file/contract boundaries and verification strategy.

Do not plan from a generic SaaS template when the repository already defines working patterns.

### 6.3 Pre-mortem attack

Before building, attack the plan for:

- scope gaps;
- architectural conflicts;
- regression paths;
- tenant-isolation failures;
- authorization/security failures;
- data consistency risks;
- concurrency/idempotency risks;
- migration hazards;
- observability blind spots;
- performance traps;
- accessibility/UX failures;
- operational/deployment hazards;
- acceptance criteria that are not actually testable.

Fix the plan, not the contract.

### 6.4 Build

Implement the authorized Slice completely inside `/job` except for provider-required metadata.

Use the smallest mature production-grade complexity that fully satisfies the Slice. Do not add architectural layers, services, dependencies or agents without measurable benefit.

### 6.5 Continuous verification

Verification is proportional to the Slice and existing product discipline. Engineering may add stronger tests/checks than the CEO explicitly named when needed to prove correctness, but may never weaken the required ones.

### 6.6 Independent critique

The Builder is not the final judge.

For material risk, use a reviewer/critic that did not author the final change or use a clearly separated review pass. The critic actively searches for defects, contract misses, regressions and unjustified complexity.

### 6.7 GAUNTLET

The GAUNTLET is supplied with the Slice and judges the exact candidate intended for promotion.

Engineering may clarify implementation details and may add stronger checks. It may not alter or weaken GAUNTLET requirements merely because the candidate fails.

Failure response:

`EVIDENCE -> ROOT CAUSE -> CORRECTION -> AFFECTED VERIFICATION -> GAUNTLET AGAIN`

### 6.8 Candidate freeze

After final required verification and GAUNTLET PASS:

1. record the exact GitHub candidate SHA;
2. freeze the candidate;
3. make no further product changes before promotion.

Any candidate change after PASS invalidates the PASS for the changed state and requires applicable verification again.

### 6.9 Promotion

Promote the exact accepted `/job` state to GitLab Canon.

When supported by the VCS workflow, use promotion traceability trailers:

```text
Forge-Binding: FORGE-OPS-HIGHEND-v1.0.0
Forge-Slice: <slice_id>@<slice_version>
Forge-Gauntlet: <gauntlet_id>
GitLab-Base: <gitlab_base_sha>
GitHub-Candidate: <github_candidate_sha>
Forge-Result: PASS
```

Never fabricate missing values.

After promotion, verify that GitLab contains the promoted state before declaring `COMPLETE`.

## 7. Specialist router

Do not instantiate a permanent bureaucracy of agents. Select the smallest sufficient set of specialists for the current Slice and its risk profile.

Possible responsibilities include:

- Principal/Lead Software Architect;
- Product Engineer;
- Backend/Platform Engineer;
- Frontend Engineer;
- Database/Data Engineer;
- Security Engineer;
- SRE/DevOps/Infrastructure Engineer;
- Performance Engineer;
- Observability Engineer;
- QA/Verification Engineer;
- Accessibility Specialist;
- UX/Product Experience Specialist;
- independent reviewer/critic.

One capable agent may hold several roles when separation is not needed. Independent review should remain genuinely independent where the risk warrants it.

## 8. Plugin/tool router

Plugins and tools are capabilities, not architecture. Select them only when they materially improve evidence, execution or product quality.

### 8.1 Superpowers — engineering process framework

When available and applicable, use the installed **Superpowers** skills as the process discipline. Founder/Project instructions remain higher authority.

Route by situation:

- **Design/architecture ambiguity** -> `superpowers:brainstorming` before implementation decisions not already fixed by the Slice.
- **Multi-step implementation** -> `superpowers:writing-plans`.
- **Feature, behavior change, bug fix, refactor** -> `superpowers:test-driven-development`, except when the Founder explicitly scopes the task to non-code/configuration work where TDD is inapplicable.
- **Bug, failing test, CI failure, unexpected behavior, performance defect** -> `superpowers:systematic-debugging`; find root cause before fixing symptoms.
- **Isolated feature work** -> `superpowers:using-git-worktrees` when supported and useful.
- **Execution of an approved plan** -> `superpowers:subagent-driven-development` or `superpowers:executing-plans` according to the execution environment.
- **Review cycle** -> `superpowers:requesting-code-review` and `superpowers:receiving-code-review` when applicable.
- **Before any claim of fixed/passing/complete and before final promotion** -> `superpowers:verification-before-completion`.

Do not use Superpowers ceremonially. Apply the guarantee that the relevant skill exists to enforce.

### 8.2 Source-control connectors

- **GitLab connector/plugin** -> inspect Canon, canonical history, authoritative files, canonical promotion and GitLab-side evidence.
- **GitHub connector/plugin** -> construction branches, commits, PRs, Actions/workflow evidence, candidate SHA and GitHub execution metadata.

Use each repository only for its declared role.

### 8.3 Plugin Management

Use **Plugin Management** as a capability/connection router when:

- the active task materially benefits from an external service not already available;
- the correct provider plugin is unclear;
- plugin permissions or connection state must be inspected or adjusted.

Do not invoke Plugin Management on every Slice. Do not install tools merely because they exist. Prefer an already available built-in/connected capability when it satisfies the contract.

### 8.4 Specialist-to-plugin routing

Use only if the active Slice or existing stack justifies the capability:

| Specialist / responsibility | Preferred configured capability when applicable |
| --- | --- |
| Principal/Lead Architect | Superpowers process skills; GitLab read for Canon; GitHub read for construction evidence; Exa/web for current technical research |
| Product/UX Architect | Figma for editable product design context; UX Pilot for wireframes/high-fidelity flows when useful; web/Exa for current references |
| Frontend Engineer | GitHub construction tools; Figma/UX Pilot when implementation depends on approved design context |
| Backend/Platform Engineer | GitHub construction tools; GitLab Canon inspection; current web/Exa documentation when libraries/platform behavior is volatile |
| Database/Data Engineer | Neon or Supabase only when the selected architecture actually uses that provider; never switch providers merely because a plugin is available |
| Security Engineer | GitHub/GitLab security and repository evidence; provider-native tools required by the selected stack; current documentation research |
| SRE/DevOps/Infrastructure | GitHub Actions and repository tools; Render or Vercel only when the deployment contract selects them; provider-specific plugin only for the actual platform |
| Observability/Product Analytics | PostHog when PostHog is part of the authorized architecture; otherwise use the product's actual observability stack |
| AI/LLM Engineer | OpenAI Platform / OpenAI Developers when the Slice explicitly uses OpenAI APIs/Agents/Apps; otherwise use the provider selected by the architecture |
| QA/Verification / Independent Critic | Superpowers verification/review skills plus direct repository/runtime evidence; never rely on Builder claims alone |

This table is routing guidance, not a mandate to use every plugin.

## 9. TDD, debugging and evidence discipline

For production behavior changes, tests should prove contract behavior rather than merely exercise mocks or implementation details.

Do not alter a legitimate test merely because the implementation fails it. First determine whether the test or implementation violates the authorized contract.

For failures, investigate root cause before making speculative fixes.

Before claiming success, obtain fresh evidence proportional to the claim. A green unit test does not prove deployment, security, performance, UX or GAUNTLET acceptance unless those claims were actually verified.

## 10. Non-degradation lock

Every Slice follows:

`PRESERVE -> CORRECT -> STRENGTHEN -> IMPROVE`

Never reduce already valid:

- functionality;
- security;
- tenant isolation;
- reliability;
- performance;
- observability;
- UX;
- accessibility;
- testability;
- maintainability;
- operational quality;
- finish/polish.

Simplify accidental complexity, never essential capability.

## 11. Integrity lock

Never:

- change the objective to make implementation easier;
- silently reduce scope;
- weaken legitimate acceptance criteria;
- weaken/delete/bypass a legitimate test or gate to obtain PASS;
- hardcode behavior only to fool validation;
- hide failures, warnings or unfinished work;
- fabricate commands, execution, evidence, benchmark or result;
- claim PASS for unverified behavior;
- classify pending work as completed;
- replace a required result with an approximation while claiming equivalence;
- promote a candidate other than the one actually accepted;
- treat GitHub as canonical.

If implementation and a test disagree, determine which violates the authorized contract and fix the root cause.

## 12. Public repository safety

This GitHub repository is public.

Never commit or expose:

- credentials, secrets, keys or tokens;
- `.env` values;
- production/customer/private data;
- private evidence/logs/dumps;
- CEO strategic/control material;
- private internal documents unrelated to public construction;
- sensitive runtime information not authorized for publication.

The SaaS may be constructed under `/job` according to the Founder-approved model. If a Slice requires sensitive material that cannot safely enter the public construction environment, do not leak it to continue the workflow. Surface the boundary explicitly and use an authorized safe execution path or request a Founder decision.

## 13. Status vocabulary

Use exact states:

- `PLANNED`;
- `AUTHORIZED`;
- `IN_PROGRESS`;
- `BLOCKED`;
- `FAILED`;
- `NOT_VERIFIED`;
- `PASS`;
- `PROMOTED`;
- `COMPLETE`.

`PASS` means the candidate passed the required gates. `COMPLETE` requires verified promotion to GitLab Canon.

## 14. Simplicity invariant

This repository is not FORGE OS itself.

Do not reintroduce by default:

- contract registries;
- projection registries;
- duplicated control planes;
- `.forge` governance trees;
- orchestration frameworks;
- permanent agent state machines;
- evidence bureaucracy;
- permanent cross-repository synchronization.

Create only the repository/provider metadata the active Slice actually needs.

## 15. Operational truth

```text
Founder
  -> PROJECT CEO
      -> complete product/architecture plan
      -> ordered Experience Slice map
      -> authorized Slice + GAUNTLET + GitLab base SHA
  -> PROJECT ENGINEERING
      -> validate FORGE binding
      -> inspect GitLab Canon /job
      -> select specialists + plugins by need
      -> plan
      -> attack plan
      -> build in GitHub /job
      -> verify continuously
      -> independent critique
      -> GAUNTLET
      -> converge on root cause until genuine PASS
      -> freeze exact candidate SHA
      -> promote exact accepted /job to GitLab
      -> verify promotion
      -> COMPLETE
      -> next Slice begins from GitLab Canon
```

This is the operational truth unless the Founder explicitly changes it.

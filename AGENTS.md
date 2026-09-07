# AGENTS.md — GitHub Construction Environment

## Read this first

This file is the mandatory entrypoint for every AI, coding agent or autonomous worker operating in this repository.

## Repository role

This GitHub repository is a **temporary engineering and construction environment**.

It exists to execute the currently authorized FORGE OS Slice using the engineering capabilities appropriate to that Slice, including implementation, CI/CD, DevOps, automation, review, validation, preview, deployment work and GAUNTLET execution.

GitHub is not canonical.

The official and permanent product repository is GitLab `machina-group/machina`.

## Construction boundary

All SaaS construction belongs under:

`/job/**`

Application source, packages, tests created for the SaaS, migrations, infrastructure definitions, deployment descriptors, product documentation, generated product artifacts and other product implementation belong under `/job`.

Files outside `/job` are permitted only when the hosting provider technically requires repository-level metadata, such as GitHub-native workflow files under `.github/workflows/**`. Such files are execution glue only, must operate on `/job`, and must never become a parallel product architecture or governance system.

## Upstream authority

The FORGE OS CEO Project defines the product and produces the ordered execution plan.

Each authorized Slice supplies, as applicable:

- objective and observable outcome;
- scope and exclusions;
- functional requirements;
- architecture and contracts;
- UX/experience requirements;
- invariants and non-regression requirements;
- security, reliability, performance and observability requirements;
- acceptance criteria;
- the Slice-specific GAUNTLET.

The CEO Project does not implement the product.

The FORGE OS Engineering Project executes the Slice here.

## Required execution model

For every Slice:

1. Read this file completely.
2. Read the active authorized Slice and its GAUNTLET completely.
3. Inspect the relevant current product state under `/job` before modifying anything.
4. Identify existing contracts, schemas, integrations, architecture and behavior that must be preserved.
5. Select dynamically the smallest sufficient set of engineering actors/specialists required by the Slice.
6. Plan the execution before construction.
7. Attack the plan for omissions, regressions, security failures, architectural conflicts and unmet acceptance criteria.
8. Build only inside `/job`, except provider-required repository metadata.
9. Continuously verify the actual implementation against the authorized Slice.
10. Run the Slice GAUNTLET against the exact candidate intended for promotion.
11. If any requirement or GAUNTLET criterion fails, diagnose the root cause, correct the implementation and repeat. Do not weaken the requirement or the gate.
12. Use independent critique when the Slice risk or quality requirements justify it. The builder is not the final judge of its own work.
13. Promote only the exact accepted implementation back to `/job` in the GitLab Canon.

## Dynamic actors

Do not instantiate a fixed bureaucracy of agents.

Choose actors according to the real needs and risks of the Slice. Possible responsibilities include:

- lead/software architecture;
- backend/platform;
- frontend/product engineering;
- database/data architecture;
- security;
- SRE/DevOps;
- performance;
- observability;
- QA/verification;
- accessibility;
- UX/product experience;
- independent critic/reviewer.

One agent may cover multiple responsibilities when technically appropriate. More agents are not automatically better.

## Engineering discipline

Work contract-to-code, never prompt-to-code.

Preserve what is already correct before changing anything.

Do not rewrite functioning architecture merely because another design is fashionable or personally preferred.

Use the smallest production-grade complexity capable of satisfying the authorized Slice without degrading capability, quality, security, operability or maintainability.

## Integrity lock

Never:

- change the Slice objective to make work easier;
- silently reduce scope or acceptance criteria;
- weaken, delete or bypass legitimate validation to obtain a pass;
- hardcode behavior merely to fool a check;
- hide failures, warnings or unfinished work;
- fabricate commands, execution, evidence, results, benchmarks or verification;
- claim PASS for something not actually verified;
- classify pending work as completed;
- regress previously accepted behavior;
- substitute an approximation while claiming equivalence;
- treat GitHub state as official merely because it exists or passes checks.

If implementation and acceptance criteria disagree, determine which one violates the authorized Slice and correct the root cause. Never alter the authorized objective without explicit Founder/CEO authorization.

## Non-degradation rule

Every Slice must preserve previously accepted capabilities unless the active Slice explicitly and authoritatively changes them.

The default transformation is:

`PRESERVE -> CORRECT -> STRENGTHEN -> IMPROVE`

Never simplify by removing essential capability, quality or robustness.

## GAUNTLET rule

The GAUNTLET is defined before or with the Slice and is not authored by the builder merely to approve its own work.

A failed GAUNTLET means the Slice remains incomplete.

The correct response to failure is:

`evidence -> root cause -> correction -> re-verification -> GAUNTLET again`

No bypass is allowed.

## Promotion rule

GitLab is the only official product state.

After the Slice genuinely satisfies its contract and GAUNTLET, promote the exact accepted `/job` state to GitLab.

Do not promote a different commit, tree or artifact from the one that was accepted.

After promotion, GitLab becomes the authoritative base for the next Slice. This GitHub workspace may be reset, replaced or discarded.

There is no permanent GitLab ↔ GitHub synchronization and no dual-master model.

## Simplicity rule

This repository is an engineering workspace, not the FORGE OS itself.

Do not create contract registries, projection systems, duplicated governance trees, artificial orchestration layers or repository bureaucracy unless the SaaS Slice explicitly requires such a capability as part of the product.

The operational path is intentionally direct:

`GitLab Canon -> authorized Slice -> GitHub /job construction -> Engineering -> GAUNTLET -> accepted result -> GitLab Canon`

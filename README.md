# Machina — GitHub Construction Environment

FORGE_BINDING_ID: `FORGE-OPS-HIGHEND/v1.0.0`

This repository is the **temporary engineering workspace** for the SaaS.

## Minimal structure

- `AGENTS.md` — mandatory construction contract for every AI/agent/engineer.
- `job/` — the complete SaaS construction workspace.
- provider-required metadata such as `.github/workflows/**` may exist only when an active Slice needs it.

## Roles

- **GitLab `machina-group/machina`** is the sole official Canon.
- **GitHub `r-sudo-jeferson/Machina`** is used for implementation, CI/CD, DevOps, automation, review, preview, deployment work, verification and GAUNTLET execution.
- **PROJECT CEO** plans the full product, architecture, Slice Map and Slice-specific GAUNTLETs; it does not build production code.
- **PROJECT ENGINEERING** executes one authorized Slice at a time.

The Engineering Project configuration, CEO Project configuration, GitLab `AGENTS.md` and this `AGENTS.md` must declare the same `FORGE_BINDING_ID`. Drift blocks construction writes.

## Product boundary

All SaaS construction belongs under `job/**`.

## Transactional flow

```text
GitLab Canon /job @ bound SHA
  -> active authorized Slice + GAUNTLET
  -> GitHub /job construction
  -> specialist/tool routing by actual need
  -> implementation + verification
  -> independent critique
  -> GAUNTLET
  -> freeze exact accepted candidate SHA
  -> promote exact candidate /job to GitLab
  -> verify promotion
  -> next Slice starts from GitLab Canon
```

GitHub never becomes Canon and there is no permanent repository synchronization.

Read `AGENTS.md` before any operation. It defines the binding protocol, preflight, specialist/plugin routing, non-degradation, public-repository safety, candidate freeze and exact-promotion rules.

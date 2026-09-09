# MCH-S001 Machina Alloy Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the MCH-S001 Machina Alloy foundation with deterministic DTCG tokens, generated CSS/TypeScript contracts, accessibility-safe material states, and the first React Aria controls.

**Architecture:** DTCG JSON under `job/packages/alloy/tokens/**` is the only token source of truth. A dependency-free Node 24.20.0 compiler validates/resolves that bounded token graph and emits committed CSS/TypeScript contracts; React Aria components consume those generated semantics later and never recreate interaction state. Verification proceeds token/accessibility first, then package/dependency lock, then React components and Storybook.

**Tech Stack:** Node 24.20.0, pnpm 12.3.4, React 19.2.8, React DOM 19.2.8, TypeScript 6.0.3, Vite 8.1.0, `@vitejs/plugin-react` 6.1.1, `react-aria-components` 1.21.1, Vitest 5.0.0, Storybook 10.6.0, `@storybook/react-vite` 10.6.0, axe-core 4.13.0. No Python.

**Spec:** `job/docs/superpowers/specs/2026-09-09-mch-s001-alloy-foundation-design.md`

**Normative correction (2026-09-09):** DTCG 2025.10 `color` values are structured objects, not CSS color strings. MCH-S001 source colors use the bounded sRGB representation `{ "colorSpace": "srgb", "components": [...], "alpha": <optional>, "hex": "#RRGGBB" }`; `alpha` defaults to `1`, and `hex` is retained as the six-digit fallback/canonical-literal check. The compiler must validate that the structured value and fallback agree before emitting CSS. The previously written `cache: false` example for `actions/setup-node` is also superseded: omit the `cache` input until a real supported package-manager cache is configured. These corrections change no palette, Slice scope, architecture, accessibility requirement, dependency pin, or GAUNTLET criterion.

## Global Constraints

- Active Slice only: `MCH-S001@1.0.0`; GAUNTLET `GNT-MCH-S001-001`.
- All product code/config/tests/generated contracts live under `job/**`; `.github/workflows/**` is orchestration glue only.
- Canonical palettes and material semantics come from approved GitLab `MCH-ARCH-001`; do not substitute a generic UI kit or change the visual metaphor.
- DTCG 2025.10 token JSON is the source of truth; generated CSS/TypeScript must be deterministic and drift-checked.
- Shadows/depth never carry state alone. Focus, labels, semantic attributes, contrast and forced-colors behavior remain independently legible.
- Forced-colors and reduced-motion contracts land before decorative React composition.
- First tranche only: chassis/surface/well plus Button/IconButton/TextField/Switch/StatusLamp. Task 9 owns full shell/journey composition.
- Project tests run before Machina tests/GAUNTLET. No PASS/COMPLETE claim follows from Task 8 alone.

---

## File map

### Token truth and compiler
- Create `job/packages/alloy/tokens/primitives.json`: raw spacing/radius/duration/easing/detail colors.
- Create `job/packages/alloy/tokens/themes/silver.json`: exact Silver material/text palette.
- Create `job/packages/alloy/tokens/themes/space-black.json`: exact Space Black material/text palette.
- Create `job/packages/alloy/tokens/semantic.json`: semantic aliases to theme/detail/primitives.
- Create `job/packages/alloy/tokens/material.json`: bounded depth recipes.
- Create `job/packages/alloy/tokens/accessibility.json`: focus/target/contrast/reduced-motion contract values.
- Create `job/packages/alloy/scripts/build-tokens.mjs`: strict loader, reference resolver, validators, deterministic CSS/TS writer.
- Create `job/packages/alloy/generated/tokens.css`: committed generated theme/material/accessibility CSS.
- Create `job/packages/alloy/generated/tokens.ts`: committed immutable token-name/theme contracts.

### Tests and CI
- Create `job/packages/alloy/test/token-contract.test.mjs`: source schema/palette/reference/contrast assertions.
- Create `job/packages/alloy/test/generated-contract.test.mjs`: byte determinism/drift/accessibility-output assertions.
- Create `.github/workflows/verify-alloy.yml`: pinned Node 24.20.0 project-test workflow calling only `job/**` scripts/tests.

### React package phase
- Create `job/packages/alloy/package.json`, `tsconfig.json`, `vite.config.ts`, `vitest.config.ts`.
- Modify `job/pnpm-lock.yaml` only through pnpm 12.3.4 generation; never hand-edit dependency graph.
- Create `job/packages/alloy/src/material.tsx`, `controls.tsx`, `status.tsx`, `index.ts`, `alloy.css`.
- Create `job/packages/alloy/src/*.test.tsx` for behavior/state semantics.
- Create `job/packages/alloy/.storybook/main.ts`, `preview.ts`; create component stories.

---

### Task 8.1: RED — token source contract and CI boundary

**Files:**
- Create: `job/packages/alloy/test/token-contract.test.mjs`
- Create: `.github/workflows/verify-alloy.yml`

**Interfaces:**
- Consumes: Node 24.20.0 and approved palette/material requirements.
- Produces: a failing project-test gate that requires the canonical token files and exact palette values.

- [ ] **Step 1: Write the failing token contract test**

The test must use only `node:test`, `node:assert/strict`, `fs/promises`, `path`, and `url`. Define `alloyRoot` from `import.meta.url`, load these required files:

```js
const required = [
  'tokens/primitives.json',
  'tokens/themes/silver.json',
  'tokens/themes/space-black.json',
  'tokens/semantic.json',
  'tokens/material.json',
  'tokens/accessibility.json',
];
```

Assert exact canonical colors through their DTCG 2025.10 structured sRGB values. The test must verify `$type: "color"`, `colorSpace: "srgb"`, three normalized components matching the canonical six-digit hex literal, optional `alpha` where transparency is canonical, and the exact six-digit `hex` fallback. Example assertions:

```js
assertDtcgSrgbColor(silver.alloy.theme.silver.chassis, '#D8DADD');
assertDtcgSrgbColor(silver.alloy.theme.silver.specularEdge, '#FFFFFF', 0.82);
assertDtcgSrgbColor(silver.alloy.theme.silver.ambientShadow, '#434850', 0.28);
assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.chassis, '#1D1F22');
assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.specularEdge, '#FFFFFF', 0.16);
assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.ambientShadow, '#000000', 0.72);
```

Also assert all remaining Silver/Space Black text/material colors, the seven detail colors, spacing base 4 px, radius set `8/12/18/24/32`, focus width 2 px, minimum target 24 px, preferred target 44 px, and semantic material names. String-valued `$value` is invalid for a MCH-S001 source color token.

- [ ] **Step 2: Create the Alloy workflow**

Use only already-pinned actions:

```yaml
name: Verify Alloy construction
on:
  push:
    branches: [forge/mch-s001-1.0.0]
    paths:
      - 'job/packages/alloy/**'
      - 'job/package.json'
      - 'job/pnpm-workspace.yaml'
      - 'job/pnpm-lock.yaml'
      - 'job/toolchains.lock.json'
      - '.github/workflows/verify-alloy.yml'
permissions:
  contents: read
jobs:
  verify-alloy:
    runs-on: ubuntu-24.04
    timeout-minutes: 8
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - run: test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020
        with:
          node-version: '24.20.0'
      - working-directory: job
        run: node --test packages/alloy/test/*.test.mjs
```

Do not pass `cache: false`; `actions/setup-node` treats `cache` as a package-manager selector rather than a boolean. Introduce caching only when pnpm is actually configured and the cache input can name the supported package manager deterministically.

- [ ] **Step 3: Run RED**

Expected GitHub Actions result: `verify-alloy` fails because one or more required `job/packages/alloy/tokens/**` files do not exist. No token implementation may be added before that failure is captured.

- [ ] **Step 4: Commit RED**

Commit message: `test(alloy): require canonical token foundation`.

---

### Task 8.2: GREEN — canonical DTCG token graph

**Files:**
- Create all six token JSON files from Task 8.1.

**Interfaces:**
- Consumes: exact canonical palette and geometry/motion values.
- Produces: bounded DTCG token graph used by compiler and React layer.

- [ ] **Step 1: Implement primitive/detail/geometry tokens**

Use DTCG 2025.10 form. Dimensions remain `{ "value": number, "unit": "px" }`. Source colors use structured sRGB values; the six-digit hex field is a validated fallback, not the typed value itself. For example:

```json
{
  "alloy": {
    "primitive": {
      "spacing": {
        "1": {"$type": "dimension", "$value": {"value": 4, "unit": "px"}},
        "2": {"$type": "dimension", "$value": {"value": 8, "unit": "px"}}
      },
      "color": {
        "electricBlue": {
          "$type": "color",
          "$value": {
            "colorSpace": "srgb",
            "components": [0.0784313725490196, 0.49019607843137253, 1],
            "hex": "#147DFF"
          }
        },
        "plasmaCyan": {
          "$type": "color",
          "$value": {
            "colorSpace": "srgb",
            "components": [0, 0.8509803921568627, 1],
            "hex": "#00D9FF"
          }
        }
      }
    }
  }
}
```

Encode all required spacing/radius/detail/motion values explicitly. No aliases in primitive files. Transparent theme source colors use the same sRGB object plus numeric `alpha`; do not encode `rgba(...)` strings.

- [ ] **Step 2: Implement exact theme palettes**

Use the exact values from the spec. Theme files contain only material/text/specular/ambient source values for their own theme. Preserve canonical six-digit source literals in `hex` and encode canonical transparency in `alpha`.

- [ ] **Step 3: Implement semantic/material/accessibility aliases**

References use DTCG braces, e.g. `"{alloy.primitive.color.electricBlue}"`. Semantic focus aliases electric blue; AI aliases plasma cyan; success/warning/danger alias reactor green/ion amber/signal red. Material recipes use named semantic ingredients and approved depth names only.

- [ ] **Step 4: Run GREEN**

Run through GitHub workflow. Expected: the Task 8.1 token source tests pass.

- [ ] **Step 5: Commit**

Commit message: `feat(alloy): add canonical DTCG token graph`.

---

### Task 8.3: RED→GREEN — deterministic compiler and accessibility contracts

**Files:**
- Create: `job/packages/alloy/test/generated-contract.test.mjs`
- Create: `job/packages/alloy/scripts/build-tokens.mjs`
- Create: `job/packages/alloy/generated/tokens.css`
- Create: `job/packages/alloy/generated/tokens.ts`
- Modify: `.github/workflows/verify-alloy.yml`

**Interfaces:**
- Consumes: six canonical token JSON files.
- Produces: `buildTokens({sourceRoot, outputRoot})`, deterministic CSS/TS contracts and drift check.

- [ ] **Step 1: Write RED generated-contract tests**

Tests must assert:

```js
assert.match(css, /\[data-alloy-theme="silver"\]/);
assert.match(css, /\[data-alloy-theme="space-black"\]/);
assert.match(css, /@media \(forced-colors: active\)/);
assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
assert.match(css, /--alloy-focus-width: 2px/);
assert.match(css, /forced-color-adjust:/);
assert.match(css, /CanvasText|Highlight/);
assert.match(ts, /export const alloyThemes = \["silver", "space-black"\] as const/);
```

Generate twice into two fresh `mkdtemp` directories and assert byte equality. Add a copied-source mutation with an unknown reference and require compiler rejection; add a two-token cycle and require cycle rejection.

- [ ] **Step 2: Add contrast tests before compiler implementation**

Implement test-local sRGB relative-luminance calculation and assert canonical intended text/background pairs meet at least 4.5:1 for normal body text. Derive luminance from the validated structured sRGB components, not by assuming `$value` is a hex string. Do not lower thresholds to make palette pass; if an intended pair fails, map that semantic use to a safer canonical plane instead of changing canonical raw colors.

- [ ] **Step 3: Run RED**

Expected: fail because compiler/generated contracts do not exist.

- [ ] **Step 4: Implement strict compiler**

`build-tokens.mjs` must:

1. Read only the six known JSON inputs in fixed order.
2. Reject duplicate fully-qualified token paths.
3. Accept only objects with `$type/$value` leaves or nested groups used by this spec.
4. Resolve `{path.to.token}` references recursively with visiting/resolved sets; unknown or cyclic references throw with the path.
5. Sort emitted custom-property names lexicographically.
6. Format dimensions as `<value><unit>`. For MCH-S001 source colors, require a DTCG structured sRGB object with three normalized numeric components, optional `alpha` in `[0,1]`, and six-digit `hex` fallback; reject CSS-string `$value`, verify `hex` agrees with the components within the exact 8-bit channel mapping used by the canonical palette, then serialize CSS deterministically as the canonical hex when alpha is `1` or `rgb(r g b / alpha)` when alpha is translucent.
7. Validate any `shadow` composite against DTCG 2025.10 (`color`, `offsetX`, `offsetY`, `blur`, `spread`, optional `inset`) and serialize it only after references are resolved.
8. Emit theme selectors and semantic/material variables without copying theme literals into component mappings.
9. Emit forced-colors rules that remove decorative shadows/background images and expose system-color border/outline/focus semantics.
10. Emit reduced-motion rules that set nonessential durations to `0.01ms`, iteration count to `1`, and remove nonessential transforms/scroll animation.
11. Write trailing-newline UTF-8 output only.

CLI behavior:

```js
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await buildTokens({
    sourceRoot: path.resolve('packages/alloy'),
    outputRoot: path.resolve('packages/alloy/generated'),
  });
}
```

- [ ] **Step 5: Generate committed outputs**

Run `node packages/alloy/scripts/build-tokens.mjs` with Node 24.20.0. Commit the exact generated CSS/TS.

- [ ] **Step 6: Strengthen workflow drift gate**

After tests, run compiler then `git diff --exit-code -- packages/alloy/generated`. Expected zero diff.

- [ ] **Step 7: Run GREEN**

Expected: source tests, generated tests, unknown/cycle tests, contrast checks and drift check all pass.

- [ ] **Step 8: Commit**

Commit message: `feat(alloy): generate deterministic accessible token contracts`.

---

### Task 8.4: Package and lock React Aria foundation

**Files:**
- Create: `job/packages/alloy/package.json`
- Create: `job/packages/alloy/tsconfig.json`
- Create: `job/packages/alloy/vite.config.ts`
- Create: `job/packages/alloy/vitest.config.ts`
- Modify: `job/pnpm-lock.yaml`
- Modify: `.github/workflows/verify-alloy.yml`

**Interfaces:**
- Consumes: generated token contracts.
- Produces: reproducible `@machina/alloy` TypeScript/React package environment.

- [ ] **Step 1: Add exact package manifest**

Use `private: true`, `type: module`, package name `@machina/alloy`. Pin runtime peers/dependencies exactly where appropriate:

```json
{
  "dependencies": {"react-aria-components": "1.21.1"},
  "peerDependencies": {"react": "19.2.8", "react-dom": "19.2.8"},
  "devDependencies": {
    "@types/react": "19.2.18",
    "@vitejs/plugin-react": "6.1.1",
    "@storybook/react-vite": "10.6.0",
    "axe-core": "4.13.0",
    "react": "19.2.8",
    "react-dom": "19.2.8",
    "storybook": "10.6.0",
    "typescript": "6.0.3",
    "vite": "8.1.0",
    "vitest": "5.0.0"
  }
}
```

- [ ] **Step 2: Generate lock only with pinned pnpm**

From `job/` with Node 24.20.0:

```bash
corepack enable
corepack prepare pnpm@12.3.4 --activate
pnpm install --lockfile-only
pnpm install --frozen-lockfile
```

Never hand-edit transitive lock entries.

- [ ] **Step 3: Add strict TypeScript/Vite/Vitest config**

Use `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, DOM libs, explicit types, React JSX transform, Vite library build, and Vitest DOM environment selected by the package tests. No JS transpiler/runtime outside the approved Node toolchain.

- [ ] **Step 4: Extend CI**

After dependency-free token gates, activate pnpm 12.3.4, run `pnpm install --frozen-lockfile`, `pnpm --filter @machina/alloy typecheck`, `test`, and later `build-storybook` once Task 8.6 lands.

- [ ] **Step 5: Commit**

Commit message: `build(alloy): lock React Aria package toolchain`.

---

### Task 8.5: RED→GREEN — material primitives and first accessible controls

**Files:**
- Create: `job/packages/alloy/src/material.tsx`
- Create: `job/packages/alloy/src/controls.tsx`
- Create: `job/packages/alloy/src/status.tsx`
- Create: `job/packages/alloy/src/index.ts`
- Create: `job/packages/alloy/src/alloy.css`
- Create: `job/packages/alloy/src/material.test.tsx`
- Create: `job/packages/alloy/src/controls.test.tsx`

**Interfaces:**
- Produces: `AlloyChassis`, `AlloySurface`, `AlloyWell`, `Button`, `IconButton`, `TextField`, `Switch`, `StatusLamp`.

- [ ] **Step 1: Write behavior tests first**

Require chassis theme selection to be only `silver | space-black`; require Button/TextField/Switch to use React Aria semantic components; require disabled/pressed/selected/focus-visible styling hooks to be React Aria/native `data-*` or pseudo-state, not a duplicate state machine. `IconButton` requires an accessible label prop. `StatusLamp` requires text or an accessible label in addition to color.

- [ ] **Step 2: Write CSS contract tests**

Require component CSS to consume `var(--alloy-...)` generated semantics and reject raw canonical palette hex literals in `src/*.css`. Require visible focus outline/perimeter, `min-inline-size/min-block-size` target tokens, stable loading geometry and forced-colors compatibility.

- [ ] **Step 3: Run RED**

Expected: components do not exist.

- [ ] **Step 4: Implement material primitives**

Components are thin semantic wrappers with `className` composition and `data-alloy-material` values. They do not own global app layout or Task 9 routing.

- [ ] **Step 5: Implement React Aria controls**

Wrap React Aria `Button`, `TextField`, `Input`, `Label`, `FieldError`, and `Switch` with Alloy class contracts while forwarding semantic props/refs. Loading is announced without removing the accessible name. Disabled remains native/React Aria state.

- [ ] **Step 6: Run GREEN and race-independent repetition**

Run package tests twice plus typecheck. Expected byte/stable behavior; no snapshots may replace semantic assertions.

- [ ] **Step 7: Commit**

Commit message: `feat(alloy): add accessible material primitives and controls`.

---

### Task 8.6: Storybook states, automated a11y and visual evidence boundary

**Files:**
- Create: `job/packages/alloy/.storybook/main.ts`
- Create: `job/packages/alloy/.storybook/preview.ts`
- Create: stories for every Task 8.5 component.
- Modify: package scripts/workflow.

**Interfaces:**
- Consumes: first Alloy component tranche.
- Produces: isolated state matrix for Silver/Space Black, keyboard/focus/disabled/loading/error/selected, reduced-motion and forced-colors inspection.

- [ ] **Step 1: Configure Storybook 10.6.0 React/Vite**

Theme globals set `data-alloy-theme` on the preview root. Storybook consumes committed generated CSS and component CSS only.

- [ ] **Step 2: Create explicit state stories**

Every interactive component must have default, keyboard-focusable, disabled, loading where applicable, error/denied where applicable, and selected/pressed where applicable stories. Material primitives need both themes and nested-depth examples capped at three local levels.

- [ ] **Step 3: Add automated accessibility checks**

Use axe-core against rendered stories/component tests for detectable issues. The gate fails on serious/critical violations. Keep manual AT requirements marked `NOT_VERIFIED` until human evidence exists.

- [ ] **Step 4: Build Storybook in CI**

Run `pnpm --filter @machina/alloy build-storybook` from a frozen lockfile. CI must not fetch mutable CDN assets or rely on secrets.

- [ ] **Step 5: Independent visual/accessibility Critic**

Review both themes with shadows present and with forced colors/shadows effectively absent. Search for state conveyed only by depth/color, clipped focus, low-contrast text, target regression, gratuitous nested shadows, and generic floating-card composition. Critical/Important findings block Task 8 closure.

- [ ] **Step 6: Commit**

Commit message: `test(alloy): cover state and accessibility matrix`.

---

## Self-review result

- Canonical Silver/Space Black values: covered by Tasks 8.1/8.2 using DTCG 2025.10 structured sRGB source colors.
- Deterministic DTCG → CSS/TypeScript generation: covered by Task 8.3.
- Contrast pairs: covered before decorative components in Task 8.3.
- Forced colors and reduced motion: generated/tested before React components in Task 8.3.
- React Aria foundation: exact locked package and first tranche in Tasks 8.4/8.5.
- Storybook/component keyboard/focus/disabled/loading/error/selected states: Task 8.6.
- Visual snapshots/automated accessibility and independent critique: Task 8.6; manual assistive-technology verification remains explicitly separate before Slice PASS.
- No Task 9 shell, Ask Dock or future policy-builder implementation leaked into this plan.

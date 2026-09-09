# MCH-S001 Machina Alloy Foundation Design

**Binding:** `FORGE-OPS-HIGHEND-v1.0.0`  
**Slice:** `MCH-S001@1.0.0`  
**GAUNTLET:** `GNT-MCH-S001-001`  
**Authority:** authorized GitLab Slice and approved `MCH-ARCH-001`; this document is an Engineering projection and does not redefine product direction.

## Objective

Create the minimum production-grade Machina Alloy foundation required by MCH-S001: stable DTCG design-token truth, deterministic CSS/TypeScript generation, Silver and Space Black themes, material depth primitives, accessibility-safe focus/state contracts, forced-colors and reduced-motion behavior, and the first React Aria-based controls needed by the authenticated shell.

## Canonical visual contract

The complete interface behaves as one machined metallic object. Structure comes from continuous chassis material, spacing, concave/convex depth, light and state rather than ornamental page dividers or generic floating cards. Neumorphic lighting is decorative reinforcement only; contrast, labels, focus, semantic state, hierarchy and affordance remain independently understandable when shadows disappear.

Lighting direction is upper-left. Depth is bounded to the approved semantic materials: `flush`, `convex-low`, `convex-high`, `concave-low`, `concave-deep`, `inlaid`, `beveled`, and `floating`; local nesting may not exceed three depth levels. Ordinary controls have no parallax or continuous shimmer.

## Token source of truth

Tokens live under `job/packages/alloy/tokens/**` using the DTCG 2025.10 `$type`, `$value` and reference model. Raw literals are permitted only in primitive/theme source tokens and explicit forced-colors system-color mappings. Semantic/component styles consume references instead of duplicating palette literals.

Token groups:

1. `primitive`: color, spacing, radius, typography, duration, easing, opacity, blur and shadow-layer ingredients.
2. `theme`: exact Silver and Space Black material/text palette plus shared high-saturation detail colors.
3. `semantic`: chassis, surface, well, raised, text, icon, focus, selection, success, warning, danger, AI and disabled aliases.
4. `material`: flush/convex/concave/inlaid/beveled/floating shadow and edge recipes.
5. `motion`: micro feedback 80–140 ms, surface 160–220 ms, dialog/drawer 220–320 ms, and reduced-motion substitutions.
6. `accessibility`: minimum pointer targets, preferred touch targets, focus perimeter width/offset, contrast thresholds and forced-colors mappings.

## Exact MCH-S001 palettes

Silver:

- chassis `#D8DADD`
- lit plane `#F5F6F7`
- shadow plane `#B4B8BE`
- concave well `#C9CCD1`
- primary text `#17191D`
- secondary text `#4D535B`
- disabled text `#737A84`
- specular edge `rgba(255,255,255,0.82)`
- ambient shadow `rgba(67,72,80,0.28)`

Space Black:

- chassis `#1D1F22`
- lit plane `#34373C`
- shadow plane `#090A0C`
- concave well `#141619`
- primary text `#F5F7FA`
- secondary text `#B2B8C1`
- disabled text `#7B828D`
- specular edge `rgba(255,255,255,0.16)`
- ambient shadow `rgba(0,0,0,0.72)`

Shared semantic detail energy:

- electric blue `#147DFF`
- plasma cyan `#00D9FF`
- volt lime `#AEFF3D`
- fusion magenta `#FF2D8D`
- ion amber `#FFB21A`
- signal red `#FF3B45`
- reactor green `#20E37A`

## Generated contracts

`job/packages/alloy/scripts/build-tokens.mjs` is a dependency-free Node 24.20.0 compiler for the token layer. It validates the bounded DTCG subset used by MCH-S001, resolves references with cycle/unknown-reference rejection, produces stable lexicographic output, and writes:

- `job/packages/alloy/generated/tokens.css`: CSS custom properties, `[data-alloy-theme="silver"]`, `[data-alloy-theme="space-black"]`, material state recipes, `@media (forced-colors: active)` and `@media (prefers-reduced-motion: reduce)` overrides.
- `job/packages/alloy/generated/tokens.ts`: immutable theme/token-name contracts for TypeScript consumers without embedding a second source of truth.

Generation is deterministic. Re-running the compiler on identical source must be byte-identical. CI regenerates into a temporary directory and compares against committed generated contracts.

## Accessibility contract

Before decorative components are accepted:

- Text pair tests calculate WCAG relative luminance/contrast from canonical hex values and enforce the approved body-text AA floor where the pair is intended for ordinary text.
- Focus is never shadow-only: normal themes expose an external 2 px semantic focus perimeter with a nonzero offset and no clipping contract; forced colors maps focus to system colors.
- State is never color-only: component APIs must expose label/icon/ARIA/native state semantics in addition to accent energy.
- Forced-colors mode removes decorative shadows/background images and preserves boundaries with system colors and outlines/borders.
- Reduced-motion mode makes nonessential animation effectively instantaneous and removes transform/displacement/shimmer behavior while preserving state change.
- Minimum pointer target token is 24 CSS px; preferred touch target token is 44 CSS px.
- 200% zoom/reflow, keyboard, screen reader and manual high-contrast evidence remain later runtime gates; token tests do not claim those manual checks.

## React foundation

After the token/accessibility layer is green, `@machina/alloy` adds React 19.2-compatible primitives using React Aria Components rather than custom keyboard/ARIA reimplementation. Current construction baseline researched on 2026-09-09 is `react-aria-components@1.21.1`; the package must remain pinned through the workspace lockfile before production code depends on it.

The first component tranche is intentionally small:

- `AlloyChassis`
- `AlloySurface`
- `AlloyWell`
- `Button`
- `IconButton`
- `TextField`
- `Switch`
- `StatusLamp`

These components are enough to establish material composition, focus, disabled/loading/error/selected semantics and the shell primitives needed by Task 9. Later approved Alloy components are added only when their owning MCH-S001 journey needs them.

## Component state contract

- default: flush or low-convex
- hover: restrained specular increase only
- focus-visible: external semantic focus perimeter
- pressed: concave tactile state
- selected: inlaid accent edge plus non-color semantic change
- disabled: flattened depth/reduced chroma but readable label
- loading: stable geometry and programmatic progress/status
- error/denied: signal icon + reason + recovery action; not color-only
- success: brief reactor-green energy plus persistent semantic result

React Aria `data-*` interaction/state attributes are the styling hooks. Native/React Aria semantics remain authoritative; Alloy does not shadow them with a parallel state machine.

## Testing architecture

Phase 1 requires no third-party package installation:

- Node `node:test` contract tests for token schema, exact palette, reference integrity, deterministic generation, CSS/TS drift, contrast math, focus tokens, forced-colors and reduced-motion output.
- GitHub workflow pinned to the existing `actions/checkout` and `actions/setup-node` SHAs and Node `24.20.0`.

Phase 2, after a deterministic workspace lockfile exists:

- React Aria component tests with Vitest 5.0.0 and DOM test environment.
- Storybook 10.6.0 / `@storybook/react-vite` 10.6.0 for isolated states and documentation.
- axe-assisted automated accessibility checks plus keyboard/focus behavior tests.
- visual snapshots in both themes and forced-colors/reduced-motion variants.

Automated checks never substitute for manual keyboard/screen-reader/high-contrast/zoom evidence before Slice PASS.

## Non-goals

Task 8 does not build the full application shell, tenant/workspace journey, Ask Dock, policy builder, arbitrary theme editor, future tenant accent configurator, or Task 9 routing/data integration. It establishes the design-system contract they consume.

## Rollback

The Alloy foundation is additive under `job/packages/alloy/**`. Before Task 9 depends on it, it can be reverted as one package without backend/database impact. Once Task 9 consumes generated token/component contracts, rollback is by compatible package commit/revert plus regenerated consumers; no database or identity migration is coupled to the design system.

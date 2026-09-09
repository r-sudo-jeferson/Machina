import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const INPUT_FILES = [
  'tokens/primitives.json',
  'tokens/themes/silver.json',
  'tokens/themes/space-black.json',
  'tokens/semantic.json',
  'tokens/material.json',
  'tokens/accessibility.json',
];

const ALLOWED_TYPES = new Set([
  'color',
  'dimension',
  'duration',
  'number',
  'cubicBezier',
  'shadow',
]);

const REFERENCE_PATTERN = /^\{([A-Za-z0-9_.-]+)\}$/;
const HEX_PATTERN = /^#[0-9A-F]{6}$/;
const MATERIAL_STATES = [
  ['flush', 'flush'],
  ['convexLow', 'convex-low'],
  ['convexHigh', 'convex-high'],
  ['concaveLow', 'concave-low'],
  ['concaveDeep', 'concave-deep'],
  ['inlaid', 'inlaid'],
  ['beveled', 'beveled'],
  ['floating', 'floating'],
];

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
  return structuredClone(value);
}

function formatNumber(value) {
  if (!Number.isFinite(value)) {
    throw new Error(`Cannot serialize non-finite number: ${value}`);
  }
  return Object.is(value, -0) ? '0' : String(value);
}

function collectTokens(document, sourceName, tokens) {
  function visit(node, segments) {
    if (!isPlainObject(node)) {
      throw new Error(`Invalid token group at ${segments.join('.') || '<root>'} in ${sourceName}`);
    }

    const hasValue = Object.hasOwn(node, '$value');
    if (hasValue) {
      if (typeof node.$type !== 'string' || !ALLOWED_TYPES.has(node.$type)) {
        throw new Error(`Unsupported or missing $type at ${segments.join('.')} in ${sourceName}`);
      }
      const allowedLeafKeys = new Set(['$type', '$value', '$description']);
      for (const key of Object.keys(node)) {
        if (!allowedLeafKeys.has(key)) {
          throw new Error(`Unexpected token property ${key} at ${segments.join('.')} in ${sourceName}`);
        }
      }
      const tokenPath = segments.join('.');
      if (!tokenPath) {
        throw new Error(`Token path cannot be empty in ${sourceName}`);
      }
      if (tokens.has(tokenPath)) {
        throw new Error(`Duplicate token path ${tokenPath}`);
      }
      tokens.set(tokenPath, {
        path: tokenPath,
        type: node.$type,
        value: node.$value,
        source: sourceName,
      });
      return;
    }

    for (const [key, value] of Object.entries(node)) {
      if (key.startsWith('$')) {
        if (key !== '$description' || typeof value !== 'string') {
          throw new Error(`Unsupported group metadata ${key} at ${segments.join('.') || '<root>'}`);
        }
        continue;
      }
      visit(value, [...segments, key]);
    }
  }

  visit(document, []);
}

function validateDimension(value, tokenPath, { allowNegative = true } = {}) {
  if (!isPlainObject(value) || typeof value.value !== 'number' || !Number.isFinite(value.value)) {
    throw new Error(`Token ${tokenPath} must resolve to a DTCG dimension object`);
  }
  if (!allowNegative && value.value < 0) {
    throw new Error(`Token ${tokenPath} cannot use a negative dimension`);
  }
  if (!['px', 'rem'].includes(value.unit)) {
    throw new Error(`Token ${tokenPath} uses unsupported dimension unit ${value.unit}`);
  }
  const keys = Object.keys(value).sort();
  if (keys.join(',') !== 'unit,value') {
    throw new Error(`Token ${tokenPath} dimension has unsupported properties`);
  }
}

function validateDuration(value, tokenPath) {
  if (!isPlainObject(value) || typeof value.value !== 'number' || !Number.isFinite(value.value)) {
    throw new Error(`Token ${tokenPath} must resolve to a DTCG duration object`);
  }
  if (value.value < 0 || !['ms', 's'].includes(value.unit)) {
    throw new Error(`Token ${tokenPath} has invalid duration`);
  }
  const keys = Object.keys(value).sort();
  if (keys.join(',') !== 'unit,value') {
    throw new Error(`Token ${tokenPath} duration has unsupported properties`);
  }
}

function validateColor(value, tokenPath) {
  if (!isPlainObject(value) || value.colorSpace !== 'srgb') {
    throw new Error(`Token ${tokenPath} must use a structured DTCG sRGB color value`);
  }
  if (!Array.isArray(value.components) || value.components.length !== 3) {
    throw new Error(`Token ${tokenPath} must contain exactly three sRGB color components`);
  }
  for (const component of value.components) {
    if (typeof component !== 'number' || !Number.isFinite(component) || component < 0 || component > 1) {
      throw new Error(`Token ${tokenPath} has an invalid sRGB color component`);
    }
  }
  const alpha = value.alpha ?? 1;
  if (typeof alpha !== 'number' || !Number.isFinite(alpha) || alpha < 0 || alpha > 1) {
    throw new Error(`Token ${tokenPath} has invalid color alpha`);
  }
  if (typeof value.hex !== 'string' || !HEX_PATTERN.test(value.hex)) {
    throw new Error(`Token ${tokenPath} must provide a six-digit uppercase hex fallback`);
  }
  const allowedKeys = new Set(['colorSpace', 'components', 'alpha', 'hex']);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`Token ${tokenPath} color has unsupported property ${key}`);
    }
  }

  const expected = [1, 3, 5].map((start) => Number.parseInt(value.hex.slice(start, start + 2), 16) / 255);
  for (let index = 0; index < expected.length; index += 1) {
    if (Math.abs(value.components[index] - expected[index]) > 1e-12) {
      throw new Error(`Token ${tokenPath} color components do not match hex fallback ${value.hex}`);
    }
  }
}

function validateCubicBezier(value, tokenPath) {
  if (!Array.isArray(value) || value.length !== 4 || value.some((part) => typeof part !== 'number' || !Number.isFinite(part))) {
    throw new Error(`Token ${tokenPath} must resolve to four cubic-bezier numbers`);
  }
  if (value[0] < 0 || value[0] > 1 || value[2] < 0 || value[2] > 1) {
    throw new Error(`Token ${tokenPath} cubic-bezier x control points must be within [0,1]`);
  }
}

function validateShadowLayer(layer, tokenPath) {
  if (!isPlainObject(layer)) {
    throw new Error(`Token ${tokenPath} shadow layer must be an object`);
  }
  const required = ['color', 'offsetX', 'offsetY', 'blur', 'spread'];
  for (const key of required) {
    if (!Object.hasOwn(layer, key)) {
      throw new Error(`Token ${tokenPath} shadow layer is missing ${key}`);
    }
  }
  const allowed = new Set([...required, 'inset']);
  for (const key of Object.keys(layer)) {
    if (!allowed.has(key)) {
      throw new Error(`Token ${tokenPath} shadow layer has unsupported property ${key}`);
    }
  }
  validateColor(layer.color, `${tokenPath}.color`);
  validateDimension(layer.offsetX, `${tokenPath}.offsetX`);
  validateDimension(layer.offsetY, `${tokenPath}.offsetY`);
  validateDimension(layer.blur, `${tokenPath}.blur`, { allowNegative: false });
  validateDimension(layer.spread, `${tokenPath}.spread`);
  if (Object.hasOwn(layer, 'inset') && typeof layer.inset !== 'boolean') {
    throw new Error(`Token ${tokenPath}.inset must be boolean`);
  }
}

function validateResolvedToken(token) {
  const { type, value, path: tokenPath } = token;
  switch (type) {
    case 'color':
      validateColor(value, tokenPath);
      break;
    case 'dimension':
      validateDimension(value, tokenPath);
      break;
    case 'duration':
      validateDuration(value, tokenPath);
      break;
    case 'number':
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new Error(`Token ${tokenPath} must resolve to a finite number`);
      }
      break;
    case 'cubicBezier':
      validateCubicBezier(value, tokenPath);
      break;
    case 'shadow': {
      const layers = Array.isArray(value) ? value : [value];
      if (layers.length === 0) {
        throw new Error(`Token ${tokenPath} shadow must contain at least one layer`);
      }
      layers.forEach((layer, index) => validateShadowLayer(layer, `${tokenPath}[${index}]`));
      break;
    }
    default:
      throw new Error(`Unsupported token type ${type} at ${tokenPath}`);
  }
}

function createResolver(tokens) {
  const resolved = new Map();
  const visiting = [];

  function resolveReference(reference, ownerPath) {
    const target = tokens.get(reference);
    if (!target) {
      throw new Error(`Unknown token reference ${reference} from ${ownerPath}`);
    }
    return resolveToken(reference);
  }

  function resolveValue(value, ownerPath) {
    if (typeof value === 'string') {
      const match = REFERENCE_PATTERN.exec(value);
      if (match) {
        return clone(resolveReference(match[1], ownerPath).value);
      }
      if (value.includes('{') || value.includes('}')) {
        throw new Error(`Malformed token reference ${value} from ${ownerPath}`);
      }
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((entry) => resolveValue(entry, ownerPath));
    }
    if (isPlainObject(value)) {
      return Object.fromEntries(
        Object.entries(value).map(([key, entry]) => [key, resolveValue(entry, ownerPath)]),
      );
    }
    return value;
  }

  function resolveToken(tokenPath) {
    if (resolved.has(tokenPath)) {
      return resolved.get(tokenPath);
    }
    const cycleIndex = visiting.indexOf(tokenPath);
    if (cycleIndex !== -1) {
      const cycle = [...visiting.slice(cycleIndex), tokenPath].join(' -> ');
      throw new Error(`Cyclic token reference: ${cycle}`);
    }
    const token = tokens.get(tokenPath);
    if (!token) {
      throw new Error(`Unknown token reference ${tokenPath}`);
    }

    visiting.push(tokenPath);
    try {
      const wholeReference = typeof token.value === 'string' ? REFERENCE_PATTERN.exec(token.value) : null;
      if (wholeReference) {
        const target = tokens.get(wholeReference[1]);
        if (!target) {
          throw new Error(`Unknown token reference ${wholeReference[1]} from ${tokenPath}`);
        }
        if (target.type !== token.type) {
          throw new Error(`Token ${tokenPath} type ${token.type} cannot reference ${target.type} token ${target.path}`);
        }
      }
      const resolvedToken = {
        ...token,
        value: resolveValue(token.value, tokenPath),
      };
      validateResolvedToken(resolvedToken);
      resolved.set(tokenPath, resolvedToken);
      return resolvedToken;
    } finally {
      visiting.pop();
    }
  }

  return {
    resolveAll() {
      for (const tokenPath of [...tokens.keys()].sort()) {
        resolveToken(tokenPath);
      }
      return resolved;
    },
  };
}

function colorToCss(value) {
  validateColor(value, '<css-color>');
  if ((value.alpha ?? 1) === 1) {
    return value.hex;
  }
  const [red, green, blue] = [1, 3, 5].map((start) => Number.parseInt(value.hex.slice(start, start + 2), 16));
  return `rgb(${red} ${green} ${blue} / ${formatNumber(value.alpha)})`;
}

function dimensionToCss(value) {
  return `${formatNumber(value.value)}${value.unit}`;
}

function durationToCss(value) {
  return `${formatNumber(value.value)}${value.unit}`;
}

function shadowToCss(value) {
  const layers = Array.isArray(value) ? value : [value];
  return layers.map((layer) => {
    const parts = [];
    if (layer.inset === true) {
      parts.push('inset');
    }
    parts.push(
      dimensionToCss(layer.offsetX),
      dimensionToCss(layer.offsetY),
      dimensionToCss(layer.blur),
      dimensionToCss(layer.spread),
      colorToCss(layer.color),
    );
    return parts.join(' ');
  }).join(', ');
}

function tokenToCss(token) {
  switch (token.type) {
    case 'color':
      return colorToCss(token.value);
    case 'dimension':
      return dimensionToCss(token.value);
    case 'duration':
      return durationToCss(token.value);
    case 'number':
      return formatNumber(token.value);
    case 'cubicBezier':
      return `cubic-bezier(${token.value.map(formatNumber).join(', ')})`;
    case 'shadow':
      return shadowToCss(token.value);
    default:
      throw new Error(`Cannot serialize ${token.type} token ${token.path}`);
  }
}

function renderRule(selector, declarations) {
  const lines = Object.entries(declarations)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => `  ${name}: ${value};`);
  return `${selector} {\n${lines.join('\n')}\n}`;
}

function requireToken(resolved, tokenPath) {
  const token = resolved.get(tokenPath);
  if (!token) {
    throw new Error(`Required Alloy token ${tokenPath} is missing`);
  }
  return token;
}

function makeCommonDeclarations(resolved) {
  const mappings = [
    ['--alloy-ai', 'alloy.semantic.ai'],
    ['--alloy-danger', 'alloy.semantic.danger'],
    ['--alloy-density-comfortable-control-target', 'alloy.density.comfortable.controlTarget'],
    ['--alloy-density-compact-control-target', 'alloy.density.compact.controlTarget'],
    ['--alloy-focus', 'alloy.semantic.focus'],
    ['--alloy-focus-contrast', 'alloy.accessibility.focus.contrast'],
    ['--alloy-focus-offset', 'alloy.accessibility.focus.offset'],
    ['--alloy-focus-width', 'alloy.accessibility.focus.width'],
    ['--alloy-contrast-normal-text', 'alloy.accessibility.contrast.normalText'],
    ['--alloy-contrast-large-text', 'alloy.accessibility.contrast.largeText'],
    ['--alloy-contrast-non-text', 'alloy.accessibility.contrast.nonText'],
    ['--alloy-motion-dialog-fast', 'alloy.motion.dialog.fast'],
    ['--alloy-motion-dialog-standard', 'alloy.motion.dialog.standard'],
    ['--alloy-motion-dialog-slow', 'alloy.motion.dialog.slow'],
    ['--alloy-motion-feedback-fast', 'alloy.motion.feedback.fast'],
    ['--alloy-motion-feedback-standard', 'alloy.motion.feedback.standard'],
    ['--alloy-motion-feedback-slow', 'alloy.motion.feedback.slow'],
    ['--alloy-motion-surface-fast', 'alloy.motion.surface.fast'],
    ['--alloy-motion-surface-standard', 'alloy.motion.surface.standard'],
    ['--alloy-motion-surface-slow', 'alloy.motion.surface.slow'],
    ['--alloy-motion-easing-enter', 'alloy.motion.easing.enter'],
    ['--alloy-motion-easing-exit', 'alloy.motion.easing.exit'],
    ['--alloy-motion-easing-standard', 'alloy.motion.easing.standard'],
    ['--alloy-reduced-motion-duration', 'alloy.accessibility.reducedMotion.duration'],
    ['--alloy-reduced-motion-iteration-count', 'alloy.accessibility.reducedMotion.iterationCount'],
    ['--alloy-selection', 'alloy.semantic.selection'],
    ['--alloy-success', 'alloy.semantic.success'],
    ['--alloy-target-minimum', 'alloy.accessibility.target.minimum'],
    ['--alloy-target-preferred', 'alloy.accessibility.target.preferred'],
    ['--alloy-warning', 'alloy.semantic.warning'],
  ];
  return Object.fromEntries(
    mappings.map(([cssName, tokenPath]) => [cssName, tokenToCss(requireToken(resolved, tokenPath))]),
  );
}

function makeThemeDeclarations(resolved, sourceTheme, outputTheme) {
  const semanticBase = `alloy.semantic.theme.${sourceTheme}`;
  const mappings = [
    ['--alloy-ambient-shadow', `${semanticBase}.ambientShadow`],
    ['--alloy-chassis', `${semanticBase}.chassis`],
    ['--alloy-disabled', `${semanticBase}.disabled`],
    ['--alloy-icon', `${semanticBase}.icon`],
    ['--alloy-raised', `${semanticBase}.raised`],
    ['--alloy-specular-edge', `${semanticBase}.specularEdge`],
    ['--alloy-surface', `${semanticBase}.surface`],
    ['--alloy-text-disabled', `${semanticBase}.text.disabled`],
    ['--alloy-text-primary', `${semanticBase}.text.primary`],
    ['--alloy-text-secondary', `${semanticBase}.text.secondary`],
    ['--alloy-well', `${semanticBase}.well`],
  ];
  const declarations = Object.fromEntries(
    mappings.map(([cssName, tokenPath]) => [cssName, tokenToCss(requireToken(resolved, tokenPath))]),
  );

  for (const [sourceState, outputState] of MATERIAL_STATES) {
    const cssName = `--alloy-material-${outputState}-shadow`;
    if (sourceState === 'flush') {
      declarations[cssName] = 'none';
      continue;
    }
    const tokenPath = `alloy.material.${sourceState}.theme.${sourceTheme}.shadow`;
    declarations[cssName] = tokenToCss(requireToken(resolved, tokenPath));
  }

  return {
    selector: `[data-alloy-theme="${outputTheme}"]`,
    declarations,
  };
}

function renderMaterialRules() {
  return MATERIAL_STATES.map(([, outputState]) => renderRule(
    `[data-alloy-material="${outputState}"]`,
    { 'box-shadow': `var(--alloy-material-${outputState}-shadow)` },
  )).join('\n\n');
}

function indentBlock(value, spaces = 2) {
  const prefix = ' '.repeat(spaces);
  return value.split('\n').map((line) => `${prefix}${line}`).join('\n');
}

function renderForcedColors() {
  const systemDeclarations = {
    '--alloy-chassis': 'Canvas',
    '--alloy-disabled': 'GrayText',
    '--alloy-focus': 'Highlight',
    '--alloy-icon': 'CanvasText',
    '--alloy-raised': 'Canvas',
    '--alloy-selection': 'Highlight',
    '--alloy-surface': 'Canvas',
    '--alloy-text-disabled': 'GrayText',
    '--alloy-text-primary': 'CanvasText',
    '--alloy-text-secondary': 'CanvasText',
    '--alloy-well': 'Canvas',
  };
  const materialDeclarations = {
    'background-image': 'none',
    'border': '1px solid CanvasText',
    'box-shadow': 'none',
    'forced-color-adjust': 'auto',
  };
  return [
    '@media (forced-colors: active) {',
    indentBlock(renderRule(':root', systemDeclarations)),
    '',
    indentBlock(renderRule('[data-alloy-material]', materialDeclarations)),
    '}',
  ].join('\n');
}

function renderReducedMotion() {
  const reducedDeclarations = {
    '--alloy-motion-dialog-fast': '0.01ms',
    '--alloy-motion-dialog-standard': '0.01ms',
    '--alloy-motion-dialog-slow': '0.01ms',
    '--alloy-motion-feedback-fast': '0.01ms',
    '--alloy-motion-feedback-standard': '0.01ms',
    '--alloy-motion-feedback-slow': '0.01ms',
    '--alloy-motion-surface-fast': '0.01ms',
    '--alloy-motion-surface-standard': '0.01ms',
    '--alloy-motion-surface-slow': '0.01ms',
  };
  const motionDeclarations = {
    'animation-duration': '0.01ms !important',
    'animation-iteration-count': '1 !important',
    'scroll-behavior': 'auto !important',
    'transition-duration': '0.01ms !important',
  };
  const displacementDeclarations = {
    'transform': 'none !important',
  };
  return [
    '@media (prefers-reduced-motion: reduce) {',
    indentBlock(renderRule(':root', reducedDeclarations)),
    '',
    indentBlock(renderRule('[data-alloy-motion]', motionDeclarations)),
    '',
    indentBlock(renderRule('[data-alloy-motion~="displacement"]', displacementDeclarations)),
    '}',
  ].join('\n');
}

function renderCss(resolved) {
  const common = makeCommonDeclarations(resolved);
  const silver = makeThemeDeclarations(resolved, 'silver', 'silver');
  const spaceBlack = makeThemeDeclarations(resolved, 'spaceBlack', 'space-black');

  return [
    '/* Generated by packages/alloy/scripts/build-tokens.mjs. Do not edit. */',
    renderRule(':root', common),
    renderRule(silver.selector, silver.declarations),
    renderRule(spaceBlack.selector, spaceBlack.declarations),
    renderMaterialRules(),
    renderForcedColors(),
    renderReducedMotion(),
    '',
  ].join('\n\n');
}

function collectCssCustomProperties(css) {
  return [...new Set([...css.matchAll(/(--alloy-[a-z0-9-]+)\s*:/g)].map((match) => match[1]))].sort();
}

function renderTypeScript(css) {
  const cssProperties = collectCssCustomProperties(css);
  return [
    '// Generated by packages/alloy/scripts/build-tokens.mjs. Do not edit.',
    'export const alloyThemes = ["silver", "space-black"] as const;',
    'export type AlloyTheme = (typeof alloyThemes)[number];',
    '',
    'export const alloyMaterialStates = ["flush", "convex-low", "convex-high", "concave-low", "concave-deep", "inlaid", "beveled", "floating"] as const;',
    'export type AlloyMaterialState = (typeof alloyMaterialStates)[number];',
    '',
    'export const alloyDensities = ["comfortable", "compact"] as const;',
    'export type AlloyDensity = (typeof alloyDensities)[number];',
    '',
    `export const alloyCssCustomProperties = ${JSON.stringify(cssProperties)} as const;`,
    'export type AlloyCssCustomProperty = (typeof alloyCssCustomProperties)[number];',
    '',
  ].join('\n');
}

export async function buildTokens({ sourceRoot, outputRoot }) {
  if (!sourceRoot || !outputRoot) {
    throw new Error('buildTokens requires sourceRoot and outputRoot');
  }

  const tokens = new Map();
  for (const relativePath of INPUT_FILES) {
    const absolutePath = path.join(sourceRoot, relativePath);
    let parsed;
    try {
      parsed = JSON.parse(await readFile(absolutePath, 'utf8'));
    } catch (error) {
      throw new Error(`Unable to read Alloy token source ${relativePath}: ${error.message}`, { cause: error });
    }
    collectTokens(parsed, relativePath, tokens);
  }

  const resolved = createResolver(tokens).resolveAll();
  const css = renderCss(resolved);
  const ts = renderTypeScript(css);

  await mkdir(outputRoot, { recursive: true });
  await Promise.all([
    writeFile(path.join(outputRoot, 'tokens.css'), css, 'utf8'),
    writeFile(path.join(outputRoot, 'tokens.ts'), ts, 'utf8'),
  ]);

  return { css, ts };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await buildTokens({
    sourceRoot: path.resolve('packages/alloy'),
    outputRoot: path.resolve('packages/alloy/generated'),
  });
}

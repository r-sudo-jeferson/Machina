import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const testDir = path.dirname(fileURLToPath(import.meta.url));
const alloyRoot = path.resolve(testDir, '..');
const normalTextMinimum = 4.5;

function parseDeclarations(block) {
  return new Map(
    [...block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/gi)].map((match) => [
      match[1],
      match[2].trim(),
    ]),
  );
}

function readRule(css, selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = css.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, 's'));
  assert.ok(match, `missing CSS rule for ${selector}`);
  return match[1];
}

function readTheme(css, selector) {
  return parseDeclarations(readRule(css, selector));
}

function parseHex(value) {
  const match = value.match(/^#([0-9a-f]{6})$/i);
  assert.ok(match, `expected canonical six-digit hex color, received ${value}`);
  return [0, 2, 4].map((offset) => Number.parseInt(match[1].slice(offset, offset + 2), 16) / 255);
}

function relativeLuminance(value) {
  const [r, g, b] = parseHex(value).map((channel) =>
    channel <= 0.04045
      ? channel / 12.92
      : ((channel + 0.055) / 1.055) ** 2.4,
  );
  return (0.2126 * r) + (0.7152 * g) + (0.0722 * b);
}

function contrastRatio(foreground, background) {
  const high = Math.max(relativeLuminance(foreground), relativeLuminance(background));
  const low = Math.min(relativeLuminance(foreground), relativeLuminance(background));
  return (high + 0.05) / (low + 0.05);
}

function resolveColor(variableName, root, theme) {
  const value = theme.get(variableName) ?? root.get(variableName);
  assert.ok(value, `missing ${variableName}`);
  return value;
}

test('field error text meets normal-text contrast on every Alloy material background', async () => {
  const [componentCss, tokensCss] = await Promise.all([
    readFile(path.join(alloyRoot, 'src', 'alloy.css'), 'utf8'),
    readFile(path.join(alloyRoot, 'generated', 'tokens.css'), 'utf8'),
  ]);

  const fieldErrorRule = readRule(componentCss, '.alloy-field-error');
  const colorMatch = fieldErrorRule.match(/color\s*:\s*var\((--[a-z0-9-]+)\)\s*;/i);
  assert.ok(colorMatch, 'field error text must use a canonical Alloy color variable');
  const foregroundVariable = colorMatch[1];

  const root = readTheme(tokensCss, ':root');
  const themes = [
    ['silver', readTheme(tokensCss, '[data-alloy-theme="silver"]')],
    ['space-black', readTheme(tokensCss, '[data-alloy-theme="space-black"]')],
  ];
  const backgrounds = ['--alloy-chassis', '--alloy-surface', '--alloy-well', '--alloy-raised'];

  for (const [themeName, theme] of themes) {
    const foreground = resolveColor(foregroundVariable, root, theme);
    for (const backgroundVariable of backgrounds) {
      const background = resolveColor(backgroundVariable, root, theme);
      const ratio = contrastRatio(foreground, background);
      assert.ok(
        ratio >= normalTextMinimum,
        `${themeName} ${foregroundVariable} ${foreground} on ${backgroundVariable} ${background} is ${ratio.toFixed(2)}:1; requires ${normalTextMinimum}:1`,
      );
    }
  }
});

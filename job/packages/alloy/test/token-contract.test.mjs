import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const alloyRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function readJson(relativePath) {
  return JSON.parse(await readFile(path.join(alloyRoot, relativePath), 'utf8'));
}

function assertDtcgSrgbColor(token, expectedHex, expectedAlpha = 1) {
  assert.equal(token.$type, 'color');
  assert.equal(typeof token.$value, 'object');
  assert.notEqual(token.$value, null);
  assert.equal(token.$value.colorSpace, 'srgb');
  assert.equal(token.$value.hex, expectedHex);
  assert.equal(token.$value.alpha ?? 1, expectedAlpha);
  assert.ok(Array.isArray(token.$value.components));
  assert.equal(token.$value.components.length, 3);

  const expectedComponents = [
    Number.parseInt(expectedHex.slice(1, 3), 16) / 255,
    Number.parseInt(expectedHex.slice(3, 5), 16) / 255,
    Number.parseInt(expectedHex.slice(5, 7), 16) / 255,
  ];

  for (const [index, expected] of expectedComponents.entries()) {
    const actual = token.$value.components[index];
    assert.equal(typeof actual, 'number');
    assert.ok(
      Math.abs(actual - expected) <= 1e-12,
      `${expectedHex} component ${index} must encode the canonical sRGB value`,
    );
  }
}

test('canonical Alloy token files and palettes are exact DTCG 2025.10 values', async () => {
  const required = [
    'tokens/primitives.json',
    'tokens/themes/silver.json',
    'tokens/themes/space-black.json',
    'tokens/semantic.json',
    'tokens/material.json',
    'tokens/accessibility.json',
  ];
  const [primitives, silver, spaceBlack, semantic, material, accessibility] = await Promise.all(
    required.map(readJson),
  );

  assertDtcgSrgbColor(silver.alloy.theme.silver.chassis, '#D8DADD');
  assertDtcgSrgbColor(silver.alloy.theme.silver.litPlane, '#F5F6F7');
  assertDtcgSrgbColor(silver.alloy.theme.silver.shadowPlane, '#B4B8BE');
  assertDtcgSrgbColor(silver.alloy.theme.silver.concaveWell, '#C9CCD1');
  assertDtcgSrgbColor(silver.alloy.theme.silver.text.primary, '#17191D');
  assertDtcgSrgbColor(silver.alloy.theme.silver.text.secondary, '#4D535B');
  assertDtcgSrgbColor(silver.alloy.theme.silver.text.disabled, '#737A84');
  assertDtcgSrgbColor(silver.alloy.theme.silver.specularEdge, '#FFFFFF', 0.82);
  assertDtcgSrgbColor(silver.alloy.theme.silver.ambientShadow, '#434850', 0.28);

  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.chassis, '#1D1F22');
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.litPlane, '#34373C');
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.shadowPlane, '#090A0C');
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.concaveWell, '#141619');
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.text.primary, '#F5F7FA');
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.text.secondary, '#B2B8C1');
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.text.disabled, '#7B828D');
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.specularEdge, '#FFFFFF', 0.16);
  assertDtcgSrgbColor(spaceBlack.alloy.theme.spaceBlack.ambientShadow, '#000000', 0.72);

  const detail = primitives.alloy.primitive.color;
  assertDtcgSrgbColor(detail.electricBlue, '#147DFF');
  assertDtcgSrgbColor(detail.plasmaCyan, '#00D9FF');
  assertDtcgSrgbColor(detail.voltLime, '#AEFF3D');
  assertDtcgSrgbColor(detail.fusionMagenta, '#FF2D8D');
  assertDtcgSrgbColor(detail.ionAmber, '#FFB21A');
  assertDtcgSrgbColor(detail.signalRed, '#FF3B45');
  assertDtcgSrgbColor(detail.reactorGreen, '#20E37A');

  assert.deepEqual(primitives.alloy.primitive.spacing.base.$value, { value: 4, unit: 'px' });
  assert.deepEqual(
    Object.values(primitives.alloy.primitive.radius).map((token) => token.$value.value),
    [8, 12, 18, 24, 32],
  );
  assert.deepEqual(accessibility.alloy.accessibility.focus.width.$value, { value: 2, unit: 'px' });
  assert.deepEqual(accessibility.alloy.accessibility.target.minimum.$value, { value: 24, unit: 'px' });
  assert.deepEqual(accessibility.alloy.accessibility.target.preferred.$value, { value: 44, unit: 'px' });

  assert.equal(semantic.alloy.semantic.focus.$value, '{alloy.primitive.color.electricBlue}');
  assert.equal(semantic.alloy.semantic.ai.$value, '{alloy.primitive.color.plasmaCyan}');
  assert.equal(semantic.alloy.semantic.success.$value, '{alloy.primitive.color.reactorGreen}');
  assert.equal(semantic.alloy.semantic.warning.$value, '{alloy.primitive.color.ionAmber}');
  assert.equal(semantic.alloy.semantic.danger.$value, '{alloy.primitive.color.signalRed}');

  assert.deepEqual(Object.keys(material.alloy.material), [
    'flush',
    'convexLow',
    'convexHigh',
    'concaveLow',
    'concaveDeep',
    'inlaid',
    'beveled',
    'floating',
  ]);
});

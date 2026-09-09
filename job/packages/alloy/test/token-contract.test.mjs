import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const alloyRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function readJson(relativePath) {
  return JSON.parse(await readFile(path.join(alloyRoot, relativePath), 'utf8'));
}

test('canonical Alloy token files and palettes are exact', async () => {
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

  assert.equal(silver.alloy.theme.silver.chassis.$value, '#D8DADD');
  assert.equal(silver.alloy.theme.silver.litPlane.$value, '#F5F6F7');
  assert.equal(silver.alloy.theme.silver.shadowPlane.$value, '#B4B8BE');
  assert.equal(silver.alloy.theme.silver.concaveWell.$value, '#C9CCD1');
  assert.equal(silver.alloy.theme.silver.text.primary.$value, '#17191D');
  assert.equal(silver.alloy.theme.silver.text.secondary.$value, '#4D535B');
  assert.equal(silver.alloy.theme.silver.text.disabled.$value, '#737A84');
  assert.equal(silver.alloy.theme.silver.specularEdge.$value, 'rgba(255,255,255,0.82)');
  assert.equal(silver.alloy.theme.silver.ambientShadow.$value, 'rgba(67,72,80,0.28)');

  assert.equal(spaceBlack.alloy.theme.spaceBlack.chassis.$value, '#1D1F22');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.litPlane.$value, '#34373C');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.shadowPlane.$value, '#090A0C');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.concaveWell.$value, '#141619');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.text.primary.$value, '#F5F7FA');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.text.secondary.$value, '#B2B8C1');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.text.disabled.$value, '#7B828D');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.specularEdge.$value, 'rgba(255,255,255,0.16)');
  assert.equal(spaceBlack.alloy.theme.spaceBlack.ambientShadow.$value, 'rgba(0,0,0,0.72)');

  const detail = primitives.alloy.primitive.color;
  assert.equal(detail.electricBlue.$value, '#147DFF');
  assert.equal(detail.plasmaCyan.$value, '#00D9FF');
  assert.equal(detail.voltLime.$value, '#AEFF3D');
  assert.equal(detail.fusionMagenta.$value, '#FF2D8D');
  assert.equal(detail.ionAmber.$value, '#FFB21A');
  assert.equal(detail.signalRed.$value, '#FF3B45');
  assert.equal(detail.reactorGreen.$value, '#20E37A');

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

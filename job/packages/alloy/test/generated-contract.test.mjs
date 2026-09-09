import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const alloyRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const compilerUrl = pathToFileURL(path.join(alloyRoot, 'scripts/build-tokens.mjs')).href;

async function readJson(relativePath, root = alloyRoot) {
  return JSON.parse(await readFile(path.join(root, relativePath), 'utf8'));
}

function linearize(component) {
  return component <= 0.04045
    ? component / 12.92
    : ((component + 0.055) / 1.055) ** 2.4;
}

function luminance(colorToken) {
  const { colorSpace, components, alpha = 1 } = colorToken.$value;
  assert.equal(colorSpace, 'srgb');
  assert.equal(alpha, 1, 'contrast source colors must be opaque');
  const [red, green, blue] = components.map(linearize);
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

function contrastRatio(foreground, background) {
  const foregroundLuminance = luminance(foreground);
  const backgroundLuminance = luminance(background);
  const lighter = Math.max(foregroundLuminance, backgroundLuminance);
  const darker = Math.min(foregroundLuminance, backgroundLuminance);
  return (lighter + 0.05) / (darker + 0.05);
}

async function importCompiler() {
  return import(compilerUrl);
}

async function withTempDir(prefix, fn) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  try {
    return await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function copySourceTokens(targetRoot) {
  await cp(path.join(alloyRoot, 'tokens'), path.join(targetRoot, 'tokens'), { recursive: true });
}

test('canonical body-text pairs meet WCAG AA without relying on shadows', async () => {
  const silver = await readJson('tokens/themes/silver.json');
  const spaceBlack = await readJson('tokens/themes/space-black.json');

  const pairs = [
    ['silver primary/chassis', silver.alloy.theme.silver.text.primary, silver.alloy.theme.silver.chassis],
    ['silver secondary/chassis', silver.alloy.theme.silver.text.secondary, silver.alloy.theme.silver.chassis],
    ['silver primary/surface', silver.alloy.theme.silver.text.primary, silver.alloy.theme.silver.litPlane],
    ['silver secondary/surface', silver.alloy.theme.silver.text.secondary, silver.alloy.theme.silver.litPlane],
    ['silver primary/well', silver.alloy.theme.silver.text.primary, silver.alloy.theme.silver.concaveWell],
    ['silver secondary/well', silver.alloy.theme.silver.text.secondary, silver.alloy.theme.silver.concaveWell],
    ['space-black primary/chassis', spaceBlack.alloy.theme.spaceBlack.text.primary, spaceBlack.alloy.theme.spaceBlack.chassis],
    ['space-black secondary/chassis', spaceBlack.alloy.theme.spaceBlack.text.secondary, spaceBlack.alloy.theme.spaceBlack.chassis],
    ['space-black primary/surface', spaceBlack.alloy.theme.spaceBlack.text.primary, spaceBlack.alloy.theme.spaceBlack.litPlane],
    ['space-black secondary/surface', spaceBlack.alloy.theme.spaceBlack.text.secondary, spaceBlack.alloy.theme.spaceBlack.litPlane],
    ['space-black primary/well', spaceBlack.alloy.theme.spaceBlack.text.primary, spaceBlack.alloy.theme.spaceBlack.concaveWell],
    ['space-black secondary/well', spaceBlack.alloy.theme.spaceBlack.text.secondary, spaceBlack.alloy.theme.spaceBlack.concaveWell],
  ];

  for (const [name, foreground, background] of pairs) {
    assert.ok(contrastRatio(foreground, background) >= 4.5, `${name} must meet 4.5:1`);
  }
});

test('compiler output is deterministic and byte-identical to committed contracts', async () => {
  const { buildTokens } = await importCompiler();

  await withTempDir('alloy-generated-a-', async (firstOutputRoot) => {
    await withTempDir('alloy-generated-b-', async (secondOutputRoot) => {
      await buildTokens({ sourceRoot: alloyRoot, outputRoot: firstOutputRoot });
      await buildTokens({ sourceRoot: alloyRoot, outputRoot: secondOutputRoot });

      const [firstCss, firstTs, secondCss, secondTs, committedCss, committedTs] = await Promise.all([
        readFile(path.join(firstOutputRoot, 'tokens.css'), 'utf8'),
        readFile(path.join(firstOutputRoot, 'tokens.ts'), 'utf8'),
        readFile(path.join(secondOutputRoot, 'tokens.css'), 'utf8'),
        readFile(path.join(secondOutputRoot, 'tokens.ts'), 'utf8'),
        readFile(path.join(alloyRoot, 'generated/tokens.css'), 'utf8'),
        readFile(path.join(alloyRoot, 'generated/tokens.ts'), 'utf8'),
      ]);

      assert.equal(firstCss, secondCss);
      assert.equal(firstTs, secondTs);
      assert.equal(firstCss, committedCss);
      assert.equal(firstTs, committedTs);

      assert.match(firstCss, /\[data-alloy-theme="silver"\]/);
      assert.match(firstCss, /\[data-alloy-theme="space-black"\]/);
      assert.match(firstCss, /@media \(forced-colors: active\)/);
      assert.match(firstCss, /@media \(prefers-reduced-motion: reduce\)/);
      assert.match(firstCss, /--alloy-focus-width: 2px/);
      assert.match(firstCss, /forced-color-adjust:/);
      assert.match(firstCss, /CanvasText|Highlight/);
      assert.match(firstTs, /export const alloyThemes = \["silver", "space-black"\] as const/);
    });
  });
});

test('compiler rejects unknown references and reference cycles', async () => {
  const { buildTokens } = await importCompiler();

  await withTempDir('alloy-unknown-ref-', async (sourceRoot) => {
    await copySourceTokens(sourceRoot);
    const semanticPath = path.join(sourceRoot, 'tokens/semantic.json');
    const semantic = JSON.parse(await readFile(semanticPath, 'utf8'));
    semantic.alloy.semantic.focus.$value = '{alloy.primitive.color.missing}';
    await writeFile(semanticPath, `${JSON.stringify(semantic, null, 2)}\n`);

    await withTempDir('alloy-unknown-output-', async (outputRoot) => {
      await assert.rejects(
        buildTokens({ sourceRoot, outputRoot }),
        /unknown token reference.*alloy\.primitive\.color\.missing/i,
      );
    });
  });

  await withTempDir('alloy-cycle-', async (sourceRoot) => {
    await copySourceTokens(sourceRoot);
    const semanticPath = path.join(sourceRoot, 'tokens/semantic.json');
    const semantic = JSON.parse(await readFile(semanticPath, 'utf8'));
    semantic.alloy.semantic.focus.$value = '{alloy.semantic.ai}';
    semantic.alloy.semantic.ai.$value = '{alloy.semantic.focus}';
    await writeFile(semanticPath, `${JSON.stringify(semantic, null, 2)}\n`);

    await withTempDir('alloy-cycle-output-', async (outputRoot) => {
      await assert.rejects(
        buildTokens({ sourceRoot, outputRoot }),
        /cyclic token reference/i,
      );
    });
  });
});

test('compiler rejects a color whose structured sRGB components disagree with its canonical hex fallback', async () => {
  const { buildTokens } = await importCompiler();

  await withTempDir('alloy-color-mismatch-', async (sourceRoot) => {
    await copySourceTokens(sourceRoot);
    const silverPath = path.join(sourceRoot, 'tokens/themes/silver.json');
    const silver = JSON.parse(await readFile(silverPath, 'utf8'));
    silver.alloy.theme.silver.chassis.$value.components[0] = 0;
    await writeFile(silverPath, `${JSON.stringify(silver, null, 2)}\n`);

    await withTempDir('alloy-color-output-', async (outputRoot) => {
      await assert.rejects(
        buildTokens({ sourceRoot, outputRoot }),
        /color components.*hex fallback/i,
      );
    });
  });
});

import assert from 'node:assert/strict';
import {access, readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const testDir = path.dirname(fileURLToPath(import.meta.url));
const alloyRoot = path.resolve(testDir, '..');
const repositoryRoot = path.resolve(alloyRoot, '..', '..', '..');

async function exists(relativePath) {
  try {
    await access(path.join(alloyRoot, relativePath));
    return true;
  } catch {
    return false;
  }
}

async function read(relativePath) {
  return readFile(path.join(alloyRoot, relativePath), 'utf8');
}

test('Task 8.6 requires the Storybook state, accessibility, and CI evidence boundary', async () => {
  const requiredFiles = [
    '.storybook/main.ts',
    '.storybook/preview.ts',
    'src/material.stories.tsx',
    'src/controls.stories.tsx',
    'src/status.stories.tsx',
    'src/accessibility.test.tsx',
  ];

  for (const relativePath of requiredFiles) {
    assert.equal(
      await exists(relativePath),
      true,
      `Task 8.6 requires ${relativePath}`,
    );
  }

  const main = await read('.storybook/main.ts');
  assert.match(main, /@storybook\/react-vite/);
  assert.match(main, /\.\.\/src\/\*\*\/\*\.stories/);

  const preview = await read('.storybook/preview.ts');
  assert.match(preview, /\.\.\/generated\/tokens\.css/);
  assert.match(preview, /\.\.\/src\/alloy\.css/);
  assert.match(preview, /data-alloy-theme/);
  assert.match(preview, /silver/);
  assert.match(preview, /space-black/);

  const materialStories = await read('src/material.stories.tsx');
  for (const requiredExport of ['SilverDepthMatrix', 'SpaceBlackDepthMatrix']) {
    assert.match(materialStories, new RegExp(`export const ${requiredExport}\\b`));
  }
  assert.match(materialStories, /AlloyChassis/);
  assert.match(materialStories, /AlloySurface/);
  assert.match(materialStories, /AlloyWell/);

  const controlStories = await read('src/controls.stories.tsx');
  for (const requiredExport of [
    'ButtonDefault',
    'ButtonKeyboardFocus',
    'ButtonDisabled',
    'ButtonLoading',
    'ButtonPressed',
    'IconButtonDefault',
    'IconButtonDisabled',
    'IconButtonLoading',
    'TextFieldDefault',
    'TextFieldDisabled',
    'TextFieldError',
    'SwitchDefault',
    'SwitchKeyboardFocus',
    'SwitchDisabled',
    'SwitchSelected',
  ]) {
    assert.match(controlStories, new RegExp(`export const ${requiredExport}\\b`));
  }
  assert.match(controlStories, /\bplay\s*:/);
  assert.match(controlStories, /userEvent/);

  const statusStories = await read('src/status.stories.tsx');
  for (const requiredExport of [
    'StatusNeutral',
    'StatusSuccess',
    'StatusWarning',
    'StatusDangerDenied',
    'StatusAI',
  ]) {
    assert.match(statusStories, new RegExp(`export const ${requiredExport}\\b`));
  }

  const accessibilityTest = await read('src/accessibility.test.tsx');
  assert.match(accessibilityTest, /from ['"]axe-core['"]/);
  assert.match(accessibilityTest, /axe\.run/);
  assert.match(accessibilityTest, /serious/);
  assert.match(accessibilityTest, /critical/);

  const packageJson = JSON.parse(await read('package.json'));
  assert.equal(
    packageJson.scripts?.['build-storybook'],
    'storybook build --config-dir .storybook --output-dir storybook-static',
  );

  const workflow = await readFile(
    path.join(repositoryRoot, '.github', 'workflows', 'verify-alloy.yml'),
    'utf8',
  );
  assert.match(workflow, /pnpm --filter @machina\/alloy build-storybook/);
});

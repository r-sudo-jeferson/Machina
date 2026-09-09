import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const alloyRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const captureScript = path.join(alloyRoot, 'scripts', 'capture-critic-evidence.mjs');

function planValues(captures, key) {
  return new Set(captures.map((capture) => capture[key]));
}

test('visual critic plan covers the complete first-tranche state and accessibility boundary', () => {
  const result = spawnSync(process.execPath, [captureScript, '--print-plan'], {
    cwd: alloyRoot,
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr || 'critic evidence plan command failed');
  const plan = JSON.parse(result.stdout);

  assert.equal(plan.schemaVersion, 2);
  assert.equal(plan.requiredFontFamily, 'Inter Variable');
  assert.deepEqual(
    [...planValues(plan.captures, 'theme')].sort(),
    ['silver', 'space-black'],
  );
  assert.deepEqual(
    [...planValues(plan.captures, 'mode')].sort(),
    ['forced-colors', 'reduced-motion', 'standard'],
  );

  const components = planValues(plan.captures, 'component');
  for (const component of ['material', 'button', 'icon-button', 'text-field', 'switch', 'status']) {
    assert.ok(components.has(component), `critic evidence must render ${component}`);
  }

  const states = planValues(plan.captures, 'state');
  for (const state of ['default', 'focus', 'disabled', 'loading', 'error', 'selected', 'pressed']) {
    assert.ok(states.has(state), `critic evidence must render ${state}`);
  }

  for (const theme of ['silver', 'space-black']) {
    assert.ok(
      plan.captures.some((capture) => capture.theme === theme && capture.mode === 'forced-colors'),
      `forced-colors evidence must cover ${theme}`,
    );
  }

  const files = plan.captures.map(({file}) => file);
  assert.equal(new Set(files).size, files.length, 'critic evidence file names must be unique');
  assert.ok(files.every((file) => /^[a-z0-9-]+\.png$/.test(file)));
});

import {execFile, spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {mkdir, mkdtemp, readFile, rm, stat, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';

const execFileAsync = promisify(execFile);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const alloyRoot = path.resolve(scriptDir, '..');
const staticRoot = path.join(alloyRoot, 'storybook-static');
const evidenceRoot = path.join(alloyRoot, 'critic-evidence');
const chromeBinary = process.env.CHROME_BIN || 'google-chrome';
const viewport = {width: 1440, height: 1080, deviceScaleFactor: 1};
const materialStates = [
  'flush',
  'convex-low',
  'convex-high',
  'concave-low',
  'concave-deep',
  'inlaid',
  'beveled',
  'floating',
];

function capture({file, storyId, theme, mode, component, state, ...rest}) {
  return {
    file,
    storyId,
    theme,
    mode,
    component,
    state,
    globals: `alloyTheme:${theme}`,
    ...rest,
  };
}

const captures = [
  capture({
    file: 'material-silver-standard.png',
    storyId: 'alloy-material--silver-depth-matrix',
    theme: 'silver',
    mode: 'standard',
    component: 'material',
    state: 'default',
    readySelector: '.alloy-chassis [data-alloy-material="floating"]',
    boundarySelector: '[data-alloy-material]',
    materialStates,
  }),
  capture({
    file: 'material-space-black-standard.png',
    storyId: 'alloy-material--space-black-depth-matrix',
    theme: 'space-black',
    mode: 'standard',
    component: 'material',
    state: 'default',
    readySelector: '.alloy-chassis [data-alloy-material="floating"]',
    boundarySelector: '[data-alloy-material]',
    materialStates,
  }),
  capture({
    file: 'material-silver-forced-colors.png',
    storyId: 'alloy-material--silver-depth-matrix',
    theme: 'silver',
    mode: 'forced-colors',
    component: 'material',
    state: 'default',
    readySelector: '.alloy-chassis [data-alloy-material="floating"]',
    boundarySelector: '[data-alloy-material]',
    materialStates,
  }),
  capture({
    file: 'material-space-black-forced-colors.png',
    storyId: 'alloy-material--space-black-depth-matrix',
    theme: 'space-black',
    mode: 'forced-colors',
    component: 'material',
    state: 'default',
    readySelector: '.alloy-chassis [data-alloy-material="floating"]',
    boundarySelector: '[data-alloy-material]',
    materialStates,
  }),
  capture({
    file: 'button-focus-silver-standard.png',
    storyId: 'alloy-controls--button-keyboard-focus',
    theme: 'silver',
    mode: 'standard',
    component: 'button',
    state: 'focus',
    readySelector: '.alloy-button[data-focus-visible]',
    boundarySelector: '.alloy-button',
  }),
  capture({
    file: 'button-loading-space-black-standard.png',
    storyId: 'alloy-controls--button-loading',
    theme: 'space-black',
    mode: 'standard',
    component: 'button',
    state: 'loading',
    readySelector: '.alloy-button[data-pending]',
    boundarySelector: '.alloy-button',
  }),
  capture({
    file: 'button-pressed-silver-standard.png',
    storyId: 'alloy-controls--button-pressed',
    theme: 'silver',
    mode: 'standard',
    component: 'button',
    state: 'pressed',
    readySelector: '.alloy-button',
    boundarySelector: '.alloy-button',
    interaction: 'hold-enter',
  }),
  capture({
    file: 'button-disabled-space-black-forced-colors.png',
    storyId: 'alloy-controls--button-disabled',
    theme: 'space-black',
    mode: 'forced-colors',
    component: 'button',
    state: 'disabled',
    readySelector: '.alloy-button[data-disabled]',
    boundarySelector: '.alloy-button',
  }),
  capture({
    file: 'button-loading-silver-reduced-motion.png',
    storyId: 'alloy-controls--button-loading',
    theme: 'silver',
    mode: 'reduced-motion',
    component: 'button',
    state: 'loading',
    readySelector: '.alloy-button[data-pending]',
    boundarySelector: '.alloy-button',
  }),
  capture({
    file: 'icon-button-default-silver-standard.png',
    storyId: 'alloy-controls--icon-button-default',
    theme: 'silver',
    mode: 'standard',
    component: 'icon-button',
    state: 'default',
    readySelector: '.alloy-icon-button',
    boundarySelector: '.alloy-icon-button',
  }),
  capture({
    file: 'icon-button-disabled-space-black-forced-colors.png',
    storyId: 'alloy-controls--icon-button-disabled',
    theme: 'space-black',
    mode: 'forced-colors',
    component: 'icon-button',
    state: 'disabled',
    readySelector: '.alloy-icon-button[data-disabled]',
    boundarySelector: '.alloy-icon-button',
  }),
  capture({
    file: 'text-field-error-silver-standard.png',
    storyId: 'alloy-controls--text-field-error',
    theme: 'silver',
    mode: 'standard',
    component: 'text-field',
    state: 'error',
    readySelector: '.alloy-text-field[data-invalid]',
    boundarySelector: '.alloy-input',
  }),
  capture({
    file: 'text-field-disabled-space-black-forced-colors.png',
    storyId: 'alloy-controls--text-field-disabled',
    theme: 'space-black',
    mode: 'forced-colors',
    component: 'text-field',
    state: 'disabled',
    readySelector: '.alloy-input[data-disabled]',
    boundarySelector: '.alloy-input',
  }),
  capture({
    file: 'switch-selected-space-black-standard.png',
    storyId: 'alloy-controls--switch-selected',
    theme: 'space-black',
    mode: 'standard',
    component: 'switch',
    state: 'selected',
    readySelector: '.alloy-switch[data-selected]',
    boundarySelector: '.alloy-switch__track, .alloy-switch__thumb',
  }),
  capture({
    file: 'switch-focus-silver-forced-colors.png',
    storyId: 'alloy-controls--switch-keyboard-focus',
    theme: 'silver',
    mode: 'forced-colors',
    component: 'switch',
    state: 'focus',
    readySelector: '.alloy-switch[data-focus-visible]',
    boundarySelector: '.alloy-switch__track, .alloy-switch__thumb',
  }),
  capture({
    file: 'status-danger-silver-standard.png',
    storyId: 'alloy-status--status-danger-denied',
    theme: 'silver',
    mode: 'standard',
    component: 'status',
    state: 'error',
    readySelector: '.alloy-status-lamp[data-alloy-tone="danger"]',
    boundarySelector: '.alloy-status-lamp__indicator',
  }),
  capture({
    file: 'status-ai-space-black-standard.png',
    storyId: 'alloy-status--status-ai',
    theme: 'space-black',
    mode: 'standard',
    component: 'status',
    state: 'selected',
    readySelector: '.alloy-status-lamp[data-alloy-tone="ai"]',
    boundarySelector: '.alloy-status-lamp__indicator',
  }),
];

const criticPlan = {
  schemaVersion: 2,
  requiredFontFamily: 'Inter Variable',
  viewport,
  captures,
};

const mediaFeatures = {
  standard: [
    {name: 'forced-colors', value: 'none'},
    {name: 'prefers-reduced-motion', value: 'no-preference'},
  ],
  'forced-colors': [
    {name: 'forced-colors', value: 'active'},
    {name: 'prefers-reduced-motion', value: 'no-preference'},
  ],
  'reduced-motion': [
    {name: 'forced-colors', value: 'none'},
    {name: 'prefers-reduced-motion', value: 'reduce'},
  ],
};

const contentTypes = new Map([
  ['.css', 'text/css; charset=utf-8'],
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.map', 'application/json; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml'],
  ['.woff', 'font/woff'],
  ['.woff2', 'font/woff2'],
]);

function resolveStaticPath(requestUrl) {
  const pathname = decodeURIComponent(new URL(requestUrl, 'http://127.0.0.1').pathname);
  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const resolved = path.resolve(staticRoot, relative);
  const rootPrefix = `${path.resolve(staticRoot)}${path.sep}`;
  if (resolved !== path.resolve(staticRoot) && !resolved.startsWith(rootPrefix)) {
    throw new Error(`refusing path outside Storybook static root: ${pathname}`);
  }
  return resolved;
}

function createStaticServer() {
  return createServer(async (request, response) => {
    try {
      const filePath = resolveStaticPath(request.url ?? '/');
      const body = await readFile(filePath);
      response.statusCode = 200;
      response.setHeader('content-type', contentTypes.get(path.extname(filePath)) ?? 'application/octet-stream');
      response.setHeader('cache-control', 'no-store');
      response.end(body);
    } catch (error) {
      response.statusCode = 404;
      response.setHeader('content-type', 'text/plain; charset=utf-8');
      response.end(error instanceof Error ? error.message : 'Not found');
    }
  });
}

async function assertStoryIdsExist() {
  const index = JSON.parse(await readFile(path.join(staticRoot, 'index.json'), 'utf8'));
  for (const item of captures) {
    if (!index.entries?.[item.storyId]) {
      throw new Error(`Storybook index does not contain ${item.storyId}`);
    }
  }
}

async function removeChromeProfile(userDataRoot) {
  await rm(userDataRoot, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}

async function launchChrome() {
  const userDataRoot = await mkdtemp(path.join(tmpdir(), 'machina-alloy-chrome-'));
  const child = spawn(chromeBinary, [
    '--headless=new',
    '--disable-background-networking',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--hide-scrollbars',
    '--no-default-browser-check',
    '--no-first-run',
    '--remote-debugging-address=127.0.0.1',
    '--remote-debugging-port=0',
    '--run-all-compositor-stages-before-draw',
    `--user-data-dir=${userDataRoot}`,
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  try {
    const webSocketUrl = await new Promise((resolve, reject) => {
      let diagnostics = '';
      const timeout = setTimeout(() => {
        reject(new Error(`timed out waiting for Chrome DevTools endpoint: ${diagnostics.slice(-2000)}`));
      }, 15_000);

      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk) => {
        diagnostics += chunk;
        const match = diagnostics.match(/DevTools listening on (ws:\/\/[^\s]+)/);
        if (match) {
          clearTimeout(timeout);
          resolve(match[1]);
        }
      });
      child.once('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once('exit', (code, signal) => {
        clearTimeout(timeout);
        reject(new Error(`Chrome exited before DevTools was ready: code ${code ?? 'null'}, signal ${signal ?? 'none'}`));
      });
    });
    return {child, userDataRoot, webSocketUrl};
  } catch (error) {
    child.kill('SIGKILL');
    await removeChromeProfile(userDataRoot);
    throw error;
  }
}

async function stopChrome(browser) {
  if (browser.child.exitCode === null) {
    browser.child.kill('SIGTERM');
    await new Promise((resolve) => {
      const timeout = setTimeout(resolve, 2_000);
      browser.child.once('exit', () => {
        clearTimeout(timeout);
        resolve();
      });
    });
    if (browser.child.exitCode === null) {
      browser.child.kill('SIGKILL');
    }
  }
  await removeChromeProfile(browser.userDataRoot);
}

async function connectCdp(webSocketUrl) {
  const socket = new WebSocket(webSocketUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, {once: true});
    socket.addEventListener('error', () => reject(new Error('Chrome DevTools WebSocket failed to open')), {once: true});
  });

  let nextId = 1;
  const pending = new Map();
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(String(event.data));
    if (!message.id || !pending.has(message.id)) {
      return;
    }
    const {resolve, reject, timeout} = pending.get(message.id);
    pending.delete(message.id);
    clearTimeout(timeout);
    if (message.error) {
      reject(new Error(`CDP ${message.error.code}: ${message.error.message}`));
      return;
    }
    resolve(message.result);
  });

  function call(method, params = {}, sessionId) {
    const id = nextId;
    nextId += 1;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`CDP call timed out: ${method}`));
      }, 15_000);
      pending.set(id, {resolve, reject, timeout});
      socket.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}));
    });
  }

  async function evaluate(sessionId, expression) {
    const response = await call('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    }, sessionId);
    if (response.exceptionDetails) {
      throw new Error(`browser evaluation failed: ${response.exceptionDetails.text}`);
    }
    return response.result.value;
  }

  return {call, evaluate, socket};
}

async function waitFor(cdp, sessionId, expression, description) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (await cdp.evaluate(sessionId, expression)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for ${description}`);
}

async function holdEnter(cdp, sessionId) {
  await cdp.evaluate(sessionId, `document.querySelector('.alloy-button')?.focus()`);
  await cdp.call('Input.dispatchKeyEvent', {
    type: 'rawKeyDown',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
    nativeVirtualKeyCode: 13,
  }, sessionId);
  await waitFor(
    cdp,
    sessionId,
    `Boolean(document.querySelector('.alloy-button[data-pressed]'))`,
    'the real pressed state',
  );
}

async function releaseEnter(cdp, sessionId) {
  await cdp.call('Input.dispatchKeyEvent', {
    type: 'keyUp',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
    nativeVirtualKeyCode: 13,
  }, sessionId);
}

function runtimeAuditExpression(item) {
  return `(() => {
    const fontTarget = document.querySelector('.alloy-chassis') ?? document.body;
    const fontFamily = getComputedStyle(fontTarget).fontFamily;
    const fontFaceLoaded = [...document.fonts].some((font) =>
      font.family.replaceAll('"', '') === ${JSON.stringify(criticPlan.requiredFontFamily)}
      && font.status === 'loaded'
    );
    const boundaryNodes = [...document.querySelectorAll(${JSON.stringify(item.boundarySelector)})];
    const styles = boundaryNodes.map((node) => getComputedStyle(node));
    const spinner = document.querySelector('.alloy-button__progress-indicator');
    return {
      fontFamily,
      fontFaceLoaded,
      forcedColorsActive: matchMedia('(forced-colors: active)').matches,
      reducedMotionActive: matchMedia('(prefers-reduced-motion: reduce)').matches,
      materialStates: [...new Set(
        [...document.querySelectorAll('[data-alloy-material]')]
          .map((node) => node.getAttribute('data-alloy-material'))
          .filter(Boolean)
      )].sort(),
      shadowsDisabled: styles.length > 0 && styles.every((style) => style.boxShadow === 'none'),
      boundariesVisible: styles.length > 0 && styles.every((style) =>
        style.borderTopStyle !== 'none' && Number.parseFloat(style.borderTopWidth) > 0
      ),
      spinner: spinner ? {
        animationDuration: getComputedStyle(spinner).animationDuration,
        animationIterationCount: getComputedStyle(spinner).animationIterationCount,
        transform: getComputedStyle(spinner).transform,
      } : null,
    };
  })()`;
}

function durationToMilliseconds(value) {
  if (value.endsWith('ms')) {
    return Number.parseFloat(value);
  }
  if (value.endsWith('s')) {
    return Number.parseFloat(value) * 1000;
  }
  return Number.NaN;
}

function assertRuntimeAudit(item, audit) {
  if (!audit.fontFaceLoaded || !audit.fontFamily.includes(criticPlan.requiredFontFamily)) {
    throw new Error(`${item.file} did not render with loaded ${criticPlan.requiredFontFamily}`);
  }
  if (item.materialStates) {
    const actual = JSON.stringify([...audit.materialStates].sort());
    const expected = JSON.stringify([...item.materialStates].sort());
    if (actual !== expected) {
      throw new Error(`${item.file} material states differ: ${actual}`);
    }
  }
  if (item.mode === 'forced-colors') {
    if (!audit.forcedColorsActive || audit.reducedMotionActive) {
      throw new Error(`${item.file} did not activate only forced-colors`);
    }
    if (!audit.shadowsDisabled || !audit.boundariesVisible) {
      throw new Error(`${item.file} did not remove shadows and preserve boundaries`);
    }
  }
  if (item.mode === 'reduced-motion') {
    const duration = durationToMilliseconds(audit.spinner?.animationDuration ?? '');
    if (
      !audit.reducedMotionActive
      || audit.forcedColorsActive
      || !Number.isFinite(duration)
      || duration > 0.01
      || audit.spinner?.animationIterationCount !== '1'
      || audit.spinner?.transform !== 'none'
    ) {
      throw new Error(`${item.file} did not enforce the reduced-motion contract`);
    }
  }
  if (item.mode === 'standard' && (audit.forcedColorsActive || audit.reducedMotionActive)) {
    throw new Error(`${item.file} standard mode inherited an accessibility emulation`);
  }
}

async function captureStory(cdp, baseUrl, item) {
  const url = new URL('/iframe.html', baseUrl);
  url.searchParams.set('id', item.storyId);
  url.searchParams.set('viewMode', 'story');
  url.searchParams.set('globals', item.globals);

  const {targetId} = await cdp.call('Target.createTarget', {url: 'about:blank'});
  const {sessionId} = await cdp.call('Target.attachToTarget', {targetId, flatten: true});
  let enterHeld = false;
  try {
    await cdp.call('Page.enable', {}, sessionId);
    await cdp.call('Runtime.enable', {}, sessionId);
    await cdp.call('Emulation.setDeviceMetricsOverride', {
      ...viewport,
      mobile: false,
      screenWidth: viewport.width,
      screenHeight: viewport.height,
    }, sessionId);
    await cdp.call('Emulation.setEmulatedMedia', {
      media: 'screen',
      features: mediaFeatures[item.mode],
    }, sessionId);
    await cdp.call('Page.navigate', {url: url.href}, sessionId);
    await waitFor(
      cdp,
      sessionId,
      `(async () => {
        if (document.readyState !== 'complete') return false;
        await document.fonts.load('16px "${criticPlan.requiredFontFamily}"');
        await document.fonts.ready;
        return Boolean(document.querySelector(${JSON.stringify(item.readySelector)}));
      })()`,
      `${item.storyId} to render ${item.readySelector}`,
    );

    if (item.interaction === 'hold-enter') {
      await holdEnter(cdp, sessionId);
      enterHeld = true;
    }

    const audit = await cdp.evaluate(sessionId, runtimeAuditExpression(item));
    assertRuntimeAudit(item, audit);
    const screenshot = await cdp.call('Page.captureScreenshot', {
      format: 'png',
      fromSurface: true,
      captureBeyondViewport: false,
    }, sessionId);
    const output = path.join(evidenceRoot, item.file);
    await writeFile(output, Buffer.from(screenshot.data, 'base64'));
    const fileStats = await stat(output);
    if (fileStats.size < 5000) {
      throw new Error(`${item.file} is unexpectedly small (${fileStats.size} bytes)`);
    }

    return {
      file: item.file,
      storyId: item.storyId,
      theme: item.theme,
      mode: item.mode,
      component: item.component,
      state: item.state,
      materialStates: item.materialStates ?? null,
      bytes: fileStats.size,
      audit,
    };
  } finally {
    if (enterHeld) {
      await releaseEnter(cdp, sessionId);
    }
    await cdp.call('Target.closeTarget', {targetId});
  }
}

async function main() {
  const server = createStaticServer();
  let browser;
  let cdp;
  try {
    await stat(path.join(staticRoot, 'iframe.html'));
    await assertStoryIdsExist();
    await mkdir(evidenceRoot, {recursive: true});

    const {stdout: chromeVersionOutput} = await execFileAsync(chromeBinary, ['--version']);
    const chromeVersion = chromeVersionOutput.trim();
    console.log(`critic_browser=${chromeVersion}`);

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('failed to resolve Storybook evidence server address');
    }

    browser = await launchChrome();
    cdp = await connectCdp(browser.webSocketUrl);
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const results = [];
    for (const item of captures) {
      results.push(await captureStory(cdp, baseUrl, item));
    }

    const manifest = {
      ...criticPlan,
      sourceSha: process.env.GITHUB_SHA ?? null,
      chromeVersion,
      captures: results,
    };
    await writeFile(
      path.join(evidenceRoot, 'manifest.json'),
      `${JSON.stringify(manifest, null, 2)}\n`,
      'utf8',
    );
    console.log(`critic_evidence_count=${results.length}`);
  } finally {
    if (cdp) {
      cdp.socket.close();
    }
    if (browser) {
      await stopChrome(browser);
    }
    await new Promise((resolve) => server.close(() => resolve()));
  }
}

if (process.argv.includes('--print-plan')) {
  process.stdout.write(`${JSON.stringify(criticPlan)}\n`);
} else {
  await main();
}

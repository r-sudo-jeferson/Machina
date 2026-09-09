import {execFile, spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {mkdir, readFile, stat, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';

const execFileAsync = promisify(execFile);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const alloyRoot = path.resolve(scriptDir, '..');
const staticRoot = path.join(alloyRoot, 'storybook-static');
const evidenceRoot = path.join(alloyRoot, 'critic-evidence');
const chromeBinary = process.env.CHROME_BIN || 'google-chrome';

const captures = [
  {
    file: 'material-silver.png',
    storyId: 'alloy-material--silver-depth-matrix',
    globals: 'alloyTheme:silver',
  },
  {
    file: 'material-space-black.png',
    storyId: 'alloy-material--space-black-depth-matrix',
    globals: 'alloyTheme:space-black',
  },
  {
    file: 'button-focus-silver.png',
    storyId: 'alloy-controls--button-keyboard-focus',
    globals: 'alloyTheme:silver',
  },
  {
    file: 'button-loading-space-black.png',
    storyId: 'alloy-controls--button-loading',
    globals: 'alloyTheme:space-black',
  },
  {
    file: 'field-error-silver.png',
    storyId: 'alloy-controls--text-field-error',
    globals: 'alloyTheme:silver',
  },
  {
    file: 'switch-selected-space-black.png',
    storyId: 'alloy-controls--switch-selected',
    globals: 'alloyTheme:space-black',
  },
  {
    file: 'status-danger-silver.png',
    storyId: 'alloy-status--status-danger-denied',
    globals: 'alloyTheme:silver',
  },
  {
    file: 'status-ai-space-black.png',
    storyId: 'alloy-status--status-ai',
    globals: 'alloyTheme:space-black',
  },
];

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

function runProcess(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {stdio: 'inherit'});
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} exited with code ${code ?? 'null'} signal ${signal ?? 'none'}`));
    });
  });
}

async function assertStoryIdsExist() {
  const index = JSON.parse(await readFile(path.join(staticRoot, 'index.json'), 'utf8'));
  for (const capture of captures) {
    if (!index.entries?.[capture.storyId]) {
      throw new Error(`Storybook index does not contain ${capture.storyId}`);
    }
  }
}

async function captureStory(baseUrl, capture) {
  const url = new URL('/iframe.html', baseUrl);
  url.searchParams.set('id', capture.storyId);
  url.searchParams.set('viewMode', 'story');
  url.searchParams.set('globals', capture.globals);

  const output = path.join(evidenceRoot, capture.file);
  await runProcess(chromeBinary, [
    '--headless=new',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--hide-scrollbars',
    '--no-default-browser-check',
    '--no-first-run',
    '--run-all-compositor-stages-before-draw',
    '--force-device-scale-factor=1',
    '--window-size=1440,1080',
    '--virtual-time-budget=1500',
    `--screenshot=${output}`,
    url.href,
  ]);

  const fileStats = await stat(output);
  if (fileStats.size < 5000) {
    throw new Error(`${capture.file} is unexpectedly small (${fileStats.size} bytes)`);
  }

  return {
    ...capture,
    bytes: fileStats.size,
    url: url.href,
  };
}

const server = createServer(async (request, response) => {
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
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const results = [];
  for (const capture of captures) {
    results.push(await captureStory(baseUrl, capture));
  }

  const manifest = {
    schemaVersion: 1,
    sourceSha: process.env.GITHUB_SHA ?? null,
    chromeVersion,
    viewport: {width: 1440, height: 1080, deviceScaleFactor: 1},
    captures: results.map(({file, storyId, globals, bytes}) => ({file, storyId, globals, bytes})),
  };
  await writeFile(
    path.join(evidenceRoot, 'manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
    'utf8',
  );
  console.log(`critic_evidence_count=${results.length}`);
} finally {
  await new Promise((resolve) => server.close(() => resolve()));
}

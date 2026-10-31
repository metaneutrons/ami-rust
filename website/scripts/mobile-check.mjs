// Mobile layout gate: loads pages in headless Chrome with a phone viewport
// and fails when the page scrolls horizontally or when article content is cut
// off at the right edge. Starlight clips overflow inside its content pane, so
// content can be unreachable without the page ever scrolling; both are checked.
//
// usage: node scripts/mobile-check.mjs [DIST_DIR] [--shots DIR]
//
// Chrome is found through CHROME_BIN, then the usual install locations. The
// check drives Chrome over the DevTools protocol because the command-line
// screenshot mode enforces a minimum window width and so cannot emulate a
// narrow viewport. Every hand-written page is checked, plus a fixed sample of
// the generated reference.

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';

const websiteRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const args = process.argv.slice(2);
const shotsIndex = args.indexOf('--shots');
const shotsDirectory = shotsIndex >= 0 ? path.resolve(args.splice(shotsIndex, 2)[1]) : null;
const dist = path.resolve(args[0] ?? path.join(websiteRoot, 'dist'));
const VIEWPORT = { width: 390, height: 844 };
const REFERENCE_SAMPLE_STEP = 25;

const chromeCandidates = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser',
].filter(Boolean);
const chrome = chromeCandidates.find((candidate) => (candidate.includes('/')
  ? existsSync(candidate)
  : spawnSync('which', [candidate]).status === 0));
if (!chrome) {
  console.error('no Chrome found: set CHROME_BIN');
  process.exit(2);
}

const walk = (directory) => readdirSync(directory, { withFileTypes: true })
  .flatMap((entry) => (entry.isDirectory() ? walk(path.join(directory, entry.name)) : [path.join(directory, entry.name)]));
const urls = walk(dist).filter((file) => file.endsWith('/index.html'))
  .map((file) => `/${path.relative(dist, path.dirname(file)).split(path.sep).join('/')}/`.replace('//', '/'))
  .sort();
const selected = [
  ...urls.filter((url) => !url.startsWith('/reference/')),
  ...urls.filter((url) => url.startsWith('/reference/')).filter((_, index) => index % REFERENCE_SAMPLE_STEP === 0),
];

const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.webp': 'image/webp', '.json': 'application/json', '.xml': 'application/xml' };
const server = http.createServer((request, response) => {
  let file = path.join(dist, decodeURIComponent(request.url.split('?')[0]));
  if (existsSync(file) && statSync(file).isDirectory()) file = path.join(file, 'index.html');
  if (!file.startsWith(dist) || !existsSync(file)) { response.writeHead(404).end(); return; }
  response.writeHead(200, { 'content-type': types[path.extname(file)] ?? 'application/octet-stream' }).end(readFileSync(file));
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

const profile = path.join(process.env.TMPDIR ?? '/tmp', `ami-mobile-check-${process.pid}`);
const browser = spawn(chrome, [
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-sandbox', '--hide-scrollbars',
  `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
const endpoint = await new Promise((resolve, reject) => {
  let text = '';
  const timer = setTimeout(() => reject(new Error('Chrome did not start')), 20000);
  browser.stderr.on('data', (chunk) => {
    text += chunk;
    const match = /DevTools listening on (ws:\/\/\S+)/.exec(text);
    if (match) { clearTimeout(timer); resolve(match[1]); }
  });
});

const socket = new WebSocket(endpoint);
await new Promise((resolve) => socket.addEventListener('open', resolve, { once: true }));
let counter = 0;
const waiting = new Map();
const listeners = [];
socket.addEventListener('message', ({ data }) => {
  const message = JSON.parse(data);
  if (message.id && waiting.has(message.id)) {
    const { resolve, reject } = waiting.get(message.id);
    waiting.delete(message.id);
    message.error ? reject(new Error(message.error.message)) : resolve(message.result);
  } else listeners.forEach((listener) => listener(message));
});
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++counter;
  waiting.set(id, { resolve, reject });
  socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
});

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Page.enable', {}, sessionId);
await send('Emulation.setDeviceMetricsOverride', { ...VIEWPORT, deviceScaleFactor: 1, mobile: true }, sessionId);
if (shotsDirectory) mkdirSync(shotsDirectory, { recursive: true });

// Chrome widens the layout viewport of an emulated phone to fit overflowing
// content, so window.innerWidth cannot be trusted; compare with the fixed width.
const measure = `(() => {
  const width = ${VIEWPORT.width};
  const scrollWidth = document.documentElement.scrollWidth;
  // Only containers inside the article count: a table or code block that scrolls itself is fine,
  // a pane around the whole article scrolling sideways is not.
  const article = document.querySelector('.sl-markdown-content');
  const inScroller = (element) => {
    for (let node = element; node && node !== article; node = node.parentElement) {
      const x = getComputedStyle(node).overflowX;
      if (node !== element && (x === 'auto' || x === 'scroll')) return true;
      if (node === element && (x === 'auto' || x === 'scroll')) return true;
    }
    return false;
  };
  let worst = null;
  for (const element of document.querySelectorAll('.sl-markdown-content *, main h1')) {
    const box = element.getBoundingClientRect();
    if (box.width && box.right > width + 1 && !inScroller(element)) {
      if (!worst || box.right > worst.right) worst = { right: Math.round(box.right), tag: element.tagName.toLowerCase(), cls: String(element.className).slice(0, 60) };
    }
  }
  return { width, innerWidth: window.innerWidth, scrollWidth, worst, viewport: Boolean(document.querySelector('meta[name=viewport]')) };
})()`;

let failures = 0;
for (const url of selected) {
  const loaded = new Promise((resolve) => {
    const listener = (message) => { if (message.method === 'Page.loadEventFired' && message.sessionId === sessionId) { listeners.splice(listeners.indexOf(listener), 1); resolve(); } };
    listeners.push(listener);
  });
  await send('Page.navigate', { url: `${origin}${url}` }, sessionId);
  await loaded;
  await new Promise((resolve) => setTimeout(resolve, 150));
  const { result } = await send('Runtime.evaluate', { expression: measure, returnByValue: true }, sessionId);
  if (process.env.MOBILE_DEBUG) console.error(url, JSON.stringify(result.value));
  const { width, scrollWidth, worst, viewport } = result.value;
  if (!viewport) { failures += 1; console.error(`${url}: no viewport meta tag`); }
  if (scrollWidth > width + 1 || worst) {
    failures += 1;
    const detail = worst ? `an article element <${worst.tag} class="${worst.cls}"> reaches ${worst.right}px outside any scroller` : `the page scrolls horizontally (${scrollWidth}px)`;
    console.error(`${url}: content does not fit a ${width}px viewport: ${detail}`);
  }
  if (shotsDirectory) {
    const { data } = await send('Page.captureScreenshot', { format: 'png' }, sessionId);
    writeFileSync(path.join(shotsDirectory, `${url.replace(/\W+/g, '_')}.png`), Buffer.from(data, 'base64'));
  }
}

socket.close();
browser.kill();
server.close();
console.log(`mobile layout checked ${selected.length} pages at ${VIEWPORT.width}px (${urls.length} built); ${failures} problems`);
process.exit(failures ? 1 : 0);

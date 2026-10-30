// Accessibility gate: runs axe-core over the built site.
//
// usage: node scripts/a11y-check.mjs [DIST_DIR]      (default: website/dist)
//
// axe runs in jsdom, which has no layout engine, so colour contrast is not
// evaluated here; scripts/check-site.mjs checks the theme's contrast ratios
// from the design tokens. Every hand-written page is checked, plus a fixed
// sample of the generated reference.

import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { JSDOM, VirtualConsole } from 'jsdom';

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const websiteRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const dist = path.resolve(process.argv[2] ?? path.join(websiteRoot, 'dist'));
const REFERENCE_SAMPLE_STEP = 25;

const walk = (directory) => readdirSync(directory, { withFileTypes: true })
  .flatMap((entry) => (entry.isDirectory() ? walk(path.join(directory, entry.name)) : [path.join(directory, entry.name)]));

const pages = walk(dist).filter((file) => file.endsWith('index.html') || file.endsWith('404.html'))
  .map((file) => ({ file, url: `/${path.relative(dist, path.dirname(file)).split(path.sep).join('/')}/`.replace('//', '/') }))
  .sort((a, b) => a.url.localeCompare(b.url));
const selected = [
  ...pages.filter((page) => !page.url.startsWith('/reference/')),
  ...pages.filter((page) => page.url.startsWith('/reference/')).filter((_, index) => index % REFERENCE_SAMPLE_STEP === 0),
];

let violations = 0;
for (const page of selected) {
  const dom = new JSDOM(readFileSync(page.file, 'utf8'), { runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: new VirtualConsole() });
  dom.window.eval(axeSource);
  const result = await dom.window.axe.run(dom.window.document, {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] },
    rules: {
      'color-contrast': { enabled: false }, // needs layout; see check-site.mjs
      region: { enabled: false },
      // Starlight renders a mobile and a desktop table of contents and hides
      // one with CSS. jsdom has no CSS, so both look visible to axe.
      'landmark-unique': { enabled: false },
    },
  });
  for (const violation of result.violations) {
    violations += 1;
    console.error(`${page.url}: [${violation.impact}] ${violation.id}: ${violation.help} (${violation.nodes.length} node${violation.nodes.length === 1 ? '' : 's'})`);
    for (const node of violation.nodes.slice(0, 2)) console.error(`    ${node.html.slice(0, 140).replace(/\s+/g, ' ')}`);
  }
  dom.window.close();
}
console.log(`axe checked ${selected.length} pages (${pages.length} built); ${violations} violations`);
process.exit(violations ? 1 : 0);

// Validates the site composed by assemble-site.mjs.
//
// usage: node scripts/check-assembled.mjs SITE_DIR
//
// Per-version content is checked by check-site.mjs during assembly. This checks
// what only the composed site has: the layout, the version manifest, the
// metadata and switcher on every page, the canonical and noindex policy, and
// that each version's links stay inside it.

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

const websiteRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const site = path.resolve(process.argv[2] ?? '');
const SITE = 'https://ami-rust.metaneutrons.cc';
const errors = [];
const fail = (message) => errors.push(message);

if (!process.argv[2] || !existsSync(site)) {
  console.error('usage: check-assembled.mjs SITE_DIR');
  process.exit(2);
}
const walk = (directory) => readdirSync(directory, { withFileTypes: true })
  .flatMap((entry) => (entry.isDirectory() ? walk(path.join(directory, entry.name)) : [path.join(directory, entry.name)]));
const read = (file) => readFileSync(path.join(site, file), 'utf8');

/* ---------- manifest and layout ---------- */

let manifest;
try { manifest = JSON.parse(read('versions.json')); } catch { fail('versions.json is missing or not JSON'); }
const sources = JSON.parse(readFileSync(path.join(websiteRoot, 'versions.json'), 'utf8'));
if (manifest) {
  if (!manifest.versions?.some((entry) => entry.version === manifest.latest)) fail(`versions.json: latest ${manifest.latest} is not listed`);
  const listed = (manifest.versions ?? []).map((entry) => entry.version).sort().join(',');
  const wanted = sources.versions.map((entry) => entry.version).sort().join(',');
  if (listed !== wanted) fail(`versions.json lists ${listed}; website/versions.json lists ${wanted}`);
  if (manifest.latest !== sources.latest) fail(`versions.json latest ${manifest.latest} differs from website/versions.json ${sources.latest}`);
}
if (!existsSync(path.join(site, 'index.html'))) fail('the site root has no index.html (latest release)');
for (const entry of manifest?.versions ?? []) {
  if (!existsSync(path.join(site, `v${entry.version}`, 'index.html'))) fail(`/v${entry.version}/ is missing`);
}
if (manifest?.next && !existsSync(path.join(site, 'next', 'index.html'))) fail('/next/ is missing');
if (!existsSync(path.join(site, 'version-switcher.js'))) fail('version-switcher.js is missing');
else if (read('version-switcher.js') !== readFileSync(path.join(websiteRoot, 'scripts/version-switcher.js'), 'utf8')) fail('version-switcher.js differs from the repository copy');
if (!/^Disallow: \/next\/$/m.test(existsSync(path.join(site, 'robots.txt')) ? read('robots.txt') : '')) fail('robots.txt does not disallow /next/');
if (!existsSync(path.join(site, 'CNAME'))) fail('CNAME is missing from the site root');

/* ---------- every page ---------- */

const regions = [
  { prefix: '', version: manifest?.latest, channel: 'release', skip: (relative) => /^(v[^/]+|next)\//.test(relative) },
  ...(manifest?.versions ?? []).map((entry) => ({ prefix: `v${entry.version}`, version: entry.version, channel: 'release' })),
  ...(manifest?.next ? [{ prefix: 'next', version: 'next', channel: 'next' }] : []),
];
let pages = 0;
for (const region of regions) {
  const directory = path.join(site, region.prefix);
  if (!existsSync(directory)) continue;
  const base = region.prefix ? `/${region.prefix}` : '';
  for (const file of walk(directory).filter((candidate) => candidate.endsWith('.html'))) {
    const relative = path.relative(directory, file).split(path.sep).join('/');
    if (region.skip?.(relative)) continue;
    const html = readFileSync(file, 'utf8');
    const label = `${base}/${relative}`;
    pages += 1;
    const meta = (name) => new RegExp(`<meta name="${name}" content="([^"]*)"`).exec(html)?.[1];
    if (meta('docs-version') !== region.version) fail(`${label}: docs-version is ${meta('docs-version')}, expected ${region.version}`);
    if (meta('docs-base') !== base) fail(`${label}: docs-base is ${JSON.stringify(meta('docs-base'))}, expected ${JSON.stringify(base)}`);
    if (meta('docs-channel') !== region.channel) fail(`${label}: docs-channel is ${meta('docs-channel')}, expected ${region.channel}`);
    if (!html.includes('<script src="/version-switcher.js" defer></script>')) fail(`${label}: version switcher script missing`);
    const noindex = /<meta name="robots" content="noindex">/.test(html);
    if (region.channel === 'next' && !noindex) fail(`${label}: development docs are not marked noindex`);
    if (region.channel !== 'next' && noindex) fail(`${label}: a release page is marked noindex`);
    const canonical = /<link rel="canonical" href="([^"]*)"/.exec(html)?.[1];
    if (canonical) {
      const isLatestCopy = region.prefix === `v${manifest?.latest}`;
      const pathPart = relative === 'index.html' ? '/' : `/${relative.replace(/index\.html$/, '')}`;
      const expected = `${SITE}${isLatestCopy || !region.prefix ? '' : base}${pathPart}`;
      if (relative !== '404.html' && canonical !== expected) fail(`${label}: canonical ${canonical}, expected ${expected}`);
    }
    // A page must not link into another version through a hand-written root-relative path.
    if (base) {
      for (const match of html.matchAll(/<a\b[^>]*\bhref="(\/(?!\/)[^"]*)"/g)) {
        if (match[1] !== base && !match[1].startsWith(`${base}/`) && match[1] !== '/versions.json') fail(`${label}: link ${match[1]} escapes ${base}`);
      }
    }
  }
}

if (errors.length) {
  console.error(`ERROR (${errors.length})`);
  for (const message of errors.slice(0, 25)) console.error(`  ${message}`);
  if (errors.length > 25) console.error(`  … and ${errors.length - 25} more`);
}
console.log(`checked the assembled site: ${regions.length} regions, ${pages} pages; ${errors.length} errors`);
process.exit(errors.length ? 1 : 0);

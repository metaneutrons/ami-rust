// Structural quality gate for the built documentation site.
//
// usage: node scripts/check-site.mjs [DIST_DIR] [--base /v0.1.0] [--dist-only]
//        (default DIST_DIR: website/dist)
//
// --base       the site was built for publication under this path; every
//              root-relative link must carry it, so links written in Markdown
//              that were not rebased are reported
// --dist-only  check only the built files, not the repository sources (content
//              rules, pinned revision, theme contrast); for builds of another
//              git ref
//
// Errors fail the run; warnings are printed. The checks cover link and anchor
// integrity, the heading outline, page metadata, content rules for the
// hand-written pages, the pinned release revision, theme contrast and the
// presence of the files a published site needs.

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { JSDOM } from 'jsdom';

const websiteRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const repository = path.resolve(websiteRoot, '..');
const args = process.argv.slice(2);
const baseIndex = args.indexOf('--base');
const base = baseIndex >= 0 ? (args.splice(baseIndex, 2)[1] ?? '').replace(/\/$/, '') : '';
const distOnly = args.includes('--dist-only');
const dist = path.resolve(args.find((argument) => !argument.startsWith('--')) ?? path.join(websiteRoot, 'dist'));
const SITE = 'https://ami-rust.metaneutrons.cc';

const errors = [];
const warnings = [];
const fail = (check, message) => errors.push({ check, message });
const warn = (check, message) => warnings.push({ check, message });

const walk = (directory, predicate) => readdirSync(directory, { withFileTypes: true })
  .flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(full, predicate) : predicate(full) ? [full] : [];
  });

if (!existsSync(dist)) {
  console.error(`dist directory not found: ${dist}`);
  process.exit(2);
}

/* ---------- load pages ---------- */

const pages = new Map();
for (const file of walk(dist, (candidate) => candidate.endsWith('.html'))) {
  const relative = path.relative(dist, file).split(path.sep).join('/');
  const url = relative === 'index.html' ? '/' : `/${relative.replace(/index\.html$/, '')}`;
  pages.set(url, new JSDOM(readFileSync(file, 'utf8')).window.document);
}
const redirects = new Set([...pages].filter(([, document]) => document.querySelector('meta[http-equiv="refresh"]')).map(([url]) => url));

/* ---------- page structure and metadata ---------- */

const titles = new Map();
for (const [url, document] of pages) {
  if (url === '/404.html' || redirects.has(url)) continue;
  const label = url;
  const title = document.title?.trim();
  if (!title) fail('metadata', `${label}: empty <title>`);
  else titles.set(title, [...(titles.get(title) || []), url]);
  const description = document.querySelector('meta[name="description"]')?.getAttribute('content')?.trim();
  if (!description) fail('metadata', `${label}: missing meta description`);
  if (!document.documentElement.getAttribute('lang')) fail('metadata', `${label}: <html> has no lang`);
  if (!document.querySelector('link[rel="canonical"]')) warn('metadata', `${label}: no canonical link`);

  const headings = [...document.querySelectorAll('main h1, main h2, main h3, main h4, main h5, main h6')]
    .filter((heading) => !heading.closest('nav, aside'));
  const h1 = headings.filter((heading) => heading.tagName === 'H1').length;
  if (h1 !== 1) fail('headings', `${label}: ${h1} <h1> elements (expected exactly 1)`);
  let previous = 0;
  for (const heading of headings) {
    const level = Number(heading.tagName[1]);
    if (previous && level > previous + 1) {
      fail('headings', `${label}: heading level jumps from h${previous} to h${level} at "${heading.textContent.trim().slice(0, 50)}"`);
      break;
    }
    previous = level;
  }
  for (const image of document.querySelectorAll('img')) {
    if (!image.hasAttribute('alt')) fail('accessibility', `${label}: <img> without alt (${image.getAttribute('src')})`);
  }
  for (const link of document.querySelectorAll('a[href]')) {
    if (!link.textContent.trim() && !link.getAttribute('aria-label') && !link.querySelector('img[alt], svg title')) {
      fail('accessibility', `${label}: link with no accessible name (${link.getAttribute('href')})`);
    }
  }
}
for (const [title, urls] of titles) {
  if (urls.length > 1) fail('metadata', `duplicate title "${title}" on ${urls.slice(0, 3).join(', ')}${urls.length > 3 ? ` and ${urls.length - 3} more` : ''}`);
}

/* ---------- links and anchors ---------- */

const idsOf = new Map([...pages].map(([url, document]) => [url, new Set([...document.querySelectorAll('[id]')].map((element) => element.id))]));
const brokenTargets = new Map();
const brokenAnchors = new Map();
const external = new Set();
let linkCount = 0;
for (const [url, document] of pages) {
  if (redirects.has(url)) continue;
  for (const anchor of document.querySelectorAll('a[href]')) {
    const href = anchor.getAttribute('href').trim();
    linkCount += 1;
    if (!href || /^(mailto:|tel:|javascript:)/.test(href)) continue;
    if (href.startsWith(SITE)) { fail('links', `${url}: absolute link to this site (${href}); use a root-relative path`); continue; }
    if (/^https?:/.test(href)) { external.add(href); continue; }
    const [pathAndQuery, fragment] = href.split('#');
    let target;
    if (!pathAndQuery) target = url;
    else {
      let linkPath = pathAndQuery.split('?')[0];
      if (base && linkPath.startsWith('/')) {
        if (linkPath !== base && !linkPath.startsWith(`${base}/`)) {
          fail('links', `${url}: root-relative link ${href} does not carry the base ${base}`);
          continue;
        }
        linkPath = linkPath.slice(base.length) || '/';
      }
      target = new URL(linkPath, `${SITE}${url}`).pathname;
    }
    const withSlash = target.endsWith('/') ? target : `${target}/`;
    const isPage = pages.has(target) || pages.has(withSlash);
    const isFile = !isPage && existsSync(path.join(dist, decodeURIComponent(target))) && statSync(path.join(dist, decodeURIComponent(target))).isFile();
    if (!isPage && !isFile) {
      brokenTargets.set(href, [...(brokenTargets.get(href) || []), url]);
      continue;
    }
    if (fragment && isPage) {
      const ids = idsOf.get(pages.has(target) ? target : withSlash);
      if (!ids.has(decodeURIComponent(fragment))) brokenAnchors.set(`${target}#${fragment}`, [...(brokenAnchors.get(`${target}#${fragment}`) || []), url]);
    }
  }
}
for (const [href, sources] of brokenTargets) fail('links', `broken link ${href} (from ${sources[0]}${sources.length > 1 ? ` and ${sources.length - 1} more` : ''})`);
for (const [href, sources] of brokenAnchors) fail('links', `missing anchor ${href} (from ${sources[0]}${sources.length > 1 ? ` and ${sources.length - 1} more` : ''})`);

if (!distOnly) {
/* ---------- content rules for hand-written pages ---------- */

const docs = path.join(repository, 'docs');
const handWritten = [...walk(docs, (file) => /\.(md|mdx)$/.test(file))]
  .filter((file) => !file.includes(`${path.sep}reference${path.sep}`))
  .filter((file) => !/(m\d-|mui-hello-qualification|mui-safe-api|evidence|plans|^changelog\.md$)/.test(path.relative(docs, file)));

// Wording that must not appear in public pages.
const forbidden = [
  [/as part of this change/i, 'change-log wording'],
  [/\bM[1-7](?:-A\d)?\b/, 'internal milestone name'],
  [/\babi-?v0\b|\babiv0\b|\bABI0\b/i, 'unsupported ABI profile'],
  [/ami-rust\.metaneutrons\.cc/, 'absolute link to this site'],
  [/\bTODO\b|\bFIXME\b|lorem ipsum/i, 'placeholder text'],
];
for (const file of handWritten) {
  const text = readFileSync(file, 'utf8');
  for (const [pattern, reason] of forbidden) {
    const match = pattern.exec(text);
    if (match) fail('content', `${path.relative(repository, file)}: ${reason} ("${match[0]}")`);
  }
}

const referenceRoot = path.join(docs, 'reference');
if (existsSync(referenceRoot)) {
  for (const file of walk(referenceRoot, (candidate) => candidate.endsWith('.md'))) {
    let fenced = false;
    for (const [index, line] of readFileSync(file, 'utf8').split('\n').entries()) {
      if (/^\s*```/.test(line)) fenced = !fenced;
      if (fenced) continue;
      if (/\[`[^`\n]+`\](?![([:])/.test(line)) fail('reference', `${path.relative(repository, file)}:${index + 1}: unresolved intra-doc link in prose`);
    }
  }
}

/* ---------- pinned revision ---------- */

const version = readFileSync(path.join(repository, 'version.txt'), 'utf8').trim();
const pins = new Map();
for (const file of handWritten) {
  for (const match of readFileSync(file, 'utf8').matchAll(/\brev\s*=\s*"([0-9a-f]{40})"/g)) {
    pins.set(match[1], [...(pins.get(match[1]) || []), path.relative(repository, file)]);
  }
}
if (pins.size > 1) fail('release', `documentation pins ${pins.size} different revisions: ${[...pins.keys()].map((sha) => sha.slice(0, 12)).join(', ')}`);
try {
  const tagged = execFileSync('git', ['rev-parse', '--verify', `v${version}^{commit}`], { cwd: repository, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  for (const [sha, files] of pins) {
    if (sha !== tagged) fail('release', `${files[0]} pins ${sha.slice(0, 12)} but tag v${version} is ${tagged.slice(0, 12)}`);
  }
} catch {
  if (process.env.CI) fail('release', `tag v${version} is not available to verify the pinned revision (fetch tags in CI)`);
  else warn('release', `tag v${version} not found locally; pinned revision not verified`);
}

/* ---------- theme contrast ---------- */

const css = readFileSync(path.join(websiteRoot, 'src/styles/ami-rust.css'), 'utf8');
const tokens = (selector) => {
  const block = new RegExp(`${selector.replace(/[[\]'.]/g, '\\$&')}\\s*\\{([^}]*)\\}`).exec(css)?.[1] ?? '';
  return Object.fromEntries([...block.matchAll(/(--[\w-]+):\s*(#[0-9a-fA-F]{6})\b/g)].map((match) => [match[1], match[2]]));
};
const luminance = (hex) => {
  const channel = (offset) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
};
const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};
const dark = tokens(":root[data-theme='dark']");
const light = tokens(":root[data-theme='light']");
const pairs = [
  ['dark', 'secondary text', dark['--sl-color-gray-2'], dark['--sl-color-black']],
  ['dark', 'muted text', dark['--sl-color-gray-3'], dark['--sl-color-black']],
  ['dark', 'muted text on panel', dark['--sl-color-gray-3'], dark['--sl-color-gray-6']],
  ['dark', 'accent', dark['--sl-color-accent'], dark['--sl-color-black']],
  ['dark', 'highlight', dark['--ami-highlight'], dark['--sl-color-black']],
  ['light', 'accent on white', light['--sl-color-accent'], '#ffffff'],
  ['light', 'accent-high on accent-low', light['--sl-color-accent-high'], light['--sl-color-accent-low']],
  ['light', 'highlight on white', light['--ami-highlight'], '#ffffff'],
  ['light', 'button text on accent', '#ffffff', light['--sl-color-accent']],
];
for (const [theme, name, foreground, background] of pairs) {
  if (!foreground || !background) { fail('contrast', `${theme} ${name}: token missing in ami-rust.css`); continue; }
  const ratio = contrast(foreground, background);
  if (ratio < 4.5) fail('contrast', `${theme} ${name}: ${foreground} on ${background} is ${ratio.toFixed(2)}:1 (needs 4.5:1)`);
}

}

/* ---------- published files ---------- */

for (const required of ['404.html', 'sitemap-index.xml', 'robots.txt', 'social-card.png', 'CNAME', 'favicon.svg']) {
  if (!existsSync(path.join(dist, required))) fail('files', `missing ${required} in the built site`);
}
if (!existsSync(path.join(dist, 'pagefind'))) fail('files', 'search index (pagefind) is missing');

/* ---------- report ---------- */

const group = (items) => items.reduce((map, item) => map.set(item.check, [...(map.get(item.check) || []), item.message]), new Map());
for (const [check, messages] of group(warnings)) {
  console.log(`warning [${check}] (${messages.length})`);
  for (const message of messages.slice(0, 5)) console.log(`  ${message}`);
}
for (const [check, messages] of group(errors)) {
  console.error(`ERROR [${check}] (${messages.length})`);
  for (const message of messages.slice(0, 15)) console.error(`  ${message}`);
  if (messages.length > 15) console.error(`  … and ${messages.length - 15} more`);
}
console.log(`checked ${pages.size} pages, ${linkCount} links (${external.size} external, not fetched); ${errors.length} errors, ${warnings.length} warnings`);
process.exit(errors.length ? 1 : 0);

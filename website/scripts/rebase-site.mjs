// Post-processes a built site for publication under a version path.
//
// usage: node scripts/rebase-site.mjs DIST BASE --version VERSION --channel release|next [--latest]
//
// `astro build --base BASE` already prefixes everything Astro and Starlight
// generate (assets, navigation, search, canonical URLs). Links written by hand
// in Markdown are not touched by Astro, so this rewrites those, and then adds
// what every published version shares: the version metadata and the version
// switcher script, so even a version whose own sources predate the switcher
// shows it.

import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const SITE = 'https://ami-rust.metaneutrons.cc';
const SWITCHER = '/version-switcher.js';

const walk = (directory) => readdirSync(directory, { withFileTypes: true })
  .flatMap((entry) => (entry.isDirectory() ? walk(path.join(directory, entry.name)) : [path.join(directory, entry.name)]));

/**
 * @param {{dist: string, base: string, version: string, channel: 'release' | 'next', latest?: boolean}} options
 *   `base` is '' for the site root, otherwise '/v0.1.0' or '/next'.
 */
export function rebaseSite({ dist, base, version, channel, latest = false }) {
  const prefix = base.replace(/\/$/, '');
  const metadata = [
    `<meta name="docs-version" content="${version}">`,
    `<meta name="docs-base" content="${prefix}">`,
    `<meta name="docs-channel" content="${channel}">`,
    channel === 'next' ? '<meta name="robots" content="noindex">' : '',
  ].filter(Boolean).join('');
  let pages = 0;
  let rewritten = 0;

  for (const file of walk(dist).filter((candidate) => candidate.endsWith('.html'))) {
    let html = readFileSync(file, 'utf8');

    if (prefix) {
      html = html.replace(/<a\b[^>]*>/g, (tag) => tag.replace(/\bhref="(\/(?!\/)[^"]*)"/, (match, value) => {
        if (value === prefix || value.startsWith(`${prefix}/`)) return match;
        rewritten += 1;
        return `href="${prefix}${value}"`;
      }));
    }

    // A versioned copy of the latest release is the same content as the site
    // root; search engines should index the root.
    if (latest && prefix) {
      html = html.replace(new RegExp(`(<link rel="canonical" href="${SITE})${prefix}/`), '$1/')
        .replace(new RegExp(`(<meta property="og:url" content="${SITE})${prefix}/`), '$1/');
    }

    html = html.replace('</head>', `${metadata}</head>`)
      .replace(/<\/body>(?![\s\S]*<\/body>)/, `<script src="${SWITCHER}" defer></script></body>`);
    writeFileSync(file, html);
    pages += 1;
  }
  return { pages, rewritten };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const option = (name) => { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : undefined; };
  const [dist, base = ''] = args;
  const version = option('--version');
  const channel = option('--channel');
  if (!dist || !version || !['release', 'next'].includes(channel)) {
    console.error('usage: rebase-site.mjs DIST BASE --version VERSION --channel release|next [--latest]');
    process.exit(2);
  }
  const result = rebaseSite({ dist: path.resolve(dist), base: base === '/' ? '' : base, version, channel, latest: args.includes('--latest') });
  console.log(`rebased ${result.pages} pages (${result.rewritten} markdown links) for ${version}`);
}

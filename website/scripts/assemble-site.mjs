// Builds every documentation version and composes the published site.
//
// usage: node scripts/assemble-site.mjs --out DIR --host TRIPLE [--skip-install] [--only next|VERSION]
//
// Layout of DIR:
//   /            the latest release (website/versions.json "latest")
//   /v<version>/ every release listed in website/versions.json
//   /next/       the current checkout, the development docs
//   /versions.json, /version-switcher.js, /robots.txt
//
// The development docs are built from the checkout this script runs in. Each
// release is built from its own git ref, with that ref's own docs, crates and
// website sources, so a released version documents what that release shipped.
// Only the deployment layer (base path, version metadata and the switcher) comes
// from this checkout, which is why it is applied after each build.

import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { rebaseSite } from './rebase-site.mjs';

const websiteRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const repository = realpathSync(path.resolve(websiteRoot, '..'));
const args = process.argv.slice(2);
const option = (name) => { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : undefined; };
const output = option('--out') && path.resolve(option('--out'));
const host = option('--host');
const only = option('--only');
const skipInstall = args.includes('--skip-install');
if (!output || !host) {
  console.error('usage: assemble-site.mjs --out DIR --host TRIPLE [--skip-install] [--only next|VERSION]');
  process.exit(2);
}
if (output.startsWith(`${repository}${path.sep}`) || repository.startsWith(`${output}${path.sep}`)) {
  console.error('--out must be outside the repository');
  process.exit(2);
}

const manifest = JSON.parse(readFileSync(path.join(websiteRoot, 'versions.json'), 'utf8'));
if (!manifest.versions.some((entry) => entry.version === manifest.latest)) {
  console.error(`versions.json: latest ${manifest.latest} is not in versions`);
  process.exit(2);
}

const run = (command, commandArgs, options = {}) => {
  const result = spawnSync(command, commandArgs, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options });
  if (result.status !== 0) {
    console.error(`$ ${command} ${commandArgs.join(' ')}\n${result.stdout}\n${result.stderr}`);
    throw new Error(`${command} failed (${result.status})`);
  }
  return result.stdout;
};
const log = (message) => console.log(`[assemble] ${message}`);

const resolveRef = (ref) => {
  for (const candidate of [ref, `origin/${ref}`, `refs/tags/${ref}`]) {
    const result = spawnSync('git', ['rev-parse', '--verify', '--quiet', `${candidate}^{commit}`], { cwd: repository, encoding: 'utf8' });
    if (result.status === 0) return result.stdout.trim();
  }
  throw new Error(`git ref ${ref} not found; fetch it (CI checks out with fetch-depth 0)`);
};

const scratch = mkdtempSync(path.join(os.tmpdir(), 'ami-docs-assemble-'));
const builds = [];

/** Builds one checkout once per base path, validates each result and keeps it outside the checkout. */
function buildCheckout({ name, directory, channel, version, targets }) {
  const checkout = realpathSync(directory);
  const site = path.join(checkout, 'website');
  log(`${name}: install`);
  if (!skipInstall) run('pnpm', ['--dir', site, 'install', '--frozen-lockfile']);

  log(`${name}: generate the API reference`);
  rmSync(path.join(checkout, 'docs/reference'), { recursive: true, force: true });
  run('bash', [path.join(checkout, 'tools/generate-astro-api.sh'), path.join(scratch, `api-${name}`), path.join(checkout, 'docs/reference'), host], { cwd: checkout });
  if (existsSync(path.join(site, 'scripts/sync-changelog.mjs'))) run('node', ['scripts/sync-changelog.mjs'], { cwd: site });

  return targets.map(({ base, folder, latest }) => {
    log(`${name}: build ${base || '/'}`);
    // The build writes through the checkout's own cache, so build inside it and move the result out.
    const built = path.join(site, `.assembled-${folder || 'root'}`);
    rmSync(built, { recursive: true, force: true });
    run('pnpm', ['--dir', site, 'exec', 'astro', 'build', '--base', base || '/', '--outDir', built], {
      env: { ...process.env, DOCS_CHANNEL: channel },
    });
    const { pages, rewritten } = rebaseSite({ dist: built, base, version, channel, latest });
    log(`${name}: ${base || '/'}: ${pages} pages, ${rewritten} markdown links rebased`);
    run('node', [path.join(websiteRoot, 'scripts/check-site.mjs'), built, '--base', base, '--dist-only']);
    const kept = path.join(scratch, `out-${name}-${folder || 'root'}`);
    cpSync(built, kept, { recursive: true });
    rmSync(built, { recursive: true, force: true });
    return { name, base, folder, dist: kept };
  });
}

try {
  if (!only || only === 'next') {
    builds.push(...buildCheckout({
      name: 'next', directory: repository, channel: 'next', version: 'next',
      targets: [{ base: '/next', folder: 'next', latest: false }],
    }));
  }
  for (const entry of manifest.versions.filter((candidate) => !only || only === candidate.version)) {
    const commit = resolveRef(entry.ref);
    const worktree = path.join(scratch, `wt-${entry.version}`);
    log(`${entry.version}: ${entry.ref} at ${commit.slice(0, 12)}`);
    run('git', ['worktree', 'add', '--detach', worktree, commit], { cwd: repository });
    try {
      const isLatest = entry.version === manifest.latest;
      builds.push(...buildCheckout({
        name: entry.version, directory: worktree, channel: 'release', version: entry.version,
        targets: [
          { base: `/v${entry.version}`, folder: `v${entry.version}`, latest: isLatest },
          ...(isLatest ? [{ base: '', folder: '', latest: true }] : []),
        ],
      }));
    } finally {
      spawnSync('git', ['worktree', 'remove', '--force', worktree], { cwd: repository });
    }
  }

  rmSync(output, { recursive: true, force: true });
  mkdirSync(output, { recursive: true });
  const root = builds.find((build) => build.folder === '');
  if (root) cpSync(root.dist, output, { recursive: true });
  for (const build of builds.filter((candidate) => candidate.folder)) cpSync(build.dist, path.join(output, build.folder), { recursive: true });

  const published = {
    latest: manifest.latest,
    versions: manifest.versions.map(({ version }) => ({ version })),
    next: builds.some((build) => build.name === 'next'),
  };
  writeFileSync(path.join(output, 'versions.json'), `${JSON.stringify(published, null, 2)}\n`);
  cpSync(path.join(websiteRoot, 'scripts/version-switcher.js'), path.join(output, 'version-switcher.js'));
  writeFileSync(path.join(output, 'robots.txt'), 'User-agent: *\nAllow: /\nDisallow: /next/\n\nSitemap: https://ami-rust.metaneutrons.cc/sitemap-index.xml\n');
  log(`site assembled in ${output}`);
} finally {
  spawnSync('git', ['worktree', 'prune'], { cwd: repository });
  rmSync(scratch, { recursive: true, force: true });
}

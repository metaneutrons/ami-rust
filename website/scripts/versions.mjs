// Decides which documentation versions exist.
//
// The documentation of a release is built from that release's tag: the tag is
// immutable and contains the docs, examples and API reference that the release
// shipped. A version therefore exists when a `vMAJOR.MINOR.PATCH` tag has the
// website sources in its tree.
//
// There are two exceptions, both listed in website/versions.json with the git
// ref the documentation is built from and the reason.
//
// - "legacy": a release that predates the site, whose tag cannot be built. The
//   entry is rejected when the tag does build, or when there is no such release.
// - "corrections": a release whose tag builds but whose documentation has a
//   mistake. The documentation is then built from a branch that contains the tag
//   and differs from it only in documentation files, so the site never describes
//   anything that was not released. The entry is rejected when the branch lacks
//   the tag, changes any file outside the documentation, or does not exist.

import { spawnSync } from 'node:child_process';

const RELEASE_TAG = /^v(\d+)\.(\d+)\.(\d+)$/;
const SITE_MARKER = 'website/astro.config.mjs';
// The files a documentation correction may change.
export const DOCUMENTATION_PATH = /^(docs\/|website\/|README\.md$|CONTRIBUTING\.md$)/;

export const compareVersions = (a, b) => {
  const left = a.split('.').map(Number);
  const right = b.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return right[index] - left[index];
  }
  return 0;
};

const git = (repository, args) => spawnSync('git', args, { cwd: repository, encoding: 'utf8' });

export function resolveCommit(repository, ref) {
  for (const candidate of [ref, `origin/${ref}`]) {
    const result = git(repository, ['rev-parse', '--verify', '--quiet', `${candidate}^{commit}`]);
    if (result.status === 0) return result.stdout.trim();
  }
  return null;
}

/**
 * @returns {{latest: string | null, versions: {version: string, ref: string, commit: string, source: 'tag' | 'legacy' | 'corrected', tag?: string, reason?: string}[],
 *            notes: string[], problems: string[]}} versions newest first
 */
export function discoverVersions({ repository, manifest }) {
  const problems = [];
  const notes = [];
  const found = new Map();
  const withoutSite = new Set();

  const tags = git(repository, ['tag', '--list', 'v*']).stdout.split('\n').filter((tag) => RELEASE_TAG.test(tag));
  for (const tag of tags) {
    const version = tag.slice(1);
    const commit = git(repository, ['rev-parse', `${tag}^{commit}`]).stdout.trim();
    const hasSite = git(repository, ['cat-file', '-e', `${commit}:${SITE_MARKER}`]).status === 0;
    if (hasSite) found.set(version, { version, ref: tag, commit, source: 'tag' });
    else withoutSite.add(version);
  }

  for (const entry of manifest.legacy ?? []) {
    const label = `legacy ${entry.version}`;
    if (!/^\d+\.\d+\.\d+$/.test(entry.version ?? '')) { problems.push(`${label}: version must be MAJOR.MINOR.PATCH`); continue; }
    if (typeof entry.ref !== 'string' || !entry.ref) { problems.push(`${label}: ref is required`); continue; }
    if (typeof entry.reason !== 'string' || entry.reason.trim().length < 10) { problems.push(`${label}: say why the tag cannot be used (reason)`); continue; }
    if (found.has(entry.version)) {
      problems.push(`${label}: tag v${entry.version} contains the site sources, so its documentation is built from the tag; remove the legacy entry`);
    } else if (!withoutSite.has(entry.version)) {
      problems.push(`${label}: there is no release tag v${entry.version}; legacy entries are only for released versions`);
    } else {
      const commit = resolveCommit(repository, entry.ref);
      if (!commit) { problems.push(`${label}: git ref ${entry.ref} does not exist (fetch it; CI checks out with fetch-depth 0)`); continue; }
      found.set(entry.version, { version: entry.version, ref: entry.ref, commit, source: 'legacy', reason: entry.reason });
      withoutSite.delete(entry.version);
    }
  }
  for (const entry of manifest.corrections ?? []) {
    const label = `correction ${entry.version}`;
    if (!/^\d+\.\d+\.\d+$/.test(entry.version ?? '')) { problems.push(`${label}: version must be MAJOR.MINOR.PATCH`); continue; }
    if (typeof entry.ref !== 'string' || !entry.ref) { problems.push(`${label}: ref is required`); continue; }
    if (typeof entry.reason !== 'string' || entry.reason.trim().length < 10) { problems.push(`${label}: say what is corrected (reason)`); continue; }
    const release = found.get(entry.version);
    if (!release) {
      problems.push(`${label}: no release tag v${entry.version} contains the site sources; corrections are only for released versions whose tag builds (a release that predates the site is a legacy entry)`);
      continue;
    }
    if (release.source !== 'tag') { problems.push(`${label}: ${entry.version} is already built from ${release.ref}; give it one entry`); continue; }
    const commit = resolveCommit(repository, entry.ref);
    if (!commit) { problems.push(`${label}: git ref ${entry.ref} does not exist (fetch it; CI checks out with fetch-depth 0)`); continue; }
    if (git(repository, ['merge-base', '--is-ancestor', release.commit, commit]).status !== 0) {
      problems.push(`${label}: ${entry.ref} does not contain the release tag v${entry.version}`);
      continue;
    }
    const changed = git(repository, ['diff', '--name-only', release.commit, commit]).stdout.split('\n').filter(Boolean);
    const outside = changed.filter((file) => !DOCUMENTATION_PATH.test(file));
    if (outside.length) {
      problems.push(`${label}: ${entry.ref} changes files outside the documentation (${outside.slice(0, 5).join(', ')}${outside.length > 5 ? ', ...' : ''}); a correction may only change docs/, website/, README.md and CONTRIBUTING.md`);
      continue;
    }
    found.set(entry.version, { version: entry.version, ref: entry.ref, commit, source: 'corrected', tag: release.ref, reason: entry.reason });
  }
  for (const version of withoutSite) notes.push(`v${version} has no documentation: its tag predates the site and no legacy entry covers it`);

  const versions = [...found.values()].sort((a, b) => compareVersions(a.version, b.version));
  if (!versions.length) problems.push('no documented release: no release tag contains the site and there is no legacy entry');
  return { latest: versions[0]?.version ?? null, versions, notes, problems };
}

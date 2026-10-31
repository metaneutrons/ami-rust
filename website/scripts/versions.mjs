// Decides which documentation versions exist.
//
// The documentation of a release is built from that release's tag: the tag is
// immutable and contains the docs, examples and API reference that the release
// shipped. A version therefore exists when a `vMAJOR.MINOR.PATCH` tag has the
// website sources in its tree.
//
// The one exception is a release that predates the site, whose tag cannot be
// built. Such a release is listed under "legacy" in website/versions.json with
// the git ref its documentation is built from and the reason. A legacy entry is
// rejected when the tag does build, or when there is no such release.

import { spawnSync } from 'node:child_process';

const RELEASE_TAG = /^v(\d+)\.(\d+)\.(\d+)$/;
const SITE_MARKER = 'website/astro.config.mjs';

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
 * @returns {{latest: string | null, versions: {version: string, ref: string, commit: string, source: 'tag' | 'legacy', reason?: string}[],
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
  for (const version of withoutSite) notes.push(`v${version} has no documentation: its tag predates the site and no legacy entry covers it`);

  const versions = [...found.values()].sort((a, b) => compareVersions(a.version, b.version));
  if (!versions.length) problems.push('no documented release: no release tag contains the site and there is no legacy entry');
  return { latest: versions[0]?.version ?? null, versions, notes, problems };
}

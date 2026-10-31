// Tests for version discovery. Run with: node --test scripts/
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { compareVersions, discoverVersions } from './versions.mjs';

let repository;
const git = (...args) => {
  const result = spawnSync('git', args, { cwd: repository, encoding: 'utf8' });
  assert.equal(result.status, 0, `git ${args.join(' ')}: ${result.stderr}`);
  return result.stdout.trim();
};
const commit = (message, { site }) => {
  mkdirSync(path.join(repository, 'website'), { recursive: true });
  if (site) writeFileSync(path.join(repository, 'website/astro.config.mjs'), `// ${message}\n`);
  else writeFileSync(path.join(repository, 'notes.txt'), `${message}\n`);
  git('add', '-A');
  git('-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', message);
};

before(() => {
  repository = mkdtempSync(path.join(os.tmpdir(), 'versions-test-'));
  git('init', '-q', '-b', 'main');
  commit('release 0.1.0, before the site existed', { site: false });
  git('tag', 'v0.1.0');
  git('branch', 'release/0.1');
  commit('the site arrives', { site: true });
  commit('release 0.2.0', { site: true });
  git('tag', 'v0.2.0');
  commit('release 0.10.0', { site: true });
  git('tag', 'v0.10.0');
  git('tag', 'v0.11.0-rc1');
  git('tag', 'not-a-release');
});
after(() => rmSync(repository, { recursive: true, force: true }));

const legacy = { version: '0.1.0', ref: 'release/0.1', reason: 'The site was added after the 0.1.0 release.' };

describe('discoverVersions', () => {
  it('builds releases whose tag contains the site from the tag, newest first', () => {
    const result = discoverVersions({ repository, manifest: { legacy: [legacy] } });
    assert.deepEqual(result.problems, []);
    assert.deepEqual(result.versions.map((entry) => `${entry.version}:${entry.source}`), ['0.10.0:tag', '0.2.0:tag', '0.1.0:legacy']);
    assert.equal(result.latest, '0.10.0', 'versions compare numerically, not as text');
    assert.equal(result.versions[0].ref, 'v0.10.0');
    assert.equal(result.versions[2].ref, 'release/0.1');
  });

  it('ignores prerelease tags and tags that are not releases', () => {
    const result = discoverVersions({ repository, manifest: { legacy: [legacy] } });
    assert.ok(!result.versions.some((entry) => /rc|not-a/.test(entry.version)));
  });

  it('skips a release without the site and without a legacy entry, and says so', () => {
    const result = discoverVersions({ repository, manifest: {} });
    assert.deepEqual(result.versions.map((entry) => entry.version), ['0.10.0', '0.2.0']);
    assert.match(result.notes.join('\n'), /v0\.1\.0 has no documentation/);
    assert.deepEqual(result.problems, []);
  });

  it('rejects a legacy entry for a tag that has the site', () => {
    const result = discoverVersions({ repository, manifest: { legacy: [legacy, { ...legacy, version: '0.2.0' }] } });
    assert.match(result.problems.join('\n'), /legacy 0\.2\.0: tag v0\.2\.0 contains the site sources/);
  });

  it('rejects a legacy entry for a release that does not exist', () => {
    const result = discoverVersions({ repository, manifest: { legacy: [legacy, { ...legacy, version: '9.9.9' }] } });
    assert.match(result.problems.join('\n'), /legacy 9\.9\.9: there is no release tag v9\.9\.9/);
  });

  it('requires a reason and an existing ref', () => {
    assert.match(discoverVersions({ repository, manifest: { legacy: [{ ...legacy, reason: '' }] } }).problems.join('\n'), /say why the tag cannot be used/);
    assert.match(discoverVersions({ repository, manifest: { legacy: [{ ...legacy, ref: 'release/nope' }] } }).problems.join('\n'), /ref release\/nope does not exist/);
  });

  it('reports when nothing can be documented', () => {
    const empty = mkdtempSync(path.join(os.tmpdir(), 'versions-empty-'));
    spawnSync('git', ['init', '-q'], { cwd: empty });
    const result = discoverVersions({ repository: empty, manifest: {} });
    rmSync(empty, { recursive: true, force: true });
    assert.match(result.problems.join('\n'), /no documented release/);
    assert.equal(result.latest, null);
  });
});

describe('compareVersions', () => {
  it('orders newest first', () => {
    assert.deepEqual(['0.9.0', '0.10.0', '1.0.0', '0.1.2'].sort(compareVersions), ['1.0.0', '0.10.0', '0.9.0', '0.1.2']);
  });
});

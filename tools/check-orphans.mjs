#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Refuses test programs and scripts that nothing builds, runs or checks.
//
// A test program that cannot build, or a script that nothing calls, looks like
// coverage and is not. This check keeps them from accumulating:
//
// - Every program under tests/, examples/ and release/ (a directory with a
//   Cargo.toml) is listed in tests/programs.json, and everything listed exists.
//   The manifest names how each program is shown to work: the qualification
//   fixture, the applications that run on AROS, the compile-fail fixtures, the
//   host checks.
// - A program that is not finished yet may be listed under "in_development"
//   instead, with the open issue that owns it and the reason it cannot be run
//   by the matrix yet. It must still build with the current helper and version,
//   but the release evidence does not cover it. With --check-issues the owning
//   issue must still be open: when it is closed, the program is either finished
//   and moves to "applications", or it is deleted.
// - A program uses the current helper and the current version: its build script
//   calls `aros_native_build::prepare` and reads no environment variable of a
//   retired setup, and every `aros*` dependency is pinned to version.txt.
// - Nothing sits loose in tests/ or scripts/.
// - Every script in tools/ and release/ is used: a workflow runs it, another
//   script or the manifest names it, or it is a test that `node --test tools/`
//   runs. A line of a workflow that only lists a path filter does not count.
//
// With --evidence the check also reads docs/evidence/native-<version>.json, the
// evidence tools/native-matrix.mjs writes, and refuses a release whose evidence
// is missing, is for another version or source state, or does not cover every
// mode, application, compile-fail fixture and host check in the manifest with
// the expected result. The release workflow runs it with --evidence.
//
// usage: check-orphans.mjs [--evidence] [--check-issues] [--version X.Y.Z] [--repository DIR]
//
// The version defaults to version.txt; the release workflow passes the version
// it is about to publish. --check-issues reads the state of each owning issue
// with the GitHub CLI (`gh`), in the repository named by GITHUB_REPOSITORY when
// it is set.

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const SKIPPED = new Set(['node_modules', 'target', '.git', 'csdk-source']);
const SCRIPT = /\.(sh|mjs|jq)$/;
// A workflow line that only lists a path filter: `- 'tools/example.sh'`.
const PATH_FILTER = /^\s*-\s*'[^']*'\s*$/;

const walk = (directory, depth = Infinity) => {
  if (!existsSync(directory) || depth < 0) return [];
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (SKIPPED.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(full, depth - 1));
    else if (entry.isFile()) files.push(full);
  }
  return files;
};

const read = (file) => readFileSync(file, 'utf8');
const relative = (repository, file) => path.relative(repository, file).split(path.sep).join('/');

export const programDirectories = (repository) => {
  const found = [];
  for (const root of ['tests', 'examples', 'release']) {
    for (const file of walk(path.join(repository, root), 3)) {
      if (path.basename(file) === 'Cargo.toml') found.push(relative(repository, path.dirname(file)));
    }
  }
  return found.sort();
};

const ISSUE = /^#[1-9][0-9]*$/;

const developmentProblems = (manifest) => {
  const problems = [];
  const applications = new Set((manifest.applications ?? []).map((entry) => entry.path));
  const seen = new Set();
  for (const entry of manifest.in_development ?? []) {
    const label = `in_development entry ${JSON.stringify(entry.path ?? null)}`;
    if (typeof entry.path !== 'string' || !entry.path) { problems.push(`tests/programs.json: an in_development entry has no path`); continue; }
    if (!ISSUE.test(entry.issue ?? '')) problems.push(`tests/programs.json: ${label} needs the open issue that owns it, written like "#66"`);
    if (typeof entry.reason !== 'string' || entry.reason.trim().length < 10) problems.push(`tests/programs.json: ${label} needs a reason (at least ten characters) that says why it cannot be run by the matrix yet`);
    if (applications.has(entry.path)) problems.push(`tests/programs.json lists ${entry.path} as an application and as in development; it is one or the other`);
    if (seen.has(entry.path)) problems.push(`tests/programs.json lists ${entry.path} twice under in_development`);
    seen.add(entry.path);
  }
  return problems;
};

const programProblems = (repository, manifest, version) => {
  const problems = developmentProblems(manifest);
  const registered = new Set([
    manifest.fixture?.path,
    ...(manifest.applications ?? []).map((entry) => entry.path),
    ...(manifest.in_development ?? []).map((entry) => entry.path),
    manifest.compile_fail?.path,
  ].filter(Boolean));
  for (const directory of programDirectories(repository)) {
    if (!registered.has(directory)) {
      problems.push(`${directory} is a program that tests/programs.json does not list; list it and say how it is run, or delete it`);
    }
  }
  for (const directory of registered) {
    if (!existsSync(path.join(repository, directory, 'Cargo.toml'))) {
      problems.push(`tests/programs.json lists ${directory}, which has no Cargo.toml; remove the entry`);
    }
  }
  for (const directory of programDirectories(repository)) {
    const buildScript = path.join(repository, directory, 'build.rs');
    if (existsSync(buildScript)) {
      const text = read(buildScript);
      if (!text.includes('aros_native_build::prepare')) {
        problems.push(`${directory}/build.rs does not call aros_native_build::prepare, so it does not build with the current toolchain helper`);
      }
      const hook = /AMI_RUST_[A-Z0-9_]+/.exec(text);
      if (hook) problems.push(`${directory}/build.rs reads ${hook[0]}, a hook of a retired setup that nothing provides`);
    }
    const manifestText = read(path.join(repository, directory, 'Cargo.toml'));
    for (const match of manifestText.matchAll(/^(aros[a-z-]*)\s*=\s*\{[^}]*version\s*=\s*"=([^"]+)"/gm)) {
      if (match[2] !== version) problems.push(`${directory}/Cargo.toml pins ${match[1]} to =${match[2]}, but the version is ${version}`);
    }
  }
  const fixtureSources = manifest.fixture?.path
    ? walk(path.join(repository, manifest.fixture.path, 'src')).filter((file) => file.endsWith('.rs')).map(read).join('\n')
    : '';
  for (const mode of manifest.fixture?.modes ?? []) {
    if (!fixtureSources.includes(`"${mode.name}"`)) {
      problems.push(`tests/programs.json lists the fixture mode ${mode.name}, which ${manifest.fixture.path}/src does not implement`);
    }
  }
  return problems;
};

const looseProblems = (repository) => {
  const problems = [];
  for (const root of ['tests', 'scripts']) {
    const directory = path.join(repository, root);
    if (!existsSync(directory)) continue;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === 'programs.json' || entry.name === 'README.md') continue;
      if (root === 'scripts') {
        problems.push(`scripts/${entry.name}: scripts live in tools/, where this check can see who uses them`);
      } else if (entry.isFile()) {
        problems.push(`tests/${entry.name} is a loose file; a test program is a directory with a Cargo.toml listed in tests/programs.json`);
      } else if (!existsSync(path.join(directory, entry.name, 'Cargo.toml'))) {
        problems.push(`tests/${entry.name} is a directory without a program; delete it`);
      }
    }
  }
  return problems;
};

const scriptProblems = (repository, manifest) => {
  const problems = [];
  const scripts = [...walk(path.join(repository, 'tools')), ...walk(path.join(repository, 'release'))]
    .filter((file) => SCRIPT.test(file))
    .map((file) => relative(repository, file));
  const workflowLines = walk(path.join(repository, '.github'))
    .flatMap((file) => read(file).split('\n'))
    .filter((line) => !PATH_FILTER.test(line));
  const workflowText = workflowLines.join('\n');
  const manifestText = JSON.stringify(manifest);
  const others = (self) => scripts.filter((file) => file !== self).map((file) => read(path.join(repository, file))).join('\n');

  for (const script of scripts) {
    const name = path.basename(script);
    if (name.endsWith('.test.mjs')) {
      const subject = path.join(repository, path.dirname(script), name.replace('.test.mjs', '.mjs'));
      if (!existsSync(subject)) problems.push(`${script} tests ${path.relative(repository, subject)}, which does not exist`);
      if (!workflowText.includes('node --test tools/')) problems.push(`${script} is never run: no workflow runs \`node --test tools/\``);
      continue;
    }
    const used = workflowText.includes(name) || manifestText.includes(script) || others(script).includes(name);
    if (!used) {
      problems.push(`${script} is not used: no workflow runs it, no other script calls it and tests/programs.json does not name it; wire it into CI or delete it`);
    }
  }
  return problems;
};

const evidenceProblems = (repository, manifest, version) => {
  const file = path.join(repository, 'docs/evidence', `native-${version}.json`);
  if (!existsSync(file)) {
    return [`there is no native evidence for ${version}: run tools/native-matrix.mjs and commit docs/evidence/native-${version}.json`];
  }
  const evidence = JSON.parse(read(file));
  const name = `docs/evidence/native-${version}.json`;
  const problems = [];
  if (evidence.schema !== 'ami-rust-native-evidence-v1') problems.push(`${name}: unknown schema`);
  if (evidence.version !== version) problems.push(`${name} is for ${evidence.version}, not ${version}`);
  if (evidence.source_clean !== true) problems.push(`${name} was produced from a source tree with uncommitted changes`);

  const abis = ['abi1', 'abi11'];
  const known = new Set();
  for (const abi of abis) {
    for (const mode of manifest.fixture.modes) {
      if (mode.abis && !mode.abis.includes(abi)) continue;
      known.add(`${abi} ${mode.name}`);
      const row = (evidence.fixture ?? []).find((entry) => entry.abi === abi && entry.mode === mode.name);
      if (!row) problems.push(`${name}: no result for fixture mode ${mode.name} on ${abi}`);
      else if (row.return_code !== 0) problems.push(`${name}: fixture mode ${mode.name} on ${abi} returned ${row.return_code}`);
    }
  }
  for (const row of evidence.fixture ?? []) {
    if (!known.has(`${row.abi} ${row.mode}`)) problems.push(`${name}: stale result for fixture mode ${row.mode} on ${row.abi}, which the manifest does not list`);
  }

  const applications = new Set();
  for (const abi of abis) {
    for (const application of manifest.applications) {
      applications.add(`${abi} ${application.path}`);
      const row = (evidence.applications ?? []).find((entry) => entry.abi === abi && entry.path === application.path);
      if (!row) { problems.push(`${name}: no result for ${application.path} on ${abi}`); continue; }
      if (application.expected_return_code === null) {
        if (row.return_code !== null || typeof row.screenshot_sha256 !== 'string') {
          problems.push(`${name}: ${application.path} on ${abi} needs a screendump and no return code`);
        }
      } else if (row.return_code !== application.expected_return_code) {
        problems.push(`${name}: ${application.path} on ${abi} returned ${row.return_code}, expected ${application.expected_return_code}`);
      }
    }
  }
  for (const row of evidence.applications ?? []) {
    if (!applications.has(`${row.abi} ${row.path}`)) problems.push(`${name}: stale result for ${row.path} on ${row.abi}, which the manifest does not list`);
  }

  for (const { bin, expected } of manifest.compile_fail.fixtures) {
    const row = (evidence.compile_fail ?? []).find((entry) => entry.bin === bin);
    if (!row) problems.push(`${name}: no compile-fail result for ${bin}`);
    else if (expected === null && row.built !== true) problems.push(`${name}: compile-fail fixture ${bin} must build and does not`);
    else if (expected !== null && (row.built !== false || !String(row.error).includes(expected))) {
      problems.push(`${name}: compile-fail fixture ${bin} must be refused with "${expected}", got ${row.built ? 'a successful build' : JSON.stringify(row.error)}`);
    }
  }
  for (const row of evidence.compile_fail ?? []) {
    if (!manifest.compile_fail.fixtures.some((entry) => entry.bin === row.bin)) problems.push(`${name}: stale compile-fail result for ${row.bin}`);
  }

  for (const check of manifest.host_checks) {
    const row = (evidence.host_checks ?? []).find((entry) => entry.name === check.name);
    if (!row) problems.push(`${name}: no result for the host check ${check.name}`);
    else if (row.status !== 'pass') problems.push(`${name}: the host check ${check.name} did not pass`);
  }
  for (const row of evidence.host_checks ?? []) {
    if (!manifest.host_checks.some((entry) => entry.name === row.name)) problems.push(`${name}: stale result for the host check ${row.name}`);
  }
  return problems;
};

// The state of an issue as the GitHub CLI reports it: 'open', 'closed' or, when it
// cannot be read, 'unknown'.
export const issueStateFromGitHub = (number) => {
  const repo = process.env.GITHUB_REPOSITORY ? ['--repo', process.env.GITHUB_REPOSITORY] : [];
  const result = spawnSync('gh', ['issue', 'view', String(number), ...repo, '--json', 'state', '--jq', '.state'], { encoding: 'utf8' });
  if (result.status !== 0) return 'unknown';
  return result.stdout.trim().toLowerCase();
};

const issueProblems = (manifest, issueState) => {
  const problems = [];
  for (const entry of manifest.in_development ?? []) {
    if (!ISSUE.test(entry.issue ?? '')) continue;
    const state = issueState(Number(entry.issue.slice(1)));
    if (state === 'open') continue;
    if (state === 'closed') {
      problems.push(`${entry.path} is in development under ${entry.issue}, which is closed; finish it and move it to "applications", or delete it`);
    } else {
      problems.push(`could not read the state of ${entry.issue}, the owner of ${entry.path}; check that \`gh\` works and that the issue exists`);
    }
  }
  return problems;
};

export const check = ({ repository, evidence = false, version: requested, issueState }) => {
  const manifestFile = path.join(repository, 'tests/programs.json');
  if (!existsSync(manifestFile)) return ['tests/programs.json is missing'];
  const manifest = JSON.parse(read(manifestFile));
  const version = requested ?? read(path.join(repository, 'version.txt')).trim();
  const problems = [
    ...programProblems(repository, manifest, version),
    ...looseProblems(repository),
    ...scriptProblems(repository, manifest),
  ];
  for (const entry of manifest.host_checks ?? []) {
    if (!existsSync(path.join(repository, entry.script))) problems.push(`tests/programs.json lists the host check ${entry.name}, but ${entry.script} does not exist`);
  }
  if (manifest.evidence?.produced_by && !existsSync(path.join(repository, manifest.evidence.produced_by))) {
    problems.push(`tests/programs.json names ${manifest.evidence.produced_by} as the producer of the evidence, and it does not exist`);
  }
  if (issueState) problems.push(...issueProblems(manifest, issueState));
  if (evidence) problems.push(...evidenceProblems(repository, manifest, version));
  return problems;
};

const main = () => {
  const argv = process.argv.slice(2);
  const at = argv.indexOf('--repository');
  const repository = path.resolve(at < 0 ? path.join(path.dirname(new URL(import.meta.url).pathname), '..') : argv[at + 1]);
  const evidence = argv.includes('--evidence');
  const versionAt = argv.indexOf('--version');
  const problems = check({
    repository, evidence,
    version: versionAt < 0 ? undefined : argv[versionAt + 1],
    issueState: argv.includes('--check-issues') ? issueStateFromGitHub : undefined,
  });
  if (problems.length) {
    console.error(`orphan check: ${problems.length} problem${problems.length > 1 ? 's' : ''}\n${problems.map((problem) => `  - ${problem}`).join('\n')}`);
    process.exit(1);
  }
  console.log(`orphan check: every test program and script is used${evidence ? ', and the native evidence covers all of them' : ''}`);
};

if (process.argv[1] && path.resolve(process.argv[1]) === new URL(import.meta.url).pathname && statSync(process.argv[1]).isFile()) main();

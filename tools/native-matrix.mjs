#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Runs every test program listed in tests/programs.json with an installed
// ami-rust toolchain and writes the native evidence of a release,
// docs/evidence/native-<version>.json.
//
// - The qualification fixture is built for each ABI and every mode runs in a
//   boot of its own, after the mode `files`, as the fixture expects.
// - Each application is built for each ABI and run once. An application with a
//   `run` block in the manifest runs every mode in a boot of its own: with its set-up
//   (stack, working directory, clock), its expected return code and the lines that
//   its output must contain (see runModes).
// - Each compile-fail fixture is built; the one that must build does, and each
//   of the others must be refused with the error the manifest names.
// - The host checks run (see tools/check-mui-layout.mjs).
//
// `tools/check-orphans.mjs --evidence` refuses a release whose file does not cover
// everything in the manifest.
//
// The programs run on AROS inside an emulator. The runner is not part of this
// repository: AMI_RUST_NATIVE_RUNNER (or --runner) names an executable with the
// interface `run-on-aros [--timeout SECONDS] [--rtc SPEC] [--add FILE=NAME] --script FILE
// ABI BINARY`, which prints `OUT=DIRECTORY`; the directory has `serial.log` and
// `screen.png`. A boot that dies in the kernel before the script finishes is
// repeated up to three times and the attempts are recorded.
//
// usage: native-matrix.mjs --toolchain NAME [--runner PATH] [--output FILE]
//          [--work DIR] [--only fixture,applications,compile-fail,host-checks]
//          [--application PATH,...] [--abi1-source CHECKOUT --abi11-source CHECKOUT --abi11-sdk INCLUDE_DIR]
//
// With --only the other groups of an existing output file are kept.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const repository = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const ABIS = ['abi1', 'abi11'];
const GROUPS = ['fixture', 'applications', 'compile-fail', 'host-checks'];
const ATTEMPTS = 3;

const sha256 = (file) => (existsSync(file) ? createHash('sha256').update(readFileSync(file)).digest('hex') : null);

export const packageName = (manifestPath) => {
  const text = readFileSync(manifestPath, 'utf8');
  const match = /^\[package\][^[]*?^name\s*=\s*"([^"]+)"/ms.exec(text);
  if (!match) throw new Error(`${manifestPath}: no package name`);
  return match[1];
};

const options = () => {
  const argv = process.argv.slice(2);
  const value = (name) => { const at = argv.indexOf(name); return at < 0 ? undefined : argv[at + 1]; };
  const version = readFileSync(path.join(repository, 'version.txt'), 'utf8').trim();
  const only = value('--only')?.split(',') ?? GROUPS;
  const applications = value('--application')?.split(',');
  const unknown = only.filter((group) => !GROUPS.includes(group));
  const toolchain = value('--toolchain');
  const runner = value('--runner') ?? process.env.AMI_RUST_NATIVE_RUNNER;
  if (!toolchain || unknown.length || (only.some((g) => g === 'fixture' || g === 'applications') && !runner)) {
    console.error(`usage: native-matrix.mjs --toolchain NAME [--runner PATH] [--output FILE] [--work DIR] [--only ${GROUPS.join(',')}]
          [--abi1-source CHECKOUT --abi11-source CHECKOUT --abi11-sdk INCLUDE_DIR]
The native groups need a runner: --runner or AMI_RUST_NATIVE_RUNNER.`);
    process.exit(2);
  }
  return {
    version, toolchain, runner, only, applications,
    output: path.resolve(value('--output') ?? path.join(repository, `docs/evidence/native-${version}.json`)),
    work: path.resolve(value('--work') ?? mkdtempSync(path.join(tmpdir(), 'ami-rust-native-matrix-'))),
    mui: { abi1Source: value('--abi1-source'), abi11Source: value('--abi11-source'), abi11Sdk: value('--abi11-sdk') },
  };
};

const build = ({ toolchain, work }, directory, abi, extra = []) => {
  const target = `x86_64-unknown-aros-${abi}`;
  const targetDirectory = path.join(work, 'target');
  const result = spawnSync('cargo', [`+${toolchain}`, 'build', '--release', '--locked', '--offline', '--target', target, ...extra], {
    cwd: path.join(repository, directory), encoding: 'utf8',
    env: { ...process.env, CARGO_TARGET_DIR: targetDirectory, CARGO_BUILD_RUSTC_WRAPPER: '' },
  });
  const binary = path.join(targetDirectory, target, 'release', packageName(path.join(repository, directory, 'Cargo.toml')));
  if (result.status !== 0 || !existsSync(binary)) {
    throw new Error(`${directory} (${abi}) does not build:\n${(result.stderr || '').split('\n').filter((l) => /^error/.test(l)).slice(0, 3).join('\n')}`);
  }
  return binary;
};

// The AmigaDOS script of one boot. The default set-up is the one of the fixture: no
// `Stack` on ABI-v1, 1000000 on ABI-v11. A program with a set-up of its own names the
// stack (ABI-v1 accepts exactly 131072 for a `std` program), the directory it starts in
// (`cwd`, made first) and the lines to run.
export const bootScript = ({ abi, stack, cwd, lines }) => {
  const stackLine = stack !== undefined ? [`Stack ${stack}`] : abi === 'abi11' ? ['Stack 1000000'] : [];
  return `${[...stackLine, 'MakeDir RAM:ami-rust-m1', ...(cwd ? [`CD ${cwd}`] : []), ...lines].join('\n')}\n`;
};

// What the guest printed between NR-BEGIN and NR-END, without control characters.
export const guestOutput = (serial) => {
  const begin = serial.lastIndexOf('NR-BEGIN');
  if (begin < 0) return '';
  const end = serial.indexOf('NR-END', begin);
  return serial.slice(begin + 'NR-BEGIN'.length, end < 0 ? undefined : end).replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').replace(/[^\t\n\x20-\x7e]/g, '').replace(/^\n+/, '');
};

// Judges the output of a mode. Every string in `expect` must appear; a line that starts
// with `RESULT` and carries the word FAIL fails the mode unless `allowFail` says that it
// is expected. Returns the problems, empty when the output is as expected.
export const outputProblems = (output, { expect = [], pattern = [], allowFail = false } = {}) => {
  const problems = [
    ...expect.filter((text) => !output.includes(text)).map((text) => `missing: ${text}`),
    ...pattern.filter((source) => !new RegExp(source, 'm').test(output)).map((source) => `no match: /${source}/`),
  ];
  if (!allowFail) {
    for (const line of output.split('\n')) {
      if (/^RESULT\b/.test(line) && /\bFAIL\b|OUT-OF-RANGE/.test(line)) problems.push(`failed: ${line.trim()}`);
    }
  }
  return problems;
};

// One boot. Returns the return code printed by `marker`, or null when none was.
const boot = ({ runner, work }, { abi, binary, lines, marker, add = [], stack, cwd, rtc, timeout = 150 }) => {
  let attempts = 0;
  let outDirectory;
  let returnCode = null;
  let timedOut = false;
  let output = '';
  while (attempts < ATTEMPTS) {
    attempts += 1;
    const script = path.join(work, 'boot.script');
    writeFileSync(script, bootScript({ abi, stack, cwd, lines }));
    const run = spawnSync(runner, ['--timeout', String(timeout), ...(rtc ? ['--rtc', rtc] : []), ...add.flatMap((entry) => ['--add', entry]), '--script', script, abi, binary], { encoding: 'utf8' });
    timedOut = run.status === 124;
    outDirectory = /^OUT=(.*)$/m.exec(`${run.stdout}${run.stderr}`)?.[1];
    const serial = outDirectory && existsSync(path.join(outDirectory, 'serial.log')) ? readFileSync(path.join(outDirectory, 'serial.log'), 'latin1') : '';
    output = guestOutput(serial);
    const code = new RegExp(`${marker}=(-?\\d+)`, 'g');
    const hits = [...serial.matchAll(code)];
    if (hits.length) { returnCode = Number(hits.at(-1)[1]); break; }
    if (!/Kernel.*Exception/.test(serial)) break;
  }
  const serialLog = outDirectory ? path.join(outDirectory, 'serial.log') : null;
  const failures = serialLog && existsSync(serialLog)
    ? readFileSync(serialLog, 'latin1').split('\n').filter((line) => line.includes('qualification-failure')).slice(0, 2).join('; ')
    : '';
  return {
    returnCode, attempts, timedOut, output, serialSha: serialLog ? sha256(serialLog) : null,
    screenshotSha: outDirectory ? sha256(path.join(outDirectory, 'screen.png')) : null, failures,
  };
};

const runFixture = (context) => {
  const manifest = JSON.parse(readFileSync(path.join(repository, 'tests/programs.json'), 'utf8'));
  const catalog = path.join(repository, manifest.fixture.path, 'fixtures/Catalogs/deutsch/ami-rust-m8.catalog');
  const rows = [];
  for (const abi of ABIS) {
    const binary = build(context, manifest.fixture.path, abi);
    for (const mode of manifest.fixture.modes) {
      if (mode.abis && !mode.abis.includes(abi)) continue;
      const argumentText = (mode.arguments ?? mode.name).replace('{ABI}', abi.toUpperCase());
      const lines = [
        ...(mode.name === 'files' ? [] : ['NATIVERUN:prog files >NRDBG:']),
        `NATIVERUN:prog ${argumentText} >NRDBG:`,
        `Echo "MODE-${mode.name}-RC=$RC" >NRDBG:`,
      ];
      const result = boot(context, {
        abi, binary, lines, marker: `MODE-${mode.name}-RC`,
        add: mode.catalog ? [`${catalog}=Catalogs/deutsch/ami-rust-m8.catalog`] : [],
      });
      rows.push({ abi, mode: mode.name, return_code: result.returnCode, attempts: result.attempts, binary_sha256: sha256(binary), serial_log_sha256: result.serialSha, ...(result.failures ? { failure: result.failures } : {}) });
      console.log(`fixture ${abi} ${mode.name}: ${result.returnCode ?? 'no return code'} (${result.attempts} boot${result.attempts > 1 ? 's' : ''})`);
    }
  }
  return rows;
};

// The modes of an application with a `run` block: one boot per mode and ABI. The set-up
// (`stack`, `cwd`, `rtc`) is the block's, a mode may name its own `rtc`. A mode passes when
// its return code is `expected_return_code`, its output has every string of `expect`, matches
// every regular expression of `expect_pattern` and has no RESULT line that says FAIL (unless
// `allow_fail`). `before` lists shell lines that run first, `{host-seconds}` in `arguments` is the
// host's Unix time. A mode with `expect_timeout` passes when the boot ran into its timeout (a
// mode that waits for a person by design).
export const modeRows = (context, application, abi, binary) => {
  const { run } = application;
  return run.modes.filter((mode) => !mode.abis || mode.abis.includes(abi)).map((mode) => {
    const marker = `MODE-${mode.name}-RC`;
    const result = boot(context, {
      abi, binary, marker, stack: run.stack, cwd: run.cwd, rtc: mode.rtc ?? run.rtc,
      timeout: mode.timeout ?? run.timeout,
      lines: [...(mode.before ?? []), `NATIVERUN:prog ${(mode.arguments ?? mode.name).replace('{host-seconds}', () => String(Math.floor(Date.now() / 1000)))} >NRDBG:`, `Echo "${marker}=$RC" >NRDBG:`],
    });
    const problems = mode.expect_timeout
      ? (result.timedOut ? [] : ['the mode was expected to wait and ended'])
      : [
        ...(result.returnCode === mode.expected_return_code ? [] : [`return code ${result.returnCode ?? 'none'}, expected ${mode.expected_return_code}`]),
        ...outputProblems(result.output, { expect: mode.expect, pattern: mode.expect_pattern, allowFail: mode.allow_fail }),
      ];
    console.log(`application ${abi} ${application.path} ${mode.name}: ${mode.expect_timeout ? (result.timedOut ? 'timeout (expected)' : 'ended') : (result.returnCode ?? 'no return code')} ${problems.length ? `PROBLEM ${problems[0]}` : 'ok'}`);
    return {
      abi, path: application.path, mode: mode.name, return_code: result.returnCode, attempts: result.attempts,
      timed_out: result.timedOut, output_matched: problems.length === 0, ...(problems.length ? { problems: problems.slice(0, 3) } : {}),
      binary_sha256: sha256(binary), serial_log_sha256: result.serialSha,
      output_sha256: createHash('sha256').update(result.output).digest('hex'), output_tail: result.output.slice(-400),
    };
  });
};

const runApplications = (context) => {
  const manifest = JSON.parse(readFileSync(path.join(repository, 'tests/programs.json'), 'utf8'));
  const rows = [];
  for (const abi of ABIS) {
    for (const application of manifest.applications) {
      if (context.applications && !context.applications.includes(application.path)) continue;
      const binary = build(context, application.path, abi);
      if (application.run) { rows.push(...modeRows(context, application, abi, binary)); continue; }
      const result = boot(context, { abi, binary, marker: 'APP-RC', lines: ['NATIVERUN:prog >NRDBG:', 'Echo "APP-RC=$RC" >NRDBG:'] });
      rows.push({
        abi, path: application.path, return_code: result.returnCode, attempts: result.attempts, binary_sha256: sha256(binary),
        serial_log_sha256: result.serialSha, ...(application.expected_return_code === null ? { screenshot_sha256: result.screenshotSha } : {}),
      });
      console.log(`application ${abi} ${application.path}: ${result.returnCode ?? 'no return code'}`);
    }
  }
  return rows;
};

const runCompileFail = ({ toolchain, work }) => {
  const manifest = JSON.parse(readFileSync(path.join(repository, 'tests/programs.json'), 'utf8')).compile_fail;
  return manifest.fixtures.map(({ bin }) => {
    const result = spawnSync('cargo', [`+${toolchain}`, 'check', '--offline', '--locked', '--target', manifest.target, '--bin', bin], {
      cwd: path.join(repository, manifest.path), encoding: 'utf8',
      env: { ...process.env, CARGO_TARGET_DIR: path.join(work, 'compile-fail-target'), CARGO_BUILD_RUSTC_WRAPPER: '' },
    });
    const error = result.status === 0 ? null : (result.stderr.split('\n').find((line) => /^error/.test(line)) ?? 'build failed');
    console.log(`compile-fail ${bin}: ${error ?? 'builds'}`);
    return { bin, built: result.status === 0, error };
  });
};

// A host check names a script and its arguments. In the arguments {work} is a
// fresh directory of the check, {toolchain} the toolchain and {abi1-source},
// {abi11-source} and {abi11-sdk} the options of the same name. Anything else is
// passed as it is.
export const resolveArguments = (template, values) => template.map((argument) => {
  const placeholder = /^\{([a-z0-9-]+)\}$/.exec(argument);
  if (!placeholder) return argument;
  const value = values[placeholder[1]];
  if (value === undefined) throw new Error(`a host check needs the option --${placeholder[1]}`);
  return value;
});

const runHostChecks = ({ toolchain, work, mui }) => {
  const manifest = JSON.parse(readFileSync(path.join(repository, 'tests/programs.json'), 'utf8'));
  return manifest.host_checks.map(({ name, script, arguments: template }) => {
    const resolved = resolveArguments(template, {
      work: path.join(work, name), toolchain, 'abi1-source': mui.abi1Source, 'abi11-source': mui.abi11Source, 'abi11-sdk': mui.abi11Sdk,
    });
    const result = spawnSync('node', [path.join(repository, script), ...resolved], { encoding: 'utf8' });
    console.log(`host check ${name}: ${result.status === 0 ? 'pass' : 'FAIL'}`);
    return { name, status: result.status === 0 ? 'pass' : 'fail', output: `${result.stdout}${result.stderr}`.trim().slice(-2000) };
  });
};

const main = () => {
  const context = options();
  mkdirSync(context.work, { recursive: true });
  const evidence = existsSync(context.output) ? JSON.parse(readFileSync(context.output, 'utf8')) : {};
  const git = (...args) => spawnSync('git', ['-C', repository, ...args], { encoding: 'utf8' }).stdout.trim();
  Object.assign(evidence, {
    schema: 'ami-rust-native-evidence-v1',
    version: context.version,
    toolchain: context.toolchain,
    source_commit: git('rev-parse', 'HEAD'),
    source_clean: git('status', '--porcelain', '--untracked-files=no') === '',
  });
  mkdirSync(path.dirname(context.output), { recursive: true });
  const save = () => writeFileSync(context.output, `${JSON.stringify(evidence, null, 2)}\n`);
  // Each group is saved when it is done, so a failure later does not lose an hour of boots.
  if (context.only.includes('fixture')) { evidence.fixture = runFixture(context); save(); }
  if (context.only.includes('applications')) { evidence.applications = runApplications(context); save(); }
  if (context.only.includes('compile-fail')) { evidence.compile_fail = runCompileFail(context); save(); }
  if (context.only.includes('host-checks')) { evidence.host_checks = runHostChecks(context); save(); }
  save();
  console.log(`wrote ${context.output}`);
};

if (process.argv[1] && path.resolve(process.argv[1]) === new URL(import.meta.url).pathname) main();

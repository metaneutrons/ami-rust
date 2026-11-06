// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Tests of the orphan check, on a small repository built here. Every refusal has
// a counter-probe: the repository is correct, one thing is broken, and the check
// must name exactly that. Run with: node --test tools/

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, beforeEach, describe, it } from 'node:test';
import { check } from './check-orphans.mjs';

const roots = [];
let repository;

const put = (file, text) => {
  mkdirSync(path.dirname(path.join(repository, file)), { recursive: true });
  writeFileSync(path.join(repository, file), text);
};

const manifest = () => ({
  fixture: { path: 'tests/fixture', modes: [{ name: 'alloc' }, { name: 'big', abis: ['abi11'] }] },
  applications: [
    { path: 'examples/app', expected_return_code: 0 },
    { path: 'examples/window', expected_return_code: null },
  ],
  compile_fail: { path: 'tests/refused', fixtures: [{ bin: 'fine', expected: null }, { bin: 'bad', expected: 'E0382' }] },
  host_checks: [{ name: 'layout', script: 'tools/layout.mjs' }],
  evidence: { produced_by: 'tools/matrix.mjs' },
});

const program = (directory, { build = true, pin = '1.2.3' } = {}) => {
  put(`${directory}/Cargo.toml`, `[package]\nname = "p"\n\n[dependencies]\naros = { version = "=${pin}", path = "../../crates/aros" }\n`);
  if (build) put(`${directory}/build.rs`, 'fn main() {\n    aros_native_build::prepare(Default::default()).expect("bridge");\n}\n');
};

const evidence = () => ({
  schema: 'ami-rust-native-evidence-v1',
  version: '1.2.3',
  source_clean: true,
  fixture: [
    { abi: 'abi1', mode: 'alloc', return_code: 0 },
    { abi: 'abi11', mode: 'alloc', return_code: 0 },
    { abi: 'abi11', mode: 'big', return_code: 0 },
  ],
  applications: ['abi1', 'abi11'].flatMap((abi) => [
    { abi, path: 'examples/app', return_code: 0 },
    { abi, path: 'examples/window', return_code: null, screenshot_sha256: 'ab' },
  ]),
  compile_fail: [{ bin: 'fine', built: true, error: null }, { bin: 'bad', built: false, error: 'error[E0382]: borrow of moved value' }],
  host_checks: [{ name: 'layout', status: 'pass' }],
});

const read = (file) => readFileSync(path.join(repository, file), 'utf8');

const writeEvidence = (value) => put('docs/evidence/native-1.2.3.json', JSON.stringify(value));

beforeEach(() => {
  repository = mkdtempSync(path.join(tmpdir(), 'orphans-'));
  roots.push(repository);
  put('version.txt', '1.2.3\n');
  put('tests/programs.json', JSON.stringify(manifest()));
  for (const directory of ['tests/fixture', 'examples/app', 'examples/window', 'tests/refused']) program(directory);
  put('tests/fixture/src/main.rs', 'fn main() { let _ = ("alloc", "big"); }\n');
  put('tools/layout.mjs', '// the layout check\n');
  put('tools/matrix.mjs', '// the matrix\n');
  put('tools/layout.test.mjs', '// tests\n');
  put('tools/orphans.sh', '#!/bin/sh\n');
  put('.github/workflows/ci.yml', 'on:\n  push:\n    paths:\n      - \'tools/orphans.sh\'\njobs:\n  a:\n    steps:\n      - run: node --test tools/\n      - run: bash tools/orphans.sh\n');
  writeEvidence(evidence());
});

after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }); });

const problems = (options = {}) => check({ repository, ...options });
const named = (list, pattern) => list.filter((line) => pattern.test(line));

describe('a repository where everything is used', () => {
  it('has no problems, with and without the evidence', () => {
    assert.deepEqual(problems(), []);
    assert.deepEqual(problems({ evidence: true }), []);
  });
});

describe('programs', () => {
  it('counter-probe: a program the manifest does not list is refused', () => {
    program('tests/forgotten');
    assert.match(problems().join('\n'), /tests\/forgotten is a program that tests\/programs\.json does not list/);
    assert.equal(problems().length, 1);
  });

  it('counter-probe: a program hidden in release/ is refused too', () => {
    program('release/recipe');
    assert.match(problems().join('\n'), /release\/recipe is a program that tests\/programs\.json does not list/);
  });

  it('counter-probe: a listed program that is gone is refused', () => {
    rmSync(path.join(repository, 'examples/window'), { recursive: true });
    assert.match(problems().join('\n'), /lists examples\/window, which has no Cargo\.toml/);
  });

  it('counter-probe: a build script of a retired setup is refused, and so is one without the helper', () => {
    put('examples/app/build.rs', 'fn main() { if let Some(o) = std::env::var_os("AMI_RUST_M3_NATIVE_OBJECTS") { drop(o); } panic!(); }\n');
    const list = problems();
    assert.match(list.join('\n'), /examples\/app\/build\.rs does not call aros_native_build::prepare/);
    assert.match(list.join('\n'), /reads AMI_RUST_M3_NATIVE_OBJECTS, a hook of a retired setup/);
  });

  it('counter-probe: a dependency pinned to another version is refused', () => {
    program('examples/app', { pin: '1.2.0' });
    assert.match(problems().join('\n'), /examples\/app\/Cargo\.toml pins aros to =1\.2\.0, but the version is 1\.2\.3/);
  });

  it('counter-probe: a fixture mode that the fixture does not implement is refused', () => {
    put('tests/fixture/src/main.rs', 'fn main() { let _ = "alloc"; }\n');
    assert.match(problems().join('\n'), /fixture mode big, which tests\/fixture\/src does not implement/);
  });

  it('counter-probe: loose files and empty directories in tests/ are refused, and so is scripts/', () => {
    put('tests/M1SCRIPT', 'Stack 131072\n');
    mkdirSync(path.join(repository, 'tests/empty'));
    put('scripts/old.sh', '#!/bin/sh\n');
    const list = problems().join('\n');
    assert.match(list, /tests\/M1SCRIPT is a loose file/);
    assert.match(list, /tests\/empty is a directory without a program/);
    assert.match(list, /scripts\/old\.sh: scripts live in tools\//);
  });
});

describe('the version', () => {
  it('counter-probe: the version to publish decides which evidence is read and what the pins must be', () => {
    assert.deepEqual(problems({ evidence: true, version: '1.2.3' }), []);
    const list = problems({ evidence: true, version: '1.2.4' }).join('\n');
    assert.match(list, /there is no native evidence for 1\.2\.4/);
    assert.match(list, /pins aros to =1\.2\.3, but the version is 1\.2\.4/);
  });
});

describe('programs in development', () => {
  const develop = (extra = {}) => {
    program('examples/unfinished');
    const value = manifest();
    value.in_development = [{ path: 'examples/unfinished', issue: '#66', reason: 'Needs a patched standard library that the matrix cannot prepare.', ...extra }];
    put('tests/programs.json', JSON.stringify(value));
  };
  const open = () => 'open';

  it('accepts a listed program with an open owning issue, and the evidence does not cover it', () => {
    develop();
    assert.deepEqual(problems(), []);
    assert.deepEqual(problems({ issueState: open }), []);
    assert.deepEqual(problems({ evidence: true, issueState: open }), []);
  });

  it('counter-probe: without the entry the same program is an orphan', () => {
    develop();
    put('tests/programs.json', JSON.stringify(manifest()));
    assert.match(problems().join('\n'), /examples\/unfinished is a program that tests\/programs\.json does not list/);
  });

  it('counter-probe: an entry without a well-formed issue or a real reason is refused', () => {
    develop({ issue: '66' });
    assert.match(problems().join('\n'), /needs the open issue that owns it, written like "#66"/);
    develop({ issue: undefined });
    assert.match(problems().join('\n'), /needs the open issue that owns it/);
    develop({ reason: 'todo' });
    assert.match(problems().join('\n'), /needs a reason \(at least ten characters\)/);
  });

  it('counter-probe: a program that is an application and in development, or listed twice, is refused', () => {
    develop({ path: 'examples/app' });
    assert.match(problems().join('\n'), /lists examples\/app as an application and as in development/);
    const value = JSON.parse(read('tests/programs.json'));
    value.in_development = [value.in_development[0], value.in_development[0]];
    put('tests/programs.json', JSON.stringify(value));
    assert.match(problems().join('\n'), /lists examples\/app twice under in_development/);
  });

  it('counter-probe: an entry whose program is gone is refused', () => {
    develop();
    rmSync(path.join(repository, 'examples/unfinished'), { recursive: true });
    assert.match(problems().join('\n'), /lists examples\/unfinished, which has no Cargo\.toml/);
  });

  it('counter-probe: an unfinished program must still use the current helper and version', () => {
    develop();
    put('examples/unfinished/build.rs', 'fn main() { let _ = std::env::var_os("AMI_RUST_M9_NATIVE_OBJECTS"); }\n');
    program('examples/unfinished', { build: false, pin: '1.0.0' });
    put('examples/unfinished/build.rs', 'fn main() { let _ = std::env::var_os("AMI_RUST_M9_NATIVE_OBJECTS"); }\n');
    const list = problems().join('\n');
    assert.match(list, /examples\/unfinished\/build\.rs does not call aros_native_build::prepare/);
    assert.match(list, /examples\/unfinished\/Cargo\.toml pins aros to =1\.0\.0/);
  });

  it('counter-probe: a result in the evidence for it is stale, because the matrix does not run it', () => {
    develop();
    const value = evidence();
    value.applications.push({ abi: 'abi1', path: 'examples/unfinished', return_code: 0 });
    writeEvidence(value);
    assert.match(problems({ evidence: true }).join('\n'), /stale result for examples\/unfinished on abi1/);
  });

  it('counter-probe: a closed owning issue, and an issue that cannot be read, are refused', () => {
    develop();
    assert.match(problems({ issueState: () => 'closed' }).join('\n'), /examples\/unfinished is in development under #66, which is closed; finish it/);
    assert.match(problems({ issueState: () => 'unknown' }).join('\n'), /could not read the state of #66, the owner of examples\/unfinished/);
    assert.deepEqual(problems(), [], 'the issue is only read when asked');
  });

  it('asks for the state of the issue that the entry names', () => {
    develop({ issue: '#123' });
    const asked = [];
    problems({ issueState: (number) => { asked.push(number); return 'open'; } });
    assert.deepEqual(asked, [123]);
  });
});

describe('scripts', () => {
  it('counter-probe: a script that nothing uses is refused', () => {
    put('tools/forgotten.sh', '#!/bin/sh\n');
    const list = named(problems(), /forgotten/);
    assert.equal(list.length, 1);
    assert.match(list[0], /tools\/forgotten\.sh is not used/);
  });

  it('counter-probe: a path filter in a workflow is not a use', () => {
    put('tools/filtered.sh', '#!/bin/sh\n');
    put('.github/workflows/docs.yml', 'on:\n  push:\n    paths:\n      - \'tools/filtered.sh\'\n');
    assert.match(problems().join('\n'), /tools\/filtered\.sh is not used/);
  });

  it('accepts a script that another script calls, or a workflow runs', () => {
    put('tools/helper.sh', '#!/bin/sh\n');
    put('tools/orphans.sh', '#!/bin/sh\nbash tools/helper.sh\n');
    assert.deepEqual(named(problems(), /helper/), []);
  });

  it('counter-probe: a test whose subject is gone, or that no workflow runs, is refused', () => {
    put('tools/lonely.test.mjs', '// tests\n');
    assert.match(problems().join('\n'), /tools\/lonely\.test\.mjs tests tools\/lonely\.mjs, which does not exist/);
    put('.github/workflows/ci.yml', 'jobs: {}\n');
    assert.match(problems().join('\n'), /layout\.test\.mjs is never run/);
  });
});

describe('release evidence', () => {
  it('counter-probe: missing evidence is refused', () => {
    rmSync(path.join(repository, 'docs/evidence/native-1.2.3.json'));
    assert.match(problems({ evidence: true }).join('\n'), /there is no native evidence for 1\.2\.3/);
    assert.deepEqual(problems(), [], 'without --evidence the check does not need it');
  });

  it('counter-probe: evidence for another version or an unclean tree is refused', () => {
    writeEvidence({ ...evidence(), version: '1.2.2', source_clean: false });
    const list = problems({ evidence: true }).join('\n');
    assert.match(list, /is for 1\.2\.2, not 1\.2\.3/);
    assert.match(list, /uncommitted changes/);
  });

  it('counter-probe: a missing or failing mode is refused, and the ABI-v11-only mode is not needed on ABI-v1', () => {
    const value = evidence();
    value.fixture = value.fixture.filter((row) => !(row.abi === 'abi11' && row.mode === 'alloc'));
    value.fixture.find((row) => row.mode === 'big').return_code = 20;
    writeEvidence(value);
    const list = problems({ evidence: true }).join('\n');
    assert.match(list, /no result for fixture mode alloc on abi11/);
    assert.match(list, /fixture mode big on abi11 returned 20/);
    assert.doesNotMatch(list, /big on abi1\b/);
  });

  it('counter-probe: an application with the wrong return code, or without its screendump, is refused', () => {
    const value = evidence();
    value.applications.find((row) => row.path === 'examples/app' && row.abi === 'abi1').return_code = 10;
    delete value.applications.find((row) => row.path === 'examples/window' && row.abi === 'abi11').screenshot_sha256;
    writeEvidence(value);
    const list = problems({ evidence: true }).join('\n');
    assert.match(list, /examples\/app on abi1 returned 10, expected 0/);
    assert.match(list, /examples\/window on abi11 needs a screendump/);
  });

  it('counter-probe: a compile-fail fixture that builds, or is refused for another reason, is refused', () => {
    const value = evidence();
    value.compile_fail.find((row) => row.bin === 'bad').built = true;
    writeEvidence(value);
    assert.match(problems({ evidence: true }).join('\n'), /compile-fail fixture bad must be refused with "E0382", got a successful build/);
    value.compile_fail.find((row) => row.bin === 'bad').built = false;
    value.compile_fail.find((row) => row.bin === 'bad').error = 'error[E0599]: no method';
    writeEvidence(value);
    assert.match(problems({ evidence: true }).join('\n'), /got "error\[E0599\]: no method"/);
  });

  it('counter-probe: a failing host check and a result nobody lists are refused', () => {
    const value = evidence();
    value.host_checks[0].status = 'fail';
    value.applications.push({ abi: 'abi1', path: 'tests/m3-runtime', return_code: 0 });
    value.fixture.push({ abi: 'abi1', mode: 'retired', return_code: 0 });
    writeEvidence(value);
    const list = problems({ evidence: true }).join('\n');
    assert.match(list, /the host check layout did not pass/);
    assert.match(list, /stale result for tests\/m3-runtime on abi1/);
    assert.match(list, /stale result for fixture mode retired on abi1/);
  });
});

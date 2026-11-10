// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Tests of the parts of tools/native-matrix.mjs that need no emulator.
// Run with: node --test tools/

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { addArguments, bootScript, guestOutput, outputProblems, resolveArguments } from './native-matrix.mjs';

describe('resolveArguments', () => {
  const values = { work: '/w/check', toolchain: '0.2.0', 'abi1-source': '/src/nx' };

  it('fills placeholders and passes every other argument, flags included, as it is', () => {
    assert.deepEqual(
      resolveArguments(['{work}', '--toolchain', '{toolchain}', '--abi1-source', '{abi1-source}'], values),
      ['/w/check', '--toolchain', '0.2.0', '--abi1-source', '/src/nx'],
    );
  });

  it('counter-probe: a placeholder without a value is refused and names the option', () => {
    assert.throws(() => resolveArguments(['{abi11-sdk}'], values), /needs the option --abi11-sdk/);
  });

  it('counter-probe: text that only contains braces is not a placeholder', () => {
    assert.deepEqual(resolveArguments(['a{work}b', '{WORK}'], values), ['a{work}b', '{WORK}']);
  });
});

describe('bootScript', () => {
  it('keeps the fixture set-up: no stack on ABI-v1, 1000000 on ABI-v11', () => {
    assert.equal(bootScript({ abi: 'abi1', lines: ['X'] }), 'MakeDir RAM:ami-rust-m1\nX\n');
    assert.equal(bootScript({ abi: 'abi11', lines: ['X'] }), 'Stack 1000000\nMakeDir RAM:ami-rust-m1\nX\n');
  });

  it('applies the stack and the directory of a program to both ABIs, the directory after it exists', () => {
    for (const abi of ['abi1', 'abi11']) {
      assert.equal(bootScript({ abi, stack: 131072, cwd: 'RAM:ami-rust-m1', lines: ['X'] }), 'Stack 131072\nMakeDir RAM:ami-rust-m1\nCD RAM:ami-rust-m1\nX\n');
    }
  });
});

describe('guestOutput', () => {
  it('returns what the guest printed between the markers, without control characters', () => {
    assert.equal(guestOutput('boot\nNR-BEGIN\n\u001b[0mRESULT a ok\r\nM-RC=0\nNR-END\nlater'), 'RESULT a ok\nM-RC=0\n');
  });

  it('counter-probe: a log without NR-BEGIN has no output, and the last run counts', () => {
    assert.equal(guestOutput('Kernel Exception'), '');
    assert.equal(guestOutput('NR-BEGIN\nold\nNR-END\nNR-BEGIN\nnew\nNR-END'), 'new\n');
  });
});

describe('outputProblems', () => {
  it('accepts an output that has every expected text', () => {
    assert.deepEqual(outputProblems('RESULT path summary 8 of 8 checks passed\n', { expect: ['summary 8 of 8'] }), []);
  });

  it('counter-probe: a missing text and a RESULT line that says FAIL are reported', () => {
    assert.deepEqual(outputProblems('RESULT path summary 7 of 8\n', { expect: ['8 of 8'] }), ['missing: 8 of 8']);
    assert.deepEqual(outputProblems('RESULT fs open FAIL (x)\n'), ['failed: RESULT fs open FAIL (x)']);
    assert.deepEqual(outputProblems('RESULT sleep a elapsed_ms=1 OUT-OF-RANGE\n').length, 1);
  });

  it('counter-probe: FAIL is allowed when the mode expects it, and only a RESULT line counts', () => {
    assert.deepEqual(outputProblems('RESULT fs open FAIL\n', { allowFail: true }), []);
    assert.deepEqual(outputProblems('the word FAIL in free text\n'), []);
  });
});

describe('outputProblems with patterns', () => {
  it('accepts an output that matches, and reports a pattern that does not', () => {
    assert.deepEqual(outputProblems('RESULT system secs=1790000000 delta=3\n', { pattern: ['delta=-?\\d+$'] }), []);
    assert.deepEqual(outputProblems('RESULT system secs=1 delta=x\n', { pattern: ['delta=-?\\d+$'] }), ['no match: /delta=-?\\d+$/']);
  });
});

describe('addArguments', () => {
  it('maps a file below the repository to the FILE=NAME form of the runner', () => {
    assert.deepEqual(addArguments([{ from: 'examples/x/a.txt', name: 'stack/a.txt' }], '/repo'), ['/repo/examples/x/a.txt=stack/a.txt']);
    assert.deepEqual(addArguments(undefined, '/repo'), []);
  });
  it('refuses a path that is absolute, climbs out, has no name or contains an equals sign', () => {
    for (const entry of [
      { from: '/etc/passwd', name: 'a' },
      { from: '../outside', name: 'a' },
      { from: 'examples/x/../../../y', name: 'a' },
      { from: 'examples/x/a', name: '/abs' },
      { from: 'examples/x/a', name: '../up' },
      { from: 'examples/x/a', name: '' },
      { from: 'examples/x/a=b', name: 'a' },
      { from: 'examples/x/a' },
    ]) assert.throws(() => addArguments([entry], '/repo'), /add:/, JSON.stringify(entry));
  });
});

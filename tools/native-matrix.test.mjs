// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Tests of the parts of tools/native-matrix.mjs that need no emulator.
// Run with: node --test tools/

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { resolveArguments } from './native-matrix.mjs';

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

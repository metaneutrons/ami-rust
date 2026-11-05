// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The message catalog that the aros-locale native test reads is committed, and
// tools/make-test-catalog.mjs writes it. This keeps the two from drifting apart.
// Run with: node --test tools/

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { it } from 'node:test';

const here = path.dirname(new URL(import.meta.url).pathname);
const committed = path.join(here, '../tests/qualification/fixtures/Catalogs/deutsch/ami-rust-m8.catalog');

it('the committed test catalog is what the generator writes', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'catalog-'));
  try {
    const output = path.join(directory, 'catalog');
    const result = spawnSync('node', [path.join(here, 'make-test-catalog.mjs'), output], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(readFileSync(output).equals(readFileSync(committed)), 'regenerate it with tools/make-test-catalog.mjs');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

it('counter-probe: the comparison notices a different catalog', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'catalog-'));
  try {
    const output = path.join(directory, 'catalog');
    spawnSync('node', [path.join(here, 'make-test-catalog.mjs'), output]);
    const changed = Buffer.from(readFileSync(output));
    changed[changed.length - 1] ^= 1;
    assert.ok(!changed.equals(readFileSync(committed)));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// SPDX-License-Identifier: MIT OR Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { compare, propose } from './check-target-libraries.mjs';

const script = path.join(import.meta.dirname, 'check-target-libraries.mjs');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

const fixture = () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'ami-libs-'));
  const contents = { 'libcore-0123456789abcdef.rlib': 'core', 'libstd-0123456789abcdef.rmeta': 'std metadata' };
  for (const [name, text] of Object.entries(contents)) writeFileSync(path.join(directory, name), text);
  const pin = {
    schema: 'aros-target-library-candidate-v1',
    target: 'x86_64-unknown-aros-abi1',
    rustc_commit: 'c'.repeat(40),
    origin: 'fixture',
    files: Object.entries(contents).map(([name, text]) => ({ path: name, bytes: text.length, sha256: digest(text) })),
    symlinks: [],
  };
  return { directory, pin };
};

test('a build that matches its pins passes', () => {
  const { directory, pin } = fixture();
  assert.deepEqual(compare(pin, directory), []);
});

test('a changed byte, a missing file and an unpinned file are each refused', () => {
  const { directory, pin } = fixture();
  writeFileSync(path.join(directory, 'libcore-0123456789abcdef.rlib'), 'c0re');
  assert.match(compare(pin, directory).join('\n'), /digest differs: libcore-/);
  writeFileSync(path.join(directory, 'libcore-0123456789abcdef.rlib'), 'cor');
  assert.match(compare(pin, directory).join('\n'), /size differs: libcore-/);
  writeFileSync(path.join(directory, 'libextra-0123456789abcdef.rlib'), 'x');
  assert.match(compare(pin, directory).join('\n'), /not pinned: libextra-/);
  const other = fixture();
  const missing = { ...other.pin, files: [...other.pin.files, { path: 'libgone-0123456789abcdef.rlib', bytes: 1, sha256: digest('g') }] };
  assert.match(compare(missing, other.directory).join('\n'), /missing: libgone-/);
});

test('the proposed pin file is what a matching build is checked against, byte for byte', () => {
  const { directory, pin } = fixture();
  const proposed = propose(pin, directory);
  assert.deepEqual(compare(JSON.parse(proposed), directory), []);
  assert.equal(propose(JSON.parse(proposed), directory), proposed);
});

test('the pin files in the repository have the format that --write produces', () => {
  const pins = path.join(import.meta.dirname, '..', 'tooling', 'crates', 'aros-native-build', 'pins');
  for (const name of ['x86_64-unknown-aros-abi1-libraries.json', 'x86_64-unknown-aros-abi11-libraries.json']) {
    const raw = readFileSync(path.join(pins, name), 'utf8');
    const pin = JSON.parse(raw);
    const directory = mkdtempSync(path.join(tmpdir(), 'ami-libs-'));
    for (const row of pin.files) writeFileSync(path.join(directory, row.path), 'x');
    // Contents differ from the pin, so only the layout of the proposal is compared.
    const rows = propose(pin, directory).split('\n').filter((line) => line.startsWith('    {'));
    assert.equal(rows.length, pin.files.length);
    assert.ok(raw.includes('"files": [\n    {"path": "'));
    assert.ok(raw.endsWith('  ],\n  "symlinks": []\n}\n'));
  }
});

test('the command exits non-zero for a difference and writes the proposal either way', () => {
  const { directory, pin } = fixture();
  const pinFile = path.join(directory, '..', `pin-${path.basename(directory)}.json`);
  writeFileSync(pinFile, JSON.stringify(pin));
  const proposal = `${pinFile}.proposed`;
  assert.equal(spawnSync('node', [script, '--pins', pinFile, '--libraries', directory, '--write', proposal]).status, 0);
  writeFileSync(path.join(directory, 'libstd-0123456789abcdef.rmeta'), 'changed');
  const refused = spawnSync('node', [script, '--pins', pinFile, '--libraries', directory, '--write', proposal]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr.toString(), /digest differs|size differs/);
  assert.equal(JSON.parse(readFileSync(proposal, 'utf8')).files.find((row) => row.path.startsWith('libstd')).sha256, digest('changed'));
  assert.equal(spawnSync('node', [script, '--pins', pinFile]).status, 2);
});

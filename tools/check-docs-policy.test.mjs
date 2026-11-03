// SPDX-License-Identifier: MIT OR Apache-2.0
// Tests of the documentation policy check. Run with: node --test tools/
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { check, publishedCrates } from './check-docs-policy.mjs';

const crate = (name, { publish = '["metaneutrons"]', lints = '[lints]\nworkspace = true\n' } = {}) =>
  `[package]\nname = "${name}"\nversion = "0.1.0"\npublish = ${publish}\n${lints}`;

function tree({ rootLints = 'missing_docs = "deny"', toolingLints = '', crates = {}, tooling = {}, sources = {} }) {
  const root = mkdtempSync(join(tmpdir(), 'docs-policy-'));
  const put = (path, text) => {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  };
  put('Cargo.toml', `[workspace]\nmembers = []\n[workspace.lints.rust]\n${rootLints}\n`);
  put('tooling/Cargo.toml', `[workspace]\nmembers = []\n[workspace.lints.rust]\nunsafe_code = "deny"\n${toolingLints}\n`);
  for (const [name, text] of Object.entries(crates)) put(`crates/${name}/Cargo.toml`, text);
  for (const [name, text] of Object.entries(tooling)) put(`tooling/crates/${name}/Cargo.toml`, text);
  for (const [path, text] of Object.entries(sources)) put(path, text);
  return root;
}

test('a crate that opts in to a denying workspace passes', () => {
  const root = tree({ crates: { one: crate('one') }, sources: { 'crates/one/src/lib.rs': '//! docs\n' } });
  assert.deepEqual(check(root), []);
});

test('counter-probe: a crate that does not opt in is refused', () => {
  const root = tree({ crates: { one: crate('one', { lints: '' }) }, sources: { 'crates/one/src/lib.rs': '' } });
  assert.match(check(root)[0], /one: missing_docs is not denied/);
});

test('counter-probe: opting in to a workspace that does not deny is refused', () => {
  const root = tree({ rootLints: 'unsafe_code = "deny"', crates: { one: crate('one') }, sources: { 'crates/one/src/lib.rs': '' } });
  assert.match(check(root)[0], /not denied/);
});

test('counter-probe: a source that allows the lint is refused', () => {
  for (const attribute of ['#![allow(missing_docs)]', '#[allow(dead_code, missing_docs)]', '#![warn(missing_docs)]', '#[expect(missing_docs)]']) {
    const root = tree({ crates: { one: crate('one') }, sources: { 'crates/one/src/lib.rs': `${attribute}\n` } });
    assert.match(check(root)[0], /weakens the missing_docs lint/, attribute);
  }
});

test('a crate of the tooling workspace sets the lint in its own manifest', () => {
  const own = '[lints.rust]\nmissing_docs = "deny"\n';
  const root = tree({ tooling: { tool: crate('tool', { lints: own }) }, sources: { 'tooling/crates/tool/src/lib.rs': '' } });
  assert.deepEqual(check(root), []);
  const weak = tree({ tooling: { tool: crate('tool', { lints: '[lints.rust]\nmissing_docs = "warn"\n' }) }, sources: { 'tooling/crates/tool/src/lib.rs': '' } });
  assert.match(check(weak)[0], /tool: missing_docs is not denied \(level warn\)/);
});

test('crates that are not published are not checked', () => {
  const root = tree({ crates: { internal: crate('internal', { publish: 'false', lints: '' }) }, sources: { 'crates/internal/src/lib.rs': '#![allow(missing_docs)]\n' } });
  assert.deepEqual(publishedCrates(root), []);
  assert.deepEqual(check(root), []);
});

test('the repository itself satisfies the policy', () => {
  const root = new URL('../', import.meta.url).pathname;
  assert.ok(publishedCrates(root).length >= 13);
});

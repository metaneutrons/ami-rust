#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Compares the target libraries that the toolchain producer built on one host
// with the pin file of that host and ABI, and refuses any difference.
//
// The producer builds an rlib and an rmeta of every crate of the target
// library set (`core`, `alloc`, `compiler_builtins`, `std`, `panic_abort` and
// the crates `std` depends on). `aros-native-build` refuses a toolchain whose
// library directory differs from the pin file by one byte or one file, so a
// pin file that differs from a fresh build makes every program fail to link.
//
// usage: check-target-libraries.mjs --pins PIN.json --libraries DIR [--write PROPOSED.json]
//
// With --write the digests of DIR are written in the format of a pin file,
// whether or not they match, so that a run on a host whose pins are not
// known yet yields the file to review and commit.

import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const fail = (message) => {
  console.error(`check-target-libraries: ${message}`);
  process.exit(2);
};

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

export const compare = (pin, directory) => {
  const expected = new Map(pin.files.map((row) => [row.path, row]));
  const actual = new Set(readdirSync(directory));
  const problems = [];
  for (const [name, row] of expected) {
    if (!actual.has(name)) {
      problems.push(`missing: ${name}`);
      continue;
    }
    const file = path.join(directory, name);
    const bytes = readFileSync(file).length;
    const digest = sha256(file);
    if (bytes !== row.bytes) problems.push(`size differs: ${name} (pinned ${row.bytes}, built ${bytes})`);
    else if (digest !== row.sha256) problems.push(`digest differs: ${name} (pinned ${row.sha256}, built ${digest})`);
  }
  for (const name of actual) {
    if (!expected.has(name)) problems.push(`not pinned: ${name}`);
  }
  return problems;
};

export const propose = (pin, directory) => {
  const rows = readdirSync(directory)
    .sort()
    .map((name) => {
      const file = path.join(directory, name);
      return `    {"path": "${name}", "bytes": ${readFileSync(file).length}, "sha256": "${sha256(file)}"}`;
    });
  const head = JSON.stringify({ ...pin, files: undefined, symlinks: undefined }, null, 2)
    .replace(/\n}$/, ',\n  "files": [\n');
  return `${head}${rows.join(',\n')}\n  ],\n  "symlinks": []\n}\n`;
};

const main = () => {
  const args = process.argv.slice(2);
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--pins', '--libraries', '--write'].includes(args[i]) || args[i + 1] === undefined) {
      fail('usage: check-target-libraries.mjs --pins PIN.json --libraries DIR [--write PROPOSED.json]');
    }
    options[args[i].slice(2)] = args[i + 1];
  }
  if (!options.pins || !options.libraries) fail('--pins and --libraries are required');
  if (!existsSync(options.pins) || !existsSync(options.libraries)) fail('pin file or library directory is missing');
  const pin = JSON.parse(readFileSync(options.pins, 'utf8'));
  if (pin.schema !== 'aros-target-library-candidate-v1' || !Array.isArray(pin.files)) {
    fail('the pin file has an unexpected schema');
  }
  if (options.write) writeFileSync(options.write, propose(pin, options.libraries));
  const problems = compare(pin, options.libraries);
  if (problems.length) {
    console.error(`${problems.length} difference(s) between ${options.pins} and ${options.libraries}:`);
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }
  console.log(`ok: ${pin.files.length} libraries match ${options.pins}`);
};

if (import.meta.url === `file://${process.argv[1]}`) main();

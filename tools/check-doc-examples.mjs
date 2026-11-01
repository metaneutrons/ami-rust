#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Compile-checks the Rustdoc examples of the public `aros` and `aros-mui`
// crates for both AROS targets.
//
// The crates are `no_std` AROS libraries, so their examples cannot run as
// doctests. They are written as ```ignore blocks and this script keeps them
// honest: every block is wrapped into a function body, collected into a
// scratch crate and built with an installed ami-rust toolchain.
//
// Rust blocks in the guides are checked too. A block that invokes `entry!` is
// built as a complete program (`#![no_main]` and `#![no_std]` are added when
// the block omits them), and a block that starts with `use aros` and defines
// functions is built as a module. The `build.rs` snippet in the consumer guide
// is the build script of every crate built here. Any other Rust block is an
// unchecked fragment and fails the run: rewrite it as one of the forms above.
//
// Example convention for source-comment examples: the block is the body of a function that has a
// `context: &aros::Context` in scope and returns `Result<(), aros::Error>`
// (for `aros-mui`: `Result<(), aros_mui::Error>`). `# ` lines are hidden
// setup, as in Rustdoc. Blocks that contain `entry!` are whole programs and
// are covered by the example crates instead.
//
// usage: check-doc-examples.mjs WORK_DIR [TOOLCHAIN]    (default toolchain: 0.1.0)

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const [workArgument, toolchain = '0.1.0'] = process.argv.slice(2);
if (!workArgument) {
  console.error('usage: check-doc-examples.mjs WORK_DIR [TOOLCHAIN]');
  process.exit(2);
}
const repository = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const work = path.resolve(workArgument);

const crates = [
  { directory: 'crates/aros/src', error: 'aros::Error' },
  { directory: 'crates/aros-mui/src', error: 'aros_mui::Error' },
  { directory: 'crates/aros-timer/src', error: 'aros::Error' },
  { directory: 'crates/aros-graphics/src', error: 'aros_graphics::Error' },
  { directory: 'crates/aros-intuition/src', error: 'aros_intuition::Error' },
  { directory: 'crates/aros-asl/src', error: 'aros_asl::Error' },
];

const sourceFiles = (directory) => readdirSync(directory, { withFileTypes: true })
  .flatMap((entry) => (entry.isDirectory() ? sourceFiles(path.join(directory, entry.name)) : entry.name.endsWith('.rs') ? [path.join(directory, entry.name)] : []));

function blocksOf(file) {
  const lines = readFileSync(file, 'utf8').split('\n');
  const blocks = [];
  let current = null;
  lines.forEach((line, index) => {
    const doc = /^\s*\/\/[/!] ?(.*)$/.exec(line);
    if (!doc) { current = null; return; }
    const text = doc[1];
    if (!current && /^```(ignore|rust)\b/.test(text)) current = { start: index + 1, lines: [] };
    else if (current && text.startsWith('```')) { blocks.push(current); current = null; }
    else if (current) current.lines.push(text);
  });
  return blocks;
}

const unhide = (line) => line.replace(/^(\s*)#(?: (.*))?$/, (_, indent, rest) => `${indent}${rest ?? ''}`)
  .replace(/^(\s*)##/, '$1#');

const functions = [];
const sourcePrograms = [];
for (const { directory, error } of crates) {
  for (const file of sourceFiles(path.join(repository, directory))) {
    for (const block of blocksOf(file)) {
      const label = `${path.relative(repository, file)}:${block.start}`;
      const body = block.lines.map(unhide).join('\n');
      if (body.includes('entry!')) { sourcePrograms.push({ label, code: body }); continue; }
      functions.push({ label, error, body });
    }
  }
}

const guides = ['docs/consumer-guide.md', 'docs/api.md', 'docs/api/aros.md', 'docs/api/aros-mui.md', 'docs/api/aros-timer.md', 'docs/api/aros-graphics.md', 'docs/api/aros-intuition.md', 'docs/api/aros-asl.md'];
const withAttributes = (code) => (code.includes('#![no_main]') ? code : `#![no_main]\n#![no_std]\n${code}`);
const programs = sourcePrograms.map(({ label, code }) => ({ label, code: withAttributes(code) }));
let buildScript = null;
const modules = [];
const fragments = [];
for (const guide of guides) {
  const text = readFileSync(path.join(repository, guide), 'utf8');
  for (const match of text.matchAll(/```rust\n([\s\S]*?)```/g)) {
    const code = match[1];
    const line = text.slice(0, match.index).split('\n').length + 1;
    const label = `${guide}:${line}`;
    if (code.includes('aros_native_build::prepare') && /fn main\(\)/.test(code)) buildScript = { label, code };
    else if (code.includes('entry!')) programs.push({ label, code: withAttributes(code) });
    else if (/^use aros/m.test(code) && /\bfn \w+/.test(code) && !code.includes('entry!')) modules.push({ label, code });
    else fragments.push(label);
  }
}

if (!buildScript) { console.error('no build.rs snippet found in the guides'); process.exit(1); }
rmSync(work, { recursive: true, force: true });
mkdirSync(path.join(work, 'src'), { recursive: true });
writeFileSync(path.join(work, 'Cargo.toml'), `[package]
name = "doc-examples"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
aros = { path = "${repository}/crates/aros", features = ["alloc"] }
aros-mui = { path = "${repository}/crates/aros-mui" }
aros-timer = { path = "${repository}/crates/aros-timer" }
aros-graphics = { path = "${repository}/crates/aros-graphics" }
aros-intuition = { path = "${repository}/crates/aros-intuition" }
aros-asl = { path = "${repository}/crates/aros-asl" }

[build-dependencies]
aros-native-build = { path = "${repository}/tooling/crates/aros-native-build" }

[workspace]
`);
writeFileSync(path.join(work, 'build.rs'), `${buildScript.code}\n`);
writeFileSync(path.join(work, '.cargo-config-note'), 'Built with the target linker configured by the repository .cargo/config.toml equivalent below.\n');
mkdirSync(path.join(work, '.cargo'), { recursive: true });
writeFileSync(path.join(work, '.cargo/config.toml'), `[target.x86_64-unknown-aros-abi1]
linker = "aros-link"
rustflags = ["-Zunstable-options"]

[target.x86_64-unknown-aros-abi11]
linker = "aros-link"
rustflags = ["-Zunstable-options"]
`);
const source = [
  '#![no_main]', '#![no_std]', '#![allow(dead_code, unused_variables, unused_imports, unused_mut)]', '',
  ...modules.map((entry, number) => `// ${entry.label}\nmod guide_${number} {\n${entry.code}\n}\n`),
  'use aros::{AppStatus, Context};', '',
  ...functions.map((entry, number) => `// ${entry.label}\nfn example_${number}(context: &Context) -> Result<(), ${entry.error}> {\n${entry.body}\n    #[allow(unreachable_code)]\n    Ok(())\n}\n`),
  'fn application(_context: &Context) -> AppStatus { AppStatus::Success }', 'aros::entry!(application, alloc);', '',
].join('\n');
writeFileSync(path.join(work, 'src/main.rs'), source);

// Each complete program is its own crate next to the example crate.
const manifest = readFileSync(path.join(work, 'Cargo.toml'), 'utf8');
const crateDirs = [work];
programs.forEach((program, number) => {
  const directory = path.join(work, 'programs', `program_${number}`);
  mkdirSync(path.join(directory, 'src'), { recursive: true });
  writeFileSync(path.join(directory, 'Cargo.toml'), manifest.replace('name = "doc-examples"', `name = "program-${number}"`));
  writeFileSync(path.join(directory, 'build.rs'), readFileSync(path.join(work, 'build.rs')));
  mkdirSync(path.join(directory, '.cargo'), { recursive: true });
  writeFileSync(path.join(directory, '.cargo/config.toml'), readFileSync(path.join(work, '.cargo/config.toml')));
  writeFileSync(path.join(directory, 'src/main.rs'), program.code);
  crateDirs.push(directory);
});

console.log(`checking ${functions.length} source examples, ${modules.length} guide examples and ${programs.length} complete programs`
  + ` (build script from ${buildScript.label}) with toolchain ${toolchain}`);
let failed = false;
for (const label of fragments) { failed = true; console.error(`unchecked Rust fragment: ${label}`); }
for (const target of ['x86_64-unknown-aros-abi1', 'x86_64-unknown-aros-abi11']) {
  for (const directory of crateDirs) {
    const result = spawnSync('cargo', [`+${toolchain}`, 'build', '--release', '--target', target, '--manifest-path', path.join(directory, 'Cargo.toml')], {
      encoding: 'utf8',
      cwd: directory,
      env: { ...process.env, CARGO_BUILD_RUSTC_WRAPPER: '', CARGO_TARGET_DIR: path.join(work, 'target') },
    });
    const ok = result.status === 0;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${target} ${path.relative(work, directory) || 'examples'}`);
    if (!ok) { failed = true; console.error(result.stderr.split('\n').filter((line) => !/^\s*(Compiling|Finished)/.test(line)).join('\n')); }
  }
}
process.exit(failed ? 1 : 0);

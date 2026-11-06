#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Checks the layout of the raw MUI and BOOPSI structures against the C compiler.
//
// `aros-sys` and `aros-mui-sys` export the layout (size, alignment and field
// offsets) of the structures they declare, as the constants BOOPSI_LAYOUT_VALUES,
// MUI_CUSTOM_CLASS_LAYOUT_VALUES, MUI_LAYOUT_VALUES and MUI_CONSTANT_VALUES.
// `cargo xtask generate mui` writes a C file per ABI, bindings/mui/layout-<abi>.c,
// that computes the same values with `sizeof`, `_Alignof` and `offsetof` from the
// pinned MUI headers. This script compiles that file with the Clang of an
// installed ami-rust toolchain, compiles the Rust values into an object with the
// toolchain's rustc, reads both arrays out of the two objects and compares them.
// Nothing runs on AROS, and no boot is needed.
//
// usage: check-mui-layout.mjs WORK_DIR --toolchain NAME
//          --abi1-source GIT_CHECKOUT --abi11-source GIT_CHECKOUT
//          --abi11-sdk INCLUDE_DIR [--abi1-sdk INCLUDE_DIR]
//
// The two checkouts are the ones `cargo xtask generate mui` takes; the pinned
// commit of each is read from bindings/mui/sources.json and exported from Git,
// so the working tree does not matter. The ABI-v11 SDK is the pinned
// SDK-202609 archive, whose `Development/include` the toolchain does not ship
// in full. The ABI-v1 SDK defaults to the toolchain's own C SDK.

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

// Reads one named object symbol out of an ELF64 little-endian relocatable object.
export const readSymbol = (elf, name) => {
  if (elf.readUInt32BE(0) !== 0x7f454c46 || elf[4] !== 2 || elf[5] !== 1) {
    throw new Error('not a 64-bit little-endian ELF object');
  }
  const sectionTable = Number(elf.readBigUInt64LE(0x28));
  const entrySize = elf.readUInt16LE(0x3a);
  const sectionCount = elf.readUInt16LE(0x3c);
  const section = (index) => {
    const base = sectionTable + index * entrySize;
    return {
      type: elf.readUInt32LE(base + 4),
      offset: Number(elf.readBigUInt64LE(base + 0x18)),
      size: Number(elf.readBigUInt64LE(base + 0x20)),
      link: elf.readUInt32LE(base + 0x28),
    };
  };
  for (let index = 0; index < sectionCount; index += 1) {
    const symbols = section(index);
    if (symbols.type !== 2) continue; // SHT_SYMTAB
    const strings = section(symbols.link);
    for (let at = symbols.offset; at < symbols.offset + symbols.size; at += 24) {
      const nameOffset = elf.readUInt32LE(at);
      const end = elf.indexOf(0, strings.offset + nameOffset);
      if (elf.toString('latin1', strings.offset + nameOffset, end) !== name) continue;
      const home = elf.readUInt16LE(at + 6);
      const value = Number(elf.readBigUInt64LE(at + 8));
      const size = Number(elf.readBigUInt64LE(at + 16));
      const target = section(home);
      if (target.type === 8) throw new Error(`${name} is uninitialised`); // SHT_NOBITS
      return elf.subarray(target.offset + value, target.offset + value + size);
    }
  }
  throw new Error(`symbol ${name} not found`);
};

export const words = (bytes) => {
  const values = [];
  for (let at = 0; at + 8 <= bytes.length; at += 8) values.push(bytes.readBigUInt64LE(at));
  return values;
};

// The first position where two arrays differ, or null.
export const firstDifference = (left, right) => {
  if (left.length !== right.length) return Math.min(left.length, right.length);
  const index = left.findIndex((value, at) => value !== right[at]);
  return index < 0 ? null : index;
};

const run = (program, args, options = {}) => {
  const result = spawnSync(program, args, { encoding: 'utf8', ...options });
  if (result.status !== 0) {
    throw new Error(`${program} ${args.slice(0, 4).join(' ')}: ${(result.stderr || result.stdout || result.error).toString().slice(0, 1500)}`);
  }
  return result.stdout;
};

const shimLibrary = `#![no_std]
#![allow(non_upper_case_globals)]
use aros_mui_sys::{MUIC_Window, MUI_CONSTANT_VALUES, MUI_CUSTOM_CLASS_LAYOUT_VALUES, MUI_LAYOUT_VALUES};
use aros_sys::BOOPSI_LAYOUT_VALUES;
use core::ffi::CStr;

#[unsafe(no_mangle)]
pub static ami_rust_check_boopsi: [usize; BOOPSI_LAYOUT_VALUES.len()] = BOOPSI_LAYOUT_VALUES;
#[unsafe(no_mangle)]
pub static ami_rust_check_custom_class: [usize; MUI_CUSTOM_CLASS_LAYOUT_VALUES.len()] = MUI_CUSTOM_CLASS_LAYOUT_VALUES;
#[unsafe(no_mangle)]
pub static ami_rust_check_mui: [usize; MUI_LAYOUT_VALUES.len()] = MUI_LAYOUT_VALUES;
#[unsafe(no_mangle)]
pub static ami_rust_check_constants: [u64; MUI_CONSTANT_VALUES.len()] = MUI_CONSTANT_VALUES;

const WINDOW: &[u8] = unsafe { CStr::from_ptr(MUIC_Window) }.to_bytes();
const fn window_class() -> [u8; WINDOW.len()] {
    let mut bytes = [0; WINDOW.len()];
    let mut index = 0;
    while index < WINDOW.len() {
        bytes[index] = WINDOW[index];
        index += 1;
    }
    bytes
}
#[unsafe(no_mangle)]
pub static ami_rust_check_window_class: [u8; WINDOW.len()] = window_class();
`;

export const checkAbi = ({ abi, repository, work, toolchain, mui, sdk }) => {
  const sysroot = run('rustup', ['run', toolchain, 'rustc', '--print', 'sysroot']).trim();
  const clang = path.join(sysroot, 'libexec/aros/llvm/bin/clang');
  const directory = path.join(work, abi);
  rmSync(directory, { recursive: true, force: true });
  mkdirSync(path.join(directory, 'shim/src'), { recursive: true });

  const oracleObject = path.join(directory, 'oracle.o');
  run(clang, [
    '--target=x86_64-unknown-aros', '-std=c11', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
    `-I${mui}`, `-I${path.join(sdk, 'aros/stdc')}`, `-I${sdk}`,
    '-c', path.join(repository, `bindings/mui/layout-${abi}.c`), '-o', oracleObject,
  ]);

  const quote = (file) => JSON.stringify(path.join(repository, file));
  writeFileSync(path.join(directory, 'shim/Cargo.toml'), `[package]
name = "ami-rust-layout-shim"
version = "0.0.0"
edition = "2024"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
aros-sys = { path = ${quote('crates/aros-sys')} }
aros-mui-sys = { path = ${quote('crates/aros-mui-sys')} }

[workspace]
`);
  writeFileSync(path.join(directory, 'shim/src/lib.rs'), shimLibrary);
  const target = `x86_64-unknown-aros-${abi}`;
  const targetDirectory = path.join(directory, 'target');
  run('cargo', [`+${toolchain}`, 'rustc', '--offline', '--release', '--target', target,
    '--config', `target.${target}.rustflags=["-Zunstable-options"]`,
    '--manifest-path', path.join(directory, 'shim/Cargo.toml'), '--lib', '--', '--emit=obj'],
  { env: { ...process.env, CARGO_TARGET_DIR: targetDirectory, CARGO_BUILD_RUSTC_WRAPPER: '' } });
  const objects = run('find', [targetDirectory, '-name', 'ami_rust_layout_shim-*.o']).trim().split('\n').filter(Boolean);
  if (objects.length !== 1) throw new Error(`expected one shim object, found ${objects.length}`);

  const oracle = readFileSync(oracleObject);
  const rust = readFileSync(objects[0]);
  const pairs = [
    ['BOOPSI_LAYOUT_VALUES', 'ami_rust_boopsi_layout_values', 'ami_rust_check_boopsi'],
    ['MUI_CUSTOM_CLASS_LAYOUT_VALUES', 'ami_rust_custom_class_layout_values', 'ami_rust_check_custom_class'],
    ['MUI_LAYOUT_VALUES', 'ami_rust_mui_layout_values', 'ami_rust_check_mui'],
    ['MUI_CONSTANT_VALUES', 'ami_rust_mui_constant_values', 'ami_rust_check_constants'],
  ];
  const problems = [];
  const counts = {};
  for (const [label, cName, rustName] of pairs) {
    const expected = words(readSymbol(oracle, cName));
    const actual = words(readSymbol(rust, rustName));
    counts[label] = actual.length;
    const at = firstDifference(expected, actual);
    if (at !== null) {
      problems.push(`${abi} ${label}: ${expected.length} C values, ${actual.length} Rust values; first difference at index ${at} (C ${expected[at]}, Rust ${actual[at]})`);
    }
  }
  const windowClass = readSymbol(rust, 'ami_rust_check_window_class').toString('latin1');
  if (!oracle.includes(Buffer.from(`${windowClass}\0`, 'latin1'))) {
    problems.push(`${abi} MUIC_Window: the C object has no string ${JSON.stringify(windowClass)}`);
  }
  return { problems, counts };
};

const exportSources = ({ repository, checkout, abi, work }) => {
  const sources = JSON.parse(readFileSync(path.join(repository, 'bindings/mui/sources.json'), 'utf8'));
  const input = sources.inputs.find((entry) => entry.abi === abi);
  const destination = path.join(work, `${abi}-mui`);
  rmSync(destination, { recursive: true, force: true });
  mkdirSync(destination, { recursive: true });
  const archive = spawnSync('git', ['-C', checkout, 'archive', input.commit, input.root], { maxBuffer: 1 << 30 });
  if (archive.status !== 0) throw new Error(`${checkout} does not contain ${input.commit}: ${archive.stderr}`);
  const unpack = spawnSync('tar', ['-x', '-C', destination], { input: archive.stdout });
  if (unpack.status !== 0) throw new Error('could not unpack the MUI sources');
  return path.join(destination, input.root);
};

const main = () => {
  const argv = process.argv.slice(2);
  const option = (name) => { const at = argv.indexOf(name); return at < 0 ? undefined : argv[at + 1]; };
  const [workArgument] = argv;
  const toolchain = option('--toolchain');
  const abi1Source = option('--abi1-source');
  const abi11Source = option('--abi11-source');
  const abi11Sdk = option('--abi11-sdk');
  if (!workArgument || workArgument.startsWith('--') || !toolchain || !abi1Source || !abi11Source || !abi11Sdk) {
    console.error('usage: check-mui-layout.mjs WORK_DIR --toolchain NAME --abi1-source CHECKOUT --abi11-source CHECKOUT --abi11-sdk INCLUDE_DIR [--abi1-sdk INCLUDE_DIR]');
    process.exit(2);
  }
  const repository = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
  const work = path.resolve(workArgument);
  mkdirSync(work, { recursive: true });
  const sysroot = run('rustup', ['run', toolchain, 'rustc', '--print', 'sysroot']).trim();
  const abi1Sdk = option('--abi1-sdk') ?? path.join(sysroot, 'lib/aros/c-sdk/include');
  const problems = [];
  for (const [abi, checkout, sdk] of [['abi1', abi1Source, abi1Sdk], ['abi11', abi11Source, path.resolve(abi11Sdk)]]) {
    const mui = exportSources({ repository, checkout, abi, work });
    const result = checkAbi({ abi, repository, work, toolchain, mui, sdk });
    problems.push(...result.problems);
    console.log(`${abi}: ${Object.entries(result.counts).map(([name, count]) => `${name} ${count}`).join(', ')}${result.problems.length ? ' DIFFERS' : ' agree with the C compiler'}`);
  }
  if (problems.length) {
    console.error(problems.join('\n'));
    process.exit(1);
  }
};

if (process.argv[1] && path.resolve(process.argv[1]) === new URL(import.meta.url).pathname) main();

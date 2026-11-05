// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Tests of the object reader and comparison in check-mui-layout.mjs, on a small
// ELF object built here. Run with: node --test tools/

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { firstDifference, readSymbol, words } from './check-mui-layout.mjs';

const section = (type, offset, size, link = 0) => {
  const header = Buffer.alloc(64);
  header.writeUInt32LE(type, 4);
  header.writeBigUInt64LE(BigInt(offset), 0x18);
  header.writeBigUInt64LE(BigInt(size), 0x20);
  header.writeUInt32LE(link, 0x28);
  return header;
};

// An object with a .data section that holds `symbols` back to back, one symbol each.
const object = (symbols, { type = 1 } = {}) => {
  const data = Buffer.concat(symbols.map(({ bytes }) => bytes));
  const names = Buffer.concat([Buffer.from([0]), ...symbols.map(({ name }) => Buffer.from(`${name}\0`))]);
  const table = Buffer.alloc(24 * (symbols.length + 1));
  let at = 0;
  let nameAt = 1;
  symbols.forEach(({ name, bytes }, index) => {
    const entry = (index + 1) * 24;
    table.writeUInt32LE(nameAt, entry);
    table.writeUInt16LE(1, entry + 6);
    table.writeBigUInt64LE(BigInt(at), entry + 8);
    table.writeBigUInt64LE(BigInt(bytes.length), entry + 16);
    at += bytes.length;
    nameAt += name.length + 1;
  });
  const head = Buffer.alloc(64);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(head);
  const dataOffset = 64;
  const tableOffset = dataOffset + data.length;
  const namesOffset = tableOffset + table.length;
  const headersOffset = namesOffset + names.length;
  head.writeBigUInt64LE(BigInt(headersOffset), 0x28);
  head.writeUInt16LE(64, 0x3a);
  head.writeUInt16LE(4, 0x3c);
  return Buffer.concat([
    head, data, table, names,
    section(0, 0, 0), section(type, dataOffset, data.length), section(2, tableOffset, table.length, 3), section(3, namesOffset, names.length),
  ]);
};

const array = (...values) => {
  const bytes = Buffer.alloc(values.length * 8);
  values.forEach((value, index) => bytes.writeBigUInt64LE(BigInt(value), index * 8));
  return bytes;
};

describe('readSymbol', () => {
  const elf = object([{ name: 'first', bytes: array(8, 16) }, { name: 'second', bytes: array(4, 24, 32) }]);

  it('returns the bytes of the named symbol and no others', () => {
    assert.deepEqual(words(readSymbol(elf, 'first')), [8n, 16n]);
    assert.deepEqual(words(readSymbol(elf, 'second')), [4n, 24n, 32n]);
  });

  it('counter-probe: a missing symbol, a non-ELF file and an uninitialised symbol are errors', () => {
    assert.throws(() => readSymbol(elf, 'third'), /symbol third not found/);
    assert.throws(() => readSymbol(Buffer.alloc(80), 'first'), /not a 64-bit little-endian ELF/);
    assert.throws(() => readSymbol(object([{ name: 'first', bytes: array(1) }], { type: 8 }), 'first'), /first is uninitialised/);
  });
});

describe('firstDifference', () => {
  it('finds nothing in equal arrays and the position of the first difference otherwise', () => {
    assert.equal(firstDifference([1n, 2n, 3n], [1n, 2n, 3n]), null);
    assert.equal(firstDifference([1n, 2n, 3n], [1n, 9n, 8n]), 1);
  });

  it('counter-probe: arrays of different length differ even when one is a prefix of the other', () => {
    assert.equal(firstDifference([1n, 2n], [1n, 2n, 3n]), 2);
    assert.equal(firstDifference([], [1n]), 0);
  });
});

#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Writes the message catalog the aros-locale native test reads: an IFF "FORM
// CTLG" with FVER, LANG and STRS chunks, as locale.library reads them. The
// output is committed under tests/qualification/fixtures/Catalogs/ and put on
// the native test medium as PROGDIR:Catalogs/deutsch/ami-rust-m8.catalog.
//
// usage: make-test-catalog.mjs OUTPUT_FILE

import { writeFileSync } from 'node:fs';

const VERSION = 3;
const REVISION = 1;
const LANGUAGE = 'deutsch';
const STRINGS = [
  [1, 'Datei oeffnen'],
  [2, 'Abbrechen'],
  [3, 'Datei sichern'],
  [10, 'Ja, bitte'],
];

const u32 = (value) => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
};

function chunk(identifier, payload) {
  const padding = payload.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0);
  return Buffer.concat([Buffer.from(identifier, 'latin1'), u32(payload.length), payload, padding]);
}

function strings() {
  return Buffer.concat(
    STRINGS.map(([number, text]) => {
      const data = Buffer.concat([Buffer.from(text, 'latin1'), Buffer.alloc(1)]);
      const padded = Buffer.concat([data, Buffer.alloc((4 - (data.length % 4)) % 4)]);
      return Buffer.concat([u32(number), u32(data.length), padded]);
    }),
  );
}

export function catalog() {
  const fver = Buffer.from(`$VER: ami-rust-m8 ${VERSION}.${REVISION} (01.11.2026)`, 'latin1');
  const body = Buffer.concat([
    Buffer.from('CTLG', 'latin1'),
    chunk('FVER', fver),
    chunk('LANG', Buffer.from(LANGUAGE, 'latin1')),
    chunk('STRS', strings()),
  ]);
  return Buffer.concat([Buffer.from('FORM', 'latin1'), u32(body.length), body]);
}

if (process.argv.length !== 3) {
  console.error('usage: make-test-catalog.mjs OUTPUT_FILE');
  process.exit(2);
}
writeFileSync(process.argv[2], catalog());

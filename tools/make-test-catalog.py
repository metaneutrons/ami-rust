#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Writes the message catalog the aros-locale native test reads: an IFF "FORM
# CTLG" with FVER, LANG and STRS chunks, as locale.library reads them. The
# output is committed under tests/qualification/fixtures/Catalogs/ and put on
# the native test medium as PROGDIR:Catalogs/deutsch/ami-rust-m8.catalog.
#
# usage: make-test-catalog.py OUTPUT_FILE

import struct
import sys

VERSION, REVISION = 3, 1
LANGUAGE = b"deutsch"
STRINGS = [
    (1, b"Datei oeffnen"),
    (2, b"Abbrechen"),
    (3, b"Datei sichern"),
    (10, b"Ja, bitte"),
]


def chunk(identifier: bytes, payload: bytes) -> bytes:
    body = payload + (b"\0" if len(payload) % 2 else b"")
    return identifier + struct.pack(">I", len(payload)) + body


def strings() -> bytes:
    out = b""
    for number, text in STRINGS:
        data = text + b"\0"
        length = len(data)
        padded = data + b"\0" * (-length % 4)
        out += struct.pack(">II", number, length) + padded
    return out


def catalog() -> bytes:
    fver = b"$VER: ami-rust-m8 %d.%d (01.11.2026)" % (VERSION, REVISION)
    body = b"CTLG" + chunk(b"FVER", fver) + chunk(b"LANG", LANGUAGE) + chunk(b"STRS", strings())
    return b"FORM" + struct.pack(">I", len(body)) + body


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__ and "usage: make-test-catalog.py OUTPUT_FILE")
    with open(sys.argv[1], "wb") as handle:
        handle.write(catalog())

---
title: "aros-elf: ELF validation and compaction"
description: Host-side validation of AROS native ELF objects and the fixed section-name compaction used by the build.
---

`aros-elf` is a host library. It audits the relocatable ELF objects that the AROS toolchain produces, and it applies the fixed section-name shortening of the native build recipe. [`aros-native-build`](/api/aros-native-build/) and the maintainer tooling use it; applications do not. It runs no compiler or linker, selects no SDK, installs nothing and has no command-line interface. It contains no `unsafe` code.

## Use it

```toml
[dependencies]
aros-elf = { version = "=0.2.0", registry = "metaneutrons" }
```

## What it contains

| Item | Use |
| --- | --- |
| `elf::audit(bytes, variant, path)` | Audits an in-memory AROS ELF object and returns the report as JSON. `variant` selects the thresholds of the reference tests; `path` is copied into the report and is not read. The thresholds are measurements: an object that exceeds them is reported, not rejected. |
| `compact::compact_elf_sections(bytes)` | Returns a copy of the object with the section names shortened. The input is never changed. |
| `compact::compact_elf_sections_with_report(bytes)` | The same, with a `CompactionReport`: input and output sizes, the bytes saved, the sections renamed, each rename, and whether every other section payload is unchanged. |
| `Refusal`, `Result` | The error type. A refusal carries a message and an exit status. |

## What it accepts

Both operations require a 64-bit little-endian ELF version 1 file with the OS/ABI byte `0x0f` and ABI version 1, of type `ET_REL` for x86-64, with no program headers and 64-byte section header entries. Anything else is refused, as is a truncated or overflowing table or payload.

The compaction renames a section to `.r<index>` when it is a Rust-local section: a name that contains `._R` and starts with `.ltext.`, `.lrodata.`, `.ldata.` or `.lbss.` (or the same with a `.rela` prefix), or a `.lrodata..Lanon.` section. Every section header then has its own name entry, the name table is rewritten and padded, and the content after it moves down. The operation checks that no alignment is violated and that every payload is byte for byte the same before it returns.

A caller should publish an output only after both the compaction and the audit have succeeded.

Every public item is documented in the source; build the reference locally with the installed toolchain:

```text
cargo +"$toolchain" doc -p aros-elf --no-deps --open
```

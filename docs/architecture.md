---
title: Architecture
description: How the ami-rust crates, native bridge, generators and toolchain fit together.
---

ami-rust has four layers. Applications use the top one; the lower layers exist so that the top one can be safe, and so that the toolchain produces binaries that match what was tested.

```text
   your application
        │
   ┌────┴─────────────┐
   │ aros   aros-mui  │   safe, task-affine APIs                 (you use these)
   ├──────────────────┤
   │ aros-sys         │   raw declarations and library calls,    (unsafe, escape hatch)
   │ aros-mui-sys     │   one generated backend per ABI
   ├──────────────────┤
   │ native bridge    │   small C layer compiled per build       (aros-native-build)
   ├──────────────────┤
   │ toolchain        │   rustc, Cargo, target libraries,        (rustup, aros-link)
   │                  │   C SDK, collector, target specs
   └──────────────────┘
```

## Application-facing crates

| Crate | Role |
| --- | --- |
| [`aros`](/api/aros/) | Entry point, `Context`, allocator, files, streams, libraries, signals, ports, messages. The safe core. |
| [`aros-mui`](/api/aros-mui/) | Typed, scope-owned MUI objects. Built on `aros` and `aros-mui-sys`. |
| [`aros-timer`](/api/aros-timer/) | Time and timers on `timer.device`. Built on `aros` and the raw timer calls in `aros-sys`. Unreleased. |
| [`aros-graphics`](/api/aros-graphics/) | Off-screen bitmaps and drawing on `graphics.library`. Built on `aros` and the raw graphics calls in `aros-sys`. Unreleased. |
| `aros-sys` | Raw, allocation-free declarations and calls for the exec, dos, utility, intuition, timer and graphics libraries, plus the bridge's C interface. |
| `aros-mui-sys` | Raw MUI: every public class ID, attribute, method, value, enum value and `MUIP_*` message in the pinned headers, and the reviewed muimaster vector calls. |

Every safe type is built on the raw crates, and none of them exposes a raw pointer except through an `unsafe` item. The raw crates choose their library-call backend from the Cargo target, which is how the two [ABIs](/targets-and-abis/) are kept out of the safe API.

## The native bridge

The bridge is a small C library (about 550 lines of production source). It owns the registries that enforce the [resource limits](/api/aros/#errors-and-bounds), the owner-task check, resource cleanup after the entry function returns, and the startup checks described in [Run on AROS](/run-on-aros/). It is compiled for the selected ABI during each build by [`aros-native-build`](/build-system/), using the toolchain's pinned C SDK, so it always matches the system headers the program targets.

## Build and tooling crates

| Crate | Audience | Role |
| --- | --- | --- |
| [`aros-native-build`](/build-system/) | Build dependency | `prepare()` for `build.rs` and the `aros-link` target linker. |
| `aros-elf` | Internal | Shared host library for validating AROS ELF output and compacting section names. `aros-link` uses it to audit the executable before Cargo sees it. It does not run a compiler or linker. |
| `aros-api-gen` | Maintainers | Generates the committed `aros-sys` backends from a reviewed allowlist (`bindings/aros-api.json`) and two complete SDKs, verifying every function and vector against both. |
| `ami-rust-core`, `ami-rust-xtask` | Maintainers | Producing, qualifying, signing and publishing the SDK, and the MUI generator. Not a public CLI or Cargo plugin. |

`aros-elf`, `aros-api-gen` and the maintainer tools are not application APIs and are not published. Applications use `aros-native-build` only through `build.rs`.

## Generated code

Two sets of Rust sources are generated and committed, so application builds never run a generator and never need an AROS source tree:

- **`aros-sys` backends** (`crates/aros-sys/src/generated/`) are produced by `aros-api-gen` from the allowlist and the two SDKs. They differ per ABI because the call convention differs.
- **The MUI surface** (`aros-mui-sys` bindings and the `aros-mui` classes, attributes, methods and values) is produced by `cargo xtask generate mui` from a canonical model, `bindings/mui/api.json`. The model is derived from pinned commits of the two AROS source trees and records, for every symbol, which ABI profiles declare it. The same generator writes the ABI-specific `cfg` gating, the documentation comments on every generated item (including the sentence "Available on ABI-v1 targets only." where it applies) and independent C layout checks.

`cargo xtask check mui` regenerates everything and fails if a committed file differs, which keeps the committed sources reproducible from the pinned inputs.

## The toolchain

The versioned toolchain is a nightly-based Rust compiler and Cargo, the target libraries for each ABI, the AROS target specifications, a relocatable C SDK, a collector (AROS's link driver) and `aros-link`. Rustup installs it under a single versioned name. See [Install and build](/quickstart-toolchain/). The two targets differ only in their ABI name, `abi1` or `abi11`, in the target specification. Everything else about the compiler configuration is shared.

## Documentation

This site is built with Astro and Starlight from the repository's `docs/` directory. The [API reference](/reference/) is generated from the crates' Rustdoc comments and type relations by `tools/generate-astro-api.sh`, once per ABI and merged. The generator fails the build if an ABI restriction stated in an item's docs disagrees with what the two builds actually declare. Examples in Rustdoc and in the guides are compiled for both targets by `tools/check-doc-examples.mjs`.

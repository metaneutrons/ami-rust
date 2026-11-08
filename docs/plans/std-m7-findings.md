---
title: STD-M7 findings, toolchain pipeline
---

# STD-M7: what was measured before changing the pipeline

Status: 2026-11-08, start of STD-M7 (#72). Everything below was measured on the macOS ARM64 host with the `0.2.0`
toolchain, the patch of `host/std-aros` as merged (44 files) and the local copy `m3dev`; Linux hosts were not available
and are not covered. The pipeline itself (the producer) was read and not yet changed.

## How the toolchain gets its target libraries today

- The producer `bare_target_producer.rs` runs `cargo -Zbuild-std=core,alloc` with
  `-Zbuild-std-features=compiler-builtins-mem` from a staged, pinned `rust-src`, with
  `-Copt-level=2 -Cpanic=abort -Ccodegen-units=1 -Cembed-bitcode=no -Clto=off` and three `--remap-path-prefix` flags, and
  retains an `rlib` and an `rmeta` for `core`, `alloc` and `compiler_builtins` only.
- `aros-native-build` checks the library directory of a toolchain against **six** pin files (host × ABI:
  `pins/{,linux-x86_64/,linux-aarch64/}x86_64-unknown-aros-abi{1,11}-libraries.json`): every file must be listed with its
  size and SHA-256, and **any other file is refused** (`ABI1 target libraries has an unexpected file`). The same files are
  embedded in `native_prefix_compose.rs` and `bare_target_record_validation.rs` checks the producer's records.
- So adding `std` is not only a producer change: it changes the producer, its record validation, six pin files, the
  composition of the prefix, and the release contract.

## What a plain `std` build produces

`cargo -Zbuild-std=std,panic_abort` with the producer's flags, on the patched `rust-src` with its vendored dependencies,
gives 14 libraries that belong in a sysroot: `core`, `alloc`, `compiler_builtins`, `std`, `panic_abort`, `panic_unwind`,
`unwind`, `hashbrown`, `libc`, `cfg_if`, `rustc_demangle`, `std_detect`, `rustc_std_workspace_core` and
`rustc_std_workspace_alloc`. Cargo also builds `proc_macro` and `rustc_literal_escaper` for the same invocation; they are not
needed by `std` and were left out of the experiment. Each library is an `rlib` without metadata and a separate `rmeta`, as
for `core` today (`libcore` rlib 504 KB, rmeta 67 MB). The library directory grows from 76 MB to 84 MB.

## Reproducibility on one host

Two builds in different work directories (with the work directory remapped) gave **byte-identical** libraries and
identical file names for all 14 crates, without the producer's metadata rewrite. The producer's wrapper
(`rewrite_rustc_metadata`) only handles `core`, `alloc` and `compiler_builtins`; whether it must cover the other crates on
the other hosts is not known, because the file names of the pinned sets differ per host (the pins are per host).

## A program against a prebuilt `std`, no `-Zbuild-std`

With the 14 libraries (rlib and rmeta) as the only files of the target library directory, and the pin file of the
experiment toolchain changed to list them, `examples/std-path` built with plain `cargo build --target
x86_64-unknown-aros-abi1` (a `.cargo/config.toml` without `build-std`, no `__CARGO_TESTS_ONLY_SRC_ROOT`) and its
`components`, `join` and `dots` modes passed on ABI-v1 in the native runner. So the shape of STD-M7-A2 works. The same was
not run on ABI-v11 and not on a second host.

## What this means for the work

| Criterion | What is needed | Can be done here | Needs a maintainer run |
| --- | --- | --- | --- |
| A1 | Producer builds `std,panic_abort` from the patched, pinned source; records; six pin files; contract | Producer, validation and macOS pins (if the pinned inputs can be acquired locally) | The Linux x86-64 and Linux ARM64 pins come only from a Linux build, which the protected qualification workflow does |
| A2 | Direct and rustup candidate deliver `std`; `no_std` keeps working | The macOS composition and install | The three-host candidate and the rustup catalog |
| A3 | Guides and a `std` guide, compiled examples for both modes | Yes, apart from compiling examples with a toolchain that has `std` | — |
| A4 | Nightly bump procedure in `CONTRIBUTING.md`, exercised once | The procedure; exercised on the pinned tree | — |

Open design points: whether the shipped `rust-src` component stays unpatched (then a user of `-Zbuild-std` gets a `std`
without AROS support, which is only reachable by mistake once `std` is prebuilt); whether `proc_macro` is shipped (it
has no use on AROS); whether `core`, `alloc` and `compiler_builtins` keep their pinned file names when they are built in one invocation with `std` (in the experiment they did not, `libcore-de6465d8198d6eab` against the pinned `libcore-2cbb80be7a935e6b`; the producer's metadata rewrite was not applied, so this was not examined further). If they change, the pins of those three libraries change with this work.

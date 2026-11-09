---
title: STD-M7 findings, toolchain pipeline
---

# STD-M7: what was measured before changing the pipeline

Status: 2026-11-08, start of STD-M7 (#72). Everything below was measured on the macOS ARM64 host with the `0.2.0`
toolchain, the patch of `host/std-aros` as merged (44 files) and the local copy `m3dev`; Linux hosts were not available
and are not covered. The first part of this document was measured before the producer was changed; "Result of the producer change" below was measured with it.

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

## Result of the producer change (A1, macOS host)

The producer now applies `host/std-aros/std-aros.patch` to its private copy of the pinned `rust-src` (in process, each of
the 44 files checked against the before and after digests of `source.json`, the result in the producer's record), builds
`-Zbuild-std=std,panic_abort` with its existing flags, and retains the `rlib` and `rmeta` of 14 crates per target. Run with
the pinned inputs of the contract on this macOS host:

- It finished in 8 minutes 40 seconds, 28 files per target, 84 MB, for both targets.
- Two runs in different work directories gave byte-identical libraries for all 28 files of both targets (the metadata
  rewrite of the producer now covers every crate of the set).
- The unpatched-source and std-patch digests, and every patched file, are in `component-inventory.json` of the producer's output.
- The macOS pins (`pins/x86_64-unknown-aros-abi{1,11}-libraries.json`) are written from that build, and the producer's
  own consistency checks pass with them. The 0.2.0 pins could not be reproduced by this producer from the current tree,
  because the target specifications changed with STD-M2 (`entry-name`), which changes the metadata digest; they were
  stale before this work.
- The produced direct archive, installed as a toolchain, built `examples/std-path` and `examples/std-threads` for both
  ABIs with plain `cargo build` (a `.cargo/config.toml` without `build-std`). On the native runner: `std-path` `dots` 30 of
  30 and `join` 16 of 16 on both ABIs, and the 12 check modes of `std-threads` (43 checks) on both ABIs. `examples/minimal`
  (`no_std`) builds for both ABIs with the same toolchain.
- The 12 unit-test failures seen with an unpinned Rust do not occur with the pinned one; with it the workspace tests pass.

## Result on the three hosts (A1)

The workflow "Target library check" built the libraries on macOS ARM64, Linux x86-64 and Linux ARM64 from the pinned
inputs and compared them with the committed pins of each host and ABI (28 files each): all three pass. The macOS pins that
came from the local build (above) are byte for byte what the CI macOS build gives, so a local build and a CI build agree
on that host. The Linux pins were written from the proposal that the workflow uploads, not by hand.

Across hosts, all 28 files per ABI have the same size on the three hosts, and 26 have different names and bytes, as
before (Cargo's host-bound disambiguators). The rule that the release pipeline applies across hosts (R1: every native
object and symbol index identical, only `lib.rmeta` and the Cargo disambiguators in member names may differ) was run on the
`rlib` files of the three hosts with the pipeline's own comparison code: all 14 crates of both ABIs pass, 56 pairwise
comparisons (a throwaway harness; the same code runs in the protected qualification workflow).

## Installation delivers `std` (A2)

- **Where the libraries go.** The producer composes the toolchain from the same file list for the direct archive and for the
  rustup components, so the 28 libraries per target are in the `rustc` component (where `core` and `alloc` already were:
  28 files per target counted in `ami-rust-rustc-<version>-<host>.tar.xz`), and the direct archive has the same files.
- **The examples.** The `.cargo/config.toml` of the eight `std` programs no longer asks for `build-std`; their READMEs say that
  they need a toolchain that ships `std`, and `examples/std-runtime/README.md` keeps the way to build `std` from the patched
  tree for released toolchains up to 0.2.0 and for trying a change of the patch.
- **A check on each host.** `tools/build-std-examples.sh` takes an installed toolchain root, refuses it when a library of
  `std`, `panic_abort`, `core` or `alloc` is missing for either ABI, and builds `std-path` and `std-threads` for both ABIs with
  plain `cargo build` against the offline vendor set. The workflow "Target library check" runs it on the three hosts with the
  direct archive that the producer made. Locally (macOS): all four builds pass, and the programs pass natively (`std-threads`
  `spawn` 10 of 10 on ABI-v1, `std-path` `join` 16 of 16 on ABI-v11); with the released 0.2.0 toolchain, which has no `std`, the
  script refuses (`toolchain lacks libstd for abi1`, exit 1, nothing built).
- **Not run:** installation through rustup. The protected qualification workflow does that for `no_std` (it builds
  `ami-rust-sha256sum` from an installed toolchain); it does not build a `std` program yet, and extending it means
  changing an observed, hash-bound step that cannot be tried without dispatching it. Until it is, the rustup route is
  supported by the layout argument above and not by a run.

Not done: the guides (A3) and the bump procedure exercised on a newer nightly (A4).

<p align="center">
  <img src="assets/ami-rust-hero.svg" alt="ami-rust — Rust for AROS x86-64 ABI-v1 and ABI-v11" width="100%">
</p>

<p align="center">
  <a href="https://github.com/metaneutrons/ami-rust/actions/workflows/ci.yml"><img src="https://github.com/metaneutrons/ami-rust/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/metaneutrons/ami-rust/releases/tag/v0.1.0"><img src="https://img.shields.io/badge/version-0.1.0-ff825e?style=flat-square" alt="Version 0.1.0"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-7c8cf8?style=flat-square" alt="License: MIT OR Apache-2.0"></a>
  <a href="docs/compatibility.md"><img src="https://img.shields.io/badge/target-AROS%20x86--64%20ABI--v1%20%2B%20ABI--v11-398f4f?style=flat-square" alt="Target: AROS x86-64 ABI-v1 and ABI-v11"></a>
  <a href="docs/api.md"><img src="https://img.shields.io/badge/Rust-no__std%20%2B%20alloc-91b8d6?style=flat-square" alt="Rust: no_std plus alloc"></a>
</p>

<p align="center">
  <strong>Build native AROS applications with standard Rust tools.</strong><br>
  Cross-compile on macOS or Linux. Run on AROS x86-64 ABI-v1 or ABI-v11.
</p>

## What ami-rust provides

ami-rust combines a pinned Rust compiler, Cargo, AROS target libraries, a
relocatable C SDK, native link tools, and AROS/Amiga crates. The public workflow
uses upstream rustup for toolchain selection and ordinary Cargo for builds.
There is no project-specific CLI, Cargo wrapper, or Python dependency.

```text
macOS / Linux host
        │
        ├── rustup selects the versioned ami-rust toolchain
        └── cargo build --target x86_64-unknown-aros-abi1
            cargo build --target x86_64-unknown-aros-abi11
                          │
                          └── native ABI1 or ABI11 AROS executable
```

The initial targets are deliberately narrow: **PC x86-64 AROS ABI-v1 and
ABI-v11** with `no_std` and `alloc`. Full `std`, additional AROS architectures,
and native AROS-hosted rustc/Cargo/rustup are future work. The target name
selects the ABI; application source does not select it through a Cargo feature.

## Status

ami-rust 0.1.0 is the initial qualified release. The exact candidate passed the
protected three-host, dual-target and native AROS qualification. Authenticated
GitHub Release archives and the immutable rustup catalog are the supported
installation routes. APT, Homebrew, AUR and crates.io are not 0.1.0 channels.

Qualified development hosts:

| Host | Architecture |
| --- | --- |
| macOS 26 | Apple Silicon |
| Ubuntu 24.04 | x86-64 |
| Ubuntu 24.04 | ARM64 |

## Standard user workflow

Users install the authenticated GitHub Release toolchain through rustup or the
documented direct route. A project then builds without an ami-rust command. The
versioned rustup name is the same on every supported development host; rustup
selects the matching host components automatically:

```toml
# .cargo/config.toml
[target.x86_64-unknown-aros-abi1]
linker = "aros-link"
rustflags = ["-Zunstable-options"]

[target.x86_64-unknown-aros-abi11]
linker = "aros-link"
rustflags = ["-Zunstable-options"]
```

Resolve and commit a project's `Cargo.lock` once. Thereafter both targets build
offline with ordinary Cargo:

```sh
toolchain=0.1.0
cargo +"$toolchain" fetch --locked
cargo +"$toolchain" build --target x86_64-unknown-aros-abi1 --release --locked --offline
cargo +"$toolchain" build --target x86_64-unknown-aros-abi11 --release --locked --offline
```

The libraries are normal Cargo dependencies. They remain Git-delivered until
their names and public APIs are stable enough for an intentional crates.io
publication. The public base set is:

- `aros` for entry, allocation and the safe core API;
- `aros-sys` for raw AROS ABI declarations;
- `aros-mui` for task-affine MUI ownership;
- `aros-mui-sys` for raw MUI vector calls.

`aros-timer` (time and timers on `timer.device`), `aros-graphics` (bitmaps
and drawing on `graphics.library`) and `aros-intuition` (windows and events on
`intuition.library`) are in the repository after release 0.1.0 and are not part
of that release.

The focused `aros-elf` and `aros-native-build` crates are maintainer and build
support, not application API crates.

See the [consumer guide](https://ami-rust.metaneutrons.cc/consumer-guide/), the
[programming model](https://ami-rust.metaneutrons.cc/api/), the
[API reference](https://ami-rust.metaneutrons.cc/reference/), the
[MUI hello-world example](https://ami-rust.metaneutrons.cc/mui-hello/), and the
[SHA-256 example](https://ami-rust.metaneutrons.cc/sha256sum/).

## Build the maintainer tooling

The repository bootstraps its pinned host Rust and Cargo, verifies every input,
and builds the maintainer task offline. The work directory must be fresh and
outside the checkout:

```sh
work="$(mktemp -d)/ami-rust-maintainer"
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) host=aarch64-apple-darwin ;;
  Linux:x86_64) host=x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) host=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
bash tools/build-maintainer-task.sh "$work" "$host"
"$work/target/release/ami-rust-xtask" --help
```

This verifies repository tooling, not a releasable SDK. Candidate production,
signing, AROS execution, and publication remain protected workflow stages.

## Repository map

| Path | Purpose |
| --- | --- |
| `crates/` | Public AROS and Amiga libraries |
| `examples/` | Native AROS example applications |
| `native/` | Startup and runtime support |
| `targets/` | Rust target specification |
| `tooling/` | Rust-only producer and qualification libraries |
| `release/` | Pinned inputs, contracts, notices, and source obligations |
| `host/` | Narrow, versioned upstream portability patches |

## Documentation

The documentation site is <https://ami-rust.metaneutrons.cc/>.

- [Install and build](https://ami-rust.metaneutrons.cc/quickstart-toolchain/)
- [Run on AROS](https://ami-rust.metaneutrons.cc/run-on-aros/)
- [Targets and ABIs](https://ami-rust.metaneutrons.cc/targets-and-abis/)
- [Crates and consumer guide](https://ami-rust.metaneutrons.cc/consumer-guide/)
- [Programming model](https://ami-rust.metaneutrons.cc/api/)
- [Rust API reference](https://ami-rust.metaneutrons.cc/reference/)
- [Compatibility boundary](https://ami-rust.metaneutrons.cc/compatibility/)
- [Troubleshooting](https://ami-rust.metaneutrons.cc/troubleshooting/)
- [Platform roadmap](https://ami-rust.metaneutrons.cc/platform-roadmap/)

To work on the documentation itself, see [CONTRIBUTING.md](CONTRIBUTING.md#documentation).

## Licence and provenance

First-party code and artwork are licensed under **MIT OR Apache-2.0**. Third-
party components retain their own terms. See [LICENSE.md](LICENSE.md),
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and the corresponding-source
records under `release/`.

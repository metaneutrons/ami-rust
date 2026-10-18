<p align="center">
  <img src="assets/ami-rust-hero.svg" alt="ami-rust — Rust for AROS. Cross-compile on macOS and Linux; run native on AROS x86-64." width="100%">
</p>

<p align="center">
  <a href="https://github.com/metaneutrons/ami-rust/actions/workflows/ci.yml"><img src="https://github.com/metaneutrons/ami-rust/actions/workflows/ci.yml/badge.svg?branch=main" alt="Source CI"></a>
  <a href="https://github.com/metaneutrons/ami-rust/actions/workflows/sdk-qualify.yml"><img src="https://github.com/metaneutrons/ami-rust/actions/workflows/sdk-qualify.yml/badge.svg?branch=main" alt="SDK qualification workflow"></a>
  <a href="https://github.com/metaneutrons/ami-rust/releases/latest"><img src="https://img.shields.io/github/v/release/metaneutrons/ami-rust?color=ff825e&amp;style=flat-square" alt="Latest SDK release"></a>
  <a href="packaging/INSTALL-APT.md"><img src="https://img.shields.io/badge/APT-available-398f4f?style=flat-square" alt="APT package available"></a>
  <a href="packaging/INSTALL-HOMEBREW.md"><img src="https://img.shields.io/badge/Homebrew-available-398f4f?style=flat-square" alt="Homebrew package available"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-7c8cf8?style=flat-square" alt="License: MIT OR Apache-2.0"></a>
  <a href="docs/compatibility.md"><img src="https://img.shields.io/badge/target-AROS%20x86--64%20ABI--v1-ff825e?style=flat-square" alt="Target: AROS x86-64 ABI-v1"></a>
  <a href="docs/api.md"><img src="https://img.shields.io/badge/Rust-no__std%20%2B%20alloc-91b8d6?style=flat-square" alt="Rust: no_std plus alloc"></a>
</p>

<p align="center">
  <strong>Build native AROS applications in Rust.</strong><br>
  A source SDK, a task-aware API, and a pinned cross-development toolchain.
</p>

<p align="center">
  <a href="docs/quickstart.md">Get started</a> ·
  <a href="docs/api.md">API guide</a> ·
  <a href="docs/compatibility.md">Compatibility</a> ·
  <a href="https://github.com/metaneutrons/ami-rust/releases">Releases</a> ·
  <a href="packaging/INSTALL-APT.md">APT</a> ·
  <a href="packaging/INSTALL-HOMEBREW.md">Homebrew</a> ·
  <a href="docs/release-status.md">Release status</a>
</p>

---

> **SDK 0.1.0 is available.** The release passed independent macOS/Linux
> installation and build replay, plus the complete AROS runtime and memory matrix.
> Install with [APT on Ubuntu 24.04 amd64](packaging/INSTALL-APT.md) or
> [Homebrew on macOS 26 Apple Silicon](packaging/INSTALL-HOMEBREW.md), or use the
> [direct SDK guide](docs/quickstart.md). See [release evidence](docs/release-status.md)
> and [package channel status](docs/distribution-status.md). Runtime support is
> confined to the documented PC x86-64 ABI-v1 QEMU profile.

## Modern Rust, native AROS

ami-rust cross-compiles Rust applications on **macOS Apple Silicon** and
**Linux x86-64** for **native PC x86-64 AROS ABI-v1**. Applications use AROS
Exec and DOS services through a small Rust facade, with ownership and task
lifetimes checked at the API boundary.

<table>
<tr>
<td width="33%" valign="top">
<h3>Native foundations</h3>
<p><code>no_std</code>, optional <code>alloc</code>, native executables, DOS file I/O,
libraries, signals, and local message ports.</p>
</td>
<td width="33%" valign="top">
<h3>Explicit toolchains</h3>
<p>Pinned compiler and SDK inputs, project locks, offline builds after preparation,
and separate host tools for macOS and Linux.</p>
</td>
<td width="33%" valign="top">
<h3>Verifiable delivery</h3>
<p>GitHub attestations, Cosign signatures, complete asset inventories, licence
records, and independent consumer replay.</p>
</td>
</tr>
</table>

## A small beginning

The generated project starts with this application:

```rust
#![no_std]
use amiga_os::{AppStatus, Context};

fn application(ctx: &Context) -> AppStatus {
    ctx.diagnostic(b"ami-rust hello", 1);
    AppStatus::Success
}

amiga_os::entry!(application);
```

`amiga-os` is the public facade. `amiga-sys` exposes the unsafe ABI boundary;
`amiga-alloc` provides the native allocator. See the [API guide](docs/api.md)
for file I/O, borrowed output streams, library lifetimes, signals, messages,
and synchronous callbacks.

## Get started

Follow the [installation and first-project guide](docs/quickstart.md).
It documents the end-to-end procedure:

1. Select the release and its independently trusted publisher source.
2. Prepare and verify the pinned host prerequisites in a private local directory.
3. Authenticate and install the SDK, then generate and lock a project.
4. Build offline and run the native executable under the documented AROS profile.

Preparation leaves global Rust and Cargo installations intact. SDK versions can
be installed side by side; uninstall keeps projects and shared prerequisites.
The SDK contains source and helpers; the Rust compiler, C SDK, native toolchain,
and vendor inputs are provisioned explicitly by the preparation recipe.

GitHub Releases remains the canonical SDK artifact and recovery channel. The
separate `v0.1.0+packaging.2` release makes packages available while preserving
the original SDK release. Install with [APT on Ubuntu 24.04 amd64](packaging/INSTALL-APT.md)
or [Homebrew on macOS 26 Apple Silicon](packaging/INSTALL-HOMEBREW.md). Both
package routes require the same [explicit user preparation before the first
build](packaging/README.md). Read the [distribution status](docs/distribution-status.md)
for acceptance evidence. AUR and rustup remain
[later deliveries](docs/distribution-channels-plan.md).

**Supported package hosts:** APT on Ubuntu 24.04 amd64, and Homebrew on macOS 26
Apple Silicon. These are the only qualified package-host profiles. Direct
GitHub-release installation requires an existing Python 3.10+ to bootstrap the
pinned interpreter. Preparation requires 6 GiB physical RAM and 24 GiB free
space. The [compatibility guide](docs/compatibility.md) records the exact inputs
and target configuration.

## Try something useful

The SDK includes a native, read-only **SHA-256 checksum utility**. Build it with
the quickstart, then run it in AROS Shell:

```text
SHAUTIL "fixture with spaces.bin"
Echo $RC
Echo "shell remains usable"
```

The utility accepts multiple files, handles paths containing spaces, and reports
failures with a nonzero status. Its [example guide](examples/sha256sum/README.md)
explains file limits and error behavior. The [minimal example](examples/minimal)
shows the runtime with and without allocation.

## Support at a glance

| Area | Initial SDK scope |
| --- | --- |
| Development hosts | macOS Apple Silicon; Linux x86-64 |
| Package channels | APT: Ubuntu 24.04 amd64; Homebrew: macOS 26 Apple Silicon |
| Target | Native PC x86-64 AROS ABI-v1 |
| Rust libraries | `core`, `alloc`, and the documented SDK facade |
| Native services | Files, stdout/stderr, libraries, signals, local ports/messages, synchronous callbacks |
| Qualification environment | Pinned QEMU image, one CPU, 512 MiB RAM |
| Separate future work | Full `std`, threads, networking, native AROS-hosted rustc/Cargo, other CPU/ABI profiles and physical hardware |

This is a cross-development SDK. Official `rustup target add` distribution and
arbitrary crate compatibility are outside the initial release scope. Application
memory uses public Exec allocation and checked layouts; the qualification
machine's 512 MiB RAM is a test profile. See the [memory policy](docs/memory-policy.md).

## Documentation

| Start here | Go deeper |
| --- | --- |
| [Installation and first project](docs/quickstart.md) | [API and lifetime contracts](docs/api.md) |
| [APT installation](packaging/INSTALL-APT.md) · [Homebrew installation](packaging/INSTALL-HOMEBREW.md) | [Package preparation and retained state](packaging/README.md) |
| [Supported hosts and target](docs/compatibility.md) | [Memory and allocation](docs/memory-policy.md) |
| [Current release status](docs/release-status.md) | [Protected SDK production](docs/hosted-sdk-producer.md) |
| [Release verification](docs/public-release-replay.md) | [Authoritative release plan](docs/m2-r1-plan.md) |
| [Distribution roadmap: APT, Homebrew, AUR, rustup](docs/distribution-channels-plan.md) | [Compatibility and limits](docs/compatibility.md) |

## Contributing

[Open an issue](https://github.com/metaneutrons/ami-rust/issues) for a reproducible
bug or a scoped proposal. Include the host profile, SDK/source identity, build
command, and relevant diagnostics. Keep changes focused and retain the pinned
inputs when reproducing a release issue.

## Licence and source availability

First-party ami-rust code and artwork are **MIT OR Apache-2.0**.
See [LICENSE.md](LICENSE.md), [LICENSE-MIT](LICENSE-MIT), and
[LICENSE-APACHE](LICENSE-APACHE).

Third-party components retain their own terms. The original and source-derived
C-SDK inputs and corresponding source are included in this repository; read the
[source-availability notice](release/portable-csdk/SOURCE-AVAILABILITY.md),
[recorded changes](release/portable-csdk/CHANGES.md), and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

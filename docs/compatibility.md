---
title: Compatibility
description: What ami-rust 0.1 supports and what is outside its boundary.
---

This page is the boundary of what ami-rust 0.1 supports. Anything not listed as supported is outside the release, even if it happens to work.

## Supported

| Area | Supported in 0.1 |
| --- | --- |
| Target system | PC x86-64 AROS, in two ABI profiles: `x86_64-unknown-aros-abi1` (ABI-v1) and `x86_64-unknown-aros-abi11` (ABI-v11). See [targets and ABIs](/targets-and-abis/). |
| Development hosts | macOS 26 on Apple Silicon, Ubuntu 24.04 on x86-64, Ubuntu 24.04 on ARM64. |
| Language surface | `no_std` and `alloc`. Allocation is available through `aros` when `entry!` installs `ExecAllocator`. |
| Toolchain use | Upstream `rustup` and ordinary Cargo. The SDK contains the matching compiler, Cargo, target libraries, a relocatable C SDK and the AROS link tools. |
| Execution evidence | Native runs of the qualified examples on both ABI profiles in the recorded [QEMU profile](/run-on-aros/#running-in-an-emulator). |

Native host build scripts and procedural macros need the normal native prerequisites for your host: Xcode Command Line Tools on macOS, or a C compiler, binutils and libc development packages on Ubuntu.

## Outside the 0.1 boundary

0.1 does not promise any of the following:

- full `std`;
- threads and networking;
- physical hardware, CPUs other than the qualified profile, or emulators other than the recorded one;
- AROS architectures other than x86-64;
- an AROS-hosted Rust compiler, Cargo or rustup;
- compatibility with arbitrary third-party crates. Crates that need `std`, or that assume an operating system API ami-rust does not provide, will not build.

Each of these needs its own target support and release documentation. See the [platform roadmap](/platform-roadmap/).

## What the limits mean for applications

The safe APIs keep native registries that grow on demand (release 0.1.0 used fixed ones, for example at most 16 open files and 8 messages). Their bounds are memory, a token space per kind and, for signals, the bits Exec leaves free; they are listed on the [`aros` guide](/api/aros/#errors-and-bounds). The guest image and emulator configuration used for qualification are records of how the release was tested. They are not memory limits or resource quotas for your application, which remains subject to ordinary AROS allocation failure.

## Versioning of the guarantee

The boundary above describes the tagged release. The public item signatures of `aros` and `aros-mui` are unchanged on `main` since that tag, and this documentation is built from `main`; see [releases and versions](/releases/).

---
title: Compatibility
description: What ami-rust 0.2 supports and what is outside its boundary.
---

This page is the boundary of what ami-rust 0.2 supports. Anything not listed as supported is outside the release, even if it happens to work.

## Supported

| Area | Supported in 0.2 |
| --- | --- |
| Target system | PC x86-64 AROS, in two ABI profiles: `x86_64-unknown-aros-abi1` (ABI-v1) and `x86_64-unknown-aros-abi11` (ABI-v11). See [targets and ABIs](/targets-and-abis/). |
| Development hosts | macOS 26 on Apple Silicon, Ubuntu 24.04 on x86-64, Ubuntu 24.04 on ARM64. |
| Language surface | `no_std` and `alloc`. Allocation is available through `aros` when `entry!` installs `ExecAllocator`. A toolchain that ships `std` also supports an experimental `std`: files, paths, time, random numbers, the environment and threads, behind `#![feature(restricted_std)]`. See [Rust std](/std/) for the surface, the limits and the known issues. |
| Toolchain use | Upstream `rustup` and ordinary Cargo. The SDK contains the matching compiler, Cargo, target libraries, a relocatable C SDK and the AROS link tools. |
| Application APIs | Nine safe crates, `aros`, `aros-mui`, `aros-timer`, `aros-graphics`, `aros-intuition`, `aros-asl`, `aros-locale`, `aros-icon` and `aros-workbench`, with the same items on both ABI profiles. See [choosing and using the crates](/consumer-guide/) and [ABI differences](/reference/abi-differences/). |
| Large files | 64-bit file sizes and positions on ABI-v1 through `dos64.library`. On ABI-v11 a size, position or offset beyond the 32-bit calls is the `Limit` error; see [large files](/api/aros/#large-files). |
| Execution evidence | Native runs of the qualified fixture modes and examples on both ABI profiles in the recorded [QEMU profile](/run-on-aros/#running-in-an-emulator). |

Native host build scripts and procedural macros need the normal native prerequisites for your host: Xcode Command Line Tools on macOS, or a C compiler, binutils and libc development packages on Ubuntu.

## Outside the 0.2 boundary

0.2 does not promise any of the following:

- in `std`: networking, processes, links, file locks and `env::current_exe`, which return `ErrorKind::Unsupported`; and the known issues that [Rust std](/std/#known-issues) lists;
- networking in any form;
- physical hardware, CPUs other than the qualified profile, or emulators other than the recorded one;
- AROS architectures other than x86-64;
- an AROS-hosted Rust compiler, Cargo or rustup;
- compatibility with arbitrary third-party crates. Crates that need `std`, or that assume an operating system API ami-rust does not provide, will not build.

Each of these needs its own target support and release documentation. See the [platform roadmap](/platform-roadmap/). The roadmap also says how far the work on `std` has come; it is not part of 0.2.

## What the limits mean for applications

The safe APIs keep native registries that grow on demand (release 0.1.0 used fixed ones, for example at most 16 open files and 8 messages). Their bounds are memory, a token space per kind and, for signals, the bits Exec leaves free; they are listed on the [`aros` guide](/api/aros/#errors-and-bounds). The guest image and emulator configuration used for qualification are records of how the release was tested. They are not memory limits or resource quotas for your application, which remains subject to ordinary AROS allocation failure.

## Which release this describes

The boundary above describes release 0.2.0, and this documentation is built from its tag; see [releases and versions](/releases/).

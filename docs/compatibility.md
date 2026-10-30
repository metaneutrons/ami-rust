---
title: SDK compatibility boundary
---

# SDK compatibility boundary

ami-rust 0.1 supports cross-compilation to PC x86-64 AROS in two target
profiles:

| Target | AROS ABI |
| --- | --- |
| `x86_64-unknown-aros-abi1` | ABI-v1 |
| `x86_64-unknown-aros-abi11` | ABI-v11 |

The same application source selects a profile with Cargo's `--target` option.
It does not use a feature flag to choose the ABI.

## Supported development hosts

The versioned SDK is produced for Apple Silicon macOS and for x86-64 and ARM64
Linux. Development uses upstream `rustup` and ordinary Cargo. The SDK includes
the matching Rust compiler, Cargo, target libraries, a relocatable C SDK, and
the required AROS link tools.

Applications require `no_std`; `alloc` is available through `aros` when the
entry macro installs `ExecAllocator`. Native host build scripts and procedural
macros require the normal native prerequisites: Xcode Command Line Tools on
macOS or the standard compiler, binutils, and libc development packages on
Ubuntu.

## Outside the 0.1 boundary

The initial release does not promise full `std`, threads, networking, physical
hardware support, non-x86-64 AROS targets, an AROS-hosted Rust compiler, or
compatibility with arbitrary third-party crates. Those extensions require their
own target support and release documentation.

The guest image and emulator configuration used for release qualification are
maintainer records. They are not SDK memory limits or application resource
quotas. Applications remain subject to ordinary AROS allocation failure and
the documented limits of each safe API.

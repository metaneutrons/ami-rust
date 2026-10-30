---
title: Platform roadmap
---

## Initial release

Version 0.1.0 targets PC x86-64 AROS ABI-v1 and ABI-v11 through the canonical
`x86_64-unknown-aros-abi1` and `x86_64-unknown-aros-abi11` targets. The
supported cross-development hosts are macOS Apple Silicon, Linux x86-64, and
Linux ARM64. All three hosts produce both AROS targets from the same pinned
input contract.

## Next targets

Additional AROS targets are independent ports, not aliases of x86-64:

1. define and qualify the target ABI and linker contract;
2. produce matching `core`, `alloc`, startup, and C-SDK components;
3. add native runtime and memory qualification on real or emulated hardware;
4. extend rustup distribution metadata without changing existing toolchain
   identities.

AArch64 is the next likely target. RV32 remains exploratory until AROS itself
has a stable ABI and bootable baseline for it.

## Native AROS toolchain

Running rustc, Cargo, and rustup on AROS requires a separate host port. It needs
process, filesystem, networking, dynamic-loading, and update semantics that are
not established by the cross-compiler. Native x86-64 and native AArch64 host
support therefore have their own acceptance work and cannot be inferred from a
successful cross-build.

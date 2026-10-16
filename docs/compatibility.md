# Exact candidate compatibility boundary

Target: PC x86-64 AROS ABI-v1 native ELF, the qualified QEMU boot profile.
No other ABI/CPU combination or physical machine is supported by this evidence.
The complete target JSON and host component file/symlink inventories are in the
authenticated SDK contract. Selection fails on any changed or missing input.

| Input | Qualified identity |
| --- | --- |
| Production candidate macOS host | macOS 26, Apple Silicon, standard GitHub-hosted macos-26 runner; actual protected replay pending |
| Production candidate Linux host | Ubuntu 24.04, x86-64, glibc, standard GitHub-hosted runner; actual protected replay pending |
| Consumer interpreter | pinned standalone CPython 3.12.15 on both hosts, archive/runtime hashes in release/ci-python-inputs.json; bootstrap uses an existing Python 3.10+ |
| Rust | nightly-2026-09-18; commit 330d317121e16b5db8e5adc63595910528ff2ee7; LLVM 23.1.1; paired rust-src |
| Cargo | source 3efb1f477e99b42974b982d939fd100303cdf7db plus recorded ami-rust-reproducible-cross-v1 and paths-v3 producer patches; per-host binary digest in component inventory |
| Native C toolchain | aros-toolchains v0.1.4, pc-x86_64, LLVM 11.0.0; unchanged per-host inventories |
| Native collector | aros-tools v0.3.19, selected bin/aros-collect; unchanged per-host inventories |
| AROS C SDK | source-derived portable x86-64 ABI-v1 Developer tree, complete distinct component inventory; release/portable-csdk/spec.json pins the unchanged original and derived input; protected two-host derivation pending |
| Boot image | SHA-256 9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1, 143360000 bytes |
| QEMU | 11.1.2; pc-i440fx-11.1, qemu64-v1, TCG single, one CPU, 512 MiB RAM, no network, immutable ISO, full 512 MiB FAT test medium |

The inherited local candidate passed on macOS 26.5.1 and CachyOS Linux
7.2.3-1 (glibc 2.44), using their recorded Python 3.15/3.14 identities. Those
interpreter identities are historical evidence, not the production selection.
The production profile above requires its own protected replay before support
is advertised. The immutable boot image and ABI baseline remain unchanged.

Each component is separately provisioned and never silently obtained by a build
or uninstall. The release inventory describes SDK/reference payloads; it does
not bundle the Rust compiler, native compiler, complete C SDK, collector or
vendor directory. The documented preparation command obtains and verifies the exact declared
prerequisites through their recorded producers, without modifying global rustup. Availability of a local prerequisite map
does not establish an externally usable public download or a publisher identity.

Core and alloc, the bounded task-affine facade, synchronous callbacks, file I/O,
libraries, signals, local ports/messages and fixed-buffer diagnostics are within
the measured subset. std, threads, networking, native rustc on AROS, arbitrary
crates, other Amiga operating systems and hardware support remain excluded.

Rust and C dependency licenses are component-specific. First-party dual licensing
does not replace AROS, LLVM/compiler runtime or dependency conditions. The signed
license review must clear every shipped source/binary before R1 qualification.

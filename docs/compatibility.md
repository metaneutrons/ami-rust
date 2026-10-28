# SDK compatibility boundary

Target: PC x86-64 AROS ABI-v1 native ELF, the qualified QEMU boot profile.
No other ABI/CPU combination or physical machine is included in this scope.
The complete target JSON and host component file/symlink inventories are in the
authenticated SDK contract. Selection fails on any changed or missing input.

| Input | Selected identity |
| --- | --- |
| Production macOS host profile | macOS 26, Apple Silicon, standard GitHub-hosted macos-26 runner |
| Production Linux host profiles | Ubuntu 24.04, x86-64 or ARM64, glibc; distinct host SDK inventories |
| Consumer tools | Upstream rustup and normal Cargo; no Python interpreter, CPython bootstrap or public ami-rust CLI |
| Rust | nightly-2026-09-18; commit 330d317121e16b5db8e5adc63595910528ff2ee7; LLVM 23.1.1; paired rust-src |
| Cargo | 1.99.0, source 3efb1f477e99b42974b982d939fd100303cdf7db plus recorded producer patches; per-host binary digest in the authenticated inventory |
| Native C toolchain | Pinned host-specific LLVM cross-tools for pc-x86_64; exact profiles in tooling/crates/aros-native-build/pins and authenticated SDK inventories |
| Native collector | Pinned host-native collector included in each SDK; exact bytes/profile in the authenticated host inventory |
| AROS C SDK | source-derived portable x86-64 ABI-v1 Developer tree, complete distinct component inventory; release/portable-csdk/spec.json pins the unchanged original and derived input |
| Boot image | SHA-256 9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1, 143360000 bytes |
| QEMU | 11.1.2; pc-i440fx-11.1, qemu64-v1, TCG single, one CPU, 512 MiB RAM, no network, immutable ISO, full 512 MiB FAT test medium |

The qualification profile uses a 128 KiB startup stack and requires measured
stack use of at most 96 KiB. These are stack conditions for this PC x86-64
ABI-v1 QEMU profile, not an application heap or whole-memory cap. Each release
must bind its qualification records to the exact source and candidate bytes.

The SDK contains paired rustc/Cargo, host libraries, AROS core/alloc, C SDK,
linker and native cross-tools. A normal application build does not download or
prepare missing compiler/C-SDK components. Native host build scripts and
procedural macros still require Xcode/Command Line Tools on macOS or GCC,
binutils and libc development files (`build-essential`) on Ubuntu.

Direct archives and Rustup components use a per-host signed file inventory.
The [source checkout guide](quickstart-toolchain.md) describes the public
boundary before the first release. The boot/ABI baseline above remains
unchanged; physical hardware, AROS-hosted Rust/Cargo/rustup and other CPU/ABI
targets require separate qualification.

Core and alloc, the bounded task-affine facade, synchronous callbacks, file I/O,
libraries, signals, local ports/messages and fixed-buffer diagnostics are within
the measured subset. std, threads, networking, native rustc on AROS, arbitrary
crates, other Amiga operating systems and hardware support remain excluded.

Rust and C dependency licenses are component-specific. First-party dual licensing
does not replace AROS, LLVM/compiler runtime or dependency conditions. The signed
license review must clear every shipped source/binary before release acceptance.


The 512 MiB guest is the repeatable qualification environment; it is not an
SDK-imposed whole-application quota. Allocation uses public Exec facilities and
remains subject to actual native out-of-memory and checked ownership failures.

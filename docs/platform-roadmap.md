---
title: Platform roadmap
---

## Releases so far

Versions 0.1.0 and 0.2.0 target PC x86-64 AROS ABI-v1 and ABI-v11 through the canonical
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

## Rust `std`

Full `std` is being built as its own release after 0.2. It is not part of 0.2.0,
and the release is not yet promised. The
[plan](https://github.com/metaneutrons/ami-rust/blob/main/docs/plans/ami-rust-std.md)
orders the work: runtime start-up, standard streams, arguments, environment and
panic handling first; then time, random numbers and the file system; then
threads and synchronisation, built on Exec tasks, signals and semaphores.
Networking and processes are deferred from the first `std` release.

Early work is already on the development branch and runs on both ABIs. It is
experimental and in no release, so until a `std` release exists ami-rust supports
`no_std` plus `alloc`, as the [compatibility](/compatibility/) page states.

### What works on the development branch

The results are the same on ABI-v1 and ABI-v11.

| Area | State |
| --- | --- |
| Starting a program | An ordinary `fn main` works. Returning from it is return code 0; an error returned from `main` is 10. A panic, an abort and an allocation that fails end the program with 20; a panic and a failed allocation also print their message on standard error. `process::exit(n)` ends it with `n`. AROS no longer shows its "Software Failure" requester and waits for a person. |
| Arguments and environment | `env::args`, and `env::var`, `set_var` and `remove_var` on the DOS variables of the process. `env::vars` is always empty, because the C library cannot list them. |
| Standard streams | Standard input, output and error. |
| Memory | `Vec`, `String`, `HashMap` and `format!`. A single allocation of more than 4 GiB fails, because the AROS allocator misbehaves for such requests. |
| Time | `Instant`, `SystemTime` and `thread::sleep`. `SystemTime` is correct until 7 February 2106, where the C library's clock wraps. |
| Files and directories | Open, create, read, write, seek, truncate, duplicate and remove files; file metadata (size, type, one date with a resolution of one second, read-only); `read_dir`, `create_dir`, `create_dir_all`, `remove_dir`, `remove_dir_all`, `copy` and `exists`. DOS requesters are switched off around path calls by default, so a missing volume is an error and not a wait for a person; `std::os::aros::fs::set_requesters(true)` turns them back on at any time (it needs `#![feature(aros_ext)]`). An empty path is an error, as on Unix. Volumes other than `RAM:` and files above 2 GiB were not tested. |
| Paths | `Path` knows AROS paths: the volume (`RAM:`) is the prefix, a path with one is absolute, and `Path::new("RAM:").join("x")` is `RAM:x`. `.` and `..` work in every path call although DOS knows neither; `std` resolves them by the name alone, without looking at the file system. `env::current_dir` and `set_current_dir`; `current_dir` reports the volume name (`RAM Disk:`), not the assign. `env::temp_dir()` is `T:`, path lists use `;`. Two slashes in a row are one, as on Unix; DOS reads them as the parent directory. |
| Random numbers | `HashMap` seeds and `std::random`. ABI-v1 uses the system's entropy source. ABI-v11 has none yet: it mixes a weak generator with the CPU's `RDRAND` instruction where there is one, and is weak without it, so `HashMap` there is not hardened against crafted keys. Not suitable for cryptography on either ABI. |
| Not yet | `rename`, `canonicalize`, symbolic links, file locks and setting file times, `env::current_exe`, threads (`thread::spawn` returns an error, and the synchronisation types are for one task), networking and processes. |

A program that uses `std` declares `#![feature(restricted_std)]`, which keeps `std`
on AROS visibly experimental. It also needs a locally prepared toolchain, because the
installed 0.2.0 toolchain has neither the patched `std` nor the target
specifications that this start-up needs. The recipe is in the
[`std-runtime` example](https://github.com/metaneutrons/ami-rust/blob/main/examples/std-runtime/README.md).
A crate that uses `aros::entry!` is a `no_std` program and does not combine with `std`;
a `std` program can still use the `aros` crate as a library.

## Native AROS toolchain

Running rustc, Cargo, and rustup on AROS requires a separate host port. It needs
process, filesystem, networking, dynamic-loading, and update semantics that are
not established by the cross-compiler. Native x86-64 and native AArch64 host
support therefore have their own acceptance work and cannot be inferred from a
successful cross-build.

---
title: STD-M1 spike findings
---

# STD-M1 spike: `std` compiles, links and runs a trivial call

Execution: https://github.com/metaneutrons/ami-rust/issues/66
Plan: [ami-rust-std](ami-rust-std.md), milestone STD-M1.
Measured on 2026-10-31 on a macOS ARM64 host with toolchain `0.1.0`
(`rustc 1.100.0-nightly (330d31712 2026-09-17)`, `rust-src` of
`nightly-2026-09-18`), branch `feat/std-m1-spike`. Everything below was run;
the last section lists what was not.

## Result against the acceptance criteria

| Criterion | Result |
| --- | --- |
| A1: reviewed, digest-pinned patch set for the five subsystems | Done as a spike: `host/std-aros/std-aros.patch`, SHA-256 `70c4875b…ad5`, bound by `host/std-aros/source.json`. 420 lines, 13 files, 284 lines added and 5 removed in `library/std`; three new files (alloc 78, io error 127, random 54 lines). Review of the content is still to be done. |
| A2: `-Zbuild-std=std,panic_abort` for both targets, offline, pinned sources only | Met. A patched copy of the pinned `rust-src` builds for `x86_64-unknown-aros-abi1` and `x86_64-unknown-aros-abi11` with an empty `CARGO_HOME`, the vendor directory of `rust-src` as the only crate source, `--offline --locked`; about 9 s per target. The pinned inventories of all three hosts list the same digest for every file the patch changes. |
| A3: native probe linked against the AROS C library calls an allocation and a write on both ABIs; linking decision recorded | Met. `examples/std-probe` runs to status 0 on both qualified images (below). The linking decision is under "Linking". |
| A4: only that `std` compiles, links and a trivial call runs | Met, and nothing more is claimed. |

Native runs used the maintainer harness `run-on-aros` with the pinned images
(ABI1 `aros-nx-abiv1-qualified.iso`, SHA-256 `9c89b548…47b1`; ABI11
`aros-pc-x86_64.iso`, SHA-256 `2228f09c…ccd7`). The probe printed all checks
`ok` and `NR-RC=0` on both. Probe binaries: ABI1 `59c979d7…3ec2`, ABI11
`3ceb8d38…dbfc`, built at scratch paths; the digests identify the runs and are
not a reproducibility claim (the full values are in the harness output:
`59c979d76e9a06fca96057eb170c1dc27747301669e37f934321ad7431503ec2` and
`3ceb8d38287431f0902ff62fb2f162f591a2b171f9041c0654616a2085b8dbfc`).

## Where the patch lives and how it is applied

`host/std-aros/` follows the `host/*/*.patch` precedent: a git-style diff,
`source.json` with the patch digest and the before and after digest of every
changed file, and a README with a script-free recipe. The patch is applied
with `patch -p1` from `lib/rustlib/src/rust` to a **copy** of the pinned
`rust-src`; nothing under `~/.rustup` is edited.

Pointing Cargo at the copy: `__CARGO_TESTS_ONLY_SRC_ROOT=<copy>/library`
works (it is the `library` directory itself, not its parent). It is Cargo's
test-only override and not a documented interface. The pipeline in STD-M7
should stage a private sysroot as `bare_target_producer.rs` already does for
`core,alloc`. The std vendor directory is not picked up from
`library/.cargo/config.toml` when the build runs elsewhere, so the build must
supply the source replacement itself, as the producer does in its
`CARGO_HOME/config.toml`.

A stale host build-script binary survived an edit of `std/build.rs` once in a
reused target directory (the std build then still carried the old `cfg`). Use
a fresh `CARGO_TARGET_DIR` when verifying the patch.

## Decisions for the five subsystems

- **Allocator** (`sys/alloc/aros.rs`): `malloc`, `calloc`, `realloc`, `free`
  and `posix_memalign` as `unix` does; `malloc` is used for alignments up to
  16 (`MIN_ALIGN`), which the probe checked for sizes 1 to 63. `posix_memalign`
  blocks are accepted by `free` but not by `realloc`, so over-aligned
  `realloc` uses the copy fallback. **Requests above 2^32 bytes are refused
  in `std`**: without the guard the pinned allocators misbehave on huge
  requests (see Risks).
- **I/O errors** (`sys/io/error/aros.rs`): the NetBSD errno numbering of AROS
  (identical in both trees), about 40 constants mapped to `ErrorKind`,
  `strerror` for text (no table). `errno` has two link names:
  `__stdc_geterrnoptr` on ABI1 and `___geterrnoptr` on ABI11, chosen with
  `target_abi`. `strerror_r` exists in the ABI1 SDK only, so the shared
  `strerror` is used; it is not thread safe.
- **Synchronisation** (`sys/sync`): the existing `no_threads` `Mutex`,
  `Condvar`, `RwLock` and `Once`. They refuse to build when the target
  declares threads, and every target without a `singlethread` flag does. The
  patch relaxes that guard to `all(target_has_threads, not(target_os =
  "aros"))` in five files and adds a comment. This is legitimate while
  `std` never creates a second thread: `thread::spawn` stays on the
  `unsupported` fallback and returns `Unsupported`, which the probe checks.
  It is not sound if user code shares `std` objects with tasks it creates
  itself. This is a first-cut decision for STD-M1 only; STD-M4 replaces it.
  The alternative (pthread-backed primitives) was rejected here because no
  pthread library is linked today (see Facts).
- **Thread-local storage** (`sys/thread_local`): the existing `no_threads`
  static storage, plus the same guard relaxation, plus AROS added to the
  selection list and to the no-op `guard::enable` list. Destructors never
  run; values are leaked at exit, as on the other single-task targets.
- **Random** (`sys/random/aros.rs`): `fill_bytes` mixes `clock_gettime` on
  `CLOCK_MONOTONIC` (value 0 on AROS) and `CLOCK_REALTIME` (value 2), a stack
  address, a heap address and a counter through SplitMix64. It is weak and
  documented as such; there is no `getrandom` or `getentropy` dependency. The
  `timespec` it declares (32-bit `time_t`, 64-bit `long`) was checked by the
  probe against the real C library on both ABIs.
- **`build.rs`**: AROS is added to the platforms without special
  requirements. Without it every user crate needs
  `#![feature(restricted_std)]`, which Cargo applies to all JSON targets.
  This is a policy choice that the maintainer may reverse; it changes
  nothing else.

Everything else (stdio, args, env, fs, time, thread, net, process, `pal`)
falls through to `unsupported`; the compile does not need more. At run time
these fail as the `unsupported` implementations do (below).

## Linking

**Decision: nothing changes in the linker recipe.** `aros-link` runs the
fixed collector with `--start-group` over the SDK libraries (ABI1: `-lstdc
-lposixc -lstdcio …`; ABI11: `-lcrt -lstdlib -lcrtprog …`). The `extern "C"`
declarations in `std` and in the probe are resolved by pulling members out of
those archives; no undefined symbol remains in either linked ELF
(`llvm-nm -u` is empty). `aros-link` accepted the `std` rlibs, the
`compiler_builtins` with `compiler-builtins-mem`, and its ELF audit passed.
The probe builds with the same `build.rs` (`aros_native_build::prepare`) as
`examples/minimal`.

Does linking `posixc` change the 0.1 start-up contract? A `no_std` program
does not pull `posixc` members, so it is unaffected. A `std` program pulls
them in and gains library requirements that the stock start-up opens
automatically:

| | `minimal` (no_std) | `std-probe` |
| --- | --- | --- |
| ABI1 | StdCBase, DOSBase, SysBase, TaskResBase, IntuitionBase | additionally **PosixCBase** and **StdCIOBase** |
| ABI11 | CrtBase, StdlibBase, DOSBase, SysBase, IntuitionBase | unchanged |

So on ABI1 a `std` program needs `posixc.library` to open at start-up; it did
on the qualified image, and the unchanged C start-up (`__startup_entry`,
`sdk_begin`, `rust_sdk_main`, `sdk_end`) reached status 0 on both ABIs. The
failure behaviour when `posixc.library` is absent was not tested.

Linking `-lpthread` would need an edit of the pinned collector recipe
(`recipe.rs`); ABI11 has no pthread library in its SDK at all.

## Start-up

STD-M2 decides who owns the task; this spike only shows what is possible.

- `aros::entry!` cannot be used with `std`: it defines a
  `#[panic_handler]`, and `std` provides one. A `std` program must export
  `rust_sdk_main` itself (`#[unsafe(no_mangle)] extern "C" fn`) and may call
  `aros::dispatch(application)`. That works on both ABIs with the global
  allocator being `std`'s `malloc` one, not `ExecAllocator`; `ctx.args()` also
  works (its first entry is the program name).
- A panic and `std::process::exit` hang the program natively on both ABIs,
  silently, with no message and no return status; `Instant::now()` (which
  panics on the `unsupported` time) did not return on ABI11. Reading `std`,
  all of these end in `core::intrinsics::abort`; the hang is presumably the
  resulting trap. The panic message goes to the `unsupported` stderr and is
  dropped. Allocation failure through `handle_alloc_error` was not tested.
  These came from a scratch variant of the probe that is not committed.
  STD-M2-A3 therefore has real work: `abort_internal`, `exit` and the panic
  path must reach `sdk_fatal` or `_Exit`.
- `std::env::var("PATH")` returns `NotPresent`, as the `unsupported`
  environment does.

## Facts about the SDK that differ from the plan

The plan's list of missing functions was derived from the `.conf` files. The
installed SDKs and the sources say more:

- ABI1: `libpthread.a` is a **static link library** built from
  `compiler/pthread/pthread.c`, not a library behind a `.conf`. It defines
  `pthread_detach`, `pthread_key_delete`, `pthread_rwlock_rdlock`,
  `pthread_rwlock_wrlock` and `sched_yield`, which the plan lists as missing.
  `strerror_r` and `getentropy` also exist in the ABI1 SDK stubs. It is not in
  the collector's library list today.
- ABI11: the SDK ships no `libpthread.a`, no `sched_yield`, no `strerror_r`
  and no `getentropy`; the Deadwood tree has `pthread.c`, but it is not in the
  pinned SDK. `fdatasync`, `poll`, `mmap`, `fork`, `posix_spawn`,
  `sigaltstack` and `getrandom` are absent in both SDKs.
- `time_t` is a 32-bit integer in both C libraries (`AROS_32BIT_TYPE`), so
  `SystemTime` through `clock_gettime` stops at 2038. `CLOCK_REALTIME`
  returned the Unix epoch (1 793 481 765 s on the day of the run), not the
  AROS epoch. Both matter to STD-M3.
- `malloc` allocates from a pool owned by the `StdCBase` of the opener, so a
  block freed by another task is a hazard. This is relevant for STD-M4.
- The C start-up demands a stack of exactly 131 072 bytes
  (`native/entry.c`); `std` code runs inside it.
- The linked probes are about 1.3 MB against 0.36 MB for `minimal`, with a
  24 KB text section. The cause (symbol and section overhead) was not
  investigated.

## Risks found

1. **The pinned allocators mishandle huge requests.** In a native probe,
   `alloc(2^37 + 16)` on ABI1 corrupted the Exec TLSF free lists
   (`free-list corruption at REMOVE_HEADER`, then a hang). On ABI11 requests
   of 2^38, 2^39, 2^40, 2^42, 2^44, 2^46 and 2^47 bytes returned non-null at
   the same low address each time after the block was freed, so evidently not
   a block of the requested size; the other sizes from 2^38 returned null.
   Requests of 2^29 to 2^36 returned null on both ABIs, as expected. Rust relies on a null return, so this is a memory-safety
   risk. The patch refuses requests above 2^32 bytes, and the probe tests
   `2^32+1`, `2^37+16`, `2^38+16` and `isize::MAX-7`. The defect itself
   belongs to the AROS baselines and is outside this repository.
2. **Abort, panic and `exit` hang the program** (Start-up). The `unsupported`
   behaviour is not acceptable beyond the spike.
3. **Soundness of the no-thread cut** depends on `thread::spawn` being
   unsupported and on users not sharing `std` objects across tasks they
   create. It is removed in STD-M4.
4. **Patch maintenance** matches the plan: 13 files, of which 10 are small
   edits to selection lists and guards that depend on the layout of
   `library/std/src/sys` at this nightly.
5. **`__CARGO_TESTS_ONLY_SRC_ROOT` is not a supported interface**; it can
   vanish with a Cargo update, which is a pin bump.
6. **LLVM elides unused allocations**: a first probe that allocated and freed
   without using the pointer reported success for every size. Tests of the
   allocator must `black_box` the pointer.

## Open decisions after this spike

- **Linking (STD-M1):** answered. No linker change; the C library members that
  `std` references are pulled from the existing group. The only behavioural
  change is the extra library requirements on ABI1 listed above.
- **Start-up ownership (STD-M2):** not answered. Evidence: `entry!` and `std`
  cannot coexist; an exported `rust_sdk_main` calling `aros::dispatch` works
  on both ABIs; the abort path must be wired to the native fatal path;
  whether `aros::Context` may be used from `std` code on another thread is
  untouched.
- **Thread functions (STD-M4):** not answered, but the premise changed. On
  ABI1 the five functions exist in the SDK link library, so the question is
  whether to link it and whether it is thread safe against `malloc`, `errno`
  and stdio. On ABI11 no pthread library ships, which is the actual blocker.

For STD-M2 to M4 the spike leaves: `stdio`, `args`, `env`, `exit` and the
panic path (all `unsupported` now); `time` on `clock_gettime`/`nanosleep`
with the 32-bit `time_t`; `fs` on `open`, `read`, `stat` and `opendir`
(struct layouts are the ABI-specific part and are untested); threads.

## Not verified

- Linux x86-64 and Linux ARM64 hosts, and the pinned authenticated pipeline;
  only a macOS ARM64 run with the installed toolchain and the vendor
  directory shipped in `rust-src`.
- The probe's own crates (`serde`, `sha2`, …, build dependencies of
  `aros-native-build`) came from the local Cargo registry cache, not from a
  vendor archive; only the library-only A2 build was done with an empty
  `CARGO_HOME`.
- A private-sysroot staging as an alternative to the Cargo test override.
- Failure behaviour when `posixc.library` is missing (ABI1), when memory is
  exhausted, or when allocation sizes between 2^30 and 2^32 are requested on
  small machines (QEMU memory size was not recorded).
- `strerror` text for codes other than 2, the full errno mapping, the quality
  of the random seed, and `realloc` of over-aligned blocks natively.
- Behaviour with more than one task, and the thread safety of the C library.
- The patch is not reviewed as a maintainer-accepted change; `source.json` is
  an inventory, not an authenticated pin recorded in the release inputs.
- The Rust `std` test suite, `clippy` and `-Zbuild-std` with `-Zjson-target-spec`
  as the producer passes it (the installed target specifications were used).

## Reproduce

See `host/std-aros/README.md` for the patched tree and the offline A2 build,
and `examples/std-probe/README.md` for the probe. Native runs:

```sh
run-on-aros abi1  "$work/probe-target/x86_64-unknown-aros-abi1/release/std-probe"
run-on-aros abi11 "$work/probe-target/x86_64-unknown-aros-abi11/release/std-probe"
```

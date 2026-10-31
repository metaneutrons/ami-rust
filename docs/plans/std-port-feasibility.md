---
title: Feasibility of a Rust std port for AROS
---

# Feasibility of a Rust `std` port for AROS

Status: analysis, 2026-10-31. Not a commitment and not part of the 0.2 plan.
Measured facts are marked as such; effort figures are the author's estimates.

## Question

How hard is it to make `std` available on AROS for x86-64, AArch64 and
ESP32-P4? Today ami-rust builds `core`, `alloc` and `compiler_builtins` from
the pinned `rust-src` (`-Zbuild-std=core,alloc`) and applications use the
`aros` crate.

## Measured starting point

All values were measured on `nightly-2026-09-18` and the 0.1.0 toolchain, which
both ship `library/std` sources.

**`std` does not build for an unknown OS.** Building a minimal `std` crate for
`x86_64-unknown-aros-abi11` with `-Zbuild-std=std,panic_abort` fails with 14
errors. Most subsystems (`fs`, `net`, `process`, `args`, `env`, `time`,
`stdio`, `pal`) fall back to the `unsupported` implementation. These five have
no fallback and need an AROS implementation or a selection entry:

1. `sys/alloc`: no allocator selected;
2. `sys/io/error`: no `errno`, `decode_error_kind`, `format_error` or
   `is_interrupted`;
3. `sys/sync` (mutex, condvar, once, rwlock): the `no_threads` implementation
   refuses to build on a target that declares threads;
4. `sys/thread_local`: no key implementation;
5. `sys/random`: no `fill_bytes`.

**Size of existing ports** (lines of Rust across all `sys/` subsystems):
`unix` 13 608, `uefi` 5 432, `sgx` 4 080, `xous` 2 786, `solid` 2 292,
`motor` 2 122, `hermit` 1 588, `itron` 1 090, `vexos` 937, `zkvm` 326, `wasi`
315, `teeos` 275, and the shared `unsupported` code 1 748. A purpose-built
port for a small OS is typically 1 000 to 3 000 lines; reusing the `unix`
implementation means supplying the C surface it expects.

**What AROS provides (C library).** AROS-NX has 844 exported C functions in
`stdc`, `posixc` and `pthread`; Deadwood has 819. Against 38 functions that a
Unix-style `std` relies on, both lack the same 12 (Deadwood also lacks
`getentropy`):

`pthread_detach`, `sched_yield`, `pthread_key_delete`,
`pthread_rwlock_rdlock`, `pthread_rwlock_wrlock`, `fdatasync`, `poll`, `mmap`,
`fork`, `posix_spawn`, `sigaltstack`, `getrandom`.

Eleven of these are declared but reserved (commented out) in `posixc.conf`; only `getrandom` is absent altogether. Present and
sufficient for a first port: `malloc` family, `read`/`write`/`open`/`lseek`,
`stat`/`fstat`, `opendir`/`readdir`, `rename`, `unlink` (alias of `remove`),
`getenv`/`setenv`, `clock_gettime`, `nanosleep`, `pthread_create`/`join`/`self`,
`pthread_key_create`, mutexes and condition variables.

Sockets are not in the C library. They go through `bsdsocket.library`
(AROSTCP); the C library only tracks descriptors for it. Process creation has
no `fork` or `posix_spawn`; the native mechanisms are `Execute`,
`SystemTagList` and `CreateNewProc`.

**Other facts.** The ABI differences found for 0.2 (SMP fields in exec
structures, `timeval32`) matter to a `std` port only where it touches those
structures directly. A C-library-based port does not. ABI1 and ABI11 are
therefore a small additional cost for `std`, not a separate port.

## Approaches

**A. Reuse the `unix` implementation by adding AROS to the `libc` crate.**
Gives `fs`, `time`, `thread` and more at once, but `unix` expects a Linux-like
surface of hundreds of symbols and types. Each missing item becomes a compile
error spread over about 13 600 lines, and the `libc` crate is an external
dependency of `std`. Not recommended.

**B. A purpose-built `sys` module on the AROS C library.** A small set of
hand-declared `extern "C"` functions (about 60), selected by `target_os =
"aros"`, for the five mandatory subsystems plus `fs`, `env`, `args`, `time`,
`stdio` and `thread`. Networking and process remain `unsupported` at first.
Recommended.

**C. A purpose-built `sys` module on Exec and DOS directly.** Independent of
the C library, but `std` sits below the `aros` crate, so the bridge would be
duplicated. Only worthwhile if the C library proves unreliable.

## Staged plan for approach B (x86-64)

Estimates are for one engineer who knows the repository, in weeks, with the
stated confidence.

| Stage | Content | Estimate | Confidence |
| --- | --- | --- | --- |
| 0 | Target gains `target_os = "aros"`, `std` builds with the five mandatory subsystems stubbed (allocator on `malloc`, minimal errors, `no_threads` sync, no TLS, weak random); patch applied to `rust-src` | 1 to 2 | medium |
| 1 | stdio, args, env, time, fs, panic=abort, `main` and `lang_start` coexistence with `aros::entry!`, a qualification application | 3 to 5 | medium |
| 2 | Threads, mutex, condvar, rwlock, TLS on `pthread_*` plus the missing functions (`pthread_detach`, `sched_yield`, `pthread_key_delete`, rwlock), which need AROS library changes | 3 to 6 | low |
| 3 | Networking through `bsdsocket.library` | 4 to 8 | low |
| 4 | `process::Command` through `SystemTagList` | 2 to 4 | low |
| 5 | Pipeline: add `std` and `panic_abort` to the pinned, authenticated target library build, update pins and release notes | 2 to 3 | medium |

Stages 0 and 1 give a useful `std` (collections, strings, formatting, files,
time) and are the sensible first commitment: roughly 4 to 7 weeks.
Stage 2 depends on changes inside AROS, not on Rust.

## Recurring costs and risks

- **Patch maintenance.** `std`'s `sys` layout changes between nightlies. A
  pinned nightly with a narrow patch set is manageable; each bump needs a
  rebase. The unknown-OS build errors above are a direct example.
- **Upstreaming.** A tier-3 target with named maintainers is possible and
  removes the patch, but needs a stable target and a maintained toolchain
  recipe. It is optional and later.
- **Unwinding.** Only `panic=abort`, as for the rest of ami-rust.
- **Two programming models.** `std` presumes it owns the task, while the
  `aros` crate's `Context` is task-affine. Coexistence rules (which one starts
  the program, whether `std` threads may use `Context`) must be designed in
  Stage 1.
- **Testing.** The `std` test suite cannot run on AROS; qualification is by
  our own applications in the pinned images.

## Per architecture

### x86-64

The reference. ABI1 and ABI11 share approach B; differences show up only in
Stage 2 if exec structures are touched. Effort as in the table; the
prerequisite (a qualified AROS runtime on both ABIs) already exists.

### AArch64

AROS-NX contains `aarch64-all`, `aarch64-raspi` and a `rpi-aarch64` target in
its toolchain lock, and the `posixc` and `stdc` libraries have an `aarch64-all`
directory. The library call convention passes the base as the last argument,
as on x86-64 ABI1. QEMU provides the `raspi*` machines for qualification
(checked for availability locally).

The Rust side is small once x86-64 works: a target specification, `compiler_builtins`
and the pipeline for a second architecture, the same `sys` module. The author
estimates 4 to 8 weeks in addition to x86-64. The real precondition is not
Rust but AROS: this analysis did not verify that the AArch64 port boots to a
qualified `dos.library` and `posixc.library`. Qualify the runtime first, as
M1 of 0.1 did for ABI11, before planning the Rust port.

### ESP32-P4

Two different questions:

1. **`std` on the P4 with ESP-IDF.** Already exists upstream: the tier-3
   targets `riscv32imafc-esp-espidf` (and `riscv32imac-`, `riscv32imc-`)
   have a `std` that uses ESP-IDF's newlib and FreeRTOS (`target_os =
   "espidf"`, `target_env = "newlib"`). The P4 has an `imafc` core, so this
   needs no work in this repository. It is not AROS.
2. **`std` on AROS for the P4.** The local `AROS-ESP32` is a bare-metal AROS
   kernel and exec port (`arch/riscv-esp32p4`), currently with SMP semaphore
   and task-record work under review. There is no evidence yet of
   `dos.library`, a C library, a file system or a network stack on it, and the
   P4 has no on-die radio (it needs a companion chip). The Rust side would
   need a new `riscv32imafc-unknown-aros` target on top of
   `riscv32imafc-unknown-none-elf`, 64-bit atomics by emulation, an AROS
   RISC-V32 library call backend, and exec SMP semantics for `std::thread`
   across two harts.

The Rust work would be similar to the AArch64 case. The AROS prerequisites are
months away, and they dominate. Recommendation: do not plan a `std` port for
this target until `AROS-ESP32` has a qualified `dos` and `posixc`. For Rust on
the P4 today, use the ESP-IDF target, or `no_std` with a bare-metal target.

## Recommendation

1. Do not include `std` in 0.2 (no change to its plan).
2. Treat Stages 0 and 1 for x86-64 as a candidate for 0.3: they are about 4 to
   7 weeks, depend on no AROS changes, and the five mandatory subsystems are
   small and measurable.
3. Decide on Stage 2 (threads) only after asking what the AROS libraries
   will change: three missing functions block `std::thread`.
4. Treat AArch64 and ESP32-P4 as blocked on AROS qualification, not on Rust.

## Method

- `std` build probe: a scratch crate with `-Zbuild-std=std,panic_abort`
  against the 0.1.0 toolchain for `x86_64-unknown-aros-abi11`; errors grouped
  by file.
- Port sizes: `find` and `wc -l` over `library/std/src/sys` by OS name.
- C library coverage: names parsed from `posixc.conf`, `posixc_lfa.conf`,
  `stdc.conf` and `pthread.conf` at AROS-NX `e0d5e36` and Deadwood `fbc242c`,
  including `.alias` entries and excluding reserved (commented) vectors.
- Target list and cfg: `rustc --print target-list` and `--print cfg` on
  `nightly-2026-09-18`.

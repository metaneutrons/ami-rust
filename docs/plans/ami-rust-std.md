---
title: ami-rust std initiative plan
---

# Initiative plan: Rust `std` for AROS

Epic: pending (created from this plan; the URL is added after creation)
Decision state: proposed; acceptance by the maintainer is recorded under
"Decision changes"

## Outcome and boundaries

Applications for PC x86-64 AROS shall be able to use Rust's `std` on the
canonical `x86_64-unknown-aros-abi1` and `x86_64-unknown-aros-abi11` targets,
with `panic=abort`, delivered in the pinned, authenticated toolchain. A
second and a third target (AArch64, ESP32-P4) are tracked behind explicit
gates because their precondition is an AROS runtime, not Rust work.

The measured baseline on 2026-10-31 (toolchain 0.1.0, `nightly-2026-09-18`
sources) is recorded in
[the feasibility analysis](https://github.com/metaneutrons/ami-rust/blob/750fdfe91501e391a9523ce496de520094d9ec5d/docs/plans/std-port-feasibility.md):

- The target builds `core`, `alloc` and `compiler_builtins` only
  (`-Zbuild-std=core,alloc`). The target specification sets `target_os =
  "aros"`, `panic = "abort"`, no `target_family` and no `target_env`.
- `-Zbuild-std=std,panic_abort` fails with 14 errors. Five `std` subsystems
  have no fallback for an unknown OS: allocator, I/O errors, synchronisation
  primitives, thread-local keys and random. All others fall back to the
  `unsupported` implementation.
- The AROS C libraries (`stdc`, `posixc`, `pthread`) export 844 functions in
  AROS-NX and 819 in Deadwood. Against the 38 functions a Unix-style `std`
  relies on, both lack the same 12 (Deadwood also lacks `getentropy`):
  `pthread_detach`, `sched_yield`, `pthread_key_delete`,
  `pthread_rwlock_rdlock`, `pthread_rwlock_wrlock`, `fdatasync`, `poll`,
  `mmap`, `fork`, `posix_spawn`, `sigaltstack` and `getrandom`.
- Sockets are provided by `bsdsocket.library`, not the C library; there is no
  `fork` or `posix_spawn`.

In scope: a `sys` implementation for `target_os = "aros"` on the AROS C
library, the patch and build pipeline that delivers it, coexistence with the
`aros` crate, qualification on both ABIs, and documentation.

Non-goals: unwinding (`panic=abort` only), running the `std` test suite on
AROS, upstreaming `std` support to `rust-lang/rust`, changes to the
AROS-NX or Deadwood trees as a deliverable of this initiative, and new
`aros-*` library crates (0.2 plan).

## Design and decisions

**Approach.** A purpose-built `sys` module for `target_os = "aros"` on the AROS
C library, with a small hand-declared set of `extern "C"` functions (about 60),
selected by `cfg`, and the `unsupported` implementation for everything not yet
implemented. Alternatives considered and rejected in the analysis:
reusing the `unix` implementation by adding AROS to the `libc` crate (about
13 600 lines expecting a Linux-like surface), and a module on Exec and DOS
directly (duplicates the bridge, because `std` sits below `aros`).

**ABI policy.** ABI1 is the upstream standard; ABI11 is Deadwood's AROS port
and is supported alongside it. The `sys` module calls C functions, so the
ABI differences found for 0.2 (SMP fields in exec structures, `timeval32`)
matter only where a structure is touched directly; such a case is declared
ABI-specific and appears on the ABI differences page. ABI1-only items are not
removed to obtain a common subset.

**Delivery of the `std` sources.** The pinned toolchain already ships
`rust-src` and builds from it. The `std` change is a narrow patch set against
that pinned source, applied and verified by digest in the build pipeline, with
precedent in the pinned `host/*/*.patch` files. No unpinned source and no
network access enter the build. Each nightly pin bump re-applies the patch
set; a bump is a separate reviewed change.

**Open decisions, each resolved in the named milestone** and then recorded
under "Decision changes":

- STD-M1: how a program links the AROS C library (SDK stubs and `aros-link`)
  from Rust, and whether linking `posixc` changes the 0.1 start-up contract;
- STD-M2: which component owns the task at start-up when both `std` and
  `aros::entry!` are present, and whether `aros::Context` may be used from a
  `std` program;
- STD-M4: for each missing thread function (`pthread_detach`, `sched_yield`,
  `pthread_key_delete`, the two rwlock functions) whether `std` implements a
  substitute or the pinned AROS baseline must change. A change to a pinned
  baseline is out of scope of this initiative; it blocks the affected
  feature, not the others.

**Gated targets.** AArch64 and ESP32-P4 are not planned as work until their
gate holds: a qualified AROS runtime with `dos.library` and a C library on
that architecture. A gate is evidence, recorded in the milestone, not a date.
For ESP32-P4, `std` already exists upstream through ESP-IDF
(`riscv32imafc-esp-espidf`); that is not AROS and not part of this plan.

**Common acceptance (C).** Every functional milestone must meet:

- C1: Each added `std` feature is exercised by a qualification application
  that runs to completion on the ABI1 and ABI11 native baselines, with
  recorded binary and image identities.
- C2: Unsupported operations return `io::ErrorKind::Unsupported` (or the
  documented panic or abort for infallible APIs), never undefined behaviour,
  and each is listed in the documentation.
- C3: The patch set applies cleanly to the pinned source, is pinned by digest,
  and the build is reproducible on the three supported hosts once STD-M7 has
  landed.
- C4: The `aros` and `aros-mui` crates keep working unchanged on both ABIs
  (no regression of 0.1 and 0.2 behaviour).
- C5: Documentation states what is and is not supported, per ABI.

## Delivery and acceptance

### STD-M1: `std` compiles and links on both ABIs

Execution: pending
Dependencies: none

- STD-M1-A1: A reviewed, digest-pinned patch set adds an AROS selection to the
  five subsystems without a fallback: allocator on `malloc`, I/O error
  mapping, synchronisation primitives, thread-local keys and random.
- STD-M1-A2: `-Zbuild-std=std,panic_abort` succeeds for both targets from the
  pinned sources, offline and with no source outside the pins.
- STD-M1-A3: A native probe linked against the AROS C library from Rust
  calls an allocation and a write on both ABIs; the linking decision is
  recorded.
- STD-M1-A4: This milestone does not yet require a `fn main` program or
  `println!`; it requires only that `std` compiles and links and that a trivial
  call into it runs on both ABIs.

### STD-M2: Runtime start-up, stdio, args, env and panic

Execution: pending
Dependencies: STD-M1

- STD-M2-A1: Resolve the start-up ownership decision. A `fn main` program and
  an `aros::entry!` program both work, and what mixing them means is
  documented and tested, including exit status.
- STD-M2-A2: `std::io::{stdin, stdout, stderr}`, `std::env::args`,
  `std::env::var` and `set_var`, and `std::process::exit` work on both ABIs.
- STD-M2-A3: A panic aborts through the existing fatal path, with the message
  on standard error and a non-zero exit status.
- STD-M2-A4: `Vec`, `String`, `HashMap` and `format!` work, and allocation
  failure behaves as documented in C2.

### STD-M3: Time, random and file system

Execution: pending
Dependencies: STD-M2

- STD-M3-A1: `Instant`, `SystemTime` (with the AROS epoch converted and
  tested), and `thread::sleep` without threads on both ABIs.
- STD-M3-A2: `std::fs` file open, read, write, seek, metadata, directory
  iteration, create, remove and rename on a RAM disk, and `std::path`
  with AROS path syntax documented.
- STD-M3-A3: `HashMap` seeding uses the best available entropy and the
  quality is documented; there is no `getrandom` and no assumption of one.
- STD-M3-A4: Behaviour that differs between ABIs (for example `FIBB_HOLD`) is
  declared ABI-specific.

### STD-M4: Threads and synchronisation

Execution: pending
Dependencies: STD-M3

- STD-M4-A1: Verify in both pinned baselines that the C library is
  thread-safe enough for `std` (allocator, stdio, `errno`), by test, and record
  the result.
- STD-M4-A2: Resolve each missing function decision (see open decisions).
- STD-M4-A3: `thread::spawn`, `join`, `park`, `yield_now`, `Builder` stack size,
  `thread_local!`, `Mutex`, `Condvar`, `RwLock`, `Once` and `mpsc` channels work
  on both ABIs with a documented thread limit.
- STD-M4-A4: A thread panic aborts the program as under C2, and no thread or
  key leaks across normal exit; the `aros` task-ownership rules are not
  violated and the interaction is documented.

### STD-M5: Networking

Execution: pending
Dependencies: STD-M2 (STD-M4 for blocking calls across threads)

- STD-M5-A1: `TcpStream`, `TcpListener` and `UdpSocket` over
  `bsdsocket.library`, with the library opened and closed per program and a
  documented behaviour when no network stack is installed.
- STD-M5-A2: Name resolution through the library, with its limits documented.
- STD-M5-A3: A loopback test passes on both ABIs; unsupported socket options
  return `Unsupported`.

### STD-M6: Processes

Execution: pending
Dependencies: STD-M2

- STD-M6-A1: `process::Command` on `SystemTagList` and `CreateNewProc` with
  arguments, working directory, environment where AROS allows it, exit
  status and captured output.
- STD-M6-A2: Features AROS cannot provide (`fork`, signals, `exec` replacing
  the process) return `Unsupported` and are listed in the documentation.
- STD-M6-A3: A native test runs a child on both ABIs.

### STD-M7: Toolchain pipeline and documentation

Execution: pending
Dependencies: STD-M1 and the features accepted so far

- STD-M7-A1: The authenticated, pinned target-library build adds `std` and
  `panic_abort` for both targets; the patch digest, inputs and outputs are
  pinned in the existing release inputs, and the three-host build matches.
- STD-M7-A2: Direct and rustup installation of the candidate deliver `std`
  and keep the existing `no_std` workflow working.
- STD-M7-A3: The installation, build-system, targets and ABIs, compatibility and
  troubleshooting guides and a new `std` guide describe the supported
  surface, the limits and the `no_std` alternative; compiled examples cover
  both modes.
- STD-M7-A4: The maintenance procedure for a nightly pin bump (re-applying
  the patch set) is documented in `CONTRIBUTING.md` and exercised once.

### STD-M8: Qualify and prepare the `std` release candidate

Execution: pending
Dependencies: STD-M1 through STD-M4 and STD-M7; STD-M5 and STD-M6 as accepted

- STD-M8-A1: Build the exact candidate on macOS ARM64, Linux x86-64 and Linux
  ARM64 for both targets.
- STD-M8-A2: Run the qualification applications for every accepted feature on
  the pinned ABI1 and ABI11 baselines and record source, toolchain, image,
  binary and evidence identities.
- STD-M8-A3: The supported-surface table in the documentation matches the
  tested behaviour, including every `Unsupported` item and every ABI
  difference.
- STD-M8-A4: Publication stays a separate maintainer decision. The release
  and the version it ships in are decided by the maintainer; this plan does
  not fix a version number.

### STD-M9: AArch64 (gated)

Execution: pending
Dependencies: STD-M8 and the gate

- STD-M9-A1: Gate: evidence that an AROS AArch64 runtime boots on a pinned
  image to a qualified `dos.library` and `posixc.library`, recorded with
  image and binary identities. Without it this milestone stays not started.
- STD-M9-A2: A target specification and target library build for AArch64 on
  the same `sys` module, with `compiler_builtins` and the pipeline for a
  second architecture, reproducible on the supported hosts.
- STD-M9-A3: The qualification applications of STD-M8 pass on the AArch64
  baseline (QEMU `raspi4b` or `raspi3b` unless hardware is qualified).

### STD-M10: ESP32-P4 (gated)

Execution: pending
Dependencies: STD-M8 and the gate

- STD-M10-A1: Gate: evidence that the AROS port for ESP32-P4 provides a
  qualified `dos.library`, a C library, a file system and a memory model, and
  defines SMP task semantics sufficient for threads. Without it this
  milestone stays not started and the recorded recommendation is to use
  the upstream ESP-IDF target or `no_std`.
- STD-M10-A2: A `riscv32imafc` target specification with 64-bit atomics by
  emulation, an AROS RISC-V32 library call backend and the pipeline, if
  and only if A1 holds.
- STD-M10-A3: The STD-M8 qualification applications pass on the qualified
  runtime.

The initiative is complete when STD-M1 to STD-M4, STD-M7 and STD-M8 are
accepted against the same plan revision and exact candidate, and STD-M5 and
STD-M6 are accepted or explicitly deferred by the maintainer with the reason
recorded. STD-M9 and STD-M10 are gated, do not block completion, and are
tracked by their own issues.

## Migration, risks and verification cost

The principal risks are the maintenance of a patch set against a moving
nightly, the unresolved linking and start-up decisions (STD-M1, STD-M2), thread
safety of the C library in the pinned baselines (STD-M4), and the lack of
`fork`, `poll`, `mmap` and signals, which limits `std` features rather than
blocking them. Additive `std` support does not change the `no_std` workflow,
and the patch set can be removed without changing `aros` or `aros-mui`.
Estimates are in the analysis (about 4 to 7 weeks for STD-M1 to STD-M3,
low-confidence ranges for later stages); no calendar is accepted before the
STD-M1 measurements exist. Native dual-ABI checks run at each functional
milestone; the three-host matrix runs at STD-M8.

## Decision changes

- 2026-10-31: Proposed. Open questions for the maintainer: acceptance of the
  scope and order, whether STD-M5 (networking) and STD-M6 (processes) are in
  the first `std` release, and the target release for the first accepted
  candidate.

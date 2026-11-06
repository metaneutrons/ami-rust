---
title: STD-M2 findings
---

# STD-M2: runtime start-up, stdio, args, env and panic

Execution: https://github.com/metaneutrons/ami-rust/issues/67
Plan: [ami-rust-std](ami-rust-std.md), milestone STD-M2.
Measured on 2026-11-06 on a macOS ARM64 host with the released toolchain `0.2.0`
(`rust-src` of `nightly-2026-09-18`) and the patch in `host/std-aros/`. Everything
under "Verified" was run natively on the pinned ABI-v1 and ABI-v11 images; the last
sections list what was not, and what is still to be decided.

## Status

All four criteria are met on both ABIs, with the limits listed at the end. `exit`,
`abort`, panic and allocation failure no longer hang the program, a program with an
ordinary `fn main` starts, and arguments, standard input and output, standard error
and the environment work. The maintainer accepted the start-up design on 2026-11-06.

| Criterion | State |
| --- | --- |
| A1: start-up ownership; `fn main` and `aros::entry!` both work | Met. Decision and evidence below. |
| A2: `stdin`, `stdout`, `stderr`, `env::args`, `env::var`, `set_var`, `process::exit` on both ABIs | Met. `env::vars()` is always empty (the C library cannot list DOS variables). |
| A3: a panic aborts through the fatal path, message on standard error, non-zero status | Met on both ABIs: return code 20, the message on standard error, no requester. |
| A4: `Vec`, `String`, `HashMap`, `format!`; allocation failure as documented | Met: an infallible allocation that fails prints the message and ends with code 20; `try_reserve` returns an error. |

## What the "hang" was

`std::process::exit`, a panic and `std::process::abort` all ended in the
instruction `ud2`: for an unknown OS, `sys/exit.rs` falls back to
`core::intrinsics::abort()`, and so does `sys::pal::abort_internal`. AROS answers
an illegal instruction with its **"Software Failure!" requester** ("Error 0x80000004
– Illegal instruction"), which waits for a person to click *Suspend* or *Reboot*. A
program started from a script never returns. There is no kernel exception in the
serial log, because it is a task alert.

With `panic = "abort"` the abort is done by the `panic_abort` crate, which calls
`std::rt::__rust_abort`, which calls `sys::pal::abort_internal`. So one function
covers `abort`, every panic and every failed infallible allocation, and
`panic_abort` needs no patch.

## Verified

The test program is `examples/std-runtime` (listed as in development under #67); the
table of expected results is in its README. All 12 modes return the same on both
ABIs, and the stack variants listed below were run in addition.

- **`process::exit(n)`** flushes pending standard output, releases what the program
  holds (`sdk_end`) and leaves with `_Exit(n)`. The AROS return code is `n` as it is:
  0, 3 and 5 were tried. The native contract that only 0, 10 and 20 are valid
  applies to returning from the native `main`, not to `_Exit`.
- **`abort_internal`** calls the native `sdk_fatal`, which records `ami-rust fatal 2`,
  releases what the program holds and ends with code 20. The reason code 2 stands
  for "std abort" (the `aros::entry!` panic handler uses 1).
- **Panic message.** The default hook prints `thread '<unnamed>' (1) panicked at
  src/main.rs:…` and the message to standard error before the abort.
- **Allocation failure.** `Vec::with_capacity(1 << 33)` and a push print `memory
  allocation of 8589934592 bytes failed` and end with code 20; this is the 2^32
  guard of #113. `Vec::try_reserve` of the same size returns `Err`, and of 64 KiB
  succeeds.
- **Standard streams** use the file descriptors 0, 1 and 2 of the C library.
  `read_line` on redirected input returns the line and then 0 bytes.
- **Environment.** `var`, `var_os`, `set_var` and `remove_var` work, an empty name or
  a name with `=` is `NotPresent`, and a DOS variable set by the shell
  (`SetEnv AMI_OUTSIDE …`) is visible. `set_var` writes a variable that is local to
  the process.
- **Stack.** The runtime works with the 128 KiB stack that ABI-v1 requires, also for
  the panic path, and on ABI-v11 with 128 KiB and with 1,000,000 bytes. ABI-v1
  refuses a different stack with code 20, as documented.

## Facts that matter later

- The AROS C library numbers its `open` flags differently from Linux:
  `O_RDONLY` is 1, `O_WRONLY` 2, `O_CREAT` 0x40, `O_TRUNC` 0x200, `O_APPEND` 0x400,
  identical in both SDKs. STD-M3 (`fs`) must use these values.
- The AROS shell cannot redirect standard error (`2>` is not understood). A test
  that needs the message redirects descriptor 2 itself with `open` and `dup2`, and
  the script prints the file afterwards.
- `getenv` is backed by `GetVar` and `setenv` by `SetVar` with `GVF_LOCAL_ONLY`, so
  the environment of a program is its DOS variables. The C library keeps no
  `environ` array that could be listed through a plain symbol, which is why
  `env::vars()` is empty.
- Reading standard input blocks when the console has no input. That is the
  expected behaviour of a console, not a hang of the runtime.

## STD-M2-A1: start-up ownership (decided 2026-11-06)

Every program that links the toolchain gets the native C `main`. It runs
`sdk_begin`, calls `rust_sdk_main`, runs `sdk_end` and maps the result to 0, 10 or
20. A normal `fn main` crate makes rustc emit its own symbol `main`, which would
collide with it.

**Decision.** The native `main` stays the only owner of the task.

- The nightly supports the target option `entry-name`. Both pinned target
  specifications set it to `ami_rust_entry`, so rustc generates that name for a
  `fn main` crate instead of `main`. A `#![no_main]` program with `aros::entry!` is
  unchanged.
- The patched `std` defines `rust_sdk_main`. It calls the renamed entry with the
  `__argc` and `__argv` that the C start-up stored, so `env::args` works and the
  one claim of the `aros` context stays free for the program.
- **Exit status.** `Ok` is 0 and an error returned from `main` is 10. A panic, an
  abort and a failed infallible allocation are 20. `process::exit(n)` and
  `ExitCode::from(n)` give `n` as it is, except that 1 is reported as 10 (it is
  what an error returned from `main` gives, and `ExitCode::FAILURE`). The native
  contract that only 0, 10 and 20 may be returned stays, so any other code leaves
  through `process::exit`.
- **`aros::Context`** is usable from a `std` program on the main task, through the
  one claim that `aros::dispatch` makes.
- **Mixing.** `fn main` and `aros::entry!` in one crate do not compile (`E0152`,
  duplicate lang item `panic_impl`: both define the panic handler). A crate with
  `entry!` is a `no_std` program. Using `aros` as a library from a `fn main` program
  is fine.

The alternative, a `std` runtime that calls `sdk_begin` itself with the native
`main` as a weak symbol, was not taken: it would move ownership into `std` and
change the pinned C bridge.

**What it changes.** The two target specifications (one line each), their digests
and byte sizes in `release/rust-production-contract.json`, the pins in
`aros-native-build`, and four digests that depend on them in the Rust sources of
`aros-native-build` and `xtask`. No C source changes. The frozen-contract check and
all tests of the two crates pass. The specification changes the bytes of an input
that the release pipeline pins, so the authenticated target-library build and the
qualification have to run again with it before a release; whether the pinned
library digests stay the same was not checked here.

**Verified.** With a local copy of the `0.2.0` toolchain that has the new
specifications and an `aros-link` built from this tree, `examples/std-runtime` and
`examples/std-probe` are ordinary `fn main` programs. They build and link, the
final ELF has one `main` (the native one), `ami_rust_entry` and `rust_sdk_main`, and
all 18 modes of `std-runtime` give the results in its README on both ABIs: 0 for
success, 10 for `Err`, 7 for `ExitCode::from(7)`, 20 for a panic, 3 for
`process::exit(3)`; `env::args` returns the program name and the arguments whole;
`aros::dispatch` from `fn main` gives a working context.

## Not verified

- Linux hosts and the authenticated pipeline; only a macOS ARM64 run.
- Interactive standard input from the console, and very large writes.
- `env::vars()` (always empty), and `set_var` visibility in child processes (STD-M6).
- Behaviour with more than one task (STD-M4).
- The authenticated target-library build with the changed specifications (see A1).
- The tests run by hand with the recipe in the README; the native matrix cannot
  build the patched `std` yet (STD-M7).

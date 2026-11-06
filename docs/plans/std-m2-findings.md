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

First slice. `exit`, `abort`, panic and allocation failure no longer hang the
program, and standard input and output, standard error and the environment work.
The start-up ownership decision (STD-M2-A1) and `std::env::args` are not done.

| Criterion | State |
| --- | --- |
| A1: start-up ownership; `fn main` and `aros::entry!` both work | **Open.** A mechanism is verified at the compiler level (below); the decision is the maintainer's. |
| A2: `stdin`, `stdout`, `stderr`, `env::var`, `set_var`, `process::exit` on both ABIs | Met, except `env::args` (needs A1) and `env::vars()`, which is always empty. |
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

## STD-M2-A1: start-up ownership (not decided)

Today every program that links the toolchain gets the native C `main`. It runs
`sdk_begin`, calls `rust_sdk_main` (supplied by Rust), runs `sdk_end` and maps the
result to 0, 10 or 20. A normal `fn main` crate makes rustc emit its own symbol
`main`, which would collide with it.

**Verified mechanism.** The nightly supports the target option `entry-name`. With
`"entry-name": "ami_rust_entry"` in a copy of the ABI-v1 target specification, rustc
emitted `ami_rust_entry` for a `fn main` crate where the stock specification emits
`main`. That checked only the symbol, with `--emit=obj`; a program was not linked and
run this way.

**Proposed design** (for the maintainer to decide):

1. Keep the native `main` as the only owner of the task. Set `entry-name` in both
   pinned target specifications. A program with `fn main` then gets a renamed entry;
   a `#![no_main]` program with `aros::entry!` is unchanged.
2. The patched `std` supplies `rust_sdk_main`: it calls the renamed entry with the
   program's `argc` and `argv` (so `env::args` works), and returns the exit status.
3. Exit status of `fn main`: `Ok` is 0 and an error is 10 (`AppStatus::Error`);
   `process::exit(n)` passes `n` as it is, as verified above; a panic or abort is 20.
4. `aros::Context` stays usable from a `std` program on the main task, through the
   one claim that `aros::dispatch` makes today. Mixing `fn main` with `aros::entry!`
   in one crate is a compile error (both define the panic handler); using `aros`
   as a library from a `fn main` program is fine.

**Consequences.** It changes the pinned target specifications and their pins in
`aros-native-build`, so it belongs to the `std` release (a new toolchain), as the plan
already says. It changes no C source. The alternative, a `std` runtime that calls
`sdk_begin` itself and turns the native `main` into a weak symbol, would move
ownership into `std` and change the pinned C bridge.

## Not verified

- Linux hosts and the authenticated pipeline; only a macOS ARM64 run.
- Interactive standard input from the console, and very large writes.
- `env::vars()` (always empty), and `set_var` visibility in child processes (STD-M6).
- Behaviour with more than one task (STD-M4).
- A `fn main` program, `env::args` and the entry rename (A1).
- The tests run by hand with the recipe in the README; the native matrix cannot
  build the patched `std` yet (STD-M7).

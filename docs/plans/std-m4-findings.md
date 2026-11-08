---
title: STD-M4 findings
---

# STD-M4: threads and synchronisation

Execution: https://github.com/metaneutrons/ami-rust/issues/69
Plan: [ami-rust-std](ami-rust-std.md), milestone STD-M4.

Findings of STD-M4, measured on the pinned ABI-v1 and ABI-v11 images with probe programs and
`examples/std-threads`. Every number below comes from a run; what was read from source is marked.

## Status

| Criterion | State |
| --- | --- |
| A1: the C library is thread-safe enough (allocator, stdio, `errno`), by test | Met with a decision: allocator and raw stdio are, `errno` is not and is read under a lock (below). |
| A2: a substitute for each missing pthread function | Does not apply: `std` builds on Exec, not pthreads (decision of 2026-11-08). |
| A3: `thread::spawn`, `join`, `park`, `yield_now`, stack size, `thread_local!`, `Mutex`, `Condvar`, `RwLock`, `Once`, `mpsc` on both ABIs, with a documented limit | Met in the first slice (`examples/std-threads`, 43 checks on each ABI). Limit: at least 1000 threads at once with the default 256 KiB stack. |
| A4: a thread panic aborts the program, no thread or key leaks across exit, task ownership documented | Partly met: the panic ends the program (code 20, at the main task's next safe point), slots are no longer left behind, threads end before the program. Open: memory that ABI-v1 does not get back (see "Open findings"). |

## What was measured before the design

Probes with real DOS processes (`CreateNewProc`) and temporary bridge functions, removed afterwards.

- **`errno`** is one variable for the whole program: every task gets the same address, on both ABIs.
  The C library's base is a global variable of the program (`StdCBase`, `errno` at offset 216, on
  ABI-v1; `CrtBase` on ABI-v11). Three tasks making failing calls for 3 s at once:
  - no lock: ABI-v1 225 of 229 wrong in the task that called `open()`; ABI-v11 30 of 9.6 million;
  - `Forbid()` around the call and the read: ABI-v1 still 214 of 218 wrong; ABI-v11 0 of 5 million.
    ABI-v1's `open()` sets `errno` and then frees memory to a pool, which can wait, and a wait lets
    other tasks run (`compiler/crt/posixc/__fdesc.c`, read);
  - a lock inside the program around the call and the read: 0 wrong on both, two runs each. Under
    contention ABI-v1 managed about 100 locked calls per second per task, ABI-v11 about 10000.
- **Semaphores** exclude (40000 of 40000 increments with, 20000 without), shared mode overlaps readers
  and keeps a writer out; **signals** wake a waiting process; **task storage slots** give every process
  its own value, start at 0, more than 5000 are available, freed ones are reused. They are in
  `task.resource` on ABI-v1 and in exec.library 51 on ABI-v11.
- **Processes**: 300 started and ended with 16 KiB stacks; a 2 MiB stack worked.
- **`Forbid()` and a wait**: a task that waits inside `Forbid()` lets the others run (2.9 million
  iterations of another task during a 300 ms sleep).
- **Ending while a thread runs**: a thread that runs on after its program returned crashed ABI-v1 once
  the memory was reused (two of two runs); ABI-v11 did not crash in two runs but kept some memory.
- **A thread that called `exit` or panicked** through the bridge of 0.2: ABI-v1 crashed the system,
  ABI-v11 ended only that thread and the program went on.

## The design

- A thread is a DOS process made by the bridge (`sdk_thread_spawn`), which keeps a record of it and
  ends it in its own trampoline under `Forbid()`, so the program can be unloaded only after the last of
  its code has run.
- When the program ends, every thread gets Ctrl-F and ends at its next safe point (a wait in a lock,
  `join`, `sleep`, `yield_now`, a C library call of `std`); the main task waits for all of them. A
  thread that never reaches one keeps the program waiting; that is the documented rule.
- A thread's `process::exit` or panic records the code, ends the thread, and the main task ends the
  program at its next safe point with that code.
- The futex is a list of waiters under `Forbid()` with a signal each; timeouts through timer.device.
  It also wakes on Ctrl-F, so a thread blocked in a lock or a channel ends when the program ends.
- `errno` is read under a lock of the program, taken only once a thread exists; the lock hands itself
  to the waiters in order, because a lock that the releasing task could take back starved the others
  (measured: one call in 3 s for two of three threads).
- Thread-locals are key based (`thread_local!` without native TLS) on task storage slots. The bridge
  frees its slots when the program ends, after clearing the main task's values: the program runs in
  the shell's process, which keeps them. Measured before: about five slots were left per run, and the
  slot number sizes every task's storage array.
- `yield_now`: Exec has no yield. Setting the own priority, also lower and back, did not let the other
  thread run (2 of 4000 turns); `Delay(0)` did, at a timer tick (about 10 ms) per call; marking the time
  slice over and a switch pending (`SysFlags`, `AttnResched`, private in `exec/execbase.h`) and calling
  `Permit()` did, at about 3 microseconds (4000 of 4000 turns). The last is used.
- Every program links the bridge, so the thread code states no library version to the linker: the
  versions it would state (33 for semaphores, 51 for task storage on ABI-v11) would raise the
  requirement of programs without threads and made the linker warn in every build. The semaphores are
  not used; task storage on ABI-v11 is called through its vectors after a version check at run time.

## Differences from other systems

- The current directory and the local DOS variables are per DOS process, so per thread; a new thread
  starts with copies of its parent's.
- The program ends after its threads, not by killing them; a busy thread delays the end.
- A thread's `exit` or panic ends the program at the main task's next call into `std`.
- An error from a failed read or write of a descriptor in a threaded program may carry another
  thread's code.
- `available_parallelism()` is 1: the images run on one CPU.

## Open findings

- **Memory on ABI-v1, before this work.** With the bridge of `main` (no thread code), ABI-v1 has less free
  memory after every program run: about 32 KB for a `no_std` program and about 204 KB for a `std` program
  (`Avail FLUSH TOTAL`, six runs each). ABI-v11 loses nothing. Not yet reproduced with a plain C program, so
  not reported.
- **Memory per thread.** On ABI-v1 a run of 1000 threads costs about 300 KB more than a run without threads
  (three batches of three runs: 888, 890 and 889 KB); ABI-v11 about 30 to 90 KB. Not yet explained; the
  bridge frees its records, and task.resource frees a task's slots when the task is removed (read).
- **A page fault on ABI-v1 in `Avail FLUSH`.** After `slots`, `tls` twice, `spawn` and nine runs of the
  1000-thread mode, the third `Avail FLUSH` faulted in two of three boots (null read, two different
  addresses outside the program; logs `20261108-132152-abi1-56553` and `20261108-132406-abi1-58556`). Nine
  runs of the 1000-thread mode alone, then `Avail FLUSH`, did not fault in two boots. Cause unknown.

## Not verified

- More than one CPU.
- A thread that is busy for a long time when the program ends (the rule is measured for 1.5 s).
- Thread priorities (not offered).
- Linux hosts and the authenticated pipeline.

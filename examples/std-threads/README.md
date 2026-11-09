# std-threads

Native test of threads in `std` on AROS: spawning and joining, `Mutex`, `Condvar`, `RwLock`, `Once`,
`OnceLock`, `LazyLock`, `Barrier`, parking, channels, `thread_local!`, errors from several threads at
once, `yield_now`, the thread limit, and every way the program can end while threads run. One
behaviour per run, chosen by the first argument. Like the other `std` programs it is not a workspace
member: it needs a toolchain that ships `std`, built from this tree (see `examples/std-runtime/README.md` for the build). The native matrix (`tools/native-matrix.mjs`) runs every mode on both ABIs; the set-up and expected result of each mode are in `tests/programs.json`.

The program must start in `RAM:ami-rust-m1/` (`MakeDir`, `CD`); the `errors` mode makes files there.

## How threads work on AROS

A thread is a DOS process, made and ended by the native bridge. The findings and the measurements
behind every choice are in `docs/plans/std-m4-findings.md`; in short:

- `Mutex`, `Condvar`, `RwLock`, `Once` and parking are `std`'s own futex implementations, on a futex
  that the bridge makes from Exec signals.
- `thread_local!` uses task storage slots; a thread's values are destroyed when it ends.
- The C library has one `errno` for the whole program, so `std` reads it under a lock once a thread
  exists. Reads and writes of descriptors are not under the lock, because they can wait for a person:
  an error from a failed read or write in a threaded program may carry another thread's code.
- The current directory and the local DOS variables belong to the DOS process, so each thread has
  its own; a new thread starts with copies of its parent's.
- The default stack is 256 KiB; `Builder::stack_size` and `RUST_MIN_STACK` choose another.
- `available_parallelism()` is 1.

## How the program ends

AROS cannot stop a task from outside, and a thread that runs on after its program has been unloaded
runs freed code (measured: a page fault on ABI-v1). So:

- The program ends only after all of its threads. When the main task ends, every thread ends at its
  next safe point: a wait in a lock, a channel, `park`, `join`, `sleep`, `yield_now`, or a file, path
  or environment call. A thread that never reaches one keeps the program waiting.
- `process::exit` in a thread, and a panic in a thread, record the code (20 for a panic) and end that
  thread. The main task ends the program at its next safe point. A main task that only computes keeps
  running until it reaches one.

## Modes and results

All twelve modes with checks pass on both ABIs: 43 checks on each.

| Mode | Checks | What it covers |
| --- | --- | --- |
| `spawn` | 10 | spawn and join with a value, ten threads, names, ids, a 4 MiB stack, `available_parallelism`, `thread::scope`, a detached thread, `is_finished` |
| `mutex` | 4 | four threads, 80000 increments, `try_lock` while held and after, a `Barrier` of four |
| `condvar` | 4 | producer and consumer, `wait_timeout` (300 ms), `notify_all` to three waiters, `wait_timeout_while` |
| `rwlock` | 3 | readers overlap, a writer is alone, every write is there |
| `once` | 3 | `Once`, `OnceLock` and `LazyLock` with six threads racing |
| `park` | 3 | park until unpark, `park_timeout` (200 ms), an unpark before the park |
| `channel` | 3 | three senders and 3000 messages, a bounded `sync_channel`, `recv_timeout` |
| `tls` | 4 | each thread's own value, the main thread's value, destructors at thread exit, 20 more threads |
| `errors` | 1 | three threads making three different failing file calls for 3 s: every error is the thread's own |
| `process` | 6 | a thread's own current directory and variables, a new thread inherits its parent's, 150 lines of `println!` from three threads |
| `yield` | 1 | with two threads taking turns, the other ran before (almost) every turn |
| `limit` | 1 | threads with the default stack until spawning fails or 1000 are running, all joined; 1000 on both ABIs |

The ways of ending print, then end in their own way. They were run with another program and a
pause after them, to show that nothing is left running:

| Mode | What happens | Return code |
| --- | --- | --- |
| `end-main-waiting` | the main task returns while threads wait in a channel, a lock and `sleep` | 0 |
| `end-main-busy` | the main task returns while a thread computes for 1.5 s; the program waits for it | 0 |
| `end-thread-exit` | a thread calls `process::exit(7)` while the main task sleeps in a loop | 7 |
| `end-thread-exit-join` | the same while the main task is blocked in `join` | 9 |
| `end-thread-panic` | a thread panics while the main task takes a lock in a loop | 20 |
| `end-main-panic` | the main task panics while a thread waits | 20 |

`slots` prints the number of the next free task storage slot. Run before and after other programs in one
boot, it stays the same (10 on ABI-v1, 3 on ABI-v11); before the bridge freed its slots it grew by about
five per run. It is also the program without threads that the memory figures are compared with.

## ABI differences

| | ABI-v1 | ABI-v11 |
| --- | --- | --- |
| Task storage | `task.resource` | exec.library 51, called after a version check |
| Memory not returned per run | 168 KB for every program that references the POSIX layer, also without threads (#131); 123 bytes per thread | none without threads; about 7 bytes per thread |

Every check gives the same result on both ABIs.

## Open findings

See "Open findings" in `docs/plans/std-m4-findings.md`:

- 123 bytes per thread that ABI-v1 does not return (about 7 on ABI-v11), and the 168 KB per run of every
  program that references the POSIX layer on ABI-v1, which is not from threads (#131).
- A page fault in `Avail FLUSH` on ABI-v1 after repeated runs of programs that start threads, in one to
  two of three boots; the same loop without threads did not fault in five boots (#132). It also happens with plain DOS processes that call `malloc`, with no thread code of `std` (5 of 27 boots).

## Not verified

- More than one CPU.
- A thread that is busy for long when the program ends.
- Panic messages on standard error: the test shell cannot redirect standard error, so only the bridge's
  line `ami-rust fatal in a thread` is seen in the log.

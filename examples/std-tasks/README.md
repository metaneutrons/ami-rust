# std-tasks

Native test of what a second AROS task can do with the C library that `std` is built
on. It is the evidence for the question that a `std` thread implementation has to
answer first: can tasks share the C library's allocator, `errno` and standard output?

It creates real DOS processes with `CreateNewProc` and uses the C functions directly. It
does not use `std::thread`, which does not exist on AROS yet. Like the other `std`
programs it is not a workspace member: it needs the patched `std` of `host/std-aros/` and
a toolchain whose target specifications rename the entry (see
`examples/std-runtime/README.md` for the build). It is listed as in development under
#69 because the native matrix cannot build it yet.

## Modes

Run once per mode, as `std-tasks MODE`, with the stack that `std-runtime` describes. Each
prints one `RESULT` line.

| Mode | What it does |
| --- | --- |
| `cross` | The main task allocates 512 blocks and fills them. A second task checks and frees them, allocates 512 of its own, and the main task checks and frees those. |
| `stress` | Three tasks (the main task and two processes) each allocate and free 60,000 blocks of varying size and check a pattern in every block, while the scheduler preempts them. |
| `errno1` | One task only: sets `errno`, calls `malloc` and `free`, and reads `errno` back, 30,000 times. |
| `errno` | The same in three tasks at once, each with its own values. |
| `errnoaddr` | Each task reports the address that the C library gives it for `errno`. |
| `stdio` | Three tasks each write 150 lines to standard output with `write(1, ...)`. |

## Results

Observed on the pinned ABI-v1 and ABI-v11 images, identical on both:

| Mode | Result |
| --- | --- |
| `cross` | `ok`: memory allocated by one task is freed by another without error |
| `stress` | `ok`: no null return and no corrupted block in 180,000 allocations |
| `errno1` | `ok`: `errno` survives `malloc` and `free` |
| `errno` | **fails**: between 72,000 and 85,000 of 90,000 reads (it varies from run to run) see another task's value |
| `errnoaddr` | all three tasks get the same address: `errno` is one variable, not one per task |
| `stdio` | `ok`: all 450 lines arrive whole and in order within each task, and the output of the tasks interleaves (448 switches), so the writes did overlap |

## What this does and does not show

- The C library allocator is usable from several tasks. In `cross` and `stress` no block
  was corrupted, and a block freed by another task is accepted.
- `errno` is shared by all tasks. A `std` thread implementation cannot rely on
  `io::Error::last_os_error()` to return the error of the call that it just made unless it
  protects the call and the read of `errno` together, or avoids `errno` where DOS gives the
  error code directly.
- Raw writes to descriptor 1 are safe from several tasks. This is not the same as `println!`,
  which also goes through state of `std` that is not safe for several tasks yet.
- The images run on one virtual CPU, so tasks are time-sliced and preempted but never
  truly parallel. Behaviour on several CPUs is not shown.
- Only the allocator that `std` uses (`malloc` and `free`) was tested, from processes
  made by `CreateNewProc`. Tasks made with `AddTask` or `NewCreateTaskA`, and the
  `aros::Context` rules for other tasks, were not tested.

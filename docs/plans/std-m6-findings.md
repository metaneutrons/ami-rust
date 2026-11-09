# STD-M6: processes, findings

Written 2026-11-10. `std::process::Command` on AROS, measured on the two pinned boot images with `examples/std-process`.
The design decisions are the maintainer's go on 2026-11-09 ("M6 zuerst"); the choices below were made in the work and
are recorded here so they can be reviewed.

## What was built

- **Bridge.** `sdk_proc_run` in `tooling/crates/aros-native-build/native/sdk.c` loads a program with `LoadSeg`, starts it
  with `CreateNewProc` (`NP_Seglist`, `NP_Arguments`, the three streams, `NP_NotifyOnDeath`, `NP_ExitCode`), waits for
  `SIGF_CHILD` and returns the return code. `sdk_proc_streams` gives the caller's `Input()`, `Output()` and `ErrorOutput()`
  so that a child inherits the parent's streams and not those of the helper process.
- **`std`.** `sys/process/aros.rs` in the patch. A command is run by a thread of `std`, which sets the child's current
  directory and DOS variables and then calls the bridge. `Process` is a state shared with that thread; `try_wait` reads it.
  `Stdio::piped()` is a file in `T:`. The patch has 41 files (the five obsolete `no_threads` edits were dropped with this
  change; see `docs/plans/std-m7-findings.md`, A4).

## Decisions and what they rest on

1. **No shell.** The first version called `SystemTagList`. It failed on arguments: the AROS shell ends a quoted word at an
   escaped quote (`*"`) when it scans for a comment, so `"quote*"inside" "semi;colon"` lost everything after the semicolon
   (checked by bisection on both images), and a `>` in an argument would have been run as a redirection. `CreateNewProc`
   with `NP_Arguments` hands the C start-up the argument string unchanged: 29 awkward arguments (spaces, quotes, `*`, tabs,
   line feeds, `;`, `>`, `<`, `$`, `|`, an empty one, text above 127) arrive as given on both ABIs.
2. **A process per child, started from a thread.** The child is a DOS process, so a crash does not take the parent with it
   (not provoked), several run at once (three children of 2 s each finished in under 5 s), and `RunCommand` and its stack
   swap in the helper are avoided. The thread makes the current directory and the variables per child without touching the
   parent's: a thread is a DOS process with its own (`docs/plans/std-m4-findings.md`).
3. **Pipes are files in `T:`.** The images have no `PIPE:` handler (not in the device list), so a pipe that both sides use at
   once is not available. What the child writes is read after it has ended, and what is written to its input is given to it
   when the input is closed, which is when it starts. This covers `output()`, `wait_with_output` and the usual
   write-then-read use; it deadlocks, as a full pipe would, for a program that waits for the child's output before it closes
   the child's input.
4. **`kill` and `env_clear` are `Unsupported`.** No process id of the child is known to the parent (the helper thread
   holds it), and DOS has no kill; a break signal would not end a program that ignores it. `env_clear` cannot be done: DOS
   variables cannot be listed.
5. **The program lookup is the parent's.** `spawn` looks for the program as given and in `C:` with `fs::metadata` and
   returns `NotFound` itself, because the child starts later in another process. The command path of the shell is not searched.

## Measured

- `std-process`, 11 modes, 61 checks, all passing on ABI-v1 and ABI-v11 (final build, one boot each). The thread modes
  `spawn mutex condvar rwlock once park channel tls` still pass on both ABIs without the obsolete edits (43 checks).
- **Stderr:** a child's standard error follows `NP_Error`, and a parent can capture it separately from the output (`stdio`).
- **Return codes:** 0, 5, 7, 10, 20, 100, 255 arrive as given; a child that returns 1 is reported as 10 (the rule of
  `std-runtime`).

## Problems met, and what they teach

- **A cached `std` hides edits.** With `__CARGO_TESTS_ONLY_SRC_ROOT`, Cargo does not notice a change to the `std` source and
  builds are stale until the target directory is deleted. Several measurements were repeated after this was found; the
  figures in the README of the example come from clean builds. The bridge has the same trap: after a change of `sdk.c`,
  delete the target directory too (the build script is cached with its staged copy of the bridge).
- **The temporary input file was deleted before the child opened it.** The pipe's drop removed it while the child had not
  started yet (DOS error 205 from `wait`). The shared state now keeps the file until the child has ended.
- **Waiting for the exit code is too early.** `NP_ExitCode` runs while the process still holds its files. A caller that went
  on at once sometimes found its own program missing on ABI-v1. Waiting for `NP_NotifyOnDeath` helped but did not remove it.

## Open

- **[#140](https://github.com/metaneutrons/ami-rust/issues/140): ABI-v1 can report an existing program as not found** by
  `stat("NATIVERUN:prog")` for about a second after another child ended: 8 failures in about 50 runs of the `wait` mode
  before the death notification, 3 in 151 after it, none in the last 100. The cause is unknown. The lookup is the one place
  where this shows; a child that fails to load would show it too.
- **Not provoked:** a child that crashes; a child that reads the screen or a window; programs on volumes other than `RAM:`,
  `C:` and the delivery volume; more than one CPU.
- **Not yet run:** the native matrix for `std-process` (it is listed in `tests/programs.json` and needs a toolchain that
  ships this patch), and the three-host build of the changed libraries.

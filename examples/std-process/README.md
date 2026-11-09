# std-process

Native test of `std::process::Command` on AROS: starting a program, its arguments, its current directory
and variables, its standard streams, its return code, and what happens when it cannot be started. One
behaviour per run, chosen by the first argument. The program starts itself as the child (the `child-*`
modes), so it needs no other program. Like the other `std` programs it is not a workspace member: it needs
a toolchain that ships `std` (see `examples/std-runtime/README.md` for the build). The native matrix
(`tools/native-matrix.mjs`) runs every mode on both ABIs; the set-up and expected result of each mode are in
`tests/programs.json`.

The run must create `RAM:ami-rust-m1` (`MakeDir`), start in it (`CD RAM:ami-rust-m1`) and use `Stack 131072`,
as the other `std` programs do.

## How a child is started

The program is loaded with `LoadSeg` and started with `CreateNewProc`, with its arguments in `NP_Arguments`:
there is no shell. The first version used `SystemTagList`, which reads the command line with the shell, and
that did not hold: the shell ends a quoted word at an escaped quote (`*"`) when it looks for a comment, so
`"quote*"inside" "semi;colon"` lost everything after the semicolon, and a `>` in an argument would have been
a redirection. Without the shell every argument arrives as it was given.

## Modes and results

All 10 modes with checks pass on both ABIs: 61 checks on each.

| Mode | Checks | What it covers |
| --- | --- | --- |
| `basic` | 6 | `Echo` through `output`, `status` of a program in `C:`, the program itself as a child |
| `exitcodes` | 10 | return codes 0, 1 (reported as 10, as for `main`), 5, 7, 10, 20, 100 and 255, `success` |
| `args` | 3 | 29 awkward arguments (spaces, quotes, `*`, tabs, line breaks, `;`, `>`, `<`, `$`, `|`, braces, an empty one, text above 127) arrive as given; a `>` did not redirect; a `;` in an argument is text |
| `cwd` | 5 | the child starts where the parent is, `current_dir` moves it, the parent stays; a missing directory and a file as directory are errors from `spawn` |
| `env` | 6 | the child sees the parent's variable, one set for it, not a removed one; the parent sees none of it; `env_clear` is `Unsupported` |
| `stdio` | 8 | piped input reaches the child, piped output and error are separate, a null output and input, the output of one child as the input of the next, the error to the parent's output, a `File` as a stream is `Unsupported` |
| `notfound` | 5 | a missing program, a missing path, a directory, an empty name, a nul byte in an argument |
| `wait` | 9 | `spawn` returns at once, `try_wait` while it runs, `kill` is `Unsupported`, `wait` returns after the child, twice, `id` differs |
| `concurrent` | 4 | three threads each run a child; three children at once (2 s each, done in under 5 s) |
| `lookup` | 5 | a program in `C:` by its name, in another case, by its full path, in the child's directory, by a relative path |
| `end-child-running` | | the parent returns while a child sleeps for a second; the program ends after it |

## Differences between the ABIs

None found: every check gives the same result on ABI-v1 and ABI-v11.

## Not verified

- Programs that read the console, windows, or anything else that needs the screen.
- Programs from another volume than `RAM:`, `C:` and the delivery volume.
- More than one CPU.
- That nothing is left running after `end-child-running` (the threads' `end-*` modes were checked with another
  program run after them; this one was not).
- A child that crashes. The bridge reports 20 when the process ends without DOS having called the exit code (by reading
  the code, not by a run); whether a crashed process ends at all, or leaves the parent waiting, was not provoked.

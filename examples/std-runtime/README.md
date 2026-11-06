# std-runtime

Native test for the edges of a `std` program on AROS: how it starts, exits,
aborts and panics, what happens when an allocation fails, and how arguments, the
standard streams and the environment behave. Each run does one thing, chosen by
the first argument.

It is an ordinary `fn main` program. Like `std-probe`, it is not a workspace
member: it needs the patched `std` of `host/std-aros/` and a toolchain whose
target specifications rename the entry that rustc generates (see below). It is
listed as in development under #67 because the native matrix cannot prepare
either yet; that is STD-M7.

## How a `fn main` program starts

The native C `main` of the toolchain stays the only owner of the task: it opens
the runtime (`sdk_begin`), calls `rust_sdk_main`, closes the runtime (`sdk_end`) and
returns the status. For a program with `fn main`, rustc would generate a second
symbol named `main`. The target specifications of AROS therefore set the target
option `entry-name` to `ami_rust_entry`, so rustc generates that name instead, and
the patched `std` supplies `rust_sdk_main`, which calls it with the `argc` and
`argv` that the C start-up stored. A program does not define `rust_sdk_main`
itself.

- **Exit status.** `Ok` is 0. An error returned from `main` is 10. A panic, an
  abort and a failed infallible allocation are 20. `process::exit(n)` and
  `ExitCode::from(n)` give `n` as it is, except that 1 (what an error returned
  from `main` gives, and what `ExitCode::FAILURE` is) is reported as 10.
- **The `aros` crate.** `aros::dispatch` can be called once from `fn main` and
  gives the program its `aros::Context`; the `context` mode does that. A crate that
  uses `aros::entry!` is not a `std` program: `entry!` and `std` both define the
  panic handler, which is a compile error (`E0152`, duplicate lang item
  `panic_impl`). Using `aros` as a library from a `fn main` program is fine.

## Build

Until the toolchain of the `std` release exists, the build needs a local toolchain
made as `CONTRIBUTING.md` describes under "Native bridge changes", and in addition
the two files `lib/rustlib/<target>/<target>.json` and `lib/rustlib/<target>/target.json`
of each target replaced with `targets/<target>.json`. `aros-link` must be built
from this tree, because it checks the specifications against its embedded pins.
With that toolchain linked as `NAME`, and the patched library tree prepared as
described in `host/std-aros/README.md` and called `$work/rust` there:

```sh
cd examples/std-runtime
for target in x86_64-unknown-aros-abi1 x86_64-unknown-aros-abi11; do
  env CARGO_BUILD_RUSTC_WRAPPER= RUSTC_WRAPPER= \
    __CARGO_TESTS_ONLY_SRC_ROOT="$work/rust/library" \
    CARGO_TARGET_DIR="$work/runtime-target" \
    cargo +NAME build --release --target "$target" --offline --locked
done
```

## Run

On AROS, once per mode: `Stack 131072`, then `std-runtime MODE`, then `Echo $RC`. ABI-v1
requires exactly that stack. On ABI-v11 the runs were made with `Stack 1000000`.
The program redirects its own standard error to `RAM:ami-rust-m1/err.txt` in the
modes that write to it, because the AROS shell does not redirect standard error;
read the file afterwards with `Type`. For `stdin`, start it as `std-runtime stdin <FILE`.

## Expected results

All of these were observed on the pinned ABI-v1 and ABI-v11 images.

| Mode | What it does | Return code | Output |
| --- | --- | --- | --- |
| `none` | returns from `main` | 0 | `returned` |
| `exit` | `print!("flushed-by-exit")`, then `process::exit(3)` | 3 | the pending text is flushed |
| `exit0`, `exit5` | `process::exit(0)`, `process::exit(5)` | 0, 5 | the code is the return code as it is |
| `panic` | `panic!("probe panic {}", 42)` | 20 | `thread 'main' (1) panicked at …` and the message on standard error; the native diagnostic `ami-rust fatal 2` |
| `abort` | `process::abort()` | 20 | `ami-rust fatal 2` |
| `oom` | `Vec::with_capacity(1 << 33)` and a push | 20 | `memory allocation of 8589934592 bytes failed` on standard error |
| `reserve` | `try_reserve` of 8 GiB and of 64 KiB | 0 | the first is an error, the second succeeds |
| `out` | `println!`, `print!`, `write_all`, `eprintln!` | 0 | all lines appear |
| `stdin` | two `read_line` calls on redirected input | 0 | the first returns the line, the second returns 0 bytes |
| `env` | `set_var`, `var`, `var_os`, overwrite, `remove_var`, invalid names, `vars()` | 0 | see below |
| `outside` | `var("AMI_OUTSIDE")` after `SetEnv AMI_OUTSIDE set-by-the-shell` in the shell | 0 | `Ok("set-by-the-shell")` |
| `args one two=three` | `env::args()` | 0 | four arguments: the program name, `args`, `one` and `two=three` |
| `context` | `aros::dispatch` from `fn main` | 0 | the context reports its two arguments |
| `main-err` | `main` returns `Err("boom")` | 10 | `Error: "boom"` on standard error |
| `code7`, `code10`, `code20` | `main` returns `ExitCode::from(n)` | 7, 10, 20 | |

Environment details: a variable that was set is found, an overwrite replaces the
value, a removed one is `NotPresent`, and an empty name or a name that contains
`=` is `NotPresent`. `env::vars()` is always empty, because the C library cannot
list DOS variables; `env::var` finds a named variable, including a DOS variable
that was set outside the program. `set_var` writes a variable that is local to
the process.

Without the patch, `exit`, `abort` and `panic` end in an illegal instruction, and
AROS shows its "Software Failure!" requester and waits for a person; a program
started from a script never returns.

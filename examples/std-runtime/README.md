# std-runtime

Native test for the edges of a `std` program on AROS: how it exits, aborts and
panics, what happens when an allocation fails, and how the standard streams and
the environment behave. Each run does one thing, chosen by the first argument.

Like `std-probe`, it is not a workspace member. It needs the patched `std` of
`host/std-aros/` and cannot build against the stock `rust-src`. It is listed as in
development under #67 because the native matrix cannot prepare that `std` yet.

The program has no `fn main`. It exports `rust_sdk_main` and enters its function
through `aros::dispatch`, as `std-probe` does. How a `fn main` program starts is
a separate decision of STD-M2 and is not exercised here.

## Build

With the patched library tree prepared as described in `host/std-aros/README.md`
and called `$work/rust` there:

```sh
cd examples/std-runtime
for target in x86_64-unknown-aros-abi1 x86_64-unknown-aros-abi11; do
  env CARGO_BUILD_RUSTC_WRAPPER= RUSTC_WRAPPER= \
    __CARGO_TESTS_ONLY_SRC_ROOT="$work/rust/library" \
    CARGO_TARGET_DIR="$work/runtime-target" \
    cargo +0.2.0 build --release --target "$target" --offline --locked
done
```

## Run

On AROS, once per mode: `Stack 131072`, then `std-runtime MODE`, then `Echo $RC`. ABI-v1
requires exactly that stack. On ABI-v11 the runs were made with `Stack 1000000`, and
`panic`, `oom`, `out` and `exit` were repeated with `Stack 131072` with the same results. The program
redirects its own standard error to `RAM:ami-rust-m1/err.txt` in the modes that
write to it, because the AROS shell does not redirect standard error; read the
file afterwards with `Type`. For `stdin`, start it as `std-runtime stdin <FILE`.

## Expected results

All of these were observed on the pinned ABI-v1 and ABI-v11 images.

| Mode | What it does | Return code | Output |
| --- | --- | --- | --- |
| `none` | returns from the function | 0 | `returned` |
| `exit` | `print!("flushed-by-exit")`, then `process::exit(3)` | 3 | the pending text is flushed |
| `exit0`, `exit5` | `process::exit(0)`, `process::exit(5)` | 0, 5 | the code is the return code as it is |
| `panic` | `panic!("probe panic {}", 42)` | 20 | `thread '<unnamed>' (1) panicked at …` and the message on standard error; the native diagnostic `ami-rust fatal 2` |
| `abort` | `process::abort()` | 20 | `ami-rust fatal 2` |
| `oom` | `Vec::with_capacity(1 << 33)` and a push | 20 | `memory allocation of 8589934592 bytes failed` on standard error |
| `reserve` | `try_reserve` of 8 GiB and of 64 KiB | 0 | the first is an error, the second succeeds |
| `out` | `println!`, `print!`, `write_all`, `eprintln!` | 0 | all lines appear |
| `stdin` | two `read_line` calls on redirected input | 0 | the first returns the line, the second returns 0 bytes |
| `env` | `set_var`, `var`, `var_os`, overwrite, `remove_var`, invalid names, `vars()` | 0 | see below |
| `outside` | `var("AMI_OUTSIDE")` after `SetEnv AMI_OUTSIDE set-by-the-shell` in the shell | 0 | `Ok("set-by-the-shell")` |

Environment details: a variable that was set is found, an overwrite replaces the
value, a removed one is `NotPresent`, and an empty name or a name that contains
`=` is `NotPresent`. `env::vars()` is always empty, because the C library cannot
list DOS variables; `env::var` finds a named variable, including a DOS variable
that was set outside the program. `set_var` writes a variable that is local to
the process.

Without the patch, `exit`, `abort` and `panic` end in an illegal instruction, and
AROS shows its "Software Failure!" requester and waits for a person; a program
started from a script never returns.

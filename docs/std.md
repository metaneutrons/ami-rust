---
title: Rust std on AROS
description: What the Rust standard library does on AROS, how to build a std program, what is not supported and how it differs from no_std.
---

ami-rust has two ways to write a program. The `no_std` way, with the `aros` crates and `entry!`, is the supported baseline and what the rest of this documentation describes. The `std` way lets you write an ordinary `fn main` with `std::fs`, `std::thread` and the rest of the standard library. It is **experimental**: it works on both ABIs and is tested, but it is marked as unstable on purpose, and the [known issues](#known-issues) below are real.

Toolchains up to and including 0.2.0 do not ship `std`. A toolchain that does ship it has the compiled standard library for both [targets](/targets-and-abis/) in its target library directory, next to `core` and `alloc`, so building a `std` program needs no `-Zbuild-std` and no source of the standard library.

## Which one should I use?

| You want | Use |
| --- | --- |
| The `aros` crates (files, streams, ports, MUI, graphics, ...) with typed errors, and the smallest executable | `no_std` with [`entry!`](/consumer-guide/) |
| `fn main`, `std::fs`, `std::thread`, `HashMap`, `Mutex`, `println!` and crates that need `std` | `std` |
| Both: the `aros` crates inside a `std` program | `std`, and see [using the `aros` crates](#using-the-aros-crates-from-a-std-program) |

A program is one or the other. `aros::entry!` installs a panic handler, `std` already has one, and the two do not compile together (error `E0152`, duplicate lang item `panic_impl`).

## Build a std program

Install a toolchain that ships `std` as described under [install and build](/quickstart-toolchain/). Then a `std` program is built like any other ami-rust program, with the same `.cargo/config.toml` (the linker `aros-link` for each target) and the same two-line `build.rs` that calls `aros_native_build::prepare` (see the [build system](/build-system/) page). `Cargo.toml` needs no `aros` dependency unless the program uses one. The only differences are in the source and in the profile:

- the crate declares `#![feature(restricted_std)]`: the standard library on AROS is deliberately marked unstable, and without the attribute the build fails with a message that names it;
- the program does not use `#![no_std]` or `#![no_main]`, and has an ordinary `fn main`;
- the release profile sets `panic = "abort"`, because AROS has no unwinding.

```rust
#![feature(restricted_std)]

use std::io::Write;
use std::process::ExitCode;
use std::{env, fs, path::Path};

fn main() -> Result<ExitCode, std::io::Error> {
    let name = env::args().nth(1).unwrap_or_else(|| "AROS".to_string());
    println!("Hello, {name}!");

    let path = Path::new("RAM:").join("hello.txt");
    let mut file = fs::File::create(&path)?;
    writeln!(file, "written by Rust std")?;
    drop(file);
    println!("{} holds {} bytes", path.display(), fs::metadata(&path)?.len());
    fs::remove_file(&path)?;
    Ok(ExitCode::SUCCESS)
}
```

Build it with `cargo build --release --locked --offline --target x86_64-unknown-aros-abi1` (or `-abi11`) and run it as described in [Run on AROS](/run-on-aros/). The stack of the shell must be 131072 bytes on both ABIs. ABI-v1 refuses to start with any other size and returns 20.

Threads work as in any `std` program:

```rust
#![feature(restricted_std)]

use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let total = Arc::new(Mutex::new(0u32));
    let workers: Vec<_> = (1..=4)
        .map(|n| {
            let total = Arc::clone(&total);
            thread::spawn(move || {
                *total.lock().unwrap() += n;
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    println!("total {}", total.lock().unwrap());
}
```

## How a program starts and ends

The native C `main` of the toolchain stays the owner of the task: it opens the runtime, calls the Rust entry, closes the runtime and returns the status. You never define the entry yourself.

| End of the program | Return code |
| --- | --- |
| `main` returns `()`, `Ok(())` or `ExitCode::SUCCESS` | 0 |
| `main` returns an `Err` | 10 (the error is printed on standard error) |
| A panic, an abort, or an allocation that fails | 20 (a panic and a failed allocation print their message on standard error) |
| `process::exit(n)`, `ExitCode::from(n)` | `n`, except that 1 is reported as 10 |

AROS does not show its "Software Failure" requester for these; the program just ends. A program that has started threads ends only after all of them: they end at their next wait or `std` call.

## Using the `aros` crates from a `std` program

The `aros` crate works as a library from a `fn main` program: `aros::dispatch` hands the program its `Context` once, and everything that takes a `Context` can then be used. `examples/std-runtime` in the repository shows it (the `context` mode). A crate that uses `aros::entry!` is a `no_std` program and does not combine with `std`.

## What is supported

The results are the same on ABI-v1 and ABI-v11 except where a row says otherwise.

| Area | State |
| --- | --- |
| Arguments and environment | `env::args`, and `env::var`, `set_var` and `remove_var` on the DOS variables of the process. `env::vars` is always empty, because the C library cannot list them. |
| Standard streams | Standard input, output and error. |
| Memory | `Vec`, `String`, `HashMap` and `format!`. A single allocation of more than 4 GiB fails, because the AROS allocator misbehaves for such requests. |
| Time | `Instant`, `SystemTime` and `thread::sleep`. `SystemTime` is correct until 7 February 2106, where the C library's clock wraps. |
| Files and directories | Open, create, read, write, seek, truncate, duplicate and remove files; file metadata (size, type, one date with a resolution of one second, read-only); `read_dir`, `create_dir`, `create_dir_all`, `remove_dir`, `remove_dir_all`, `copy`, `exists`, `rename` and `canonicalize`; setting the modification date (one date per file, whole seconds, 1978 to 2106). `rename` never loses a file, also where the C library underneath would. DOS requesters are switched off around path calls by default, so a missing volume is an error and not a wait for a person; `std::os::aros::fs::set_requesters(true)` turns them back on at any time (it needs `#![feature(aros_ext)]`). An empty path is an error, as on Unix. |
| Paths | `Path` knows AROS paths: the volume (`RAM:`) is the prefix, a path with one is absolute, and `Path::new("RAM:").join("x")` is `RAM:x`. `.` and `..` work in every path call although DOS knows neither; `std` resolves them by the name alone, without looking at the file system. `env::current_dir` and `set_current_dir`; `current_dir` reports the volume name (`RAM Disk:`), not the assign. `env::temp_dir()` is `T:`, path lists use `;`. Two slashes in a row are one, as on Unix; DOS reads them as the parent directory. |
| Random numbers | `HashMap` seeds and `std::random`. ABI-v1 uses the system's entropy source. ABI-v11 has none yet: it mixes a weak generator with the CPU's `RDRAND` instruction where there is one, and is weak without it, so `HashMap` there is not hardened against crafted keys. Not suitable for cryptography on either ABI. |
| Threads | `thread::spawn`, `join`, `thread::scope`, `Mutex`, `Condvar`, `RwLock`, `Once`, `OnceLock`, `LazyLock`, `Barrier`, `park`, channels, `thread_local!` and `yield_now`; at least 1000 threads at once with the default 256 KiB stack. A thread is a DOS process, so it has its own current directory and DOS variables. A thread's `process::exit` or panic ends the program at the main task's next `std` call. An error from a failed read or write in a threaded program may carry another thread's code, because the C library keeps one `errno` for all tasks of a program. `available_parallelism` is 1. |
| Child programs | `process::Command`: `new`, `arg`, `args`, `current_dir`, `env`, `env_remove`, `spawn`, `status` and `output`, `Child::wait`, `try_wait`, `wait_with_output` and `id`, and `ExitStatus`. A command is a DOS program, looked for as it is and, when its name has no volume, in `C:`; the command path of the shell is not searched. The arguments go to the program as they are (no shell reads them), so a quote, a semicolon or a `>` in an argument is text. The standard streams are the parent's unless the command says otherwise; `Stdio::piped()` is a file in `T:`, so what the child wrote can be read when it has ended (a read waits for that), and what is written to its input is given to it when the input is closed, which is when it starts. The exit status is the return code of the program. Each child is a process of its own, and several run at once. `Child::kill` and `env_clear` are `Unsupported` (see below), and so is a `File` as a standard stream of a child. |
| Networking | `TcpStream`, `TcpListener` and `UdpSocket` over `bsdsocket.library` (read, write, `peek`, timeouts, non-blocking mode, `connect_timeout`, `shutdown`, `TCP_NODELAY`, the time to live, addresses of both ends), and name lookup of IPv4 names through the stack. Nothing starts the stack: AROSTCP must be running, and it reads its configuration from a `db` directory next to its `C` directory. The ABI-v1 image carries the program but no `db`; two files of three lines make a loopback-only stack (see `examples/std-net`). Without a running stack, every call that needs one returns `ErrorKind::Unsupported` at once with a message that says so, and nothing waits. A socket belongs to the thread that made it, because the stack's library base belongs to a task: another thread gets `Unsupported`, and a socket dropped in another thread is closed at the next socket call of the thread that made it, or when that thread ends. Name lookup reads what the stack's `netdb` names (the hosts of its files and its name servers). |

## What is not supported

These return `ErrorKind::Unsupported` (or, for an API that cannot fail, are empty), and they are not a bug:

- symbolic and hard links, and file locks;
- `env::current_exe`, and `env::home_dir`, which is always `None`;
- on sockets, `try_clone`, `set_linger`, `set_only_v6`, the multicast options, and the use of a socket by a thread other than the one that made it;
- `fork`, `exec`, signals, `Child::kill` while the child runs, `Command::env_clear`, and a pipe that parent and child use at the same time (a `Stdio::piped()` stream is a file; see above);
- `std::io::pipe`.

Not tested, so not promised: traffic beyond the loopback interface, IPv6 traffic, name servers, volumes other than `RAM:` and the delivery volume, files above 2 GiB, time zones other than UTC, more than one CPU, and `RDRAND` failure cases on ABI-v11.

## Known issues

- **ABI-v1 loses memory with every run.** Each run of a program that uses the C library's POSIX layer, which every `std` program does, leaves about 168 KB unreleased until the system restarts. ABI-v11 does not. A machine that runs many such programs on ABI-v1 eventually runs out of memory. A thread costs a further 123 bytes on ABI-v1 and about 7 on ABI-v11. See [#131](https://github.com/metaneutrons/ami-rust/issues/131).
- **ABI-v1 can take a page fault after repeated runs.** After many runs of programs that call the C library from more than one process (a program with threads is one), freeing unused libraries with `Avail FLUSH` took a page fault in about one boot in five in tests. The cause is not known. See [#132](https://github.com/metaneutrons/ami-rust/issues/132).
- **Deep recursion in the main task.** The main task runs on the stack of the shell, which is fixed at 128 KiB on ABI-v1. A program that needs more should do its work in a thread, where `thread::Builder::stack_size` sets the stack.

## Differences from `no_std`

| Aspect | `no_std` with `entry!` | `std` |
| --- | --- | --- |
| Entry | `aros::entry!` | `fn main` |
| Errors | The typed errors of the `aros` crates | `std::io::Error` and the standard types |
| Large files | 64-bit sizes through `dos64.library` on ABI-v1; the `Limit` error on ABI-v11 beyond the 32-bit calls | 64-bit offsets of the C library on both ABIs; files above 2 GiB were not tested |
| Stability | Supported | Experimental, behind `restricted_std` |

See [targets and ABIs](/targets-and-abis/) for what the two ABIs share, [compatibility](/compatibility/) for the boundary, and [troubleshooting](/troubleshooting/) for the build errors that `std` programs meet.

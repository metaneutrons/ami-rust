//! Behaviour of `std` on AROS at the edges of a program: exit status, abort, panic,
//! allocation failure, arguments, standard streams and the environment. One
//! behaviour per run, chosen by the first argument. The expected results are in
//! README.md.
//!
//! This is an ordinary `fn main` program: the toolchain renames the entry that rustc
//! generates (the target option `entry-name`), so it does not clash with the native
//! `main` that owns the task.

// std on AROS is experimental: every program that uses it opts in to restricted_std.
#![feature(restricted_std)]

use aros::{AppStatus, Context};
use std::ffi::{c_char, c_int};
use std::io::{BufRead, Write};
use std::process::ExitCode;

unsafe extern "C" {
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn dup2(old: c_int, new: c_int) -> c_int;
}

// AROS flag values: O_WRONLY 2, O_CREAT 0x40, O_TRUNC 0x200.
fn redirect_stderr(path: &std::ffi::CStr) {
    let fd = unsafe { open(path.as_ptr(), 2 | 0x40 | 0x200, 0o644 as c_int) };
    if fd >= 0 {
        unsafe { dup2(fd, 2) };
    } else {
        println!("redirect: open failed ({fd})");
    }
}

/// Uses the `aros` crate from a `std` program, through the one claim of the context.
fn with_context(context: &Context) -> AppStatus {
    println!("context: {} arguments, first {:?}", context.args().count(), context.args().next().map(String::from_utf8_lossy));
    AppStatus::Success
}

fn main() -> Result<ExitCode, String> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let err = c"RAM:ami-rust-m1/err.txt";
    match mode.as_str() {
        "exit" => {
            print!("flushed-by-exit");
            std::process::exit(3)
        }
        "exit0" => std::process::exit(0),
        "exit5" => std::process::exit(5),
        "panic" => {
            redirect_stderr(err);
            println!("before-panic");
            panic!("probe panic {}", 42)
        }
        "abort" => {
            redirect_stderr(err);
            eprintln!("before-abort");
            std::process::abort()
        }
        "oom" => {
            redirect_stderr(err);
            let mut v: Vec<u8> = Vec::with_capacity(1usize << 33);
            v.push(1);
            std::hint::black_box(&v);
            println!("unexpected: allocated {}", v.capacity());
        }
        "reserve" => {
            let mut v: Vec<u8> = Vec::new();
            let big = v.try_reserve(1usize << 33);
            std::hint::black_box(&v);
            println!("try_reserve(8 GiB) is_err={}", big.is_err());
            println!("try_reserve(64 KiB) is_ok={}", v.try_reserve(1 << 16).is_ok());
        }
        "out" => {
            println!("println works");
            print!("print without newline");
            std::io::stdout().write_all(b"\nwrite_all works\n").unwrap();
            eprintln!("stderr line");
            eprint!("stderr no newline");
            println!("{:?} {}", vec![1, 2, 3], String::from("string"));
        }
        "stdin" => {
            let mut line = String::new();
            let n = std::io::stdin().lock().read_line(&mut line).unwrap();
            println!("read {n} bytes: {:?}", line);
            let mut rest = String::new();
            let m = std::io::stdin().lock().read_line(&mut rest).unwrap();
            println!("second read {m} bytes (0 means end of input)");
        }
        "env" => {
            println!("before: {:?}", std::env::var("AMI_X"));
            unsafe { std::env::set_var("AMI_X", "one") };
            println!("after set: {:?}", std::env::var("AMI_X"));
            println!("var_os: {:?}", std::env::var_os("AMI_X"));
            unsafe { std::env::set_var("AMI_X", "two") };
            println!("overwritten: {:?}", std::env::var("AMI_X"));
            unsafe { std::env::remove_var("AMI_X") };
            println!("after remove: {:?}", std::env::var("AMI_X"));
            println!("invalid names: {:?} {:?}", std::env::var(""), std::env::var("A=B"));
            println!("vars().count() = {}", std::env::vars().count());
        }
        "outside" => println!("AMI_OUTSIDE: {:?}", std::env::var("AMI_OUTSIDE")),
        "args" => {
            let all: Vec<String> = std::env::args().collect();
            println!("args().count() = {}", all.len());
            for (i, a) in all.iter().enumerate() {
                println!("args[{i}] = {a:?}");
            }
        }
        "context" => {
            let status = aros::dispatch(with_context);
            println!("dispatch returned {status}");
        }
        "main-err" => {
            redirect_stderr(err);
            return Err("boom".to_string());
        }
        "code7" => return Ok(ExitCode::from(7)),
        "code10" => return Ok(ExitCode::from(10)),
        "code20" => return Ok(ExitCode::from(20)),
        _ => {}
    }
    println!("returned");
    Ok(ExitCode::SUCCESS)
}

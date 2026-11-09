//! Child programs in `std` on AROS: `process::Command` over `SystemTagList`. One behaviour per run,
//! chosen by the first argument; the expected results are in README.md. The program starts itself as the
//! child (the `child-*` modes), so it needs nothing else on the volume. The files it makes are in
//! `RAM:ami-rust-m1/`, which the run must create (`MakeDir`) and start in (`CD`).

#![feature(restricted_std)]
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BASE: &str = "RAM:ami-rust-m1/";

struct T {
    failed: u32,
    total: u32,
}

impl T {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        self.total += 1;
        if !ok {
            self.failed += 1;
        }
        println!("RESULT process {name} {}{}", if ok { "ok" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
    }

    fn is<V: PartialEq + std::fmt::Debug>(&mut self, name: &str, got: V, want: V) {
        let ok = got == want;
        self.check(name, ok, if ok { String::new() } else { format!("got {got:?}, wanted {want:?}") });
    }
}

/// The program itself, as the shell starts it.
fn me() -> String {
    std::env::args().next().unwrap_or_else(|| "NATIVERUN:prog".to_string())
}

fn child(args: &[&str]) -> Command {
    let mut c = Command::new(me());
    c.args(args);
    c
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    let mut t = T { failed: 0, total: 0 };
    match mode {
        // ---- the child side ----
        "child-exit" => return ExitCode::from(args[2].parse::<u8>().unwrap()),
        "child-args" => {
            for (i, a) in args.iter().enumerate().skip(2) {
                println!("ARG{}={a:?}", i - 2);
            }
            println!("COUNT={}", args.len() - 2);
            return ExitCode::SUCCESS;
        }
        "child-cwd" => {
            println!("CWD={}", std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default());
            return ExitCode::SUCCESS;
        }
        "child-env" => {
            for name in &args[2..] {
                println!("ENV {name}={:?}", std::env::var(name).ok());
            }
            return ExitCode::SUCCESS;
        }
        "child-stdin" => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).unwrap();
            println!("READ {} bytes: {}", s.len(), s.trim_end());
            return ExitCode::SUCCESS;
        }
        "child-both" => {
            println!("to-stdout");
            eprintln!("to-stderr");
            return ExitCode::SUCCESS;
        }
        "child-sleep" => {
            thread::sleep(Duration::from_millis(args[2].parse().unwrap()));
            println!("slept");
            return ExitCode::SUCCESS;
        }

        // ---- the parent side ----
        "basic" => {
            let out = Command::new("Echo").arg("hello").output();
            match out {
                Ok(o) => {
                    t.is("Echo gives its text", text(&o.stdout), "hello\n".to_string());
                    t.is("a good status", o.status.code(), Some(0));
                    t.check("success()", o.status.success(), String::new());
                    t.is("nothing on the error", o.stderr.len(), 0);
                }
                Err(e) => t.check("Command::new(\"Echo\").output()", false, format!("{e:?}")),
            }
            let status = Command::new("C:Echo").arg("inherited output line").status();
            t.is("status() of a program in C:", status.map(|s| s.code()).ok(), Some(Some(0)));
            let o = child(&["child-args", "a", "b"]).output().unwrap();
            t.is("the program itself as a child", text(&o.stdout), "ARG0=\"a\"\nARG1=\"b\"\nCOUNT=2\n".to_string());
        }
        "exitcodes" => {
            for code in [0u8, 1, 5, 7, 10, 20, 100, 255] {
                let s = child(&["child-exit", &code.to_string()]).status().unwrap();
                // 1 is what an error returned from main gives, which std reports as 10 (see std-runtime).
                let want = if code == 1 { 10 } else { i32::from(code) };
                t.is(&format!("return code {code}"), s.code(), Some(want));
            }
            let s = child(&["child-exit", "0"]).status().unwrap();
            t.check("exit_ok on success", s.success() && s.code() == Some(0), String::new());
            let s = child(&["child-exit", "7"]).status().unwrap();
            t.check("exit_ok on failure", !s.success(), String::new());
        }
        "args" => {
            let nasty: Vec<&str> = vec![
                "plain",
                "two words",
                "",
                "quote\"inside",
                "star*inside",
                "**",
                "tab\there",
                "semi;colon",
                ">RAM:ami-rust-m1/injected",
                "<NIL:",
                "$HOME",
                "{braces}",
                "(paren)",
                "back`tick",
                "single'quote",
                "percent%d",
                "dots...",
                "volume:path/name",
                "a=b",
                "ünïcode",
                "line\nbreak",
                "-flag",
                "--",
                "[ ]",
                "|pipe",
                "&amp",
                "~tilde",
                "trailing space ",
                " leading space",
            ];
            let _ = fs::remove_file(format!("{BASE}injected"));
            let mut a = vec!["child-args"];
            a.extend(nasty.iter().copied());
            let o = child(&a).output().unwrap();
            let got = text(&o.stdout);
            let mut want = String::new();
            for (i, s) in nasty.iter().enumerate() {
                want.push_str(&format!("ARG{i}={s:?}\n"));
            }
            want.push_str(&format!("COUNT={}\n", nasty.len()));
            t.check("every argument arrives as it was given", got == want, format!("got:\n{got}"));
            t.check("a redirection in an argument did not run", !Path::new(&format!("{BASE}injected")).exists(), String::new());
            let o = Command::new("Echo").arg(";Type NIL:").output().unwrap();
            t.is("a semicolon in an argument is text", text(&o.stdout), ";Type NIL:\n".to_string());
        }
        "cwd" => {
            let _ = fs::create_dir_all(format!("{BASE}sub/deep"));
            let before = std::env::current_dir().unwrap();
            let o = child(&["child-cwd"]).output().unwrap();
            t.is("a child starts where the parent is", text(&o.stdout).trim_end().to_string(), format!("CWD={}", before.display()));
            let o = child(&["child-cwd"]).current_dir(format!("{BASE}sub/deep")).output().unwrap();
            t.check("current_dir moves the child", text(&o.stdout).trim_end().ends_with("ami-rust-m1/sub/deep"), text(&o.stdout));
            t.is("the parent stays", std::env::current_dir().unwrap(), before);
            let r = child(&["child-cwd"]).current_dir(format!("{BASE}nothere")).output();
            t.is("a missing directory", r.map(|_| ()).map_err(|e| e.kind()), Err(ErrorKind::NotFound));
            let _ = fs::write(format!("{BASE}afile"), b"x");
            let r = child(&["child-cwd"]).current_dir(format!("{BASE}afile")).output();
            t.is("a file as directory", r.map(|_| ()).map_err(|e| e.kind()), Err(ErrorKind::NotADirectory));
            let _ = fs::remove_dir_all(format!("{BASE}sub"));
            let _ = fs::remove_file(format!("{BASE}afile"));
        }
        "env" => {
            unsafe { std::env::set_var("AMI_PARENT", "from-parent") };
            unsafe { std::env::set_var("AMI_GONE", "present") };
            let o = child(&["child-env", "AMI_PARENT", "AMI_SET", "AMI_GONE"]).env("AMI_SET", "set-for-child").env_remove("AMI_GONE").output().unwrap();
            let got = text(&o.stdout);
            t.check("the child sees a variable of the parent", got.contains("ENV AMI_PARENT=Some(\"from-parent\")"), got.clone());
            t.check("the child sees one that was set for it", got.contains("ENV AMI_SET=Some(\"set-for-child\")"), got.clone());
            t.check("a removed variable is gone in the child", got.contains("ENV AMI_GONE=None"), got);
            t.is("the parent does not see the child's variable", std::env::var("AMI_SET").ok(), None);
            t.is("the parent still has the removed one", std::env::var("AMI_GONE").ok(), Some("present".to_string()));
            let r = child(&["child-exit", "0"]).env_clear().status();
            t.is("env_clear is unsupported", r.map(|_| ()).map_err(|e| e.kind()), Err(ErrorKind::Unsupported));
        }
        "stdio" => {
            let mut c = child(&["child-stdin"]);
            c.stdin(Stdio::piped()).stdout(Stdio::piped());
            let mut p = c.spawn().unwrap();
            p.stdin.take().unwrap().write_all(b"first line\nsecond line\n").unwrap();
            let o = p.wait_with_output().unwrap();
            t.is("stdin reaches the child", text(&o.stdout), "READ 23 bytes: first line\nsecond line\n".to_string());
            let o = child(&["child-both"]).output().unwrap();
            t.is("stdout is captured", text(&o.stdout), "to-stdout\n".to_string());
            t.is("stderr is captured", text(&o.stderr), "to-stderr\n".to_string());
            let o = child(&["child-both"]).stdout(Stdio::null()).stderr(Stdio::piped()).output().unwrap();
            t.is("a null stdout", (o.stdout.len(), text(&o.stderr)), (0, "to-stderr\n".to_string()));
            let mut p = child(&["child-stdin"]).stdin(Stdio::null()).stdout(Stdio::piped()).spawn().unwrap();
            let mut s = String::new();
            p.stdout.take().unwrap().read_to_string(&mut s).unwrap();
            p.wait().unwrap();
            t.is("a null stdin reads nothing", text(s.as_bytes()), "READ 0 bytes: \n".to_string());
            let mut first = child(&["child-args", "x", "y"]).stdout(Stdio::piped()).spawn().unwrap();
            let pipe = first.stdout.take().unwrap();
            let o = child(&["child-stdin"]).stdin(pipe).output().unwrap();
            first.wait().unwrap();
            t.is("the output of one child is the input of the next", text(&o.stdout), "READ 26 bytes: ARG0=\"x\"\nARG1=\"y\"\nCOUNT=2\n".to_string());
            let o = child(&["child-both"]).stderr(Stdio::from(std::io::stdout())).stdout(Stdio::piped()).output().unwrap();
            t.is("stderr to the stdout of the parent", (text(&o.stdout), o.stderr.len()), ("to-stdout\n".to_string(), 0));
            let f = fs::File::create(format!("{BASE}out.txt")).unwrap();
            let r = child(&["child-both"]).stdout(f).status();
            t.is("a File as stdout is unsupported", r.map(|_| ()).map_err(|e| e.kind()), Err(ErrorKind::Unsupported));
            let _ = fs::remove_file(format!("{BASE}out.txt"));
        }
        "notfound" => {
            let r = Command::new("NoSuchProgram").status();
            t.is("a missing program", r.map(|_| ()).map_err(|e| e.kind()), Err(ErrorKind::NotFound));
            let r = Command::new("RAM:nothere/prog").output();
            t.is("a missing path", r.map(|_| ()).map_err(|e| e.kind()), Err(ErrorKind::NotFound));
            let r = Command::new("C:").status();
            t.check("a directory is not a program", r.is_err(), format!("{r:?}"));
            let r = Command::new("").status();
            t.check("an empty program name", r.is_err(), format!("{r:?}"));
            let r = Command::new("Echo").arg("a\0b").output();
            t.is("a nul byte in an argument", r.map(|_| ()).map_err(|e| e.kind()), Err(ErrorKind::InvalidInput));
        }
        "wait" => {
            let started = Instant::now();
            let mut p = child(&["child-sleep", "1500"]).stdout(Stdio::piped()).spawn().unwrap();
            t.check("spawn returns at once", started.elapsed() < Duration::from_millis(1200), format!("{:?}", started.elapsed()));
            t.is("try_wait while it runs", p.try_wait().map_err(|e| e.kind()), Ok(None));
            let r = p.kill();
            t.is("kill is unsupported while it runs", r.map_err(|e| e.kind()), Err(ErrorKind::Unsupported));
            let id = p.id();
            let status = p.wait().unwrap();
            t.check("wait returns after the child", started.elapsed() >= Duration::from_millis(1400), format!("{:?}", started.elapsed()));
            t.is("the status", status.code(), Some(0));
            t.is("wait twice gives the same status", p.wait().map(|s| s.code()).ok(), Some(Some(0)));
            t.is("try_wait after the end", p.try_wait().map(|s| s.map(|s| s.code())).ok(), Some(Some(Some(0))));
            t.is("kill after the end", p.kill().map_err(|e| e.kind()), Ok(()));
            match child(&["child-exit", "0"]).spawn() {
                Ok(other) => {
                    t.check("ids differ", other.id() != id, format!("{id} {}", other.id()));
                    drop(other);
                }
                Err(e) => t.check("a second child starts", false, format!("{e:?}")),
            }
        }
        "concurrent" => {
            let handles: Vec<_> = (0..3)
                .map(|n| {
                    thread::spawn(move || {
                        let tag = format!("worker-{n}");
                        let o = child(&["child-args", &tag]).output().unwrap();
                        (n, text(&o.stdout), o.status.code())
                    })
                })
                .collect();
            for h in handles {
                let (n, out, code) = h.join().unwrap();
                t.is(&format!("thread {n} gets its own child's output"), (out, code), (format!("ARG0=\"worker-{n}\"\nCOUNT=1\n"), Some(0)));
            }
            let mut ps: Vec<_> = (0..3).map(|n| child(&["child-sleep", "2000"]).stdout(Stdio::piped()).env("N", n.to_string()).spawn().unwrap()).collect();
            let started = Instant::now();
            let all = ps.iter_mut().all(|p| p.wait().map(|s| s.success()).unwrap_or(false));
            t.check("three children at once", all && started.elapsed() < Duration::from_millis(5000), format!("{:?}", started.elapsed()));
        }
        "end-child-running" => {
            // The parent returns while a child still runs: the program ends after it.
            let p = child(&["child-sleep", "1000"]).stdout(Stdio::null()).spawn().unwrap();
            drop(p);
            println!("RESULT process the parent returns while a child runs ok");
        }
        "lookup" => {
            let o = Command::new("Echo").args(["a", "b"]).output();
            t.check("a program in C: by its name", o.is_ok(), String::new());
            let o = Command::new("c:echo").arg("lower").output();
            t.is("another case", o.map(|o| text(&o.stdout)).ok(), Some("lower\n".to_string()));
            let o = Command::new("SYS:C/Echo").arg("path").output();
            t.is("a program by its full path", o.map(|o| text(&o.stdout)).ok(), Some("path\n".to_string()));
            let _ = fs::create_dir_all(format!("{BASE}bin"));
            let _ = fs::copy(me(), format!("{BASE}bin/mine"));
            let o = Command::new("mine").arg("child-exit").arg("3").current_dir(format!("{BASE}bin")).status();
            t.is("a program in the directory of the child", o.map(|s| s.code()).ok(), Some(Some(3)));
            let o = Command::new(OsStr::new("bin/mine")).args(["child-exit", "4"]).status();
            t.is("a relative path", o.map(|s| s.code()).ok(), Some(Some(4)));
            let _ = fs::remove_dir_all(format!("{BASE}bin"));
        }
        _ => println!("modes: basic exitcodes args cwd env stdio notfound wait concurrent end-child-running lookup"),
    }
    println!("RESULT process summary {} of {} checks passed", t.total - t.failed, t.total);
    if t.failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(3) }
}

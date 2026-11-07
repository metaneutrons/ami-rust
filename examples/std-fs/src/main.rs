//! Files in `std` on AROS: open, read, write, seek, truncate, duplicate, unlink, the errors, and the
//! behaviours of the C library that `std` has to work around. One behaviour per run; the expected
//! results are in README.md. The files are made in `RAM:ami-rust-m1/`, which the run must create.

#![feature(restricted_std)]
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::ExitCode;

const BASE: &str = "RAM:ami-rust-m1/";

struct T { failed: u32, total: u32 }
impl T {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        self.total += 1;
        if !ok { self.failed += 1; }
        println!("RESULT fs {name} {}{}", if ok { "ok" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
    }
    fn kind(&mut self, name: &str, r: io::Result<impl Sized>, want: ErrorKind) {
        match r {
            Ok(_) => self.check(name, false, format!("succeeded, wanted {want:?}")),
            Err(e) => self.check(name, e.kind() == want, format!("got {:?} (os error {:?}), wanted {want:?}", e.kind(), e.raw_os_error())),
        }
    }
}
fn p(name: &str) -> String { format!("{BASE}{name}") }
fn pattern(n: usize, seed: u8) -> Vec<u8> { (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed).wrapping_add((i >> 8) as u8)).collect() }
fn clean(names: &[&str]) { for n in names { let _ = fs::remove_file(p(n)); } }

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let mut t = T { failed: 0, total: 0 };
    match mode.as_str() {
        "rw" => {
            clean(&["a"]);
            let data = pattern(70_000, 1);
            t.check("fs::write", fs::write(p("a"), &data).is_ok(), String::new());
            t.check("fs::read", fs::read(p("a")).ok().as_deref() == Some(&data[..]), String::new());
            t.check("fs::write text", fs::write(p("a"), "hello\nworld\n").is_ok(), String::new());
            t.check("fs::read_to_string", fs::read_to_string(p("a")).ok().as_deref() == Some("hello\nworld\n"), String::new());
            let mut f = File::open(p("a")).unwrap();
            let mut four = [0u8; 4];
            t.check("read_exact", f.read_exact(&mut four).is_ok() && &four == b"hell", String::new());
            let mut rest = Vec::new();
            t.check("read_to_end", f.read_to_end(&mut rest).is_ok() && rest == b"o\nworld\n", String::new());
            t.check("read at end is 0", f.read(&mut four).ok() == Some(0), String::new());
            t.kind("read_exact past end", File::open(p("a")).unwrap().read_exact(&mut [0u8; 100]), ErrorKind::UnexpectedEof);
            let lines: Vec<String> = BufReader::new(File::open(p("a")).unwrap()).lines().map(|l| l.unwrap()).collect();
            t.check("lines", lines == ["hello", "world"], format!("{lines:?}"));
            clean(&["a"]);
        }
        "large" => {
            clean(&["big"]);
            let chunk = pattern(4096 + 17, 7);
            {
                let mut w = BufWriter::new(File::create(p("big")).unwrap());
                for _ in 0..300 { w.write_all(&chunk).unwrap(); }
                t.check("BufWriter flush", w.flush().is_ok(), String::new());
            }
            let total = 300 * chunk.len();
            let back = fs::read(p("big")).unwrap();
            t.check("1.2 MB size", back.len() == total, format!("{} of {total}", back.len()));
            t.check("1.2 MB content", back.chunks(chunk.len()).all(|c| c == &chunk[..]), String::new());
            let mut f = File::open(p("big")).unwrap();
            let mut buf = vec![0u8; 100_000];
            let mut got = 0usize; let mut reads = 0u32;
            loop { let n = f.read(&mut buf).unwrap(); if n == 0 { break; } got += n; reads += 1; }
            t.check("partial reads add up", got == total, format!("{got} bytes in {reads} reads"));
            clean(&["big"]);
        }
        "seek" => {
            clean(&["s"]);
            let data = pattern(1000, 3);
            fs::write(p("s"), &data).unwrap();
            let mut f = File::open(p("s")).unwrap();
            t.check("seek Start", f.seek(SeekFrom::Start(100)).ok() == Some(100), String::new());
            let mut b = [0u8; 10]; f.read_exact(&mut b).unwrap();
            t.check("read after seek", b == data[100..110], String::new());
            t.check("stream_position", f.stream_position().ok() == Some(110), String::new());
            t.check("seek Current", f.seek(SeekFrom::Current(-10)).ok() == Some(100), String::new());
            t.check("seek End", f.seek(SeekFrom::End(-1)).ok() == Some(999), String::new());
            let mut one = [0u8; 1]; f.read_exact(&mut one).unwrap();
            t.check("last byte", one[0] == data[999], String::new());
            t.check("seek End(0) is the length", f.seek(SeekFrom::End(0)).ok() == Some(1000), String::new());
            t.kind("seek before the start", f.seek(SeekFrom::Current(-5000)), ErrorKind::InvalidInput);
            // reading and writing share one position
            clean(&["s2"]);
            let mut rw = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(p("s2")).unwrap();
            rw.write_all(b"0123456789").unwrap();
            rw.seek(SeekFrom::Start(3)).unwrap();
            rw.write_all(b"abc").unwrap();
            rw.seek(SeekFrom::Start(0)).unwrap();
            let mut all = String::new(); rw.read_to_string(&mut all).unwrap();
            t.check("overwrite in the middle", all == "012abc6789", all);
            clean(&["s", "s2"]);
        }
        "open" => {
            clean(&["o", "o2"]);
            t.kind("open missing for reading", File::open(p("o")), ErrorKind::NotFound);
            t.check("create", File::create(p("o")).and_then(|mut f| f.write_all(b"12345")).is_ok(), String::new());
            t.kind("create_new on existing", OpenOptions::new().write(true).create_new(true).open(p("o")), ErrorKind::AlreadyExists);
            t.check("create_new on missing", OpenOptions::new().write(true).create_new(true).open(p("o2")).is_ok(), String::new());
            t.check("truncate empties", { File::create(p("o")).unwrap(); fs::read(p("o")).unwrap().is_empty() }, String::new());
            fs::write(p("o"), b"abc").unwrap();
            { let mut f = OpenOptions::new().append(true).open(p("o")).unwrap(); f.seek(SeekFrom::Start(0)).unwrap(); f.write_all(b"def").unwrap(); }
            let appended = fs::read(p("o")).unwrap();
            t.check("append writes at the end even after a seek", appended == b"abcdef", format!("{:?}", String::from_utf8_lossy(&appended)));
            { let mut f = OpenOptions::new().append(true).create(true).open(p("o2")).unwrap(); f.write_all(b"x").unwrap(); }
            t.check("append + create", fs::read(p("o2")).unwrap() == b"x", String::new());
            t.kind("no access mode", OpenOptions::new().open(p("o")), ErrorKind::InvalidInput);
            t.kind("truncate without write", OpenOptions::new().read(true).truncate(true).open(p("o")), ErrorKind::InvalidInput);
            t.kind("create without write", OpenOptions::new().read(true).create(true).open(p("o")), ErrorKind::InvalidInput);
            t.kind("append + truncate", OpenOptions::new().append(true).truncate(true).open(p("o")), ErrorKind::InvalidInput);
            let before = fs::read(p("o")).unwrap();
            let wr = File::open(p("o")).unwrap().write(b"x");
            t.check("write to a read-only handle is refused (EBADF)", wr.as_ref().is_err_and(|e| e.raw_os_error() == Some(9)), format!("{wr:?}"));
            t.check("and the file is unchanged", fs::read(p("o")).unwrap() == before, String::new());
            let rd = OpenOptions::new().write(true).open(p("o")).unwrap().read(&mut [0u8; 4]);
            t.check("read from a write-only handle is refused (EBADF)", rd.as_ref().is_err_and(|e| e.raw_os_error() == Some(9)), format!("{rd:?}"));
            t.kind("missing directory", File::create("RAM:ami-rust-m1/nodir/x"), ErrorKind::NotFound);
            let started = std::time::Instant::now();
            t.kind("missing volume (no requester, no wait for a person)", File::open("NOSUCHVOLUME:x"), ErrorKind::NotFound);
            t.check("and it returns at once", started.elapsed() < std::time::Duration::from_secs(5), format!("{:?}", started.elapsed()));
            t.kind("unlink on a missing volume", fs::remove_file("NOSUCHVOLUME:x"), ErrorKind::NotFound);
            clean(&["o", "o2"]);
        }
        "trunc" => {
            clean(&["t"]);
            let mut f = OpenOptions::new().read(true).write(true).create(true).open(p("t")).unwrap();
            f.write_all(&pattern(1000, 5)).unwrap();
            t.check("set_len shrinks", f.set_len(10).is_ok() && f.seek(SeekFrom::End(0)).ok() == Some(10), String::new());
            t.check("set_len grows", f.set_len(5000).is_ok() && f.seek(SeekFrom::End(0)).ok() == Some(5000), String::new());
            f.seek(SeekFrom::Start(100)).unwrap();
            let mut z = [7u8; 8]; f.read_exact(&mut z).unwrap();
            t.check("grown part reads as zeros", z == [0u8; 8], format!("{z:?}"));
            t.check("shrunk part is kept", { f.seek(SeekFrom::Start(0)).unwrap(); let mut h = [0u8; 10]; f.read_exact(&mut h).unwrap(); h == pattern(1000, 5)[..10] }, String::new());
            clean(&["t"]);
        }
        "dup" => {
            clean(&["d"]);
            fs::write(p("d"), b"0123456789").unwrap();
            let mut a = File::open(p("d")).unwrap();
            let mut b = a.try_clone().unwrap();
            let mut x = [0u8; 4]; a.read_exact(&mut x).unwrap();
            let mut y = [0u8; 4]; b.read_exact(&mut y).unwrap();
            println!("INFO try_clone shares the position: {}", &y == b"4567");
            t.check("try_clone reads", &x == b"0123" && (&y == b"4567" || &y == b"0123"), format!("{:?} {:?}", x, y));
            drop(a);
            t.check("a clone survives the original being closed", b.read(&mut y).is_ok(), String::new());
            clean(&["d"]);
        }
        "unlink" => {
            clean(&["u"]);
            fs::write(p("u"), b"x").unwrap();
            t.check("remove_file", fs::remove_file(p("u")).is_ok(), String::new());
            t.kind("open after remove", File::open(p("u")), ErrorKind::NotFound);
            t.kind("remove missing", fs::remove_file(p("u")), ErrorKind::NotFound);
            { let f = File::create(p("u")).unwrap(); let _ = f; }
            let held = File::open(p("u")).unwrap();
            let r = fs::remove_file(p("u"));
            t.check("remove a file that is open is refused as busy", r.as_ref().is_err_and(|e| e.kind() == ErrorKind::ResourceBusy), format!("{:?}", r.as_ref().map_err(|e| (e.kind(), e.raw_os_error()))));
            t.check("the file still exists", File::open(p("u")).is_ok(), String::new());
            drop(held);
            t.check("after closing it, remove works", fs::remove_file(p("u")).is_ok(), String::new());
        }
        "sync" => {
            clean(&["y"]);
            let mut f = File::create(p("y")).unwrap();
            f.write_all(b"data").unwrap();
            t.check("flush", f.flush().is_ok(), String::new());
            t.check("sync_all", f.sync_all().is_ok(), String::new());
            t.check("sync_data", f.sync_data().is_ok(), String::new());
            clean(&["y"]);
        }
        "unsupported" => {
            clean(&["n"]);
            let f = File::create(p("n")).unwrap();
            t.kind("metadata", f.metadata(), ErrorKind::Unsupported);
            t.kind("fs::metadata", fs::metadata(p("n")), ErrorKind::Unsupported);
            t.kind("lock", f.lock(), ErrorKind::Unsupported);
            t.kind("read_dir", fs::read_dir(BASE), ErrorKind::Unsupported);
            t.kind("create_dir", fs::create_dir(p("newdir")), ErrorKind::Unsupported);
            t.kind("rename", fs::rename(p("n"), p("n2")), ErrorKind::Unsupported);
            t.kind("canonicalize", fs::canonicalize(p("n")), ErrorKind::Unsupported);
            clean(&["n"]);
        }
        "errors" => {
            clean(&["e"]);
            fs::write(p("e"), b"1").unwrap();
            // A path that goes through a file is not a directory.
            let r = File::open(p("e/inner"));
            println!("INFO path through a file: {:?}", r.as_ref().map_err(|e| (e.kind(), e.raw_os_error())));
            // Opening a volume root or a directory as a file.
            let r = OpenOptions::new().write(true).open("RAM:ami-rust-m1");
            println!("INFO a directory opened for writing: {:?}", r.as_ref().map_err(|e| (e.kind(), e.raw_os_error())));
            let r = File::open("RAM:ami-rust-m1");
            println!("INFO a directory opened for reading: {:?}", r.as_ref().map(|_| ()).map_err(|e| (e.kind(), e.raw_os_error())));
            let r = File::create("RAM:");
            println!("INFO a volume opened for writing: {:?}", r.as_ref().map(|_| ()).map_err(|e| (e.kind(), e.raw_os_error())));
            // The program starts on a read-only volume (the delivery CD), so writing there is refused.
            let r = fs::write("NATIVERUN:ami-ro-probe", b"x");
            t.check("a write to a read-only volume is refused with a kind", r.as_ref().is_err_and(|e| matches!(e.kind(), ErrorKind::ReadOnlyFilesystem | ErrorKind::PermissionDenied)), format!("{:?}", r.as_ref().map_err(|e| (e.kind(), e.raw_os_error()))));
            t.check("the message of a DOS error is readable", { let m = format!("{}", r.unwrap_err()); !m.contains("Unknown") && m.contains("DOS error") }, String::new());
            clean(&["e"]);
        }
        "requesters" => {
            // The window pointer of the process must be the same after file system calls as before.
            // It is read through the bridge function that std uses: set it, and get the old value back.
            unsafe extern "C" { fn sdk_proc_window_set(window: *mut std::ffi::c_void) -> *mut std::ffi::c_void; }
            let read = || unsafe { let old = sdk_proc_window_set(usize::MAX as *mut _); sdk_proc_window_set(old); old as usize };
            let before = read();
            let _ = File::open("NOSUCHVOLUME:a");
            let _ = fs::remove_file("NOSUCHVOLUME:a");
            let _ = File::open(p("not-there"));
            let after = read();
            t.check("window pointer restored", after == before, format!("{before:#x} then {after:#x}"));
            t.check("window pointer is not -1 outside the calls", after != usize::MAX, String::new());
        }
        "seekprobe" => {
            // Seeks past the end of a 1000-byte file: the position is exactly what POSIX says, and the
            // file is not changed by the seek, on either ABI.
            for (name, from) in [("Start", 0u8), ("Current", 1), ("End", 2)] {
                for target in [0i64, 10, 999, 1000, 1001, 1500, 5000] {
                    clean(&["sp"]);
                    fs::write(p("sp"), vec![1u8; 1000]).unwrap();
                    let mut f = OpenOptions::new().read(true).write(true).open(p("sp")).unwrap();
                    let (pos, expected) = match from {
                        0 => (f.seek(SeekFrom::Start(target as u64)), target as u64),
                        1 => (f.seek(SeekFrom::Current(target)), target as u64),
                        _ => (f.seek(SeekFrom::End(target)), 1000 + target as u64),
                    };
                    let tell = f.stream_position().ok();
                    let mut b = [9u8; 4];
                    let read = f.read(&mut b);
                    let read_ok = if expected >= 1000 { read.as_ref().ok() == Some(&0) } else { read.as_ref().is_ok_and(|n| *n > 0) };
                    drop(f);
                    let len = fs::read(p("sp")).unwrap().len();
                    t.check(&format!("seek {name}({target}) -> {expected}"), pos.as_ref().ok() == Some(&expected) && tell == Some(expected) && read_ok && len == 1000,
                        format!("position {:?}, tell {tell:?}, read {read:?}, file {len} bytes", pos.as_ref().map_err(|e| e.kind())));
                }
            }
            clean(&["sp"]);
        }
        "seekro" => {
            // A READ-ONLY handle that seeks past the end must not change the file.
            clean(&["sr"]);
            fs::write(p("sr"), vec![1u8; 1000]).unwrap();
            {
                let mut f = File::open(p("sr")).unwrap();
                let pos = f.seek(SeekFrom::Start(3000));
                let mut b = [0u8; 4];
                let n = f.read(&mut b);
                t.check("read-only: seek past the end, read gives 0", pos.as_ref().ok() == Some(&3000) && n.as_ref().ok() == Some(&0), format!("{pos:?} {n:?}"));
                t.check("read-only: seek back into the file reads data again", f.seek(SeekFrom::Start(10)).ok() == Some(10) && f.read(&mut b).ok() == Some(4) && b == [1; 4], String::new());
            }
            let len = fs::read(p("sr")).unwrap().len();
            t.check("a read-only handle's seek does not change the file", len == 1000, format!("{len} bytes"));
            clean(&["sr"]);
        }
        "seekwrite" => {
            // A write after a seek past the end extends the file with zeros, and only up to the write.
            clean(&["sw"]);
            fs::write(p("sw"), vec![1u8; 1000]).unwrap();
            let mut f = OpenOptions::new().read(true).write(true).open(p("sw")).unwrap();
            t.check("seek past the end", f.seek(SeekFrom::Start(1500)).ok() == Some(1500), String::new());
            t.check("file unchanged before the write", fs::read(p("sw")).unwrap().len() == 1000, String::new());
            t.check("write there", f.write_all(b"XY").is_ok(), String::new());
            t.check("position after the write", f.stream_position().ok() == Some(1502), format!("{:?}", f.stream_position().ok()));
            drop(f);
            let data = fs::read(p("sw")).unwrap();
            t.check("length is exactly position + data", data.len() == 1502, format!("{}", data.len()));
            t.check("old data kept, gap is zeros, data in place", data[..1000].iter().all(|&b| b == 1) && data[1000..1500].iter().all(|&b| b == 0) && &data[1500..] == b"XY", String::new());
            // a duplicate shares the remembered position
            let mut a = OpenOptions::new().read(true).write(true).open(p("sw")).unwrap();
            let mut b = a.try_clone().unwrap();
            a.seek(SeekFrom::Start(2000)).unwrap();
            t.check("a clone sees the same position", b.stream_position().ok() == Some(2000), format!("{:?}", b.stream_position().ok()));
            b.write_all(b"Z").unwrap();
            t.check("and writing through it extends the file", fs::read(p("sw")).unwrap().len() == 2001, String::new());
            // append ignores a remembered position
            let mut ap = OpenOptions::new().append(true).open(p("sw")).unwrap();
            ap.seek(SeekFrom::Start(9000)).unwrap();
            ap.write_all(b"!").unwrap();
            t.check("append writes at the end, not at the remembered position", fs::read(p("sw")).unwrap().len() == 2002, String::new());
            clean(&["sw"]);
        }
        "paths" => {
            clean(&["with space", "two.dots.txt", "n"]);
            t.check("name with a space", fs::write(p("with space"), b"1").is_ok() && fs::read(p("with space")).is_ok(), String::new());
            t.check("name with dots", fs::write(p("two.dots.txt"), b"1").is_ok() && fs::read(p("two.dots.txt")).is_ok(), String::new());
            // a non-ASCII byte (Latin-1 e acute) in a name
            let name: OsString = unsafe { OsString::from_encoded_bytes_unchecked(b"RAM:ami-rust-m1/caf\xe9".to_vec()) };
            let r = fs::write(Path::new(&name), b"1");
            println!("INFO name with a Latin-1 byte: write {:?}, read back {:?}", r.as_ref().map_err(|e| e.kind()), fs::read(Path::new(&name)).map(|v| v.len()).map_err(|e| e.kind()));
            let _ = fs::remove_file(Path::new(&name));
            t.check("NIL: accepts writes", File::create("NIL:").and_then(|mut f| f.write_all(b"discarded")).is_ok(), String::new());
            t.check("a file at the root of a volume", fs::write("RAM:ami-root-file", b"r").is_ok() && fs::read("RAM:ami-root-file").ok().as_deref() == Some(b"r"), String::new());
            let _ = fs::remove_file("RAM:ami-root-file");
            let rel = fs::write("ami-rel-file", b"rel");
            println!("INFO relative path: write {:?}", rel.as_ref().map_err(|e| (e.kind(), e.raw_os_error())));
            t.check("relative path round trip", rel.is_ok() && fs::read("ami-rel-file").ok().as_deref() == Some(b"rel"), String::new());
            let _ = fs::remove_file("ami-rel-file");
            for len in [30, 31, 100, 107, 108, 120] {
                let long = format!("{BASE}{}", "x".repeat(len));
                let rl = fs::write(&long, b"1");
                println!("INFO a {len}-character file name: {:?}", rl.as_ref().map_err(|e| e.kind()));
                let _ = fs::remove_file(&long);
            }
            let env = fs::read("ENV:ami-env-probe");
            println!("INFO a DOS variable as a file (ENV:): {:?}", env.map_err(|e| e.kind()));
            clean(&["with space", "two.dots.txt"]);
        }
        _ => println!("modes: rw large seek open trunc dup unlink sync unsupported paths errors requesters seekprobe seekro seekwrite"),
    }
    println!("RESULT fs summary {} of {} checks passed", t.total - t.failed, t.total);
    if t.failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(3) }
}

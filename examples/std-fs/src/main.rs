//! The file system in `std` on AROS: files (open, read, write, seek, truncate, duplicate), metadata and
//! file dates, permissions, directories, `copy`, the errors, and the behaviours of the C library that
//! `std` has to work around. One behaviour per run; the expected results are in README.md. The files
//! are made in `RAM:ami-rust-m1/`, which the run must create.

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
fn rm_all(name: &str) { let _ = fs::remove_dir_all(p(name)); }
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
            t.kind("lock", f.lock(), ErrorKind::Unsupported);
            t.kind("set_modified", f.set_modified(std::time::SystemTime::now()), ErrorKind::Unsupported);
            t.kind("rename", fs::rename(p("n"), p("n2")), ErrorKind::Unsupported);
            t.kind("canonicalize", fs::canonicalize(p("n")), ErrorKind::Unsupported);
            t.kind("read_link", fs::read_link(p("n")), ErrorKind::Unsupported);
            t.kind("hard_link", fs::hard_link(p("n"), p("n2")), ErrorKind::Unsupported);
            drop(f);
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
            let ro_kinds = |r: io::Result<()>| r.as_ref().is_err_and(|e| matches!(e.kind(), ErrorKind::ReadOnlyFilesystem | ErrorKind::PermissionDenied));
            let r = fs::create_dir("NATIVERUN:ami-ro-dir");
            t.check("create_dir on a read-only volume is refused with a kind", ro_kinds(r.as_ref().map(|_| ()).map_err(|e| io::Error::from(e.kind()))), format!("{:?}", r.map_err(|e| (e.kind(), e.raw_os_error()))));
            let r = fs::remove_file("NATIVERUN:prog");
            t.check("remove_file on a read-only volume is refused with a kind", ro_kinds(r.as_ref().map(|_| ()).map_err(|e| io::Error::from(e.kind()))), format!("{:?}", r.map_err(|e| (e.kind(), e.raw_os_error()))));
            t.check("the delivery volume can be listed and examined", fs::read_dir("NATIVERUN:").is_ok_and(|d| d.filter_map(Result::ok).any(|e| e.file_name() == "prog" && e.metadata().is_ok_and(|m| m.is_file()))), String::new());
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
        "meta" => {
            clean(&["m1", "m2"]);
            fs::write(p("m1"), vec![7u8; 1234]).unwrap();
            let m = fs::metadata(p("m1")).unwrap();
            t.check("file length", m.len() == 1234, format!("{}", m.len()));
            t.check("file type", m.is_file() && !m.is_dir() && !m.file_type().is_symlink(), String::new());
            t.check("a new file is not read-only", !m.permissions().readonly(), format!("{:?}", m.permissions()));
            t.check("Debug of Metadata", !format!("{m:?}").is_empty(), String::new());
            t.check("created is unsupported (DOS has one date)", m.created().is_err_and(|e| e.kind() == ErrorKind::Unsupported), String::new());
            t.check("accessed works", m.accessed().is_ok(), String::new());
            let s = fs::symlink_metadata(p("m1")).unwrap();
            t.check("symlink_metadata of a file", s.len() == 1234 && s.is_file(), String::new());
            let d = fs::metadata(BASE).unwrap();
            t.check("directory", d.is_dir() && !d.is_file(), String::new());
            t.check("directory without the trailing slash", fs::metadata(BASE.trim_end_matches('/')).is_ok_and(|m| m.is_dir()), String::new());
            t.check("volume root", fs::metadata("RAM:").is_ok_and(|m| m.is_dir()), String::new());
            t.kind("missing file", fs::metadata(p("nonexist")), ErrorKind::NotFound);
            t.kind("missing volume", fs::metadata("NOSUCHVOLUME:x"), ErrorKind::NotFound);
            t.kind("missing directory", fs::metadata(p("nodir/x")), ErrorKind::NotFound);
            // Unix says NotADirectory here; the C library reports "object not found".
            t.kind("path through a file", fs::metadata(p("m1/x")), ErrorKind::NotFound);
            // DOS takes an empty path for the current directory; std refuses it as Unix does.
            t.kind("empty path: metadata", fs::metadata(""), ErrorKind::NotFound);
            t.kind("empty path: open", File::open(""), ErrorKind::NotFound);
            t.kind("empty path: read_dir", fs::read_dir(""), ErrorKind::NotFound);
            t.kind("empty path: create_dir", fs::create_dir(""), ErrorKind::NotFound);
            t.kind("empty path: remove_file", fs::remove_file(""), ErrorKind::NotFound);
            t.kind("empty path: remove_dir", fs::remove_dir(""), ErrorKind::NotFound);
            t.check("exists", fs::exists(p("m1")).ok() == Some(true) && fs::exists(BASE).ok() == Some(true) && fs::exists(p("nonexist")).ok() == Some(false) && fs::exists("NOSUCHVOLUME:x").ok() == Some(false), String::new());
            let mut f = OpenOptions::new().read(true).write(true).create(true).open(p("m2")).unwrap();
            f.write_all(b"abcdefgh").unwrap();
            t.check("File::metadata sees what was written", f.metadata().is_ok_and(|m| m.len() == 8 && m.is_file()), String::new());
            t.check("fs::metadata of a file that is open for writing", fs::metadata(p("m2")).is_ok_and(|m| m.len() == 8), String::new());
            t.check("File::metadata after set_len", f.set_len(3).is_ok() && f.metadata().is_ok_and(|m| m.len() == 3), String::new());
            drop(f);
            let nil = File::create("NIL:").and_then(|f| f.metadata());
            println!("INFO metadata of NIL: {:?}", nil.map(|m| (m.len(), m.is_file())).map_err(|e| (e.kind(), e.raw_os_error(), e.to_string())));
            clean(&["m1", "m2"]);
        }
        "times" => {
            use std::time::{Duration, SystemTime, UNIX_EPOCH};
            clean(&["tm"]);
            let diff = |a: SystemTime, b: SystemTime| -> i64 {
                match a.duration_since(b) {
                    Ok(d) => d.as_secs() as i64,
                    Err(e) => -(e.duration().as_secs() as i64),
                }
            };
            fs::write(p("tm"), b"1").unwrap();
            let now = SystemTime::now();
            let m = fs::metadata(p("tm")).unwrap();
            let t1 = m.modified().unwrap();
            let secs = t1.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            println!("INFO the file's date is {secs} s after 1970, year {}; SystemTime::now is {} s later", 1970 + secs / 31_556_952, diff(now, t1));
            t.check("modified is the time of the write", (-2..=2).contains(&diff(now, t1)), format!("{} s", diff(now, t1)));
            t.check("accessed is the same date", m.accessed().ok() == Some(t1), String::new());
            t.check("whole seconds", t1.duration_since(UNIX_EPOCH).is_ok_and(|d| d.subsec_nanos() == 0), String::new());
            std::thread::sleep(Duration::from_millis(2100));
            fs::write(p("tm"), b"22").unwrap();
            let t2 = fs::metadata(p("tm")).unwrap().modified().unwrap();
            t.check("a later write gives a later date", t2 > t1 && diff(t2, t1) <= 4, format!("{} s", diff(t2, t1)));
            let dir = fs::metadata(BASE).unwrap().modified();
            t.check("a directory has a date", dir.is_ok(), String::new());
            let old = fs::metadata("NATIVERUN:prog").and_then(|m| m.modified());
            println!("INFO date of NATIVERUN:prog (the delivery volume): {:?}", old.map(|t| t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)).map_err(|e| e.kind()));
            clean(&["tm"]);
        }
        "dirs" => {
            rm_all("dd"); clean(&["df"]);
            t.check("create_dir", fs::create_dir(p("dd")).is_ok(), String::new());
            t.check("it is a directory", fs::metadata(p("dd")).is_ok_and(|m| m.is_dir()), String::new());
            t.kind("create_dir again", fs::create_dir(p("dd")), ErrorKind::AlreadyExists);
            t.kind("create_dir with a missing parent", fs::create_dir(p("nodir/sub")), ErrorKind::NotFound);
            fs::write(p("df"), b"x").unwrap();
            t.kind("create_dir over a file", fs::create_dir(p("df")), ErrorKind::AlreadyExists);
            t.check("create_dir_all", fs::create_dir_all(p("dd/a/b/c")).is_ok() && fs::metadata(p("dd/a/b/c")).is_ok_and(|m| m.is_dir()), String::new());
            t.check("create_dir_all again", fs::create_dir_all(p("dd/a/b/c")).is_ok(), String::new());
            t.check("create_dir_all with a trailing slash", fs::create_dir_all(p("dd/s/t/")).is_ok() && fs::metadata(p("dd/s/t")).is_ok_and(|m| m.is_dir()), String::new());
            let through = fs::create_dir_all(p("df/x/y"));
            println!("INFO create_dir_all through a file: {:?}", through.as_ref().map_err(|e| (e.kind(), e.raw_os_error())));
            t.check("create_dir_all through a file fails", through.is_err(), String::new());
            t.check("remove_dir on an empty directory", fs::remove_dir(p("dd/a/b/c")).is_ok() && fs::metadata(p("dd/a/b/c")).is_err(), String::new());
            // ABI-v1 reports no error at all for this (errno 0); std reports it as not empty.
            t.kind("remove_dir on a directory that is not empty", fs::remove_dir(p("dd/a")), ErrorKind::DirectoryNotEmpty);
            t.check("... which is still there", fs::metadata(p("dd/a/b")).is_ok_and(|m| m.is_dir()), String::new());
            // The C library of ABI-v1 does not set an error for this, so an earlier failure shows through.
            let _ = fs::create_dir(p("dd/a"));
            t.kind("... also when the last failed call was another one", fs::remove_dir(p("dd/a")), ErrorKind::DirectoryNotEmpty);
            let _ = fs::metadata(p("nonexist"));
            t.kind("... and after a failed lookup", fs::remove_dir(p("dd/a")), ErrorKind::DirectoryNotEmpty);
            t.kind("remove_dir on a missing directory", fs::remove_dir(p("dd/zz")), ErrorKind::NotFound);
            // The C library deletes a file with rmdir and a directory with unlink; std refuses both.
            t.kind("remove_dir on a file", fs::remove_dir(p("df")), ErrorKind::NotADirectory);
            t.check("... the file is still there", fs::metadata(p("df")).is_ok_and(|m| m.is_file()), String::new());
            t.kind("remove_file on a directory", fs::remove_file(p("dd/a/b")), ErrorKind::IsADirectory);
            t.check("... the directory is still there", fs::metadata(p("dd/a/b")).is_ok_and(|m| m.is_dir()), String::new());
            t.check("remove_dir of the emptied directories", fs::remove_dir(p("dd/a/b")).is_ok() && fs::remove_dir(p("dd/a")).is_ok(), String::new());
            rm_all("dd"); clean(&["df"]);
        }
        "readdir" => {
            rm_all("rd"); rm_all("many");
            fs::create_dir_all(p("rd/sub")).unwrap();
            fs::create_dir(p("rd/empty")).unwrap();
            fs::write(p("rd/f1"), b"1").unwrap();
            fs::write(p("rd/sub/f2"), b"22").unwrap();
            fs::write(p("rd/with space"), b"333").unwrap();
            let mut got: Vec<(String, bool, bool, u64)> = fs::read_dir(p("rd")).unwrap().map(|e| {
                let e = e.unwrap();
                let ft = e.file_type().unwrap();
                (e.file_name().to_string_lossy().into_owned(), ft.is_dir(), ft.is_file(), e.metadata().unwrap().len())
            }).collect();
            got.sort();
            let want = vec![("empty".to_string(), true, false, 0), ("f1".to_string(), false, true, 1), ("sub".to_string(), true, false, 0), ("with space".to_string(), false, true, 3)];
            t.check("entries, types and sizes", got == want, format!("{got:?}"));
            let mut paths: Vec<String> = fs::read_dir(p("rd")).unwrap().map(|e| e.unwrap().path().to_string_lossy().into_owned()).collect();
            paths.sort();
            t.check("entry paths", paths == ["RAM:ami-rust-m1/rd/empty", "RAM:ami-rust-m1/rd/f1", "RAM:ami-rust-m1/rd/sub", "RAM:ami-rust-m1/rd/with space"], format!("{paths:?}"));
            let slash: Vec<String> = fs::read_dir(p("rd/")).unwrap().map(|e| e.unwrap().path().to_string_lossy().into_owned()).collect();
            t.check("entry paths of a path with a trailing slash have no double slash", slash.iter().all(|s| !s.contains("//")), format!("{slash:?}"));
            t.check("no . or ..", got.iter().all(|e| e.0 != "." && e.0 != ".."), String::new());
            t.check("an entry outlives its ReadDir", { let e = fs::read_dir(p("rd")).unwrap().next().unwrap().unwrap(); e.metadata().is_ok() && e.path().to_string_lossy().starts_with("RAM:ami-rust-m1/rd/") }, String::new());
            t.check("an empty directory has no entries", fs::read_dir(p("rd/empty")).unwrap().count() == 0, String::new());
            t.check("a directory can be listed twice", fs::read_dir(p("rd")).unwrap().count() == 4 && fs::read_dir(p("rd")).unwrap().count() == 4, String::new());
            t.check("Debug of ReadDir", format!("{:?}", fs::read_dir(p("rd")).unwrap()).contains("rd"), String::new());
            t.kind("read_dir of a file", fs::read_dir(p("rd/f1")), ErrorKind::NotADirectory);
            t.kind("read_dir of a missing directory", fs::read_dir(p("nonexist")), ErrorKind::NotFound);
            t.kind("read_dir of a missing volume", fs::read_dir("NOSUCHVOLUME:"), ErrorKind::NotFound);
            let root: Vec<_> = fs::read_dir("RAM:").unwrap().map(|e| e.unwrap()).collect();
            t.check("RAM: lists entries", !root.is_empty(), String::new());
            // Path::join would give "RAM:/T", which is the parent of the volume.
            t.check("paths below a volume name have no slash after the colon", root.iter().all(|e| { let s = e.path().to_string_lossy().into_owned(); s.starts_with("RAM:") && !s.starts_with("RAM:/") }), String::new());
            t.check("the entries of RAM: can be examined", root.iter().all(|e| e.metadata().is_ok()), String::new());
            fs::create_dir(p("many")).unwrap();
            let long = "x".repeat(107);
            for i in 0..300 { fs::write(p(&format!("many/file-{i:03}")), b"x").unwrap(); }
            fs::write(p(&format!("many/{long}")), b"x").unwrap();
            let mut names: Vec<String> = fs::read_dir(p("many")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            let total = names.len();
            names.sort(); names.dedup();
            t.check("301 entries, all different", total == 301 && names.len() == 301, format!("{total} entries, {} different", names.len()));
            t.check("a 107-character name is listed whole", names.iter().any(|n| *n == long), String::new());
            let mut removed = 0;
            for e in fs::read_dir(p("many")).unwrap() { if fs::remove_file(e.unwrap().path()).is_ok() { removed += 1; } }
            t.check("deleting while listing removes every entry", removed == 301 && fs::read_dir(p("many")).unwrap().count() == 0, format!("{removed} removed"));
            for _ in 0..300 { let mut r = fs::read_dir(p("rd")).unwrap(); let _ = r.next(); }
            t.check("300 listings dropped after one entry, and listing still works", fs::read_dir(p("rd")).unwrap().count() == 4, String::new());
            rm_all("rd"); rm_all("many");
        }
        "perm" => {
            clean(&["pm"]);
            fs::write(p("pm"), b"data").unwrap();
            let mut perm = fs::metadata(p("pm")).unwrap().permissions();
            t.check("a new file is writable", !perm.readonly(), String::new());
            perm.set_readonly(true);
            t.check("set_permissions read-only", fs::set_permissions(p("pm"), perm.clone()).is_ok(), String::new());
            t.check("read-only afterwards", fs::metadata(p("pm")).unwrap().permissions().readonly(), String::new());
            let w = fs::write(p("pm"), b"x");
            t.check("writing to a read-only file is refused", w.as_ref().is_err_and(|e| e.kind() == ErrorKind::PermissionDenied), format!("{:?}", w.map_err(|e| (e.kind(), e.raw_os_error()))));
            t.check("and the content is unchanged", fs::read(p("pm")).unwrap() == b"data", String::new());
            t.check("reading is allowed", File::open(p("pm")).is_ok(), String::new());
            t.check("appending is refused", OpenOptions::new().append(true).open(p("pm")).and_then(|mut f| f.write_all(b"y")).is_err(), String::new());
            // DOS keeps the right to delete apart from the right to write.
            let mut copy = perm.clone();
            copy.set_readonly(false);
            t.check("set_permissions writable", fs::set_permissions(p("pm"), copy).is_ok() && !fs::metadata(p("pm")).unwrap().permissions().readonly(), String::new());
            t.check("writing works again", fs::write(p("pm"), b"z").is_ok(), String::new());
            {
                let f = File::open(p("pm")).unwrap();
                let mut pr = f.metadata().unwrap().permissions();
                pr.set_readonly(true);
                t.check("File::set_permissions", f.set_permissions(pr).is_ok(), String::new());
            }
            t.check("... visible through the path", fs::metadata(p("pm")).unwrap().permissions().readonly(), String::new());
            t.check("a read-only file can be deleted (DOS has a separate delete right)", fs::remove_file(p("pm")).is_ok(), String::new());
            t.kind("set_permissions on a missing file", fs::set_permissions(p("nonexist"), perm), ErrorKind::NotFound);
            clean(&["pm"]);
        }
        "copy" => {
            clean(&["c1", "c2", "c3", "c4", "c5"]);
            let data = pattern(70_000, 9);
            fs::write(p("c1"), &data).unwrap();
            t.check("copy returns the length", fs::copy(p("c1"), p("c2")).ok() == Some(70_000), String::new());
            t.check("the copy has the content", fs::read(p("c2")).unwrap() == data, String::new());
            fs::write(p("c3"), vec![1u8; 100_000]).unwrap();
            t.check("copy over a longer file", fs::copy(p("c1"), p("c3")).is_ok() && fs::read(p("c3")).unwrap() == data, String::new());
            fs::write(p("c1"), b"").unwrap();
            t.check("copy of an empty file", fs::copy(p("c1"), p("c4")).ok() == Some(0) && fs::read(p("c4")).unwrap().is_empty(), String::new());
            fs::write(p("c1"), b"ro").unwrap();
            let mut perm = fs::metadata(p("c1")).unwrap().permissions();
            perm.set_readonly(true);
            fs::set_permissions(p("c1"), perm).unwrap();
            t.check("the permissions are copied", fs::copy(p("c1"), p("c5")).is_ok() && fs::metadata(p("c5")).unwrap().permissions().readonly(), String::new());
            t.kind("copy of a directory", fs::copy(BASE, p("c6")), ErrorKind::InvalidInput);
            t.kind("copy of a missing file", fs::copy(p("nonexist"), p("c6")), ErrorKind::NotFound);
            t.check("a failed copy leaves no file", fs::metadata(p("c6")).is_err(), String::new());
            clean(&["c1", "c2", "c3", "c4", "c5"]);
        }
        "removeall" => {
            rm_all("ra"); clean(&["raf"]);
            fs::create_dir_all(p("ra/a/b")).unwrap();
            fs::create_dir_all(p("ra/c")).unwrap();
            for i in 0..60 {
                fs::write(p(&format!("ra/f{i}")), b"x").unwrap();
                fs::write(p(&format!("ra/a/g{i}")), b"x").unwrap();
                fs::write(p(&format!("ra/a/b/h{i}")), b"x").unwrap();
            }
            t.check("remove_dir_all of a tree of 180 files", fs::remove_dir_all(p("ra")).is_ok(), String::new());
            t.check("it is gone", fs::metadata(p("ra")).is_err(), String::new());
            t.kind("remove_dir_all of a missing directory", fs::remove_dir_all(p("ra")), ErrorKind::NotFound);
            fs::write(p("raf"), b"1").unwrap();
            t.kind("remove_dir_all of a file", fs::remove_dir_all(p("raf")), ErrorKind::NotADirectory);
            t.check("the file is still there", fs::metadata(p("raf")).is_ok_and(|m| m.is_file()), String::new());
            clean(&["raf"]);
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
        _ => println!("modes: rw large seek open trunc dup unlink sync unsupported paths errors requesters seekprobe seekro seekwrite meta times dirs readdir perm copy removeall"),
    }
    println!("RESULT fs summary {} of {} checks passed", t.total - t.failed, t.total);
    if t.failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(3) }
}

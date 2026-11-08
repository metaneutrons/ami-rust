//! Paths in `std` on AROS: the syntax of `volume:dir/name` in `std::path`, the current directory,
//! `path::absolute`, the temporary directory and path lists. One behaviour per run; the expected
//! results are in README.md. The `cwd` mode makes files in `RAM:ami-rust-m1/`, which the run must create,
//! and must start there (`CD RAM:ami-rust-m1`).

#![feature(restricted_std)]
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::ExitCode;

const BASE: &str = "RAM:ami-rust-m1";

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
        println!(
            "RESULT path {name} {}{}",
            if ok { "ok" } else { "FAIL" },
            if detail.is_empty() { String::new() } else { format!(" ({detail})") }
        );
    }
    /// A value against the expected one, shown on a failure.
    fn is<V: PartialEq + std::fmt::Debug>(&mut self, name: &str, got: V, want: V) {
        let ok = got == want;
        let detail = if ok { String::new() } else { format!("got {got:?}, wanted {want:?}") };
        self.check(name, ok, detail);
    }
    fn kind(&mut self, name: &str, r: io::Result<impl Sized>, want: ErrorKind) {
        match r {
            Ok(_) => self.check(name, false, format!("succeeded, wanted {want:?}")),
            Err(e) => self.check(name, e.kind() == want, format!("got {:?} (os error {:?}), wanted {want:?}", e.kind(), e.raw_os_error())),
        }
    }
}

fn comps(path: &str) -> Vec<String> {
    Path::new(path)
        .components()
        .map(|c| match c {
            Component::Prefix(p) => format!("P:{}", p.as_os_str().to_string_lossy()),
            Component::RootDir => "/".to_string(),
            Component::CurDir => ".".to_string(),
            Component::ParentDir => "..".to_string(),
            Component::Normal(s) => s.to_string_lossy().into_owned(),
        })
        .collect()
}

/// The volume of the current directory with its colon. DOS reports the name of the volume, which is
/// not always the name that the run used: `RAM:` is the volume `RAM Disk:`.
fn volume() -> String {
    match env::current_dir().unwrap().components().next() {
        Some(Component::Prefix(p)) => p.as_os_str().to_string_lossy().into_owned(),
        _ => String::new(),
    }
}

fn join(a: &str, b: &str) -> String {
    Path::new(a).join(b).to_string_lossy().into_owned()
}

fn s(p: Option<&Path>) -> Option<String> {
    p.map(|p| p.to_string_lossy().into_owned())
}

fn os(p: Option<&OsStr>) -> Option<String> {
    p.map(|p| p.to_string_lossy().into_owned())
}

fn main() -> ExitCode {
    let mode = env::args().nth(1).unwrap_or_default();
    let mut t = T { failed: 0, total: 0 };
    match mode.as_str() {
        "components" => {
            let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
            t.is("a path with a volume", comps("RAM:T/x"), v(&["P:RAM:", "T", "x"]));
            t.is("a volume alone", comps("RAM:"), v(&["P:RAM:"]));
            t.is("a trailing slash", comps("RAM:T/"), v(&["P:RAM:", "T"]));
            t.is("a relative path", comps("dir/file"), v(&["dir", "file"]));
            t.is("one name", comps("file"), v(&["file"]));
            t.is("a leading slash (the parent in DOS)", comps("/x"), v(&["/", "x"]));
            t.is("a leading colon (no volume name)", comps(":x"), v(&[":x"]));
            t.is("a short volume name", comps("a:b/c"), v(&["P:a:", "b", "c"]));
            t.is("a colon in a later name", comps("dir/a:b"), v(&["dir", "a:b"]));
            t.is("a dot is dropped", comps("RAM:a/./b"), v(&["P:RAM:", "a", "b"]));
            t.is("two slashes collapse (DOS reads them as the parent)", comps("RAM:a//b"), v(&["P:RAM:", "a", "b"]));
            t.is("a double dot is kept", comps("RAM:a/.."), v(&["P:RAM:", "a", ".."]));
            t.is("spaces", comps("SYS:Tools/Dir Opus/x y"), v(&["P:SYS:", "Tools", "Dir Opus", "x y"]));
            t.is("an empty path", comps(""), Vec::<String>::new());
            let kind = Path::new("RAM:T").components().next().and_then(|c| match c {
                Component::Prefix(p) => Some(match p.kind() {
                    Prefix::DeviceNS(n) => format!("DeviceNS({})", n.to_string_lossy()),
                    _ => "other".to_string(),
                }),
                _ => None,
            });
            t.is("the prefix is the volume with its colon", kind, Some("DeviceNS(RAM:)".to_string()));
            let iter: Vec<String> = Path::new("RAM:T/x").iter().map(|c| c.to_string_lossy().into_owned()).collect();
            t.is("iter", iter, v(&["RAM:", "T", "x"]));
            let rebuilt: PathBuf = Path::new("RAM:T/x").components().collect();
            t.is("components collect back to the same path", rebuilt, PathBuf::from("RAM:T/x"));
            let from_iter: PathBuf = ["RAM:", "T", "x"].iter().collect();
            t.is("a PathBuf from names", from_iter, PathBuf::from("RAM:T/x"));
        }
        "absolute" => {
            for (p, want) in [("RAM:", true), ("RAM:T/x", true), ("T:", true), ("SYS:a/b", true), ("a:b", true), ("dir/x", false), ("x", false), ("/x", false), (":x", false), ("", false)] {
                t.is(&format!("is_absolute({p:?})"), Path::new(p).is_absolute(), want);
                t.is(&format!("is_relative({p:?})"), Path::new(p).is_relative(), !want);
            }
            t.check("has_root is only for a leading slash", !Path::new("RAM:T").has_root() && Path::new("/x").has_root(), String::new());
        }
        "parts" => {
            t.is("parent of a file", s(Path::new("RAM:T/x").parent()), Some("RAM:T".into()));
            t.is("parent of a directory below a volume", s(Path::new("RAM:T").parent()), Some("RAM:".into()));
            t.is("parent of a volume", s(Path::new("RAM:").parent()), None);
            t.is("parent of a relative path", s(Path::new("dir/x").parent()), Some("dir".into()));
            t.is("parent of one name", s(Path::new("x").parent()), Some("".into()));
            t.is("parent of an empty path", s(Path::new("").parent()), None);
            t.is("parent ignores a trailing slash", s(Path::new("RAM:T/").parent()), Some("RAM:".into()));
            t.is("file_name", os(Path::new("RAM:T/x.txt").file_name()), Some("x.txt".into()));
            t.is("file_name of a name below a volume", os(Path::new("RAM:T").file_name()), Some("T".into()));
            t.is("file_name of a volume", os(Path::new("RAM:").file_name()), None);
            t.is("file_name of a double dot", os(Path::new("RAM:T/..").file_name()), None);
            t.is("extension", os(Path::new("RAM:a.b/c.tar.gz").extension()), Some("gz".into()));
            t.is("file_stem", os(Path::new("RAM:a.b/c.tar.gz").file_stem()), Some("c.tar".into()));
            t.is("with_extension", Path::new("RAM:T/x.txt").with_extension("rs"), PathBuf::from("RAM:T/x.rs"));
            t.is("with_file_name", Path::new("RAM:T/x").with_file_name("y"), PathBuf::from("RAM:T/y"));
            t.is("with_file_name below a volume", Path::new("RAM:x").with_file_name("z"), PathBuf::from("RAM:z"));
            t.is("with_file_name on a volume", Path::new("RAM:").with_file_name("q"), PathBuf::from("RAM:q"));
            let ancestors: Vec<String> = Path::new("RAM:T/x").ancestors().map(|p| p.to_string_lossy().into_owned()).collect();
            t.is("ancestors", ancestors, vec!["RAM:T/x".to_string(), "RAM:T".to_string(), "RAM:".to_string()]);
            t.is("strip_prefix of a volume", s(Path::new("RAM:T/x").strip_prefix("RAM:").ok()), Some("T/x".into()));
            t.is("strip_prefix of a directory", s(Path::new("RAM:T/x").strip_prefix("RAM:T").ok()), Some("x".into()));
            t.check("strip_prefix of another volume fails", Path::new("DH0:x").strip_prefix("RAM:").is_err(), String::new());
            t.check("starts_with a directory", Path::new("RAM:T/x").starts_with("RAM:T"), String::new());
            t.check("starts_with compares whole names", !Path::new("RAM:T/x").starts_with("RAM"), String::new());
            t.check("ends_with", Path::new("RAM:T/x").ends_with("x") && Path::new("RAM:T/x").ends_with("T/x"), String::new());
            t.check("a dot does not change equality", Path::new("RAM:T/x") == Path::new("RAM:T/./x"), String::new());
            use std::hash::{BuildHasher, RandomState};
            let h = RandomState::new();
            t.check("or the hash", h.hash_one(Path::new("RAM:T/x")) == h.hash_one(Path::new("RAM:T/./x")), String::new());
            t.check("different volumes differ", Path::new("RAM:x") != Path::new("DH0:x"), String::new());
            t.is("display", format!("{}", Path::new("RAM:T/x").display()), "RAM:T/x".to_string());
        }
        "join" => {
            t.is("a name below a volume (the case that gave RAM:/x)", join("RAM:", "x"), "RAM:x".into());
            t.is("a name below a directory", join("RAM:T", "x"), "RAM:T/x".into());
            t.is("a directory with a trailing slash", join("RAM:T/", "x"), "RAM:T/x".into());
            t.is("relative", join("dir", "x"), "dir/x".into());
            t.is("another volume replaces the first", join("RAM:T", "DH0:y"), "DH0:y".into());
            t.is("a path below a volume", join("RAM:", "T/x"), "RAM:T/x".into());
            t.is("to an empty path", join("", "x"), "x".into());
            t.is("of an empty path", join("RAM:T", ""), "RAM:T/".into());
            t.is("a short volume name", join("a:", "b"), "a:b".into());
            let mut b = PathBuf::from("RAM:");
            b.push("a");
            b.push("b");
            t.is("push twice", b.clone(), PathBuf::from("RAM:a/b"));
            t.check("pop", b.pop() && b == Path::new("RAM:a") && b.pop() && b == Path::new("RAM:"), format!("{b:?}"));
            t.check("a volume cannot be popped", !b.pop() && b == Path::new("RAM:"), format!("{b:?}"));
            let mut c = PathBuf::from("RAM:T");
            c.set_file_name("U");
            t.is("set_file_name", c, PathBuf::from("RAM:U"));
            let mut d = PathBuf::from("RAM:T/x");
            d.set_extension("rs");
            t.is("set_extension", d, PathBuf::from("RAM:T/x.rs"));
            let mut e = PathBuf::from("RAM:");
            e.extend(["a", "b", "c"]);
            t.is("extend", e, PathBuf::from("RAM:a/b/c"));
            t.is("pushing a component", { let mut p = PathBuf::from("RAM:"); p.push(Component::Normal(OsStr::new("x"))); p }, PathBuf::from("RAM:x"));
        }
        "cwd" => {
            let cwd = env::current_dir();
            println!("INFO current directory: {:?}", cwd.as_ref().map_err(|e| (e.kind(), e.raw_os_error())));
            let vol = volume();
            let at = |rest: &str| PathBuf::from(format!("{vol}{rest}"));
            t.check("the volume has a name that differs from the assign", !vol.is_empty() && vol.ends_with(':'), vol.clone());
            t.is("current_dir is where the run started", cwd.as_ref().ok().cloned(), Some(at("ami-rust-m1")));
            t.check("and is absolute", cwd.as_ref().is_ok_and(|p| p.is_absolute()), String::new());
            t.check("and is the directory that BASE names", fs::metadata(cwd.as_ref().unwrap()).is_ok_and(|m| m.is_dir()) && fs::read_dir(BASE).is_ok_and(|a| fs::read_dir(cwd.as_ref().unwrap()).is_ok_and(|b| a.count() == b.count())), String::new());
            let _ = fs::remove_dir_all(Path::new(BASE).join("cd1"));
            fs::create_dir_all(Path::new(BASE).join("cd1/sub")).unwrap();
            fs::write(Path::new(BASE).join("cdfile"), b"x").unwrap();
            let _ = fs::remove_dir_all(Path::new(BASE).join("cd1"));
            fs::create_dir_all(Path::new(BASE).join("cd1/sub")).unwrap();
            fs::write(Path::new(BASE).join("cdfile"), b"x").unwrap();
            for dots in ["RAM:ami-rust-m1/cdfile", "RAM:ami-rust-m1/.", "RAM:ami-rust-m1/..", "RAM:ami-rust-m1/cd1/../cdfile", "./cdfile", "../ami-rust-m1/cdfile"] {
                println!("INFO DOS is given {dots:?}: {:?}", fs::metadata(dots).map(|m| (m.is_dir(), m.len())).map_err(|e| (e.kind(), e.raw_os_error())));
            }
            t.check("set_current_dir to a volume", env::set_current_dir("RAM:").is_ok() && env::current_dir().is_ok_and(|p| p == at("")), format!("{:?}", env::current_dir()));
            t.check("set_current_dir back", env::set_current_dir(BASE).is_ok() && env::current_dir().is_ok_and(|p| p == at("ami-rust-m1")), String::new());
            t.check("a relative set_current_dir", env::set_current_dir("cd1").is_ok() && env::current_dir().is_ok_and(|p| p == at("ami-rust-m1/cd1")), format!("{:?}", env::current_dir()));
            t.check("a relative path now means this directory", fs::write("f", b"y").is_ok() && fs::metadata("RAM:ami-rust-m1/cd1/f").is_ok_and(|m| m.is_file()), String::new());
            t.check("one level further down", env::set_current_dir("sub").is_ok() && env::current_dir().is_ok_and(|p| p == at("ami-rust-m1/cd1/sub")), format!("{:?}", env::current_dir()));
            // A leading slash is the parent in DOS; it goes through to the C library unchanged.
            t.check("a leading slash goes to the parent", env::set_current_dir("/").is_ok() && env::current_dir().is_ok_and(|p| p == at("ami-rust-m1/cd1")), format!("{:?}", env::current_dir()));
            t.kind("set_current_dir to a missing directory", env::set_current_dir("nodir"), ErrorKind::NotFound);
            t.kind("set_current_dir to a file", env::set_current_dir("f"), ErrorKind::NotADirectory);
            t.kind("set_current_dir to an empty path", env::set_current_dir(""), ErrorKind::NotFound);
            let started = std::time::Instant::now();
            t.kind("set_current_dir to a missing volume", env::set_current_dir("NOSUCHVOLUME:"), ErrorKind::NotFound);
            t.check("... at once", started.elapsed() < std::time::Duration::from_secs(5), String::new());
            t.check("a failed set_current_dir leaves the directory", env::current_dir().is_ok_and(|p| p == at("ami-rust-m1/cd1")), String::new());
            fs::remove_file("f").unwrap();
            t.check("back to the start", env::set_current_dir(BASE).is_ok(), String::new());
            let _ = fs::remove_dir_all(Path::new(BASE).join("cd1"));
            let _ = fs::remove_file(Path::new(BASE).join("cdfile"));
        }
        "make-absolute" => {
            let vol = volume();
            let abs = |p: &str| std::path::absolute(p).map(|p| p.to_string_lossy().into_owned()).map_err(|e| e.kind());
            t.is("a relative path", abs("x/y"), Ok(format!("{vol}ami-rust-m1/x/y")));
            t.is("one name", abs("x"), Ok(format!("{vol}ami-rust-m1/x")));
            t.is("an absolute path stays as it is", abs("RAM:T/x"), Ok("RAM:T/x".to_string()));
            t.is("a volume stays as it is", abs("RAM:"), Ok("RAM:".to_string()));
            t.is("a dot is dropped", abs("RAM:a/./b"), Ok("RAM:a/b".to_string()));
            t.is("a leading dot is dropped", abs("./x"), Ok(format!("{vol}ami-rust-m1/x")));
            t.is("a double dot is kept", abs("a/../b"), Ok(format!("{vol}ami-rust-m1/a/../b")));
            t.is("a leading colon is the root of this volume", abs(":x"), Ok(format!("{vol}x")));
            t.is("a leading slash is the parent", abs("/x"), Ok(format!("{vol}x")));
            t.is("two slashes: the root of the volume has no parent, so it stays", abs("//x"), Ok(format!("{vol}x")));
            t.is("an empty path", abs(""), Err(ErrorKind::InvalidInput));
            t.is("the current directory itself", abs("."), Ok(format!("{vol}ami-rust-m1")));
            t.check("it does not look at the file system", abs("no/such/dir/x").is_ok(), String::new());
            let _ = fs::create_dir_all(Path::new(BASE).join("ab/c"));
            env::set_current_dir("RAM:ami-rust-m1/ab/c").unwrap();
            t.is("a leading slash from a deeper directory", abs("/x"), Ok(format!("{vol}ami-rust-m1/ab/x")));
            t.is("two leading slashes", abs("//x"), Ok(format!("{vol}ami-rust-m1/x")));
            t.is("three leading slashes", abs("///x"), Ok(format!("{vol}x")));
            env::set_current_dir(BASE).unwrap();
            let _ = fs::remove_dir_all(Path::new(BASE).join("ab"));
        }
        "dots" => {
            // DOS knows neither "." nor "..": std resolves them before the path goes to the C library.
            let vol = volume();
            let d = |p: &str| fs::metadata(p).map(|m| (m.is_dir(), m.len())).map_err(|e| e.kind());
            let _ = fs::remove_dir_all(Path::new(BASE).join("dt"));
            fs::create_dir_all(Path::new(BASE).join("dt/a")).unwrap();
            fs::create_dir_all(Path::new(BASE).join("dt/b")).unwrap();
            fs::write(Path::new(BASE).join("dt/a/file"), b"123").unwrap();
            fs::write(Path::new(BASE).join("dt/b/other"), b"4567").unwrap();
            env::set_current_dir("RAM:ami-rust-m1/dt/b").unwrap();
            let here = env::current_dir().unwrap();
            t.is("a file in the current directory", d("./other"), Ok((false, 4)));
            t.is("a dot alone is the current directory", d("."), Ok((true, 0)));
            t.is("a dot in the middle", d("RAM:ami-rust-m1/dt/./a/file"), Ok((false, 3)));
            t.is("a leading double dot", d("../a/file"), Ok((false, 3)));
            t.is("a double dot after a name", d("RAM:ami-rust-m1/dt/a/../b/other"), Ok((false, 4)));
            t.is("a double dot alone is the parent", d("..").map(|m| m.0), Ok(true));
            t.check("... and it is the parent: it holds both directories", fs::read_dir("..").is_ok_and(|r| { let mut n: Vec<_> = r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect(); n.sort(); n == ["a", "b"] }), String::new());
            t.is("two levels up", d("../..").map(|m| m.0), Ok(true));
            t.check("... which is the directory of the run", fs::read_dir("../..").is_ok_and(|r| r.filter_map(Result::ok).any(|e| e.file_name() == "dt")), String::new());
            t.is("three levels up is the root of the volume", d("../../..").map(|m| m.0), Ok(true));
            t.is("a double dot at the root stays at the root", d("RAM:..").map(|m| m.0), Ok(true));
            t.is("and further up still", d("RAM:../../ami-rust-m1/dt/a/file"), Ok((false, 3)));
            t.is("a leading double dot, then down", d("../../dt/b/other"), Ok((false, 4)));
            t.is("two slashes in a row are one", d("RAM:ami-rust-m1//dt//a/file"), Ok((false, 3)));
            t.is("a trailing slash", d("RAM:ami-rust-m1/dt/a/"), Ok((true, 0)));
            t.is("a dot with a trailing slash", d("./"), Ok((true, 0)));
            t.is("a leading slash is still the DOS parent", d("/a/file"), Ok((false, 3)));
            t.is("and \"/..\" is the parent's parent", d("/../dt/a/file"), Ok((false, 3)));
            t.is("a missing name before a double dot is not noticed (lexical)", d("nothere/../other"), Ok((false, 4)));
            // The calls that take a path all go through the same step.
            t.check("File::create and open", fs::write("./new", b"n").is_ok() && fs::read("../b/./new").is_ok_and(|v| v == b"n"), String::new());
            t.check("create_dir and read_dir", fs::create_dir("./sub").is_ok() && fs::read_dir("./sub").is_ok_and(|r| r.count() == 0) && fs::read_dir(".").is_ok_and(|r| r.count() == 3), String::new());
            t.check("create_dir_all with dots", fs::create_dir_all("./x/../y/./z").is_ok() && d("y/z").is_ok() && d("x").is_err(), String::new());
            t.check("remove_file, remove_dir, remove_dir_all", fs::remove_file("./new").is_ok() && fs::remove_dir("./sub").is_ok() && fs::remove_dir_all("./y").is_ok() && d("y").is_err(), String::new());
            t.check("copy", fs::copy("../a/file", "./copy").is_ok() && fs::read("./copy").is_ok_and(|v| v == b"123"), String::new());
            t.check("set_permissions", { let mut p = fs::metadata("./copy").unwrap().permissions(); p.set_readonly(true); fs::set_permissions("./copy", p).is_ok() }, String::new());
            t.check("set_current_dir with a double dot", env::set_current_dir("..").is_ok() && env::current_dir().is_ok_and(|p| p == Path::new(&format!("{vol}ami-rust-m1/dt"))), format!("{:?}", env::current_dir()));
            t.check("set_current_dir with a dot and a name", env::set_current_dir("./a").is_ok() && env::current_dir().is_ok_and(|p| p == Path::new(&format!("{vol}ami-rust-m1/dt/a"))), format!("{:?}", env::current_dir()));
            t.check("set_current_dir from a double dot and a name", env::set_current_dir("../b").is_ok() && env::current_dir().is_ok_and(|p| p == here), String::new());
            t.kind("a missing file with dots", fs::metadata("./nothere"), ErrorKind::NotFound);
            t.kind("a double dot above a file", env::set_current_dir("../a/file"), ErrorKind::NotADirectory);
            env::set_current_dir(BASE).unwrap();
            let _ = fs::remove_dir_all(Path::new(BASE).join("dt"));
        }
        "lists" => {
            let split: Vec<PathBuf> = env::split_paths("RAM:a;DH0:b;c").collect();
            t.is("split_paths", split, vec![PathBuf::from("RAM:a"), PathBuf::from("DH0:b"), PathBuf::from("c")]);
            t.is("join_paths", env::join_paths(["RAM:a", "DH0:b"]).ok().map(|s| s.to_string_lossy().into_owned()), Some("RAM:a;DH0:b".to_string()));
            t.check("join_paths refuses a semicolon", env::join_paths(["a;b"]).is_err(), String::new());
            t.is("split of join", env::split_paths(&env::join_paths(["RAM:x", "SYS:y"]).unwrap()).collect::<Vec<_>>(), vec![PathBuf::from("RAM:x"), PathBuf::from("SYS:y")]);
            t.is("temp_dir", env::temp_dir(), PathBuf::from("T:"));
            let f = env::temp_dir().join("ami-rust-path-probe");
            t.check("a file in temp_dir", fs::write(&f, b"x").is_ok() && fs::metadata("T:ami-rust-path-probe").is_ok_and(|m| m.is_file()), format!("{f:?}"));
            let _ = fs::remove_file(&f);
            t.is("home_dir", env::home_dir(), None);
            t.kind("current_exe is unsupported", env::current_exe(), ErrorKind::Unsupported);
        }
        _ => println!("modes: components absolute parts join cwd make-absolute dots lists"),
    }
    println!("RESULT path summary {} of {} checks passed", t.total - t.failed, t.total);
    if t.failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(3) }
}

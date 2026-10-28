//! A focused compiler qualification for source and header prefix mapping.
//!
//! The caller owns process supervision, cancellation, aggregate resource
//! accounting, and command evidence. This helper only prepares four fresh
//! source cases, requests the commands through that runner, and audits their
//! bounded object outputs. Failed roots are intentionally retained.

use crate::{
    Refusal, Result, digest::encode_hex, directory::Directory, files::open_regular_nofollow,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, OsStr, OsString},
    fs,
    io::{Read, Write},
    os::{
        fd::FromRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

const MAX_COMPILER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_VERSION_OUTPUT_BYTES: usize = 64 * 1024;

/// Qualify source/header prefix mapping using a caller-owned supervised runner.
///
/// `compiler` is the pinned compiler executable and `root` must be a fresh,
/// absolute path whose ancestors already exist. The runner receives complete
/// argv (including argv[0]), a working directory, and a stable label. It must
/// supervise cancellation and resource limits, reject nonzero or incomplete
/// command results, and return captured command evidence. The version command
/// evidence must contain a UTF-8 `stdout` string. Command execution remains
/// entirely with the caller so one coordinator can own aggregate resources.
///
/// The helper never removes the root: failed source files and outputs remain
/// available for diagnosis. A success report is returned only after all four
/// cases pass their mapping and ELF checks.
pub fn probe_prefix_mapping(
    compiler: &Path,
    root: &Path,
    mut run: impl FnMut(&[OsString], &Path, &str) -> Result<Value>,
) -> Result<Value> {
    validate_absolute_path(compiler, "pinned compiler")?;
    validate_absolute_path(root, "prefix-map probe root")?;

    // Open and retain the parent before checking or creating the leaf. The
    // descriptor-relative mkdir closes the check/create race and never follows
    // a replaced parent path.
    let root_name = root
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| {
            Refusal::new("prefix-map probe root must name a directory below its parent")
        })?;
    let parent_path = root
        .parent()
        .ok_or_else(|| Refusal::new("prefix-map probe root must have a parent directory"))?;
    let parent = Directory::open(parent_path)?;
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(Refusal::new("fresh prefix-map probe root required")),
    }

    let compiler_sha256 = hash_compiler_bounded(compiler)?;
    let root_directory = create_private_directory(&parent, root_name)?;
    ensure_directory_matches(parent_path, &parent, "prefix-map root parent")?;
    ensure_directory_matches(root, &root_directory, "prefix-map probe root")?;

    let compiler_argv = vec![
        compiler.as_os_str().to_os_string(),
        OsString::from("--version"),
    ];
    let version_process = run(&compiler_argv, root, "prefix-map-compiler-version")?;
    ensure_directory_matches(root, &root_directory, "prefix-map probe root")?;
    let version = version_process
        .get("stdout")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("prefix-map compiler evidence must contain UTF-8 stdout"))?
        .to_owned();
    if version.len() > MAX_VERSION_OUTPUT_BYTES {
        return Err(Refusal::new(
            "prefix-map compiler version output exceeds its byte bound",
        ));
    }
    if !version.contains("clang version 11.0.0") {
        return Err(Refusal::new(
            "prefix-map probe requires the pinned LLVM 11 compiler",
        ));
    }

    let cases = [
        ("root-a", "map"),
        ("different root b", "map"),
        ("unmapped-control", "none"),
        ("incorrect-prefix", "wrong"),
    ];
    let mut records = Vec::with_capacity(cases.len());
    let mut first_mapped_object: Option<Vec<u8>> = None;

    for (name, mode) in cases {
        ensure_directory_matches(root, &root_directory, "prefix-map probe root")?;
        let source_directory = create_private_directory(&root_directory, OsStr::new(name))?;
        let include_directory = create_private_directory(&source_directory, OsStr::new("inc"))?;
        write_new_regular(
            &include_directory,
            OsStr::new("probe.h"),
            b"const char header_origin[] = __FILE__;\n",
        )?;
        write_new_regular(
            &source_directory,
            OsStr::new("probe.c"),
            b"#include \"inc/probe.h\"\nconst char source_origin[] = __FILE__;\n",
        )?;

        let source_path = root.join(name).join("probe.c");
        let output_path = root.join(name).join("probe.o");
        let mut argv = vec![
            compiler.as_os_str().to_os_string(),
            OsString::from("--target=x86_64-unknown-aros"),
            OsString::from("-ffreestanding"),
            OsString::from("-O0"),
            OsString::from("-c"),
            source_path.as_os_str().to_os_string(),
            OsString::from("-o"),
            output_path.as_os_str().to_os_string(),
        ];
        if mode != "none" {
            let prefix = if mode == "map" {
                root.join(name)
            } else {
                root.join("nonexistent-source-prefix")
            };
            let mut flag = OsString::from("-ffile-prefix-map=");
            flag.push(prefix.as_os_str());
            flag.push("=.");
            argv.push(flag);
        }

        let label = match name {
            "different root b" => "prefix-different-root-b",
            _ => match mode {
                "none" => "prefix-unmapped-control",
                "wrong" => "prefix-incorrect-prefix",
                _ => "prefix-root-a",
            },
        };
        ensure_directory_matches(root, &root_directory, "prefix-map probe root")?;
        let process = run(&argv, root, label)?;
        ensure_directory_matches(root, &root_directory, "prefix-map probe root")?;
        ensure_directory_matches(
            &root.join(name),
            &source_directory,
            "prefix-map case directory",
        )?;

        let raw = read_regular_bounded(&source_directory, OsStr::new("probe.o"), MAX_OBJECT_BYTES)?;
        check_elf_x86_64_relocatable(&raw)?;
        let local_source_prefix_present =
            contains_bytes(&raw, source_directory_bytes(&source_path));
        if mode == "map" {
            if local_source_prefix_present
                || !contains_bytes(&raw, b"./probe.c")
                || !contains_bytes(&raw, b"./inc/probe.h")
            {
                return Err(Refusal::new(
                    "compiler failed to map source/header diagnostic paths",
                ));
            }
            if let Some(first) = &first_mapped_object {
                if first != &raw {
                    return Err(Refusal::new(
                        "prefix-map objects differ across the two absolute roots",
                    ));
                }
            } else {
                first_mapped_object = Some(raw.clone());
            }
        } else if !local_source_prefix_present {
            return Err(Refusal::new(
                "prefix-map counter-probe failed to retain the real source path",
            ));
        }

        records.push(json!({
            "case": name,
            "mode": mode,
            "bytes": raw.len(),
            "sha256": crate::digest::sha256_bytes(&raw),
            "local_source_prefix_present": local_source_prefix_present,
            "process": process,
            "status": if mode == "map" { "PASS" } else { "EXPECTED_LOCAL_PREFIX_DETECTED" },
        }));
    }

    if hash_compiler_bounded(compiler)? != compiler_sha256 {
        return Err(Refusal::new(
            "pinned compiler changed during the prefix-map probe",
        ));
    }

    Ok(json!({
        "status": "PASS_PREFIX_MAPPING_ONLY",
        "compiler_version": version,
        "compiler_sha256": compiler_sha256,
        "version_process": version_process,
        "two_roots_byte_identical": true,
        "cases": records,
    }))
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} path must be absolute")));
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            _ => return Err(Refusal::new(format!("{label} path is not normalized"))),
        }
    }
    Ok(())
}

fn hash_compiler_bounded(path: &Path) -> Result<String> {
    let mut file = open_regular_nofollow(path)?;
    let before = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect pinned compiler: {error}")))?;
    if before.len() > MAX_COMPILER_BYTES {
        return Err(Refusal::new("pinned compiler exceeds its hash byte bound"));
    }
    if before.mode() & 0o111 == 0 {
        return Err(Refusal::new("pinned compiler is not executable"));
    }

    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read pinned compiler: {error}"
                )));
            }
        };
        total = total
            .checked_add(
                u64::try_from(read).map_err(|_| Refusal::new("compiler read length overflow"))?,
            )
            .ok_or_else(|| Refusal::new("compiler byte count overflow"))?;
        if total > MAX_COMPILER_BYTES {
            return Err(Refusal::new("pinned compiler exceeds its hash byte bound"));
        }
        digest.update(&buffer[..read]);
    }
    if total != before.len() {
        return Err(Refusal::new("pinned compiler changed while it was hashed"));
    }
    let bytes: [u8; 32] = digest.finalize().into();
    Ok(encode_hex(&bytes))
}

#[allow(
    unsafe_code,
    reason = "Descriptor-relative directory creation is needed to keep the fresh root anchored."
)]
fn create_private_directory(parent: &Directory, name: &OsStr) -> Result<Directory> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| Refusal::new("directory name contains a NUL byte"))?;
    let mode: libc::mode_t = 0o700;
    // SAFETY: parent owns a live directory descriptor, `name` is NUL-terminated,
    // and mkdirat creates one entry without resolving any path components.
    let result = unsafe { libc::mkdirat(parent.raw_fd(), name.as_ptr(), mode) };
    if result != 0 {
        return Err(Refusal::new(format!(
            "could not create fresh prefix-map directory: {}",
            std::io::Error::last_os_error()
        )));
    }
    let directory = parent.child(OsStr::from_bytes(name.as_bytes()))?;
    // SAFETY: the opened descriptor refers to the directory just created above.
    if unsafe { libc::fchmod(directory.raw_fd(), mode) } != 0 {
        return Err(Refusal::new(format!(
            "could not set private prefix-map directory permissions: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(directory)
}

fn ensure_directory_matches(path: &Path, expected: &Directory, label: &str) -> Result<()> {
    let observed = Directory::open(path)?;
    let expected_metadata = expected.metadata()?;
    let observed_metadata = observed.metadata()?;
    if expected_metadata.dev() != observed_metadata.dev()
        || expected_metadata.ino() != observed_metadata.ino()
    {
        return Err(Refusal::new(format!("{label} changed during the probe")));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Descriptor-relative exclusive file creation avoids following probe-root links."
)]
fn write_new_regular(directory: &Directory, name: &OsStr, contents: &[u8]) -> Result<()> {
    let name =
        CString::new(name.as_bytes()).map_err(|_| Refusal::new("file name contains a NUL byte"))?;
    let mode = libc::c_uint::from(0o600_u16);
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: directory owns a live descriptor, `name` is NUL-terminated, and
    // O_EXCL|O_NOFOLLOW creates a new regular output without following links.
    let fd = unsafe { libc::openat(directory.raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(Refusal::new(format!(
            "could not create prefix-map probe input: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `fd` is a fresh descriptor returned by openat and is transferred
    // to exactly one owning File.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(contents)
        .map_err(|error| Refusal::new(format!("could not write prefix-map probe input: {error}")))
}

fn read_regular_bounded(directory: &Directory, name: &OsStr, limit: usize) -> Result<Vec<u8>> {
    let mut file = directory.regular(name)?;
    let initial_length = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect prefix-map object: {error}")))?
        .len();
    let limit_u64 = u64::try_from(limit)
        .map_err(|_| Refusal::new("prefix-map object bound cannot fit in a file length"))?;
    if initial_length > limit_u64 {
        return Err(Refusal::new("prefix-map object exceeds its byte bound"));
    }
    let initial_capacity = usize::try_from(initial_length)
        .map_err(|_| Refusal::new("prefix-map object length cannot fit in memory"))?;
    let mut contents = Vec::new();
    contents
        .try_reserve_exact(initial_capacity)
        .map_err(|error| Refusal::new(format!("could not allocate prefix-map object: {error}")))?;
    let over_limit = limit
        .checked_add(1)
        .ok_or_else(|| Refusal::new("prefix-map object bound overflow"))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = over_limit - contents.len();
        let read_limit = buffer.len().min(remaining);
        let read = match file.read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read prefix-map object: {error}"
                )));
            }
        };
        contents.try_reserve(read).map_err(|error| {
            Refusal::new(format!("could not grow prefix-map object buffer: {error}"))
        })?;
        contents.extend_from_slice(&buffer[..read]);
        if contents.len() > limit {
            return Err(Refusal::new("prefix-map object exceeds its byte bound"));
        }
    }
    if u64::try_from(contents.len()).ok() != Some(initial_length) {
        return Err(Refusal::new("prefix-map object changed while it was read"));
    }
    Ok(contents)
}

fn check_elf_x86_64_relocatable(bytes: &[u8]) -> Result<()> {
    if bytes.get(..4) != Some(b"\x7fELF".as_slice())
        || bytes.get(4) != Some(&2)
        || bytes.get(5) != Some(&1)
        || bytes.get(16..18) != Some(&[1_u8, 0][..])
        || bytes.get(18..20) != Some(&[62_u8, 0][..])
    {
        return Err(Refusal::new(
            "prefix-map probe did not produce little-endian ELF64 x86-64 relocatable output",
        ));
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn source_directory_bytes(source: &Path) -> &[u8] {
    source
        .parent()
        .expect("absolute probe source has a parent")
        .as_os_str()
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::probe_prefix_mapping;
    use crate::{Result, digest::sha256_bytes};
    use serde_json::{Value, json};
    use std::{
        ffi::{OsStr, OsString},
        fs,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let parent = fs::canonicalize(std::env::current_dir().expect("current directory"))
                .expect("canonicalize current directory");
            for _ in 0..100 {
                let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    ".csdk-prefix-map-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create prefix-map fixture: {error}"),
                }
            }
            panic!("could not allocate a prefix-map fixture");
        }

        fn compiler(&self) -> PathBuf {
            let path = self.0.join("clang-11");
            fs::write(&path, b"synthetic pinned compiler executable")
                .expect("write compiler fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("make compiler executable");
            path
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove prefix-map fixture");
        }
    }

    fn synthetic_object(strings: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 20];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[16..18].copy_from_slice(&[1, 0]);
        bytes[18..20].copy_from_slice(&[62, 0]);
        bytes.extend_from_slice(strings);
        bytes
    }

    fn fake_runner(
        fail_case: Option<&'static str>,
        wrong_version: bool,
        wrong_architecture: bool,
    ) -> impl FnMut(&[OsString], &Path, &str) -> Result<Value> {
        move |argv, _cwd, label| {
            if argv.get(1).and_then(|argument| argument.to_str()) == Some("--version") {
                let stdout = if wrong_version {
                    "clang version 12.0.0\n"
                } else {
                    "clang version 11.0.0 synthetic\n"
                };
                return Ok(json!({"stdout": stdout, "exit_code": 0}));
            }

            let compile_index = argv
                .iter()
                .position(|argument| argument.as_os_str() == OsStr::new("-c"))
                .expect("compile argv has -c");
            let source = Path::new(argv[compile_index + 1].as_os_str());
            let case_directory = source.parent().expect("source parent");
            let case = case_directory
                .file_name()
                .and_then(|name| name.to_str())
                .expect("synthetic case name");
            let output_index = argv
                .iter()
                .position(|argument| argument.as_os_str() == OsStr::new("-o"))
                .expect("compile argv has -o");
            let output = Path::new(argv[output_index + 1].as_os_str());
            let map_flag = argv
                .iter()
                .find(|argument| argument.as_bytes().starts_with(b"-ffile-prefix-map="));
            let actual_map = map_flag.is_some_and(|flag| {
                let mut expected = b"-ffile-prefix-map=".to_vec();
                expected.extend_from_slice(case_directory.as_os_str().as_bytes());
                expected.extend_from_slice(b"=.");
                flag.as_bytes() == expected.as_slice()
            });
            let raw = if actual_map && fail_case != Some(case) {
                synthetic_object(b"./probe.c\0./inc/probe.h\0")
            } else {
                let local = case_directory.as_os_str().as_bytes();
                let mut strings = local.to_vec();
                strings.extend_from_slice(b"/probe.c\0");
                strings.extend_from_slice(local);
                strings.extend_from_slice(b"/inc/probe.h\0");
                synthetic_object(&strings)
            };
            let mut raw = raw;
            if wrong_architecture && label == "prefix-root-a" {
                raw[18..20].copy_from_slice(&[3, 0]);
            }
            fs::write(output, raw).expect("write synthetic object");
            Ok(json!({"exit_code": 0, "label": label, "synthetic": true}))
        }
    }

    #[test]
    fn accepts_mapped_objects_only_when_both_controls_retain_local_paths() {
        let fixture = Fixture::new();
        let compiler = fixture.compiler();
        let root = fixture.path().join("probe-root");
        let report =
            probe_prefix_mapping(&compiler, &root, fake_runner(None, false, false)).unwrap();
        assert_eq!(report["status"], "PASS_PREFIX_MAPPING_ONLY");
        assert_eq!(
            report["compiler_sha256"],
            sha256_bytes(b"synthetic pinned compiler executable")
        );
        assert_eq!(report["two_roots_byte_identical"], true);
        assert_eq!(report["cases"].as_array().unwrap().len(), 4);
        assert_eq!(report["cases"][0]["sha256"], report["cases"][1]["sha256"]);
        assert_eq!(report["cases"][0]["local_source_prefix_present"], false);
        assert_eq!(report["cases"][1]["local_source_prefix_present"], false);
        assert_eq!(report["cases"][2]["local_source_prefix_present"], true);
        assert_eq!(report["cases"][3]["local_source_prefix_present"], true);
        assert_eq!(
            report["cases"][2]["status"],
            "EXPECTED_LOCAL_PREFIX_DETECTED"
        );
        assert_eq!(
            report["cases"][3]["status"],
            "EXPECTED_LOCAL_PREFIX_DETECTED"
        );
        assert!(root.join("root-a/probe.c").is_file());
    }

    #[test]
    fn refuses_wrong_version_before_compilation_and_retains_fresh_root() {
        let fixture = Fixture::new();
        let compiler = fixture.compiler();
        let root = fixture.path().join("wrong-version-root");
        let mut compile_calls = 0;
        let result = probe_prefix_mapping(&compiler, &root, |argv, cwd, label| {
            if argv.get(1).and_then(|argument| argument.to_str()) == Some("--version") {
                return fake_runner(None, true, false)(argv, cwd, label);
            }
            compile_calls += 1;
            fake_runner(None, false, false)(argv, cwd, label)
        });
        assert!(result.is_err());
        assert_eq!(compile_calls, 0);
        assert!(root.is_dir());
    }

    #[test]
    fn refuses_a_mapping_failure_and_a_non_x86_64_object() {
        let fixture = Fixture::new();
        let compiler = fixture.compiler();
        let map_root = fixture.path().join("mapping-failure-root");
        assert!(
            probe_prefix_mapping(
                &compiler,
                &map_root,
                fake_runner(Some("root-a"), false, false)
            )
            .is_err()
        );

        let elf_root = fixture.path().join("wrong-elf-root");
        assert!(
            probe_prefix_mapping(&compiler, &elf_root, fake_runner(None, false, true)).is_err()
        );
        assert!(map_root.join("root-a/probe.o").is_file());
        assert!(elf_root.join("root-a/probe.o").is_file());
    }

    #[test]
    fn refuses_relative_occupied_and_symlink_roots_before_running() {
        let fixture = Fixture::new();
        let compiler = fixture.compiler();
        let mut calls = 0;
        let mut runner = |_: &[OsString], _: &Path, _: &str| -> Result<Value> {
            calls += 1;
            Ok(json!({"stdout":"clang version 11.0.0"}))
        };
        assert!(
            probe_prefix_mapping(&compiler, Path::new("relative-probe-root"), &mut runner).is_err()
        );

        let occupied = fixture.path().join("occupied");
        fs::create_dir(&occupied).unwrap();
        assert!(probe_prefix_mapping(&compiler, &occupied, &mut runner).is_err());

        let linked = fixture.path().join("linked");
        #[cfg(unix)]
        std::os::unix::fs::symlink("occupied", &linked).unwrap();
        assert!(probe_prefix_mapping(&compiler, &linked, &mut runner).is_err());
        assert_eq!(calls, 0);
    }
}

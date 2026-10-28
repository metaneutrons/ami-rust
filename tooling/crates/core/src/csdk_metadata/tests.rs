use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::current_dir()
            .expect("current directory")
            .join(format!(
                ".ami-rust-aom-metadata-test-{}-{}",
                std::process::id(),
                NEXT_TEST.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove test directory");
    }
}

#[test]
fn cmake_paths_allow_spaces_and_apostrophes_but_reject_interpolation_and_escapes() {
    let safe = Path::new("/tmp/different metadata b/O'Brien");
    assert_eq!(
        safe_cmake_path(safe, "fixture").unwrap(),
        safe.to_str().unwrap()
    );
    for unsafe_path in [
        "/tmp/has\"quote",
        "/tmp/has\\backslash",
        "/tmp/has$dollar",
        "/tmp/has;list",
        "/tmp/has\nnewline",
    ] {
        assert!(safe_cmake_path(Path::new(unsafe_path), "fixture").is_err());
    }
}

#[test]
fn prefix_rewrite_changes_only_the_value_and_preserves_crlf() {
    let original = b"prefix=/tmp/Developer\r\nexec_prefix=${prefix}\nLibs.private: -lm\n";
    let (rewritten, prefix) = rewrite_prefix(original).unwrap();
    assert_eq!(prefix, "/tmp/Developer");
    assert_eq!(
        rewritten,
        b"prefix=${pcfiledir}/../..\r\nexec_prefix=${prefix}\nLibs.private: -lm\n"
    );
    assert!(rewrite_prefix(b"prefix=/one\nprefix=/two\n").is_err());
    assert!(rewrite_prefix(b"prefix=relative/path\n").is_err());
}

#[test]
fn tokenizer_matches_shell_quoting_for_spaces_and_apostrophes() {
    assert_eq!(
        posix_tokens("-I'/path with spaces' -L/path\\ with\\ spaces -laom").unwrap(),
        vec![
            "-I/path with spaces".to_owned(),
            "-L/path with spaces".to_owned(),
            "-laom".to_owned(),
        ]
    );
    assert_eq!(
        posix_tokens("'/path/O'\\''Brien'").unwrap(),
        vec!["/path/O'Brien".to_owned()]
    );
    assert!(posix_tokens("'/unfinished").is_err());
}

#[test]
fn relocation_flags_reject_extra_switches_and_accept_only_expected_paths() {
    let fixture = TempDirectory::new();
    let moved = fixture.0.join("relocated Developer");
    fs::create_dir_all(moved.join("include")).unwrap();
    fs::create_dir_all(moved.join("lib")).unwrap();
    let valid = vec![
        format!("-I{}", moved.join("include").display()),
        format!("-L{}", moved.join("lib").display()),
        "-laom".to_owned(),
    ];
    validate_relocated_flags(&valid, &moved).unwrap();
    let mut extra = valid;
    extra.push("-lm".to_owned());
    assert!(validate_relocated_flags(&extra, &moved).is_err());
}

#[test]
fn wrong_archive_pins_are_refused_before_any_archive_read() {
    assert!(
        validate_archive_pin(CsdkSourceFilePin {
            bytes: ARCHIVE_BYTES,
            sha256: [0; 32],
        })
        .is_err()
    );
    assert!(
        validate_archive_pin(CsdkSourceFilePin {
            bytes: ARCHIVE_BYTES + 1,
            sha256: [0; 32],
        })
        .is_err()
    );
}

#[test]
fn executable_tool_files_must_match_their_length_and_sha256_pin() {
    let fixture = TempDirectory::new();
    let path = fixture.0.join("tool");
    let bytes = b"pinned executable bytes";
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let checker: CheckFn<'_> = Rc::new(RefCell::new(|_: &str| Ok(())));
    let tool = CsdkMetadataTool {
        path,
        pin: CsdkSourceFilePin {
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        },
    };
    verify_tool(&tool, &checker, "fixture").unwrap();
    let wrong = CsdkMetadataTool {
        pin: CsdkSourceFilePin {
            bytes: bytes.len() as u64,
            sha256: [0; 32],
        },
        ..tool
    };
    assert!(verify_tool(&wrong, &checker, "fixture").is_err());
}

#[test]
fn reported_prefix_accepts_raw_and_shell_escaped_paths_including_apostrophes() {
    let fixture = TempDirectory::new();
    let expected = fixture.0.join("different metadata O'Brien");
    fs::create_dir(&expected).unwrap();
    let raw = expected.to_str().unwrap();
    assert_eq!(reported_prefix(raw, &expected).unwrap(), raw);
    let escaped = format!("'{}'", raw.replace('\'', "'\\''"));
    assert_eq!(reported_prefix(&escaped, &expected).unwrap(), raw);
}

#[test]
fn root_and_nested_source_members_resolve_without_an_empty_directory_entry() {
    let fixture = TempDirectory::new();
    let root = Directory::open(&fixture.0).unwrap();
    let checker: CheckFn<'_> = Rc::new(RefCell::new(|_: &str| Ok(())));
    for relative in ["CHANGELOG", "build/cmake/util.cmake"] {
        let (parent, basename) = source_parent(&root, relative, true).unwrap();
        write_new_file(&parent, basename, b"retained version input", &checker).unwrap();
        assert_eq!(
            fs::read(fixture.0.join(relative)).unwrap(),
            b"retained version input"
        );
        assert_eq!(
            read_relative_file(&root, relative, 1024, &checker, "test source member").unwrap(),
            b"retained version input"
        );
    }
}

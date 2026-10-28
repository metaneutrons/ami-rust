//! Integration coverage for the maintainer CLI's path-based program guard.

use ami_rust_core::digest::{sha256_bytes, sha256_file};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
        for _ in 0..100 {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "ami-rust-qualification-cli-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("make fixture root private");
                    return Self(fs::canonicalize(path).expect("canonical fixture root"));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create fixture root: {error}"),
            }
        }
        panic!("could not allocate a unique fixture root");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_request(path: &Path, program: &Path, cwd: &Path) -> Vec<u8> {
    let request = json!({
        "schema": "ami-rust-native-command-qualification-request-v1",
        "program": program.to_string_lossy().into_owned(),
        "args": [
            "-c",
            "printf '%s\\n' ami-rust-command-child-exit7-stdout-v1; \\
             printf '%s\\n' ami-rust-command-child-exit7-stderr-v1 >&2; \\
             exit 7"
        ],
        "cwd": cwd.to_string_lossy().into_owned(),
        "environment": {},
        "required_roots": [cwd.to_string_lossy().into_owned()],
        "limits": {
            "seconds": 10,
            "rss_bytes": 1073741824_u64,
            "workspace_bytes": 1048576_u64,
            "log_bytes": 1048576_u64
        }
    });
    let bytes = serde_json::to_vec(&request).expect("serialize command request");
    fs::write(path, &bytes).expect("write command request");
    bytes
}

fn run_cli(request: &Path, record: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ami-rust-xtask"))
        .args(["qualification-command", "--request"])
        .arg(request)
        .arg("--record")
        .arg(record)
        .output()
        .expect("run actual ami-rust-xtask CLI")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("JSON string")
}

#[test]
fn actual_cli_rejects_symlink_program_path_and_records_canonical_child_exit() {
    let fixture = TempRoot::new();
    let root = fixture.path();
    let shell = fs::canonicalize("/bin/sh").expect("canonical system shell");
    let shell_name = shell.file_name().expect("shell filename");
    let alias_directory = root.join("shell-directory-alias");
    symlink(shell.parent().expect("shell parent"), &alias_directory)
        .expect("create owned directory alias to the system shell");
    let requested_alias = alias_directory.join(shell_name);
    let canonical_alias = fs::canonicalize(&requested_alias).expect("resolve directory alias");
    assert_eq!(canonical_alias, shell);

    let refused_cwd = root.join("refused-cwd");
    fs::create_dir(&refused_cwd).expect("create refusal cwd");
    let refused_request = root.join("symlink-request.json");
    let refused_record = refused_cwd.join("record");
    write_request(&refused_request, &requested_alias, &refused_cwd);
    let refused = run_cli(&refused_request, &refused_record);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("directory must have no symlink components"),
        "unexpected refusal: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !refused_record.exists(),
        "refusal must precede typed-record creation"
    );

    let positive_cwd = root.join("positive-cwd");
    fs::create_dir(&positive_cwd).expect("create positive cwd");
    let positive_request = root.join("canonical-request.json");
    let positive_record = positive_cwd.join("record");
    let request_bytes = write_request(&positive_request, &canonical_alias, &positive_cwd);
    let completed = run_cli(&positive_request, &positive_record);
    assert_eq!(
        completed.status.code(),
        Some(7),
        "child status must propagate"
    );

    let stdout = b"ami-rust-command-child-exit7-stdout-v1\n";
    let stderr = b"ami-rust-command-child-exit7-stderr-v1\n";
    assert_eq!(
        fs::read(positive_record.join("stdout.log")).unwrap(),
        stdout
    );
    assert_eq!(
        fs::read(positive_record.join("stderr.log")).unwrap(),
        stderr
    );
    let result_bytes = fs::read(positive_record.join("result.json")).expect("typed result");
    let result: Value = serde_json::from_slice(&result_bytes).expect("parse typed result");
    assert_eq!(
        result["schema"],
        "ami-rust-native-command-qualification-record-v1"
    );
    assert_eq!(result["passed"].as_bool(), Some(false));
    assert_eq!(result["request_sha256"], sha256_bytes(&request_bytes));
    assert_eq!(result["child_exit_code"], 7);
    assert_eq!(result["child_signal"], Value::Null);
    assert_eq!(result["capture_complete"].as_bool(), Some(true));
    assert_eq!(result["capture_error"], Value::Null);
    assert_eq!(
        result["resource_report"]["incomplete_cleanup"].as_bool(),
        Some(false)
    );
    assert_eq!(
        text(&result["command"]["program"]),
        shell.to_string_lossy().as_ref()
    );
    assert_eq!(
        text(&result["command"]["program_sha256"]),
        sha256_file(&shell).expect("hash canonical shell")
    );
    let helper = fs::canonicalize(env!("CARGO_BIN_EXE_ami-rust-xtask"))
        .expect("canonical actual xtask helper");
    assert_eq!(
        text(&result["command"]["helper_sha256"]),
        sha256_file(&helper).expect("hash actual xtask helper")
    );
    assert_eq!(
        result["stdout"]["bytes"].as_u64(),
        Some(stdout.len() as u64)
    );
    assert_eq!(result["stdout"]["sha256"], sha256_bytes(stdout));
    assert_eq!(
        result["stderr"]["bytes"].as_u64(),
        Some(stderr.len() as u64)
    );
    assert_eq!(result["stderr"]["sha256"], sha256_bytes(stderr));

    let fixture_path = root.to_path_buf();
    drop(fixture);
    assert!(
        !fixture_path.exists(),
        "fixture cleanup must remove all test records"
    );
}

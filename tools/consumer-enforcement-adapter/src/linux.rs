// SPDX-License-Identifier: MIT OR Apache-2.0
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    )),
    allow(dead_code, unused_imports)
)]
#![cfg_attr(test, allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_ERROR_PREFIX: &str = "consumer-enforcement-adapter-linux-a1";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const LINUX_ERROR_PREFIX: &str = "consumer-enforcement-adapter-linux-a2";

#[derive(Clone, Debug)]
struct ExecRule {
    path: PathBuf,
    expected_sha256: Option<String>,
    expected_closure_sha256: Option<String>,
    deferred: bool,
}

#[derive(Clone, Debug)]
struct ExecTree {
    role: String,
    path: PathBuf,
}

#[derive(Clone, Debug)]
struct ExecDerivedTree {
    role: String,
    path: PathBuf,
    source_closure_sha256: String,
}

#[derive(Clone, Debug)]
struct ReadLibraryRule {
    path: PathBuf,
    expected_sha256: String,
    pre_run_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeviceIdentity {
    device: u64,
    inode: u64,
    rdev: u64,
}

#[derive(Debug)]
struct WriteNullRule {
    pre_run_identity: DeviceIdentity,
    post_run_identity: Option<DeviceIdentity>,
    post_run_identity_matches: Option<bool>,
    post_run_error: Option<String>,
}

#[derive(Debug, Default)]
struct Policy {
    exec: Vec<ExecRule>,
    exec_trees: Vec<ExecTree>,
    exec_derived_trees: Vec<ExecDerivedTree>,
    deny_exec: Vec<PathBuf>,
    deny_library: Vec<PathBuf>,
    read_files: Vec<PathBuf>,
    read_directories: Vec<PathBuf>,
    read_libraries: Vec<ReadLibraryRule>,
    write_null: Option<WriteNullRule>,
    read_trees: Vec<(String, PathBuf)>,
    write_trees: Vec<(String, PathBuf)>,
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    network_outbound: bool,
}

#[derive(Debug)]
struct Capture {
    saved: usize,
    total: u64,
    truncated: bool,
    write_error: Option<String>,
}

#[derive(Debug)]
struct ExecHashCheck {
    path: PathBuf,
    expected_sha256: Option<String>,
    expected_closure_sha256: Option<String>,
    hash_verified_before_run: bool,
    hash_deferred_until_materialized: bool,
    path_missing_before_run: bool,
    post_run_sha256: Option<String>,
    post_run_hash_matches: Option<bool>,
}

#[derive(Debug)]
struct ReadLibraryHashCheck {
    path: PathBuf,
    expected_sha256: String,
    pre_run_sha256: String,
    post_run_sha256: Option<String>,
    post_run_hash_matches: bool,
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64")
))]
pub(crate) fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--control") {
        if let Err(error) = linux::control(&args[1..]) {
            eprintln!("adapter control error: {error}");
            process::exit(2);
        }
        return;
    }
    match linux::run(&args) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("{LINUX_ERROR_PREFIX}: {error}");
            process::exit(2);
        }
    }
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64")
)))]
pub(crate) fn main() {
    eprintln!(
        "consumer-enforcement-adapter: native macOS, Linux x86-64, or Linux AArch64 is required"
    );
    process::exit(2);
}

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64")
))]
mod linux {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::Instant;

    const EACCES: i32 = 13;
    #[cfg(target_arch = "x86_64")]
    const SYS_SECCOMP: isize = 317;
    #[cfg(target_arch = "aarch64")]
    const SYS_SECCOMP: isize = 277;
    #[cfg(target_arch = "x86_64")]
    const SYS_MEMFD_CREATE: isize = 319;
    #[cfg(target_arch = "aarch64")]
    const SYS_MEMFD_CREATE: isize = 279;
    #[cfg(target_arch = "x86_64")]
    const SYS_EXECVEAT: isize = 322;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXECVEAT: isize = 281;
    const SYS_LANDLOCK_CREATE_RULESET: isize = 444;
    const SYS_LANDLOCK_ADD_RULE: isize = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: isize = 446;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    const SECCOMP_SET_MODE_FILTER: u32 = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
    #[cfg(target_arch = "x86_64")]
    const NATIVE_ARCH: &str = "x86_64";
    #[cfg(target_arch = "aarch64")]
    const NATIVE_ARCH: &str = "aarch64";
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    #[cfg(target_arch = "x86_64")]
    const REPORT_SCHEMA: &str = "consumer-enforcement-adapter-a1";
    #[cfg(target_arch = "aarch64")]
    const REPORT_SCHEMA: &str = "consumer-enforcement-adapter-a2";
    #[cfg(target_arch = "x86_64")]
    const REPORT_BACKEND: &str =
        "Landlock path-beneath allow rules and seccomp-BPF on Linux x86-64";
    #[cfg(target_arch = "aarch64")]
    const REPORT_BACKEND: &str =
        "Landlock path-beneath allow rules and seccomp-BPF on Linux aarch64";
    #[cfg(target_arch = "x86_64")]
    const REPORT_ABI_GUARD: &str = "\"x32_syscalls_denied\":true,";
    #[cfg(target_arch = "aarch64")]
    const REPORT_ABI_GUARD: &str = "\"non_native_audit_arch_killed\":true,";
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    #[cfg(any(test, target_arch = "x86_64"))]
    const BPF_JMP_JSET_K: u16 = 0x45;
    const BPF_RET_K: u16 = 0x06;
    const O_PATH: i32 = 0x0020_0000;
    const O_CLOEXEC: i32 = 0x0008_0000;
    const O_NOFOLLOW: i32 = 0x0002_0000;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const MFD_CLOEXEC: u32 = 1;

    // Architecture-specific Linux syscall numbers for the network-deny
    // profile. The policy and argument checks are shared across LP64 ABIs.
    // Native AArch64 values follow asm-generic; socketpair is the sole local
    // socket exception and io_uring_setup remains denied.
    #[cfg(target_arch = "x86_64")]
    const NETWORK_SYSCALLS: &[u32] = &[
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54, 55, 288, 299, 307, 425,
    ];
    #[cfg(target_arch = "aarch64")]
    const NETWORK_SYSCALLS: &[u32] = &[
        198, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 242, 243, 269, 425,
    ];
    #[cfg(target_arch = "x86_64")]
    const RETURNING_FD_NETWORK_SYSCALLS: &[u32] = &[41, 43, 288, 425];
    #[cfg(target_arch = "aarch64")]
    const RETURNING_FD_NETWORK_SYSCALLS: &[u32] = &[198, 202, 242, 425];

    const AF_UNIX: i32 = 1;
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;
    const SOCK_SEQPACKET: i32 = 5;
    const SOCK_CLOEXEC: i32 = 0x0008_0000;
    #[cfg(target_arch = "x86_64")]
    const SYS_SOCKET: isize = 41;
    #[cfg(target_arch = "aarch64")]
    const SYS_SOCKET: isize = 198;
    #[cfg(all(test, target_arch = "x86_64"))]
    const SYS_SENDTO: isize = 44;
    #[cfg(all(test, target_arch = "aarch64"))]
    const SYS_SENDTO: isize = 206;
    #[cfg(target_arch = "x86_64")]
    const SYS_RECVFROM: isize = 45;
    #[cfg(target_arch = "aarch64")]
    const SYS_RECVFROM: isize = 207;
    #[cfg(target_arch = "x86_64")]
    const SYS_SOCKETPAIR: isize = 53;
    #[cfg(target_arch = "aarch64")]
    const SYS_SOCKETPAIR: isize = 199;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    unsafe extern "C" {
        fn syscall(number: isize, ...) -> isize;
        fn prctl(option: i32, ...) -> i32;
        fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        fn close(fd: i32) -> i32;
        fn geteuid() -> u32;
    }

    struct OpenRule {
        path: PathBuf,
        allowed_access: u64,
        fd: File,
    }

    struct LandlockPlan {
        ruleset: File,
        _rules: Vec<OpenRule>,
        handled_fs: u64,
    }

    const LINUX_NULL_RDEV: u64 = 0x103; // Linux character device 1:3.

    fn validated_null_identity(
        policy_path: &str,
        canonical_path: &Path,
        metadata: &fs::Metadata,
    ) -> Result<DeviceIdentity, String> {
        if policy_path != "/dev/null" || canonical_path != Path::new("/dev/null") {
            return Err("write-null must name the exact canonical path /dev/null".to_owned());
        }
        if !metadata.file_type().is_char_device() {
            return Err("write-null /dev/null is not a character device".to_owned());
        }
        if metadata.rdev() != LINUX_NULL_RDEV {
            return Err(format!(
                "write-null /dev/null has unexpected character-device number {}",
                metadata.rdev()
            ));
        }
        Ok(DeviceIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            rdev: metadata.rdev(),
        })
    }

    fn inspect_null_device() -> Result<DeviceIdentity, String> {
        inspect_write_null_policy_path("/dev/null")
    }

    fn inspect_write_null_policy_path(policy_path: &str) -> Result<DeviceIdentity, String> {
        if policy_path != "/dev/null" {
            return Err("write-null only accepts the exact path /dev/null".to_owned());
        }
        let path = Path::new(policy_path);
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("inspect write-null path {policy_path}: {error}"))?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("canonicalize write-null path {policy_path}: {error}"))?;
        validated_null_identity(policy_path, &canonical, &metadata)
    }

    fn verify_write_null_before_run(policy: &Policy) -> Result<(), String> {
        if let Some(rule) = &policy.write_null {
            let current = inspect_null_device()?;
            if current != rule.pre_run_identity {
                return Err(
                    "/dev/null device identity changed before the sandboxed command started"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    fn record_write_null_after_run(policy: &mut Policy) -> Option<String> {
        let rule = policy.write_null.as_mut()?;
        match inspect_null_device() {
            Ok(identity) => {
                let matches = identity == rule.pre_run_identity;
                rule.post_run_identity = Some(identity);
                rule.post_run_identity_matches = Some(matches);
                rule.post_run_error = None;
                (!matches).then(|| {
                    "declared /dev/null character-device identity changed after the run".to_owned()
                })
            }
            Err(error) => {
                rule.post_run_identity = None;
                rule.post_run_identity_matches = Some(false);
                rule.post_run_error = Some(error);
                Some(
                    "declared /dev/null character device could not be verified after the run"
                        .to_owned(),
                )
            }
        }
    }

    impl OpenRule {
        fn new(path: &Path, allowed_access: u64) -> Result<Self, String> {
            let canonical = fs::canonicalize(path).map_err(|error| {
                format!("canonicalize Landlock path {}: {error}", path.display())
            })?;
            let cpath = CString::new(canonical.to_string_lossy().as_bytes())
                .map_err(|error| format!("Landlock path contains NUL: {error}"))?;
            // SAFETY: cpath is NUL-terminated, O_PATH does not dereference a
            // user pointer beyond the path, and the returned descriptor is
            // owned below.
            let raw_fd = unsafe { open(cpath.as_ptr(), O_PATH | O_CLOEXEC) };
            if raw_fd < 0 {
                return Err(format!(
                    "open O_PATH {}: {}",
                    canonical.display(),
                    io::Error::last_os_error()
                ));
            }
            // SAFETY: raw_fd is a newly opened descriptor.
            let fd = unsafe { File::from_raw_fd(raw_fd) };
            let opened = fd
                .metadata()
                .map_err(|error| format!("fstat {}: {error}", canonical.display()))?;
            let named = fs::metadata(&canonical)
                .map_err(|error| format!("stat {}: {error}", canonical.display()))?;
            if opened.dev() != named.dev() || opened.ino() != named.ino() {
                return Err(format!(
                    "Landlock path identity changed while opening: {}",
                    canonical.display()
                ));
            }
            Ok(Self {
                path: canonical,
                allowed_access,
                fd,
            })
        }

        fn new_write_null(expected: &DeviceIdentity, allowed_access: u64) -> Result<Self, String> {
            let path = Path::new("/dev/null");
            let canonical = fs::canonicalize(path)
                .map_err(|error| format!("canonicalize /dev/null for Landlock: {error}"))?;
            if canonical != path {
                return Err(
                    "write-null path no longer resolves canonically to /dev/null".to_owned(),
                );
            }
            let cpath = CString::new("/dev/null").expect("literal path contains no NUL");
            // O_NOFOLLOW makes a last-component symlink substitution fail
            // closed. The descriptor then anchors the Landlock exception to
            // the already-validated character device inode.
            // SAFETY: cpath is NUL-terminated, O_PATH does not dereference a
            // user pointer beyond the path, and the returned descriptor is
            // owned below.
            let raw_fd = unsafe { open(cpath.as_ptr(), O_PATH | O_NOFOLLOW | O_CLOEXEC) };
            if raw_fd < 0 {
                return Err(format!(
                    "open O_PATH /dev/null: {}",
                    io::Error::last_os_error()
                ));
            }
            // SAFETY: raw_fd is a newly opened descriptor.
            let fd = unsafe { File::from_raw_fd(raw_fd) };
            let opened = fd
                .metadata()
                .map_err(|error| format!("fstat /dev/null: {error}"))?;
            let opened_identity = validated_null_identity("/dev/null", path, &opened)?;
            let named =
                fs::symlink_metadata(path).map_err(|error| format!("lstat /dev/null: {error}"))?;
            let named_identity = validated_null_identity("/dev/null", path, &named)?;
            if opened_identity != *expected
                || named_identity != *expected
                || opened_identity != named_identity
            {
                return Err(
                    "/dev/null device identity changed while opening Landlock rule".to_owned(),
                );
            }
            Ok(Self {
                path: path.to_path_buf(),
                allowed_access,
                fd,
            })
        }
    }

    pub(super) fn run(args: &[String]) -> Result<i32, String> {
        if env::consts::OS != "linux" || env::consts::ARCH != NATIVE_ARCH {
            return Err(format!(
                "Linux {NATIVE_ARCH} only; host is {}-{}",
                env::consts::OS,
                env::consts::ARCH
            ));
        }
        let separator = args.iter().position(|arg| arg == "--").ok_or_else(|| {
            "usage: adapter --policy FILE --report-dir DIR --run -- /absolute/command [args...]"
                .to_owned()
        })?;
        if separator == 0 || separator + 1 >= args.len() {
            return Err("the --run command vector is empty".to_owned());
        }
        let prefix = &args[..separator];
        if !prefix.iter().any(|arg| arg == "--run") {
            return Err("expected --run before --".to_owned());
        }
        let policy_path = existing_file(
            option(prefix, "--policy").ok_or_else(|| "missing --policy FILE".to_owned())?,
        )?;
        let report_dir_arg = absolute_path(
            option(prefix, "--report-dir").ok_or_else(|| "missing --report-dir DIR".to_owned())?,
        )?;
        fs::create_dir_all(&report_dir_arg)
            .map_err(|error| format!("create report directory: {error}"))?;
        let report_dir = fs::canonicalize(&report_dir_arg)
            .map_err(|error| format!("resolve report directory: {error}"))?;
        let policy_text =
            fs::read_to_string(&policy_path).map_err(|error| format!("read policy: {error}"))?;
        let mut policy = parse_policy(&policy_text)?;
        validate_report_directory_disjoint(&report_dir, &policy.write_trees)?;

        let command_path = existing_executable(&args[separator + 1])?;
        if !policy.exec.iter().any(|rule| rule.path == command_path)
            && !policy
                .exec_trees
                .iter()
                .any(|tree| command_path.starts_with(&tree.path))
        {
            return Err(format!(
                "command is not covered by an exact exec rule or reviewed exec-tree: {}",
                command_path.display()
            ));
        }
        if policy.deny_exec.contains(&command_path) {
            return Err(format!(
                "command is explicitly denied: {}",
                command_path.display()
            ));
        }

        let abi = query_landlock_abi()?;
        if abi < 2 {
            return Err(format!(
                "unsupported Landlock ABI {abi}; this adapter requires ABI 2 for REFER handling"
            ));
        }
        let landlock = prepare_landlock(&policy, abi)?;
        verify_write_null_before_run(&policy)?;
        let seccomp_filter = seccomp_filter(policy.network_outbound);
        let stdout_path = report_dir.join("stdout.raw");
        let stderr_path = report_dir.join("stderr.raw");
        let stdout_file = create_new_private(&stdout_path)?;
        let stderr_file = create_new_private(&stderr_path)?;

        let argv = &args[separator + 2..];
        let mut child_command = Command::new(&command_path);
        child_command
            .args(argv)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &policy.env {
            child_command.env(name, value);
        }
        if let Some(cwd) = &policy.cwd {
            child_command.current_dir(cwd);
        }

        let ruleset_fd = landlock.ruleset.as_raw_fd();
        let started_micros = now_micros();
        let started = Instant::now();
        // SAFETY: The closure only issues precomputed syscalls in the
        // single-threaded post-fork child, then execs the requested command.
        unsafe {
            child_command.pre_exec(move || apply_child_restrictions(ruleset_fd, &seccomp_filter));
        }
        let mut child = match child_command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let launch_error = error.to_string();
                drop(stdout_file);
                drop(stderr_file);
                let finished_micros = now_micros();
                let empty = Capture {
                    saved: 0,
                    total: 0,
                    truncated: false,
                    write_error: None,
                };
                let hash_checks = verify_exec_hashes(&policy);
                let library_hash_checks = verify_read_library_hashes(&policy);
                let mut evidence_failures = vec![format!(
                    "sandboxed consumer command did not launch: {launch_error}"
                )];
                if let Some(failure) = record_write_null_after_run(&mut policy) {
                    evidence_failures.push(failure);
                }
                for check in &library_hash_checks {
                    if !check.post_run_hash_matches {
                        evidence_failures.push(format!(
                            "declared library hash did not match after run: {}",
                            check.path.display()
                        ));
                    }
                }
                let report_path = report_dir.join("report.json");
                let report = report_json(
                    &policy_path,
                    &report_dir,
                    &command_path,
                    argv,
                    started_micros,
                    finished_micros,
                    started.elapsed().as_millis(),
                    None,
                    Some(&launch_error),
                    None,
                    None,
                    &stdout_path,
                    &stderr_path,
                    &empty,
                    &empty,
                    None,
                    &evidence_failures,
                    &hash_checks,
                    &library_hash_checks,
                    &policy,
                    abi,
                    landlock.handled_fs,
                );
                if let Err(report_error) = write_new_private(&report_path, report.as_bytes()) {
                    eprintln!(
                        "consumer-enforcement-adapter qualification evidence failed: report write failed: {report_error}; launch_error={launch_error}"
                    );
                    return Ok(125);
                }
                eprintln!(
                    "consumer-enforcement-adapter report: {}",
                    report_path.display()
                );
                eprintln!(
                    "consumer-enforcement-adapter qualification evidence failed; no child exit status exists; launch_error={launch_error}"
                );
                return Ok(125);
            }
        };
        let pid = child.id();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "consumer stdout pipe missing".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "consumer stderr pipe missing".to_owned())?;
        let stdout_thread = capture_stream(stdout, stdout_file);
        let stderr_thread = capture_stream(stderr, stderr_file);
        let status = child
            .wait()
            .map_err(|error| format!("wait for consumer command: {error}"))?;
        let stdout_capture = stdout_thread
            .join()
            .map_err(|_| "stdout capture thread panicked".to_owned())?
            .map_err(|error| format!("capture stdout: {error}"))?;
        let stderr_capture = stderr_thread
            .join()
            .map_err(|_| "stderr capture thread panicked".to_owned())?
            .map_err(|error| format!("capture stderr: {error}"))?;
        let finished_micros = now_micros();
        let elapsed_millis = started.elapsed().as_millis();
        let child_exit_code = status.code();
        let child_signal = status.signal();
        let adapter_child_code = child_exit_code.unwrap_or_else(|| 128 + child_signal.unwrap_or(1));
        let replay_error = replay_bounded(&stdout_path, &stderr_path).err();
        let hash_checks = verify_exec_hashes(&policy);
        let library_hash_checks = verify_read_library_hashes(&policy);
        let mut evidence_failures = Vec::new();
        if let Some(failure) = record_write_null_after_run(&mut policy) {
            evidence_failures.push(failure);
        }
        for check in &hash_checks {
            if check.expected_sha256.is_some() && check.post_run_hash_matches != Some(true) {
                evidence_failures.push(format!(
                    "declared executable hash did not match after run: {}",
                    check.path.display()
                ));
            }
        }
        for check in &library_hash_checks {
            if !check.post_run_hash_matches {
                evidence_failures.push(format!(
                    "declared library hash did not match after run: {}",
                    check.path.display()
                ));
            }
        }
        for (label, capture) in [("stdout", &stdout_capture), ("stderr", &stderr_capture)] {
            if let Some(error) = &capture.write_error {
                evidence_failures.push(format!("{label} raw capture write failed: {error}"));
            }
        }
        if let Some(error) = &replay_error {
            evidence_failures.push(format!("bounded output replay failed: {error}"));
        }
        let report_path = report_dir.join("report.json");
        let report = report_json(
            &policy_path,
            &report_dir,
            &command_path,
            argv,
            started_micros,
            finished_micros,
            elapsed_millis,
            Some(pid),
            None,
            child_exit_code,
            child_signal,
            &stdout_path,
            &stderr_path,
            &stdout_capture,
            &stderr_capture,
            replay_error.as_deref(),
            &evidence_failures,
            &hash_checks,
            &library_hash_checks,
            &policy,
            abi,
            landlock.handled_fs,
        );
        if let Err(error) = write_new_private(&report_path, report.as_bytes()) {
            eprintln!(
                "consumer-enforcement-adapter qualification evidence failed: report write failed: {error}; original child exit_code={child_exit_code:?} signal={child_signal:?}"
            );
            return Ok(125);
        }
        eprintln!(
            "consumer-enforcement-adapter report: {}",
            report_path.display()
        );
        if !evidence_failures.is_empty() {
            eprintln!(
                "consumer-enforcement-adapter qualification evidence failed; original child exit_code={child_exit_code:?} signal={child_signal:?}"
            );
            for failure in &evidence_failures {
                eprintln!("  {failure}");
            }
            return Ok(125);
        }
        Ok(adapter_child_code)
    }

    fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
    }

    fn parse_policy(text: &str) -> Result<Policy, String> {
        let mut policy = Policy::default();
        let mut exec_seen = BTreeSet::new();
        let mut pending_exec_trees = Vec::new();
        let mut pending_exec_derived_trees = Vec::new();
        let mut library_lookup_seen = BTreeSet::new();
        let mut library_targets = BTreeMap::new();
        let mut future_exec = Vec::new();
        let mut future_derived = Vec::new();

        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line == "consumer-policy-v1" {
                continue;
            }
            let (kind, rest) = line.split_once(' ').ok_or_else(|| {
                format!("policy line {} must have a directive and value", index + 1)
            })?;
            let rest = rest.trim();
            match kind {
                "exec" => {
                    let path = existing_executable(rest)?;
                    if !exec_seen.insert(path.clone()) {
                        return Err(format!("duplicate exec path {}", path.display()));
                    }
                    policy.exec.push(ExecRule {
                        path,
                        expected_sha256: None,
                        expected_closure_sha256: None,
                        deferred: false,
                    });
                }
                "exec-hash" => {
                    let (path_text, hash) = rest
                        .rsplit_once(' ')
                        .ok_or_else(|| "exec-hash requires PATH SHA256".to_owned())?;
                    validate_hash(hash)?;
                    let path = existing_executable(path_text)?;
                    let actual = sha256_file(&path)?;
                    if actual != hash.to_ascii_lowercase() {
                        return Err(format!(
                            "exec hash mismatch for {}: expected {hash}, got {actual}",
                            path.display()
                        ));
                    }
                    if !exec_seen.insert(path.clone()) {
                        return Err(format!("duplicate exec path {}", path.display()));
                    }
                    policy.exec.push(ExecRule {
                        path,
                        expected_sha256: Some(hash.to_ascii_lowercase()),
                        expected_closure_sha256: None,
                        deferred: false,
                    });
                }
                "exec-future" => {
                    let (path, hash) = rest
                        .rsplit_once(' ')
                        .ok_or_else(|| "exec-future requires PATH SHA256".to_owned())?;
                    validate_hash(hash)?;
                    future_exec.push((path.to_owned(), hash.to_ascii_lowercase()));
                }
                "exec-derived" => {
                    let (path, closure_hash) = rest.rsplit_once(' ').ok_or_else(|| {
                        "exec-derived requires PATH SOURCE_CLOSURE_SHA256".to_owned()
                    })?;
                    validate_hash(closure_hash)?;
                    future_derived.push((path.to_owned(), closure_hash.to_ascii_lowercase()));
                }
                "exec-tree" => {
                    let (role, path) = rest
                        .split_once(' ')
                        .ok_or_else(|| "exec-tree requires ROLE EXISTING_DIRECTORY".to_owned())?;
                    if !["installer-stage", "target-generated-buildscripts"].contains(&role) {
                        return Err(format!("unreviewed executable subtree role {role:?}"));
                    }
                    pending_exec_trees.push((role.to_owned(), path.to_owned()));
                }
                "exec-derived-tree" => {
                    let (role, rest) = rest.split_once(' ').ok_or_else(|| {
                        "exec-derived-tree requires ROLE EXISTING_EMPTY_PRIVATE_PARENT SOURCE_CLOSURE_SHA256"
                            .to_owned()
                    })?;
                    if !["consumer-state-parent", "consumer-build-parent"].contains(&role) {
                        return Err(format!("unreviewed executable-tree role {role:?}"));
                    }
                    let (path, closure_hash) = rest.rsplit_once(' ').ok_or_else(|| {
                        "exec-derived-tree requires ROLE EXISTING_EMPTY_PRIVATE_PARENT SOURCE_CLOSURE_SHA256"
                            .to_owned()
                    })?;
                    validate_hash(closure_hash)?;
                    pending_exec_derived_trees.push((
                        role.to_owned(),
                        path.to_owned(),
                        closure_hash.to_ascii_lowercase(),
                    ));
                }
                "deny-exec" => policy.deny_exec.push(existing_or_future_path(rest)?),
                "deny-library" => policy.deny_library.push(existing_or_future_path(rest)?),
                "read-file" => policy.read_files.push(existing_or_future_path(rest)?),
                "write-null" => {
                    if policy.write_null.is_some() {
                        return Err("duplicate write-null directive".to_owned());
                    }
                    policy.write_null = Some(WriteNullRule {
                        pre_run_identity: inspect_write_null_policy_path(rest)?,
                        post_run_identity: None,
                        post_run_identity_matches: None,
                        post_run_error: None,
                    });
                }
                "read-directory" => policy.read_directories.push(existing_directory(rest)?),
                "read-library" => {
                    let (path_text, hash) = rest
                        .rsplit_once(' ')
                        .ok_or_else(|| "read-library requires PATH SHA256".to_owned())?;
                    validate_hash(hash)?;
                    let path = existing_regular_file(path_text)?;
                    let actual = sha256_file(&path)?;
                    if actual != hash.to_ascii_lowercase() {
                        return Err(format!(
                            "read-library hash mismatch for {}: expected {hash}, got {actual}",
                            path.display()
                        ));
                    }
                    if !library_lookup_seen.insert(path_text.to_owned()) {
                        return Err(format!("duplicate read-library lookup path {path_text}"));
                    }
                    let expected_sha256 = hash.to_ascii_lowercase();
                    match library_targets.get(&path) {
                        Some(existing_hash) if existing_hash != &expected_sha256 => {
                            return Err(format!(
                                "read-library aliases disagree on canonical target hash: {}",
                                path.display()
                            ));
                        }
                        Some(_) => {}
                        None => {
                            library_targets.insert(path.clone(), expected_sha256.clone());
                            policy.read_libraries.push(ReadLibraryRule {
                                path,
                                expected_sha256,
                                pre_run_sha256: actual,
                            });
                        }
                    }
                }
                "read-tree" => {
                    let (role, path) = rest
                        .split_once(' ')
                        .ok_or_else(|| "read-tree requires ROLE PATH".to_owned())?;
                    if ![
                        "sdk",
                        "source",
                        "toolchain",
                        "collector",
                        "cargo",
                        "vendor",
                        "state",
                        "work",
                        "home",
                        "tmp",
                        "output",
                        "target-generated-buildscripts",
                        "artifact",
                    ]
                    .contains(&role)
                    {
                        return Err(format!("unreviewed read-tree role {role:?}"));
                    }
                    policy
                        .read_trees
                        .push((role.to_owned(), existing_directory(path)?));
                }
                "write-tree" => {
                    let (role, path) = rest
                        .split_once(' ')
                        .ok_or_else(|| "write-tree requires ROLE PATH".to_owned())?;
                    if ![
                        "state",
                        "work",
                        "home",
                        "tmp",
                        "output",
                        "target",
                        "cargo-home",
                        "artifact",
                    ]
                    .contains(&role)
                    {
                        return Err(format!("unreviewed write-tree role {role:?}"));
                    }
                    let path = existing_directory(path)?;
                    validate_write_tree_path(&path)?;
                    policy.write_trees.push((role.to_owned(), path));
                }
                "env" => {
                    let (name, value) = rest
                        .split_once('=')
                        .ok_or_else(|| "env requires NAME=VALUE".to_owned())?;
                    if name.is_empty()
                        || !name
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '_')
                    {
                        return Err(format!("invalid environment name {name:?}"));
                    }
                    if name.starts_with("LD_")
                        || name.starts_with("BASH_FUNC_")
                        || ["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"].contains(&name)
                    {
                        return Err(format!(
                            "unsafe loader or shell-startup environment variable {name:?}"
                        ));
                    }
                    policy.env.insert(name.to_owned(), value.to_owned());
                }
                "cwd" => policy.cwd = Some(existing_directory(rest)?),
                "network" => match rest {
                    "outbound" => policy.network_outbound = true,
                    "deny" => policy.network_outbound = false,
                    _ => return Err("network must be outbound or deny".to_owned()),
                },
                _ => {
                    return Err(format!(
                        "unknown policy directive {kind:?} at line {}",
                        index + 1
                    ));
                }
            }
        }

        for (role, path_text) in pending_exec_trees {
            let path = existing_directory(&path_text)?;
            validate_exec_tree_role(&role, &path)?;
            let roots = policy
                .write_trees
                .iter()
                .filter(|(write_role, root)| {
                    let role_matches = match role.as_str() {
                        "target-generated-buildscripts" => write_role == "target",
                        "installer-stage" => {
                            ["work", "tmp", "state"].contains(&write_role.as_str())
                        }
                        _ => false,
                    };
                    role_matches && path.starts_with(root) && path != *root
                })
                .collect::<Vec<_>>();
            if roots.is_empty() {
                return Err(format!(
                    "exec-tree must be a strict descendant of a declared write-tree: {}",
                    path.display()
                ));
            }
            if policy
                .exec_trees
                .iter()
                .any(|tree: &ExecTree| tree.path.starts_with(&path) || path.starts_with(&tree.path))
            {
                return Err(format!(
                    "executable subtree roots may not overlap: {}",
                    path.display()
                ));
            }
            policy.exec_trees.push(ExecTree { role, path });
        }

        for (role, path_text, closure_hash) in pending_exec_derived_trees {
            let path = existing_empty_private_parent(&path_text)?;
            let is_within_owned_root = policy.write_trees.iter().any(|(write_role, root)| {
                ["work", "state", "target"].contains(&write_role.as_str())
                    && path.starts_with(root)
                    && path != *root
            });
            if !is_within_owned_root {
                return Err(format!(
                    "exec-derived-tree must be a strict descendant of a declared work/state/target write-tree: {}",
                    path.display()
                ));
            }
            if policy
                .exec_trees
                .iter()
                .any(|tree| paths_overlap(&tree.path, &path))
                || policy
                    .exec_derived_trees
                    .iter()
                    .any(|tree: &ExecDerivedTree| paths_overlap(&tree.path, &path))
            {
                return Err(format!(
                    "executable subtree roots may not overlap: {}",
                    path.display()
                ));
            }
            policy.exec_derived_trees.push(ExecDerivedTree {
                role,
                path,
                source_closure_sha256: closure_hash,
            });
        }

        for (path_text, hash) in future_exec {
            let path = future_executable_under_write_roots(&path_text, &policy.write_trees)?;
            let deferred = !Path::new(&path_text).exists();
            if !deferred {
                existing_executable(&path_text)?;
                let actual = sha256_file(&path)?;
                if actual != hash {
                    return Err(format!(
                        "exec-future hash mismatch for {}: expected {hash}, got {actual}",
                        path.display()
                    ));
                }
            } else if !policy
                .exec_trees
                .iter()
                .any(|tree| path.starts_with(&tree.path))
                && !policy
                    .exec_derived_trees
                    .iter()
                    .any(|tree| path.starts_with(&tree.path))
            {
                return Err(format!(
                    "Landlock needs a reviewed exec-tree for future executable {} ",
                    path.display()
                ));
            }
            if !exec_seen.insert(path.clone()) {
                return Err(format!("duplicate exec path {}", path.display()));
            }
            policy.exec.push(ExecRule {
                path,
                expected_sha256: Some(hash),
                expected_closure_sha256: None,
                deferred,
            });
        }

        for (path_text, closure_hash) in future_derived {
            let path = future_executable_under_write_roots(&path_text, &policy.write_trees)?;
            let deferred = !Path::new(&path_text).exists();
            if !deferred {
                existing_executable(&path_text)?;
            } else if !policy
                .exec_trees
                .iter()
                .any(|tree| path.starts_with(&tree.path))
                && !policy
                    .exec_derived_trees
                    .iter()
                    .any(|tree| path.starts_with(&tree.path))
            {
                return Err(format!(
                    "Landlock needs a reviewed exec-tree for future executable {}",
                    path.display()
                ));
            }
            if !exec_seen.insert(path.clone()) {
                return Err(format!("duplicate exec path {}", path.display()));
            }
            policy.exec.push(ExecRule {
                path,
                expected_sha256: None,
                expected_closure_sha256: Some(closure_hash),
                deferred,
            });
        }

        if policy.write_null.is_some() {
            if let Some((role, root)) = policy
                .write_trees
                .iter()
                .find(|(_, root)| paths_overlap(root, Path::new("/dev/null")))
            {
                return Err(format!(
                    "write-null cannot be combined with broader write-tree role {role:?}: {}",
                    root.display()
                ));
            }
        }

        if policy.exec.is_empty()
            && policy.exec_trees.is_empty()
            && policy.exec_derived_trees.is_empty()
        {
            return Err("policy has no executable allow rules".to_owned());
        }
        dedup_paths(&mut policy.deny_exec)?;
        dedup_paths(&mut policy.deny_library)?;
        dedup_paths(&mut policy.read_files)?;
        dedup_paths(&mut policy.read_directories)?;

        for denied in &policy.deny_exec {
            if exec_seen.contains(denied)
                || policy
                    .exec_trees
                    .iter()
                    .any(|tree| paths_overlap(denied, &tree.path))
                || policy
                    .exec_derived_trees
                    .iter()
                    .any(|tree| paths_overlap(denied, &tree.path))
            {
                return Err(format!(
                    "path is both allowed and denied for exec: {}",
                    denied.display()
                ));
            }
            let readable = policy
                .read_files
                .iter()
                .any(|path| paths_overlap(path, denied))
                || policy
                    .read_libraries
                    .iter()
                    .any(|library| paths_overlap(&library.path, denied))
                || policy
                    .read_trees
                    .iter()
                    .any(|(_, root)| paths_overlap(root, denied))
                || policy
                    .write_trees
                    .iter()
                    .any(|(_, root)| paths_overlap(root, denied));
            if readable {
                return Err(format!(
                    "deny-exec overlaps a read/write allowance; an allowed ELF loader could read it: {}",
                    denied.display()
                ));
            }
        }
        for denied in &policy.deny_library {
            let readable = policy
                .read_files
                .iter()
                .any(|path| paths_overlap(path, denied))
                || policy
                    .read_libraries
                    .iter()
                    .any(|library| paths_overlap(&library.path, denied))
                || policy
                    .exec
                    .iter()
                    .any(|rule| paths_overlap(&rule.path, denied))
                || policy
                    .exec_trees
                    .iter()
                    .any(|tree| paths_overlap(denied, &tree.path))
                || policy
                    .exec_derived_trees
                    .iter()
                    .any(|tree| paths_overlap(denied, &tree.path))
                || policy
                    .read_trees
                    .iter()
                    .any(|(_, root)| denied.starts_with(root) || root.starts_with(denied))
                || policy
                    .write_trees
                    .iter()
                    .any(|(_, root)| denied.starts_with(root) || root.starts_with(denied));
            if readable {
                return Err(format!(
                    "deny-library overlaps a read or write allowance; Landlock cannot subtract it: {}",
                    denied.display()
                ));
            }
        }
        for library in &policy.read_libraries {
            let overlaps_execution = policy
                .exec
                .iter()
                .any(|rule| paths_overlap(&rule.path, &library.path))
                || policy
                    .exec_trees
                    .iter()
                    .any(|tree| paths_overlap(&tree.path, &library.path))
                || policy
                    .exec_derived_trees
                    .iter()
                    .any(|tree| paths_overlap(&tree.path, &library.path));
            let overlaps_write = policy
                .write_trees
                .iter()
                .any(|(_, root)| paths_overlap(root, &library.path));
            if overlaps_execution || overlaps_write {
                return Err(format!(
                    "read-library overlaps an executable or writable allowance: {}",
                    library.path.display()
                ));
            }
        }
        Ok(policy)
    }

    fn paths_overlap(left: &Path, right: &Path) -> bool {
        left.starts_with(right) || right.starts_with(left)
    }

    fn validate_write_tree_path(path: &Path) -> Result<(), String> {
        if path.components().count() < 3
            || ["/", "/tmp", "/var/tmp", "/home", "/root", "/usr", "/opt"]
                .iter()
                .any(|root| path == Path::new(root))
        {
            return Err(format!(
                "write-tree must name a narrow owned directory, not a shared root: {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn validate_exec_tree_role(role: &str, path: &Path) -> Result<(), String> {
        let system_roots = [
            "/bin",
            "/usr/bin",
            "/sbin",
            "/usr/sbin",
            "/usr/local/bin",
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/libexec",
            "/usr/local/lib",
            "/etc",
            "/proc",
            "/sys",
            "/dev",
        ];
        if system_roots
            .iter()
            .any(|root| path.starts_with(Path::new(root)))
        {
            return Err(format!(
                "exec-tree may not cover a system executable or library directory: {}",
                path.display()
            ));
        }
        match role {
            "installer-stage" => {
                if !["exec-staging", "installer-stage"].contains(
                    &path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default(),
                ) {
                    return Err(format!(
                        "installer-stage must be a dedicated exec-staging or installer-stage directory: {}",
                        path.display()
                    ));
                }
            }
            "target-generated-buildscripts" => {
                let name = path.file_name().and_then(|value| value.to_str());
                let profile = path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|value| value.to_str());
                let target = path
                    .parent()
                    .and_then(Path::parent)
                    .and_then(Path::file_name)
                    .and_then(|value| value.to_str());
                if name != Some("build")
                    || !matches!(profile, Some("debug" | "release"))
                    || target != Some("target")
                {
                    return Err(format!(
                        "target-generated-buildscripts must be target/debug/build or target/release/build: {}",
                        path.display()
                    ));
                }
            }
            _ => return Err(format!("unreviewed executable subtree role {role:?}")),
        }
        Ok(())
    }

    fn dedup_paths(paths: &mut Vec<PathBuf>) -> Result<(), String> {
        let mut unique = BTreeSet::new();
        for path in paths.iter() {
            unique.insert(normalize_rule_path(path)?);
        }
        *paths = unique.into_iter().collect();
        Ok(())
    }

    fn existing_file(path: &str) -> Result<PathBuf, String> {
        let path = absolute_path(path)?;
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("resolve {}: {error}", path.display()))?;
        if !canonical.is_file() {
            return Err(format!("not a file: {}", canonical.display()));
        }
        Ok(canonical)
    }

    fn existing_regular_file(path: &str) -> Result<PathBuf, String> {
        let canonical = existing_file(path)?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|error| format!("inspect regular file {}: {error}", canonical.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!("not a regular file: {}", canonical.display()));
        }
        Ok(canonical)
    }

    fn existing_empty_private_parent(path: &str) -> Result<PathBuf, String> {
        let requested = absolute_path(path)?;
        let canonical = fs::canonicalize(&requested)
            .map_err(|error| format!("resolve private parent {}: {error}", requested.display()))?;
        if canonical != requested {
            return Err(format!(
                "exec-derived-tree parent must be supplied by its canonical path: {}",
                requested.display()
            ));
        }
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|error| format!("inspect private parent {}: {error}", canonical.display()))?;
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "exec-derived-tree parent is not a directory: {}",
                canonical.display()
            ));
        }
        // SAFETY: geteuid has no preconditions and returns the effective user ID.
        let effective_uid = unsafe { geteuid() };
        if metadata.uid() != effective_uid {
            return Err(format!(
                "exec-derived-tree parent is not owned by the current effective user: {}",
                canonical.display()
            ));
        }
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(format!(
                "exec-derived-tree parent must have mode 0700: {}",
                canonical.display()
            ));
        }
        if fs::read_dir(&canonical)
            .map_err(|error| {
                format!(
                    "inspect private parent contents {}: {error}",
                    canonical.display()
                )
            })?
            .next()
            .is_some()
        {
            return Err(format!(
                "exec-derived-tree parent must be empty at policy load: {}",
                canonical.display()
            ));
        }
        Ok(canonical)
    }

    fn existing_executable(path: &str) -> Result<PathBuf, String> {
        let canonical = existing_file(path)?;
        let metadata = fs::metadata(&canonical).map_err(|error| error.to_string())?;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!("not executable: {}", canonical.display()));
        }
        Ok(canonical)
    }

    fn existing_directory(path: &str) -> Result<PathBuf, String> {
        let path = absolute_path(path)?;
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("resolve directory {}: {error}", path.display()))?;
        if !canonical.is_dir() {
            return Err(format!("not a directory: {}", canonical.display()));
        }
        Ok(canonical)
    }

    fn existing_or_future_path(path: &str) -> Result<PathBuf, String> {
        if Path::new(path).exists() {
            let path = absolute_path(path)?;
            return fs::canonicalize(&path)
                .map_err(|error| format!("resolve {}: {error}", path.display()));
        }
        resolve_future_path(path)
    }

    fn future_executable_under_write_roots(
        path: &str,
        write_trees: &[(String, PathBuf)],
    ) -> Result<PathBuf, String> {
        let candidate = resolve_future_path(path)?;
        if !write_trees
            .iter()
            .any(|(_, root)| candidate.starts_with(root))
        {
            return Err(format!(
                "future exec path must be inside an explicitly declared write-tree: {}",
                candidate.display()
            ));
        }
        Ok(candidate)
    }

    fn resolve_future_path(path: &str) -> Result<PathBuf, String> {
        let requested = absolute_path(path)?;
        if requested
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(format!(
                "path with .. is not accepted: {}",
                requested.display()
            ));
        }
        if requested.exists() {
            return fs::canonicalize(&requested)
                .map_err(|error| format!("resolve {}: {error}", requested.display()));
        }
        let mut ancestor = requested.as_path();
        let mut missing = Vec::<OsString>::new();
        while !ancestor.exists() {
            if fs::symlink_metadata(ancestor).is_ok() {
                return Err(format!(
                    "unresolvable symlink in future path: {}",
                    ancestor.display()
                ));
            }
            let name = ancestor
                .file_name()
                .ok_or_else(|| format!("future path has no filename: {}", requested.display()))?;
            missing.push(name.to_os_string());
            ancestor = ancestor.parent().ok_or_else(|| {
                format!(
                    "future path has no existing ancestor: {}",
                    requested.display()
                )
            })?;
        }
        let mut resolved = fs::canonicalize(ancestor).map_err(|error| {
            format!(
                "resolve future path ancestor {}: {error}",
                ancestor.display()
            )
        })?;
        if !missing.is_empty() && !resolved.is_dir() {
            return Err(format!(
                "future path ancestor is not a directory: {}",
                resolved.display()
            ));
        }
        for component in missing.into_iter().rev() {
            resolved.push(component);
        }
        Ok(resolved)
    }

    fn absolute_path(path: &str) -> Result<PathBuf, String> {
        let path = Path::new(path);
        if !path.is_absolute() {
            return Err(format!("path must be absolute: {}", path.display()));
        }
        Ok(path.to_path_buf())
    }

    fn normalize_rule_path(path: &Path) -> Result<PathBuf, String> {
        if path.exists() {
            fs::canonicalize(path)
                .map_err(|error| format!("resolve policy path {}: {error}", path.display()))
        } else {
            resolve_future_path(&path.to_string_lossy())
        }
    }

    fn query_landlock_abi() -> Result<i32, String> {
        // SAFETY: Landlock's VERSION query ignores the pointer and size.
        let version = unsafe {
            syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<u8>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if version < 0 {
            return Err(format!(
                "landlock_create_ruleset(VERSION) failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(version as i32)
    }

    fn handled_access_fs(abi: i32) -> u64 {
        let mut rights = LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;
        if abi >= 2 {
            rights |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        if abi >= 5 {
            rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        }
        rights
    }

    fn prepare_landlock(policy: &Policy, abi: i32) -> Result<LandlockPlan, String> {
        let handled_fs = handled_access_fs(abi);
        let write_rights = LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SYM
            | if abi >= 2 {
                LANDLOCK_ACCESS_FS_REFER
            } else {
                0
            }
            | if abi >= 3 {
                LANDLOCK_ACCESS_FS_TRUNCATE
            } else {
                0
            };
        let mut rights_by_path = BTreeMap::<PathBuf, u64>::new();
        for rule in &policy.exec {
            // Future paths are covered by their already-validated exec-tree.
            // Adding an exact Landlock rule would canonicalize the missing path
            // and fail before the consumer can materialize it.
            if rule.deferred {
                continue;
            }
            rights_by_path
                .entry(rule.path.clone())
                .and_modify(|rights| {
                    *rights |= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE
                })
                .or_insert(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE);
        }
        for tree in &policy.exec_trees {
            rights_by_path
                .entry(tree.path.clone())
                .and_modify(|rights| {
                    *rights |= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE
                })
                .or_insert(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE);
        }
        for tree in &policy.exec_derived_trees {
            rights_by_path
                .entry(tree.path.clone())
                .and_modify(|rights| {
                    *rights |= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE
                })
                .or_insert(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE);
        }
        for path in &policy.read_files {
            rights_by_path
                .entry(path.clone())
                .and_modify(|rights| *rights |= LANDLOCK_ACCESS_FS_READ_FILE)
                .or_insert(LANDLOCK_ACCESS_FS_READ_FILE);
        }
        for path in &policy.read_directories {
            rights_by_path
                .entry(path.clone())
                .and_modify(|rights| *rights |= LANDLOCK_ACCESS_FS_READ_DIR)
                .or_insert(LANDLOCK_ACCESS_FS_READ_DIR);
        }
        for library in &policy.read_libraries {
            rights_by_path
                .entry(library.path.clone())
                .and_modify(|rights| *rights |= LANDLOCK_ACCESS_FS_READ_FILE)
                .or_insert(LANDLOCK_ACCESS_FS_READ_FILE);
        }
        for (_, path) in &policy.read_trees {
            rights_by_path
                .entry(path.clone())
                .and_modify(|rights| {
                    *rights |= LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
                })
                .or_insert(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
        }
        for (_, path) in &policy.write_trees {
            rights_by_path
                .entry(path.clone())
                .and_modify(|rights| *rights |= write_rights)
                .or_insert(write_rights);
        }
        if policy.write_null.is_some() {
            let null_write_rights = LANDLOCK_ACCESS_FS_WRITE_FILE
                | if abi >= 3 {
                    LANDLOCK_ACCESS_FS_TRUNCATE
                } else {
                    0
                };
            rights_by_path
                .entry(PathBuf::from("/dev/null"))
                .and_modify(|rights| *rights |= null_write_rights)
                .or_insert(null_write_rights);
        }
        if rights_by_path.is_empty() {
            return Err("empty Landlock path rule set".to_owned());
        }
        let attrs = LandlockRulesetAttr {
            handled_access_fs: handled_fs,
        };
        // SAFETY: attrs points to the correctly laid-out version 1 ruleset
        // structure and its size matches the Landlock UAPI structure.
        let raw_ruleset = unsafe {
            syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attrs as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };
        if raw_ruleset < 0 {
            return Err(format!(
                "landlock_create_ruleset failed: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: raw_ruleset is the new descriptor returned by the kernel.
        let ruleset = unsafe { File::from_raw_fd(raw_ruleset as i32) };
        let mut rules = Vec::with_capacity(rights_by_path.len());
        for (path, rights) in rights_by_path {
            let rule = if path == Path::new("/dev/null") {
                if let Some(write_null) = &policy.write_null {
                    OpenRule::new_write_null(&write_null.pre_run_identity, rights)?
                } else {
                    OpenRule::new(&path, rights)?
                }
            } else {
                OpenRule::new(&path, rights)?
            };
            let attr = LandlockPathBeneathAttr {
                allowed_access: rule.allowed_access,
                parent_fd: rule.fd.as_raw_fd(),
            };
            // SAFETY: ruleset and parent_fd are live descriptors; attr has the
            // kernel UAPI layout for LANDLOCK_RULE_PATH_BENEATH.
            let added = unsafe {
                syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    ruleset.as_raw_fd(),
                    LANDLOCK_RULE_PATH_BENEATH,
                    &attr as *const LandlockPathBeneathAttr,
                    0u32,
                )
            };
            if added < 0 {
                return Err(format!(
                    "landlock_add_rule {} failed: {}",
                    rule.path.display(),
                    io::Error::last_os_error()
                ));
            }
            rules.push(rule);
        }
        Ok(LandlockPlan {
            ruleset,
            _rules: rules,
            handled_fs,
        })
    }

    fn validate_report_directory_disjoint(
        report_dir: &Path,
        write_trees: &[(String, PathBuf)],
    ) -> Result<(), String> {
        for (role, write_root) in write_trees {
            if report_dir.starts_with(write_root) || write_root.starts_with(report_dir) {
                return Err(format!(
                    "report directory overlaps child write-tree role {role:?}: report={} write-tree={}",
                    report_dir.display(),
                    write_root.display()
                ));
            }
        }
        Ok(())
    }

    fn seccomp_filter(network_outbound: bool) -> Vec<SockFilter> {
        let mut filter = vec![
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_NATIVE,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        #[cfg(target_arch = "x86_64")]
        filter.extend([
            SockFilter {
                code: BPF_JMP_JSET_K,
                jt: 0,
                jf: 1,
                k: X32_SYSCALL_BIT,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | EACCES as u32,
            },
        ]);
        if !network_outbound {
            // Rust's Linux fork-based subprocess handshake receives one
            // eight-byte status message through the native recvfrom syscall
            // on its private SOCK_SEQPACKET pair. Other receive shapes stay denied except for that
            // exact shape. The argument checks preserve the syscall number
            // accumulator when this is not recvfrom and inspect both halves
            // of each 64-bit size or pointer argument.
            filter.push(SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 16,
                k: SYS_RECVFROM as u32,
            });
            for (index, (offset, value)) in [
                (32, 8), // args[2], count low word
                (36, 0), // args[2], count high word
                (40, 0), // args[3], flags
                (48, 0), // args[4], address low word
                (52, 0), // args[4], address high word
                (56, 0), // args[5], address-length pointer low word
                (60, 0), // args[5], address-length pointer high word
            ]
            .into_iter()
            .enumerate()
            {
                filter.push(SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: offset,
                });
                filter.push(SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: (13 - index * 2) as u8,
                    k: value,
                });
            }
            filter.extend([
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ALLOW,
                },
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ERRNO | EACCES as u32,
                },
            ]);

            // Rust's Unix subprocess backend uses a private, unnamed
            // AF_UNIX/SOCK_SEQPACKET socketpair for its child handshake.
            // This narrow exception grants no addressable socket or public
            // network operation. Read syscall arguments as low 32-bit words:
            // the kernel receives these three parameters as `int` values.
            filter.extend([
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 9,
                    k: SYS_SOCKETPAIR as u32,
                },
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 16, // args[0], domain
                },
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 6,
                    k: AF_UNIX as u32,
                },
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 24, // args[1], type
                },
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 1,
                    jf: 0,
                    k: SOCK_SEQPACKET as u32,
                },
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 3,
                    k: (SOCK_SEQPACKET | SOCK_CLOEXEC) as u32,
                },
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 32, // args[2], protocol
                },
                SockFilter {
                    code: BPF_JMP_JEQ_K,
                    jt: 0,
                    jf: 1,
                    k: 0,
                },
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ALLOW,
                },
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ERRNO | EACCES as u32,
                },
            ]);
        }
        let mut blocked = vec![SYS_EXECVEAT as u32, SYS_MEMFD_CREATE as u32];
        if !network_outbound {
            blocked.extend_from_slice(NETWORK_SYSCALLS);
        }
        for number in blocked {
            filter.push(SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: number,
            });
            filter.push(SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | EACCES as u32,
            });
        }
        filter.push(SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
        filter
    }

    fn apply_child_restrictions(ruleset_fd: i32, filter: &[SockFilter]) -> io::Result<()> {
        // SAFETY: PR_SET_NO_NEW_PRIVS has scalar arguments and is valid for the
        // child process before installing its Landlock ruleset.
        if unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ruleset_fd is a live ruleset descriptor inherited across fork.
        let restricted = unsafe { syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
        if restricted < 0 {
            return Err(io::Error::last_os_error());
        }
        // Close the ruleset descriptor after restriction; path rule descriptors
        // are O_CLOEXEC and close automatically on successful exec.
        // SAFETY: close accepts the inherited ruleset descriptor.
        if unsafe { close(ruleset_fd) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let program = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        // SAFETY: filter remains alive in the closure for this syscall and is a
        // valid classic-BPF program. TSYNC is used as in the accepted probe.
        let result = unsafe {
            syscall(
                SYS_SECCOMP,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC,
                &program as *const SockFprog,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result != 0 {
            return Err(io::Error::other(format!(
                "seccomp TSYNC returned unexpected thread id {result}"
            )));
        }
        Ok(())
    }

    fn capture_stream<R: Read + Send + 'static>(
        mut input: R,
        mut output: File,
    ) -> thread::JoinHandle<io::Result<Capture>> {
        thread::spawn(move || {
            let mut total = 0u64;
            let mut saved = 0usize;
            let mut write_error = None;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let read = input.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                total += read as u64;
                if saved < MAX_CAPTURE_BYTES && write_error.is_none() {
                    let count = (MAX_CAPTURE_BYTES - saved).min(read);
                    let mut offset = 0;
                    while offset < count {
                        match output.write(&buffer[offset..count]) {
                            Ok(0) => {
                                write_error =
                                    Some("raw output write returned zero bytes".to_owned());
                                break;
                            }
                            Ok(written) => {
                                saved += written;
                                offset += written;
                            }
                            Err(error) => {
                                write_error = Some(error.to_string());
                                break;
                            }
                        }
                    }
                }
            }
            if let Err(error) = output.flush() {
                if write_error.is_none() {
                    write_error = Some(error.to_string());
                }
            }
            Ok(Capture {
                saved,
                total,
                truncated: total > saved as u64,
                write_error,
            })
        })
    }

    fn replay_bounded(stdout: &Path, stderr: &Path) -> Result<(), String> {
        io::stdout()
            .write_all(&fs::read(stdout).map_err(|error| error.to_string())?)
            .and_then(|_| io::stdout().flush())
            .map_err(|error| format!("replay stdout: {error}"))?;
        io::stderr()
            .write_all(&fs::read(stderr).map_err(|error| error.to_string())?)
            .and_then(|_| io::stderr().flush())
            .map_err(|error| format!("replay stderr: {error}"))?;
        Ok(())
    }

    fn report_json(
        policy_path: &Path,
        report_dir: &Path,
        command: &Path,
        args: &[String],
        started: u128,
        finished: u128,
        elapsed_millis: u128,
        pid: Option<u32>,
        launch_error: Option<&str>,
        exit_code: Option<i32>,
        signal: Option<i32>,
        stdout_path: &Path,
        stderr_path: &Path,
        out: &Capture,
        err: &Capture,
        replay_error: Option<&str>,
        evidence_failures: &[String],
        hash_checks: &[ExecHashCheck],
        library_hash_checks: &[ReadLibraryHashCheck],
        policy: &Policy,
        abi: i32,
        handled_fs: u64,
    ) -> String {
        let argv = std::iter::once(command.display().to_string())
            .chain(args.iter().cloned())
            .map(|value| json(&value))
            .collect::<Vec<_>>()
            .join(",");
        let read_library_mappings = library_hash_checks
            .iter()
            .map(|check| {
                format!(
                    "{{\"path\":{},\"identity\":\"library-sha256\",\"expected_sha256\":{},\"permissions\":[\"READ_FILE\"],\"process_exec\":false,\"hash_verified_before_run\":{},\"pre_run_sha256\":{},\"post_run_sha256\":{},\"post_run_hash_matches\":{}}}",
                    json(&check.path.display().to_string()),
                    json(&check.expected_sha256),
                    check.pre_run_sha256 == check.expected_sha256,
                    json(&check.pre_run_sha256),
                    check.post_run_sha256.as_ref().map(|value| json(value)).unwrap_or_else(|| "null".to_owned()),
                    check.post_run_hash_matches
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let execs = hash_checks
            .iter()
            .map(|check| {
                let identity = if check.expected_sha256.is_some() {
                    "binary-sha256"
                } else if check.expected_closure_sha256.is_some() {
                    "reviewed-source-closure"
                } else {
                    "literal-path-only"
                };
                format!(
                    "{{\"path\":{},\"identity\":{},\"expected_sha256\":{},\"expected_closure_sha256\":{},\"closure_digest_verification\":{},\"hash_verified_before_run\":{},\"hash_deferred_until_materialized\":{},\"path_missing_before_run\":{},\"post_run_sha256\":{},\"post_run_hash_matches\":{}}}",
                    json(&check.path.display().to_string()),
                    json(identity),
                    check.expected_sha256.as_ref().map(|value| json(value)).unwrap_or_else(|| "null".to_owned()),
                    check.expected_closure_sha256.as_ref().map(|value| json(value)).unwrap_or_else(|| "null".to_owned()),
                    check.expected_closure_sha256.as_ref().map(|_| json("declared by policy; not verified by adapter")).unwrap_or_else(|| "null".to_owned()),
                    check.hash_verified_before_run,
                    check.expected_sha256.is_some() && check.hash_deferred_until_materialized,
                    check.path_missing_before_run,
                    check.post_run_sha256.as_ref().map(|value| json(value)).unwrap_or_else(|| "null".to_owned()),
                    check.post_run_hash_matches.map(|value| value.to_string()).unwrap_or_else(|| "null".to_owned())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let exec_trees = policy
            .exec_trees
            .iter()
            .map(|tree| {
                format!(
                    "{{\"role\":{},\"path\":{},\"semantics\":\"Landlock path-beneath subtree; all descendants may execute\"}}",
                    json(&tree.role),
                    json(&tree.path.display().to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let exec_derived_trees = policy
            .exec_derived_trees
            .iter()
            .map(|tree| {
                format!(
                    "{{\"role\":{},\"path\":{},\"source_closure_sha256\":{},\"source_closure_verification\":\"declared by policy; not verified by adapter\",\"semantics\":\"Landlock path-beneath subtree; descendants may execute\"}}",
                    json(&tree.role),
                    json(&tree.path.display().to_string()),
                    json(&tree.source_closure_sha256)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let read_trees = policy
            .read_trees
            .iter()
            .map(|(role, path)| {
                format!(
                    "{{\"role\":{},\"path\":{}}}",
                    json(role),
                    json(&path.display().to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let read_directories = policy
            .read_directories
            .iter()
            .map(|path| {
                format!(
                    "{{\"path\":{},\"permissions\":[\"READ_DIR\"],\"scope\":\"directory-listing-below-path; no file data or execution\"}}",
                    json(&path.display().to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let write_trees = policy
            .write_trees
            .iter()
            .map(|(role, path)| {
                format!(
                    "{{\"role\":{},\"path\":{}}}",
                    json(role),
                    json(&path.display().to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let write_null = policy
            .write_null
            .as_ref()
            .map(|rule| {
                let mut permissions = vec![json("WRITE_FILE")];
                if abi >= 3 {
                    permissions.push(json("TRUNCATE"));
                }
                let post_identity = rule
                    .post_run_identity
                    .as_ref()
                    .map(|identity| {
                        format!(
                            "{{\"device\":{},\"inode\":{},\"rdev\":{}}}",
                            identity.device, identity.inode, identity.rdev
                        )
                    })
                    .unwrap_or_else(|| "null".to_owned());
                format!(
                    "{{\"path\":{},\"device_type\":\"character-device\",\"permissions\":[{}],\"pre_run_identity\":{{\"device\":{},\"inode\":{},\"rdev\":{}}},\"post_run_identity\":{},\"post_run_identity_matches\":{},\"post_run_error\":{},\"content_sha256\":null}}",
                    json("/dev/null"),
                    permissions.join(","),
                    rule.pre_run_identity.device,
                    rule.pre_run_identity.inode,
                    rule.pre_run_identity.rdev,
                    post_identity,
                    rule.post_run_identity_matches.map(|matches| matches.to_string()).unwrap_or_else(|| "null".to_owned()),
                    rule.post_run_error.as_ref().map(|error| json(error)).unwrap_or_else(|| "null".to_owned())
                )
            })
            .unwrap_or_else(|| "null".to_owned());
        let evidence = evidence_failures
            .iter()
            .map(|failure| json(failure))
            .collect::<Vec<_>>()
            .join(",");
        let exec_allowlist = policy
            .exec
            .iter()
            .map(|rule| json(&rule.path.display().to_string()))
            .collect::<Vec<_>>()
            .join(",");
        let denied_exec = policy
            .deny_exec
            .iter()
            .map(|path| json(&path.display().to_string()))
            .collect::<Vec<_>>()
            .join(",");
        let denied_library = policy
            .deny_library
            .iter()
            .map(|path| json(&path.display().to_string()))
            .collect::<Vec<_>>()
            .join(",");
        let read_files = policy
            .read_files
            .iter()
            .map(|path| json(&path.display().to_string()))
            .collect::<Vec<_>>()
            .join(",");
        let env_names = policy
            .env
            .keys()
            .map(|name| json(name))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\n  \"schema\":\"{REPORT_SCHEMA}\",\n  \"backend\":\"{REPORT_BACKEND}\",\n  \"policy\":{},\n  \"report_directory\":{},\n  \"landlock_abi\":{},\n  \"landlock_fs_rights_reviewed_through_abi\":5,\n  \"landlock_handled_fs_rights_mask\":{},\n  \"seccomp\":{{\"tsync\":true,\"execveat_denied\":true,\"memfd_create_denied\":true,{REPORT_ABI_GUARD}\"network_denied\":{}}},\n  \"command\":[{}],\n  \"started_unix_micros\":{},\n  \"finished_unix_micros\":{},\n  \"elapsed_millis\":{},\n  \"pid\":{},\n  \"launch_error\":{},\n  \"child_exit_code\":{},\n  \"child_signal\":{},\n  \"stdout\":{{\"path\":{},\"bytes_captured\":{},\"bytes_total\":{},\"truncated\":{},\"write_error\":{}}},\n  \"stderr\":{{\"path\":{},\"bytes_captured\":{},\"bytes_total\":{},\"truncated\":{},\"write_error\":{}}},\n  \"network_outbound_allowed\":{},\n  \"exec_allowlist\":[{}],\n  \"exec_identity_checks\":[{}],\n  \"read_library_mappings\":[{}],\n  \"exec_trees\":[{}],\n  \"exec_derived_trees\":[{}],\n  \"deny_exec\":[{}],\n  \"deny_library\":{{\"paths\":[{}],\"enforcement\":\"no overlapping Landlock READ_FILE/EXECUTE allowance\"}},\n  \"read_files\":[{}],\n  \"read_directories\":[{}],\n  \"read_trees\":[{}],\n  \"write_trees\":[{}],\n  \"write_null\":{},\n  \"environment_names\":[{}],\n  \"cwd\":{},\n  \"output_replay_error\":{},\n  \"qualification_evidence_valid\":{},\n  \"evidence_failures\":[{}],\n  \"outer_supervisor_timeout_cleanup_required\":true,\n  \"outer_supervisor_timeout_cleanup_verified_by_adapter\":false\n}}\n",
            json(&policy_path.display().to_string()),
            json(&report_dir.display().to_string()),
            abi,
            handled_fs,
            !policy.network_outbound,
            argv,
            started,
            finished,
            elapsed_millis,
            pid.map(|value| value.to_string())
                .unwrap_or_else(|| "null".to_owned()),
            launch_error.map(json).unwrap_or_else(|| "null".to_owned()),
            exit_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".to_owned()),
            signal
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".to_owned()),
            json(&stdout_path.display().to_string()),
            out.saved,
            out.total,
            out.truncated,
            out.write_error
                .as_ref()
                .map(|error| json(error))
                .unwrap_or_else(|| "null".to_owned()),
            json(&stderr_path.display().to_string()),
            err.saved,
            err.total,
            err.truncated,
            err.write_error
                .as_ref()
                .map(|error| json(error))
                .unwrap_or_else(|| "null".to_owned()),
            policy.network_outbound,
            exec_allowlist,
            execs,
            read_library_mappings,
            exec_trees,
            exec_derived_trees,
            denied_exec,
            denied_library,
            read_files,
            read_directories,
            read_trees,
            write_trees,
            write_null,
            env_names,
            policy
                .cwd
                .as_ref()
                .map(|path| json(&path.display().to_string()))
                .unwrap_or_else(|| "null".to_owned()),
            replay_error.map(json).unwrap_or_else(|| "null".to_owned()),
            evidence_failures.is_empty(),
            evidence
        )
    }

    fn verify_exec_hashes(policy: &Policy) -> Vec<ExecHashCheck> {
        policy
            .exec
            .iter()
            .map(|rule| {
                let post = if rule.expected_sha256.is_some() && rule.path.is_file() {
                    sha256_file(&rule.path).ok()
                } else {
                    None
                };
                let matches = rule
                    .expected_sha256
                    .as_ref()
                    .map(|expected| post.as_ref() == Some(expected));
                ExecHashCheck {
                    path: rule.path.clone(),
                    expected_sha256: rule.expected_sha256.clone(),
                    expected_closure_sha256: rule.expected_closure_sha256.clone(),
                    hash_verified_before_run: rule.expected_sha256.is_some() && !rule.deferred,
                    hash_deferred_until_materialized: rule.deferred,
                    path_missing_before_run: rule.deferred,
                    post_run_sha256: post,
                    post_run_hash_matches: matches,
                }
            })
            .collect()
    }

    fn verify_read_library_hashes(policy: &Policy) -> Vec<ReadLibraryHashCheck> {
        policy
            .read_libraries
            .iter()
            .map(|library| {
                let remains_canonical =
                    fs::canonicalize(&library.path).ok().as_deref() == Some(library.path.as_path());
                let remains_regular = fs::symlink_metadata(&library.path)
                    .is_ok_and(|metadata| metadata.file_type().is_file());
                let post_run_sha256 = if remains_canonical && remains_regular {
                    sha256_file(&library.path).ok()
                } else {
                    None
                };
                let post_run_hash_matches =
                    post_run_sha256.as_deref() == Some(library.expected_sha256.as_str());
                ReadLibraryHashCheck {
                    path: library.path.clone(),
                    expected_sha256: library.expected_sha256.clone(),
                    pre_run_sha256: library.pre_run_sha256.clone(),
                    post_run_sha256,
                    post_run_hash_matches,
                }
            })
            .collect()
    }

    pub(super) fn control(args: &[String]) -> Result<(), String> {
        let mode = args.first().map(String::as_str).unwrap_or_default();
        match mode {
            "positive" => {
                if let Some(path) = option(args, "--path") {
                    fs::write(path, b"adapter-positive\n")
                        .map_err(|error| format!("write positive-control output: {error}"))?;
                }
                println!("ADAPTER_NATIVE_POSITIVE");
            }
            "write-null-probe" => {
                match OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open("/dev/null")
                {
                    Ok(mut null) => {
                        null.write_all(b"consumer-enforcement-null-write-probe\n")
                            .map_err(|error| format!("write /dev/null probe: {error}"))?;
                        println!("WRITE_NULL_ALLOWED");
                    }
                    Err(error) if matches!(error.raw_os_error(), Some(EACCES) | Some(1)) => {
                        println!(
                            "WRITE_NULL_REFUSED errno={}",
                            error.raw_os_error().unwrap_or_default()
                        );
                    }
                    Err(error) => return Err(format!("open /dev/null write probe: {error}")),
                }
            }
            "positive-spawn" => {
                let path = required(args, "--path")?;
                let self_path = env::current_exe().map_err(|error| error.to_string())?;
                // Exercise the same Command::output setup as the refusal
                // controls, including opening /dev/null for the child's stdin.
                let output = Command::new(self_path)
                    .args(["--control", "positive", "--path", path])
                    .output()
                    .map_err(|error| format!("launch native positive descendant: {error}"))?;
                if !output.status.success()
                    || output.stdout != b"ADAPTER_NATIVE_POSITIVE\n"
                    || !output.stderr.is_empty()
                {
                    return Err(format!(
                        "native positive descendant failed: status={:?} stdout={:?} stderr={:?}",
                        output.status.code(),
                        output.stdout,
                        output.stderr
                    ));
                }
                println!("ADAPTER_NATIVE_DESCENDANT_POSITIVE");
            }
            "positive-fork-spawn" => {
                let self_path = env::current_exe().map_err(|error| error.to_string())?;
                let mut command = Command::new(self_path);
                command.args(["--control", "positive"]);
                if let Some(path) = option(args, "--path") {
                    command.args(["--path", path]);
                }
                // SAFETY: This hook is deliberately empty. It performs no
                // allocation, locking, or other work between fork and exec.
                unsafe {
                    command.pre_exec(|| Ok(()));
                }
                let output = command.output().map_err(|error| {
                    format!("launch native forked positive descendant: {error}")
                })?;
                if !output.status.success()
                    || output.stdout != b"ADAPTER_NATIVE_POSITIVE\n"
                    || !output.stderr.is_empty()
                {
                    return Err(format!(
                        "native forked positive descendant failed: status={:?} stdout={:?} stderr={:?}",
                        output.status.code(),
                        output.stdout,
                        output.stderr
                    ));
                }
                println!("ADAPTER_NATIVE_FORK_DESCENDANT_POSITIVE");
            }
            "future-materialize" => {
                let source = required(args, "--source")?;
                let target = PathBuf::from(required(args, "--path")?);
                let delete_after = args.iter().any(|argument| argument == "--delete-after");
                if target.exists() {
                    return Err(format!(
                        "future-exec destination already exists: {}",
                        target.display()
                    ));
                }
                let parent = target
                    .parent()
                    .ok_or_else(|| format!("future target has no parent: {}", target.display()))?;
                fs::create_dir_all(parent)
                    .map_err(|error| format!("create nested future-exec parent: {error}"))?;
                fs::copy(source, &target)
                    .map_err(|error| format!("materialize future executable: {error}"))?;
                let mut permissions = fs::metadata(&target)
                    .map_err(|error| error.to_string())?
                    .permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(&target, permissions).map_err(|error| error.to_string())?;
                match Command::new(&target).status() {
                    Ok(status) if status.success() => {
                        if delete_after {
                            fs::remove_file(&target)
                                .map_err(|error| format!("remove transient executable: {error}"))?;
                            println!(
                                "FUTURE_EXEC_OK path={} removed_after_execution=true",
                                target.display()
                            );
                        } else {
                            println!("FUTURE_EXEC_OK path={}", target.display());
                        }
                    }
                    Ok(status) => {
                        println!(
                            "FUTURE_EXEC_NONZERO path={} status={status:?}",
                            target.display()
                        );
                        process::exit(status.code().unwrap_or(1));
                    }
                    Err(error) => {
                        println!(
                            "FUTURE_EXEC_REFUSED path={} error={error}",
                            target.display()
                        );
                        process::exit(95);
                    }
                }
            }
            "seccomp" => seccomp_control()?,
            "socketpair-refusal" => socketpair_refusal_control()?,
            _ => return Err(format!("unknown control mode {mode:?}")),
        }
        Ok(())
    }

    fn seccomp_control() -> Result<(), String> {
        let target = CString::new("/usr/bin/true").expect("literal has no NUL");
        let empty = CString::new("").expect("literal has no NUL");
        let name = CString::new("adapter-a1").expect("literal has no NUL");
        // SAFETY: target and name are NUL-terminated; open returns an owned
        // descriptor used only by the execveat denial control.
        let target_fd = unsafe { open(target.as_ptr(), O_PATH | O_CLOEXEC) };
        if target_fd < 0 {
            return Err(format!(
                "open positive execveat target: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: These are valid null-terminated argv/envp vectors. The
        // syscall is expected to fail with EACCES under the accepted filter.
        let argv = [target.as_ptr(), std::ptr::null()];
        let envp: [*const std::ffi::c_char; 1] = [std::ptr::null()];
        let exec_result = unsafe {
            syscall(
                SYS_EXECVEAT,
                target_fd,
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                AT_EMPTY_PATH,
            )
        };
        let exec_errno = io::Error::last_os_error().raw_os_error();
        // SAFETY: target_fd is still open and owned by this function.
        let _ = unsafe { close(target_fd) };
        if exec_result != -1 || exec_errno != Some(EACCES) {
            return Err(format!(
                "execveat control expected EACCES; result={exec_result} errno={exec_errno:?}"
            ));
        }
        println!("EXECVEAT_REFUSED errno={EACCES}");
        // SAFETY: name is NUL-terminated; return should be -1/EACCES.
        let memfd_result = unsafe { syscall(SYS_MEMFD_CREATE, name.as_ptr(), MFD_CLOEXEC) };
        let memfd_errno = io::Error::last_os_error().raw_os_error();
        if memfd_result != -1 || memfd_errno != Some(EACCES) {
            return Err(format!(
                "memfd_create control expected EACCES; result={memfd_result} errno={memfd_errno:?}"
            ));
        }
        println!("MEMFD_CREATE_REFUSED errno={EACCES}");
        Ok(())
    }

    fn socketpair_refusal_control() -> Result<(), String> {
        for (domain, sock_type, protocol, label) in [
            (AF_INET, SOCK_SEQPACKET, 0, "inet-domain"),
            (AF_UNIX, SOCK_STREAM, 0, "stream-type"),
            (AF_UNIX, SOCK_SEQPACKET, 1, "nonzero-protocol"),
        ] {
            let mut pair = [-1; 2];
            // SAFETY: pair points to two writable integers; the remaining
            // arguments are scalar socket parameters. Seccomp must refuse
            // each disallowed combination before the kernel creates a pair.
            let result = unsafe {
                syscall(
                    SYS_SOCKETPAIR,
                    domain,
                    sock_type,
                    protocol,
                    pair.as_mut_ptr(),
                )
            };
            let errno = io::Error::last_os_error().raw_os_error();
            if result == 0 {
                for fd in pair {
                    // SAFETY: a successful socketpair returned both owned fds.
                    let _ = unsafe { close(fd) };
                }
            }
            if result != -1 || errno != Some(EACCES) {
                return Err(format!(
                    "disallowed socketpair {label} expected EACCES; result={result} errno={errno:?}"
                ));
            }
            println!("SOCKETPAIR_REFUSED case={label} errno={EACCES}");
        }

        for sock_type in [SOCK_SEQPACKET, SOCK_SEQPACKET | SOCK_CLOEXEC] {
            local_socketpair_roundtrip(sock_type)?;
        }
        println!("LOCAL_SOCKETPAIR_IO_OK");
        println!("PRIVATE_HANDSHAKE_RECV_OK");

        for (label, arguments) in [
            ("bad-count", [u64::MAX, 0, 7, 0, 0, 0]),
            ("high-count", [u64::MAX, 0, 8 + (1 << 32), 0, 0, 0]),
            ("bad-flags", [u64::MAX, 0, 8, 1, 0, 0]),
            ("address-low", [u64::MAX, 0, 8, 0, 1, 0]),
            ("address-high", [u64::MAX, 0, 8, 0, 1 << 32, 0]),
            ("address-length-low", [u64::MAX, 0, 8, 0, 0, 1]),
            ("address-length-high", [u64::MAX, 0, 8, 0, 0, 1 << 32]),
        ] {
            let result = syscall6(SYS_RECVFROM, arguments);
            let errno = io::Error::last_os_error().raw_os_error();
            if result != -1 || errno != Some(EACCES) {
                return Err(format!(
                    "recvfrom {label} expected EACCES; result={result} errno={errno:?}"
                ));
            }
            println!("HANDSHAKE_RECV_REFUSED case={label} errno={EACCES}");
        }

        for number in NETWORK_SYSCALLS {
            let arguments = if *number == SYS_SOCKET as u32 {
                [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0]
            } else if *number == 425 {
                [1, 0, 0, 0, 0, 0]
            } else {
                [u64::MAX, 0, 0, 0, 0, 0]
            };
            let result = syscall6(*number as isize, arguments);
            let errno = io::Error::last_os_error().raw_os_error();
            if result >= 0 && RETURNING_FD_NETWORK_SYSCALLS.contains(number) {
                // socket, accept, accept4, and io_uring_setup return one
                // owned descriptor if unexpectedly allowed.
                // SAFETY: result is the descriptor returned by that syscall.
                let _ = unsafe { close(result as i32) };
            }
            if result != -1 || errno != Some(EACCES) {
                return Err(format!(
                    "network syscall {number} expected EACCES; result={result} errno={errno:?}"
                ));
            }
            println!("NETWORK_SYSCALL_REFUSED number={number} errno={EACCES}");
        }
        println!("ADAPTER_NETWORK_DENIAL_CONTROL");
        Ok(())
    }

    fn local_socketpair_roundtrip(sock_type: i32) -> Result<(), String> {
        let mut pair = [-1; 2];
        // SAFETY: pair points to two writable integers; the accepted AF_UNIX
        // and SOCK_SEQPACKET arguments create only an unnamed local pair.
        let result = unsafe { syscall(SYS_SOCKETPAIR, AF_UNIX, sock_type, 0, pair.as_mut_ptr()) };
        if result != 0 {
            return Err(format!(
                "allowed local socketpair type={sock_type:#x} failed: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: successful socketpair returned two newly owned descriptors.
        let sender = unsafe { File::from_raw_fd(pair[0]) };
        // SAFETY: successful socketpair returned two newly owned descriptors.
        let mut receiver = unsafe { File::from_raw_fd(pair[1]) };
        let payload = b"private rust subprocess handshake";
        (&sender)
            .write_all(payload)
            .map_err(|error| format!("write allowed local socketpair: {error}"))?;
        let mut received = vec![0; payload.len()];
        receiver
            .read_exact(&mut received)
            .map_err(|error| format!("read allowed local socketpair: {error}"))?;
        if received != payload {
            return Err("local socketpair returned unexpected payload".to_owned());
        }

        let handshake = b"FORKACK!";
        (&sender)
            .write_all(handshake)
            .map_err(|error| format!("write allowed local handshake: {error}"))?;
        let mut handshake_received = [0; 8];
        let result = syscall6(
            SYS_RECVFROM,
            [
                receiver.as_raw_fd() as u64,
                handshake_received.as_mut_ptr() as usize as u64,
                handshake_received.len() as u64,
                0,
                0,
                0,
            ],
        );
        if result != handshake_received.len() as isize {
            return Err(format!(
                "read allowed local handshake with recvfrom: result={result}, error={}",
                io::Error::last_os_error()
            ));
        }
        if handshake_received != *handshake {
            return Err("local recvfrom handshake returned unexpected payload".to_owned());
        }
        Ok(())
    }

    fn syscall6(number: isize, arguments: [u64; 6]) -> isize {
        // SAFETY: callers supply the argument layout for the named Linux
        // syscall. Refusal controls use invalid fds and non-dereferenceable
        // addresses; the positive recvfrom check uses a live private socket
        // pair and an eight-byte local buffer.
        unsafe {
            syscall(
                number,
                arguments[0],
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4],
                arguments[5],
            )
        }
    }

    fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
        args.iter()
            .position(|argument| argument == name)
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
            .ok_or_else(|| format!("missing {name}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn private_test_root(label: &str) -> PathBuf {
            let path = env::temp_dir().join(format!(
                "consumer-adapter-linux-a1-{label}-{}-{}",
                process::id(),
                now_micros()
            ));
            fs::create_dir_all(&path).expect("create private test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("restrict private test directory");
            fs::canonicalize(path).expect("canonicalize private test directory")
        }

        fn create_private_directory(path: &Path) {
            fs::create_dir_all(path).expect("create test directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("set test directory mode");
        }

        fn evaluate_seccomp_filter(
            filter: &[SockFilter],
            arch: u32,
            syscall_number: u32,
            arguments: [u64; 6],
        ) -> u32 {
            let mut accumulator = 0u32;
            let mut pc = 0usize;
            loop {
                let instruction = filter.get(pc).expect("BPF program terminates");
                match instruction.code {
                    BPF_LD_W_ABS => {
                        accumulator = match instruction.k {
                            0 => syscall_number,
                            4 => arch,
                            offset if (16..64).contains(&offset) => {
                                let argument = ((offset - 16) / 8) as usize;
                                let high_word = (offset - 16) % 8 == 4;
                                let value = arguments[argument];
                                if high_word {
                                    (value >> 32) as u32
                                } else {
                                    value as u32
                                }
                            }
                            offset => panic!("unexpected BPF data offset {offset}"),
                        };
                    }
                    BPF_JMP_JEQ_K => {
                        pc += 1 + if accumulator == instruction.k {
                            instruction.jt as usize
                        } else {
                            instruction.jf as usize
                        };
                        continue;
                    }
                    BPF_JMP_JSET_K => {
                        pc += 1 + if accumulator & instruction.k != 0 {
                            instruction.jt as usize
                        } else {
                            instruction.jf as usize
                        };
                        continue;
                    }
                    BPF_RET_K => return instruction.k,
                    code => panic!("unexpected BPF instruction {code:#x}"),
                }
                pc += 1;
            }
        }

        fn assert_eacces(result: u32) {
            assert_eq!(result, SECCOMP_RET_ERRNO | EACCES as u32);
        }

        #[repr(C)]
        struct SeccompDataLayout {
            nr: i32,
            arch: u32,
            instruction_pointer: u64,
            args: [u64; 6],
        }

        #[test]
        fn native_linux_syscall_tables_match_the_supported_lp64_abis() {
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(AUDIT_ARCH_NATIVE, 0xc000_003e);
                assert_eq!(SYS_SECCOMP, 317);
                assert_eq!(SYS_MEMFD_CREATE, 319);
                assert_eq!(SYS_EXECVEAT, 322);
                assert_eq!(SYS_SOCKET, 41);
                assert_eq!(SYS_SOCKETPAIR, 53);
                assert_eq!(SYS_RECVFROM, 45);
                assert_eq!(
                    NETWORK_SYSCALLS,
                    &[41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54, 55, 288, 299, 307, 425]
                );
            }
            #[cfg(target_arch = "aarch64")]
            {
                assert_eq!(AUDIT_ARCH_NATIVE, 0xc000_00b7);
                assert_eq!(SYS_SECCOMP, 277);
                assert_eq!(SYS_MEMFD_CREATE, 279);
                assert_eq!(SYS_EXECVEAT, 281);
                assert_eq!(SYS_SOCKET, 198);
                assert_eq!(SYS_SOCKETPAIR, 199);
                assert_eq!(SYS_RECVFROM, 207);
                assert_eq!(
                    NETWORK_SYSCALLS,
                    &[
                        198, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 242,
                        243, 269, 425
                    ]
                );
                assert!(!NETWORK_SYSCALLS.contains(&199));
            }
        }

        #[test]
        fn linux_uapi_layouts_match_the_lp64_syscall_contract() {
            use std::mem::{offset_of, size_of};

            assert_eq!(size_of::<SockFilter>(), 8);
            assert_eq!(size_of::<SockFprog>(), 16);
            assert_eq!(offset_of!(SockFprog, len), 0);
            assert_eq!(offset_of!(SockFprog, filter), 8);
            assert_eq!(size_of::<SeccompDataLayout>(), 64);
            assert_eq!(offset_of!(SeccompDataLayout, nr), 0);
            assert_eq!(offset_of!(SeccompDataLayout, arch), 4);
            assert_eq!(offset_of!(SeccompDataLayout, instruction_pointer), 8);
            assert_eq!(offset_of!(SeccompDataLayout, args), 16);
            assert_eq!(size_of::<LandlockRulesetAttr>(), 8);
            assert_eq!(offset_of!(LandlockRulesetAttr, handled_access_fs), 0);
            assert_eq!(offset_of!(LandlockPathBeneathAttr, allowed_access), 0);
            assert_eq!(offset_of!(LandlockPathBeneathAttr, parent_fd), 8);
        }

        #[test]
        fn network_deny_filter_only_allows_private_seqpacket_handshake() {
            let filter = seccomp_filter(false);
            assert!(!NETWORK_SYSCALLS.contains(&(SYS_SOCKETPAIR as u32)));
            assert!(NETWORK_SYSCALLS.contains(&(SYS_SOCKET as u32)));
            assert!(NETWORK_SYSCALLS.contains(&(SYS_RECVFROM as u32)));
            assert!(
                NETWORK_SYSCALLS.contains(&425),
                "io_uring_setup stays denied"
            );
            for sock_type in [SOCK_SEQPACKET, SOCK_SEQPACKET | SOCK_CLOEXEC] {
                let args = [AF_UNIX as u64, sock_type as u64, 0, 0, 0, 0];
                assert_eq!(
                    evaluate_seccomp_filter(
                        &filter,
                        AUDIT_ARCH_NATIVE,
                        SYS_SOCKETPAIR as u32,
                        args,
                    ),
                    SECCOMP_RET_ALLOW,
                    "AF_UNIX SOCK_SEQPACKET type={sock_type:#x}"
                );
            }

            // socketpair() takes int parameters, so the kernel uses the low
            // 32 bits even if a raw syscall register contains high bits.
            let args = [
                (0xfeed_beefu64 << 32) | AF_UNIX as u64,
                (0xfade_babeu64 << 32) | SOCK_SEQPACKET as u64,
                0xffff_ffff_0000_0000,
                0,
                0,
                0,
            ];
            assert_eq!(
                evaluate_seccomp_filter(&filter, AUDIT_ARCH_NATIVE, SYS_SOCKETPAIR as u32, args,),
                SECCOMP_RET_ALLOW
            );

            assert_eq!(
                evaluate_seccomp_filter(
                    &filter,
                    AUDIT_ARCH_NATIVE,
                    SYS_RECVFROM as u32,
                    [u64::MAX, 0xfeed_beef, 8, 0, 0, 0],
                ),
                SECCOMP_RET_ALLOW,
                "the exact eight-byte recvfrom handshake shape is allowed"
            );

            for (label, arguments) in [
                ("short count", [u64::MAX, 0, 7, 0, 0, 0]),
                ("long count", [u64::MAX, 0, 9, 0, 0, 0]),
                ("high count", [u64::MAX, 0, 8 + (1 << 32), 0, 0, 0]),
                ("flags", [u64::MAX, 0, 8, 1, 0, 0]),
                ("address low half", [u64::MAX, 0, 8, 0, 1, 0]),
                ("address high half", [u64::MAX, 0, 8, 0, 1 << 32, 0]),
                ("address-length low half", [u64::MAX, 0, 8, 0, 0, 1]),
                ("address-length high half", [u64::MAX, 0, 8, 0, 0, 1 << 32]),
            ] {
                assert_eacces(evaluate_seccomp_filter(
                    &filter,
                    AUDIT_ARCH_NATIVE,
                    SYS_RECVFROM as u32,
                    arguments,
                ));
                assert!(
                    NETWORK_SYSCALLS.contains(&(SYS_RECVFROM as u32)),
                    "recvfrom remains in the network-deny syscall list ({label})"
                );
            }

            for (domain, sock_type, protocol) in [
                (AF_INET, SOCK_SEQPACKET, 0),
                (AF_UNIX, SOCK_STREAM, 0),
                (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | 0x800, 0),
                (AF_UNIX, SOCK_SEQPACKET, 1),
            ] {
                assert_eacces(evaluate_seccomp_filter(
                    &filter,
                    AUDIT_ARCH_NATIVE,
                    SYS_SOCKETPAIR as u32,
                    [domain as u64, sock_type as u64, protocol as u64, 0, 0, 0],
                ));
            }

            assert!(!NETWORK_SYSCALLS.contains(&(SYS_SOCKETPAIR as u32)));
            for syscall_number in NETWORK_SYSCALLS
                .iter()
                .copied()
                .filter(|number| *number != SYS_RECVFROM as u32)
            {
                assert!(NETWORK_SYSCALLS.contains(&syscall_number));
                assert_eacces(evaluate_seccomp_filter(
                    &filter,
                    AUDIT_ARCH_NATIVE,
                    syscall_number,
                    [0; 6],
                ));
            }
            assert!(NETWORK_SYSCALLS.contains(&(SYS_SENDTO as u32)));
            assert_eacces(evaluate_seccomp_filter(
                &filter,
                AUDIT_ARCH_NATIVE,
                SYS_SENDTO as u32,
                [u64::MAX, 0, 8, 0x4000, 0, 0],
            ));
            #[cfg(target_arch = "x86_64")]
            {
                assert_eacces(evaluate_seccomp_filter(
                    &filter,
                    AUDIT_ARCH_NATIVE,
                    SYS_SOCKETPAIR as u32 | X32_SYSCALL_BIT,
                    [AF_UNIX as u64, SOCK_SEQPACKET as u64, 0, 0, 0, 0],
                ));
            }
            #[cfg(target_arch = "x86_64")]
            let foreign_arch = 0x4000_0003; // AUDIT_ARCH_I386
            #[cfg(target_arch = "aarch64")]
            let foreign_arch = 0x4000_0028; // AUDIT_ARCH_ARM compat ABI
            assert_eq!(
                evaluate_seccomp_filter(
                    &filter,
                    foreign_arch,
                    SYS_SOCKETPAIR as u32,
                    [AF_UNIX as u64, SOCK_SEQPACKET as u64, 0, 0, 0, 0],
                ),
                SECCOMP_RET_KILL_PROCESS
            );
        }

        #[test]
        fn network_outbound_filter_keeps_network_syscalls_allowed() {
            let filter = seccomp_filter(true);
            for syscall_number in NETWORK_SYSCALLS.iter().copied() {
                assert_eq!(
                    evaluate_seccomp_filter(&filter, AUDIT_ARCH_NATIVE, syscall_number, [0; 6],),
                    SECCOMP_RET_ALLOW
                );
            }
            assert_eacces(evaluate_seccomp_filter(
                &filter,
                AUDIT_ARCH_NATIVE,
                SYS_EXECVEAT as u32,
                [0; 6],
            ));
            assert_eacces(evaluate_seccomp_filter(
                &filter,
                AUDIT_ARCH_NATIVE,
                SYS_MEMFD_CREATE as u32,
                [0; 6],
            ));
        }

        fn test_capture() -> Capture {
            Capture {
                saved: 0,
                total: 0,
                truncated: false,
                write_error: None,
            }
        }

        #[test]
        fn handles_known_filesystem_rights_across_supported_abi_boundaries() {
            let abi2 = handled_access_fs(2);
            let abi3 = handled_access_fs(3);
            let abi5 = handled_access_fs(5);
            let newer = handled_access_fs(9);
            assert_ne!(abi2 & LANDLOCK_ACCESS_FS_REFER, 0);
            assert_eq!(abi2 & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
            assert_ne!(abi3 & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
            assert_eq!(abi3 & LANDLOCK_ACCESS_FS_IOCTL_DEV, 0);
            assert_ne!(abi5 & LANDLOCK_ACCESS_FS_IOCTL_DEV, 0);
            assert_eq!(
                newer, abi5,
                "new unrelated ABI rights remain outside this reviewed mask"
            );
        }

        #[test]
        fn write_null_accepts_only_the_real_device_and_grants_narrow_abi_rights() {
            let mut policy =
                parse_policy("consumer-policy-v1\nexec /bin/true\nwrite-null /dev/null\n")
                    .expect("accept the exact native null device");
            let identity = &policy
                .write_null
                .as_ref()
                .expect("write-null rule")
                .pre_run_identity;
            assert_eq!(identity.rdev, LINUX_NULL_RDEV);
            verify_write_null_before_run(&policy).expect("identity remains stable before run");

            let available_abi = query_landlock_abi().expect("query native Landlock ABI");
            assert!(
                available_abi >= 2,
                "unexpected Landlock ABI {available_abi}"
            );
            for abi in [2, 3].into_iter().filter(|abi| *abi <= available_abi) {
                let plan = prepare_landlock(&policy, abi).expect("prepare exact null rule");
                let rule = plan
                    ._rules
                    .iter()
                    .find(|rule| rule.path == Path::new("/dev/null"))
                    .expect("exact Landlock rule for /dev/null");
                let expected = LANDLOCK_ACCESS_FS_WRITE_FILE
                    | if abi >= 3 {
                        LANDLOCK_ACCESS_FS_TRUNCATE
                    } else {
                        0
                    };
                assert_eq!(rule.allowed_access, expected);
            }
            assert!(record_write_null_after_run(&mut policy).is_none());
            let report = report_json(
                Path::new("/policy"),
                Path::new("/reports"),
                Path::new("/bin/true"),
                &[],
                1,
                2,
                1,
                None,
                None,
                Some(0),
                None,
                Path::new("/stdout"),
                Path::new("/stderr"),
                &test_capture(),
                &test_capture(),
                None,
                &[],
                &verify_exec_hashes(&policy),
                &verify_read_library_hashes(&policy),
                &policy,
                available_abi,
                handled_access_fs(available_abi),
            );
            assert!(report.contains("\"post_run_identity_matches\":true"));
            assert!(report.contains("\"content_sha256\":null"));
            assert!(
                report.contains("\"permissions\":[\"WRITE_FILE\"")
                    || report.contains("\"permissions\":[\"WRITE_FILE\",\"TRUNCATE\"]")
            );
            drop(policy);

            for invalid in ["/dev/zero", "/dev//null", "/dev/../dev/null"] {
                assert!(
                    inspect_write_null_policy_path(invalid).is_err(),
                    "reject noncanonical policy spelling {invalid}"
                );
                let invalid_policy =
                    format!("consumer-policy-v1\nexec /bin/true\nwrite-null {invalid}\n");
                assert!(parse_policy(&invalid_policy).is_err());
            }
            let root = private_test_root("write-null-invalid-targets");
            let regular = root.join("regular-null");
            fs::write(&regular, b"not a device").expect("write regular-file fixture");
            let regular_metadata = fs::symlink_metadata(&regular).expect("stat regular fixture");
            assert!(validated_null_identity(
                "/dev/null",
                Path::new("/dev/null"),
                &regular_metadata
            )
            .expect_err("reject regular replacement")
            .contains("not a character device"));
            let symlink = root.join("null-link");
            std::os::unix::fs::symlink("/dev/null", &symlink).expect("create null symlink");
            let symlink_metadata = fs::symlink_metadata(&symlink).expect("lstat null symlink");
            assert!(validated_null_identity(
                "/dev/null",
                Path::new("/dev/null"),
                &symlink_metadata
            )
            .expect_err("reject symlink replacement")
            .contains("not a character device"));
            assert!(inspect_write_null_policy_path(&symlink.to_string_lossy()).is_err());
            assert!(parse_policy(&format!(
                "consumer-policy-v1\nexec /bin/true\nwrite-null {}\n",
                symlink.display()
            ))
            .is_err());
            fs::remove_dir_all(root).expect("remove private test root");
        }

        #[test]
        fn accepts_nested_future_executable_under_reviewed_staging_tree() {
            let root = private_test_root("nested-future");
            let work = root.join("work");
            let exec_staging = work.join("exec-staging");
            fs::create_dir_all(&exec_staging).expect("create work and staging roots");
            let future = exec_staging.join("rust-installer/nested/install-helper");
            let policy_text = format!(
                "consumer-policy-v1\nwrite-tree work {}\nexec-tree installer-stage {}\nexec-derived {} {}\n",
                work.display(),
                exec_staging.display(),
                future.display(),
                "a".repeat(64)
            );
            let policy = parse_policy(&policy_text).expect("accept owned future executable");
            assert!(policy.exec[0].deferred);
            assert_eq!(policy.exec[0].path, future);
            assert_eq!(policy.exec_trees[0].path, exec_staging);
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn landlock_setup_accepts_missing_future_path_via_existing_exec_tree() {
            let root = private_test_root("future-landlock-setup");
            let work = root.join("work");
            let exec_staging = work.join("exec-staging");
            fs::create_dir_all(&exec_staging).expect("create work and staging roots");
            let future = exec_staging.join("rust-installer/nested/install-helper");
            let policy_text = format!(
                "consumer-policy-v1\nwrite-tree work {}\nexec-tree installer-stage {}\nexec-derived {} {}\n",
                work.display(),
                exec_staging.display(),
                future.display(),
                "c".repeat(64)
            );
            let policy = parse_policy(&policy_text).expect("parse future executable policy");
            assert!(!future.exists(), "fixture must remain genuinely absent");
            let abi = query_landlock_abi().expect("query native Landlock ABI");
            assert!(abi >= 2, "unexpected Landlock ABI {abi}");
            let plan = prepare_landlock(&policy, abi)
                .expect("prepare rules without opening a missing exact future path");
            assert!(plan._rules.iter().any(|rule| rule.path == exec_staging));
            assert!(plan._rules.iter().all(|rule| rule.path != future));
            drop(plan);
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn accepts_report_directory_disjoint_from_child_write_trees() {
            let root = private_test_root("report-disjoint");
            let write_root = root.join("work");
            let report_dir = root.join("reports/run-1");
            fs::create_dir_all(&write_root).expect("create write root");
            fs::create_dir_all(&report_dir).expect("create separate report root");
            let write_trees = vec![("work".to_owned(), write_root)];
            assert!(validate_report_directory_disjoint(&report_dir, &write_trees).is_ok());
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn rejects_report_directory_inside_child_write_tree() {
            let root = private_test_root("report-inside-write");
            let write_root = root.join("work");
            let report_dir = write_root.join("reports/run-1");
            fs::create_dir_all(&report_dir).expect("create nested report directory");
            let write_trees = vec![("work".to_owned(), write_root)];
            assert!(validate_report_directory_disjoint(&report_dir, &write_trees).is_err());
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn rejects_report_directory_that_is_ancestor_of_child_write_tree() {
            let root = private_test_root("report-ancestor-write");
            let report_dir = root.join("outputs");
            let write_root = report_dir.join("work");
            fs::create_dir_all(&write_root).expect("create nested write root");
            let write_trees = vec![("work".to_owned(), write_root)];
            assert!(validate_report_directory_disjoint(&report_dir, &write_trees).is_err());
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn accepts_only_the_generated_buildscript_subtree_role() {
            let root = private_test_root("buildscript-tree");
            let target = root.join("project/target");
            let build = target.join("debug/build");
            fs::create_dir_all(&build).expect("create target generated tree");
            let policy_text = format!(
                "consumer-policy-v1\nwrite-tree target {}\nexec-tree target-generated-buildscripts {}\n",
                target.display(),
                build.display()
            );
            let policy = parse_policy(&policy_text).expect("accept generated buildscript root");
            assert_eq!(policy.exec_trees[0].path, build);
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn rejects_denied_executable_hidden_in_read_tree() {
            let root = private_test_root("read-tree-denial");
            let system_like = root.join("tool-runtime");
            fs::create_dir_all(&system_like).expect("create runtime fixture root");
            let denied_tool = system_like.join("forbidden-tool");
            fs::write(&denied_tool, b"fixture").expect("create executable placeholder");
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nread-tree toolchain {}\ndeny-exec {}\n",
                system_like.display(),
                denied_tool.display()
            );
            let error =
                parse_policy(&policy_text).expect_err("read-tree may expose denied ELF to loader");
            assert!(error.contains("allowed ELF loader could read it"));
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn rejects_denied_library_hidden_in_runtime_read_tree() {
            let root = private_test_root("library-read-tree-denial");
            let runtime = root.join("runtime");
            fs::create_dir_all(&runtime).expect("create runtime fixture root");
            let library = runtime.join("libforbidden-fixture.so");
            fs::write(&library, b"fixture").expect("create library placeholder");
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nread-tree toolchain {}\ndeny-library {}\n",
                runtime.display(),
                library.display()
            );
            let error =
                parse_policy(&policy_text).expect_err("read-tree must not shadow a denied library");
            assert!(error.contains("Landlock cannot subtract it"));
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn rejects_nested_future_executable_without_reviewed_exec_tree() {
            let root = private_test_root("future-outside-exec-tree");
            let work = root.join("work");
            fs::create_dir_all(&work).expect("create work root");
            let future = work.join("nested/runner");
            let policy_text = format!(
                "consumer-policy-v1\nwrite-tree work {}\nexec-derived {} {}\n",
                work.display(),
                future.display(),
                "b".repeat(64)
            );
            let error = parse_policy(&policy_text)
                .expect_err("future path needs a narrowly reviewed Landlock subtree");
            assert!(error.contains("reviewed exec-tree"));
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn rejects_broad_system_executable_subtrees_and_shared_write_roots() {
            assert!(validate_exec_tree_role("installer-stage", Path::new("/usr/bin")).is_err());
            assert!(validate_write_tree_path(Path::new("/tmp")).is_err());
        }

        #[test]
        fn read_library_is_read_file_only_hashed_and_reported_separately() {
            let root = private_test_root("read-library");
            let library = root.join("libfixture.so");
            fs::write(&library, b"fixture library bytes").expect("write library fixture");
            let digest = sha256_file(&library).expect("hash library fixture");
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nread-library {} {}\n",
                library.display(),
                digest
            );
            let policy = parse_policy(&policy_text).expect("accept matching library hash");
            assert_eq!(policy.read_libraries.len(), 1);
            assert!(policy.exec.iter().all(|rule| rule.path != library));
            let check = verify_read_library_hashes(&policy);
            assert!(check[0].post_run_hash_matches);

            let abi = query_landlock_abi().expect("query Landlock ABI");
            let plan = prepare_landlock(&policy, abi).expect("prepare library read rule");
            let library_rule = plan
                ._rules
                .iter()
                .find(|rule| rule.path == library)
                .expect("Landlock rule for library");
            assert_eq!(library_rule.allowed_access, LANDLOCK_ACCESS_FS_READ_FILE);

            let report = report_json(
                Path::new("/policy"),
                Path::new("/reports"),
                Path::new("/bin/true"),
                &[],
                1,
                2,
                1,
                Some(42),
                None,
                Some(0),
                None,
                Path::new("/stdout"),
                Path::new("/stderr"),
                &test_capture(),
                &test_capture(),
                None,
                &[],
                &verify_exec_hashes(&policy),
                &check,
                &policy,
                abi,
                handled_access_fs(abi),
            );
            let exact_exec_field = report
                .split("\"exec_allowlist\":[")
                .nth(1)
                .and_then(|tail| tail.split(']').next())
                .expect("exec allowlist field");
            assert!(!exact_exec_field.contains(&library.display().to_string()));
            assert!(report.contains(&format!(
                "\"identity\":\"library-sha256\",\"expected_sha256\":\"{digest}\",\"permissions\":[\"READ_FILE\"],\"process_exec\":false"
            )));

            fs::write(&library, b"changed library bytes").expect("mutate library fixture");
            assert!(!verify_read_library_hashes(&policy)[0].post_run_hash_matches);
            drop(plan);
            fs::remove_dir_all(root).expect("remove private test directory");
        }

        #[test]
        fn read_library_aliases_are_verified_and_share_one_enforcement_entry() {
            let root = private_test_root("read-library-aliases");
            let library = root.join("libfixture.so.11");
            let alias_one = root.join("libfixture.so");
            let alias_two = root.join("libfixture.so.1");
            fs::write(&library, b"fixture library bytes").expect("write library fixture");
            std::os::unix::fs::symlink(&library, &alias_one).expect("create first library alias");
            std::os::unix::fs::symlink(&library, &alias_two).expect("create second library alias");

            let canonical = fs::canonicalize(&library).expect("canonical library target");
            let digest = sha256_file(&canonical).expect("hash canonical library");
            let target_inode = fs::metadata(&canonical).expect("stat library target").ino();
            assert_eq!(
                fs::metadata(&alias_one)
                    .expect("stat first library alias")
                    .ino(),
                target_inode
            );
            assert_eq!(
                fs::metadata(&alias_two)
                    .expect("stat second library alias")
                    .ino(),
                target_inode
            );

            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nread-library {} {}\nread-library {} {}\nread-library {} {}\n",
                canonical.display(),
                digest,
                alias_one.display(),
                digest,
                alias_two.display(),
                digest
            );
            let policy = parse_policy(&policy_text).expect("accept distinct verified aliases");
            assert_eq!(policy.read_libraries.len(), 1);
            assert_eq!(policy.read_libraries[0].path, canonical);
            assert_eq!(policy.read_libraries[0].expected_sha256, digest);
            assert_eq!(verify_read_library_hashes(&policy).len(), 1);

            let wrong_hash = "0".repeat(64);
            let wrong_hash = if wrong_hash == digest {
                "1".repeat(64)
            } else {
                wrong_hash
            };
            let alias_mismatch = format!(
                "consumer-policy-v1\nexec /bin/true\nread-library {} {}\nread-library {} {}\n",
                canonical.display(),
                digest,
                alias_one.display(),
                wrong_hash
            );
            assert!(parse_policy(&alias_mismatch)
                .expect_err("verify every alias digest before de-duplication")
                .contains("read-library hash mismatch"));

            let missing = root.join("missing-library.so");
            let invalid_file = format!(
                "consumer-policy-v1\nexec /bin/true\nread-library {} {}\n",
                missing.display(),
                digest
            );
            assert!(parse_policy(&invalid_file)
                .expect_err("reject missing library path")
                .contains("resolve"));

            fs::remove_dir_all(root).expect("remove private test directory");
        }

        #[test]
        fn read_library_rejects_repeated_original_lookup_spelling() {
            let root = private_test_root("read-library-duplicate-lookup");
            let library = root.join("libfixture.so");
            fs::write(&library, b"fixture library bytes").expect("write library fixture");
            let digest = sha256_file(&library).expect("hash library fixture");
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nread-library {} {}\nread-library {} {}\n",
                library.display(),
                digest,
                library.display(),
                digest
            );

            assert!(parse_policy(&policy_text)
                .expect_err("reject repeated lookup directive")
                .contains("duplicate read-library lookup path"));
            fs::remove_dir_all(root).expect("remove private test directory");
        }

        #[test]
        fn read_library_rejects_hash_mismatch_and_deny_overlap() {
            let root = private_test_root("read-library-invalid");
            let library = root.join("libfixture.so");
            fs::write(&library, b"fixture library bytes").expect("write library fixture");
            let wrong_hash = "0".repeat(64);
            let mismatch = format!(
                "consumer-policy-v1\nexec /bin/true\nread-library {} {}\n",
                library.display(),
                wrong_hash
            );
            assert!(parse_policy(&mismatch)
                .expect_err("reject mismatching library hash")
                .contains("read-library hash mismatch"));

            let digest = sha256_file(&library).expect("hash library fixture");
            let overlap = format!(
                "consumer-policy-v1\nexec /bin/true\nread-library {} {}\ndeny-library {}\n",
                library.display(),
                digest,
                library.display()
            );
            assert!(parse_policy(&overlap)
                .expect_err("reject explicitly denied mapped library")
                .contains("Landlock cannot subtract it"));

            let file_overlap = format!(
                "consumer-policy-v1\nexec /bin/true\nread-file {}\ndeny-library {}\n",
                library.display(),
                library.display()
            );
            assert!(parse_policy(&file_overlap)
                .expect_err("reject file-data allowance for denied library")
                .contains("Landlock cannot subtract it"));
            fs::remove_dir_all(root).expect("remove private test directory");
        }

        #[test]
        fn read_directory_grants_only_directory_listing_around_denied_library() {
            let root = private_test_root("read-directory");
            let runtime = root.join("runtime");
            create_private_directory(&runtime);
            let library = runtime.join("libforbidden-fixture.so");
            fs::write(&library, b"denied library bytes").expect("write denied library fixture");
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nread-directory {}\ndeny-library {}\n",
                runtime.display(),
                library.display()
            );
            let policy = parse_policy(&policy_text).expect("directory-only parent access is safe");
            assert_eq!(policy.read_directories, vec![runtime.clone()]);
            assert!(policy.read_files.iter().all(|path| path != &runtime));

            let abi = query_landlock_abi().expect("query Landlock ABI");
            let plan = prepare_landlock(&policy, abi).expect("prepare directory-only rule");
            let directory_rule = plan
                ._rules
                .iter()
                .find(|rule| rule.path == runtime)
                .expect("Landlock rule for listed directory");
            assert_eq!(directory_rule.allowed_access, LANDLOCK_ACCESS_FS_READ_DIR);
            assert!(plan._rules.iter().all(|rule| rule.path != library
                || rule.allowed_access & LANDLOCK_ACCESS_FS_READ_FILE == 0));

            let report = report_json(
                Path::new("/policy"),
                Path::new("/reports"),
                Path::new("/bin/true"),
                &[],
                1,
                2,
                1,
                Some(42),
                None,
                Some(0),
                None,
                Path::new("/stdout"),
                Path::new("/stderr"),
                &test_capture(),
                &test_capture(),
                None,
                &[],
                &verify_exec_hashes(&policy),
                &[],
                &policy,
                abi,
                handled_access_fs(abi),
            );
            assert!(report.contains(&format!(
                "\"read_directories\":[{{\"path\":\"{}\",\"permissions\":[\"READ_DIR\"],\"scope\":\"directory-listing-below-path; no file data or execution\"}}]",
                runtime.display()
            )));
            assert!(report.contains("\"read_files\":[]"));
            drop(plan);
            fs::remove_dir_all(root).expect("remove test directory");
        }

        #[test]
        fn exec_derived_tree_accepts_missing_future_setup_under_empty_private_parent() {
            let root = private_test_root("derived-tree-positive");
            let target = root.join("project/target");
            let parent = target.join("consumer-build");
            create_private_directory(&root.join("project"));
            create_private_directory(&target);
            create_private_directory(&parent);
            let future_tool = parent.join("fresh-build/helper");
            let digest = "a".repeat(64);
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nwrite-tree target {}\nexec-derived {} {}\nexec-derived-tree consumer-build-parent {} {}\n",
                target.display(),
                future_tool.display(),
                digest,
                parent.display(),
                digest
            );
            let policy = parse_policy(&policy_text).expect("accept dedicated private parent");
            assert!(
                !future_tool.exists(),
                "future child path must remain absent"
            );
            assert_eq!(policy.exec_derived_trees[0].path, parent);
            let future_exec = policy
                .exec
                .iter()
                .find(|rule| rule.path == future_tool)
                .expect("deferred future setup executable");
            assert!(future_exec.deferred);
            assert_eq!(
                future_exec.expected_closure_sha256.as_deref(),
                Some(digest.as_str())
            );
            let abi = query_landlock_abi().expect("query Landlock ABI");
            let plan = prepare_landlock(&policy, abi).expect("prepare descendant execute rule");
            let parent_rule = plan
                ._rules
                .iter()
                .find(|rule| rule.path == parent)
                .expect("Landlock rule for private parent");
            assert_eq!(
                parent_rule.allowed_access,
                LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE
            );
            assert!(plan._rules.iter().all(|rule| rule.path != future_tool));
            let report = report_json(
                Path::new("/policy"),
                Path::new("/reports"),
                Path::new("/bin/true"),
                &[],
                1,
                2,
                1,
                Some(42),
                None,
                Some(0),
                None,
                Path::new("/stdout"),
                Path::new("/stderr"),
                &test_capture(),
                &test_capture(),
                None,
                &[],
                &verify_exec_hashes(&policy),
                &[],
                &policy,
                abi,
                handled_access_fs(abi),
            );
            assert!(report.contains(&format!(
                "\"role\":\"consumer-build-parent\",\"path\":\"{}\",\"source_closure_sha256\":\"{digest}\",\"source_closure_verification\":\"declared by policy; not verified by adapter\"",
                parent.display()
            )));
            drop(plan);
            fs::remove_dir_all(root).expect("remove private test directory");
        }

        #[test]
        fn exec_derived_tree_rejects_nonempty_wrong_mode_and_unscoped_parent() {
            let root = private_test_root("derived-tree-invalid");
            let work = root.join("work");
            create_private_directory(&work);
            let digest = "b".repeat(64);

            let nonempty = work.join("nonempty-parent");
            create_private_directory(&nonempty);
            fs::write(nonempty.join("existing.bin"), b"must reject").expect("populate parent");
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nwrite-tree work {}\nexec-derived-tree consumer-state-parent {} {}\n",
                work.display(),
                nonempty.display(),
                digest
            );
            assert!(parse_policy(&policy_text)
                .expect_err("reject nonempty parent")
                .contains("must be empty"));

            let broad = work.join("broad-parent");
            fs::create_dir(&broad).expect("create broad parent");
            fs::set_permissions(&broad, fs::Permissions::from_mode(0o755))
                .expect("set broad permissions");
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nwrite-tree work {}\nexec-derived-tree consumer-state-parent {} {}\n",
                work.display(),
                broad.display(),
                digest
            );
            assert!(parse_policy(&policy_text)
                .expect_err("reject broad parent mode")
                .contains("mode 0700"));

            let outside = root.join("outside-parent");
            create_private_directory(&outside);
            let policy_text = format!(
                "consumer-policy-v1\nexec /bin/true\nwrite-tree work {}\nexec-derived-tree consumer-state-parent {} {}\n",
                work.display(),
                outside.display(),
                digest
            );
            assert!(parse_policy(&policy_text)
                .expect_err("reject parent outside declared write-tree")
                .contains("strict descendant"));
            fs::remove_dir_all(root).expect("remove private test directory");
        }
    }
}

fn create_new_private(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = create_new_private(path)?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn now_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn json(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            character if character <= '\u{1f}' => {
                result.push_str(&format!("\\u{:04x}", character as u32))
            }
            character => result.push(character),
        }
    }
    result.push('"');
    result
}

fn validate_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid SHA-256 {hash:?}"));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("open for SHA-256 {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read for SHA-256 {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    total_bytes: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            total_bytes: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(input.len() as u64);
        if self.buffered > 0 {
            let copied = (64 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + copied].copy_from_slice(&input[..copied]);
            self.buffered += copied;
            input = &input[copied..];
            if self.buffered == 64 {
                Self::compress(&mut self.state, &self.buffer);
                self.buffered = 0;
            }
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().expect("64-byte block");
            Self::compress(&mut self.state, block);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffered = input.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.total_bytes.wrapping_mul(8);
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            Self::compress(&mut self.state, &self.buffer);
            self.buffer = [0; 64];
        } else {
            self.buffer[self.buffered..56].fill(0);
        }
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        Self::compress(&mut self.state, &self.buffer);
        let mut digest = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, bytes) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().expect("four bytes"));
        }
        for index in 16..64 {
            let x = words[index - 15];
            let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            let y = words[index - 2];
            let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::{hex, Sha256};

    #[test]
    fn sha256_streaming_known_vectors() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        assert_eq!(
            hex(&hasher.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let mut split = Sha256::new();
        split.update(b"a");
        split.update(b"bc");
        assert_eq!(
            hex(&split.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let mut multi_block = Sha256::new();
        multi_block.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex(&multi_block.finalize()),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}

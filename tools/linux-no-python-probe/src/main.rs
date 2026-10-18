// SPDX-License-Identifier: MIT OR Apache-2.0
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    linux::entry();
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("linux-no-python-probe: native Linux x86-64 execution is required");
    std::process::exit(2);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::collections::BTreeMap;
    use std::env;
    use std::ffi::CString;
    use std::fmt::Write as FmtWrite;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{self, Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc::{self, Sender};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const SCHEMA: &str = "ami-rust-linux-no-python-probe-v1";
    const DIRECT_MARKER: &str = "RC0_LINUX_NO_PYTHON_DIRECT_MARKER";
    const DESCENDANT_MARKER: &str = "RC0_LINUX_NO_PYTHON_DESCENDANT_MARKER";
    const SHEBANG_MARKER: &str = "RC0_LINUX_NO_PYTHON_SHEBANG_MARKER";
    const EMBEDDED_MARKER: &str = "RC0_LINUX_NO_PYTHON_EMBEDDED_MARKER";
    const LOADER_MARKER: &str = "RC0_LINUX_NO_PYTHON_LOADER_MARKER";
    const MAX_OUTPUT: usize = 64 * 1024;
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
    const DRAIN_GRACE: Duration = Duration::from_secs(2);
    const EACCES: i32 = 13;
    const SIGKILL: i32 = 9;

    const SYS_SECCOMP: isize = 317;
    const SYS_MEMFD_CREATE: isize = 319;
    const SYS_EXECVEAT: isize = 322;
    const SYS_LANDLOCK_CREATE_RULESET: isize = 444;
    const SYS_LANDLOCK_ADD_RULE: isize = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: isize = 446;

    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    const SECCOMP_SET_MODE_FILTER: u32 = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JSET_K: u16 = 0x45;
    const BPF_RET_K: u16 = 0x06;
    const O_PATH: i32 = 0x0020_0000;
    const O_CLOEXEC: i32 = 0x0008_0000;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const MFD_CLOEXEC: u32 = 1;

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
        fn open(path: *const i8, flags: i32, ...) -> i32;
        fn close(fd: i32) -> i32;
        fn kill(pid: i32, signal: i32) -> i32;
    }

    struct Capture {
        exit_code: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        launch_error: Option<String>,
        launch_errno: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        stdout_total: u64,
        stderr_total: u64,
        stdout_complete: bool,
        stderr_complete: bool,
        stdout_read_error: Option<String>,
        stderr_read_error: Option<String>,
        duration_ms: u128,
    }

    impl Capture {
        fn launch(error: io::Error) -> Self {
            Self {
                exit_code: None,
                signal: None,
                timed_out: false,
                launch_error: Some(error.to_string()),
                launch_errno: error.raw_os_error(),
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_total: 0,
                stderr_total: 0,
                stdout_complete: true,
                stderr_complete: true,
                stdout_read_error: None,
                stderr_read_error: None,
                duration_ms: 0,
            }
        }

        fn success(&self) -> bool {
            !self.timed_out && self.launch_error.is_none() && self.exit_code == Some(0)
        }

        fn stdout_text(&self) -> String {
            String::from_utf8_lossy(&self.stdout).into_owned()
        }

        fn stderr_text(&self) -> String {
            String::from_utf8_lossy(&self.stderr).into_owned()
        }
    }

    struct Record {
        name: String,
        argv: Vec<String>,
        capture: Capture,
    }

    struct Component {
        path: String,
        sha256: String,
        role: String,
        executable_allowed: bool,
        readable_allowed: bool,
    }

    #[derive(Clone)]
    struct ReadDone {
        stdout: bool,
        bytes: Vec<u8>,
        total: u64,
        error: Option<String>,
    }

    struct Report {
        distro: String,
        kernel: String,
        report_path: PathBuf,
        fixture_dir: Option<PathBuf>,
        python_path: Option<String>,
        python_origin: Option<String>,
        python_version: Option<String>,
        python_sha256: Option<String>,
        python_version_record: Option<Record>,
        python_config_record: Option<Record>,
        setup_records: Vec<Record>,
        landlock_abi: Option<i32>,
        landlock_error: Option<String>,
        components: BTreeMap<String, Component>,
        read_closure: Vec<String>,
        loader_path: Option<String>,
        libpython_path: Option<String>,
        libpython_sha256: Option<String>,
        cases: Vec<String>,
        case_results: Vec<(String, bool)>,
        errors: Vec<String>,
    }

    impl Report {
        fn new(report_path: PathBuf) -> Self {
            let distro = parse_os_release().unwrap_or_else(|error| format!("unavailable: {error}"));
            let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|error| format!("unavailable: {error}"))
                .trim()
                .to_owned();
            Self {
                distro,
                kernel,
                report_path,
                fixture_dir: None,
                python_path: None,
                python_origin: None,
                python_version: None,
                python_sha256: None,
                python_version_record: None,
                python_config_record: None,
                setup_records: Vec::new(),
                landlock_abi: None,
                landlock_error: None,
                components: BTreeMap::new(),
                read_closure: Vec::new(),
                loader_path: None,
                libpython_path: None,
                libpython_sha256: None,
                cases: Vec::new(),
                case_results: Vec::new(),
                errors: Vec::new(),
            }
        }

        fn passed(&self) -> bool {
            self.errors.is_empty()
                && self.landlock_abi.is_some()
                && self.case_results.iter().all(|(_, pass)| *pass)
                && [
                    "positive_control_direct_python",
                    "positive_control_descendant_python",
                    "positive_control_absolute_shebang",
                    "positive_control_dynamic_embedding",
                    "positive_native_allowlisted",
                    "direct_python_denied",
                    "descendant_python_denied",
                    "absolute_shebang_denied",
                    "allowed_binary_dynamic_embedding_denied",
                    "dynamic_loader_python_denied",
                    "execveat_empty_path_denied",
                    "memfd_create_denied",
                ]
                .iter()
                .all(|required| {
                    self.case_results
                        .iter()
                        .any(|(name, pass)| name == required && *pass)
                })
        }

        fn add_component(
            &mut self,
            path: &Path,
            role: &str,
            executable_allowed: bool,
            readable_allowed: bool,
        ) -> Result<(), String> {
            let canonical = fs::canonicalize(path)
                .map_err(|error| format!("canonicalize component {}: {error}", path.display()))?;
            let key = path_string(&canonical)?;
            let digest = sha256_path(&canonical)?;
            self.components
                .entry(key.clone())
                .and_modify(|item| {
                    item.executable_allowed |= executable_allowed;
                    item.readable_allowed |= readable_allowed;
                    if !item.role.contains(role) {
                        item.role.push_str("; ");
                        item.role.push_str(role);
                    }
                })
                .or_insert(Component {
                    path: key,
                    sha256: digest,
                    role: role.to_owned(),
                    executable_allowed,
                    readable_allowed,
                });
            Ok(())
        }

        fn verify_components(&self, phase: &str) -> Result<(), String> {
            for component in self.components.values() {
                let current = sha256_path(Path::new(&component.path))?;
                if current != component.sha256 {
                    return Err(format!(
                        "component changed {phase}: {} expected {}, observed {current}",
                        component.path, component.sha256
                    ));
                }
            }
            Ok(())
        }

        fn json(&self) -> String {
            let mut out = String::new();
            let library_excluded = self
                .components
                .values()
                .find(|item| item.role.contains("runner-installed libpython"))
                .map(|item| !item.executable_allowed && !item.readable_allowed)
                .unwrap_or(false);
            let embedded_fixture = self
                .components
                .values()
                .find(|item| item.role.contains("dynamic embedding fixture"));
            let embedded_denial_observed = self
                .case_results
                .iter()
                .find(|(name, _)| name == "allowed_binary_dynamic_embedding_denied")
                .map(|(_, passed)| *passed)
                .unwrap_or(false);
            let _ = writeln!(out, "{{");
            let _ = writeln!(out, "  \"schema\": {},", json_string(SCHEMA));
            let _ = writeln!(
                out,
                "  \"overall\": {},",
                json_string(if self.passed() { "PASS" } else { "FAIL" })
            );
            let _ = writeln!(out, "  \"host\": {{\"os\": \"linux\", \"distribution\": {}, \"kernel_release\": {}, \"architecture\": \"x86_64\"}},", json_string(&self.distro), json_string(&self.kernel));
            let _ = writeln!(out, "  \"claim_scope\": \"Ubuntu 24.04 x86-64 detector controls only; no full production source/dependency closure claim\",");
            let _ = writeln!(out, "  \"policy\": {{");
            let _ = writeln!(out, "    \"mechanism\": \"Landlock exact-file EXECUTE and READ_FILE rules plus PR_SET_NO_NEW_PRIVS, then seccomp-BPF blocking execveat, memfd_create, and x32 syscall numbers\",");
            let _ = writeln!(
                out,
                "    \"landlock_abi\": {},",
                self.landlock_abi
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_owned())
            );
            let _ = writeln!(
                out,
                "    \"landlock_error\": {},",
                opt_string(self.landlock_error.as_deref())
            );
            let _ = writeln!(out, "    \"no_new_privs\": true,");
            let _ = writeln!(out, "    \"handled_landlock_access\": [\"LANDLOCK_ACCESS_FS_EXECUTE\", \"LANDLOCK_ACCESS_FS_READ_FILE\"],");
            let _ = writeln!(out, "    \"seccomp_filter_tsync\": true,");
            let _ = writeln!(out, "    \"seccomp_errno\": \"EACCES (13)\",");
            let _ = writeln!(out, "    \"failure_policy\": \"fail closed; no negative case runs without both enforcement layers\",");
            let _ = writeln!(out, "    \"allowed_executables\": [");
            let exec = self
                .components
                .values()
                .filter(|item| item.executable_allowed)
                .collect::<Vec<_>>();
            for (index, item) in exec.iter().enumerate() {
                let comma = if index + 1 == exec.len() { "" } else { "," };
                let _ = writeln!(
                    out,
                    "      {{\"path\":{},\"sha256\":{},\"role\":{}}}{}",
                    json_string(&item.path),
                    json_string(&item.sha256),
                    json_string(&item.role),
                    comma
                );
            }
            let _ = writeln!(out, "    ],");
            let _ = writeln!(out, "    \"readable_files\": [");
            let readable = self
                .components
                .values()
                .filter(|item| item.readable_allowed)
                .collect::<Vec<_>>();
            for (index, item) in readable.iter().enumerate() {
                let comma = if index + 1 == readable.len() { "" } else { "," };
                let _ = writeln!(
                    out,
                    "      {{\"path\":{},\"sha256\":{},\"role\":{}}}{}",
                    json_string(&item.path),
                    json_string(&item.sha256),
                    json_string(&item.role),
                    comma
                );
            }
            let _ = writeln!(out, "    ],");
            let _ = writeln!(
                out,
                "    \"read_closure_paths\": [{}],",
                self.read_closure
                    .iter()
                    .map(|p| json_string(p))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let _ = writeln!(
                out,
                "    \"libpython_excluded_from_read_and_execute\": {library_excluded}"
            );
            let _ = writeln!(out, "  }},");
            let _ = writeln!(out, "  \"python_control\": {{\"path\": {}, \"version\": {}, \"sha256\": {}, \"origin\": {}, \"supported_no_python_path\": false, \"raw_outcome\": {}}},", opt_string(self.python_path.as_deref()), opt_string(self.python_version.as_deref()), opt_string(self.python_sha256.as_deref()), opt_string(self.python_origin.as_deref()), self.python_version_record.as_ref().map(record_json).unwrap_or_else(|| "null".to_owned()));
            let source = self
                .components
                .values()
                .find(|item| item.role.contains("dynamic embedding source"));
            let _ = writeln!(out, "  \"embedded_control\": {{\"source_path\": {}, \"binary_path\": {}, \"binary_sha256\": {}, \"dynamic_python_library_path\": {}, \"dynamic_python_library_sha256\": {}, \"python_library_config_raw_outcome\": {}, \"fixture_executable_is_allowlisted\": {}, \"libpython_denial_observed\": {}}},", source.map(|v| json_string(&v.path)).unwrap_or_else(|| "null".to_owned()), embedded_fixture.map(|v| json_string(&v.path)).unwrap_or_else(|| "null".to_owned()), embedded_fixture.map(|v| json_string(&v.sha256)).unwrap_or_else(|| "null".to_owned()), opt_string(self.libpython_path.as_deref()), opt_string(self.libpython_sha256.as_deref()), self.python_config_record.as_ref().map(record_json).unwrap_or_else(|| "null".to_owned()), embedded_fixture.map(|v| v.executable_allowed).unwrap_or(false), embedded_denial_observed);
            let _ = writeln!(
                out,
                "  \"fixture_directory\": {},",
                self.fixture_dir
                    .as_ref()
                    .map(|p| path_string(p).map(|s| json_string(&s)))
                    .transpose()
                    .unwrap_or(None)
                    .unwrap_or_else(|| "null".to_owned())
            );
            let _ = writeln!(out, "  \"bounded_execution\": {{\"per_command_timeout_seconds\": 20, \"capture_limit_bytes_per_stream\": {}, \"timeout_kills_process_group\": true}},", MAX_OUTPUT);
            let _ = writeln!(out, "  \"setup_commands\": [");
            for (index, record) in self.setup_records.iter().enumerate() {
                let comma = if index + 1 == self.setup_records.len() {
                    ""
                } else {
                    ","
                };
                let _ = writeln!(out, "    {}{}", record_json(record), comma);
            }
            let _ = writeln!(out, "  ],");
            let _ = writeln!(out, "  \"components\": [");
            let components = self.components.values().collect::<Vec<_>>();
            for (index, component) in components.iter().enumerate() {
                let comma = if index + 1 == components.len() {
                    ""
                } else {
                    ","
                };
                let _ = writeln!(out, "    {{\"path\":{},\"sha256\":{},\"role\":{},\"executable_allowed\":{},\"readable_allowed\":{}}}{}", json_string(&component.path), json_string(&component.sha256), json_string(&component.role), component.executable_allowed, component.readable_allowed, comma);
            }
            let _ = writeln!(out, "  ],");
            let _ = writeln!(out, "  \"cases\": [");
            for (index, case) in self.cases.iter().enumerate() {
                let comma = if index + 1 == self.cases.len() {
                    ""
                } else {
                    ","
                };
                let _ = writeln!(out, "    {}{}", case, comma);
            }
            let _ = writeln!(out, "  ],");
            let _ = writeln!(
                out,
                "  \"errors\": [{}],",
                self.errors
                    .iter()
                    .map(|v| json_string(v))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let _ = writeln!(out, "  \"limitations\": [\"This probe enforces only the named filesystem rights and syscall routes; it does not restrict network access or all system calls.\", \"Named controls observe their own raw failures and markers; arbitrary code can hide attempts, so there is no independent audit stream for all exec or library-load attempts.\", \"An executable can still statically embed or implement Python; production acceptance needs reviewed source/build/dependency closure and provenance.\", \"The runtime read closure covers only the ELF files required by these fixtures, not a production closure.\", \"Hashes do not prevent same-user replacement of trusted inputs during a run.\", \"No Linux PASS is claimed by compiling this crate on macOS.\"],");
            let _ = writeln!(
                out,
                "  \"report_path\": {}",
                json_string(&self.report_path.display().to_string())
            );
            let _ = writeln!(out, "}}");
            out
        }
    }

    pub fn entry() {
        let args = env::args().skip(1).collect::<Vec<_>>();
        let code = match args.first().map(String::as_str) {
            Some("--self-test") => match self_test(&args[1..]) {
                Ok(true) => 0,
                Ok(false) => 1,
                Err(error) => {
                    eprintln!("linux-no-python-probe: {error}");
                    2
                }
            },
            Some("--sandbox-case") => sandbox_case(&args[1..]),
            Some("--control-child") => control_child(&args[1..]),
            _ => {
                eprintln!(
                    "usage: linux-no-python-probe --self-test --output /absolute/output/directory"
                );
                2
            }
        };
        process::exit(code);
    }

    fn self_test(args: &[String]) -> Result<bool, String> {
        let output_arg = option_value(args, "--output")
            .ok_or_else(|| "--self-test requires --output /absolute/output/directory".to_owned())?;
        let output_dir = PathBuf::from(output_arg);
        if !output_dir.is_absolute() {
            return Err(format!(
                "--output must be absolute: {}",
                output_dir.display()
            ));
        }
        fs::create_dir_all(&output_dir).map_err(|error| {
            format!("create output directory {}: {error}", output_dir.display())
        })?;
        let report_path = output_dir.join(format!("linux-no-python-{}.json", unique_suffix()));
        let mut report = Report::new(report_path);
        if !report.distro.contains("ID=ubuntu") || !report.distro.contains("VERSION_ID=\"24.04\"") {
            report.errors.push(format!(
                "unsupported host: expected Ubuntu 24.04 x86-64; observed {}",
                report.distro
            ));
            return write_report(report);
        }

        let python_requested = match option_value(args, "--python") {
            Some(value) => PathBuf::from(value),
            None => resolve_program("python3")?,
        };
        report.python_origin = Some(if option_value(args, "--python").is_some() {
            "caller-supplied --python path; path and SHA-256 observed at runtime, not authenticated by the probe".to_owned()
        } else {
            "resolved from runner PATH at runtime; not an authenticated pin".to_owned()
        });
        if !python_requested.is_absolute() {
            return Err(format!(
                "Python detector control must be an absolute path: {}",
                python_requested.display()
            ));
        }
        let python = fs::canonicalize(&python_requested).map_err(|error| {
            format!(
                "resolve Python detector control {}: {error}",
                python_requested.display()
            )
        })?;
        ensure_executable(&python)?;
        let python_s = path_string(&python)?;
        report.python_path = Some(python_s.clone());

        let fixture_dir = create_fixture_dir(&output_dir)?;
        report.fixture_dir = Some(fixture_dir.clone());
        let probe = fs::canonicalize(
            env::current_exe().map_err(|error| format!("resolve current executable: {error}"))?,
        )
        .map_err(|error| format!("canonicalize current executable: {error}"))?;
        let true_path = fs::canonicalize("/usr/bin/true")
            .map_err(|error| format!("resolve /usr/bin/true: {error}"))?;
        ensure_executable(&true_path)?;

        // Positive Python routes run first and are recorded as isolated detector controls.
        let py_record = run_record("positive_control_direct_python", &python, &["-I", "-S", "-c", &format!("import sys; print('{DIRECT_MARKER}'); print('PYTHON_VERSION=' + sys.version.split()[0]); print('PYTHON_IMPLEMENTATION=' + sys.implementation.name)")], true, true);
        report.python_version = extract_prefix(&py_record.capture.stdout_text(), "PYTHON_VERSION=");
        report.python_sha256 = Some(sha256_path(&python)?);
        let py_pass = py_record.capture.success()
            && py_record.capture.stdout_text().contains(DIRECT_MARKER)
            && report.python_version.is_some();
        let py_case_record = record_clone(&py_record);
        report.python_version_record = Some(py_record);
        push_case_owned(
            &mut report,
            "positive_control_direct_python",
            "exit 0, distinct marker, observed Python version",
            py_case_record,
            py_pass,
            &["exit_code=0", "direct_marker_present", "version_observed"],
        );

        let descendant_record = run_record(
            "positive_control_descendant_python",
            &probe,
            &[
                "--control-child",
                "--python",
                &python_s,
                "--positive",
                "--marker",
                DESCENDANT_MARKER,
            ],
            true,
            true,
        );
        let descendant_pass = descendant_record.capture.exit_code == Some(92)
            && descendant_record
                .capture
                .stdout_text()
                .contains(DESCENDANT_MARKER)
            && descendant_record
                .capture
                .stdout_text()
                .contains(DIRECT_MARKER);
        push_case_owned(
            &mut report,
            "positive_control_descendant_python",
            "owned child starts absolute-path Python and returns control exit 92",
            descendant_record,
            descendant_pass,
            &[
                "control_exit_code=92",
                "descendant_marker_present",
                "direct_marker_present",
            ],
        );

        let script_path = fixture_dir.join("python-shebang-control");
        let script = format!("#!{} -I\nimport sys\nprint('{SHEBANG_MARKER}')\nprint('PYTHON_VERSION=' + sys.version.split()[0])\n", python.display());
        fs::write(&script_path, script.as_bytes())
            .map_err(|error| format!("write shebang fixture: {error}"))?;
        let mut permissions = fs::metadata(&script_path)
            .map_err(|error| error.to_string())?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions)
            .map_err(|error| format!("chmod shebang fixture: {error}"))?;
        let script_path = fs::canonicalize(&script_path)
            .map_err(|error| format!("canonicalize shebang fixture: {error}"))?;
        let script_record = run_record(
            "positive_control_absolute_shebang",
            &script_path,
            &[],
            true,
            true,
        );
        let script_pass = script_record.capture.success()
            && script_record.capture.stdout_text().contains(SHEBANG_MARKER);
        push_case_owned(
            &mut report,
            "positive_control_absolute_shebang",
            "absolute shebang starts Python and emits its marker",
            script_record,
            script_pass,
            &["exit_code=0", "shebang_marker_present"],
        );

        let config_script = "import sys,sysconfig; print('\\t'.join([sys.version.split()[0], str(sysconfig.get_config_var('LIBDIR') or ''), str(sysconfig.get_config_var('LDLIBRARY') or ''), str(sysconfig.get_config_var('INSTSONAME') or '')]))";
        let config_record = run_record(
            "inspect_python_shared_library_identity",
            &python,
            &["-I", "-S", "-c", config_script],
            true,
            true,
        );
        let config_pass = config_record.capture.success();
        report.python_config_record = Some(config_record);
        if !config_pass {
            report.errors.push(
                "could not read Python sysconfig for the dynamic embedding fixture".to_owned(),
            );
            push_not_run(
                &mut report,
                "positive_control_dynamic_embedding",
                "Python sysconfig failed",
            );
            return write_report(report);
        }
        let config_fields = report
            .python_config_record
            .as_ref()
            .unwrap()
            .capture
            .stdout_text()
            .trim()
            .split('\t')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if config_fields.len() != 4
            || report.python_version.as_deref() != config_fields.first().map(String::as_str)
        {
            report.errors.push(format!(
                "Python sysconfig output is incomplete or version-mismatched: {:?}",
                config_fields
            ));
            push_not_run(
                &mut report,
                "positive_control_dynamic_embedding",
                "Python sysconfig output invalid",
            );
            return write_report(report);
        }
        let libdir = PathBuf::from(&config_fields[1]);
        let library_candidate = [&config_fields[2], &config_fields[3]]
            .into_iter()
            .map(|name| libdir.join(name))
            .find(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.starts_with("libpython") && name.contains(".so"))
                        .unwrap_or(false)
            });
        let Some(library_candidate) = library_candidate else {
            report.errors.push(format!(
                "runner Python has no dynamic libpython suitable for dlopen at {} or {}",
                config_fields[2], config_fields[3]
            ));
            push_not_run(
                &mut report,
                "positive_control_dynamic_embedding",
                "dynamic libpython is unavailable",
            );
            return write_report(report);
        };
        let libpython = fs::canonicalize(&library_candidate).map_err(|error| {
            format!(
                "resolve Python shared library {}: {error}",
                library_candidate.display()
            )
        })?;
        report.libpython_path = Some(path_string(&libpython)?);
        report.libpython_sha256 = Some(sha256_path(&libpython)?);

        let compiler = resolve_program("cc")?;
        let readelf = resolve_program("readelf")?;
        let ldd = resolve_program("ldd")?;
        let source_path = fixture_dir.join("embedded-python-control.c");
        let embedded_path = fixture_dir.join("embedded-python-control");
        let source = format!(
            r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
typedef void (*py_init_fn)(void);
typedef int (*py_run_fn)(const char *);
typedef int (*py_fini_fn)(void);
int main(int argc, char **argv) {{
  if (argc != 2) return 80;
  errno = 0;
  void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (library == NULL) {{ fprintf(stderr, "DLOPEN_DENIED errno=%d message=%s\n", errno, dlerror()); return 82; }}
  py_init_fn initialize = (py_init_fn)dlsym(library, "Py_Initialize");
  py_run_fn run = (py_run_fn)dlsym(library, "PyRun_SimpleString");
  py_fini_fn finalize = (py_fini_fn)dlsym(library, "Py_FinalizeEx");
  if (initialize == NULL || run == NULL || finalize == NULL) return 83;
  initialize();
  if (run("print('{EMBEDDED_MARKER}')") != 0) return 84;
  return finalize();
}}
"#
        );
        fs::write(&source_path, source.as_bytes())
            .map_err(|error| format!("write embedding control source: {error}"))?;
        let compile_record = run_record(
            "compile_dynamic_embedding_fixture",
            &compiler,
            &[
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                &path_string(&source_path)?,
                "-ldl",
                "-o",
                &path_string(&embedded_path)?,
            ],
            false,
            true,
        );
        let compile_pass = compile_record.capture.success();
        report.setup_records.push(compile_record);
        if !compile_pass {
            report
                .errors
                .push("C compiler failed to build the dlopen embedding fixture".to_owned());
            push_not_run(
                &mut report,
                "positive_control_dynamic_embedding",
                "fixture compilation failed",
            );
            return write_report(report);
        }
        ensure_executable(&embedded_path)?;
        let embedded_path = fs::canonicalize(&embedded_path)
            .map_err(|error| format!("canonicalize embedding fixture: {error}"))?;

        let readelf_record = run_record(
            "inspect_embedding_fixture_dynamic_tags",
            &readelf,
            &["-d", &path_string(&embedded_path)?],
            true,
            true,
        );
        let readelf_text = readelf_record.capture.stdout_text();
        let readelf_pass = readelf_record.capture.success() && !readelf_text.contains("libpython");
        report.setup_records.push(readelf_record);
        if !readelf_pass {
            report.errors.push("embedding fixture has a libpython DT_NEEDED dependency; expected runtime dlopen only".to_owned());
            push_not_run(
                &mut report,
                "positive_control_dynamic_embedding",
                "fixture dynamic dependency shape invalid",
            );
            return write_report(report);
        }

        let mut ldd_records = Vec::new();
        let mut runtime_files = BTreeMap::<String, PathBuf>::new();
        let mut loader_path = None;
        for (name, binary) in [
            ("probe", probe.as_path()),
            ("true", true_path.as_path()),
            ("embedding_fixture", embedded_path.as_path()),
        ] {
            let record = run_record(
                "inspect_elf_runtime_closure",
                &ldd,
                &[&path_string(binary)?],
                false,
                true,
            );
            let output = record.capture.stdout_text();
            if !record.capture.success() || output.contains("not found") {
                let why = format!(
                    "ldd failed or reported a missing runtime dependency for {name}: {}",
                    record.capture.stderr_text()
                );
                report.setup_records.push(record);
                report.errors.push(why);
                push_not_run(
                    &mut report,
                    "positive_control_dynamic_embedding",
                    "ELF runtime closure unavailable",
                );
                return write_report(report);
            }
            for path in parse_ldd_paths(&output) {
                let canonical = fs::canonicalize(&path)
                    .map_err(|error| format!("resolve ldd path {}: {error}", path.display()))?;
                let text = path_string(&canonical)?;
                if text.contains("ld-linux") || text.contains("ld64") || text.contains("ld.so") {
                    loader_path = Some(canonical.clone());
                }
                runtime_files.insert(text, canonical);
            }
            ldd_records.push(record);
        }
        report.setup_records.extend(ldd_records);
        let Some(loader) = loader_path else {
            report
                .errors
                .push("ldd did not identify the ELF dynamic loader".to_owned());
            push_not_run(
                &mut report,
                "positive_control_dynamic_embedding",
                "ELF loader unavailable",
            );
            return write_report(report);
        };
        report.loader_path = Some(path_string(&loader)?);

        let embedded_binary_arg = path_string(&embedded_path)?;
        let ldd_fixture = report.setup_records.iter().rev().find(|item| {
            item.name == "inspect_elf_runtime_closure"
                && item.argv.last().map(String::as_str) == Some(embedded_binary_arg.as_str())
        });
        if ldd_fixture
            .map(|item| item.capture.stdout_text().contains("libpython"))
            .unwrap_or(true)
        {
            report.errors.push(
                "ldd reports libpython as a startup dependency of the embedding fixture".to_owned(),
            );
            push_not_run(
                &mut report,
                "positive_control_dynamic_embedding",
                "fixture unexpectedly loads Python before dlopen",
            );
            return write_report(report);
        }

        let embedded_positive = run_record(
            "positive_control_dynamic_embedding",
            &embedded_path,
            &[&path_string(&libpython)?],
            true,
            true,
        );
        let embedded_pass = embedded_positive.capture.success()
            && embedded_positive
                .capture
                .stdout_text()
                .contains(EMBEDDED_MARKER);
        push_case_owned(&mut report, "positive_control_dynamic_embedding", "allowlisted C fixture loads observed libpython with dlopen and emits marker outside policy", embedded_positive, embedded_pass, &["exit_code=0", "embedded_marker_present", "dlopen_libpython_succeeded"]);

        let empty_preload_file = match fs::read_to_string("/etc/ld.so.preload") {
            Ok(preload) => {
                if !preload.trim().is_empty() {
                    report.errors.push("/etc/ld.so.preload is nonempty; a process could load libpython before Landlock policy setup".to_owned());
                    return write_report(report);
                }
                Some(
                    fs::canonicalize("/etc/ld.so.preload")
                        .map_err(|error| format!("resolve empty ld.so.preload: {error}"))?,
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                report
                    .errors
                    .push(format!("cannot inspect /etc/ld.so.preload: {error}"));
                return write_report(report);
            }
        };

        // Assemble an exact read closure for the three allowed ELF objects.
        // Python itself and the dlopen-only libpython are intentionally absent.
        if Path::new("/etc/ld.so.cache").is_file() {
            let path = fs::canonicalize("/etc/ld.so.cache")
                .map_err(|error| format!("resolve ld.so cache: {error}"))?;
            runtime_files.insert(path_string(&path)?, path);
        }
        if let Some(path) = empty_preload_file {
            runtime_files.insert(path_string(&path)?, path);
        }
        for (key, path) in runtime_files {
            if path == libpython {
                report.errors.push("libpython appeared in the ordinary ELF read closure and cannot be denied independently".to_owned());
                return write_report(report);
            }
            report.read_closure.push(key);
            report.add_component(&path, "closed ELF runtime read dependency", false, true)?;
        }
        report.read_closure.sort();
        report.add_component(
            &probe,
            "probe executable; allowed for descendants",
            true,
            true,
        )?;
        report.add_component(&true_path, "ordinary native positive; allowed", true, true)?;
        report.add_component(
            &script_path,
            "absolute Python shebang file; script allowed, interpreter excluded",
            true,
            true,
        )?;
        report.add_component(
            &embedded_path,
            "dynamic embedding fixture; executable is allowed, dlopen library is excluded",
            true,
            true,
        )?;
        report.add_component(
            &loader,
            "ELF dynamic loader; allowed for reviewed runtime files",
            true,
            true,
        )?;
        report.add_component(
            &python,
            "runner-installed Python positive control; excluded",
            false,
            false,
        )?;
        report.add_component(
            &libpython,
            "runner-installed libpython for dlopen control; excluded from read/execute closure",
            false,
            false,
        )?;
        report.add_component(
            &source_path,
            "dynamic embedding source fixture",
            false,
            false,
        )?;
        report.add_component(&compiler, "C compiler; setup only", false, false)?;
        report.add_component(
            &readelf,
            "ELF dynamic-tag inspector; setup only",
            false,
            false,
        )?;
        report.add_component(&ldd, "ELF dependency resolver; setup only", false, false)?;
        report.verify_components("after positive controls and policy inputs")?;

        match query_landlock_abi() {
            Ok(abi) if abi >= 1 => report.landlock_abi = Some(abi),
            Ok(abi) => {
                report.landlock_error = Some(format!("invalid ABI value {abi}"));
                report.errors.push(format!(
                    "Landlock ABI {abi} unsupported; negative cases were not run"
                ));
                add_not_run_policy_cases(&mut report);
                return write_report(report);
            }
            Err(error) => {
                report.landlock_error = Some(error.clone());
                report.errors.push(format!(
                    "Landlock unavailable; negative cases were not run: {error}"
                ));
                add_not_run_policy_cases(&mut report);
                return write_report(report);
            }
        }

        let mut exec_allow = vec![
            probe.clone(),
            true_path.clone(),
            script_path.clone(),
            embedded_path.clone(),
            loader.clone(),
        ];
        exec_allow.sort();
        exec_allow.dedup();
        let read_allow = report
            .read_closure
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let inputs = SandboxInputs {
            executable: probe.clone(),
            allow_exec: exec_allow,
            allow_read: read_allow,
            python: python.clone(),
            script: script_path,
            embedded: embedded_path,
            true_path,
            loader,
            libpython,
        };
        for (name, mode) in [
            ("positive_native_allowlisted", "native"),
            ("execveat_empty_path_denied", "execveat"),
            ("memfd_create_denied", "memfd"),
            ("direct_python_denied", "direct"),
            ("descendant_python_denied", "descendant"),
            ("absolute_shebang_denied", "shebang"),
            ("allowed_binary_dynamic_embedding_denied", "embedded"),
            ("dynamic_loader_python_denied", "loader"),
        ] {
            if let Err(error) = run_sandbox_case(&mut report, &inputs, name, mode) {
                report.errors.push(error);
                break;
            }
        }
        write_report(report)
    }

    struct SandboxInputs {
        executable: PathBuf,
        allow_exec: Vec<PathBuf>,
        allow_read: Vec<PathBuf>,
        python: PathBuf,
        script: PathBuf,
        embedded: PathBuf,
        true_path: PathBuf,
        loader: PathBuf,
        libpython: PathBuf,
    }

    fn run_sandbox_case(
        report: &mut Report,
        inputs: &SandboxInputs,
        name: &str,
        mode: &str,
    ) -> Result<(), String> {
        report.verify_components(&format!("before {name}"))?;
        let mut args = vec!["--sandbox-case".to_owned(), mode.to_owned()];
        for path in &inputs.allow_exec {
            args.extend(["--allow-exec".to_owned(), path_string(path)?]);
        }
        for path in &inputs.allow_read {
            args.extend(["--allow-read".to_owned(), path_string(path)?]);
        }
        args.extend([
            "--python".to_owned(),
            path_string(&inputs.python)?,
            "--script".to_owned(),
            path_string(&inputs.script)?,
            "--embedded".to_owned(),
            path_string(&inputs.embedded)?,
            "--true".to_owned(),
            path_string(&inputs.true_path)?,
            "--loader".to_owned(),
            path_string(&inputs.loader)?,
            "--libpython".to_owned(),
            path_string(&inputs.libpython)?,
        ]);
        let record = run_record_owned(name, &inputs.executable, &args, true, true);
        let stdout = record.capture.stdout_text();
        let stderr = record.capture.stderr_text();
        let all_output = format!("{stdout}\n{stderr}");
        let (expected, passed, checks): (String, bool, Vec<&str>) = match mode {
            "native" => (
                "exit 0 after Landlock and seccomp are installed, executing allowlisted true".to_owned(),
                record.capture.exit_code == Some(0) && stdout.contains("POLICY_READY") && stdout.contains("NATIVE_TARGET_EXIT=0"),
                vec!["exit_code=0", "policy_ready", "native_target_exit_0"],
            ),
            "execveat" => (
                "exit 79 after seccomp returns EACCES for execveat(AT_EMPTY_PATH) targeting allowlisted true".to_owned(),
                record.capture.exit_code == Some(79) && stdout.contains("EXECVEAT_DENIED errno=13"),
                vec!["control_exit_code=79", "errno_EACCES", "target_true_is_allowlisted"],
            ),
            "memfd" => (
                "exit 80 after seccomp returns EACCES for memfd_create".to_owned(),
                record.capture.exit_code == Some(80) && stdout.contains("MEMFD_DENIED errno=13"),
                vec!["control_exit_code=80", "errno_EACCES"],
            ),
            "direct" => (
                "exit 77 after direct absolute-path Python exec returns raw EACCES; no marker".to_owned(),
                record.capture.exit_code == Some(77) && stdout.contains("DIRECT_DENIED errno=13") && !all_output.contains(DIRECT_MARKER),
                vec!["control_exit_code=77", "errno_EACCES", "marker_absent"],
            ),
            "descendant" => (
                "exit 78 after an allowed descendant inherits the policy and records EACCES; no marker".to_owned(),
                record.capture.exit_code == Some(78) && stdout.contains("DESCENDANT_DENIED") && stdout.contains("DIRECT_DENIED errno=13") && !all_output.contains(DIRECT_MARKER),
                vec!["control_exit_code=78", "descendant_inherited_policy", "errno_EACCES", "marker_absent"],
            ),
            "shebang" => (
                "exit 77 after the allowed absolute-shebang script cannot execute its denied interpreter".to_owned(),
                record.capture.exit_code == Some(77) && stdout.contains("SHEBANG_DENIED errno=13") && !all_output.contains(SHEBANG_MARKER),
                vec!["control_exit_code=77", "errno_EACCES", "shebang_marker_absent"],
            ),
            "embedded" => (
                "allowed C executable reaches dlopen, but Landlock denies reading/executing libpython with EACCES before marker".to_owned(),
                record.capture.exit_code == Some(82) && stdout.contains("EMBEDDED_FIXTURE exit=82") && stderr.contains("DLOPEN_DENIED errno=13") && !all_output.contains(EMBEDDED_MARKER),
                vec!["fixture_exec_allowed", "dlopen_errno_EACCES", "embedded_marker_absent", "libpython_excluded_from_read_execute"],
            ),
            "loader" => (
                "allowed ELF loader cannot load absolute-path Python because its file is outside read/execute closure".to_owned(),
                stdout.contains("DYNAMIC_LOADER_PYTHON_DENIED") && !all_output.contains(LOADER_MARKER),
                vec!["loader_exec_allowed", "python_read_denied", "loader_marker_absent"],
            ),
            _ => return Err(format!("unknown sandbox case mode {mode}")),
        };
        push_case_owned(report, name, &expected, record, passed, &checks);
        report.verify_components(&format!("after {name}"))?;
        Ok(())
    }

    fn sandbox_case(args: &[String]) -> i32 {
        let mode = args.first().map(String::as_str).unwrap_or_default();
        let exec_paths = option_values(args, "--allow-exec")
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let read_paths = option_values(args, "--allow-read")
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let required = [
            "--python",
            "--script",
            "--embedded",
            "--true",
            "--loader",
            "--libpython",
        ];
        if exec_paths.is_empty() || required.iter().any(|key| option_value(args, key).is_none()) {
            eprintln!("sandbox child lacks a complete policy manifest");
            return 2;
        }
        let python = PathBuf::from(option_value(args, "--python").unwrap());
        let script = PathBuf::from(option_value(args, "--script").unwrap());
        let embedded = PathBuf::from(option_value(args, "--embedded").unwrap());
        let true_path = PathBuf::from(option_value(args, "--true").unwrap());
        let loader = PathBuf::from(option_value(args, "--loader").unwrap());
        let libpython = PathBuf::from(option_value(args, "--libpython").unwrap());
        let abi = match install_policy(&exec_paths, &read_paths) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("POLICY_SETUP_FAIL={error}");
                return 2;
            }
        };
        println!("POLICY_READY landlock_abi={abi} no_new_privs=1 seccomp_tsync=1 exec_allow_count={} read_allow_count={} libpython_excluded=1", exec_paths.len(), read_paths.len());
        match mode {
            "native" => {
                let result = run_record("allowlisted_true", &true_path, &[], true, false);
                if result.capture.success() {
                    println!("NATIVE_TARGET_EXIT=0");
                    0
                } else {
                    println!(
                        "NATIVE_TARGET_FAIL exit={:?} signal={:?}",
                        result.capture.exit_code, result.capture.signal
                    );
                    3
                }
            }
            "direct" => try_python(&python, "DIRECT"),
            "descendant" => {
                let own = match env::current_exe() {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("current_exe: {error}");
                        return 2;
                    }
                };
                let py = match path_string(&python) {
                    Ok(v) => v,
                    Err(error) => {
                        eprintln!("{error}");
                        return 2;
                    }
                };
                let result = run_record(
                    "descendant_python_attempt",
                    &own,
                    &["--control-child", "--python", &py],
                    true,
                    false,
                );
                let text = result.capture.stdout_text();
                if result.capture.exit_code == Some(77)
                    && text.contains("DIRECT_DENIED errno=13")
                    && !text.contains(DIRECT_MARKER)
                {
                    println!(
                        "DESCENDANT_DENIED child_exit=77 child_stdout_b64={} child_stdout={}",
                        base64(&result.capture.stdout),
                        single_line(&text)
                    );
                    78
                } else {
                    println!(
                        "DESCENDANT_ESCAPE child_exit={:?} child_stdout_b64={} child_stdout={}",
                        result.capture.exit_code,
                        base64(&result.capture.stdout),
                        single_line(&text)
                    );
                    92
                }
            }
            "shebang" => {
                let result = run_record("absolute_shebang_attempt", &script, &[], true, false);
                if result.capture.launch_errno == Some(EACCES) {
                    println!(
                        "SHEBANG_DENIED errno=13 error={}",
                        result.capture.launch_error.unwrap_or_default()
                    );
                    77
                } else {
                    println!(
                        "SHEBANG_ESCAPE errno={:?} exit={:?} stdout_b64={} stdout={}",
                        result.capture.launch_errno,
                        result.capture.exit_code,
                        base64(&result.capture.stdout),
                        single_line(&result.capture.stdout_text())
                    );
                    93
                }
            }
            "embedded" => {
                let lib = match path_string(&libpython) {
                    Ok(v) => v,
                    Err(error) => {
                        eprintln!("{error}");
                        return 2;
                    }
                };
                let result = run_record(
                    "allowed_dynamic_embedding_fixture",
                    &embedded,
                    &[&lib],
                    true,
                    false,
                );
                let stdout = result.capture.stdout_text();
                let stderr = result.capture.stderr_text();
                println!("EMBEDDED_FIXTURE exit={:?} signal={:?} stdout_b64={} stderr_b64={} stdout={} stderr={}", result.capture.exit_code, result.capture.signal, base64(&result.capture.stdout), base64(&result.capture.stderr), single_line(&stdout), single_line(&stderr));
                result.capture.exit_code.unwrap_or(96)
            }
            "loader" => {
                let py = match path_string(&python) {
                    Ok(v) => v,
                    Err(error) => {
                        eprintln!("{error}");
                        return 2;
                    }
                };
                let script = format!("print('{LOADER_MARKER}')");
                let result = run_record(
                    "invoke_loader_with_python",
                    &loader,
                    &[&py, "-I", "-S", "-c", &script],
                    true,
                    false,
                );
                let out = result.capture.stdout_text();
                let err = result.capture.stderr_text();
                if result.capture.exit_code != Some(0)
                    && err.to_ascii_lowercase().contains("permission denied")
                    && err.contains(&py)
                    && !out.contains(LOADER_MARKER)
                {
                    println!(
                        "DYNAMIC_LOADER_PYTHON_DENIED exit={:?} stderr_b64={} stderr={}",
                        result.capture.exit_code,
                        base64(&result.capture.stderr),
                        single_line(&err)
                    );
                    81
                } else {
                    println!(
                        "DYNAMIC_LOADER_PYTHON_ESCAPE exit={:?} stdout_b64={} stdout={}",
                        result.capture.exit_code,
                        base64(&result.capture.stdout),
                        single_line(&out)
                    );
                    94
                }
            }
            "execveat" => attempt_execveat(&true_path),
            "memfd" => attempt_memfd(),
            _ => {
                eprintln!("unknown sandbox mode {mode}");
                2
            }
        }
    }

    fn control_child(args: &[String]) -> i32 {
        let Some(python) = option_value(args, "--python") else {
            eprintln!("--control-child requires --python");
            return 2;
        };
        let marker = option_value(args, "--marker").unwrap_or(DIRECT_MARKER);
        let positive = args.iter().any(|arg| arg == "--positive");
        let code = format!("print('{marker}'); print('{DIRECT_MARKER}')");
        let result = run_record(
            "child_python",
            Path::new(python),
            &["-I", "-S", "-c", &code],
            true,
            false,
        );
        if positive && result.capture.success() && result.capture.stdout_text().contains(marker) {
            println!(
                "DESCENDANT_POSITIVE exit=0 stdout_b64={} stdout={}",
                base64(&result.capture.stdout),
                single_line(&result.capture.stdout_text())
            );
            92
        } else if !positive && result.capture.launch_errno == Some(EACCES) {
            println!(
                "DIRECT_DENIED errno=13 marker={marker} error={}",
                result.capture.launch_error.unwrap_or_default()
            );
            77
        } else {
            println!(
                "DIRECT_ESCAPE exit={:?} errno={:?} stdout_b64={} stdout={}",
                result.capture.exit_code,
                result.capture.launch_errno,
                base64(&result.capture.stdout),
                single_line(&result.capture.stdout_text())
            );
            if positive {
                92
            } else {
                96
            }
        }
    }

    fn try_python(path: &Path, label: &str) -> i32 {
        let code = format!("print('{DIRECT_MARKER}')");
        let result = run_record(
            "direct_absolute_python_attempt",
            path,
            &["-I", "-S", "-c", &code],
            true,
            false,
        );
        if result.capture.launch_errno == Some(EACCES) {
            println!(
                "{label}_DENIED errno=13 error={}",
                result.capture.launch_error.unwrap_or_default()
            );
            77
        } else {
            println!(
                "{label}_ESCAPE exit={:?} errno={:?} stdout_b64={} stdout={}",
                result.capture.exit_code,
                result.capture.launch_errno,
                base64(&result.capture.stdout),
                single_line(&result.capture.stdout_text())
            );
            91
        }
    }

    fn attempt_execveat(target: &Path) -> i32 {
        let cpath = match CString::new(path_string(target).unwrap_or_default()) {
            Ok(v) => v,
            Err(error) => {
                eprintln!("execveat path: {error}");
                return 2;
            }
        };
        let fd = unsafe { open(cpath.as_ptr(), O_CLOEXEC) };
        if fd < 0 {
            println!("EXECVEAT_SETUP_FAIL error={}", io::Error::last_os_error());
            return 2;
        }
        let argv0 = CString::new("true").expect("static string");
        let empty = b"\0";
        let argv = [argv0.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<i8>()];
        let result = unsafe {
            syscall(
                SYS_EXECVEAT,
                fd,
                empty.as_ptr() as *const i8,
                argv.as_ptr(),
                envp.as_ptr(),
                AT_EMPTY_PATH,
            )
        };
        let error = io::Error::last_os_error();
        unsafe {
            close(fd);
        }
        if result == -1 && error.raw_os_error() == Some(EACCES) {
            println!("EXECVEAT_DENIED errno=13 target=/usr/bin/true flags=AT_EMPTY_PATH");
            79
        } else {
            println!(
                "EXECVEAT_NOT_DENIED result={result} errno={:?} error={error}",
                error.raw_os_error()
            );
            94
        }
    }

    fn attempt_memfd() -> i32 {
        let name = CString::new("linux-no-python-probe").expect("static string");
        let fd = unsafe { syscall(SYS_MEMFD_CREATE, name.as_ptr(), MFD_CLOEXEC) };
        let error = io::Error::last_os_error();
        if fd == -1 && error.raw_os_error() == Some(EACCES) {
            println!("MEMFD_DENIED errno=13 route=memfd_create");
            80
        } else {
            if fd >= 0 {
                unsafe {
                    close(fd as i32);
                }
            }
            println!(
                "MEMFD_NOT_DENIED result={fd} errno={:?} error={error}",
                error.raw_os_error()
            );
            95
        }
    }

    struct OpenRule {
        path: PathBuf,
        fd: File,
    }

    impl OpenRule {
        fn new(path: &Path) -> Result<Self, String> {
            let canonical = fs::canonicalize(path)
                .map_err(|error| format!("canonicalize policy path {}: {error}", path.display()))?;
            let cpath =
                CString::new(path_string(&canonical)?).map_err(|error| error.to_string())?;
            let raw_fd = unsafe { open(cpath.as_ptr(), O_PATH | O_CLOEXEC) };
            if raw_fd < 0 {
                return Err(format!(
                    "open O_PATH {}: {}",
                    canonical.display(),
                    io::Error::last_os_error()
                ));
            }
            let fd = unsafe { File::from_raw_fd(raw_fd) };
            let opened = fd
                .metadata()
                .map_err(|error| format!("fstat {}: {error}", canonical.display()))?;
            let (read_metadata, _) = hash_file(&canonical)?;
            if opened.dev() != read_metadata.dev() || opened.ino() != read_metadata.ino() {
                return Err(format!(
                    "policy path changed identity while opening: {}",
                    canonical.display()
                ));
            }
            Ok(Self {
                path: canonical,
                fd,
            })
        }
    }

    fn install_policy(exec_paths: &[PathBuf], read_paths: &[PathBuf]) -> Result<i32, String> {
        let abi = query_landlock_abi()?;
        if abi < 1 {
            return Err(format!("unsupported Landlock ABI {abi}"));
        }
        let mut rules = BTreeMap::<String, (OpenRule, u64)>::new();
        for path in exec_paths {
            ensure_executable(path)?;
            let rule = OpenRule::new(path)?;
            let key = path_string(&rule.path)?;
            rules
                .entry(key)
                .and_modify(|entry| {
                    entry.1 |= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE
                })
                .or_insert((
                    rule,
                    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                ));
        }
        for path in read_paths {
            let rule = OpenRule::new(path)?;
            let key = path_string(&rule.path)?;
            rules
                .entry(key)
                .and_modify(|entry| entry.1 |= LANDLOCK_ACCESS_FS_READ_FILE)
                .or_insert((rule, LANDLOCK_ACCESS_FS_READ_FILE));
        }
        if rules.is_empty() {
            return Err("empty Landlock path rule set".to_owned());
        }
        let attrs = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
        };
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
        let ruleset = raw_ruleset as i32;
        for (rule, access) in rules.values() {
            let attr = LandlockPathBeneathAttr {
                allowed_access: *access,
                parent_fd: rule.fd.as_raw_fd(),
            };
            let added = unsafe {
                syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    ruleset,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &attr as *const LandlockPathBeneathAttr,
                    0u32,
                )
            };
            if added < 0 {
                let error = io::Error::last_os_error();
                unsafe {
                    close(ruleset);
                }
                return Err(format!(
                    "landlock_add_rule {} failed: {error}",
                    rule.path.display()
                ));
            }
        }
        let nnp = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if nnp != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                close(ruleset);
            }
            return Err(format!("PR_SET_NO_NEW_PRIVS failed: {error}"));
        }
        let restricted = unsafe { syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0u32) };
        let restrict_error = if restricted < 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe {
            close(ruleset);
        }
        if let Some(error) = restrict_error {
            return Err(format!("landlock_restrict_self failed: {error}"));
        }
        install_seccomp()?;
        Ok(abi)
    }

    fn query_landlock_abi() -> Result<i32, String> {
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

    fn install_seccomp() -> Result<(), String> {
        let filter = [
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
                k: AUDIT_ARCH_X86_64,
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
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: SYS_EXECVEAT as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | EACCES as u32,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: SYS_MEMFD_CREATE as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ERRNO | EACCES as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ];
        let program = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        let result = unsafe {
            syscall(
                SYS_SECCOMP,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC,
                &program as *const SockFprog,
            )
        };
        if result < 0 {
            return Err(format!(
                "seccomp filter installation failed: {}",
                io::Error::last_os_error()
            ));
        }
        if result != 0 {
            return Err(format!("seccomp TSYNC returned nonzero thread id {result}"));
        }
        Ok(())
    }

    fn run_record(
        name: &str,
        program: &Path,
        args: &[&str],
        clear_env: bool,
        new_group: bool,
    ) -> Record {
        let argv =
            std::iter::once(path_string(program).unwrap_or_else(|_| program.display().to_string()))
                .chain(args.iter().map(|s| (*s).to_owned()))
                .collect::<Vec<_>>();
        let mut command = Command::new(program);
        command.args(args);
        if clear_env {
            command.env_clear();
        }
        run_command(name, argv, command, new_group)
    }

    fn run_record_owned(
        name: &str,
        program: &Path,
        args: &[String],
        clear_env: bool,
        new_group: bool,
    ) -> Record {
        let argv =
            std::iter::once(path_string(program).unwrap_or_else(|_| program.display().to_string()))
                .chain(args.iter().cloned())
                .collect::<Vec<_>>();
        let mut command = Command::new(program);
        command.args(args);
        if clear_env {
            command.env_clear();
        }
        run_command(name, argv, command, new_group)
    }

    fn run_command(name: &str, argv: Vec<String>, mut command: Command, new_group: bool) -> Record {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        if new_group {
            command.process_group(0);
        }
        let start = Instant::now();
        let capture = match command.spawn() {
            Ok(mut child) => capture_child(&mut child, start),
            Err(error) => Capture::launch(error),
        };
        Record {
            name: name.to_owned(),
            argv,
            capture,
        }
    }

    fn capture_child(child: &mut Child, start: Instant) -> Capture {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (sender, receiver) = mpsc::channel();
        if let Some(pipe) = stdout {
            read_in_thread(pipe, true, sender.clone());
        }
        if let Some(pipe) = stderr {
            read_in_thread(pipe, false, sender);
        }
        let deadline = start + COMMAND_TIMEOUT;
        let mut status: Option<ExitStatus> = None;
        let mut stdout_done: Option<ReadDone> = None;
        let mut stderr_done: Option<ReadDone> = None;
        let mut timed_out = false;
        let mut drain_deadline = None;
        loop {
            if status.is_none() {
                match child.try_wait() {
                    Ok(value) => status = value,
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Capture::launch(error);
                    }
                }
            }
            while let Ok(done) = receiver.try_recv() {
                if done.stdout {
                    stdout_done = Some(done);
                } else {
                    stderr_done = Some(done);
                }
            }
            if status.is_some() && stdout_done.is_some() && stderr_done.is_some() {
                break;
            }
            if !timed_out && Instant::now() >= deadline {
                timed_out = true;
                unsafe {
                    kill(-(child.id() as i32), SIGKILL);
                }
                let _ = child.kill();
                if status.is_none() {
                    status = child.wait().ok();
                }
                drain_deadline = Some(Instant::now() + DRAIN_GRACE);
            }
            if timed_out && drain_deadline.map(|d| Instant::now() >= d).unwrap_or(false) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let elapsed = start.elapsed().as_millis();
        let (exit_code, signal) = status
            .map(|s| (s.code(), s.signal()))
            .unwrap_or((None, None));
        let stdout = stdout_done.unwrap_or(ReadDone {
            stdout: true,
            bytes: Vec::new(),
            total: 0,
            error: Some("reader did not finish within drain grace".to_owned()),
        });
        let stderr = stderr_done.unwrap_or(ReadDone {
            stdout: false,
            bytes: Vec::new(),
            total: 0,
            error: Some("reader did not finish within drain grace".to_owned()),
        });
        Capture {
            exit_code,
            signal,
            timed_out,
            launch_error: None,
            launch_errno: None,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            stdout_total: stdout.total,
            stderr_total: stderr.total,
            stdout_complete: stdout.error.is_none(),
            stderr_complete: stderr.error.is_none(),
            stdout_read_error: stdout.error,
            stderr_read_error: stderr.error,
            duration_ms: elapsed,
        }
    }

    fn read_in_thread<R: Read + Send + 'static>(
        mut reader: R,
        stdout: bool,
        sender: Sender<ReadDone>,
    ) {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 8192];
            let mut error = None;
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        total = total.saturating_add(count as u64);
                        let keep = MAX_OUTPUT.saturating_sub(bytes.len()).min(count);
                        bytes.extend_from_slice(&buffer[..keep]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error = Some(e.to_string());
                        break;
                    }
                }
            }
            let _ = sender.send(ReadDone {
                stdout,
                bytes,
                total,
                error,
            });
        });
    }

    fn record_json(record: &Record) -> String {
        let mut out = String::new();
        let _ = write!(out, "{{\"name\":{},\"argv\":[{}],\"exit_code\":{},\"signal\":{},\"timed_out\":{},\"launch_error\":{},\"launch_errno\":{},\"duration_ms\":{},", json_string(&record.name), record.argv.iter().map(|v| json_string(v)).collect::<Vec<_>>().join(","), record.capture.exit_code.map(|v| v.to_string()).unwrap_or_else(|| "null".to_owned()), record.capture.signal.map(|v| v.to_string()).unwrap_or_else(|| "null".to_owned()), record.capture.timed_out, opt_string(record.capture.launch_error.as_deref()), record.capture.launch_errno.map(|v| v.to_string()).unwrap_or_else(|| "null".to_owned()), record.capture.duration_ms);
        let _ = write!(out, "\"stdout_bytes_total\":{},\"stdout_truncated\":{},\"stdout_base64\":{},\"stdout_text\":{},\"stdout_complete\":{},\"stdout_read_error\":{},", record.capture.stdout_total, record.capture.stdout_total > record.capture.stdout.len() as u64, json_string(&base64(&record.capture.stdout)), json_string(&record.capture.stdout_text()), record.capture.stdout_complete, opt_string(record.capture.stdout_read_error.as_deref()));
        let _ = write!(out, "\"stderr_bytes_total\":{},\"stderr_truncated\":{},\"stderr_base64\":{},\"stderr_text\":{},\"stderr_complete\":{},\"stderr_read_error\":{}}}", record.capture.stderr_total, record.capture.stderr_total > record.capture.stderr.len() as u64, json_string(&base64(&record.capture.stderr)), json_string(&record.capture.stderr_text()), record.capture.stderr_complete, opt_string(record.capture.stderr_read_error.as_deref()));
        out
    }

    fn case_json(
        name: &str,
        expected: &str,
        checks: &[&str],
        passed: bool,
        record: &Record,
    ) -> String {
        format!(
            "{{\"name\":{},\"passed\":{},\"expected\":{},\"checks\":[{}],\"raw_outcome\":{}}}",
            json_string(name),
            passed,
            json_string(expected),
            checks
                .iter()
                .map(|v| json_string(v))
                .collect::<Vec<_>>()
                .join(","),
            record_json(record)
        )
    }

    fn push_case_owned(
        report: &mut Report,
        name: &str,
        expected: &str,
        record: Record,
        passed: bool,
        checks: &[&str],
    ) {
        report
            .cases
            .push(case_json(name, expected, checks, passed, &record));
        report.case_results.push((name.to_owned(), passed));
        println!(
            "CASE={} {} exit={:?}",
            name,
            if passed { "PASS" } else { "FAIL" },
            record.capture.exit_code
        );
    }

    fn record_clone(record: &Record) -> Record {
        Record {
            name: record.name.clone(),
            argv: record.argv.clone(),
            capture: Capture {
                exit_code: record.capture.exit_code,
                signal: record.capture.signal,
                timed_out: record.capture.timed_out,
                launch_error: record.capture.launch_error.clone(),
                launch_errno: record.capture.launch_errno,
                stdout: record.capture.stdout.clone(),
                stderr: record.capture.stderr.clone(),
                stdout_total: record.capture.stdout_total,
                stderr_total: record.capture.stderr_total,
                stdout_complete: record.capture.stdout_complete,
                stderr_complete: record.capture.stderr_complete,
                stdout_read_error: record.capture.stdout_read_error.clone(),
                stderr_read_error: record.capture.stderr_read_error.clone(),
                duration_ms: record.capture.duration_ms,
            },
        }
    }

    fn push_not_run(report: &mut Report, name: &str, why: &str) {
        let capture = Capture {
            exit_code: None,
            signal: None,
            timed_out: false,
            launch_error: Some(format!("not run: {why}")),
            launch_errno: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_total: 0,
            stderr_total: 0,
            stdout_complete: true,
            stderr_complete: true,
            stdout_read_error: None,
            stderr_read_error: None,
            duration_ms: 0,
        };
        let record = Record {
            name: name.to_owned(),
            argv: Vec::new(),
            capture,
        };
        push_case_owned(report, name, why, record, false, &["not_run"]);
    }

    fn add_not_run_policy_cases(report: &mut Report) {
        for name in [
            "positive_native_allowlisted",
            "execveat_empty_path_denied",
            "memfd_create_denied",
            "direct_python_denied",
            "descendant_python_denied",
            "absolute_shebang_denied",
            "allowed_binary_dynamic_embedding_denied",
            "dynamic_loader_python_denied",
        ] {
            push_not_run(report, name, "Landlock support unavailable");
        }
    }

    fn write_report(report: Report) -> Result<bool, String> {
        let passed = report.passed();
        let report_path = report.report_path.clone();
        let json = report.json();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&report_path)
            .map_err(|error| {
                format!(
                    "create report {} without overwriting earlier evidence: {error}",
                    report_path.display()
                )
            })?;
        file.write_all(json.as_bytes())
            .map_err(|error| format!("write report {}: {error}", report_path.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync report {}: {error}", report_path.display()))?;
        println!("RESULT={}", if passed { "PASS" } else { "FAIL" });
        for error in report.errors {
            eprintln!("ERROR={error}");
        }
        println!("REPORT={}", report_path.display());
        Ok(passed)
    }

    fn option_value<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
        args.iter()
            .position(|value| value == option)
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
    }

    fn option_values(args: &[String], option: &str) -> Vec<String> {
        args.iter()
            .enumerate()
            .filter_map(|(index, value)| {
                if value == option {
                    args.get(index + 1).cloned()
                } else {
                    None
                }
            })
            .collect()
    }

    fn parse_os_release() -> Result<String, String> {
        let content = fs::read_to_string("/etc/os-release").map_err(|error| error.to_string())?;
        Ok(content
            .lines()
            .filter(|line| {
                line.starts_with("ID=")
                    || line.starts_with("VERSION_ID=")
                    || line.starts_with("PRETTY_NAME=")
            })
            .collect::<Vec<_>>()
            .join("; "))
    }

    fn create_fixture_dir(output: &Path) -> Result<PathBuf, String> {
        for attempt in 0..32 {
            let path = output.join(format!(
                "fixtures-{}-{}-{attempt}",
                process::id(),
                unique_suffix()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "create fixture directory {}: {error}",
                        path.display()
                    ))
                }
            }
        }
        Err("could not allocate a unique fixture directory".to_owned())
    }

    fn unique_suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }

    fn resolve_program(name: &str) -> Result<PathBuf, String> {
        let path = env::var_os("PATH").ok_or_else(|| "PATH is unset".to_owned())?;
        for directory in env::split_paths(&path) {
            let candidate = directory.join(name);
            if candidate.is_file() {
                let canonical = fs::canonicalize(&candidate)
                    .map_err(|error| format!("canonicalize {}: {error}", candidate.display()))?;
                if fs::metadata(&canonical)
                    .map(|m| m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
                {
                    return Ok(canonical);
                }
            }
        }
        Err(format!("could not find {name} on PATH"))
    }

    fn ensure_executable(path: &Path) -> Result<(), String> {
        let metadata =
            fs::metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!("{} is not a regular executable", path.display()));
        }
        Ok(())
    }

    fn path_string(path: &Path) -> Result<String, String> {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
    }

    fn extract_prefix(text: &str, prefix: &str) -> Option<String> {
        text.lines()
            .find_map(|line| line.strip_prefix(prefix).map(str::to_owned))
    }

    fn parse_ldd_paths(output: &str) -> Vec<PathBuf> {
        let mut paths = BTreeMap::<String, PathBuf>::new();
        for line in output.lines() {
            let candidate = if let Some((_, right)) = line.split_once("=>") {
                right.split_whitespace().next()
            } else {
                line.split_whitespace().next()
            };
            if let Some(path) = candidate.filter(|value| value.starts_with('/')) {
                let path = PathBuf::from(path);
                paths.insert(path.display().to_string(), path);
            }
        }
        paths.into_values().collect()
    }

    fn single_line(value: &str) -> String {
        value.replace('\n', "\\n").replace('\r', "\\r")
    }

    fn opt_string(value: Option<&str>) -> String {
        value.map(json_string).unwrap_or_else(|| "null".to_owned())
    }

    fn json_string(value: &str) -> String {
        let mut out = String::with_capacity(value.len() + 2);
        out.push('"');
        for ch in value.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c <= '\u{1f}' => {
                    let _ = write!(out, "\\u{:04x}", c as u32);
                }
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    fn base64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let a = chunk[0] as u32;
            let b = chunk.get(1).copied().unwrap_or(0) as u32;
            let c = chunk.get(2).copied().unwrap_or(0) as u32;
            let value = (a << 16) | (b << 8) | c;
            out.push(TABLE[((value >> 18) & 63) as usize] as char);
            out.push(TABLE[((value >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                TABLE[((value >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[(value & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn sha256_path(path: &Path) -> Result<String, String> {
        let (_, hash) = hash_file(path)?;
        Ok(hex(&hash))
    }

    fn hash_file(path: &Path) -> Result<(fs::Metadata, [u8; 32]), String> {
        let mut file = File::open(path)
            .map_err(|error| format!("open {} for hash: {error}", path.display()))?;
        let before = file.metadata().map_err(|error| error.to_string())?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 32768];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => hasher.update(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("read {} for hash: {error}", path.display())),
            }
        }
        let after = file.metadata().map_err(|error| error.to_string())?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(format!("{} changed while hashing", path.display()));
        }
        Ok((after, hasher.finish()))
    }

    fn hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(TABLE[(byte >> 4) as usize] as char);
            out.push(TABLE[(byte & 0xf) as usize] as char);
        }
        out
    }

    struct Sha256 {
        state: [u32; 8],
        block: [u8; 64],
        used: usize,
        bytes: u64,
    }

    impl Sha256 {
        fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                block: [0; 64],
                used: 0,
                bytes: 0,
            }
        }
        fn update(&mut self, mut input: &[u8]) {
            self.bytes = self.bytes.wrapping_add(input.len() as u64);
            if self.used > 0 {
                let count = (64 - self.used).min(input.len());
                self.block[self.used..self.used + count].copy_from_slice(&input[..count]);
                self.used += count;
                input = &input[count..];
                if self.used == 64 {
                    let block = self.block;
                    self.compress(&block);
                    self.used = 0;
                } else {
                    // A short update must keep the buffered partial block.
                    return;
                }
            }
            let (blocks, remainder) = input.as_chunks::<64>();
            for chunk in blocks {
                self.compress(chunk);
            }
            self.block[..remainder.len()].copy_from_slice(remainder);
            self.used = remainder.len();
        }
        fn finish(mut self) -> [u8; 32] {
            let bits = self.bytes.wrapping_mul(8);
            self.block[self.used] = 0x80;
            self.used += 1;
            if self.used > 56 {
                self.block[self.used..].fill(0);
                let b = self.block;
                self.compress(&b);
                self.block = [0; 64];
                self.used = 0;
            }
            self.block[self.used..56].fill(0);
            self.block[56..].copy_from_slice(&bits.to_be_bytes());
            let b = self.block;
            self.compress(&b);
            let mut result = [0u8; 32];
            for (index, word) in self.state.iter().enumerate() {
                result[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            result
        }
        fn compress(&mut self, block: &[u8; 64]) {
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
            let mut w = [0u32; 64];
            for (i, chunk) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
                w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut v = self.state;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v = [
                    t1.wrapping_add(t2),
                    v[0],
                    v[1],
                    v[2],
                    v[3].wrapping_add(t1),
                    v[4],
                    v[5],
                    v[6],
                ];
            }
            for (state, value) in self.state.iter_mut().zip(v) {
                *state = state.wrapping_add(value);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{base64, hex, Sha256};
        #[test]
        fn sha256_known_vectors_streaming() {
            let mut hash = Sha256::new();
            hash.update(b"a");
            hash.update(b"bc");
            assert_eq!(
                hex(&hash.finish()),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            let mut large = Sha256::new();
            large.update(&vec![b'a'; 1000]);
            assert_eq!(
                hex(&large.finish()),
                "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
            );
        }
        #[test]
        fn base64_preserves_binary_output() {
            assert_eq!(base64(b"raw\0bytes"), "cmF3AGJ5dGVz");
        }
    }
}

//! One private consumer operation and its observed native child commands.
//! Command environments never inherit registry credentials or user Git config.
use crate::{
    Refusal, Result,
    directory::Directory,
    ownership,
    process_capture::{CaptureLimits, CommandSpec},
    resource_capture::{ResourceLimits, ResourceReport, SampleLimits, capture_with_resources},
    signals::SigtermGuard,
    workspace_accounting::ScanLimits,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct ConsumerSession<'a> {
    path: PathBuf,
    root: Directory,
    logs: Directory,
    signals: &'a SigtermGuard,
    next_command: u64,
    last_failure_exit_code: Option<u8>,
    build_output: bool,
}

enum ProgramValidation<'a> {
    Ordinary,
    #[cfg(target_os = "macos")]
    SelectedGit(&'a crate::consumer_source::SelectedMacosGit),
    #[cfg(not(target_os = "macos"))]
    _Lifetime(std::marker::PhantomData<&'a ()>),
}

pub struct ConsumerOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub resources: ResourceReport,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Serialize)]
struct CommandReport<'a> {
    schema: &'static str,
    label: &'a str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    elapsed_seconds: f64,
    resources: &'a ResourceReport,
    program_bytes: Vec<u8>,
    argument_bytes: Vec<Vec<u8>>,
}

impl<'a> ConsumerSession<'a> {
    /// The state is exclusively created by its caller and deliberately retained
    /// on failure. Reopening validates its private current-user ownership.
    pub fn new(path: &Path, signals: &'a SigtermGuard) -> Result<Self> {
        Self::new_with_policy(path, signals, false)
    }

    pub fn new_build(path: &Path, signals: &'a SigtermGuard) -> Result<Self> {
        Self::new_with_policy(path, signals, true)
    }

    fn new_with_policy(path: &Path, signals: &'a SigtermGuard, build_output: bool) -> Result<Self> {
        let root = if build_output {
            ownership::existing_private_build_output(path)?
        } else {
            ownership::existing_private_state(path)?
        };
        root.mkdir_new(OsStr::new("home"), 0o700)?;
        root.mkdir_new(OsStr::new("tmp"), 0o700)?;
        let logs = root.mkdir_new(OsStr::new("commands"), 0o700)?;
        Ok(Self {
            path: path.to_path_buf(),
            root,
            logs,
            signals,
            next_command: 0,
            last_failure_exit_code: None,
            build_output,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_failure_exit_code(&self) -> Option<u8> {
        self.last_failure_exit_code
    }

    pub fn environment(&self) -> BTreeMap<OsString, OsString> {
        [
            (
                OsString::from("PATH"),
                OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
            ),
            (
                OsString::from("HOME"),
                self.path.join("home").into_os_string(),
            ),
            (
                OsString::from("TMPDIR"),
                self.path.join("tmp").into_os_string(),
            ),
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("TZ"), OsString::from("UTC")),
            (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                OsString::from("/dev/null"),
            ),
            (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
        ]
        .into_iter()
        .collect()
    }

    pub fn run(
        &mut self,
        label: &str,
        program: &Path,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> Result<ConsumerOutput> {
        let spec = CommandSpec::new(program.as_os_str(), args, &self.path, self.environment());
        self.run_spec(label, spec, timeout)
    }

    /// The build adapter supplies its explicit offline Cargo environment and
    /// private working directory. Credentials are stripped even from an
    /// explicitly supplied environment, and the state remains the managed root.
    pub fn run_spec(
        &mut self,
        label: &str,
        spec: CommandSpec,
        timeout: Duration,
    ) -> Result<ConsumerOutput> {
        self.run_spec_inner(label, spec, timeout, true, ProgramValidation::Ordinary)
    }

    /// Preserve the actual child status for build frontends while retaining the
    /// same supervision, failed monitoring reports and cancellation handling.
    pub fn run_spec_retaining_exit(
        &mut self,
        label: &str,
        spec: CommandSpec,
        timeout: Duration,
    ) -> Result<ConsumerOutput> {
        self.run_spec_inner(label, spec, timeout, false, ProgramValidation::Ordinary)
    }

    /// Run only the exact Git authorized by the checked macOS selection.
    /// Other consumer commands retain the ordinary full ancestor policy.
    #[cfg(target_os = "macos")]
    pub(crate) fn run_selected_macos_git(
        &mut self,
        label: &str,
        selected: &crate::consumer_source::SelectedMacosGit,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> Result<ConsumerOutput> {
        let program = selected.checked_program()?;
        let spec = CommandSpec::new(program.as_os_str(), args, &self.path, self.environment());
        self.run_spec_inner(
            label,
            spec,
            timeout,
            true,
            ProgramValidation::SelectedGit(selected),
        )
    }

    fn run_spec_inner(
        &mut self,
        label: &str,
        mut spec: CommandSpec,
        timeout: Duration,
        require_success: bool,
        program_validation: ProgramValidation<'_>,
    ) -> Result<ConsumerOutput> {
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        self.last_failure_exit_code = None;
        if self.signals.requested() {
            self.last_failure_exit_code = Some(130);
            return Err(Refusal::new("consumer operation interrupted").with_exit_code(130));
        }
        if label.is_empty()
            || label.len() > 80
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Refusal::new("invalid consumer command label"));
        }
        spec.env.remove(OsStr::new("CARGO_REGISTRY_TOKEN"));
        spec.env
            .remove(OsStr::new("CARGO_REGISTRIES_CRATES_IO_TOKEN"));
        match program_validation {
            ProgramValidation::Ordinary => {
                validate_program(Path::new(&spec.program), self.root.metadata()?.uid())?;
            }
            #[cfg(target_os = "macos")]
            ProgramValidation::SelectedGit(selected) => {
                if selected.checked_program()? != Path::new(&spec.program) {
                    return Err(Refusal::new(
                        "consumer command differs from selected macOS Git",
                    ));
                }
            }
            #[cfg(not(target_os = "macos"))]
            ProgramValidation::_Lifetime(_) => unreachable!(),
        }
        self.next_command = self
            .next_command
            .checked_add(1)
            .ok_or_else(|| Refusal::new("consumer command count overflow"))?;
        let name = format!("{:04}-{label}", self.next_command);
        let directory = self.logs.mkdir_new(OsStr::new(&name), 0o700)?;
        let result = capture_with_resources(
            &spec,
            CaptureLimits {
                timeout,
                stdout_bytes: 16 * 1024 * 1024,
                stderr_bytes: 16 * 1024 * 1024,
                termination_grace: Duration::from_secs(2),
            },
            ResourceLimits {
                max_visible_rss_bytes: 4 * 1024 * 1024 * 1024,
                max_workspace_bytes: 12 * 1024 * 1024 * 1024,
                max_log_bytes: 16 * 1024 * 1024,
            },
            SampleLimits {
                max_ps_bytes: 2 * 1024 * 1024,
                max_ps_rows: 32_768,
                max_history_entries: 131_072,
                max_roots: 1,
                scan: ScanLimits {
                    max_entries: 100_000,
                    max_work_units: 200_001,
                },
            },
            std::slice::from_ref(&self.path),
            || self.signals.requested(),
        );
        match result {
            Ok(result) => {
                write_file(&directory, "stdout.log", &result.process.stdout)?;
                write_file(&directory, "stderr.log", &result.process.stderr)?;
                let report = CommandReport {
                    schema: "ami-rust-consumer-command-v1",
                    label,
                    exit_code: result.process.exit_code(),
                    signal: result.process.signal(),
                    elapsed_seconds: result.process.elapsed.as_secs_f64(),
                    resources: &result.report,
                    program_bytes: spec.program.as_bytes().to_vec(),
                    argument_bytes: spec
                        .args
                        .iter()
                        .map(|argument| argument.as_bytes().to_vec())
                        .collect(),
                };
                write_file(
                    &directory,
                    "result.json",
                    &serde_json::to_vec_pretty(&report).map_err(|error| {
                        Refusal::new(format!("cannot serialize consumer command report: {error}"))
                    })?,
                )?;
                if require_success && !result.process.status.success() {
                    self.last_failure_exit_code =
                        Some(supervised_failure_status(Some(result.process.status)));
                    return Err(Refusal::new(format!(
                        "consumer command {label} failed; retained logs: {}",
                        self.path.join("commands").join(name).display()
                    ))
                    .with_exit_code(supervised_failure_status(Some(result.process.status))));
                }
                if self.signals.requested() {
                    self.last_failure_exit_code = Some(130);
                    return Err(Refusal::new(
                        "consumer operation interrupted after child completion",
                    )
                    .with_exit_code(130));
                }
                self.last_failure_exit_code = None;
                Ok(ConsumerOutput {
                    exit_code: result.process.exit_code(),
                    signal: result.process.signal(),
                    stdout: result.process.stdout,
                    stderr: result.process.stderr,
                    resources: result.report,
                })
            }
            Err(error) => {
                use crate::resource_capture::ResourceCaptureError;
                let status = match &error {
                    ResourceCaptureError::Capture { error, .. } => error.status,
                    ResourceCaptureError::Setup { .. } => None,
                };
                let code = if self.signals.requested() {
                    130
                } else {
                    supervised_failure_status(status)
                };
                self.last_failure_exit_code = Some(code);
                write_file(&directory, "failed-process.json", &serde_json::to_vec_pretty(&serde_json::json!({
                    "schema":"ami-rust-consumer-command-failure-v1", "label":label,
                    "exit_code":status.and_then(|status| status.code()),
                    "signal":status.and_then(|status| { use std::os::unix::process::ExitStatusExt; status.signal() }),
                    "returned_exit_code":code, "reason":error.to_string(),
                })).map_err(|e|Refusal::new(e.to_string()))?)?;
                let report = serde_json::to_vec_pretty(error.report()).map_err(|e| {
                    Refusal::new(format!("cannot serialize failed resource report: {e}"))
                })?;
                write_file(&directory, "failed-resources.json", &report)?;
                if let crate::resource_capture::ResourceCaptureError::Capture {
                    error: captured,
                    ..
                } = &error
                {
                    write_file(&directory, "stdout.log", &captured.stdout)?;
                    write_file(&directory, "stderr.log", &captured.stderr)?;
                }
                Err(Refusal::new(format!(
                    "consumer command {label} failed: {error}; retained logs: {}",
                    self.path.join("commands").join(name).display()
                ))
                .with_exit_code(code))
            }
        }
    }

    pub fn recheck_root(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let reopened = if self.build_output {
            ownership::existing_private_build_output(&self.path)?
        } else {
            ownership::existing_private_state(&self.path)?
        };
        let before = self.root.metadata()?;
        let after = reopened.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(Refusal::new("consumer state root changed"));
        }
        self.signals.check()
    }
}

fn supervised_failure_status(status: Option<std::process::ExitStatus>) -> u8 {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Some(status) if status.signal().is_some() => 130,
        Some(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .filter(|code| *code != 0)
            .unwrap_or(1),
        None => 1,
    }
}

/// Tool aliases such as clang and llvm-strip must retain their invocation name.
/// This permits only leaf aliases, through the same protected ancestor policy
/// as ordinary tools. External trust inputs retain their stricter no-link API.
fn validate_program(program: &Path, owner_uid: u32) -> Result<()> {
    use crate::directory::EntryType;
    use std::os::unix::fs::MetadataExt;
    use std::{collections::BTreeSet, path::Component};
    if !program.is_absolute() {
        return Err(Refusal::new("consumer executable must be absolute"));
    }
    let mut candidate = program.to_path_buf();
    let mut visited = BTreeSet::new();
    let mut aliases = Vec::new();
    for _ in 0..32 {
        if !visited.insert(candidate.clone()) {
            return Err(Refusal::new("consumer executable alias cycle"));
        }
        let parent = candidate
            .parent()
            .ok_or_else(|| Refusal::new("executable has no parent"))?;
        let leaf = candidate
            .file_name()
            .ok_or_else(|| Refusal::new("executable has no file name"))?;
        let root = ownership::protected_directory(parent)?;
        if root.classify_entry(leaf)?.entry_type() == EntryType::Symlink {
            let metadata = std::fs::symlink_metadata(&candidate)?;
            if ![0, owner_uid].contains(&metadata.uid()) {
                return Err(Refusal::new("consumer executable alias has another owner"));
            }
            let target = root.link_target(leaf, 4096)?;
            let target_path = Path::new(&target);
            let joined = if target_path.is_absolute() {
                target_path.to_path_buf()
            } else {
                parent.join(target_path)
            };
            let mut normalized = PathBuf::new();
            for component in joined.components() {
                match component {
                    Component::ParentDir => {
                        if !normalized.pop() {
                            return Err(Refusal::new("executable alias escapes root"));
                        }
                    }
                    Component::CurDir => {}
                    _ => normalized.push(component.as_os_str()),
                }
            }
            aliases.push((root, leaf.to_os_string(), target));
            candidate = normalized;
        } else {
            ownership::protected_regular_file(&candidate, true)?;
            for (root, leaf, target) in aliases {
                if root.link_target(&leaf, 4096)? != target {
                    return Err(Refusal::new("consumer executable alias changed"));
                }
            }
            return Ok(());
        }
    }
    Err(Refusal::new(
        "consumer executable alias chain exceeds 32 entries",
    ))
}

fn write_file(root: &Directory, name: &str, raw: &[u8]) -> Result<()> {
    let mut file = root.create_new_file(OsStr::new(name), 0o600)?;
    file.write_all(raw)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, MetadataExt},
    };

    #[test]
    fn supervised_failure_codes_preserve_children_and_never_report_success() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            supervised_failure_status(Some(std::process::ExitStatus::from_raw(7 << 8))),
            7
        );
        assert_eq!(
            supervised_failure_status(Some(std::process::ExitStatus::from_raw(0))),
            1
        );
        assert_eq!(
            supervised_failure_status(Some(std::process::ExitStatus::from_raw(libc::SIGTERM))),
            130
        );
        assert_eq!(supervised_failure_status(None), 1);
    }

    #[test]
    fn native_session_controls_run_with_isolated_signal_state() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "consumer_session::tests::session_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", std::env::var_os("HOME").unwrap())
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("AMI_CONSUMER_SESSION_FIXTURE", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    #[ignore = "run by parent with process-wide SIGTERM state isolated"]
    fn session_child_fixture() {
        assert_eq!(
            std::env::var("AMI_CONSUMER_SESSION_FIXTURE").as_deref(),
            Ok("1")
        );
        let path =
            std::env::temp_dir().join(format!("ami-consumer-session-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let signals = SigtermGuard::acquire().unwrap();
        let mut session = ConsumerSession::new(&path, &signals).unwrap();
        let environment = session.environment();
        assert!(!environment.contains_key(OsStr::new("CARGO_REGISTRY_TOKEN")));
        assert!(!environment.contains_key(OsStr::new("CARGO_REGISTRIES_CRATES_IO_TOKEN")));
        let result = session
            .run(
                "native-environment",
                Path::new("/usr/bin/env"),
                vec![],
                Duration::from_secs(10),
            )
            .unwrap();
        assert!(result.resources.last_sample_complete);
        assert!(result.stdout.windows(5).any(|part| part == b"HOME="));
        assert!(
            session
                .run(
                    "../escape",
                    Path::new("/usr/bin/true"),
                    vec![],
                    Duration::from_secs(10)
                )
                .is_err()
        );
        assert!(!path.join("escape").exists());
        assert!(
            session
                .run(
                    "native-failure",
                    Path::new("/usr/bin/false"),
                    vec![],
                    Duration::from_secs(10)
                )
                .is_err()
        );
        let report: serde_json::Value = serde_json::from_slice(
            &fs::read(path.join("commands/0002-native-failure/result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(report["exit_code"], 1);
        assert_eq!(report["resources"]["last_sample_complete"], true);
        let alias = path.join("false-alias");
        std::os::unix::fs::symlink("/usr/bin/false", &alias).unwrap();
        let result = session
            .run_spec_retaining_exit(
                "native-build-failure",
                CommandSpec::new(alias.as_os_str(), Vec::new(), &path, session.environment()),
                Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(result.exit_code, Some(1));
        assert_eq!(result.signal, None);
        assert!(result.resources.last_sample_complete);
        let loop_alias = path.join("loop");
        std::os::unix::fs::symlink("loop", &loop_alias).unwrap();
        assert!(validate_program(&loop_alias, session.root.metadata().unwrap().uid()).is_err());
        let broken = path.join("broken");
        std::os::unix::fs::symlink("missing", &broken).unwrap();
        assert!(validate_program(&broken, session.root.metadata().unwrap().uid()).is_err());
        let sparse = fs::File::create(path.join("over-budget-control")).unwrap();
        sparse.set_len(12 * 1024 * 1024 * 1024 + 1).unwrap();
        let error = match session.run_spec_retaining_exit(
            "monitor-failure",
            CommandSpec::new("/usr/bin/true", Vec::new(), &path, session.environment()),
            Duration::from_secs(10),
        ) {
            Ok(_) => panic!("over-budget workspace accepted"),
            Err(error) => error,
        };
        let code = session.last_failure_exit_code().unwrap();
        assert!(code == 1 || code == 130, "{code}");
        assert_eq!(error.exit_code(), code);
        assert!(
            path.join("commands/0004-monitor-failure/failed-process.json")
                .is_file()
        );
        drop(sparse);
        session.recheck_root().unwrap();
        drop(session);
        signals.finish().unwrap();
        fs::remove_dir_all(path).unwrap();
    }
}

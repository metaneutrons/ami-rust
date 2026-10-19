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
}

pub struct ConsumerOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub resources: ResourceReport,
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
        let root = ownership::existing_private_state(path)?;
        root.mkdir_new(OsStr::new("home"), 0o700)?;
        root.mkdir_new(OsStr::new("tmp"), 0o700)?;
        let logs = root.mkdir_new(OsStr::new("commands"), 0o700)?;
        Ok(Self {
            path: path.to_path_buf(),
            root,
            logs,
            signals,
            next_command: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
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
        mut spec: CommandSpec,
        timeout: Duration,
    ) -> Result<ConsumerOutput> {
        use std::os::unix::ffi::OsStrExt;
        self.signals.check()?;
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
        ownership::protected_regular_file(Path::new(&spec.program), true)?;
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
                if !result.process.status.success() {
                    return Err(Refusal::new(format!(
                        "consumer command {label} failed; retained logs: {}",
                        self.path.join("commands").join(name).display()
                    )));
                }
                self.signals.check()?;
                Ok(ConsumerOutput {
                    stdout: result.process.stdout,
                    stderr: result.process.stderr,
                    resources: result.report,
                })
            }
            Err(error) => {
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
                )))
            }
        }
    }

    pub fn recheck_root(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let reopened = ownership::existing_private_state(&self.path)?;
        let before = self.root.metadata()?;
        let after = reopened.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(Refusal::new("consumer state root changed"));
        }
        self.signals.check()
    }
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
    use std::{fs, os::unix::fs::DirBuilderExt};

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
        session.recheck_root().unwrap();
        drop(session);
        signals.finish().unwrap();
        fs::remove_dir_all(path).unwrap();
    }
}

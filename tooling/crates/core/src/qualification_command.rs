//! Internal, one-command host qualification with sampled child resources.
//!
//! This records one explicit command. It does not qualify a complete campaign,
//! SDK, source census, or release. Process observation is not containment.
//! The helper samples its own ru_maxrss after raw-log writes and stream digests.
//! Final accounting and pending-report serialization/write are outside that RSS
//! boundary. `result.json` appears only at the atomic no-replace commit point;
//! `result.pending.json` is always nonauthoritative.

use crate::{
    Refusal, Result,
    digest::sha256_bytes,
    directory::Directory,
    json::{JsonProfile, parse_json},
    ownership,
    process_capture::{CaptureLimits, CommandSpec},
    resource_capture::{
        ResourceCaptureError, ResourceLimits, ResourceReport, SampleLimits, capture_with_resources,
    },
    signals::SigtermGuard,
    workspace_accounting::{self, Accounting, ScanLimits},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

pub const REQUEST_SCHEMA: &str = "ami-rust-native-command-qualification-request-v1";
const RECORD_SCHEMA: &str = "ami-rust-native-command-qualification-record-v1";
const PENDING_NAME: &str = "result.pending.json";
const FINAL_NAME: &str = "result.json";
const CLAIM: &str =
    "one explicit host command only; not full campaign, SDK, or release qualification";
const TERMINATION_GRACE: Duration = Duration::from_secs(2);
const MAX_PS_BYTES: usize = 2 * 1024 * 1024;
const MAX_PS_ROWS: usize = 32_768;
const MAX_HISTORY_ENTRIES: usize = 131_072;
const MAX_SCAN_ENTRIES: u64 = 1_000_000;
const MAX_SCAN_WORK: u64 = 2_000_001;

#[cfg(test)]
static FAIL_NEXT_PENDING_SYNC: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static PENDING_SYNC_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static INJECT_FINALIZATION_SIGTERM: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static FINALIZATION_SIGTERM_HITS: AtomicU64 = AtomicU64::new(0);

/// Strict request for one explicit command. The environment replaces the
/// parent environment completely; values are never copied into the record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub schema: String,
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub environment: BTreeMap<String, String>,
    pub required_roots: Vec<String>,
    pub limits: CommandBudgets,
}

/// All acceptance budgets come from the caller.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandBudgets {
    pub seconds: u64,
    pub rss_bytes: u64,
    pub workspace_bytes: u64,
    pub log_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommandBinding {
    pub program: String,
    pub program_sha256: String,
    pub cwd: String,
    pub args_sha256: String,
    pub environment_keys: Vec<String>,
    pub environment_sha256: String,
    pub helper_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StreamRecord {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct QualificationRecord {
    pub schema: &'static str,
    pub scope: &'static str,
    pub passed: bool,
    pub refusal: Option<String>,
    pub request_sha256: String,
    pub command: CommandBinding,
    pub limits: CommandBudgets,
    pub elapsed_nanos: u128,
    pub capture_complete: bool,
    pub capture_error: Option<String>,
    pub child_exit_code: Option<i32>,
    pub child_signal: Option<i32>,
    pub stdout: StreamRecord,
    pub stderr: StreamRecord,
    pub own_ru_maxrss_raw: Option<i64>,
    pub own_ru_maxrss_unit: &'static str,
    pub own_rss_boundary: &'static str,
    pub own_peak_rss_bytes: Option<u64>,
    pub child_peak_visible_rss_bytes: u64,
    pub aggregate_peak_rss_bytes: Option<u64>,
    pub workspace_bytes_at_finish: Option<u64>,
    pub log_bytes_at_finish: Option<u64>,
    pub resource_report: ResourceReport,
    /// In-memory publication outcome; the committed file's presence is the
    /// authority, so this state is intentionally not serialized.
    #[serde(skip)]
    pub result_published: bool,
    /// Whether the nonauthoritative pending path was retained at return.
    #[serde(skip)]
    pub pending_retained: bool,
    /// Signal requested after command completion but before report publication.
    #[serde(skip)]
    pub driver_signal: Option<i32>,
}

impl QualificationRecord {
    /// Child nonzero status is propagated after its complete record is saved.
    pub fn cli_exit_code(&self) -> i32 {
        if self.passed && self.result_published {
            0
        } else if let Some(code) = self.child_exit_code.filter(|code| *code != 0) {
            code
        } else if let Some(signal) = self.child_signal.or(self.driver_signal) {
            128_i32.saturating_add(signal).min(255)
        } else {
            2
        }
    }
}

pub fn parse_request(raw: &[u8]) -> Result<CommandRequest> {
    let request: CommandRequest = parse_json(raw, JsonProfile::PackageMetadataStateSelection)?;
    if request.schema != REQUEST_SCHEMA {
        return Err(Refusal::new(
            "unsupported native-command qualification request schema",
        ));
    }
    Ok(request)
}

/// Execute one command and persist raw logs plus a resource record in a fresh
/// directory. Caller roots are disjoint. A nested record is counted through
/// its containing caller root; an external record is appended as one root.
pub fn run_and_record(
    request: &CommandRequest,
    raw_request: &[u8],
    record_path: &Path,
) -> Result<QualificationRecord> {
    if parse_request(raw_request)? != *request {
        return Err(Refusal::new(
            "parsed command request does not match the bound request bytes",
        ));
    }
    validate_request_paths(request)?;

    let caller_roots: Vec<PathBuf> = request
        .required_roots
        .iter()
        .map(|root| PathBuf::from(root.as_str()))
        .collect();
    if caller_roots.is_empty() {
        return Err(Refusal::new(
            "at least one required managed root is required",
        ));
    }
    for left in 0..caller_roots.len() {
        for right in left + 1..caller_roots.len() {
            ownership::require_disjoint(
                &caller_roots[left],
                &caller_roots[right],
                "required managed roots overlap",
            )?;
        }
    }

    let record_target = ownership::fresh_output(record_path)?;
    let mut containing_roots = 0usize;
    let mut record_is_ancestor = false;
    for root in &caller_roots {
        if record_target.path().starts_with(root) && record_target.path() != root {
            containing_roots = containing_roots
                .checked_add(1)
                .ok_or_else(|| Refusal::new("record root count overflow"))?;
        }
        if root.starts_with(record_target.path()) {
            record_is_ancestor = true;
        }
    }
    if containing_roots > 1 || record_is_ancestor {
        return Err(Refusal::new(
            "record directory must be outside required roots or nested in exactly one root",
        ));
    }
    let record_is_nested = containing_roots == 1;

    let mut retained_roots = Vec::new();
    retained_roots
        .try_reserve(caller_roots.len() + usize::from(!record_is_nested))
        .map_err(|_| Refusal::new("could not allocate managed-root list"))?;
    for path in &caller_roots {
        retained_roots.push(ManagedRoot::open(path)?);
    }

    let signals = SigtermGuard::acquire()?;
    let record_directory = record_target
        .parent()
        .mkdir_new(record_target.name(), 0o700)?;
    let record_root = ManagedRoot::open(record_target.path())?;
    if !record_is_nested {
        retained_roots.push(ManagedRoot::open(record_target.path())?);
    }
    let all_scan_roots = retained_roots.iter().collect::<Vec<_>>();
    let mut capture_paths: Vec<PathBuf> = caller_roots.clone();
    if !record_is_nested {
        capture_paths.push(record_target.path().to_path_buf());
    }
    let root_bound = capture_paths.len();

    let command = CommandSpec::new(
        OsString::from(request.program.as_str()),
        request
            .args
            .iter()
            .map(|argument| OsString::from(argument.as_str())),
        PathBuf::from(&request.cwd),
        request
            .environment
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect(),
    );
    let helper_path = std::env::current_exe()
        .map_err(|error| Refusal::new(format!("cannot resolve helper executable: {error}")))?;
    let program_sha256 = hash_open_file(ownership::protected_regular_file(
        Path::new(&request.program),
        true,
    )?)?;
    let helper_sha256 = hash_open_file(ownership::protected_regular_file(&helper_path, true)?)?;
    let environment_sha256 =
        sha256_bytes(&serde_json::to_vec(&request.environment).map_err(|error| {
            Refusal::new(format!("cannot digest command environment: {error}"))
        })?);
    let args_sha256 = sha256_bytes(
        &serde_json::to_vec(&request.args)
            .map_err(|error| Refusal::new(format!("cannot digest command arguments: {error}")))?,
    );
    let request_sha256 = sha256_bytes(raw_request);
    let command_binding = CommandBinding {
        program: request.program.clone(),
        program_sha256,
        cwd: request.cwd.clone(),
        args_sha256,
        environment_keys: request.environment.keys().cloned().collect(),
        environment_sha256,
        helper_sha256,
    };

    let stream_limit = usize::try_from(request.limits.log_bytes)
        .map_err(|_| Refusal::new("log-byte budget is not representable on this host"))?;
    let sample_limits = SampleLimits {
        max_ps_bytes: MAX_PS_BYTES,
        max_ps_rows: MAX_PS_ROWS,
        max_history_entries: MAX_HISTORY_ENTRIES,
        max_roots: root_bound,
        scan: ScanLimits {
            max_entries: MAX_SCAN_ENTRIES,
            max_work_units: MAX_SCAN_WORK,
        },
    };
    let observed = capture_with_resources(
        &command,
        CaptureLimits {
            timeout: Duration::from_secs(request.limits.seconds),
            stdout_bytes: stream_limit,
            stderr_bytes: stream_limit,
            termination_grace: TERMINATION_GRACE,
        },
        ResourceLimits {
            max_visible_rss_bytes: request.limits.rss_bytes,
            max_workspace_bytes: request.limits.workspace_bytes,
            max_log_bytes: request.limits.log_bytes,
        },
        sample_limits,
        &capture_paths,
        || signals.requested(),
    );

    let (stdout, stderr, exit_code, signal, elapsed, capture_error, mut report) = match observed {
        Ok(captured) => {
            let process = captured.process;
            let (code, signal) = exit_and_signal(&process.status);
            (
                process.stdout,
                process.stderr,
                code,
                signal,
                process.elapsed,
                None,
                captured.report,
            )
        }
        Err(ResourceCaptureError::Setup { error, report }) => (
            Vec::new(),
            Vec::new(),
            None,
            None,
            Duration::ZERO,
            Some(error.to_string()),
            *report,
        ),
        Err(ResourceCaptureError::Capture { error, report }) => {
            let status = error.status.as_ref().map(exit_and_signal);
            let elapsed = error.elapsed;
            let message = error.to_string();
            (
                error.stdout,
                error.stderr,
                status.and_then(|pair| pair.0),
                status.and_then(|pair| pair.1),
                elapsed,
                Some(message),
                *report,
            )
        }
    };
    let mut refusal = None;
    let mut set_refusal = |message: String| {
        if refusal.is_none() {
            refusal = Some(message);
        }
    };
    if let Err(error) = record_root.verify_namespace() {
        set_refusal(format!(
            "record directory changed during observation: {error}"
        ));
    }
    // Keep the SIGTERM guard while logs, final accounting, and the pending
    // report are prepared. Failed log writes refuse qualification but retain
    // any output already written.
    if let Err(error) = write_new(&record_directory, "stdout.log", &stdout) {
        set_refusal(format!("could not retain stdout log: {error}"));
    }
    if let Err(error) = write_new(&record_directory, "stderr.log", &stderr) {
        set_refusal(format!("could not retain stderr log: {error}"));
    }
    if let Err(error) = record_root.verify_namespace() {
        set_refusal(format!(
            "record directory changed during finalization: {error}"
        ));
    }

    let stdout_record = stream_record(&stdout)?;
    let stderr_record = stream_record(&stderr)?;
    let own_rss = own_peak_rss_bytes();
    let accounting = match scan_roots(all_scan_roots.as_slice()) {
        Ok(accounting) => Some(accounting),
        Err(error) => {
            report.last_sample_complete = false;
            set_refusal(format!("final managed-root accounting failed: {error}"));
            None
        }
    };

    if let Some(error) = &capture_error {
        set_refusal(format!(
            "command capture or resource observation failed: {error}"
        ));
    }
    if let Some(code) = exit_code.filter(|code| *code != 0) {
        set_refusal(format!("child exited with status {code}"));
    } else if let Some(signal) = signal {
        set_refusal(format!("child terminated by signal {signal}"));
    } else if exit_code.is_none() && capture_error.is_none() {
        set_refusal("child exit status was unavailable".to_owned());
    }
    if !report.last_sample_complete || report.incomplete_cleanup || report.sample_count == 0 {
        set_refusal("process observation or cleanup was incomplete".to_owned());
    }

    let own_raw = own_rss.as_ref().ok().map(|value| value.0);
    let own_bytes = own_rss.as_ref().ok().map(|value| value.1);
    let aggregate = match own_bytes {
        Some(own) => match aggregate_rss(own, report.peak_visible_rss_bytes) {
            Ok(total) => Some(total),
            Err(error) => {
                set_refusal(error.to_string());
                None
            }
        },
        None => {
            set_refusal(format!(
                "could not sample helper ru_maxrss: {}",
                own_rss.as_ref().expect_err("missing own RSS error")
            ));
            None
        }
    };
    if let Some(own) = own_bytes
        && let Err(error) =
            aggregate_rss_with_limit(own, report.peak_visible_rss_bytes, request.limits.rss_bytes)
    {
        set_refusal(error.to_string());
    }

    let workspace_at_finish = accounting.as_ref().map(|value| value.regular_file_bytes);
    let logs_at_finish = accounting.as_ref().map(|value| value.log_file_bytes);
    if let Some(accounting) = accounting {
        report.current_workspace_bytes = accounting.regular_file_bytes;
        report.peak_workspace_bytes = report
            .peak_workspace_bytes
            .max(accounting.regular_file_bytes);
        report.current_disk_log_bytes = accounting.log_file_bytes;
        report.current_pending_output_bytes = 0;
        report.current_log_bytes = accounting.log_file_bytes;
        report.peak_log_bytes = report.peak_log_bytes.max(accounting.log_file_bytes);
        if accounting.log_file_bytes > request.limits.log_bytes {
            set_refusal(format!(
                "final log bytes {} exceed caller limit {}",
                accounting.log_file_bytes, request.limits.log_bytes
            ));
        }
        if accounting.regular_file_bytes > request.limits.workspace_bytes {
            set_refusal(format!(
                "workspace bytes {} exceed caller limit {}",
                accounting.regular_file_bytes, request.limits.workspace_bytes
            ));
        }
    } else {
        set_refusal("final managed-root accounting failed".to_owned());
    }

    let mut record = QualificationRecord {
        schema: RECORD_SCHEMA,
        scope: CLAIM,
        passed: false,
        refusal: None,
        request_sha256,
        command: command_binding,
        limits: request.limits,
        elapsed_nanos: elapsed.as_nanos(),
        capture_complete: capture_error.is_none(),
        capture_error,
        child_exit_code: exit_code,
        child_signal: signal,
        stdout: stdout_record,
        stderr: stderr_record,
        own_ru_maxrss_raw: own_raw,
        own_ru_maxrss_unit: current_ru_maxrss_unit(),
        own_rss_boundary: "after stdout/stderr log writes and stream digests; before final workspace walk and result serialization/write",
        own_peak_rss_bytes: own_bytes,
        child_peak_visible_rss_bytes: report.peak_visible_rss_bytes,
        aggregate_peak_rss_bytes: aggregate,
        workspace_bytes_at_finish: workspace_at_finish,
        log_bytes_at_finish: logs_at_finish,
        resource_report: report,
        result_published: false,
        pending_retained: false,
        driver_signal: None,
    };
    record.passed = refusal.is_none();
    record.refusal = refusal;

    // result.pending.json is explicitly nonauthoritative. A complete-looking
    // PASS can become authoritative only through the final no-replace rename.
    let mut pending_file = None;
    let mut pending_error = None;
    match result_bytes_with_workspace(&mut record, accounting, request.limits.workspace_bytes) {
        Ok(bytes) => match record_directory.create_new_file(OsStr::new(PENDING_NAME), 0o600) {
            Ok(mut file) => {
                let write_result = file.write_all(&bytes).map_err(|error| {
                    Refusal::new(format!("could not write pending command record: {error}"))
                });
                let prepared = write_result.and_then(|()| {
                    sync_pending(&file).map_err(|error| {
                        Refusal::new(format!("could not sync pending command record: {error}"))
                    })
                });
                if let Err(error) = prepared {
                    pending_error = Some(error.to_string());
                }
                pending_file = Some(file);
            }
            Err(error) => pending_error = Some(error.to_string()),
        },
        Err(error) => pending_error = Some(error.to_string()),
    }

    record.pending_retained = pending_file.is_some();
    let mut block_publication = pending_error.is_some() || pending_file.is_none();
    if let Err(error) = maybe_inject_finalization_sigterm() {
        block_publication = true;
        append_refusal(
            &mut record,
            format!("finalization signal hook failed: {error}"),
        );
    }

    // The synced pending report, logs, and final accounting are complete
    // before restoring the process-wide SIGTERM handler.
    let signal_result = signals.finish_requested();
    if let Some(error) = pending_error {
        append_refusal(
            &mut record,
            format!("pending report preparation failed: {error}"),
        );
    }
    match signal_result {
        Ok(true) => {
            block_publication = true;
            record.driver_signal = Some(libc::SIGTERM);
            append_refusal(
                &mut record,
                "SIGTERM requested during command qualification or finalization".to_owned(),
            );
        }
        Ok(false) => {}
        Err(error) => {
            block_publication = true;
            append_refusal(
                &mut record,
                format!("could not restore SIGTERM observation: {error}"),
            );
        }
    }
    if block_publication {
        // The already-synced pending candidate remains nonauthoritative. Do not
        // perform more filesystem work after restoring the signal handler.
        return Ok(record);
    }

    // Recheck every root and both record path identities immediately before
    // the atomic publication. No workspace walk or result write follows this.
    drop(pending_file.take());
    if let Err(error) = verify_commit_namespace(
        &retained_roots,
        &record_root,
        &record_directory,
        record_target
            .path()
            .parent()
            .expect("fresh output has a parent"),
        record_target.parent(),
    ) {
        append_refusal(
            &mut record,
            format!("final record namespace changed: {error}"),
        );
        return Ok(record);
    }

    // This no-replace atomic rename is the commit point and the final fallible
    // library operation. Do not add post-publication sync or cleanup.
    if let Err(error) = record_directory.rename_no_replace(
        OsStr::new(PENDING_NAME),
        &record_directory,
        OsStr::new(FINAL_NAME),
    ) {
        append_refusal(
            &mut record,
            format!("could not publish final command record: {error}"),
        );
        return Ok(record);
    }
    record.result_published = true;
    record.pending_retained = false;
    Ok(record)
}

fn validate_request_paths(request: &CommandRequest) -> Result<()> {
    if request.schema != REQUEST_SCHEMA {
        return Err(Refusal::new(
            "unsupported native-command qualification request schema",
        ));
    }
    if request.required_roots.is_empty() {
        return Err(Refusal::new(
            "at least one required managed root is required",
        ));
    }
    ownership::protected_regular_file(Path::new(&request.program), true)?;
    ownership::protected_directory(Path::new(&request.cwd))?;
    for root in &request.required_roots {
        ownership::protected_directory(Path::new(root))?;
    }
    Ok(())
}

struct ManagedRoot {
    path: PathBuf,
    directory: Directory,
    device: u64,
    inode: u64,
    mode: u32,
}

impl ManagedRoot {
    fn open(path: &Path) -> Result<Self> {
        Self::from_open(path.to_path_buf(), ownership::protected_directory(path)?)
    }

    fn from_open(path: PathBuf, directory: Directory) -> Result<Self> {
        let metadata = directory.metadata()?;
        Ok(Self {
            path,
            directory,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        })
    }

    fn verify_namespace(&self) -> Result<()> {
        let retained = self.directory.metadata()?;
        if !same_identity(&retained, self.device, self.inode, self.mode) {
            return Err(Refusal::new(
                "retained managed-root descriptor changed identity",
            ));
        }
        let current = ownership::protected_directory(&self.path)?;
        let metadata = current.metadata()?;
        if !same_identity(&metadata, self.device, self.inode, self.mode) {
            return Err(Refusal::new("required managed root was replaced"));
        }
        Ok(())
    }

    fn verify_handle(&self, directory: &Directory) -> Result<()> {
        if !same_identity(&directory.metadata()?, self.device, self.inode, self.mode) {
            return Err(Refusal::new("retained record directory changed identity"));
        }
        Ok(())
    }
}

fn verify_directory_namespace(path: &Path, retained: &Directory) -> Result<()> {
    let expected = retained.metadata()?;
    let current = ownership::protected_directory(path)?;
    if !same_identity(
        &current.metadata()?,
        expected.dev(),
        expected.ino(),
        expected.mode(),
    ) {
        return Err(Refusal::new("record parent directory was replaced"));
    }
    Ok(())
}

fn verify_commit_namespace(
    roots: &[ManagedRoot],
    record_root: &ManagedRoot,
    record_directory: &Directory,
    record_parent_path: &Path,
    record_parent: &Directory,
) -> Result<()> {
    for root in roots {
        root.verify_namespace()?;
    }
    record_root.verify_namespace()?;
    record_root.verify_handle(record_directory)?;
    verify_directory_namespace(record_parent_path, record_parent)
}

fn append_refusal(record: &mut QualificationRecord, message: String) {
    record.passed = false;
    match record.refusal.take() {
        Some(previous) if !previous.contains(&message) => {
            record.refusal = Some(format!("{previous}; {message}"));
        }
        Some(previous) => record.refusal = Some(previous),
        None => record.refusal = Some(message),
    }
}

fn sync_pending(file: &File) -> io::Result<()> {
    #[cfg(test)]
    {
        PENDING_SYNC_CALLS.fetch_add(1, Ordering::SeqCst);
        if FAIL_NEXT_PENDING_SYNC.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected pending-report sync failure"));
        }
    }
    file.sync_all()
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "Test hook raises SIGTERM while the production guard is installed."
)]
fn maybe_inject_finalization_sigterm() -> io::Result<()> {
    if INJECT_FINALIZATION_SIGTERM.swap(false, Ordering::SeqCst) {
        FINALIZATION_SIGTERM_HITS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: SIGTERM is raised against this process while SigtermGuard has
        // installed its handler; raise takes no pointer arguments.
        if unsafe { libc::raise(libc::SIGTERM) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(test))]
fn maybe_inject_finalization_sigterm() -> io::Result<()> {
    Ok(())
}

fn same_identity(metadata: &fs::Metadata, device: u64, inode: u64, mode: u32) -> bool {
    metadata.dev() == device && metadata.ino() == inode && metadata.mode() == mode
}

fn scan_roots(roots: &[&ManagedRoot]) -> Result<Accounting> {
    let mut total = Accounting::default();
    for root in roots {
        root.verify_namespace()?;
        let remaining = ScanLimits {
            max_entries: MAX_SCAN_ENTRIES
                .checked_sub(total.entries_seen)
                .ok_or_else(|| Refusal::new("managed-root scan entry bound exceeded"))?,
            max_work_units: MAX_SCAN_WORK
                .checked_sub(total.work_units)
                .ok_or_else(|| Refusal::new("managed-root scan work bound exceeded"))?,
        };
        let current = workspace_accounting::scan_directory(&root.directory, remaining)
            .map_err(|error| Refusal::new(format!("managed-root accounting failed: {error}")))?;
        total = add_accounting(total, current)?;
        root.verify_namespace()?;
    }
    Ok(total)
}

fn add_accounting(left: Accounting, right: Accounting) -> Result<Accounting> {
    Ok(Accounting {
        regular_file_bytes: left
            .regular_file_bytes
            .checked_add(right.regular_file_bytes)
            .ok_or_else(|| Refusal::new("workspace byte total overflow"))?,
        log_file_bytes: left
            .log_file_bytes
            .checked_add(right.log_file_bytes)
            .ok_or_else(|| Refusal::new("log byte total overflow"))?,
        entries_seen: left
            .entries_seen
            .checked_add(right.entries_seen)
            .ok_or_else(|| Refusal::new("workspace entry total overflow"))?,
        work_units: left
            .work_units
            .checked_add(right.work_units)
            .ok_or_else(|| Refusal::new("workspace work total overflow"))?,
    })
}

fn result_bytes_with_workspace(
    record: &mut QualificationRecord,
    accounting: Option<Accounting>,
    workspace_limit: u64,
) -> Result<Vec<u8>> {
    let mut predicted_record_bytes = 0_u64;
    for _ in 0..8 {
        if let Some(accounting) = accounting {
            let final_total = accounting
                .regular_file_bytes
                .checked_add(predicted_record_bytes)
                .ok_or_else(|| Refusal::new("final workspace byte total overflow"))?;
            record.workspace_bytes_at_finish = Some(final_total);
            record.resource_report.current_workspace_bytes = final_total;
            record.resource_report.peak_workspace_bytes =
                record.resource_report.peak_workspace_bytes.max(final_total);
            if final_total > workspace_limit {
                record.passed = false;
                if record.refusal.is_none() {
                    record.refusal = Some(format!(
                        "workspace bytes {final_total} exceed caller limit {workspace_limit}"
                    ));
                }
            }
        } else {
            record.workspace_bytes_at_finish = None;
        }
        let mut bytes = serde_json::to_vec(record)
            .map_err(|error| Refusal::new(format!("cannot serialize command record: {error}")))?;
        bytes.push(b'\n');
        let next_record_bytes = u64::try_from(bytes.len())
            .map_err(|_| Refusal::new("result record length exceeds u64"))?;
        if next_record_bytes == predicted_record_bytes {
            return Ok(bytes);
        }
        predicted_record_bytes = next_record_bytes;
    }
    Err(Refusal::new(
        "final workspace record size did not stabilize",
    ))
}

fn write_new(root: &Directory, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = root.create_new_file(OsStr::new(name), 0o600)?;
    file.write_all(bytes)
        .map_err(|error| Refusal::new(format!("could not write command record: {error}")))?;
    file.sync_all()
        .map_err(|error| Refusal::new(format!("could not sync command record: {error}")))?;
    Ok(())
}

fn stream_record(bytes: &[u8]) -> Result<StreamRecord> {
    Ok(StreamRecord {
        bytes: u64::try_from(bytes.len())
            .map_err(|_| Refusal::new("captured stream length exceeds u64"))?,
        sha256: sha256_bytes(bytes),
    })
}

fn exit_and_signal(status: &ExitStatus) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    (status.code(), status.signal())
}

fn aggregate_rss(own: u64, child_peak: u64) -> Result<u64> {
    own.checked_add(child_peak)
        .ok_or_else(|| Refusal::new("aggregate helper plus child RSS byte sum overflows"))
}

fn aggregate_rss_with_limit(own: u64, child_peak: u64, limit: u64) -> Result<u64> {
    let total = aggregate_rss(own, child_peak)?;
    if total > limit {
        return Err(Refusal::new(format!(
            "aggregate driver plus child RSS {total} exceeds caller limit {limit}"
        )));
    }
    Ok(total)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RusageUnit {
    Bytes,
    Kibibytes,
}

fn ru_maxrss_bytes(raw: i64, unit: RusageUnit) -> Result<u64> {
    let raw = u64::try_from(raw).map_err(|_| Refusal::new("ru_maxrss is negative"))?;
    match unit {
        RusageUnit::Bytes => Ok(raw),
        RusageUnit::Kibibytes => raw
            .checked_mul(1024)
            .ok_or_else(|| Refusal::new("ru_maxrss byte conversion overflows")),
    }
}

fn current_ru_maxrss_unit() -> &'static str {
    if cfg!(target_os = "linux") {
        "KiB"
    } else {
        "bytes"
    }
}

fn own_peak_rss_bytes() -> io::Result<(i64, u64)> {
    #[allow(
        unsafe_code,
        reason = "getrusage reads the current process high-water RSS."
    )]
    fn read_usage() -> io::Result<libc::rusage> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the output structure when it returns 0.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful getrusage initialized the complete structure.
        Ok(unsafe { usage.assume_init() })
    }

    let usage = read_usage()?;
    // All qualified host platforms use a signed 64-bit ru_maxrss field.
    let raw: i64 = usage.ru_maxrss;
    let unit = if cfg!(target_os = "linux") {
        RusageUnit::Kibibytes
    } else {
        RusageUnit::Bytes
    };
    ru_maxrss_bytes(raw, unit)
        .map(|bytes| (raw, bytes))
        .map_err(|error| io::Error::other(error.to_string()))
}

fn hash_open_file(mut file: File) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => {
                let digest: [u8; 32] = digest.finalize().into();
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut output = String::with_capacity(64);
                for byte in digest {
                    output.push(char::from(HEX[usize::from(byte >> 4)]));
                    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
                }
                return Ok(output);
            }
            Ok(read) => digest.update(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not hash protected command file: {error}"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RusageUnit, aggregate_rss, aggregate_rss_with_limit, ru_maxrss_bytes};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn request_bytes(request: &super::CommandRequest) -> Vec<u8> {
        serde_json::to_vec(request).unwrap()
    }

    fn test_request(
        program: &str,
        args: Vec<String>,
        root: &std::path::Path,
        seconds: u64,
        rss_bytes: u64,
        workspace_bytes: u64,
        log_bytes: u64,
    ) -> super::CommandRequest {
        super::CommandRequest {
            schema: super::REQUEST_SCHEMA.to_owned(),
            program: program.to_owned(),
            args,
            cwd: root.to_string_lossy().into_owned(),
            environment: Default::default(),
            required_roots: vec![root.to_string_lossy().into_owned()],
            limits: super::CommandBudgets {
                seconds,
                rss_bytes,
                workspace_bytes,
                log_bytes,
            },
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let parent = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
            let path = parent.join(format!(
                ".qualification-command-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn ru_maxrss_units_and_overflow_are_explicit() {
        assert_eq!(ru_maxrss_bytes(7, RusageUnit::Bytes).unwrap(), 7);
        assert_eq!(ru_maxrss_bytes(7, RusageUnit::Kibibytes).unwrap(), 7 * 1024);
        assert!(ru_maxrss_bytes(-1, RusageUnit::Bytes).is_err());
        assert!(ru_maxrss_bytes(i64::MAX, RusageUnit::Kibibytes).is_err());
        assert_eq!(aggregate_rss(10, 15).unwrap(), 25);
        assert_eq!(aggregate_rss_with_limit(10, 15, 25).unwrap(), 25);
        assert!(aggregate_rss_with_limit(10, 15, 24).is_err());
        assert!(aggregate_rss(u64::MAX, 1).is_err());
    }

    #[test]
    fn request_parser_rejects_unknown_fields_and_accepts_explicit_command() {
        let valid = br#"{"schema":"ami-rust-native-command-qualification-request-v1","program":"/usr/bin/printf","args":["native"],"cwd":"/","environment":{},"required_roots":["/"],"limits":{"seconds":1,"rss_bytes":10,"workspace_bytes":10,"log_bytes":10}}"#;
        assert!(super::parse_request(valid).is_ok());
        let unknown = br#"{"schema":"ami-rust-native-command-qualification-request-v1","program":"/usr/bin/printf","args":[],"cwd":"/","environment":{},"required_roots":["/"],"limits":{"seconds":1,"rss_bytes":10,"workspace_bytes":10,"log_bytes":10},"extra":true}"#;
        assert!(super::parse_request(unknown).is_err());
    }

    #[test]
    fn nested_record_is_counted_once_and_successful_command_output_is_native() {
        let _serial = SERIAL.lock().unwrap();
        let temp = TempDir::new();
        let root = temp.0.join("root");
        let record = root.join("record");
        fs::create_dir(&root).unwrap();
        let request = super::CommandRequest {
            schema: super::REQUEST_SCHEMA.to_owned(),
            program: "/usr/bin/printf".to_owned(),
            args: vec!["native".to_owned()],
            cwd: root.to_string_lossy().into_owned(),
            environment: Default::default(),
            required_roots: vec![root.to_string_lossy().into_owned()],
            limits: super::CommandBudgets {
                seconds: 1,
                rss_bytes: u64::MAX,
                workspace_bytes: u64::MAX,
                log_bytes: 1024,
            },
        };
        // The record is allowed inside one caller root. It remains exclusive
        // because the target leaf is created with mkdirat through its parent.
        let made = super::run_and_record(&request, &request_bytes(&request), &record).unwrap();
        assert!(made.passed, "{:?}", made.refusal);
        assert_eq!(fs::read(record.join("stdout.log")).unwrap(), b"native");
        let recorded_total = fs::metadata(record.join("stdout.log")).unwrap().len()
            + fs::metadata(record.join("stderr.log")).unwrap().len()
            + fs::metadata(record.join("result.json")).unwrap().len();
        assert_eq!(made.workspace_bytes_at_finish, Some(recorded_total));
    }

    #[test]
    fn nonzero_child_status_is_preserved_in_record() {
        let _serial = SERIAL.lock().unwrap();
        let temp = TempDir::new();
        let root = temp.0.join("root");
        let record = temp.0.join("record");
        fs::create_dir(&root).unwrap();
        let request = super::CommandRequest {
            schema: super::REQUEST_SCHEMA.to_owned(),
            program: "/usr/bin/false".to_owned(),
            args: vec![],
            cwd: root.to_string_lossy().into_owned(),
            environment: Default::default(),
            required_roots: vec![root.to_string_lossy().into_owned()],
            limits: super::CommandBudgets {
                seconds: 10,
                rss_bytes: u64::MAX,
                workspace_bytes: u64::MAX,
                log_bytes: 1024,
            },
        };
        let result = super::run_and_record(&request, &request_bytes(&request), &record).unwrap();
        assert!(!result.passed);
        assert_eq!(result.child_exit_code, Some(1));
        assert_eq!(result.cli_exit_code(), 1);
        assert!(result.result_published);
        assert!(record.join("result.json").is_file());
    }

    #[test]
    fn existing_record_is_refused_without_replacement() {
        let _serial = SERIAL.lock().unwrap();
        let temp = TempDir::new();
        let root = temp.0.join("root");
        let record = temp.0.join("existing");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&record).unwrap();
        fs::write(record.join("keep"), b"existing").unwrap();
        let request = super::CommandRequest {
            schema: super::REQUEST_SCHEMA.to_owned(),
            program: "/usr/bin/printf".to_owned(),
            args: vec!["native-output".to_owned()],
            cwd: root.to_string_lossy().into_owned(),
            environment: Default::default(),
            required_roots: vec![root.to_string_lossy().into_owned()],
            limits: super::CommandBudgets {
                seconds: 10,
                rss_bytes: u64::MAX,
                workspace_bytes: u64::MAX,
                log_bytes: 1024,
            },
        };
        assert!(super::run_and_record(&request, &request_bytes(&request), &record).is_err());
        assert_eq!(fs::read(record.join("keep")).unwrap(), b"existing");
    }

    #[test]
    fn timeout_log_workspace_and_rss_budgets_refuse_and_keep_partial_records() {
        let _serial = SERIAL.lock().unwrap();
        let temp = TempDir::new();
        let root = temp.0.join("root");
        fs::create_dir(&root).unwrap();
        let sleep_program = if cfg!(target_os = "macos") {
            "/bin/sleep"
        } else {
            "/usr/bin/sleep"
        };
        let cases = [
            (sleep_program, vec!["2"], 0, u64::MAX, u64::MAX, 1024),
            ("/usr/bin/printf", vec!["native"], 10, u64::MAX, u64::MAX, 2),
            ("/usr/bin/true", vec![], 10, u64::MAX, 1, 1024),
            ("/usr/bin/true", vec![], 10, 1, u64::MAX, 1024),
        ];
        for (index, (program, args, seconds, rss, workspace, logs)) in cases.into_iter().enumerate()
        {
            let record = temp.0.join(format!("budget-{index}"));
            let request = test_request(
                program,
                args.into_iter().map(str::to_owned).collect(),
                &root,
                seconds,
                rss,
                workspace,
                logs,
            );
            let result =
                super::run_and_record(&request, &request_bytes(&request), &record).unwrap();
            assert!(!result.passed);
            assert!(record.join("result.json").is_file());
            assert!(record.join("stdout.log").is_file());
            assert!(record.join("stderr.log").is_file());
        }
    }

    #[test]
    fn missing_symlink_and_overlapping_roots_are_refused_before_record_creation() {
        let temp = TempDir::new();
        let root = temp.0.join("root");
        let child = root.join("child");
        let link = temp.0.join("link");
        fs::create_dir_all(&child).unwrap();
        std::os::unix::fs::symlink(&root, &link).unwrap();

        let mut request = test_request(
            "/usr/bin/true",
            Vec::new(),
            &root,
            10,
            u64::MAX,
            u64::MAX,
            1024,
        );
        request.required_roots = vec![
            root.to_string_lossy().into_owned(),
            child.to_string_lossy().into_owned(),
        ];
        let overlap_record = temp.0.join("overlap-record");
        assert!(
            super::run_and_record(&request, &request_bytes(&request), &overlap_record).is_err()
        );
        assert!(!overlap_record.exists());

        request.required_roots = vec![link.to_string_lossy().into_owned()];
        let symlink_record = temp.0.join("symlink-record");
        assert!(
            super::run_and_record(&request, &request_bytes(&request), &symlink_record).is_err()
        );
        assert!(!symlink_record.exists());

        let missing = temp.0.join("missing");
        request.required_roots = vec![missing.to_string_lossy().into_owned()];
        let missing_record = temp.0.join("missing-record");
        assert!(
            super::run_and_record(&request, &request_bytes(&request), &missing_record).is_err()
        );
        assert!(!missing_record.exists());
    }

    #[test]
    fn aggregate_limit_refuses_combined_peak() {
        let own = 4096;
        let child = 8192;
        let budget = 10_000;
        let total = aggregate_rss(own, child).unwrap();
        assert_eq!(total, 12_288);
        assert!(total > budget);
        assert!(super::aggregate_rss_with_limit(own, child, budget).is_err());
    }

    #[test]
    fn finalization_sigterm_keeps_pending_failure_without_authoritative_result() {
        let _serial = SERIAL.lock().unwrap();
        let temp = TempDir::new();
        let root = temp.0.join("root");
        let record_path = temp.0.join("record");
        fs::create_dir(&root).unwrap();
        let request = test_request(
            "/usr/bin/true",
            Vec::new(),
            &root,
            10,
            u64::MAX,
            u64::MAX,
            1024,
        );
        super::FINALIZATION_SIGTERM_HITS.store(0, Ordering::SeqCst);
        super::INJECT_FINALIZATION_SIGTERM.store(true, Ordering::SeqCst);

        let result =
            super::run_and_record(&request, &request_bytes(&request), &record_path).unwrap();

        assert!(!result.passed);
        assert!(!result.result_published);
        assert!(result.pending_retained);
        assert!(result.refusal.as_deref().unwrap().contains("SIGTERM"));
        assert_eq!(result.cli_exit_code(), 128 + libc::SIGTERM);
        assert_eq!(super::FINALIZATION_SIGTERM_HITS.load(Ordering::SeqCst), 1);
        assert!(!record_path.join("result.json").exists());
        assert!(record_path.join("stdout.log").is_file());
        assert!(record_path.join("stderr.log").is_file());
        let pending: serde_json::Value =
            serde_json::from_slice(&fs::read(record_path.join("result.pending.json")).unwrap())
                .unwrap();
        assert!(pending["resource_report"].is_object());
    }

    #[test]
    fn pending_sync_failure_cannot_publish_authoritative_pass() {
        let _serial = SERIAL.lock().unwrap();
        let temp = TempDir::new();
        let root = temp.0.join("root");
        let record_path = temp.0.join("record");
        fs::create_dir(&root).unwrap();
        let request = test_request(
            "/usr/bin/true",
            Vec::new(),
            &root,
            10,
            u64::MAX,
            u64::MAX,
            1024,
        );
        let syncs_before = super::PENDING_SYNC_CALLS.load(Ordering::SeqCst);
        super::FAIL_NEXT_PENDING_SYNC.store(true, Ordering::SeqCst);

        let result =
            super::run_and_record(&request, &request_bytes(&request), &record_path).unwrap();

        assert!(!result.passed);
        assert!(!result.result_published);
        assert!(result.pending_retained);
        assert!(result.refusal.as_deref().unwrap().contains("sync"));
        assert_eq!(
            super::PENDING_SYNC_CALLS.load(Ordering::SeqCst) - syncs_before,
            1
        );
        assert!(!record_path.join("result.json").exists());
        assert!(record_path.join("stdout.log").is_file());
        assert!(record_path.join("stderr.log").is_file());
        let pending: serde_json::Value =
            serde_json::from_slice(&fs::read(record_path.join("result.pending.json")).unwrap())
                .unwrap();
        assert!(pending["resource_report"].is_object());
    }
}

//! Resource sampling composed with bounded direct-child output capture.
//!
//! This is an observer for trusted same-UID host tools, not process
//! containment. Process-table reads are samples, directory walks are not
//! atomic snapshots, and same-UID writers may race between checks. Sampled
//! process IDs and groups are linkage data only; this module never signals
//! them. It relies on `process_capture` to supervise only its leased child and
//! original process group.

#[cfg(target_os = "macos")]
#[path = "macos_process_snapshot.rs"]
mod macos_process_snapshot;

#[cfg(not(target_os = "macos"))]
use crate::process_snapshot;
use crate::{
    Refusal,
    directory::Directory,
    ownership,
    process_capture::{
        self, CaptureError, CaptureLimits, CaptureObservation, CaptureObservationPhase,
        CapturedProcess, CommandSpec,
    },
    process_snapshot::{ProcessRow, ScopeSnapshot},
    workspace_accounting::{self, Accounting, ScanLimits},
};
use serde::Serialize;
#[cfg(any(not(target_os = "macos"), test))]
use std::time::Duration;
use std::{
    error::Error,
    fmt, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[cfg(not(target_os = "macos"))]
const PS_CAPTURE_LIMITS: CaptureLimits = CaptureLimits {
    timeout: Duration::from_secs(2),
    stdout_bytes: 2 * 1024 * 1024,
    stderr_bytes: 64 * 1024,
    termination_grace: Duration::from_secs(2),
};

/// Caller-selected resource thresholds. No application-wide defaults are
/// imposed by this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub max_visible_rss_bytes: u64,
    pub max_workspace_bytes: u64,
    pub max_log_bytes: u64,
}

/// Bounds for each process-table sample, the accumulated linkage history, and
/// each required managed-root walk. Every supplied root is required; a root
/// that disappears or is replaced causes observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleLimits {
    pub max_ps_bytes: usize,
    pub max_ps_rows: usize,
    pub max_history_entries: usize,
    pub max_roots: usize,
    pub scan: ScanLimits,
}

/// Highest observed values and the latest sampled scope. Historical process
/// groups can remain listed after they empty; only current rows outside the
/// original group set `incomplete_cleanup`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ResourceReport {
    pub sample_count: u64,
    /// True only after this sample's process scope and every required root
    /// have been collected. Peaks from earlier complete samples are retained.
    pub last_sample_complete: bool,
    pub current_visible_rss_bytes: u64,
    pub peak_visible_rss_bytes: u64,
    pub current_workspace_bytes: u64,
    pub peak_workspace_bytes: u64,
    pub current_disk_log_bytes: u64,
    pub current_pending_output_bytes: u64,
    pub current_log_bytes: u64,
    pub peak_log_bytes: u64,
    pub visible_process_ids: Vec<u32>,
    /// Includes remembered groups from prior samples. This list grants no
    /// authority to signal those groups.
    pub observed_process_groups: Vec<u32>,
    /// Only groups present in current in-scope rows outside the direct child's
    /// original process group appear here.
    pub current_escaped_process_groups: Vec<u32>,
    pub incomplete_cleanup: bool,
}

/// A successful capture and its sampled resource report. The direct child's
/// nonzero exit status remains available in `process.status`.
#[derive(Debug)]
pub struct ResourceCapturedProcess {
    pub process: CapturedProcess,
    pub report: ResourceReport,
}

/// Capture or host-observation failure, with partial resource peaks retained.
#[derive(Debug)]
pub enum ResourceCaptureError {
    Setup {
        error: io::Error,
        report: Box<ResourceReport>,
    },
    Capture {
        error: CaptureError,
        report: Box<ResourceReport>,
    },
}

impl ResourceCaptureError {
    pub fn report(&self) -> &ResourceReport {
        match self {
            Self::Setup { report, .. } | Self::Capture { report, .. } => report,
        }
    }
}

impl fmt::Display for ResourceCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup { error, .. } => {
                write!(formatter, "resource observer setup failed: {error}")
            }
            Self::Capture { error, .. } => {
                write!(formatter, "resource-observed capture failed: {error}")
            }
        }
    }
}

impl Error for ResourceCaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Setup { error, .. } => Some(error),
            Self::Capture { error, .. } => Some(error),
        }
    }
}

/// Capture one command while sampling its visible process scope and required
/// managed roots. Root order and overlap are preserved, so overlapping roots
/// are counted once per supplied root, matching the caller's historical
/// accounting inputs.
pub fn capture_with_resources(
    spec: &CommandSpec,
    capture_limits: CaptureLimits,
    resource_limits: ResourceLimits,
    sample_limits: SampleLimits,
    required_roots: &[PathBuf],
    cancelled: impl FnMut() -> bool,
) -> std::result::Result<ResourceCapturedProcess, ResourceCaptureError> {
    capture_with_resources_observed(
        spec,
        capture_limits,
        resource_limits,
        sample_limits,
        required_roots,
        cancelled,
        |_| Ok(()),
    )
}

/// As `capture_with_resources`, invoking one additional fallible observer at
/// every bounded capture pass. The extra observer runs before resource
/// sampling, allowing a caller to enforce a cheap local bound before a
/// potentially more expensive process-table and directory sample.
pub(crate) fn capture_with_resources_observed(
    spec: &CommandSpec,
    capture_limits: CaptureLimits,
    resource_limits: ResourceLimits,
    sample_limits: SampleLimits,
    required_roots: &[PathBuf],
    cancelled: impl FnMut() -> bool,
    mut additional_observer: impl FnMut(CaptureObservation) -> io::Result<()>,
) -> std::result::Result<ResourceCapturedProcess, ResourceCaptureError> {
    validate_sample_limits(sample_limits, required_roots.len()).map_err(|error| {
        ResourceCaptureError::Setup {
            error,
            report: Box::default(),
        }
    })?;
    let roots = open_required_roots(required_roots, sample_limits.max_roots).map_err(|error| {
        ResourceCaptureError::Setup {
            error,
            report: Box::default(),
        }
    })?;

    let mut observer = ResourceObserver {
        roots,
        resource_limits,
        sample_limits,
        report: ResourceReport::default(),
        root_pid: None,
        previous_pids: Vec::new(),
        previous_groups: Vec::new(),
    };
    let result = process_capture::capture_observed(spec, capture_limits, cancelled, |event| {
        additional_observer(event)?;
        observer.observe(event)
    });
    let report = observer.report;
    match result {
        Ok(process) => Ok(ResourceCapturedProcess { process, report }),
        Err(error) => Err(ResourceCaptureError::Capture {
            error,
            report: Box::new(report),
        }),
    }
}

fn validate_sample_limits(limits: SampleLimits, root_count: usize) -> io::Result<()> {
    if limits.max_ps_bytes == 0
        || limits.max_ps_rows == 0
        || limits.max_history_entries == 0
        || limits.max_roots == 0
    {
        return Err(input_error("resource observer bounds must be positive"));
    }
    if root_count == 0 {
        return Err(input_error("at least one required managed root is needed"));
    }
    if root_count > limits.max_roots {
        return Err(input_error(
            "required managed-root count exceeds caller bound",
        ));
    }
    Ok(())
}

fn open_required_roots(paths: &[PathBuf], maximum: usize) -> io::Result<Vec<ProtectedRoot>> {
    if paths.len() > maximum {
        return Err(input_error(
            "required managed-root count exceeds caller bound",
        ));
    }
    let mut roots = Vec::new();
    roots
        .try_reserve(paths.len())
        .map_err(|_| allocation_error("could not allocate bounded managed-root list"))?;
    for path in paths {
        roots.push(ProtectedRoot::open(path)?);
    }
    Ok(roots)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
        }
    }
}

struct ProtectedRoot {
    path: PathBuf,
    directory: Directory,
    identity: DirectoryIdentity,
}

impl ProtectedRoot {
    fn open(path: &Path) -> io::Result<Self> {
        let directory = ownership::protected_directory(path).map_err(refusal_to_io)?;
        let metadata = directory.metadata().map_err(refusal_to_io)?;
        validate_managed_root_leaf(&metadata)?;
        Ok(Self {
            path: path.to_path_buf(),
            directory,
            identity: DirectoryIdentity::from_metadata(&metadata),
        })
    }

    fn verify_namespace(&self) -> io::Result<()> {
        let retained = self.directory.metadata().map_err(refusal_to_io)?;
        validate_managed_root_leaf(&retained)?;
        if DirectoryIdentity::from_metadata(&retained) != self.identity {
            return Err(input_error(
                "retained managed-root descriptor changed identity",
            ));
        }
        let current = ownership::protected_directory(&self.path).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("required managed root is missing or unsafe: {error}"),
            )
        })?;
        let current_metadata = current.metadata().map_err(refusal_to_io)?;
        validate_managed_root_leaf(&current_metadata)?;
        if DirectoryIdentity::from_metadata(&current_metadata) != self.identity {
            return Err(input_error(
                "required managed root was replaced during observation",
            ));
        }
        Ok(())
    }
}

fn validate_managed_root_leaf(metadata: &std::fs::Metadata) -> io::Result<()> {
    if !metadata.is_dir() {
        return Err(input_error("required managed root is not a directory"));
    }
    if ![0, effective_uid()].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(input_error(
            "required managed-root leaf must be root/current-user owned and not group/world writable",
        ));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "The effective UID is read solely to validate the managed-root leaf owner."
)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no pointers and only reads the current process UID.
    unsafe { libc::geteuid() as u32 }
}

struct ResourceObserver {
    roots: Vec<ProtectedRoot>,
    resource_limits: ResourceLimits,
    sample_limits: SampleLimits,
    report: ResourceReport,
    root_pid: Option<u32>,
    previous_pids: Vec<u32>,
    previous_groups: Vec<u32>,
}

impl ResourceObserver {
    fn observe(&mut self, event: CaptureObservation) -> io::Result<()> {
        if event.direct_pid == 0 {
            return Err(input_error("capture supplied an invalid direct-child PID"));
        }
        match self.root_pid {
            Some(root_pid) if root_pid != event.direct_pid => {
                return Err(input_error(
                    "capture changed direct-child PID during observation",
                ));
            }
            None => self.root_pid = Some(event.direct_pid),
            _ => {}
        }

        // Pending pipe bytes are not yet present in the on-disk log tree. Add
        // them once to the most recent disk sample at every bounded drain pass.
        self.check_pending_log_bytes(event.stdout_bytes, event.stderr_bytes)?;

        match event.phase {
            CaptureObservationPhase::Running { sample_due: true }
            | CaptureObservationPhase::BeforeReap => {
                let final_sample = event.phase == CaptureObservationPhase::BeforeReap;
                self.take_sample(event)?;
                self.check_pending_log_bytes(event.stdout_bytes, event.stderr_bytes)?;
                if final_sample {
                    self.check_before_reap(event.direct_pid)?;
                }
            }
            CaptureObservationPhase::Running { sample_due: false } => {}
        }
        Ok(())
    }

    fn check_pending_log_bytes(&mut self, stdout: usize, stderr: usize) -> io::Result<()> {
        let pending = usize_to_u64(stdout)?
            .checked_add(usize_to_u64(stderr)?)
            .ok_or_else(|| input_error("pending captured output byte sum overflows"))?;
        let current = self
            .report
            .current_disk_log_bytes
            .checked_add(pending)
            .ok_or_else(|| input_error("aggregate log byte sum overflows"))?;
        self.report.current_pending_output_bytes = pending;
        self.report.current_log_bytes = current;
        self.report.peak_log_bytes = self.report.peak_log_bytes.max(current);
        check_resource_limits(
            self.resource_limits,
            self.report.current_visible_rss_bytes,
            self.report.current_workspace_bytes,
            current,
        )
    }

    fn take_sample(&mut self, event: CaptureObservation) -> io::Result<()> {
        self.report.last_sample_complete = false;
        self.report.current_visible_rss_bytes = 0;
        self.report.current_workspace_bytes = 0;
        self.report.current_disk_log_bytes = 0;
        self.report.current_pending_output_bytes =
            pending_output_bytes(event.stdout_bytes, event.stderr_bytes)?;
        self.report.current_log_bytes = self.report.current_pending_output_bytes;
        self.report.peak_log_bytes = self
            .report
            .peak_log_bytes
            .max(self.report.current_log_bytes);
        self.report.visible_process_ids.clear();
        self.report.observed_process_groups.clear();
        self.report.current_escaped_process_groups.clear();
        self.report.incomplete_cleanup = false;

        #[cfg(target_os = "macos")]
        let scope = self.query_process_table(event.direct_pid)?;
        #[cfg(not(target_os = "macos"))]
        let snapshot = self.query_process_table()?;
        #[cfg(not(target_os = "macos"))]
        let scope = process_snapshot::observe_scope(
            &snapshot,
            event.direct_pid,
            &self.previous_pids,
            &self.previous_groups,
            self.sample_limits.max_history_entries,
        )
        .map_err(|error| input_error(format!("could not compute process scope: {error}")))?;
        self.report.sample_count = self
            .report
            .sample_count
            .checked_add(1)
            .ok_or_else(|| input_error("resource sample counter overflow"))?;
        self.report.visible_process_ids = try_copy_slice(&scope.process_ids)?;
        self.report.observed_process_groups = try_copy_slice(&scope.process_groups)?;
        self.report.current_escaped_process_groups =
            current_escaped_groups(&scope.rows, event.direct_pid)?;
        self.report.incomplete_cleanup = !self.report.current_escaped_process_groups.is_empty();
        if scope.process_ids.contains(&std::process::id()) {
            return Err(input_error(
                "observed process scope contains the resource-observer process",
            ));
        }
        self.report.current_visible_rss_bytes = scope.rss_bytes;
        self.report.peak_visible_rss_bytes =
            self.report.peak_visible_rss_bytes.max(scope.rss_bytes);
        if !scope.root_present {
            return Err(input_error(
                "direct-child PID is missing from the required process-table sample",
            ));
        }

        self.extend_history(&scope)?;
        let mut accounting = Accounting::default();
        for index in 0..self.roots.len() {
            let remaining = ScanLimits {
                max_entries: self
                    .sample_limits
                    .scan
                    .max_entries
                    .checked_sub(accounting.entries_seen)
                    .ok_or_else(|| input_error("aggregate scan-entry bound exceeded"))?,
                max_work_units: self
                    .sample_limits
                    .scan
                    .max_work_units
                    .checked_sub(accounting.work_units)
                    .ok_or_else(|| input_error("aggregate scan-work bound exceeded"))?,
            };
            let current = {
                let root = &self.roots[index];
                root.verify_namespace()?;
                workspace_accounting::scan_directory(&root.directory, remaining).map_err(
                    |error| input_error(format!("managed-root accounting failed: {error}")),
                )?
            };
            accounting = add_accounting(accounting, current)?;
            self.record_disk_sample(accounting, event.stdout_bytes, event.stderr_bytes)?;
            self.roots[index].verify_namespace()?;
        }
        self.report.last_sample_complete = true;
        check_resource_limits(
            self.resource_limits,
            self.report.current_visible_rss_bytes,
            self.report.current_workspace_bytes,
            self.report.current_log_bytes,
        )
    }

    fn record_disk_sample(
        &mut self,
        accounting: Accounting,
        stdout_bytes: usize,
        stderr_bytes: usize,
    ) -> io::Result<()> {
        let pending = pending_output_bytes(stdout_bytes, stderr_bytes)?;
        let log_bytes = accounting
            .log_file_bytes
            .checked_add(pending)
            .ok_or_else(|| input_error("aggregate log byte sum overflows"))?;
        self.report.current_workspace_bytes = accounting.regular_file_bytes;
        self.report.peak_workspace_bytes = self
            .report
            .peak_workspace_bytes
            .max(accounting.regular_file_bytes);
        self.report.current_disk_log_bytes = accounting.log_file_bytes;
        self.report.current_pending_output_bytes = pending;
        self.report.current_log_bytes = log_bytes;
        self.report.peak_log_bytes = self.report.peak_log_bytes.max(log_bytes);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn query_process_table(&self, target_pid: u32) -> io::Result<ScopeSnapshot> {
        macos_process_snapshot::query_process_scope(
            target_pid,
            &self.previous_pids,
            &self.previous_groups,
            self.sample_limits.max_ps_bytes,
            self.sample_limits.max_ps_rows,
            self.sample_limits.max_history_entries,
        )
    }

    #[cfg(not(target_os = "macos"))]
    fn query_process_table(&self) -> io::Result<process_snapshot::ProcessSnapshot> {
        use std::{collections::BTreeMap, ffi::OsString};

        let env = BTreeMap::from([(OsString::from("LC_ALL"), OsString::from("C"))]);
        let spec = CommandSpec::new(
            "/bin/ps",
            [
                OsString::from("-axo"),
                OsString::from("pid=,ppid=,pgid=,rss="),
            ],
            "/",
            env,
        );
        let output = process_capture::capture(&spec, PS_CAPTURE_LIMITS, || false)
            .map_err(|error| input_error(format!("bounded /bin/ps capture failed: {error}")))?;
        if !output.status.success() {
            return Err(input_error(format!(
                "bounded /bin/ps exited unsuccessfully ({})",
                output.status
            )));
        }
        process_snapshot::parse_ps_snapshot(
            &output.stdout,
            self.sample_limits.max_ps_bytes,
            self.sample_limits.max_ps_rows,
        )
        .map_err(|error| input_error(format!("could not parse /bin/ps output: {error}")))
    }

    fn extend_history(&mut self, scope: &ScopeSnapshot) -> io::Result<()> {
        // Count every candidate element, including values duplicated across
        // old and new slices, before reserving or extending either history.
        validate_history_growth(
            &self.previous_pids,
            &self.previous_groups,
            &scope.process_ids,
            &scope.process_groups,
            self.sample_limits.max_history_entries,
        )?;
        extend_unique_history(&mut self.previous_pids, &scope.process_ids)?;
        extend_unique_history(&mut self.previous_groups, &scope.process_groups)?;
        Ok(())
    }

    fn check_before_reap(&self, direct_pid: u32) -> io::Result<()> {
        if self.report.incomplete_cleanup {
            return Err(input_error(
                "current process scope contains a member outside the original process group",
            ));
        }
        if self
            .report
            .visible_process_ids
            .iter()
            .any(|process_id| *process_id != direct_pid)
        {
            return Err(input_error(
                "process-table sample still contains non-root members before reap",
            ));
        }
        Ok(())
    }
}

fn validate_history_growth(
    previous_pids: &[u32],
    previous_groups: &[u32],
    new_pids: &[u32],
    new_groups: &[u32],
    maximum: usize,
) -> io::Result<()> {
    let attempted = previous_pids
        .len()
        .checked_add(previous_groups.len())
        .and_then(|count| count.checked_add(new_pids.len()))
        .and_then(|count| count.checked_add(new_groups.len()))
        .ok_or_else(|| input_error("process-history size overflows"))?;
    if attempted > maximum {
        return Err(input_error(
            "combined process-history slices exceed caller entry bound",
        ));
    }
    Ok(())
}

fn extend_unique_history(history: &mut Vec<u32>, candidates: &[u32]) -> io::Result<()> {
    history
        .try_reserve(candidates.len())
        .map_err(|_| allocation_error("could not grow bounded process history"))?;
    history.extend_from_slice(candidates);
    history.sort_unstable();
    history.dedup();
    Ok(())
}

fn add_accounting(left: Accounting, right: Accounting) -> io::Result<Accounting> {
    Ok(Accounting {
        regular_file_bytes: left
            .regular_file_bytes
            .checked_add(right.regular_file_bytes)
            .ok_or_else(|| input_error("aggregate workspace byte sum overflows"))?,
        log_file_bytes: left
            .log_file_bytes
            .checked_add(right.log_file_bytes)
            .ok_or_else(|| input_error("aggregate disk-log byte sum overflows"))?,
        entries_seen: left
            .entries_seen
            .checked_add(right.entries_seen)
            .ok_or_else(|| input_error("aggregate scan-entry counter overflows"))?,
        work_units: left
            .work_units
            .checked_add(right.work_units)
            .ok_or_else(|| input_error("aggregate scan-work counter overflows"))?,
    })
}

fn check_resource_limits(
    limits: ResourceLimits,
    visible_rss: u64,
    workspace: u64,
    logs: u64,
) -> io::Result<()> {
    if visible_rss > limits.max_visible_rss_bytes {
        return Err(input_error("visible process RSS exceeds caller limit"));
    }
    if workspace > limits.max_workspace_bytes {
        return Err(input_error("managed workspace bytes exceed caller limit"));
    }
    if logs > limits.max_log_bytes {
        return Err(input_error("aggregate log bytes exceed caller limit"));
    }
    Ok(())
}

fn try_copy_slice<T: Copy>(source: &[T]) -> io::Result<Vec<T>> {
    let mut copy = Vec::new();
    copy.try_reserve(source.len())
        .map_err(|_| allocation_error("could not retain bounded process sample"))?;
    copy.extend_from_slice(source);
    Ok(copy)
}

fn usize_to_u64(value: usize) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| input_error("captured output length exceeds u64"))
}

fn pending_output_bytes(stdout: usize, stderr: usize) -> io::Result<u64> {
    usize_to_u64(stdout)?
        .checked_add(usize_to_u64(stderr)?)
        .ok_or_else(|| input_error("pending captured output byte sum overflows"))
}

fn refusal_to_io(error: Refusal) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn input_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn allocation_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn current_escaped_groups(rows: &[ProcessRow], original_group: u32) -> io::Result<Vec<u32>> {
    let mut groups = Vec::new();
    groups
        .try_reserve(rows.len())
        .map_err(|_| allocation_error("could not retain escaped process groups"))?;
    for row in rows {
        if row.pgid != original_group {
            groups.push(row.pgid);
        }
    }
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_capture::CaptureCause;
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        fs,
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let uncanonicalized_path = std::env::temp_dir().join(format!(
                "ami-rust-resource-capture-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&uncanonicalized_path).unwrap();
            let path = fs::canonicalize(uncanonicalized_path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits(max_log: u64, max_workspace: u64, max_rss: u64) -> ResourceLimits {
        ResourceLimits {
            max_visible_rss_bytes: max_rss,
            max_workspace_bytes: max_workspace,
            max_log_bytes: max_log,
        }
    }

    fn sample_limits() -> SampleLimits {
        SampleLimits {
            max_ps_bytes: 2 * 1024 * 1024,
            max_ps_rows: 32_768,
            max_history_entries: 32_768,
            max_roots: 8,
            scan: ScanLimits {
                max_entries: 100_000,
                max_work_units: 200_001,
            },
        }
    }

    fn echo_spec(message: &str) -> CommandSpec {
        CommandSpec::new("/bin/echo", [OsString::from(message)], "/", BTreeMap::new())
    }

    fn rss_fixture_spec(root: &Path) -> CommandSpec {
        let executable = std::env::current_exe().unwrap();
        let args = [
            OsString::from("--ignored"),
            OsString::from("--nocapture"),
            OsString::from("rss_subprocess_fixture_allocates"),
        ];
        let env = BTreeMap::from([
            (
                OsString::from("AMI_RUST_RESOURCE_RSS_FIXTURE"),
                OsString::from("allocate"),
            ),
            (
                OsString::from("AMI_RUST_RESOURCE_RSS_STARTED"),
                root.join("rss-allocation-started").into_os_string(),
            ),
            (
                OsString::from("AMI_RUST_RESOURCE_RSS_SURVIVED"),
                root.join("rss-survived").into_os_string(),
            ),
        ]);
        CommandSpec::new(executable.into_os_string(), args, "/", env)
    }

    fn capture_echo(
        root: &Path,
        resource_limits: ResourceLimits,
    ) -> std::result::Result<ResourceCapturedProcess, ResourceCaptureError> {
        capture_with_resources(
            &echo_spec("new"),
            CaptureLimits {
                timeout: Duration::from_secs(5),
                stdout_bytes: 4096,
                stderr_bytes: 4096,
                termination_grace: Duration::from_millis(100),
            },
            resource_limits,
            sample_limits(),
            &[root.to_path_buf()],
            || false,
        )
    }

    fn capture_rss_fixture(
        root: &Path,
        max_visible_rss_bytes: u64,
    ) -> std::result::Result<ResourceCapturedProcess, ResourceCaptureError> {
        capture_with_resources(
            &rss_fixture_spec(root),
            CaptureLimits {
                timeout: Duration::from_secs(5),
                stdout_bytes: 64 * 1024,
                stderr_bytes: 64 * 1024,
                termination_grace: Duration::from_millis(500),
            },
            limits(u64::MAX, u64::MAX, max_visible_rss_bytes),
            sample_limits(),
            &[root.to_path_buf()],
            || false,
        )
    }

    #[test]
    fn native_capture_combines_existing_logs_with_pending_output_once() {
        let directory = TestDirectory::new();
        fs::write(directory.path().join("previous.log"), b"old").unwrap();
        let captured = capture_echo(directory.path(), limits(7, 3, u64::MAX)).unwrap();
        assert_eq!(captured.process.stdout, b"new\n");
        assert_eq!(captured.report.current_disk_log_bytes, 3);
        assert_eq!(captured.report.current_pending_output_bytes, 4);
        assert_eq!(captured.report.peak_log_bytes, 7);
        assert_eq!(captured.report.peak_workspace_bytes, 3);
        assert!(captured.report.sample_count >= 2);
    }

    #[test]
    fn native_capture_refuses_combined_existing_and_pending_log_excess() {
        let directory = TestDirectory::new();
        fs::write(directory.path().join("previous.log"), b"old").unwrap();
        let error = capture_echo(directory.path(), limits(6, 3, u64::MAX)).unwrap_err();
        let ResourceCaptureError::Capture { error, report } = error else {
            panic!("capture should report the observer refusal through capture");
        };
        assert!(matches!(error.cause, CaptureCause::Observation(_)));
        assert_eq!(report.peak_log_bytes, 7);
    }

    #[test]
    fn native_capture_retains_measured_logs_when_workspace_and_log_limits_fail() {
        let directory = TestDirectory::new();
        fs::write(directory.path().join("previous.log"), b"old").unwrap();
        fs::write(directory.path().join("payload.bin"), b"four").unwrap();
        let error = capture_echo(directory.path(), limits(6, 3, u64::MAX)).unwrap_err();
        let ResourceCaptureError::Capture { error, report } = error else {
            panic!("capture should report resource refusal through capture");
        };
        assert!(matches!(error.cause, CaptureCause::Observation(_)));
        assert_eq!(report.current_workspace_bytes, 7);
        assert_eq!(report.peak_workspace_bytes, 7);
        assert_eq!(report.current_disk_log_bytes, 3);
        assert_eq!(report.current_pending_output_bytes, 4);
        assert_eq!(report.current_log_bytes, 7);
        assert_eq!(report.peak_log_bytes, 7);
        assert!(report.last_sample_complete);
    }

    #[test]
    fn live_rss_limit_terminates_the_owned_fixture_and_retains_measurement() {
        let directory = TestDirectory::new();
        let limit = 64 * 1024 * 1024;
        let error = capture_rss_fixture(directory.path(), limit).unwrap_err();
        let ResourceCaptureError::Capture { error, report } = error else {
            panic!("RSS refusal should be reported through capture");
        };
        assert!(matches!(error.cause, CaptureCause::Observation(_)));
        assert!(report.peak_visible_rss_bytes > limit);
        assert!(report.last_sample_complete);
        assert!(
            directory.path().join("rss-allocation-started").exists(),
            "fixture must mark allocation start before growing its working set"
        );
        assert!(
            !directory.path().join("rss-survived").exists(),
            "the fixture reached its post-sleep marker after an RSS refusal"
        );
        assert_eq!(
            error.status.as_ref().and_then(ExitStatusExt::signal),
            Some(libc::SIGTERM),
            "the owned fixture must terminate from group SIGTERM; status={:?}, cleanup_error={:?}",
            error.status,
            error.cleanup_error
        );
        #[cfg(target_os = "macos")]
        if let Some(cleanup) = &error.cleanup_error {
            assert_eq!(
                cleanup.raw_os_error(),
                Some(libc::EPERM),
                "unexpected cleanup failure: {cleanup}"
            );
            // Some macOS kernels reject the final signal to a group whose
            // only member is the already-exited unreaped child. Preserve the
            // error; the observed wait status proves only this child's exit.
            eprintln!("RSS control retained cleanup error: {cleanup}");
        }
        #[cfg(target_os = "linux")]
        assert!(
            error.cleanup_error.is_none(),
            "unexpected cleanup failure after the owned fixture exited: {:?}",
            error.cleanup_error
        );
    }

    #[test]
    fn generous_live_rss_limit_accepts_the_owned_fixture() {
        let directory = TestDirectory::new();
        let minimum = 64 * 1024 * 1024;
        let captured = capture_rss_fixture(directory.path(), 256 * 1024 * 1024).unwrap();
        assert!(captured.report.peak_visible_rss_bytes >= minimum);
        assert!(captured.report.last_sample_complete);
        assert!(directory.path().join("rss-allocation-started").exists());
        assert!(directory.path().join("rss-survived").exists());
        assert_eq!(captured.process.exit_code(), Some(0));
    }

    #[test]
    #[ignore = "spawned only by the resource-observer RSS integration tests"]
    fn rss_subprocess_fixture_allocates() {
        if std::env::var_os("AMI_RUST_RESOURCE_RSS_FIXTURE").is_none() {
            return;
        }
        let started_marker = std::env::var_os("AMI_RUST_RESOURCE_RSS_STARTED")
            .expect("subprocess fixture receives its allocation-start marker path");
        let survived_marker = std::env::var_os("AMI_RUST_RESOURCE_RSS_SURVIVED")
            .expect("subprocess fixture receives its post-sleep marker path");
        // This marker only records entry into the allocation phase. It must
        // exist even when the observer terminates the fixture while pages are
        // still being committed; the separate survived marker is written only
        // after every page has been touched and the dwell interval completes.
        fs::write(started_marker, b"allocation-started").unwrap();
        let mut working_set = vec![0_u8; 96 * 1024 * 1024];
        for page in working_set.chunks_mut(4096) {
            page[0] = 0xa5;
        }
        assert_eq!(std::hint::black_box(&working_set)[0], 0xa5);
        std::thread::sleep(Duration::from_millis(800));
        fs::write(survived_marker, b"survived").unwrap();
    }

    #[test]
    fn replaced_required_root_is_detected_against_retained_identity() {
        let parent = TestDirectory::new();
        let root = parent.path().join("managed");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let retained = ProtectedRoot::open(&root).unwrap();
        let old = parent.path().join("old-managed");
        fs::rename(&root, &old).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(retained.verify_namespace().is_err());
    }

    #[test]
    fn missing_required_root_is_not_treated_as_zero() {
        let parent = TestDirectory::new();
        let root = parent.path().join("managed");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let retained = ProtectedRoot::open(&root).unwrap();
        fs::remove_dir(&root).unwrap();
        assert!(retained.verify_namespace().is_err());
    }

    #[test]
    fn shared_writable_managed_root_leaf_is_refused() {
        let parent = TestDirectory::new();
        let root = parent.path().join("managed");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ProtectedRoot::open(&root).is_err());
    }

    #[test]
    fn resource_thresholds_and_history_count_are_checked_before_growth() {
        assert!(check_resource_limits(limits(3, 3, 3), 4, 0, 0).is_err());
        assert!(check_resource_limits(limits(3, 3, 3), 0, 4, 0).is_err());
        assert!(check_resource_limits(limits(3, 3, 3), 0, 0, 4).is_err());
        assert!(validate_history_growth(&[1, 1], &[1], &[1], &[1], 4).is_err());
        assert!(validate_history_growth(&[1, 1], &[1], &[1], &[1], 5).is_ok());
    }

    #[test]
    fn large_history_merge_sorts_and_deduplicates() {
        let mut history = (0..20_000).rev().collect::<Vec<u32>>();
        let candidates = (10_000..30_000).rev().collect::<Vec<u32>>();
        validate_history_growth(&history, &[], &candidates, &[], 40_000).unwrap();
        extend_unique_history(&mut history, &candidates).unwrap();
        assert_eq!(history.len(), 30_000);
        assert!(history.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(history.first(), Some(&0));
        assert_eq!(history.last(), Some(&29_999));
    }

    #[test]
    fn currently_observed_escaped_group_is_distinct_from_remembered_empty_group() {
        let rows = [
            ProcessRow {
                pid: 10,
                ppid: 1,
                pgid: 10,
                rss_kib: 1,
            },
            ProcessRow {
                pid: 11,
                ppid: 10,
                pgid: 11,
                rss_kib: 1,
            },
        ];
        let current = current_escaped_groups(&rows, 10).unwrap();
        assert_eq!(current, vec![11]);
        assert!(current_escaped_groups(&rows[..1], 10).unwrap().is_empty());

        let many_rows = (0..20_000)
            .map(|index| ProcessRow {
                pid: index + 1,
                ppid: 0,
                pgid: (index % 1_000) + 2,
                rss_kib: 0,
            })
            .collect::<Vec<_>>();
        let many_groups = current_escaped_groups(&many_rows, 1).unwrap();
        assert_eq!(many_groups.len(), 1_000);
        assert!(many_groups.windows(2).all(|pair| pair[0] < pair[1]));
    }
}

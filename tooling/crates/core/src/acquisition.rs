//! Bounded acquisition of one pinned HTTPS object through an explicitly
//! identified system curl executable.
//!
//! Redirects are handled one response at a time. Curl is never asked to follow
//! a redirect; the next URL is checked against the pin before another request
//! is started. The response is written to an exclusive sibling staging file,
//! then size and SHA-256 are checked before an atomic no-replace publication.
//! These APIs assume another process with the same UID does not race the
//! caller's verified executable or staging path; retained parent descriptors
//! protect publication from replacement of the destination's path ancestors.

use crate::{
    Refusal, Result,
    digest::{encode_hex, is_sha256_digest},
    directory::Directory,
    ownership::{self, FreshTarget},
    process_capture::{CaptureCause, CaptureLimits, CommandSpec},
    resource_capture::{self, ResourceCaptureError, ResourceLimits, ResourceReport, SampleLimits},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_URL_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CURL_STDERR_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: u8 = 5;
const MAX_CURL_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const WRITE_OUT_MARKER: &[u8] = b"\nAMIRUST-ACQUISITION-RESULT-V1\n";
const WRITE_OUT_FORMAT: &str = "\nAMIRUST-ACQUISITION-RESULT-V1\n%{http_code}\n%{redirect_url}\n";
static NEXT_STAGING_NAME: AtomicU64 = AtomicU64::new(0);

/// One HTTPS origin supported by the existing CI download pins.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpsOrigin {
    StaticRustLang,
    Github,
    RawGithub,
    GithubReleaseAssets,
    GithubObjects,
}

impl HttpsOrigin {
    fn host(self) -> &'static str {
        match self {
            Self::StaticRustLang => "static.rust-lang.org",
            Self::Github => "github.com",
            Self::RawGithub => "raw.githubusercontent.com",
            Self::GithubReleaseAssets => "release-assets.githubusercontent.com",
            Self::GithubObjects => "objects.githubusercontent.com",
        }
    }

    fn is_cdn(self) -> bool {
        matches!(self, Self::GithubReleaseAssets | Self::GithubObjects)
    }
}

/// Authenticated metadata for a single object expected from a release pin.
/// The URL is intentionally omitted from `Debug` output because it may carry
/// a short-lived query token.
pub struct DownloadPin {
    url: String,
    expected_bytes: u64,
    expected_sha256: String,
    origin: HttpsOrigin,
    redirect_origins: Vec<HttpsOrigin>,
}

impl std::fmt::Debug for DownloadPin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DownloadPin")
            .field("url", &"<redacted>")
            .field("expected_bytes", &self.expected_bytes)
            .field("expected_sha256", &self.expected_sha256)
            .field("origin", &self.origin)
            .field("redirect_origins", &self.redirect_origins)
            .finish()
    }
}

impl DownloadPin {
    /// Construct a pin after checking its exact initial origin and redirect
    /// allowlist. Static Rust downloads may not redirect; GitHub downloads may
    /// name either of the two CDN origins used by the legacy CI downloader.
    pub fn new(
        url: impl Into<String>,
        expected_bytes: u64,
        expected_sha256: impl Into<String>,
        origin: HttpsOrigin,
        redirect_origins: impl IntoIterator<Item = HttpsOrigin>,
    ) -> Result<Self> {
        let url = url.into();
        let expected_sha256 = expected_sha256.into();
        if expected_bytes == 0 || expected_bytes > i64::MAX as u64 {
            return Err(Refusal::new(
                "pinned download size must be positive and representable",
            ));
        }
        if !is_sha256_digest(&expected_sha256) {
            return Err(Refusal::new(
                "pinned download digest must be lowercase SHA-256 hex",
            ));
        }
        if !matches!(origin, HttpsOrigin::StaticRustLang | HttpsOrigin::Github | HttpsOrigin::RawGithub) {
            return Err(Refusal::new(
                "pinned download origin is not a permitted source",
            ));
        }
        validate_url_for_origin(&url, origin)?;

        let mut redirects = Vec::new();
        for redirect in redirect_origins {
            if !redirect.is_cdn() || origin != HttpsOrigin::Github {
                return Err(Refusal::new(
                    "pinned download redirect origin is not permitted",
                ));
            }
            if redirects.contains(&redirect) {
                return Err(Refusal::new(
                    "pinned download redirect origin is duplicated",
                ));
            }
            redirects.push(redirect);
        }
        redirects.sort_unstable();
        Ok(Self {
            url,
            expected_bytes,
            expected_sha256,
            origin,
            redirect_origins: redirects,
        })
    }
}

/// Caller-supplied identity for the curl executable. Its file ownership,
/// executable type and SHA-256 are checked again immediately before use.
#[derive(Clone, Debug)]
pub struct CurlExecutablePin {
    path: PathBuf,
    sha256: String,
}

impl CurlExecutablePin {
    pub fn new(path: impl Into<PathBuf>, sha256: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let sha256 = sha256.into();
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(Refusal::new(
                "curl executable path must be absolute and normalized",
            ));
        }
        if !is_sha256_digest(&sha256) {
            return Err(Refusal::new(
                "curl executable identity must be lowercase SHA-256 hex",
            ));
        }
        Ok(Self { path, sha256 })
    }

    fn verify(&self) -> Result<()> {
        let mut file = ownership::protected_regular_file(&self.path, true)?;
        let before = file.metadata().map_err(|error| {
            Refusal::new(format!("could not inspect pinned curl executable: {error}"))
        })?;
        if before.len() == 0 || before.len() > MAX_CURL_EXECUTABLE_BYTES {
            return Err(Refusal::new(
                "pinned curl executable exceeds its verification bound",
            ));
        }
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut hashed = 0_u64;
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    hashed = hashed
                        .checked_add(read as u64)
                        .ok_or_else(|| Refusal::new("curl executable size overflow"))?;
                    if hashed > MAX_CURL_EXECUTABLE_BYTES {
                        return Err(Refusal::new(
                            "pinned curl executable exceeds its verification bound",
                        ));
                    }
                    digest.update(&buffer[..read]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(Refusal::new(format!(
                        "could not hash pinned curl executable: {error}"
                    )));
                }
            }
        }
        let after = file.metadata().map_err(|error| {
            Refusal::new(format!("could not recheck pinned curl executable: {error}"))
        })?;
        if !same_file_snapshot(&before, &after) {
            return Err(Refusal::new(
                "pinned curl executable changed during verification",
            ));
        }
        let actual: [u8; 32] = digest.finalize().into();
        if encode_hex(&actual) != self.sha256 {
            return Err(Refusal::new(
                "curl executable differs from the caller-supplied identity",
            ));
        }
        Ok(())
    }
}

/// Caller-selected transport bounds. The byte ceiling also applies to
/// non-final redirect response bodies, which are downloaded to the same
/// private staging entry and discarded before the next request.
#[derive(Clone, Copy, Debug)]
pub struct DownloadLimits {
    pub max_bytes: u64,
    pub total_timeout: Duration,
    pub per_hop_timeout: Duration,
    pub termination_grace: Duration,
    pub max_redirects: u8,
    pub max_header_bytes: usize,
    pub max_stderr_bytes: usize,
}

/// Caller-selected resource observation for each curl process. The roots are
/// explicit managed-workspace paths; acquisition does not infer a workspace
/// boundary from the destination or process environment.
#[derive(Clone, Debug)]
pub struct AcquisitionObservationConfig {
    pub resource_limits: ResourceLimits,
    pub sample_limits: SampleLimits,
    pub required_roots: Vec<PathBuf>,
}

impl DownloadLimits {
    fn validate(self, pin: &DownloadPin) -> Result<()> {
        if self.max_bytes == 0
            || pin.expected_bytes > self.max_bytes
            || self.max_bytes > i64::MAX as u64
        {
            return Err(Refusal::new(
                "pinned download exceeds the selected byte ceiling",
            ));
        }
        if self.total_timeout.as_millis() == 0 || self.per_hop_timeout.as_millis() == 0 {
            return Err(Refusal::new(
                "download time limits must be at least one millisecond",
            ));
        }
        if self.max_redirects > MAX_REDIRECTS {
            return Err(Refusal::new(
                "download redirect limit exceeds the supported bound",
            ));
        }
        if self.max_header_bytes == 0 || self.max_header_bytes > MAX_HEADER_BYTES {
            return Err(Refusal::new(
                "download response header bound is outside the supported range",
            ));
        }
        if self.max_stderr_bytes == 0 || self.max_stderr_bytes > MAX_CURL_STDERR_BYTES {
            return Err(Refusal::new(
                "curl diagnostic bound is outside the supported range",
            ));
        }
        Ok(())
    }
}

/// Size and digest of an exclusively published object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquiredDownload {
    pub bytes: u64,
    pub sha256: String,
    /// One report for each completed curl request, including checked redirects.
    pub resource_reports: Vec<ResourceReport>,
}

/// Verify the supplied curl identity, download one pinned HTTPS object, and
/// publish it into a previously validated fresh destination.
///
/// Curl receives a replacement environment, no stdin, `-q` as its first
/// argument, no proxy settings, no automatic redirect option, and a private
/// sibling staging path. The capture loop polls every 25 ms while a response
/// body is being written, so cancellation and staged-size checks do not wait
/// for the transfer to finish. Stdout is bounded response headers and write-out
/// metadata; stderr is bounded and never copied into a refusal message.
pub fn acquire_pinned_download(
    pin: &DownloadPin,
    curl: &CurlExecutablePin,
    destination: &FreshTarget,
    limits: DownloadLimits,
    observation: &AcquisitionObservationConfig,
    mut cancelled: impl FnMut() -> bool,
) -> Result<AcquiredDownload> {
    limits.validate(pin)?;
    curl.verify()?;
    let deadline = Instant::now()
        .checked_add(limits.total_timeout)
        .ok_or_else(|| Refusal::new("download total timeout cannot be represented"))?;
    let mut transport = CurlTransport {
        curl,
        max_header_bytes: limits.max_header_bytes,
        max_stderr_bytes: limits.max_stderr_bytes,
        termination_grace: limits.termination_grace,
        observation,
    };
    acquire_with_transport(
        pin,
        destination,
        limits,
        deadline,
        &mut cancelled,
        &mut transport,
    )
}

fn acquire_with_transport(
    pin: &DownloadPin,
    destination: &FreshTarget,
    limits: DownloadLimits,
    deadline: Instant,
    cancelled: &mut dyn FnMut() -> bool,
    transport: &mut dyn FetchTransport,
) -> Result<AcquiredDownload> {
    limits.validate(pin)?;
    if cancelled() {
        return Err(Refusal::new(
            "pinned download was cancelled before transport",
        ));
    }
    let mut staging = StagedDownload::create(destination)?;
    let mut resource_reports = Vec::new();
    let operation = (|| {
        let mut url = pin.url.clone();
        let mut redirects_followed = 0_u8;
        loop {
            if cancelled() {
                return Err(Refusal::new("pinned download was cancelled"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Refusal::new("pinned download exceeded its total deadline"));
            }
            let hop_timeout = limits.per_hop_timeout.min(remaining);
            let mut check_staging = || staging.check_size(limits.max_bytes);
            let response = transport.fetch(
                &url,
                &staging.path,
                pin.expected_bytes,
                hop_timeout,
                cancelled,
                &mut check_staging,
            )?;
            resource_reports.push(response.resource_report);
            if Instant::now() >= deadline {
                return Err(Refusal::new("pinned download exceeded its total deadline"));
            }
            staging.check_size(limits.max_bytes)?;
            let reply = parse_curl_reply(&response.stdout, limits.max_header_bytes)?;

            if is_redirect_status(reply.status) {
                if redirects_followed >= limits.max_redirects {
                    return Err(Refusal::new("pinned download exceeded its redirect limit"));
                }
                let next = reply
                    .redirect_url
                    .filter(|next| !next.is_empty())
                    .ok_or_else(|| {
                        Refusal::new("HTTPS redirect did not provide a usable target")
                    })?;
                validate_redirect_target(pin, &next)?;
                staging.reset()?;
                url = next;
                redirects_followed += 1;
                continue;
            }
            if reply.status != 200 {
                return Err(Refusal::new("HTTPS server returned an unexpected status"));
            }
            if let Some(content_length) = reply.content_length
                && content_length != pin.expected_bytes
            {
                return Err(Refusal::new(
                    "HTTPS Content-Length differs from the pinned size",
                ));
            }
            let mut acquired = verify_staged_file(&staging, pin)?;
            destination
                .parent()
                .rename_no_replace(
                    staging.name.as_os_str(),
                    destination.parent(),
                    destination.name(),
                )
                .map_err(|error| {
                    Refusal::new(format!(
                        "could not exclusively publish the pinned download: {error}"
                    ))
                })?;
            staging.owned = false;
            let _ = destination.parent().sync_best_effort();
            acquired.resource_reports = std::mem::take(&mut resource_reports);
            return Ok(acquired);
        }
    })();

    match operation {
        Ok(acquired) => Ok(acquired),
        Err(error) => Err(staging.cleanup_after(append_resource_reports(error, &resource_reports))),
    }
}

struct FetchResponse {
    stdout: Vec<u8>,
    resource_report: ResourceReport,
}

trait FetchTransport {
    fn fetch(
        &mut self,
        url: &str,
        staged_path: &Path,
        max_bytes: u64,
        timeout: Duration,
        cancelled: &mut dyn FnMut() -> bool,
        check_progress: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<FetchResponse>;
}

struct CurlTransport<'a> {
    curl: &'a CurlExecutablePin,
    max_header_bytes: usize,
    max_stderr_bytes: usize,
    termination_grace: Duration,
    observation: &'a AcquisitionObservationConfig,
}

impl FetchTransport for CurlTransport<'_> {
    fn fetch(
        &mut self,
        url: &str,
        staged_path: &Path,
        max_bytes: u64,
        timeout: Duration,
        cancelled: &mut dyn FnMut() -> bool,
        check_progress: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<FetchResponse> {
        let stdout_limit = self
            .max_header_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(MAX_URL_BYTES + 256))
            .ok_or_else(|| Refusal::new("curl output bound overflow"))?;
        let mut args = vec![
            OsString::from("-q"),
            OsString::from("--silent"),
            OsString::from("--show-error"),
            OsString::from("--globoff"),
            OsString::from("--noproxy"),
            OsString::from("*"),
            OsString::from("--proto"),
            OsString::from("=https"),
            OsString::from("--proto-redir"),
            OsString::from("=https"),
            OsString::from("--connect-timeout"),
            OsString::from(format_duration(timeout.min(Duration::from_secs(30)))?),
            OsString::from("--max-time"),
            OsString::from(format_duration(timeout)?),
            OsString::from("--max-filesize"),
            OsString::from(max_bytes.to_string()),
            OsString::from("--user-agent"),
            OsString::from("ami-rust-hosted-cargo/1"),
            OsString::from("--dump-header"),
            OsString::from("-"),
            OsString::from("--output"),
            staged_path.as_os_str().to_os_string(),
            OsString::from("--write-out"),
            OsString::from(WRITE_OUT_FORMAT),
            OsString::from("--url"),
            OsString::from(url),
        ];
        if args.first().map(OsString::as_os_str) != Some(OsStr::new("-q")) {
            return Err(Refusal::new(
                "curl must start with its configuration-disable option",
            ));
        }

        let mut environment = BTreeMap::new();
        environment.insert(OsString::from("LANG"), OsString::from("C"));
        environment.insert(OsString::from("LC_ALL"), OsString::from("C"));
        environment.insert(OsString::from("HOME"), OsString::from("/nonexistent"));
        environment.insert(OsString::from("CURL_HOME"), OsString::from("/nonexistent"));
        environment.insert(OsString::from("NO_PROXY"), OsString::from("*"));
        environment.insert(OsString::from("no_proxy"), OsString::from("*"));

        let spec = CommandSpec::new(
            self.curl.path.as_os_str().to_os_string(),
            std::mem::take(&mut args),
            Path::new("/"),
            environment,
        );
        let captured = resource_capture::capture_with_resources_observed(
            &spec,
            CaptureLimits {
                timeout,
                stdout_bytes: stdout_limit,
                stderr_bytes: self.max_stderr_bytes,
                termination_grace: self.termination_grace,
            },
            self.observation.resource_limits,
            self.observation.sample_limits,
            &self.observation.required_roots,
            cancelled,
            |_| check_progress(),
        )
        .map_err(map_resource_capture_error)?;
        if !captured.process.status.success() {
            return Err(refusal_with_resource_report(
                "pinned HTTPS transport exited unsuccessfully",
                &captured.report,
            ));
        }
        Ok(FetchResponse {
            stdout: captured.process.stdout,
            resource_report: captured.report,
        })
    }
}

fn map_resource_capture_error(error: ResourceCaptureError) -> Refusal {
    match error {
        ResourceCaptureError::Setup { report, .. } => {
            refusal_with_resource_report("curl resource observer could not be initialized", &report)
        }
        ResourceCaptureError::Capture { error, report } => {
            let message = match error.cause {
                CaptureCause::Timeout => "pinned HTTPS request exceeded its per-hop deadline",
                CaptureCause::Cancelled => "pinned HTTPS request was cancelled",
                CaptureCause::Observation(_) => "curl resource or staged-output observation failed",
                CaptureCause::StdoutLimitExceeded => {
                    "pinned HTTPS response headers exceeded their bound"
                }
                CaptureCause::StderrLimitExceeded => "curl diagnostics exceeded their bound",
                CaptureCause::DescendantRetainedPipe => {
                    "curl exited while a descendant retained an output pipe"
                }
                CaptureCause::OutputAllocation => "could not allocate bounded curl output",
                CaptureCause::Io(_) => "pinned HTTPS transport could not be completed",
            };
            let cleanup = error.cleanup_error.is_some();
            let mut refusal = refusal_with_resource_report(message, &report);
            if cleanup {
                refusal = Refusal::new(format!("{refusal}; curl process cleanup also failed"));
            }
            refusal
        }
    }
}

fn append_resource_reports(error: Refusal, reports: &[ResourceReport]) -> Refusal {
    if reports.is_empty() {
        return error;
    }
    let summaries = reports
        .iter()
        .map(resource_report_summary)
        .collect::<Vec<_>>()
        .join("; ");
    Refusal::new(format!(
        "{error}; completed curl resource reports: {summaries}"
    ))
}

fn refusal_with_resource_report(message: &str, report: &ResourceReport) -> Refusal {
    Refusal::new(format!("{message}; {}", resource_report_summary(report)))
}

fn resource_report_summary(report: &ResourceReport) -> String {
    format!(
        "resource report: samples={}, complete={}, visible_rss_current={}, visible_rss_peak={}, workspace_current={}, workspace_peak={}, disk_log_current={}, pending_output_current={}, log_current={}, log_peak={}, visible_processes={}, observed_groups={}, escaped_groups={}, incomplete_cleanup={}",
        report.sample_count,
        report.last_sample_complete,
        report.current_visible_rss_bytes,
        report.peak_visible_rss_bytes,
        report.current_workspace_bytes,
        report.peak_workspace_bytes,
        report.current_disk_log_bytes,
        report.current_pending_output_bytes,
        report.current_log_bytes,
        report.peak_log_bytes,
        report.visible_process_ids.len(),
        report.observed_process_groups.len(),
        report.current_escaped_process_groups.len(),
        report.incomplete_cleanup,
    )
}

struct StagedDownload<'a> {
    parent: &'a Directory,
    name: OsString,
    path: PathBuf,
    owned: bool,
}

impl<'a> StagedDownload<'a> {
    fn create(destination: &'a FreshTarget) -> Result<Self> {
        let parent_path = destination
            .path()
            .parent()
            .ok_or_else(|| Refusal::new("download destination has no parent directory"))?;
        let sequence = NEXT_STAGING_NAME.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = OsString::from(format!(
            ".ami-rust-acquisition-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        let file = destination.parent().create_new_file(&name, 0o600)?;
        drop(file);
        Ok(Self {
            parent: destination.parent(),
            path: parent_path.join(&name),
            name,
            owned: true,
        })
    }

    fn reset(&mut self) -> Result<()> {
        self.parent.unlink_entry(&self.name)?;
        self.owned = false;
        let file = self.parent.create_new_file(&self.name, 0o600)?;
        drop(file);
        self.owned = true;
        Ok(())
    }

    fn check_size(&self, maximum: u64) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file() || metadata.len() > maximum {
            return Err(io::Error::other(
                "staged response is not regular or exceeded its size bound",
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.owned {
            self.parent.unlink_entry(&self.name)?;
            self.owned = false;
        }
        Ok(())
    }

    fn cleanup_after(&mut self, cause: Refusal) -> Refusal {
        match self.cleanup() {
            Ok(()) => cause,
            Err(cleanup) => Refusal::new(format!(
                "{cause}; temporary download cleanup failed ({cleanup}); recovery path: {}",
                self.path.display()
            )),
        }
    }
}

impl Drop for StagedDownload<'_> {
    fn drop(&mut self) {
        if self.owned && self.parent.unlink_entry(&self.name).is_ok() {
            self.owned = false;
        }
    }
}

fn verify_staged_file(staging: &StagedDownload<'_>, pin: &DownloadPin) -> Result<AcquiredDownload> {
    let mut file = staging.parent.regular(&staging.name)?;
    let before = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect staged download: {error}")))?;
    if before.len() != pin.expected_bytes {
        return Err(Refusal::new(
            "download byte count differs from the pinned size",
        ));
    }
    let mut digest = Sha256::new();
    let mut received = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                received = received
                    .checked_add(read as u64)
                    .ok_or_else(|| Refusal::new("download byte count overflow"))?;
                if received > pin.expected_bytes {
                    return Err(Refusal::new(
                        "download exceeded the pinned size while hashing",
                    ));
                }
                digest.update(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not hash staged download: {error}"
                )));
            }
        }
    }
    let after = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not recheck staged download: {error}")))?;
    if received != pin.expected_bytes || !same_file_snapshot(&before, &after) {
        return Err(Refusal::new(
            "staged download changed while it was being verified",
        ));
    }
    let value: [u8; 32] = digest.finalize().into();
    let actual = encode_hex(&value);
    if actual != pin.expected_sha256 {
        return Err(Refusal::new("download SHA-256 differs from the pin"));
    }
    Ok(AcquiredDownload {
        bytes: received,
        sha256: actual,
        resource_reports: Vec::new(),
    })
}

fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

struct CurlReply {
    status: u16,
    redirect_url: Option<String>,
    content_length: Option<u64>,
}

fn parse_curl_reply(stdout: &[u8], maximum_headers: usize) -> Result<CurlReply> {
    let marker = stdout
        .windows(WRITE_OUT_MARKER.len())
        .rposition(|window| window == WRITE_OUT_MARKER)
        .ok_or_else(|| Refusal::new("curl did not return its response metadata"))?;
    let headers = &stdout[..marker];
    if headers.len() > maximum_headers {
        return Err(Refusal::new("HTTPS response headers exceeded their bound"));
    }
    let write_out = std::str::from_utf8(&stdout[marker + WRITE_OUT_MARKER.len()..])
        .map_err(|_| Refusal::new("curl returned malformed response metadata"))?;
    let write_out = write_out
        .strip_suffix('\n')
        .ok_or_else(|| Refusal::new("curl returned incomplete response metadata"))?;
    let (status_text, redirect_text) = write_out
        .split_once('\n')
        .ok_or_else(|| Refusal::new("curl returned incomplete response metadata"))?;
    if redirect_text
        .chars()
        .any(|character| matches!(character, '\n' | '\r'))
    {
        return Err(Refusal::new("curl returned malformed redirect metadata"));
    }
    let status = parse_status_code(status_text.as_bytes())
        .ok_or_else(|| Refusal::new("curl returned an invalid HTTP status"))?;
    let (header_status, content_length) = parse_response_headers(headers)?;
    if status != header_status {
        return Err(Refusal::new(
            "curl status metadata differs from response headers",
        ));
    }
    Ok(CurlReply {
        status,
        redirect_url: (!redirect_text.is_empty()).then(|| redirect_text.to_owned()),
        content_length,
    })
}

fn parse_response_headers(headers: &[u8]) -> Result<(u16, Option<u64>)> {
    let mut blocks = Vec::new();
    let mut current_status = None;
    let mut current_content_length = None;
    let mut saw_content_length = false;
    let mut ended_block = false;

    for raw_line in headers.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            if let Some(status) = current_status.take() {
                blocks.push((status, current_content_length.take()));
                if blocks.len() > 16 {
                    return Err(Refusal::new(
                        "HTTPS response contained too many header blocks",
                    ));
                }
                saw_content_length = false;
            }
            ended_block = true;
            continue;
        }
        ended_block = false;
        if current_status.is_none() {
            let status = parse_status_line(line)
                .ok_or_else(|| Refusal::new("HTTPS response contained malformed headers"))?;
            current_status = Some(status);
            continue;
        }
        if line
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            return Err(Refusal::new("HTTPS response used a folded header"));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| Refusal::new("HTTPS response contained malformed headers"))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().copied().all(is_header_name_byte) {
            return Err(Refusal::new(
                "HTTPS response contained an invalid header name",
            ));
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if saw_content_length {
                return Err(Refusal::new("HTTPS response duplicated Content-Length"));
            }
            saw_content_length = true;
            let value = trim_ows(&line[colon + 1..]);
            if value.is_empty() || !value.iter().all(|byte| byte.is_ascii_digit()) {
                return Err(Refusal::new("HTTPS response had an invalid Content-Length"));
            }
            let text = std::str::from_utf8(value)
                .map_err(|_| Refusal::new("HTTPS response had an invalid Content-Length"))?;
            current_content_length = Some(
                text.parse::<u64>()
                    .map_err(|_| Refusal::new("HTTPS response had an invalid Content-Length"))?,
            );
        }
    }
    if current_status.is_some() {
        return Err(Refusal::new("HTTPS response headers were not terminated"));
    }
    if !ended_block || blocks.is_empty() {
        return Err(Refusal::new(
            "HTTPS response contained no complete header block",
        ));
    }
    blocks
        .pop()
        .ok_or_else(|| Refusal::new("HTTPS response contained no complete header block"))
}

fn parse_status_line(line: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.split_ascii_whitespace();
    let protocol = parts.next()?;
    if !protocol.starts_with("HTTP/") {
        return None;
    }
    parse_status_code(parts.next()?.as_bytes())
}

fn parse_status_code(value: &[u8]) -> Option<u16> {
    (value.len() == 3 && value.iter().all(|byte| byte.is_ascii_digit())).then(|| {
        u16::from(value[0] - b'0') * 100
            + u16::from(value[1] - b'0') * 10
            + u16::from(value[2] - b'0')
    })
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn validate_url_for_origin(url: &str, expected: HttpsOrigin) -> Result<()> {
    let actual = url_origin(url)?;
    if actual != expected {
        return Err(Refusal::new("HTTPS URL does not match its pinned origin"));
    }
    Ok(())
}

fn validate_redirect_target(pin: &DownloadPin, url: &str) -> Result<()> {
    let origin = url_origin(url)?;
    if origin != pin.origin && !pin.redirect_origins.contains(&origin) {
        return Err(Refusal::new(
            "HTTPS redirect target is outside the pinned origin allowlist",
        ));
    }
    Ok(())
}

fn url_origin(url: &str) -> Result<HttpsOrigin> {
    if url.len() > MAX_URL_BYTES
        || !url.starts_with("https://")
        || url
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || byte == b'\\' || byte == b'#')
    {
        return Err(Refusal::new("pinned HTTPS URL has an unsupported form"));
    }
    let rest = &url["https://".len()..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.contains(':') {
        return Err(Refusal::new(
            "pinned HTTPS URL must use an exact host on the default port",
        ));
    }
    let origin = match authority {
        "static.rust-lang.org" => HttpsOrigin::StaticRustLang,
        "github.com" => HttpsOrigin::Github,
        "raw.githubusercontent.com" => HttpsOrigin::RawGithub,
        "release-assets.githubusercontent.com" => HttpsOrigin::GithubReleaseAssets,
        "objects.githubusercontent.com" => HttpsOrigin::GithubObjects,
        _ => {
            return Err(Refusal::new(
                "HTTPS URL host is outside the supported origins",
            ));
        }
    };
    if origin.host() != authority {
        return Err(Refusal::new(
            "HTTPS URL host is not in canonical lowercase form",
        ));
    }
    Ok(origin)
}

fn format_duration(duration: Duration) -> Result<String> {
    let millis = duration.as_millis();
    if millis == 0 {
        return Err(Refusal::new(
            "curl timeout must be at least one millisecond",
        ));
    }
    let seconds = millis / 1000;
    let fractional = millis % 1000;
    Ok(format!("{seconds}.{fractional:03}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_capture::CaptureError;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                ".ami-acquisition-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create acquisition fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure acquisition fixture");
            Self(path)
        }

        fn fresh_target(&self, name: &str) -> FreshTarget {
            ownership::fresh_output(&self.0.join(name)).expect("fresh output target")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove acquisition fixture");
        }
    }

    fn pin(url: &str, bytes: &[u8]) -> DownloadPin {
        DownloadPin::new(
            url,
            bytes.len() as u64,
            crate::digest::sha256_bytes(bytes),
            HttpsOrigin::Github,
            [HttpsOrigin::GithubReleaseAssets, HttpsOrigin::GithubObjects],
        )
        .unwrap()
    }

    fn limits(expected: usize) -> DownloadLimits {
        DownloadLimits {
            max_bytes: expected as u64,
            total_timeout: Duration::from_secs(10),
            per_hop_timeout: Duration::from_secs(3),
            termination_grace: Duration::from_millis(100),
            max_redirects: 3,
            max_header_bytes: 4096,
            max_stderr_bytes: 4096,
        }
    }

    fn response(status: u16, redirect: &str, content_length: Option<u64>) -> Vec<u8> {
        let mut bytes = format!("HTTP/2 {status}\r\n").into_bytes();
        if let Some(length) = content_length {
            bytes.extend_from_slice(format!("content-length: {length}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(WRITE_OUT_MARKER);
        bytes.extend_from_slice(format!("{status}\n{redirect}\n").as_bytes());
        bytes
    }

    fn mock_fetch_response(
        stdout: Vec<u8>,
        sample_count: u64,
        peak_workspace_bytes: u64,
    ) -> FetchResponse {
        FetchResponse {
            stdout,
            resource_report: ResourceReport {
                sample_count,
                peak_workspace_bytes,
                ..ResourceReport::default()
            },
        }
    }

    struct MockTransport<F>(F);

    impl<F> FetchTransport for MockTransport<F>
    where
        F: FnMut(
            &str,
            &Path,
            u64,
            Duration,
            &mut dyn FnMut() -> bool,
            &mut dyn FnMut() -> io::Result<()>,
        ) -> Result<FetchResponse>,
    {
        fn fetch(
            &mut self,
            url: &str,
            staged_path: &Path,
            max_bytes: u64,
            timeout: Duration,
            cancelled: &mut dyn FnMut() -> bool,
            check_progress: &mut dyn FnMut() -> io::Result<()>,
        ) -> Result<FetchResponse> {
            (self.0)(
                url,
                staged_path,
                max_bytes,
                timeout,
                cancelled,
                check_progress,
            )
        }
    }

    #[test]
    fn validates_supported_initial_urls_and_exact_redirect_policy() {
        let valid = DownloadPin::new(
            "https://static.rust-lang.org/dist/channel-rust-1.98.1.toml",
            1,
            crate::digest::sha256_bytes(b"x"),
            HttpsOrigin::StaticRustLang,
            [],
        );
        assert!(valid.is_ok());
        let token_pin = pin(
            "https://github.com/example/project/releases/download/v1/a?token=private",
            b"x",
        );
        assert!(!format!("{token_pin:?}").contains("private"));
        assert!(
            DownloadPin::new(
                "https://static.rust-lang.org/a",
                1,
                crate::digest::sha256_bytes(b"x"),
                HttpsOrigin::StaticRustLang,
                [HttpsOrigin::GithubReleaseAssets],
            )
            .is_err()
        );
        for url in [
            "http://github.com/org/repo",
            "https://user@github.com/org/repo",
            "https://github.com:443/org/repo",
            "https://github.com/org/repo#fragment",
            "https://GitHub.com/org/repo",
            "https://evil.example/org/repo",
        ] {
            assert!(
                DownloadPin::new(
                    url,
                    1,
                    crate::digest::sha256_bytes(b"x"),
                    HttpsOrigin::Github,
                    [],
                )
                .is_err(),
                "accepted {url:?}"
            );
        }
    }

    #[test]
    fn refuses_invalid_or_ambiguous_response_headers() {
        assert!(parse_curl_reply(&response(200, "", Some(4)), 4096).is_ok());
        for (case, raw) in [
            (
                "duplicate content length",
                b"HTTP/2 200\r\ncontent-length: 4\r\ncontent-length: 4\r\n\r\n".as_slice(),
            ),
            (
                "nonnumeric content length",
                b"HTTP/2 200\r\ncontent-length: four\r\n\r\n".as_slice(),
            ),
            (
                "folded header",
                b"HTTP/2 200\r\n folded: value\r\n\r\n".as_slice(),
            ),
            (
                "unterminated headers",
                b"HTTP/2 200\r\ncontent-length: 4".as_slice(),
            ),
        ] {
            let mut stdout = raw.to_vec();
            stdout.extend_from_slice(WRITE_OUT_MARKER);
            stdout.extend_from_slice(b"200\n\n");
            assert!(
                parse_curl_reply(&stdout, 4096).is_err(),
                "accepted malformed response: {case}"
            );
        }
        let too_large = response(200, "", Some(4));
        assert!(parse_curl_reply(&too_large, 1).is_err());
    }

    #[test]
    fn resource_failure_retains_peaks_without_exposing_transport_diagnostics() {
        let error = map_resource_capture_error(ResourceCaptureError::Capture {
            error: CaptureError {
                cause: CaptureCause::Observation(io::Error::other("token=private")),
                stdout: b"sensitive response".to_vec(),
                stderr: b"sensitive diagnostic".to_vec(),
                status: None,
                elapsed: Duration::from_millis(45),
                cleanup_error: Some(io::Error::other("cleanup token=also-private")),
            },
            report: Box::new(ResourceReport {
                sample_count: 4,
                peak_visible_rss_bytes: 128,
                peak_workspace_bytes: 256,
                peak_log_bytes: 512,
                ..ResourceReport::default()
            }),
        });
        let message = error.to_string();
        assert!(message.contains("samples=4"));
        assert!(message.contains("visible_rss_peak=128"));
        assert!(message.contains("workspace_peak=256"));
        assert!(message.contains("log_peak=512"));
        assert!(message.contains("curl process cleanup also failed"));
        assert!(!message.contains("private"));
        assert!(!message.contains("sensitive"));
    }

    #[test]
    fn publishes_only_exact_pinned_bytes_after_checked_redirects() {
        let fixture = TempDir::new();
        let destination = fixture.fresh_target("download.bin");
        let content = b"archive bytes";
        let pin = pin(
            "https://github.com/example/project/releases/download/v1/a.tar.xz",
            content,
        );
        let limits = limits(content.len());
        let deadline = Instant::now() + limits.total_timeout;
        let mut calls = Vec::new();
        let mut transport = MockTransport(
            |url: &str,
             staged: &Path,
             _maximum: u64,
             _timeout: Duration,
             cancelled: &mut dyn FnMut() -> bool,
             check: &mut dyn FnMut() -> io::Result<()>| {
                calls.push(url.to_owned());
                if cancelled() {
                    return Err(Refusal::new("cancelled"));
                }
                if url == "https://github.com/example/project/releases/download/v1/a.tar.xz" {
                    fs::write(staged, b"redirect").unwrap();
                    check().unwrap();
                    Ok(mock_fetch_response(
                        response(
                            302,
                            "https://release-assets.githubusercontent.com/download/a?token=secret",
                            None,
                        ),
                        1,
                        17,
                    ))
                } else {
                    assert_eq!(
                        url,
                        "https://release-assets.githubusercontent.com/download/a?token=secret"
                    );
                    fs::write(staged, content).unwrap();
                    check().unwrap();
                    Ok(mock_fetch_response(
                        response(200, "", Some(content.len() as u64)),
                        2,
                        29,
                    ))
                }
            },
        );
        let acquired = acquire_with_transport(
            &pin,
            &destination,
            limits,
            deadline,
            &mut || false,
            &mut transport,
        )
        .unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(acquired.bytes, content.len() as u64);
        assert_eq!(acquired.sha256, crate::digest::sha256_bytes(content));
        assert_eq!(acquired.resource_reports.len(), 2);
        assert_eq!(acquired.resource_reports[0].peak_workspace_bytes, 17);
        assert_eq!(acquired.resource_reports[1].peak_workspace_bytes, 29);
        assert_eq!(fs::read(destination.path()).unwrap(), content);
        assert_eq!(
            fs::metadata(destination.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_out_of_allowlist_redirect_before_requesting_it_and_cleans_partial() {
        let fixture = TempDir::new();
        let destination = fixture.fresh_target("download.bin");
        let content = b"archive bytes";
        let pin = pin(
            "https://github.com/example/project/releases/download/v1/a.tar.xz",
            content,
        );
        let limits = limits(content.len());
        let deadline = Instant::now() + limits.total_timeout;
        let mut calls = 0;
        let mut transport = MockTransport(
            |_: &str,
             staged: &Path,
             _maximum: u64,
             _timeout: Duration,
             _cancelled: &mut dyn FnMut() -> bool,
             check: &mut dyn FnMut() -> io::Result<()>| {
                calls += 1;
                fs::write(staged, b"redirect").unwrap();
                check().unwrap();
                Ok(mock_fetch_response(
                    response(302, "https://evil.example/stolen?token=secret", None),
                    3,
                    123,
                ))
            },
        );
        let error = acquire_with_transport(
            &pin,
            &destination,
            limits,
            deadline,
            &mut || false,
            &mut transport,
        )
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(!destination.path().exists());
        assert!(!error.to_string().contains("secret"));
        assert!(error.to_string().contains("workspace_peak=123"));
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
    }

    #[test]
    fn size_and_digest_failures_leave_no_partial_and_destination_race_is_no_replace() {
        let content = b"archive bytes";
        let pin = pin(
            "https://github.com/example/project/releases/download/v1/a.tar.xz",
            content,
        );
        let limits = limits(content.len());

        let fixture = TempDir::new();
        let destination = fixture.fresh_target("wrong-digest.bin");
        let deadline = Instant::now() + limits.total_timeout;
        let mut transport = MockTransport(
            |_: &str,
             staged: &Path,
             _maximum: u64,
             _timeout: Duration,
             _cancelled: &mut dyn FnMut() -> bool,
             check: &mut dyn FnMut() -> io::Result<()>| {
                fs::write(staged, b"wrong bytes!!").unwrap();
                check().unwrap();
                Ok(mock_fetch_response(
                    response(200, "", Some(content.len() as u64)),
                    1,
                    0,
                ))
            },
        );
        assert!(
            acquire_with_transport(
                &pin,
                &destination,
                limits,
                deadline,
                &mut || false,
                &mut transport,
            )
            .is_err()
        );
        assert!(!destination.path().exists());
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());

        let race_fixture = TempDir::new();
        let raced = race_fixture.fresh_target("raced.bin");
        let deadline = Instant::now() + limits.total_timeout;
        let raced_path = raced.path().to_path_buf();
        let mut transport = MockTransport(
            move |_: &str,
                  staged: &Path,
                  _maximum: u64,
                  _timeout: Duration,
                  _cancelled: &mut dyn FnMut() -> bool,
                  check: &mut dyn FnMut() -> io::Result<()>| {
                fs::write(staged, content).unwrap();
                fs::write(&raced_path, b"caller file").unwrap();
                check().unwrap();
                Ok(mock_fetch_response(
                    response(200, "", Some(content.len() as u64)),
                    1,
                    0,
                ))
            },
        );
        assert!(
            acquire_with_transport(
                &pin,
                &raced,
                limits,
                deadline,
                &mut || false,
                &mut transport,
            )
            .is_err()
        );
        assert_eq!(fs::read(raced.path()).unwrap(), b"caller file");
        assert_eq!(fs::read_dir(&race_fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn staging_limit_and_cancellation_refuse_before_publication() {
        let fixture = TempDir::new();
        let destination = fixture.fresh_target("download.bin");
        let content = b"archive bytes";
        let pin = pin(
            "https://github.com/example/project/releases/download/v1/a.tar.xz",
            content,
        );
        let limits = limits(content.len());
        let deadline = Instant::now() + limits.total_timeout;
        let mut transport = MockTransport(
            |_: &str,
             staged: &Path,
             _maximum: u64,
             _timeout: Duration,
             _cancelled: &mut dyn FnMut() -> bool,
             check: &mut dyn FnMut() -> io::Result<()>| {
                fs::write(staged, vec![b'x'; content.len() + 1]).unwrap();
                assert!(check().is_err());
                Err(Refusal::new("mock observed overflow"))
            },
        );
        assert!(
            acquire_with_transport(
                &pin,
                &destination,
                limits,
                deadline,
                &mut || false,
                &mut transport,
            )
            .is_err()
        );
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());

        let mut never_called = MockTransport(
            |_: &str,
             _: &Path,
             _: u64,
             _: Duration,
             _: &mut dyn FnMut() -> bool,
             _: &mut dyn FnMut() -> io::Result<()>|
             -> Result<FetchResponse> {
                panic!("cancelled acquisition must not start transport")
            },
        );
        assert!(
            acquire_with_transport(
                &pin,
                &destination,
                limits,
                Instant::now() + limits.total_timeout,
                &mut || true,
                &mut never_called,
            )
            .is_err()
        );
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
    }
}

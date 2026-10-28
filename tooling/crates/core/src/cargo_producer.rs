//! Supervised host Cargo prerequisite producer for the pinned patched source.
//!
//! This produces a host Cargo executable or its dependency vendor tree. It is
//! not SDK, guest, or release qualification. Process capture owns the child
//! process group, resource sampling observes its descendants, and every
//! bounded output buffer is retained in the command record on failure.

use crate::{
    Refusal, Result,
    cargo_vendor_overlay::{validate_producer_host, verify_overlay},
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    directory::Directory,
    files::{open_regular_nofollow, read_regular_bounded, validate_relative_inventory_path},
    json::{JsonProfile, parse_json},
    process_capture::{
        CaptureCause, CaptureLimits, CaptureObservation, CaptureObservationPhase, CapturedProcess,
        CommandSpec, capture,
    },
    resource_capture::{
        ResourceCaptureError, ResourceLimits, ResourceReport, SampleLimits,
        capture_with_resources_observed,
    },
    signals::SigtermGuard,
    workspace_accounting::{self, Accounting, ScanLimits},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr, OsString},
    fs,
    io::{self, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt, process::ExitStatusExt},
    path::{Component, Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

const SOURCE_PIN_V2_SHA256: &str =
    "73c9fc79976541cb43cefb39ce878218a3245493e86bb37fac449ec3bee00a52";
const PATCH_V2_SHA256: &str = "1f22b7e2c6a7f4469cc6c2f4a84019d8d8ade558e78241d1e996d88a7f1de97f";
const SOURCE_PIN_V3_SHA256: &str =
    "9c8ac1d58262c73116c74172c93c345196bd8ffa3995bebba3d1f8ea00bc59ce";
const PATCH_V3_SHA256: &str = "2c3ab831d216cc4395decc4bcc307a1d9bac6b6936cd01d7c496c44e55d9826b";
const SOURCE_PROFILES: [SourceProfile; 2] = [
    SourceProfile {
        source_pin_sha256: SOURCE_PIN_V2_SHA256,
        patch_sha256: PATCH_V2_SHA256,
    },
    SourceProfile {
        source_pin_sha256: SOURCE_PIN_V3_SHA256,
        patch_sha256: PATCH_V3_SHA256,
    },
];
const RECEIPT_SCHEMA: &str = "ami-rust-cargo-prerequisite-producer-v1";
const CLAIM: &str =
    "pinned host Cargo prerequisite producer only; not SDK or release qualification";
const MAX_SECONDS: u64 = 1_200;
const MAX_RSS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_WORKSPACE_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const JOBS: u64 = 2;
const MINIMUM_RAM_BYTES: u64 = 6 * 1024 * 1024 * 1024;
const MINIMUM_FREE_DISK_BYTES: u64 = 24 * 1024 * 1024 * 1024;
const WORKSPACE_SCAN_ENTRIES: u64 = 1_000_000;
const WORKSPACE_SCAN_WORK: u64 = 2_000_001;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_GRACE: Duration = Duration::from_secs(1);
const CAPTURE_STREAM_BYTES: usize = MAX_LOG_BYTES as usize;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Provision,
    Build,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Dev,
    Release,
}

/// Inputs for one explicit provision or build phase.
#[derive(Clone, Debug)]
pub struct ProducerOptions {
    pub phase: Phase,
    pub source: PathBuf,
    pub host_rust: PathBuf,
    pub work: PathBuf,
    pub vendor: PathBuf,
    pub record: PathBuf,
    pub recipe: PathBuf,
    pub vendor_overlay_receipt: Option<PathBuf>,
    pub resource_policy: Option<PathBuf>,
    pub profile: Profile,
    pub share_supervisor_group: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdditionalSourceFile {
    path: String,
    original_sha256: String,
    patched_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourcePin {
    upstream: String,
    commit: String,
    path: String,
    original_sha256: String,
    patched_sha256: String,
    patch_sha256: String,
    purpose: String,
    scope: String,
    rustc_or_rust_src_changes: bool,
    additional_files: Vec<AdditionalSourceFile>,
    opt_in: String,
    environment_marker_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct ResourceProfile {
    seconds: u64,
    rss_bytes: u64,
    workspace_bytes: u64,
    jobs: u64,
    log_bytes: u64,
}

impl Default for ResourceProfile {
    fn default() -> Self {
        Self {
            seconds: MAX_SECONDS,
            rss_bytes: MAX_RSS_BYTES,
            workspace_bytes: MAX_WORKSPACE_BYTES,
            jobs: JOBS,
            log_bytes: MAX_LOG_BYTES,
        }
    }
}

#[derive(Clone, Debug)]
struct LoadedPlan {
    pin: SourcePin,
    pin_sha256: String,
    patch_sha256: String,
    patch_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceProfile {
    source_pin_sha256: &'static str,
    patch_sha256: &'static str,
}

#[derive(Clone, Debug)]
struct ResourcePolicyIdentity {
    json: Value,
    capacity: Value,
    physical_ram_bytes: u64,
    free_disk_bytes: u64,
}

/// Run the exact pinned helper recipe. Failed command output and a result
/// record are retained in `record`; source, vendor, and work trees are never
/// cleaned up here.
pub fn produce(options: ProducerOptions) -> Result<Value> {
    if options.share_supervisor_group {
        return Err(Refusal::new(
            "--share-supervisor-group cannot be preserved by process_capture: it always starts Cargo in a private process group, so the outer supervisor could not reliably terminate the same shared group",
        ));
    }

    let recipe = existing_directory(&options.recipe, "Cargo recipe")?;
    let plan = load_pinned_plan(&recipe)?;
    let source = existing_directory(&options.source, "Cargo source")?;
    let rust_root = existing_directory(&options.host_rust, "host Rust installation")?;
    let work_target = target_path(&options.work, "producer work")?;
    let record_target = target_path(&options.record, "producer record")?;
    let vendor_target = target_path(&options.vendor, "vendor tree")?;
    let work_was_existing = target_exists(&work_target.path)?;
    let vendor_was_existing = target_exists(&vendor_target.path)?;

    if options.phase == Phase::Provision && vendor_was_existing {
        return Err(Refusal::new(
            "provisioning requires a fresh, absent vendor output directory",
        ));
    }
    if options.phase == Phase::Build && !vendor_was_existing {
        return Err(Refusal::new(
            "build requires an explicitly provisioned vendor directory",
        ));
    }
    if options.phase == Phase::Build {
        existing_directory(&vendor_target.path, "vendor tree")?;
    }
    if options.phase == Phase::Provision && options.vendor_overlay_receipt.is_some() {
        return Err(Refusal::new(
            "provision the vendor overlay explicitly before the producer build",
        ));
    }

    let vendor_overlay_receipt = options
        .vendor_overlay_receipt
        .as_deref()
        .map(|path| existing_regular_file(path, "vendor overlay receipt"))
        .transpose()?;
    let resource_profile = ResourceProfile::default();
    let resource_policy_path = options
        .resource_policy
        .as_deref()
        .map(|path| existing_regular_file(path, "hosted resource policy"))
        .transpose()?;
    let (resource_profile, resource_policy) = match resource_policy_path.as_deref() {
        Some(path) => {
            let (profile, identity) = load_resource_policy(path, &source)?;
            (profile, Some(identity))
        }
        None => (resource_profile, None),
    };

    let git = Path::new("/usr/bin/git");
    let head = probe_text(
        git,
        &[OsString::from("rev-parse"), OsString::from("HEAD")],
        &source,
        git_environment(),
        "Cargo source revision",
    )?;
    let changed = probe_text(
        git,
        &[OsString::from("diff"), OsString::from("--name-only")],
        &source,
        git_environment(),
        "Cargo source diff",
    )?;
    let changed_paths = changed.lines().map(str::to_owned).collect::<Vec<_>>();
    let source_digest = sha256_file(&source.join(&plan.pin.path))?;
    let mut additional_digests = BTreeMap::new();
    for row in &plan.pin.additional_files {
        additional_digests.insert(row.path.clone(), sha256_file(&source.join(&row.path))?);
    }
    validate_source_checkout(
        &plan.pin,
        head.trim(),
        &source_digest,
        &changed_paths,
        &additional_digests,
    )?;
    if sha256_file(&plan.patch_path)? != plan.patch_sha256 {
        return Err(Refusal::new("pinned Cargo source patch identity mismatch"));
    }

    let rust_bin = rust_root.join("bin");
    let compiler = probe_text(
        &rust_bin.join("rustc"),
        &[OsString::from("-Vv")],
        &source,
        BTreeMap::new(),
        "pinned host rustc version",
    )?;
    if !compiler.contains("release: 1.98.1\n")
        || !compiler.contains("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985")
    {
        return Err(Refusal::new(
            "host rustc release or commit differs from the pinned bootstrap compiler",
        ));
    }
    let native_host = validate_producer_host(&recipe, &compiler)?;
    let cargo_lock_sha256 = sha256_file(&source.join("Cargo.lock"))?;

    let mut protected_inputs = vec![&source, &recipe, &rust_root];
    if let Some(receipt) = &vendor_overlay_receipt {
        protected_inputs.push(receipt);
    }
    if let Some(policy) = &resource_policy_path {
        protected_inputs.push(policy);
    }
    validate_output_separation(
        &protected_inputs,
        &[&work_target.path, &vendor_target.path, &record_target.path],
    )?;

    let work = ensure_directory(&work_target, work_was_existing, "producer work")?;
    let record = create_fresh_directory(&record_target, "producer record")?;
    let cargo_home = ensure_child_directory(&work, &work_target.path, "cargo-home")?;
    ensure_child_directory(&work, &work_target.path, "tmp")?;
    ensure_child_directory(&work, &work_target.path, "home")?;

    let vendor_overlay = if let Some(receipt) = &vendor_overlay_receipt {
        Some(verify_overlay(&vendor_target.path, receipt, &recipe)?)
    } else {
        None
    };

    let config_path = cargo_home.join("config.toml");
    let cargo_home_dir = Directory::open(&cargo_home)?;
    if options.phase == Phase::Build {
        if target_exists(&config_path)? {
            return Err(Refusal::new(
                "build refuses an existing Cargo home config in the producer work tree",
            ));
        }
        let vendor_text = path_text(&vendor_target.path, "vendor path")?;
        let config = format!(
            "[source.crates-io]\nreplace-with=\"vendored\"\n[source.vendored]\ndirectory={}\n",
            serde_json::to_string(&vendor_text)
                .map_err(|error| Refusal::new(format!("cannot encode vendor path: {error}")))?
        );
        write_new_file(&cargo_home_dir, "config.toml", config.as_bytes())?;
    } else if target_exists(&config_path)? {
        return Err(Refusal::new(
            "provisioning requires a fresh Cargo home without a vendor config",
        ));
    }

    let (command, environment) = cargo_command(
        options.phase,
        options.profile,
        &source,
        &rust_root,
        &work_target.path,
        &vendor_target.path,
    )?;
    let producer_sha256 = sha256_bytes(include_bytes!("cargo_producer.rs"));
    let overlay_verifier_sha256 = vendor_overlay
        .as_ref()
        .map(|_| sha256_bytes(include_bytes!("cargo_vendor_overlay.rs")));
    let executable = std::env::current_exe()
        .map_err(|error| Refusal::new(format!("could not resolve producer executable: {error}")))?;
    let executable = fs::canonicalize(executable).map_err(|error| {
        Refusal::new(format!(
            "could not canonicalize producer executable: {error}"
        ))
    })?;
    let executable_sha256 = sha256_file(&executable)?;
    let inputs = json!({
        "schema": "ami-rust-cargo-prerequisite-producer-input-v1",
        "claim": CLAIM,
        "phase": options.phase,
        "profile": options.profile,
        "upstream_commit": plan.pin.commit,
        "source_pin_sha256": plan.pin_sha256,
        "patch_sha256": plan.patch_sha256,
        "producer_sha256": producer_sha256,
        "producer_executable": path_text(&executable, "producer executable path")?,
        "producer_executable_sha256": executable_sha256,
        "cargo_lock_sha256": cargo_lock_sha256,
        "compiler": compiler,
        "native_host_triple": native_host,
        "host": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "source": path_text(&source, "Cargo source path")?,
        "host_rust": path_text(&rust_root, "host Rust path")?,
        "work": path_text(&work_target.path, "producer work path")?,
        "vendor": path_text(&vendor_target.path, "vendor path")?,
        "record": path_text(&record_target.path, "producer record path")?,
        "command": command.iter().map(|argument| argument.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "environment": environment,
        "budgets": resource_profile,
        "explicit_resource_policy": resource_policy.as_ref().map(resource_policy_value),
        "vendor_overlay": vendor_overlay,
        "overlay_verifier_sha256": overlay_verifier_sha256,
    });
    write_json_new(&record, "inputs.json", &inputs)?;

    let spec = CommandSpec::new(
        command[0].clone(),
        command[1..].to_vec(),
        source.clone(),
        environment
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect(),
    );
    let signals = SigtermGuard::acquire()?;
    let roots = vec![
        source.clone(),
        work_target.path.clone(),
        vendor_target.path.clone(),
        record_target.path.clone(),
    ];
    let monitor = RefCell::new(WorkspaceMonitor::new(
        roots.clone(),
        resource_profile.workspace_bytes,
        resource_profile.log_bytes,
    ));
    let captured = capture_with_resources_observed(
        &spec,
        CaptureLimits {
            timeout: Duration::from_secs(resource_profile.seconds),
            stdout_bytes: CAPTURE_STREAM_BYTES,
            stderr_bytes: CAPTURE_STREAM_BYTES,
            termination_grace: PROCESS_GRACE,
        },
        ResourceLimits {
            max_visible_rss_bytes: resource_profile.rss_bytes,
            // Workspace is sampled by WorkspaceMonitor so the provision
            // output path may remain absent until Cargo creates it.
            max_workspace_bytes: u64::MAX,
            max_log_bytes: resource_profile.log_bytes,
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
        std::slice::from_ref(&record_target.path),
        || signals.requested(),
        |event| monitor.borrow_mut().observe(event),
    );
    let workspace_peak = monitor.borrow().peak_workspace_bytes;
    let observer_reason = monitor.borrow().stop_reason.clone();

    let mut command_result = match captured {
        Ok(captured) => CommandOutcome::completed(captured),
        Err(error) => CommandOutcome::failed(error),
    };
    if let Some(reason) = observer_reason {
        command_result.stop_reason = Some(reason);
    }
    if signals.requested() && command_result.stop_reason.is_none() {
        command_result.stop_reason = Some("producer interrupted by SIGTERM".to_owned());
    }

    let logs_written = write_capture_logs(
        &record,
        &command_result.stdout,
        &command_result.stderr,
        resource_profile.log_bytes as usize,
    )?;
    let workspace_after_logs = workspace_bytes(&roots)?;
    let workspace_peak = workspace_peak.max(workspace_after_logs);
    if workspace_after_logs > resource_profile.workspace_bytes
        && command_result.stop_reason.is_none()
    {
        command_result.stop_reason = Some("producer workspace".to_owned());
    }

    let mut overlay_recheck = None;
    let mut artifact = None;
    let mut postprocess_error = None;
    if should_inspect_cargo_artifact(
        options.phase,
        command_result
            .status
            .as_ref()
            .is_some_and(ExitStatus::success),
        command_result.stop_reason.is_none(),
        signals.requested(),
    ) {
        if let Some(receipt) = &vendor_overlay_receipt {
            match verify_overlay(&vendor_target.path, receipt, &recipe) {
                Ok(identity) => overlay_recheck = Some(identity),
                Err(error) => postprocess_error = Some(error.to_string()),
            }
        }
        if postprocess_error.is_none() {
            let binary = work_target.path.join("target").join(match options.profile {
                Profile::Dev => "debug/cargo",
                Profile::Release => "release/cargo",
            });
            match inspect_artifact(&binary, &source, &signals) {
                Ok(identity) => artifact = Some(identity),
                Err(error) => postprocess_error = Some(error.to_string()),
            }
        }
    }
    let provisioned_vendor = if should_inspect_vendor_output(
        options.phase,
        command_result
            .status
            .as_ref()
            .is_some_and(ExitStatus::success),
        command_result.stop_reason.is_none(),
        signals.requested(),
    ) {
        match inspect_vendor_output(&vendor_target.path) {
            Ok(identity) => Some(identity),
            Err(error) => {
                postprocess_error = Some(error.to_string());
                None
            }
        }
    } else {
        None
    };

    if let Some(error) = &postprocess_error
        && command_result.stop_reason.is_none()
    {
        command_result.stop_reason = Some(format!("post-build validation failed: {error}"));
    }
    let ((result, succeeded, returned_exit_code), interrupted_before_finalization, _) =
        finalize_with_sigterm_guard(signals, |interrupted| {
            if interrupted && command_result.stop_reason.is_none() {
                command_result.stop_reason = Some("producer interrupted by SIGTERM".to_owned());
            }
            let status_success = command_result
                .status
                .as_ref()
                .is_some_and(ExitStatus::success);
            let succeeded = status_success
                && command_result.stop_reason.is_none()
                && postprocess_error.is_none();
            let returned_exit_code = if succeeded {
                0
            } else if interrupted {
                130
            } else {
                command_result
                    .status
                    .as_ref()
                    .and_then(ExitStatus::code)
                    .filter(|code| *code > 0)
                    .unwrap_or(1)
            };
            let result = json!({
                "schema": RECEIPT_SCHEMA,
                "status": if succeeded { "PRODUCED_PREREQUISITE_ONLY" } else { "FAILED" },
                "claim": CLAIM,
                "exit_code": command_result.status.as_ref().and_then(ExitStatus::code),
                "signal": command_result.status.as_ref().and_then(ExitStatusExt::signal),
                "returned_exit_code": returned_exit_code,
                "stop_reason": command_result.stop_reason,
                "sigterm_requested_before_finalization": interrupted,
                "process_cleanup": {
                    "status": command_result.cleanup_status,
                    "error": command_result.cleanup_error,
                },
                "elapsed_seconds": command_result.elapsed_seconds,
                "cargo_process_tree_rss_peak_observed_bytes": command_result.resource_report.peak_visible_rss_bytes,
                "rss_scope": "Cargo process tree; excludes the supervising producer process",
                "workspace_peak_observed_bytes": workspace_peak,
                "log_peak_observed_bytes": command_result.resource_report.peak_log_bytes
                    .max(command_result.peak_output_bytes as u64),
                "logs_written_bytes": logs_written,
                "logs_truncated_to_profile": command_result.stdout.len().saturating_add(command_result.stderr.len()) > resource_profile.log_bytes as usize,
                "resources": command_result.resource_report,
                "vendor_overlay_recheck": overlay_recheck,
                "provisioned_vendor": provisioned_vendor,
                "postprocess_error": postprocess_error,
                "artifact": artifact,
            });
            write_json_new(&record, "result.json", &result)?;
            Ok((result, succeeded, returned_exit_code))
        })?;
    debug_assert!(!interrupted_before_finalization || !succeeded);
    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|error| Refusal::new(format!("cannot format producer result: {error}")))?
    );
    if !succeeded {
        return Err(Refusal::new(format!(
            "Cargo prerequisite producer failed; logs and receipt retained at {}",
            record_target.path.display()
        ))
        .with_exit_code(returned_exit_code.min(255) as u8));
    }
    Ok(result)
}

struct CommandOutcome {
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    elapsed_seconds: f64,
    stop_reason: Option<String>,
    resource_report: ResourceReport,
    peak_output_bytes: usize,
    cleanup_status: &'static str,
    cleanup_error: Option<String>,
}

impl CommandOutcome {
    fn completed(captured: crate::resource_capture::ResourceCapturedProcess) -> Self {
        let peak_output_bytes = captured
            .process
            .stdout
            .len()
            .saturating_add(captured.process.stderr.len());
        Self {
            status: Some(captured.process.status),
            stdout: captured.process.stdout,
            stderr: captured.process.stderr,
            elapsed_seconds: captured.process.elapsed.as_secs_f64(),
            stop_reason: None,
            resource_report: captured.report,
            peak_output_bytes,
            cleanup_status: "completed",
            cleanup_error: None,
        }
    }

    fn failed(error: ResourceCaptureError) -> Self {
        match error {
            ResourceCaptureError::Setup { error, report } => Self {
                status: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                elapsed_seconds: 0.0,
                stop_reason: Some(format!("producer monitor failed: {error}")),
                resource_report: *report,
                peak_output_bytes: 0,
                cleanup_status: "not_started",
                cleanup_error: None,
            },
            ResourceCaptureError::Capture { error, report } => {
                let reason = capture_stop_reason(&error.cause, &error.to_string());
                let peak_output_bytes = error.stdout.len().saturating_add(error.stderr.len());
                let cleanup_error = error.cleanup_error.map(|error| error.to_string());
                Self {
                    status: error.status,
                    stdout: error.stdout,
                    stderr: error.stderr,
                    elapsed_seconds: error.elapsed.as_secs_f64(),
                    stop_reason: Some(reason),
                    resource_report: *report,
                    peak_output_bytes,
                    cleanup_status: if cleanup_error.is_some() {
                        "failed"
                    } else {
                        "completed"
                    },
                    cleanup_error,
                }
            }
        }
    }
}

/// Keep the cooperative SIGTERM action installed until the result has been
/// synced. A request observed before the callback is part of the result; a
/// request delivered after that snapshot cannot turn a committed receipt into
/// an incomplete one.
fn finalize_with_sigterm_guard<T>(
    signals: SigtermGuard,
    finalize: impl FnOnce(bool) -> Result<T>,
) -> Result<(T, bool, bool)> {
    let finalized = signals.with_blocked(|| {
        let requested_before_finalization = signals.requested();
        finalize(requested_before_finalization).map(|value| (value, requested_before_finalization))
    });
    let requested_after_finalization = signals.requested();
    let restored = signals.finish();
    match (finalized, restored) {
        (Ok((value, requested_before)), Ok(())) => {
            Ok((value, requested_before, requested_after_finalization))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(Refusal::new(format!(
            "result finalization completed, but SIGTERM handler restoration failed: {error}"
        ))),
        (Err(error), Err(restore_error)) => Err(Refusal::new(format!(
            "{error}; SIGTERM handler restoration also failed: {restore_error}"
        ))),
    }
}

fn capture_stop_reason(cause: &CaptureCause, detail: &str) -> String {
    match cause {
        CaptureCause::Timeout => "producer timeout".to_owned(),
        CaptureCause::Cancelled => "producer cancelled".to_owned(),
        CaptureCause::StdoutLimitExceeded | CaptureCause::StderrLimitExceeded => {
            "producer log limit".to_owned()
        }
        CaptureCause::Observation(_)
            if detail.contains("visible process RSS exceeds caller limit") =>
        {
            "producer aggregate RSS".to_owned()
        }
        CaptureCause::Observation(_)
            if detail.contains("aggregate log bytes exceed caller limit") =>
        {
            "producer log limit".to_owned()
        }
        CaptureCause::Observation(_) => format!("producer monitor failed: {detail}"),
        CaptureCause::DescendantRetainedPipe => {
            "producer exited while a descendant retained an output pipe".to_owned()
        }
        CaptureCause::OutputAllocation => "producer output allocation failed".to_owned(),
        CaptureCause::Io(_) => format!("producer process capture failed: {detail}"),
    }
}

struct WorkspaceMonitor {
    roots: Vec<PathBuf>,
    maximum_workspace_bytes: u64,
    maximum_log_bytes: u64,
    next_workspace_sample: Duration,
    peak_workspace_bytes: u64,
    peak_output_bytes: usize,
    stop_reason: Option<String>,
}

impl WorkspaceMonitor {
    fn new(roots: Vec<PathBuf>, maximum_workspace_bytes: u64, maximum_log_bytes: u64) -> Self {
        Self {
            roots,
            maximum_workspace_bytes,
            maximum_log_bytes,
            next_workspace_sample: Duration::ZERO,
            peak_workspace_bytes: 0,
            peak_output_bytes: 0,
            stop_reason: None,
        }
    }

    fn observe(&mut self, event: CaptureObservation) -> std::io::Result<()> {
        let pending = event
            .stdout_bytes
            .checked_add(event.stderr_bytes)
            .ok_or_else(|| io::Error::other("captured output size overflow"))?;
        self.peak_output_bytes = self.peak_output_bytes.max(pending);
        if u64::try_from(pending).unwrap_or(u64::MAX) > self.maximum_log_bytes {
            self.stop_reason = Some("producer log limit".to_owned());
            return Err(io::Error::other("producer combined log limit exceeded"));
        }

        let sample_due = matches!(event.phase, CaptureObservationPhase::BeforeReap)
            || (matches!(
                event.phase,
                CaptureObservationPhase::Running { sample_due: true }
            ) && event.elapsed >= self.next_workspace_sample);
        if sample_due {
            let workspace =
                workspace_bytes_with_pending(&self.roots, pending).map_err(|error| {
                    self.stop_reason = Some(format!("producer monitor failed: {error}"));
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
            self.peak_workspace_bytes = self.peak_workspace_bytes.max(workspace);
            self.next_workspace_sample = event.elapsed.saturating_add(Duration::from_secs(2));
            if workspace > self.maximum_workspace_bytes {
                self.stop_reason = Some("producer workspace".to_owned());
                return Err(io::Error::other("producer workspace limit exceeded"));
            }
        }
        Ok(())
    }
}

fn load_pinned_plan(recipe: &Path) -> Result<LoadedPlan> {
    let pin_path = recipe.join("source.json");
    let pin_raw = read_regular_bounded(
        &pin_path,
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let pin_sha256 = sha256_bytes(&pin_raw);
    let profile = SOURCE_PROFILES
        .iter()
        .find(|profile| profile.source_pin_sha256 == pin_sha256)
        .ok_or_else(|| Refusal::new("pinned Cargo source recipe identity mismatch"))?;
    let pin: SourcePin = parse_json(&pin_raw, JsonProfile::PackageMetadataStateSelection)?;
    if pin.patch_sha256 != profile.patch_sha256
        || pin.upstream != "https://github.com/rust-lang/cargo"
        || pin.commit != "3efb1f477e99b42974b982d939fd100303cdf7db"
        || !is_sha256_digest(&pin.original_sha256)
        || !is_sha256_digest(&pin.patched_sha256)
    {
        return Err(Refusal::new(
            "pinned Cargo source recipe fields are inconsistent",
        ));
    }
    validate_source_pin_files(&pin)?;
    let patch_path = recipe.join("cargo-metadata.patch");
    if sha256_file(&patch_path)? != profile.patch_sha256 {
        return Err(Refusal::new("pinned Cargo source patch identity mismatch"));
    }
    Ok(LoadedPlan {
        pin,
        pin_sha256,
        patch_sha256: profile.patch_sha256.to_owned(),
        patch_path,
    })
}

fn validate_source_pin_files(pin: &SourcePin) -> Result<()> {
    validate_relative_inventory_path(&pin.path)?;
    let mut paths = BTreeSet::new();
    paths.insert(pin.path.clone());
    for row in &pin.additional_files {
        validate_relative_inventory_path(&row.path)?;
        if !is_sha256_digest(&row.original_sha256)
            || !is_sha256_digest(&row.patched_sha256)
            || !paths.insert(row.path.clone())
        {
            return Err(Refusal::new(
                "pinned Cargo source recipe has invalid additional file pins",
            ));
        }
    }
    Ok(())
}

fn validate_source_checkout(
    pin: &SourcePin,
    head: &str,
    source_sha256: &str,
    changed_paths: &[String],
    additional_digests: &BTreeMap<String, String>,
) -> Result<()> {
    if head != pin.commit {
        return Err(Refusal::new(
            "Cargo source checkout commit differs from its pin",
        ));
    }
    if source_sha256 != pin.patched_sha256 {
        return Err(Refusal::new("patched Cargo source identity mismatch"));
    }
    let mut expected_paths = vec![pin.path.clone()];
    expected_paths.extend(pin.additional_files.iter().map(|row| row.path.clone()));
    expected_paths.sort();
    let mut actual_paths = changed_paths.to_vec();
    actual_paths.sort();
    if actual_paths != expected_paths {
        return Err(Refusal::new(
            "Cargo source diff differs from the exact pinned patch file inventory",
        ));
    }
    for row in &pin.additional_files {
        if additional_digests.get(&row.path) != Some(&row.patched_sha256) {
            return Err(Refusal::new(format!(
                "patched Cargo additional source identity mismatch: {}",
                row.path
            )));
        }
    }
    Ok(())
}

fn cargo_command(
    phase: Phase,
    profile: Profile,
    source: &Path,
    rust_root: &Path,
    work: &Path,
    vendor: &Path,
) -> Result<(Vec<OsString>, BTreeMap<String, String>)> {
    let rust_bin = rust_root.join("bin");
    let cargo_home = work.join("cargo-home");
    let temporary = work.join("tmp");
    let home = work.join("home");
    let source_remap = remap_path(source, "/cargo-source")?;
    let work_remap = remap_path(work, "/cargo-build")?;
    let vendor_remap = remap_path(vendor, "/cargo-vendor")?;
    let mut rustflags = vec![source_remap, work_remap, vendor_remap];
    if cfg!(target_os = "macos") && phase == Phase::Build {
        rustflags.push("-C".to_owned());
        rustflags.push(format!(
            "link-arg=-Wl,-oso_prefix,{}/",
            path_text(rust_root, "Rust toolchain path")?
        ));
    }
    let encoded_rustflags = encode_rustflags(&rustflags)?;
    let cargo = rust_bin.join("cargo");
    let mut command = vec![cargo.into_os_string()];
    match phase {
        Phase::Provision => command.extend([
            OsString::from("vendor"),
            OsString::from("--locked"),
            OsString::from("--versioned-dirs"),
            vendor.as_os_str().to_os_string(),
        ]),
        Phase::Build => {
            command.extend([
                OsString::from("build"),
                OsString::from("--locked"),
                OsString::from("--offline"),
                OsString::from("-j"),
                OsString::from("2"),
                OsString::from("--bin"),
                OsString::from("cargo"),
                OsString::from("--features"),
                OsString::from("all-static"),
            ]);
            if profile == Profile::Release {
                command.push(OsString::from("--release"));
            }
        }
    }

    let mut environment = BTreeMap::from([
        ("HOME".to_owned(), path_text(&home, "producer HOME")?),
        (
            "PATH".to_owned(),
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                path_text(&rust_bin, "Rust bin path")?
            ),
        ),
        (
            "RUSTC".to_owned(),
            path_text(&rust_bin.join("rustc"), "rustc path")?,
        ),
        (
            "RUSTDOC".to_owned(),
            path_text(&rust_bin.join("rustdoc"), "rustdoc path")?,
        ),
        (
            "CARGO_HOME".to_owned(),
            path_text(&cargo_home, "Cargo home")?,
        ),
        (
            "CARGO_TARGET_DIR".to_owned(),
            path_text(&work.join("target"), "Cargo target directory")?,
        ),
        ("CARGO_BUILD_JOBS".to_owned(), "2".to_owned()),
        ("CARGO_INCREMENTAL".to_owned(), "0".to_owned()),
        ("CARGO_PROFILE_DEV_DEBUG".to_owned(), "0".to_owned()),
        (
            "CARGO_PROFILE_DEV_INCREMENTAL".to_owned(),
            "false".to_owned(),
        ),
        (
            "TMPDIR".to_owned(),
            path_text(&temporary, "producer TMPDIR")?,
        ),
        ("CARGO_PROFILE_RELEASE_DEBUG".to_owned(), "0".to_owned()),
        (
            "CARGO_PROFILE_RELEASE_INCREMENTAL".to_owned(),
            "false".to_owned(),
        ),
        ("CARGO_PROFILE_RELEASE_OPT_LEVEL".to_owned(), "2".to_owned()),
        (
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS".to_owned(),
            "16".to_owned(),
        ),
        ("CARGO_PROFILE_RELEASE_LTO".to_owned(), "false".to_owned()),
        ("LC_ALL".to_owned(), "C".to_owned()),
        ("TZ".to_owned(), "UTC".to_owned()),
        ("SOURCE_DATE_EPOCH".to_owned(), "1791936000".to_owned()),
        ("CARGO_ENCODED_RUSTFLAGS".to_owned(), encoded_rustflags),
    ]);
    if phase == Phase::Build {
        environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    }
    Ok((command, environment))
}

fn remap_path(path: &Path, target: &str) -> Result<String> {
    let path = path_text(path, "compiler remap path")?;
    if path.contains('\u{1f}') {
        return Err(Refusal::new(
            "Cargo encoded compiler flags cannot contain the unit separator in a path",
        ));
    }
    Ok(format!("--remap-path-prefix={path}={target}"))
}

fn encode_rustflags(flags: &[String]) -> Result<String> {
    if flags.iter().any(|flag| flag.contains('\u{1f}')) {
        return Err(Refusal::new(
            "Cargo encoded compiler flags cannot contain the unit separator",
        ));
    }
    Ok(flags.join("\u{1f}"))
}

fn git_environment() -> BTreeMap<OsString, OsString> {
    BTreeMap::from([
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        ),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
        (OsString::from("HOME"), OsString::from("/dev/null")),
        (OsString::from("LC_ALL"), OsString::from("C")),
    ])
}

fn probe_text(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    env: BTreeMap<OsString, OsString>,
    label: &str,
) -> Result<String> {
    let spec = CommandSpec::new(
        program.as_os_str().to_os_string(),
        args.iter().cloned(),
        cwd,
        env,
    );
    let output = capture(
        &spec,
        CaptureLimits {
            timeout: PROCESS_TIMEOUT,
            stdout_bytes: 1024 * 1024,
            stderr_bytes: 128 * 1024,
            termination_grace: PROCESS_GRACE,
        },
        || false,
    )
    .map_err(|error| Refusal::new(format!("{label} could not be captured: {error}")))?;
    if !output.status.success() {
        return Err(Refusal::new(format!(
            "{label} exited unsuccessfully ({})",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Refusal::new(format!("{label} output is not UTF-8")))
}

fn load_resource_policy(
    path: &Path,
    source: &Path,
) -> Result<(ResourceProfile, ResourcePolicyIdentity)> {
    let raw = read_regular_bounded(path, JsonProfile::PackageMetadataStateSelection.max_bytes())?;
    let value: Value = parse_json(&raw, JsonProfile::PackageMetadataStateSelection)?;
    if value.get("schema").and_then(Value::as_str) != Some("ami-rust-hosted-resources-v1") {
        return Err(Refusal::new("incompatible hosted producer resource policy"));
    }
    let build = value
        .get("build")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("hosted producer build profile is missing"))?;
    let expected = BTreeSet::from([
        "jobs",
        "log_bytes",
        "rss_bytes",
        "seconds",
        "workspace_bytes",
    ]);
    if build.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(Refusal::new(
            "hosted producer resource fields differ from the admitted profile",
        ));
    }
    let profile = ResourceProfile {
        seconds: policy_integer(build.get("seconds"), "seconds")?,
        rss_bytes: policy_integer(build.get("rss_bytes"), "rss_bytes")?,
        workspace_bytes: policy_integer(build.get("workspace_bytes"), "workspace_bytes")?,
        jobs: policy_integer(build.get("jobs"), "jobs")?,
        log_bytes: policy_integer(build.get("log_bytes"), "log_bytes")?,
    };
    let ceilings = ResourceProfile::default();
    if profile.seconds == 0
        || profile.seconds > ceilings.seconds
        || profile.rss_bytes == 0
        || profile.rss_bytes > ceilings.rss_bytes
        || profile.workspace_bytes == 0
        || profile.workspace_bytes > ceilings.workspace_bytes
        || profile.jobs != JOBS
        || profile.log_bytes == 0
        || profile.log_bytes > ceilings.log_bytes
    {
        return Err(Refusal::new(
            "hosted producer resource limits exceed the admitted profile",
        ));
    }
    let capacity = value
        .get("host_capacity")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("hosted producer capacity policy is missing"))?;
    let expected_capacity =
        BTreeSet::from(["disk_free_minimum_bytes", "ram_minimum_bytes", "schema"]);
    if capacity.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_capacity
        || capacity.get("schema").and_then(Value::as_str) != Some("ami-rust-host-capacity-v1")
    {
        return Err(Refusal::new("incompatible host capacity policy"));
    }
    let ram_minimum_bytes = policy_integer(capacity.get("ram_minimum_bytes"), "RAM floor")?;
    let disk_free_minimum_bytes =
        policy_integer(capacity.get("disk_free_minimum_bytes"), "disk floor")?;
    if ram_minimum_bytes < MINIMUM_RAM_BYTES || disk_free_minimum_bytes < MINIMUM_FREE_DISK_BYTES {
        return Err(Refusal::new(
            "host capacity minima are below the admitted floors",
        ));
    }
    let (physical_ram_bytes, free_disk_bytes) = host_capacity(source)?;
    if physical_ram_bytes < ram_minimum_bytes || free_disk_bytes < disk_free_minimum_bytes {
        return Err(Refusal::new(format!(
            "host capacity refused: {physical_ram_bytes} RAM bytes and {free_disk_bytes} free bytes",
        )));
    }
    let capacity_value = Value::Object(capacity.clone());
    Ok((
        profile,
        ResourcePolicyIdentity {
            json: json!({
                "sha256": sha256_bytes(&raw),
                "host_capacity": capacity_value,
                "physical_ram_bytes": physical_ram_bytes,
                "free_disk_bytes": free_disk_bytes,
            }),
            capacity: Value::Object(capacity.clone()),
            physical_ram_bytes,
            free_disk_bytes,
        },
    ))
}

fn policy_integer(value: Option<&Value>, label: &str) -> Result<u64> {
    value.and_then(Value::as_u64).ok_or_else(|| {
        Refusal::new(format!(
            "hosted resource {label} must be a positive integer"
        ))
    })
}

fn resource_policy_value(identity: &ResourcePolicyIdentity) -> Value {
    json!({
        "sha256": identity.json["sha256"],
        "host_capacity": identity.capacity,
        "physical_ram_bytes": identity.physical_ram_bytes,
        "free_disk_bytes": identity.free_disk_bytes,
    })
}

#[allow(
    unsafe_code,
    reason = "POSIX sysconf/statvfs only read host physical RAM and available disk."
)]
#[allow(
    clippy::unnecessary_cast,
    reason = "statvfs field widths differ across supported Unix hosts."
)]
/// Read physical host RAM and available bytes on the filesystem containing `source`.
pub fn host_capacity(source: &Path) -> Result<(u64, u64)> {
    use std::mem::MaybeUninit;

    // SAFETY: sysconf takes no pointers and returns the physical page count
    // and page size; nonpositive values are rejected below.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    // SAFETY: same read-only query for the system page size.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let ram = u64::try_from(pages)
        .ok()
        .and_then(|pages| u64::try_from(page_size).ok().map(|size| (pages, size)))
        .filter(|(pages, size)| *pages > 0 && *size > 0)
        .and_then(|(pages, size)| pages.checked_mul(size))
        .ok_or_else(|| Refusal::new("could not determine physical host RAM"))?;

    let source_c = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| Refusal::new("Cargo source path contains NUL"))?;
    let mut stats = MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: source_c is a NUL-terminated path and stats points to writable
    // storage; successful statvfs initializes the complete structure.
    if unsafe { libc::statvfs(source_c.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(Refusal::new(format!(
            "could not measure free Cargo source workspace: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful statvfs initialized the complete structure.
    let stats = unsafe { stats.assume_init() };
    let unit = if stats.f_frsize != 0 {
        stats.f_frsize as u64
    } else {
        stats.f_bsize as u64
    };
    let free = (stats.f_bavail as u64)
        .checked_mul(unit)
        .ok_or_else(|| Refusal::new("free Cargo source workspace size overflow"))?;
    Ok((ram, free))
}

fn inspect_artifact(binary: &Path, source: &Path, signals: &SigtermGuard) -> Result<Value> {
    let file = open_regular_nofollow(binary)?;
    let bytes = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect Cargo artifact: {error}")))?
        .len();
    let digest = sha256_file(binary)?;
    let output = probe_capture(
        binary,
        &[OsString::from("-Vv")],
        source,
        BTreeMap::from([
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("TZ"), OsString::from("UTC")),
        ]),
        || signals.requested(),
    )
    .map_err(|error| Refusal::new(format!("built Cargo version probe failed: {error}")))?;
    if !output.status.success() {
        return Err(Refusal::new(format!(
            "built Cargo version probe exited unsuccessfully ({})",
            output.status
        )));
    }
    let version = String::from_utf8(output.stdout)
        .map_err(|_| Refusal::new("built Cargo version is not UTF-8"))?;
    Ok(json!({
        "path": path_text(binary, "Cargo artifact path")?,
        "bytes": bytes,
        "sha256": digest,
        "version": version,
    }))
}

fn inspect_vendor_output(vendor: &Path) -> Result<Value> {
    let vendor = existing_directory(vendor, "Cargo vendor output")?;
    let directory = Directory::open(&vendor)?;
    let metadata = directory.metadata()?;
    if metadata.mode() & 0o022 != 0 {
        return Err(Refusal::new(
            "Cargo vendor output directory is group/world writable",
        ));
    }
    let accounting = workspace_accounting::scan(
        &vendor,
        ScanLimits {
            max_entries: WORKSPACE_SCAN_ENTRIES,
            max_work_units: WORKSPACE_SCAN_WORK,
        },
    )
    .map_err(|error| Refusal::new(format!("Cargo vendor output scan failed: {error}")))?;
    Ok(json!({
        "path": path_text(&vendor, "Cargo vendor output path")?,
        "root_mode": metadata.mode() & 0o7777,
        "entries_seen": accounting.entries_seen,
        "regular_file_bytes": accounting.regular_file_bytes,
    }))
}

fn should_inspect_cargo_artifact(
    phase: Phase,
    command_succeeded: bool,
    stop_reason_absent: bool,
    interrupted: bool,
) -> bool {
    phase == Phase::Build && command_succeeded && stop_reason_absent && !interrupted
}

fn should_inspect_vendor_output(
    phase: Phase,
    command_succeeded: bool,
    stop_reason_absent: bool,
    interrupted: bool,
) -> bool {
    phase == Phase::Provision && command_succeeded && stop_reason_absent && !interrupted
}

fn probe_capture(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    env: BTreeMap<OsString, OsString>,
    cancelled: impl FnMut() -> bool,
) -> std::result::Result<CapturedProcess, crate::process_capture::CaptureError> {
    capture(
        &CommandSpec::new(
            program.as_os_str().to_os_string(),
            args.iter().cloned(),
            cwd,
            env,
        ),
        CaptureLimits {
            timeout: PROCESS_TIMEOUT,
            stdout_bytes: 1024 * 1024,
            stderr_bytes: 128 * 1024,
            termination_grace: PROCESS_GRACE,
        },
        cancelled,
    )
}

fn workspace_bytes(roots: &[PathBuf]) -> Result<u64> {
    workspace_bytes_with_pending(roots, 0)
}

fn workspace_bytes_with_pending(roots: &[PathBuf], pending: usize) -> Result<u64> {
    let limits = ScanLimits {
        max_entries: WORKSPACE_SCAN_ENTRIES,
        max_work_units: WORKSPACE_SCAN_WORK,
    };
    let mut total = u64::try_from(pending)
        .map_err(|_| Refusal::new("pending Cargo output size is not representable"))?;
    for root in roots {
        let Accounting {
            regular_file_bytes, ..
        } = workspace_accounting::scan(root, limits)
            .map_err(|error| Refusal::new(format!("producer workspace scan failed: {error}")))?;
        total = total
            .checked_add(regular_file_bytes)
            .ok_or_else(|| Refusal::new("producer workspace byte sum overflow"))?;
    }
    Ok(total)
}

fn write_capture_logs(
    record: &Directory,
    stdout: &[u8],
    stderr: &[u8],
    maximum: usize,
) -> Result<u64> {
    let stdout_bytes = stdout.len().min(maximum);
    let remaining = maximum.saturating_sub(stdout_bytes);
    let stderr_bytes = stderr.len().min(remaining);
    write_new_file(record, "stdout.log", &stdout[..stdout_bytes])?;
    write_new_file(record, "stderr.log", &stderr[..stderr_bytes])?;
    u64::try_from(stdout_bytes.saturating_add(stderr_bytes))
        .map_err(|_| Refusal::new("written Cargo log size is not representable"))
}

fn write_json_new(root: &Directory, name: &str, value: &Value) -> Result<()> {
    let mut raw = serde_json::to_vec_pretty(value)
        .map_err(|error| Refusal::new(format!("cannot serialize producer record: {error}")))?;
    raw.push(b'\n');
    write_new_file(root, name, &raw)
}

fn write_new_file(root: &Directory, name: &str, raw: &[u8]) -> Result<()> {
    let mut file = root.create_new_file(OsStr::new(name), 0o600)?;
    file.write_all(raw)?;
    file.sync_all()?;
    Ok(())
}

struct TargetPath {
    path: PathBuf,
    parent: Directory,
    name: OsString,
}

fn existing_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let target = target_path(path, label)?;
    let directory = target
        .parent
        .child(&target.name)
        .map_err(|error| Refusal::new(format!("{label} must be a real directory: {error}")))?;
    if !directory.metadata()?.is_dir() {
        return Err(Refusal::new(format!("{label} is not a directory")));
    }
    Ok(target.path)
}

fn existing_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let target = target_path(path, label)?;
    let file = target
        .parent
        .regular(&target.name)
        .map_err(|error| Refusal::new(format!("{label} must be a regular file: {error}")))?;
    drop(file);
    Ok(target.path)
}

fn target_path(path: &Path, label: &str) -> Result<TargetPath> {
    let absolute = absolute_normalized(path, label)?;
    let name = match absolute.components().next_back() {
        Some(Component::Normal(name)) => name.to_os_string(),
        _ => return Err(Refusal::new(format!("{label} path has no final component"))),
    };
    let parent_path = absolute
        .parent()
        .ok_or_else(|| Refusal::new(format!("{label} path has no parent")))?;
    let before = fs::metadata(parent_path)
        .map_err(|error| Refusal::new(format!("could not inspect {label} parent: {error}")))?;
    let canonical_parent = fs::canonicalize(parent_path)
        .map_err(|error| Refusal::new(format!("could not resolve {label} parent: {error}")))?;
    let parent = Directory::open(&canonical_parent)
        .map_err(|error| Refusal::new(format!("{label} parent is unsafe: {error}")))?;
    let after = parent.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Refusal::new(format!(
            "{label} parent changed during path resolution"
        )));
    }
    Ok(TargetPath {
        path: canonical_parent.join(&name),
        parent,
        name,
    })
}

fn absolute_normalized(path: &Path, label: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(Refusal::new(format!("{label} path is required")));
    }
    let input = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| Refusal::new(format!("could not resolve current directory: {error}")))?
            .join(path)
    };
    if !input.is_absolute() {
        return Err(Refusal::new(format!("{label} path must be absolute")));
    }
    Ok(input)
}

fn target_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Refusal::new(format!(
            "could not inspect producer path {}: {error}",
            path.display()
        ))),
    }
}

fn ensure_directory(target: &TargetPath, existed: bool, label: &str) -> Result<Directory> {
    if existed {
        let directory = target
            .parent
            .child(&target.name)
            .map_err(|error| Refusal::new(format!("{label} must be a real directory: {error}")))?;
        if directory.metadata()?.mode() & 0o022 != 0 {
            return Err(Refusal::new(format!(
                "existing {label} directory is group/world writable"
            )));
        }
        Ok(directory)
    } else {
        target
            .parent
            .mkdir_new(&target.name, 0o700)
            .map_err(|error| Refusal::new(format!("could not create {label}: {error}")))
    }
}

fn create_fresh_directory(target: &TargetPath, label: &str) -> Result<Directory> {
    target
        .parent
        .mkdir_new(&target.name, 0o700)
        .map_err(|error| Refusal::new(format!("{label} must be fresh: {error}")))
}

fn ensure_child_directory(
    parent: &Directory,
    parent_path: &Path,
    child_name: &str,
) -> Result<PathBuf> {
    let path = parent_path.join(child_name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let directory = parent.child(OsStr::new(child_name)).map_err(|error| {
                Refusal::new(format!(
                    "producer directory must be a real directory: {error}"
                ))
            })?;
            if directory.metadata()?.mode() & 0o022 != 0 {
                return Err(Refusal::new(
                    "existing producer subdirectory is group/world writable",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            parent.mkdir_new(OsStr::new(child_name), 0o700)?;
        }
        Err(error) => {
            return Err(Refusal::new(format!(
                "could not inspect producer subdirectory: {error}"
            )));
        }
    }
    Ok(path)
}

fn validate_output_separation(protected: &[&PathBuf], outputs: &[&PathBuf]) -> Result<()> {
    for (index, output) in outputs.iter().enumerate() {
        for other in outputs.iter().skip(index + 1) {
            if paths_overlap(output, other) {
                return Err(Refusal::new(
                    "producer work, vendor, and record paths must be disjoint",
                ));
            }
        }
        for input in protected {
            if paths_overlap(output, input) {
                return Err(Refusal::new(
                    "producer outputs must be disjoint from source, recipe, and host Rust inputs",
                ));
            }
        }
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn path_text(path: &Path, label: &str) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| Refusal::new(format!("{label} is not UTF-8")))?;
    if value.contains('\0') {
        return Err(Refusal::new(format!("{label} contains NUL")));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    const SIGTERM_CHILD_MODE: &str = "AMI_RUST_CARGO_PRODUCER_FINALIZATION_CHILD";
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ami-rust-cargo-producer-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temporary producer fixture");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove producer fixture");
        }
    }

    #[test]
    fn three_host_recipe_reuses_the_exact_pinned_cargo_source_and_patch() {
        let recipe = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../host/cargo-repro/three-host-v2")
            .canonicalize()
            .unwrap();
        let plan = load_pinned_plan(&recipe).unwrap();
        assert_eq!(plan.pin_sha256, SOURCE_PIN_V2_SHA256);
        assert_eq!(plan.patch_sha256, PATCH_V2_SHA256);
        assert_eq!(sha256_file(&plan.patch_path).unwrap(), PATCH_V2_SHA256);
    }

    #[test]
    fn three_host_v3_recipe_loads_only_its_exact_pin_patch_and_four_file_inventory() {
        let recipe = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../host/cargo-repro/three-host-v3")
            .canonicalize()
            .unwrap();
        let plan = load_pinned_plan(&recipe).unwrap();
        assert_eq!(plan.pin_sha256, SOURCE_PIN_V3_SHA256);
        assert_eq!(plan.patch_sha256, PATCH_V3_SHA256);
        assert_eq!(sha256_file(&plan.patch_path).unwrap(), PATCH_V3_SHA256);
        assert_eq!(plan.pin.additional_files.len(), 3);
        assert_eq!(
            plan.pin
                .additional_files
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            [
                "src/workspace/features.rs",
                "src/compiler/build_runner/mod.rs",
                "src/compiler/fingerprint/mod.rs"
            ]
        );
    }

    #[test]
    fn v3_recipe_refuses_copied_unknown_pin_and_wrong_patch_bytes() {
        let recipe = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../host/cargo-repro/three-host-v3")
            .canonicalize()
            .unwrap();
        let root = TempDir::new();

        let unknown_pin = root.path().join("unknown-pin");
        copy_recipe(&recipe, &unknown_pin);
        let mut pin = fs::read(unknown_pin.join("source.json")).unwrap();
        pin.push(b' ');
        fs::write(unknown_pin.join("source.json"), pin).unwrap();
        assert!(load_pinned_plan(&unknown_pin).is_err());

        let wrong_patch = root.path().join("wrong-patch");
        copy_recipe(&recipe, &wrong_patch);
        let mut patch = fs::read(wrong_patch.join("cargo-metadata.patch")).unwrap();
        patch.push(b'\n');
        fs::write(wrong_patch.join("cargo-metadata.patch"), patch).unwrap();
        assert!(load_pinned_plan(&wrong_patch).is_err());
    }

    fn copy_recipe(source: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        for name in ["source.json", "cargo-metadata.patch"] {
            fs::copy(source.join(name), destination.join(name)).unwrap();
        }
    }

    fn fixture_pin() -> SourcePin {
        SourcePin {
            upstream: "https://github.com/rust-lang/cargo".to_owned(),
            commit: "3efb1f477e99b42974b982d939fd100303cdf7db".to_owned(),
            path: "src/lib.rs".to_owned(),
            original_sha256: sha256_bytes(b"original"),
            patched_sha256: sha256_bytes(b"patched"),
            patch_sha256: PATCH_V2_SHA256.to_owned(),
            purpose: "fixture".to_owned(),
            scope: "fixture".to_owned(),
            rustc_or_rust_src_changes: false,
            additional_files: vec![AdditionalSourceFile {
                path: "src/extra.rs".to_owned(),
                original_sha256: sha256_bytes(b"extra original"),
                patched_sha256: sha256_bytes(b"extra patched"),
            }],
            opt_in: "fixture".to_owned(),
            environment_marker_required: false,
        }
    }

    #[test]
    fn source_checkout_requires_exact_pinned_commit_files_and_patch_digests() {
        let pin = fixture_pin();
        let changed = vec!["src/lib.rs".to_owned(), "src/extra.rs".to_owned()];
        let additional = BTreeMap::from([(
            "src/extra.rs".to_owned(),
            pin.additional_files[0].patched_sha256.clone(),
        )]);
        assert!(
            validate_source_checkout(
                &pin,
                &pin.commit,
                &pin.patched_sha256,
                &changed,
                &additional
            )
            .is_ok()
        );

        assert!(
            validate_source_checkout(
                &pin,
                "different",
                &pin.patched_sha256,
                &changed,
                &additional
            )
            .is_err()
        );
        assert!(
            validate_source_checkout(
                &pin,
                &pin.commit,
                &sha256_bytes(b"wrong"),
                &changed,
                &additional
            )
            .is_err()
        );
        assert!(
            validate_source_checkout(
                &pin,
                &pin.commit,
                &pin.patched_sha256,
                &["src/lib.rs".to_owned()],
                &additional
            )
            .is_err()
        );
        assert!(
            validate_source_checkout(
                &pin,
                &pin.commit,
                &pin.patched_sha256,
                &changed,
                &BTreeMap::new()
            )
            .is_err()
        );
    }

    #[test]
    fn v3_source_checkout_requires_all_four_exact_paths_and_postimages() {
        let recipe = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../host/cargo-repro/three-host-v3")
            .canonicalize()
            .unwrap();
        let plan = load_pinned_plan(&recipe).unwrap();
        let mut changed = vec![plan.pin.path.clone()];
        changed.extend(plan.pin.additional_files.iter().map(|row| row.path.clone()));
        let additional = plan
            .pin
            .additional_files
            .iter()
            .map(|row| (row.path.clone(), row.patched_sha256.clone()))
            .collect::<BTreeMap<_, _>>();
        assert!(validate_source_pin_files(&plan.pin).is_ok());
        assert!(
            validate_source_checkout(
                &plan.pin,
                &plan.pin.commit,
                &plan.pin.patched_sha256,
                &changed,
                &additional
            )
            .is_ok()
        );

        assert!(
            validate_source_checkout(
                &plan.pin,
                &plan.pin.commit,
                &sha256_bytes(b"wrong primary postimage"),
                &changed,
                &additional
            )
            .is_err()
        );

        let mut missing = changed.clone();
        missing.pop();
        assert!(
            validate_source_checkout(
                &plan.pin,
                &plan.pin.commit,
                &plan.pin.patched_sha256,
                &missing,
                &additional
            )
            .is_err()
        );

        let mut extra = changed.clone();
        extra.push("src/compiler/extra.rs".to_owned());
        assert!(
            validate_source_checkout(
                &plan.pin,
                &plan.pin.commit,
                &plan.pin.patched_sha256,
                &extra,
                &additional
            )
            .is_err()
        );

        let mut wrong_postimage = additional.clone();
        wrong_postimage.insert(
            plan.pin.additional_files[2].path.clone(),
            sha256_bytes(b"wrong postimage"),
        );
        assert!(
            validate_source_checkout(
                &plan.pin,
                &plan.pin.commit,
                &plan.pin.patched_sha256,
                &changed,
                &wrong_postimage
            )
            .is_err()
        );
    }

    #[test]
    fn source_pin_file_inventory_rejects_unsafe_and_duplicate_paths() {
        let pin = load_pinned_plan(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../host/cargo-repro/three-host-v3")
                .canonicalize()
                .unwrap(),
        )
        .unwrap()
        .pin;
        let mut duplicate = pin.clone();
        duplicate.additional_files[0].path = duplicate.path.clone();
        assert!(validate_source_pin_files(&duplicate).is_err());

        let mut unsafe_path = pin;
        unsafe_path.additional_files[0].path = "../outside.rs".to_owned();
        assert!(validate_source_pin_files(&unsafe_path).is_err());
    }

    #[test]
    fn producer_command_keeps_offline_static_build_profile_and_explicit_remaps() {
        let root = Path::new("/tmp/fixture with spaces");
        let source = root.join("source");
        let rust = root.join("rust");
        let work = root.join("work");
        let vendor = root.join("vendor");
        let (command, environment) = cargo_command(
            Phase::Build,
            Profile::Release,
            &source,
            &rust,
            &work,
            &vendor,
        )
        .unwrap();
        let command_arguments = command[1..]
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            command_arguments,
            [
                "build",
                "--locked",
                "--offline",
                "-j",
                "2",
                "--bin",
                "cargo",
                "--features",
                "all-static",
                "--release",
            ]
        );
        assert_eq!(
            environment.get("CARGO_NET_OFFLINE").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            environment.get("CARGO_BUILD_JOBS").map(String::as_str),
            Some("2")
        );
        let encoded_flags = environment.get("CARGO_ENCODED_RUSTFLAGS").unwrap();
        let flags = encoded_flags.split('\u{1f}').collect::<Vec<_>>();
        assert!(flags[0].contains("fixture with spaces/source=/cargo-source"));
        assert!(flags[1].contains("fixture with spaces/work=/cargo-build"));
        assert!(flags[2].contains("fixture with spaces/vendor=/cargo-vendor"));
        if cfg!(target_os = "macos") {
            assert_eq!(flags[3], "-C");
            assert!(flags[4].starts_with("link-arg=-Wl,-oso_prefix,"));
        }
        assert!(!environment.contains_key("RUSTFLAGS"));
        assert!(!environment.contains_key("HTTP_PROXY"));
    }

    #[test]
    fn workspace_accounting_ignores_symlink_targets_but_counts_regular_files() {
        let root = TempDir::new();
        let source = root.path().join("source");
        let work = root.path().join("work");
        let vendor = root.path().join("vendor");
        let record = root.path().join("record");
        for path in [&source, &work, &vendor, &record] {
            fs::create_dir(path).unwrap();
        }
        fs::write(source.join("file"), b"four").unwrap();
        fs::write(root.path().join("outside"), b"outside bytes").unwrap();
        symlink(root.path().join("outside"), work.join("link")).unwrap();
        assert_eq!(workspace_bytes(&[source, work, vendor, record]).unwrap(), 4);
    }

    #[test]
    fn caller_parent_alias_is_resolved_before_opening_the_output_parent() {
        let root = TempDir::new();
        let real = root.path().join("real");
        let alias = root.path().join("alias");
        fs::create_dir(&real).unwrap();
        symlink(&real, &alias).unwrap();

        let target = target_path(&alias.join("output"), "fixture output").unwrap();
        assert_eq!(target.path, real.join("output"));
        target.parent.mkdir_new(&target.name, 0o700).unwrap();
        assert!(real.join("output").is_dir());
    }

    #[test]
    fn phase_postprocess_selects_only_its_own_success_artifact() {
        assert!(should_inspect_cargo_artifact(
            Phase::Build,
            true,
            true,
            false
        ));
        assert!(!should_inspect_cargo_artifact(
            Phase::Provision,
            true,
            true,
            false
        ));
        assert!(should_inspect_vendor_output(
            Phase::Provision,
            true,
            true,
            false
        ));
        assert!(!should_inspect_vendor_output(
            Phase::Build,
            true,
            true,
            false
        ));
    }

    #[test]
    fn failed_command_logs_are_retained_with_the_combined_profile_bound() {
        let root = TempDir::new();
        let record = Directory::open(root.path()).unwrap();
        let written =
            write_capture_logs(&record, b"partial stdout", b"partial stderr", 20).unwrap();
        assert_eq!(written, 20);
        assert_eq!(
            fs::read(root.path().join("stdout.log")).unwrap(),
            b"partial stdout"
        );
        assert_eq!(fs::read(root.path().join("stderr.log")).unwrap(), b"partia");
    }

    #[test]
    fn capture_cleanup_failure_is_preserved_separately_from_stop_reason() {
        let outcome = CommandOutcome::failed(ResourceCaptureError::Capture {
            error: crate::process_capture::CaptureError {
                cause: CaptureCause::Timeout,
                stdout: b"partial stdout".to_vec(),
                stderr: b"partial stderr".to_vec(),
                status: None,
                elapsed: Duration::from_secs(2),
                cleanup_error: Some(io::Error::other("injected child cleanup failure")),
            },
            report: Box::default(),
        });

        assert_eq!(outcome.stop_reason.as_deref(), Some("producer timeout"));
        assert_eq!(outcome.cleanup_status, "failed");
        assert_eq!(
            outcome.cleanup_error.as_deref(),
            Some("injected child cleanup failure")
        );
    }

    #[test]
    fn sigterm_finalization_commits_a_complete_receipt_before_restoring_handler() {
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("cargo_producer::tests::sigterm_finalization_child_fixture")
            .arg("--ignored")
            .arg("--nocapture")
            .env(SIGTERM_CHILD_MODE, "run")
            .output()
            .expect("spawn isolated SIGTERM finalization fixture");
        assert!(
            output.status.success(),
            "isolated finalization fixture failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run only through the isolated child-process test"]
    fn sigterm_finalization_child_fixture() {
        assert_eq!(std::env::var(SIGTERM_CHILD_MODE).as_deref(), Ok("run"));
        let original_mask =
            set_sigterm_mask(libc::SIG_UNBLOCK).expect("unblock SIGTERM for the isolated fixture");
        let root = TempDir::new();
        let record = Directory::open(root.path()).expect("open result fixture directory");
        let guard = SigtermGuard::acquire().expect("acquire SIGTERM guard");

        let (receipt, requested_before, requested_after) =
            finalize_with_sigterm_guard(guard, |interrupted| {
                assert!(!interrupted, "SIGTERM arrived before the commit boundary");
                send_sigterm_to_current_thread()?;
                let receipt = json!({
                    "status": "PRODUCED_PREREQUISITE_ONLY",
                    "sigterm_requested_before_finalization": interrupted,
                    "complete": true,
                });
                write_json_new(&record, "result.json", &receipt)?;
                Ok(receipt)
            })
            .expect("finish and restore SIGTERM after receipt sync");

        assert!(!requested_before);
        assert!(
            requested_after,
            "pending SIGTERM was not observed after commit"
        );
        assert_eq!(
            receipt.get("status").and_then(Value::as_str),
            Some("PRODUCED_PREREQUISITE_ONLY")
        );
        assert_eq!(receipt.get("complete").and_then(Value::as_bool), Some(true));
        let persisted: Value = serde_json::from_slice(
            &fs::read(root.path().join("result.json")).expect("read committed result"),
        )
        .expect("parse committed result");
        assert_eq!(persisted, receipt);
        restore_sigterm_mask(&original_mask).expect("restore isolated fixture signal mask");
    }

    #[allow(
        unsafe_code,
        reason = "The isolated fixture adjusts its current thread's SIGTERM mask."
    )]
    fn set_sigterm_mask(how: libc::c_int) -> Result<libc::sigset_t> {
        let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: both pointers refer to writable storage for sigset_t.
        if unsafe { libc::sigemptyset(set.as_mut_ptr()) } != 0
            || unsafe { libc::sigaddset(set.as_mut_ptr(), libc::SIGTERM) } != 0
        {
            return Err(Refusal::new(format!(
                "could not create isolated SIGTERM mask: {}",
                io::Error::last_os_error()
            )));
        }
        let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: the signal set and output pointer are valid for pthread_sigmask.
        let result = unsafe { libc::pthread_sigmask(how, set.as_ptr(), previous.as_mut_ptr()) };
        if result != 0 {
            return Err(Refusal::new(format!(
                "could not adjust isolated SIGTERM mask: {}",
                io::Error::from_raw_os_error(result)
            )));
        }
        // SAFETY: pthread_sigmask initialized the previous mask on success.
        Ok(unsafe { previous.assume_init() })
    }

    #[allow(
        unsafe_code,
        reason = "The isolated fixture restores its current thread's signal mask."
    )]
    fn restore_sigterm_mask(previous: &libc::sigset_t) -> Result<()> {
        // SAFETY: `previous` is a valid mask captured by set_sigterm_mask.
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, previous, std::ptr::null_mut()) };
        if result != 0 {
            return Err(Refusal::new(format!(
                "could not restore isolated SIGTERM mask: {}",
                io::Error::from_raw_os_error(result)
            )));
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "The isolated fixture sends SIGTERM to its current test thread."
    )]
    fn send_sigterm_to_current_thread() -> Result<()> {
        // SAFETY: pthread_self returns this live test thread's identifier.
        let current = unsafe { libc::pthread_self() };
        // SAFETY: SIGTERM is valid and `current` is the calling thread.
        let result = unsafe { libc::pthread_kill(current, libc::SIGTERM) };
        if result != 0 {
            return Err(Refusal::new(format!(
                "could not queue SIGTERM for finalization fixture: {}",
                io::Error::from_raw_os_error(result)
            )));
        }
        Ok(())
    }
}

//! Maintainer-only interruption observation for the published 0.1.0-2 Python
//! prepare command. This historical control deliberately executes Python; it
//! is not part of the active consumer oracle and proves no no-Python claim.

use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes},
    host_platform,
    json::{JsonProfile, parse_json_value},
    ownership,
    process_capture::{
        CaptureCause, CaptureError, CaptureLimits, CaptureObservation, CaptureObservationPhase,
        CapturedProcess, CommandSpec, capture_observed,
    },
    records::Host,
    signals::SigtermGuard,
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const CI_PYTHON_INPUTS: &str = include_str!("../../../../release/ci-python-inputs.json");
const HISTORICAL_CLI_SHA256: &str =
    "c9ebf03734968a19a6ee9242fdb04a04e314b9da2dbdb682a762b610d81d6378";
const HISTORICAL_CLI_MAX_BYTES: u64 = 64 * 1024;
const PYTHON_RUNTIME_MAX_BYTES: u64 = 128 * 1024 * 1024;
const STAGE_LABEL: &str = "fetch begun, checkout/bootstrap not begun";
const STAGE_DEADLINE: Duration = Duration::from_secs(15);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(120);
const STREAM_LIMIT: usize = 16 * 1024 * 1024;
const SIGTERM: i32 = 15;

#[derive(Clone, Debug)]
struct ProbePaths {
    python: PathBuf,
    frontend: PathBuf,
    state: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
    cwd: PathBuf,
    output: PathBuf,
}

#[derive(Clone, Debug)]
struct PythonPin {
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug)]
struct InputDigests {
    python_sha256: String,
    frontend_sha256: String,
}

#[derive(Default)]
struct Gate {
    attempted: bool,
    sent: bool,
    pid: Option<u32>,
    elapsed_ms: Option<u128>,
    fetch_head: Option<Value>,
    later_stage: Option<Vec<String>>,
    scan_error: Option<String>,
    signal_error: Option<String>,
}

enum Stage {
    Waiting,
    Ready(Value),
    Later(Vec<String>),
}

struct CaptureOutcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    elapsed_ms: u128,
    result: &'static str,
    cause_name: Option<&'static str>,
    cause_detail: Option<String>,
    cleanup_error: Option<String>,
}

struct PostCapture {
    fetch_head: Value,
    ready_json_present: Option<bool>,
    upper_ready_present: Option<bool>,
    index_present: Option<bool>,
    cli_python_present: Option<bool>,
    later_markers: Vec<String>,
    private_state: bool,
    error: Option<String>,
}

pub fn run(mut args: impl Iterator<Item = OsString>) -> Result<()> {
    let paths = parse_and_validate_paths(&mut args)?;
    let host = host_platform::supported_host()?;
    create_private_output(&paths.output)?;
    let pin = match python_pin_for_host(host) {
        Ok(value) => value,
        Err(error) => {
            return record_preflight_refusal(&paths, host, error.to_string());
        }
    };
    let digests = match verify_inputs(&paths, &pin) {
        Ok(value) => value,
        Err(error) => {
            return record_preflight_refusal(&paths, host, error.to_string());
        }
    };

    let signals = match SigtermGuard::acquire() {
        Ok(value) => value,
        Err(error) => {
            return record_preflight_refusal(
                &paths,
                host,
                format!("could not acquire the helper SIGTERM guard: {error}"),
            );
        }
    };
    let report = observe_prepare(&paths, host, &digests, signals)?;
    if report["status"] != "OBSERVED_FETCH_STAGE_SIGTERM" {
        return Err(Refusal::new(format!(
            "historical prepare interruption failed; evidence retained at {}",
            paths.output.display()
        )));
    }
    println!(
        "{}",
        json!({
            "schema":"ami-rust-historical-prepare-capture-result-v2",
            "status":report["status"],
            "report":paths.output.join("preparation-capture.json").display().to_string(),
            "python_sha256":digests.python_sha256,
            "frontend_sha256":digests.frontend_sha256,
            "direct_child_raw_signal":report["observation"]["direct_child_raw_signal"],
            "derived_shell_status":report["observation"]["derived_shell_status_from_signal"],
            "claim":"One historical prepare interruption observation only; no-Python and complete RC1 acceptance remain separate."
        })
    );
    Ok(())
}

fn parse_and_validate_paths(args: &mut impl Iterator<Item = OsString>) -> Result<ProbePaths> {
    let allowed = [
        "--python",
        "--frontend",
        "--state",
        "--home",
        "--tmp",
        "--cwd",
        "--output",
    ];
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if !allowed.iter().any(|candidate| key == *candidate) {
            return Err(Refusal::new(
                "unknown historical-prepare-interruption option",
            ));
        }
        let value = args.next().ok_or_else(|| {
            Refusal::new("historical-prepare-interruption option requires a value")
        })?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new(
                "historical-prepare-interruption options may occur only once",
            ));
        }
    }

    let python = take_path(&mut options, "--python")?;
    let frontend = take_path(&mut options, "--frontend")?;
    let state = take_path(&mut options, "--state")?;
    let home = take_path(&mut options, "--home")?;
    let tmp = take_path(&mut options, "--tmp")?;
    let cwd = take_path(&mut options, "--cwd")?;
    let output = take_path(&mut options, "--output")?;

    canonical_absolute(&python, "Python")?;
    canonical_absolute(&frontend, "historical frontend")?;
    if frontend.file_name() != Some(OsStr::new("cli.py")) {
        return Err(Refusal::new(
            "historical frontend must be the published cli.py",
        ));
    }
    let home = private_directory(&home, "HOME")?;
    let tmp = private_directory(&tmp, "TMPDIR")?;
    let cwd = private_directory(&cwd, "working directory")?;
    let state = fresh_private_directory_path(&state, "state")?;
    let output = fresh_private_directory_path(&output, "output")?;

    ownership::require_disjoint(
        &state,
        &output,
        "historical state and output directories must be disjoint",
    )?;
    for input in [&python, &frontend] {
        ownership::require_disjoint(
            &state,
            input,
            "historical state must be disjoint from read-only inputs",
        )?;
        ownership::require_disjoint(
            &output,
            input,
            "historical output must be disjoint from read-only inputs",
        )?;
    }
    for (path, label) in [
        (&python, "Python"),
        (&frontend, "historical frontend"),
        (&state, "state"),
        (&home, "HOME"),
        (&tmp, "TMPDIR"),
        (&cwd, "working directory"),
        (&output, "output"),
    ] {
        path_text(path, label)?;
    }

    Ok(ProbePaths {
        python,
        frontend,
        state,
        home,
        tmp,
        cwd,
        output,
    })
}

fn python_pin_for_host(host: Host) -> Result<PythonPin> {
    let (host_key, target) = match host {
        Host::LinuxX86_64 => ("linux-x86_64", "x86_64-unknown-linux-gnu"),
        Host::MacosAarch64 => ("macos-aarch64", "aarch64-apple-darwin"),
    };
    let value = parse_json_value(
        CI_PYTHON_INPUTS.as_bytes(),
        JsonProfile::PackageMetadataStateSelection,
    )?;
    if value["schema"] != "ami-rust-ci-python-inputs-v1"
        || value["version"] != "3.12.15"
        || value["hosts"].get(host_key).is_none()
    {
        return Err(Refusal::new(
            "compiled CI Python inputs do not contain the expected runtime record",
        ));
    }
    let row = &value["hosts"][host_key];
    let relative_path = row["runtime_relative_path"]
        .as_str()
        .ok_or_else(|| Refusal::new("compiled Python runtime path is missing"))?;
    let bytes = row["runtime_bytes"]
        .as_u64()
        .ok_or_else(|| Refusal::new("compiled Python runtime byte count is missing"))?;
    let sha256 = row["runtime_sha256"]
        .as_str()
        .ok_or_else(|| Refusal::new("compiled Python runtime digest is missing"))?;
    if row["host"] != host_key
        || row["target_triple"] != target
        || relative_path != "python/bin/python3.12"
        || bytes == 0
        || bytes > PYTHON_RUNTIME_MAX_BYTES
        || !is_sha256_digest(sha256)
    {
        return Err(Refusal::new(
            "compiled Python runtime record has an unsupported host or identity",
        ));
    }
    Ok(PythonPin {
        bytes,
        sha256: sha256.to_owned(),
    })
}

fn verify_inputs(paths: &ProbePaths, pin: &PythonPin) -> Result<InputDigests> {
    let python_bytes = read_protected_file(&paths.python, "Python", true, pin.bytes)?;
    let python_sha256 = verify_pinned_bytes("Python", &python_bytes, Some(pin.bytes), &pin.sha256)?;
    let frontend_bytes = read_protected_file(
        &paths.frontend,
        "historical frontend",
        false,
        HISTORICAL_CLI_MAX_BYTES,
    )?;
    let frontend_sha256 = verify_pinned_bytes(
        "historical frontend",
        &frontend_bytes,
        None,
        HISTORICAL_CLI_SHA256,
    )?;
    Ok(InputDigests {
        python_sha256,
        frontend_sha256,
    })
}

fn read_protected_file(
    path: &Path,
    label: &str,
    executable: bool,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let file = ownership::protected_regular_file(path, executable).map_err(|error| {
        Refusal::new(format!(
            "cannot validate {label} as a protected regular file: {error}"
        ))
    })?;
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Err(Refusal::new(format!(
            "{label} exceeds its pinned byte bound"
        )));
    }
    let initial_capacity = usize::try_from(metadata.len())
        .map_err(|_| Refusal::new(format!("{label} length is not representable")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(initial_capacity)
        .map_err(|error| Refusal::new(format!("could not allocate bounded {label}: {error}")))?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| Refusal::new(format!("{label} byte bound overflow")))?;
    file.take(read_limit).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(Refusal::new(format!("{label} grew beyond its byte bound")));
    }
    Ok(bytes)
}

fn verify_pinned_bytes(
    label: &str,
    bytes: &[u8],
    expected_bytes: Option<u64>,
    expected_sha256: &str,
) -> Result<String> {
    if !is_sha256_digest(expected_sha256) {
        return Err(Refusal::new(format!("{label} pin is not a SHA-256 digest")));
    }
    if expected_bytes
        .is_some_and(|expected| u64::try_from(bytes.len()).unwrap_or(u64::MAX) != expected)
    {
        return Err(Refusal::new(format!(
            "{label} byte length differs from its pin"
        )));
    }
    let actual = sha256_bytes(bytes);
    if actual != expected_sha256 {
        return Err(Refusal::new(format!(
            "{label} SHA-256 differs from its pinned identity"
        )));
    }
    Ok(actual)
}

fn observe_prepare(
    paths: &ProbePaths,
    host: Host,
    digests: &InputDigests,
    signals: SigtermGuard,
) -> Result<Value> {
    let environment = BTreeMap::from([
        (
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
        ),
        (
            OsString::from("HOME"),
            paths.home.as_os_str().to_os_string(),
        ),
        (
            OsString::from("TMPDIR"),
            paths.tmp.as_os_str().to_os_string(),
        ),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("TZ"), OsString::from("UTC")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_SYSTEM"),
            OsString::from("/dev/null"),
        ),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
    ]);
    let spec = CommandSpec::new(
        paths.python.as_os_str(),
        [
            OsString::from("-I"),
            OsString::from("-B"),
            paths.frontend.as_os_str().to_os_string(),
            OsString::from("prepare"),
            OsString::from("--state"),
            paths.state.as_os_str().to_os_string(),
        ],
        &paths.cwd,
        environment,
    );

    let started = Instant::now();
    let gate = RefCell::new(Gate::default());
    let capture = capture_observed(
        &spec,
        CaptureLimits {
            timeout: CAPTURE_TIMEOUT,
            stdout_bytes: STREAM_LIMIT,
            stderr_bytes: STREAM_LIMIT,
            termination_grace: Duration::from_secs(2),
        },
        || signals.requested() || (!gate.borrow().attempted && started.elapsed() >= STAGE_DEADLINE),
        |seen: CaptureObservation| {
            if gate.borrow().attempted
                || !matches!(seen.phase, CaptureObservationPhase::Running { .. })
            {
                return Ok(());
            }
            match inspect_stage(&paths.state) {
                Ok(Stage::Waiting) => Ok(()),
                Ok(Stage::Later(markers)) => {
                    gate.borrow_mut().later_stage = Some(markers.clone());
                    Err(io::Error::other(format!(
                        "prepare advanced beyond the historical fetch gate: {}",
                        markers.join(", ")
                    )))
                }
                Ok(Stage::Ready(fetch_head)) => {
                    {
                        let mut current = gate.borrow_mut();
                        current.attempted = true;
                        current.pid = Some(seen.direct_pid);
                        current.elapsed_ms = Some(seen.elapsed.as_millis());
                        current.fetch_head = Some(fetch_head);
                    }
                    match signal_direct_child(seen.direct_pid) {
                        Ok(()) => {
                            gate.borrow_mut().sent = true;
                            Ok(())
                        }
                        Err(error) => {
                            gate.borrow_mut().signal_error = Some(error.to_string());
                            Err(error)
                        }
                    }
                }
                Err(error) => {
                    gate.borrow_mut().scan_error = Some(error.to_string());
                    Err(error)
                }
            }
        },
    );
    let gate = gate.into_inner();
    let helper_signal = signals.finish_requested();
    let (helper_interrupted, helper_signal_error) = match helper_signal {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let captured = capture_outcome(capture);

    write_new(&paths.output.join("prepare.stdout.raw"), &captured.stdout)?;
    write_new(&paths.output.join("prepare.stderr.raw"), &captured.stderr)?;

    let post = inspect_post_capture(&paths.state);
    let accepted_path = accepted_capture_path(&captured);
    let derived_shell_status = captured.signal.and_then(|signal| signal.checked_add(128));
    let shell_convention_status = derived_shell_status.or(captured.exit_code);
    let passed = gate.attempted
        && gate.sent
        && gate.signal_error.is_none()
        && gate.scan_error.is_none()
        && gate.later_stage.is_none()
        && captured.signal == Some(SIGTERM)
        && captured.exit_code.is_none()
        && derived_shell_status == Some(143)
        && accepted_path != "unqualified-capture-path"
        && helper_interrupted == Some(false)
        && helper_signal_error.is_none()
        && post.private_state
        && post.error.is_none()
        && post.later_markers.is_empty()
        && post.fetch_head["present"] == true
        && post.fetch_head["regular_file"] == true
        && post.fetch_head["size_bytes"] == 0;

    let report_path = paths.output.join("preparation-capture.json");
    let report = json!({
        "schema":"ami-rust-historical-prepare-capture-v2",
        "status":if passed {"OBSERVED_FETCH_STAGE_SIGTERM"} else {"HISTORICAL_PREPARE_CAPTURE_FAILED"},
        "host":host,
        "host_key":host_key(host),
        "expected_stage_label":STAGE_LABEL,
        "claim":if passed {"One execution of the published 0.1.0-2 Python prepare command on the current supported host was interrupted at the empty FETCH_HEAD filesystem-stage marker before checkout/bootstrap sentinels appeared."} else {"No successful historical prepare interruption claim is made because one or more bounded probe criteria failed."},
        "limit":"The marker is filesystem-stage evidence only; the fetch argv is not observed. This historical Python control does not establish the Rust-side or full A2 pair, signed RC1, or no-Python execution.",
        "command":{
            "program":paths.python.display().to_string(),
            "python_sha256":digests.python_sha256,
            "frontend_sha256":digests.frontend_sha256,
            "argv":["-I","-B",paths.frontend.display().to_string(),"prepare","--state",paths.state.display().to_string()],
            "cwd":paths.cwd.display().to_string(),
            "environment":{"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":paths.home.display().to_string(),"TMPDIR":paths.tmp.display().to_string(),"LANG":"C","LC_ALL":"C","TZ":"UTC","git_config_isolated":true}
        },
        "capture_limits":{"stage_deadline_seconds":STAGE_DEADLINE.as_secs(),"timeout_seconds":CAPTURE_TIMEOUT.as_secs(),"stdout_bytes":STREAM_LIMIT,"stderr_bytes":STREAM_LIMIT,"termination_grace_seconds":2},
        "observation":{
            "attempted":gate.attempted,
            "signal_sent":gate.sent,
            "direct_child_pid":gate.pid,
            "elapsed_millis":gate.elapsed_ms,
            "fetch_head_at_signal":gate.fetch_head,
            "stage_label":if gate.attempted {Some(STAGE_LABEL)} else {None::<&str>},
            "signal":"SIGTERM",
            "signal_error":gate.signal_error,
            "scan_error":gate.scan_error,
            "later_stage":gate.later_stage,
            "helper_interrupted":helper_interrupted,
            "helper_signal_error":helper_signal_error,
            "direct_child_raw_signal":captured.signal,
            "direct_child_exit_code":captured.exit_code,
            "derived_shell_status_from_signal":derived_shell_status,
            "shell_convention_status":shell_convention_status,
            "shell_was_invoked":false,
            "shell_status_note":"143 is derived from a raw direct-child SIGTERM 15; it is not reported as the child's exit code."
        },
        "capture":{
            "result":captured.result,
            "accepted_path":accepted_path,
            "cause":captured.cause_name,
            "cause_detail":captured.cause_detail,
            "cleanup_error":captured.cleanup_error,
            "cleanup_outcome":if captured.cleanup_error.is_some() {"reported-error"} else if accepted_path != "unqualified-capture-path" {"accepted-path-with-no-reported-cleanup-error"} else {"not-proven"},
            "cleanup_proof":cleanup_proof(&captured, accepted_path),
            "elapsed_millis":captured.elapsed_ms,
            "stdout":{"path":"prepare.stdout.raw","bytes":captured.stdout.len(),"sha256":sha256_bytes(&captured.stdout)},
            "stderr":{"path":"prepare.stderr.raw","bytes":captured.stderr.len(),"sha256":sha256_bytes(&captured.stderr)}
        },
        "post_capture":{
            "fetch_head":post.fetch_head,
            "ready_json_present":post.ready_json_present,
            "READY_present":post.upper_ready_present,
            "git_index_present":post.index_present,
            "ci_python_present":post.cli_python_present,
            "later_stage_markers":post.later_markers,
            "private_state_owned":post.private_state,
            "state_check_error":post.error
        }
    });
    write_new(
        &report_path,
        &serde_json::to_vec_pretty(&report)
            .map_err(|error| Refusal::new(format!("cannot encode capture report: {error}")))?,
    )?;

    if passed {
        Ok(report)
    } else {
        println!(
            "{}",
            json!({
                "schema":"ami-rust-historical-prepare-capture-result-v2",
                "status":report["status"],
                "report":report_path.display().to_string(),
                "python_sha256":digests.python_sha256,
                "frontend_sha256":digests.frontend_sha256,
                "direct_child_raw_signal":captured.signal,
                "derived_shell_status":derived_shell_status
            })
        );
        Err(Refusal::new(format!(
            "historical prepare interruption failed; evidence retained at {}",
            paths.output.display()
        )))
    }
}

fn capture_outcome(capture: std::result::Result<CapturedProcess, CaptureError>) -> CaptureOutcome {
    match capture {
        Ok(process) => CaptureOutcome {
            exit_code: process.exit_code(),
            signal: process.signal(),
            stdout: process.stdout,
            stderr: process.stderr,
            elapsed_ms: process.elapsed.as_millis(),
            result: "captured-normal",
            cause_name: None,
            cause_detail: None,
            cleanup_error: None,
        },
        Err(error) => {
            let exit_code = error.status.as_ref().and_then(|status| status.code());
            let signal = error.status.as_ref().and_then(ExitStatusExt::signal);
            let (cause_name, cause_detail) = capture_cause(&error.cause);
            CaptureOutcome {
                stdout: error.stdout,
                stderr: error.stderr,
                exit_code,
                signal,
                elapsed_ms: error.elapsed.as_millis(),
                result: "capture-error",
                cause_name: Some(cause_name),
                cause_detail: Some(cause_detail),
                cleanup_error: error.cleanup_error.map(|value| value.to_string()),
            }
        }
    }
}

fn capture_cause(cause: &CaptureCause) -> (&'static str, String) {
    let name = match cause {
        CaptureCause::Timeout => "Timeout",
        CaptureCause::Cancelled => "Cancelled",
        CaptureCause::Observation(_) => "Observation",
        CaptureCause::StdoutLimitExceeded => "StdoutLimitExceeded",
        CaptureCause::StderrLimitExceeded => "StderrLimitExceeded",
        CaptureCause::DescendantRetainedPipe => "DescendantRetainedPipe",
        CaptureCause::OutputAllocation => "OutputAllocation",
        CaptureCause::Io(_) => "Io",
    };
    (name, cause.to_string())
}

fn accepted_capture_path(captured: &CaptureOutcome) -> &'static str {
    if captured.cleanup_error.is_some()
        || captured.signal != Some(SIGTERM)
        || captured.exit_code.is_some()
    {
        return "unqualified-capture-path";
    }
    match captured.cause_name {
        None if captured.result == "captured-normal" => "CapturedProcess-raw-SIGTERM-reaped",
        Some("DescendantRetainedPipe") if captured.result == "capture-error" => {
            "DescendantRetainedPipe-cleaned-and-reaped"
        }
        _ => "unqualified-capture-path",
    }
}

fn cleanup_proof(captured: &CaptureOutcome, accepted_path: &str) -> &'static str {
    if captured.cleanup_error.is_some() {
        "capture_observed reported a cleanup error; cleanup and reap are not claimed"
    } else if accepted_path == "DescendantRetainedPipe-cleaned-and-reaped" {
        "capture_observed returned DescendantRetainedPipe after lease-managed process-group cleanup and reaping, with no cleanup error"
    } else if accepted_path == "CapturedProcess-raw-SIGTERM-reaped" {
        "capture_observed returned CapturedProcess after its normal group/output-drain and reap path, with raw direct-child SIGTERM 15 and no cleanup error"
    } else {
        "no accepted capture cleanup/reap path was established"
    }
}

fn inspect_stage(state: &Path) -> io::Result<Stage> {
    let later = later_markers(state)?;
    if !later.is_empty() {
        return Ok(Stage::Later(later));
    }
    let source = state.join("source");
    if !optional_real_dir(&source)? {
        return Ok(Stage::Waiting);
    }
    let git = source.join(".git");
    if !optional_real_dir(&git)? {
        return Ok(Stage::Waiting);
    }
    let fetch = git.join("FETCH_HEAD");
    let metadata = match fs::symlink_metadata(&fetch) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Stage::Waiting),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::other("FETCH_HEAD is not a regular file"));
    }
    if metadata.len() != 0 {
        return Ok(Stage::Waiting);
    }
    Ok(Stage::Ready(json!({
        "path":fetch.display().to_string(),
        "regular_file":true,
        "size_bytes":metadata.len(),
        "mode":metadata.mode() & 0o7777,
        "uid":metadata.uid(),
        "mtime_seconds":metadata.mtime(),
        "index_absent":true,
        "ci_python_absent":true,
        "ready_json_absent":true,
        "READY_absent":true
    })))
}

fn optional_real_dir(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a real directory",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn later_markers(state: &Path) -> io::Result<Vec<String>> {
    let source = state.join("source");
    let mut values = Vec::new();
    for (path, name) in [
        (state.join("ready.json"), "ready.json"),
        (state.join("READY"), "READY"),
        (source.join(".git/index"), "source/.git/index"),
        (
            source.join("release/ci_python.py"),
            "source/release/ci_python.py",
        ),
    ] {
        if entry_present(&path)? {
            values.push(name.to_owned());
        }
    }
    Ok(values)
}

fn inspect_post_capture(state: &Path) -> PostCapture {
    let mut errors = Vec::new();
    let fetch_head = match optional_file_state(&state.join("source/.git/FETCH_HEAD")) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("FETCH_HEAD: {error}"));
            Value::Null
        }
    };
    let (ready_json_present, ready_json_error) = marker_present(&state.join("ready.json"));
    let (upper_ready_present, upper_ready_error) = marker_present(&state.join("READY"));
    let (index_present, index_error) = marker_present(&state.join("source/.git/index"));
    let (cli_python_present, cli_python_error) =
        marker_present(&state.join("source/release/ci_python.py"));
    for (label, error) in [
        ("ready.json", ready_json_error),
        ("READY", upper_ready_error),
        ("source/.git/index", index_error),
        ("source/release/ci_python.py", cli_python_error),
    ] {
        if let Some(error) = error {
            errors.push(format!("{label}: {error}"));
        }
    }
    let later_markers = match later_markers(state) {
        Ok(markers) => markers,
        Err(error) => {
            errors.push(format!("later-stage marker scan: {error}"));
            Vec::new()
        }
    };
    let private_state = match ownership::existing_private_state(state) {
        Ok(_) => true,
        Err(error) => {
            errors.push(format!("private state check: {error}"));
            false
        }
    };
    PostCapture {
        fetch_head,
        ready_json_present,
        upper_ready_present,
        index_present,
        cli_python_present,
        later_markers,
        private_state,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn marker_present(path: &Path) -> (Option<bool>, Option<String>) {
    match entry_present(path) {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    }
}

fn optional_file_state(path: &Path) -> io::Result<Value> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(json!({
            "present":true,
            "regular_file":metadata.file_type().is_file(),
            "size_bytes":metadata.len(),
            "mode":metadata.mode() & 0o7777,
            "uid":metadata.uid()
        })),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(json!({"present":false})),
        Err(error) => Err(error),
    }
}

fn entry_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[allow(
    unsafe_code,
    reason = "Signal only the capture-owned live direct child PID."
)]
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

#[allow(
    unsafe_code,
    reason = "Never signal a process group; use the capture-owned child PID."
)]
fn signal_direct_child(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID is not representable"))?;
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PID must be positive",
        ));
    }
    // SAFETY: capture_observed owns this positive live direct-child PID.
    if unsafe { kill(pid, SIGTERM) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn private_directory(path: &Path, label: &str) -> Result<PathBuf> {
    canonical_absolute(path, label)?;
    ownership::existing_private_state(path).map_err(|error| {
        Refusal::new(format!(
            "{label} must be a private current-user directory: {error}"
        ))
    })?;
    Ok(path.to_path_buf())
}

fn fresh_private_directory_path(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} path must be absolute")));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Refusal::new(format!("{label} path has no parent")))?;
    let parent = private_directory(parent, &format!("{label} parent"))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| Refusal::new(format!("{label} path must name a directory")))?;
    let normalized = parent.join(leaf);
    if normalized.as_path() != path {
        return Err(Refusal::new(format!(
            "{label} path must be normalized and have no symlink components"
        )));
    }
    if entry_present(path)? {
        return Err(Refusal::new(format!("{label} directory must be fresh")));
    }
    if label == "state" {
        ownership::fresh_private_state(path)?;
    } else {
        let validated = ownership::fresh_output(path)?;
        if validated.path() != path {
            return Err(Refusal::new("output path must be normalized and absolute"));
        }
    }
    Ok(path.to_path_buf())
}

fn canonical_absolute(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} path must be absolute")));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("cannot resolve {label} path: {error}")))?;
    if canonical.as_path() != path {
        return Err(Refusal::new(format!(
            "{label} path must be canonical and contain no symlinks"
        )));
    }
    Ok(())
}

fn create_private_output(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn record_preflight_refusal(paths: &ProbePaths, host: Host, error: String) -> Result<()> {
    let stdout_path = paths.output.join("prepare.stdout.raw");
    let stderr_path = paths.output.join("prepare.stderr.raw");
    write_new(&stdout_path, &[])?;
    write_new(&stderr_path, &[])?;
    let report_path = paths.output.join("preparation-capture.json");
    let empty_sha = sha256_bytes(&[]);
    let report = json!({
        "schema":"ami-rust-historical-prepare-capture-v2",
        "status":"HISTORICAL_PREPARE_CAPTURE_FAILED",
        "host":host,
        "host_key":host_key(host),
        "expected_stage_label":STAGE_LABEL,
        "claim":"No historical prepare interruption claim is made; input validation refused before command execution.",
        "limit":"The historical helper was not executed because its preflight did not establish the pinned inputs.",
        "preflight_error":error.clone(),
        "command":{
            "program":paths.python.display().to_string(),
            "python_sha256":Value::Null,
            "frontend_sha256":Value::Null,
            "argv":["-I","-B",paths.frontend.display().to_string(),"prepare","--state",paths.state.display().to_string()],
            "cwd":paths.cwd.display().to_string(),
            "environment":{"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":paths.home.display().to_string(),"TMPDIR":paths.tmp.display().to_string(),"LANG":"C","LC_ALL":"C","TZ":"UTC","git_config_isolated":true}
        },
        "capture_limits":{"stage_deadline_seconds":STAGE_DEADLINE.as_secs(),"timeout_seconds":CAPTURE_TIMEOUT.as_secs(),"stdout_bytes":STREAM_LIMIT,"stderr_bytes":STREAM_LIMIT,"termination_grace_seconds":2},
        "observation":{
            "attempted":false,"signal_sent":false,"direct_child_pid":null,"elapsed_millis":null,
            "fetch_head_at_signal":null,"stage_label":null,"signal":"SIGTERM",
            "signal_error":null,"scan_error":null,"later_stage":null,
            "helper_interrupted":null,"helper_signal_error":null,
            "direct_child_raw_signal":null,"direct_child_exit_code":null,
            "derived_shell_status_from_signal":null,"shell_convention_status":null,
            "shell_was_invoked":false,
            "shell_status_note":"No child was started; no shell or child status is claimed."
        },
        "capture":{
            "result":"not-started","accepted_path":"unqualified-capture-path","cause":null,
            "cause_detail":null,"cleanup_error":null,"cleanup_outcome":"not-proven",
            "cleanup_proof":"The command was not executed; no child cleanup/reap claim is made.",
            "elapsed_millis":0,
            "stdout":{"path":"prepare.stdout.raw","bytes":0,"sha256":empty_sha},
            "stderr":{"path":"prepare.stderr.raw","bytes":0,"sha256":empty_sha}
        },
        "post_capture":{
            "fetch_head":{"present":false},"ready_json_present":false,"READY_present":false,
            "git_index_present":false,"ci_python_present":false,"later_stage_markers":[],
            "private_state_owned":false,"state_check_error":"state was not created"
        }
    });
    write_new(
        &report_path,
        &serde_json::to_vec_pretty(&report)
            .map_err(|error| Refusal::new(format!("cannot encode preflight report: {error}")))?,
    )?;
    println!(
        "{}",
        json!({
            "schema":"ami-rust-historical-prepare-capture-result-v2",
            "status":"HISTORICAL_PREPARE_CAPTURE_FAILED",
            "report":report_path.display().to_string(),
            "direct_child_raw_signal":null,
            "derived_shell_status":null
        })
    );
    Err(Refusal::new(format!(
        "historical prepare preflight refused before execution; evidence retained at {}: {error}",
        paths.output.display()
    )))
}

fn host_key(host: Host) -> &'static str {
    match host {
        Host::LinuxX86_64 => "linux-x86_64",
        Host::MacosAarch64 => "macos-aarch64",
    }
}

fn take_path(options: &mut BTreeMap<OsString, OsString>, key: &str) -> Result<PathBuf> {
    let value = options
        .remove(OsStr::new(key))
        .ok_or_else(|| Refusal::new(format!("missing required {key} option")))?;
    Ok(PathBuf::from(value))
}

fn path_text<'a>(path: &'a Path, label: &str) -> Result<&'a str> {
    path.to_str()
        .ok_or_else(|| Refusal::new(format!("{label} path must be UTF-8")))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let parent = std::env::temp_dir();
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    ".ami-rust-historical-prepare-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                            .expect("restrict temporary test directory");
                        return Self(path);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create temporary test directory: {error}"),
                }
            }
            panic!("could not allocate a temporary test directory");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn stage_gate_requires_empty_regular_fetch_head_and_rejects_later_markers() {
        let temp = TempDirectory::new();
        let state = temp.path().join("state");
        fs::create_dir(&state).expect("state directory");
        let git = state.join("source/.git");
        fs::create_dir_all(&git).expect("source git directory");
        let fetch = git.join("FETCH_HEAD");
        fs::write(&fetch, b"").expect("empty fetch marker");

        assert!(matches!(inspect_stage(&state), Ok(Stage::Ready(_))));
        fs::write(&fetch, b"nonempty").expect("nonempty fetch marker");
        assert!(matches!(inspect_stage(&state), Ok(Stage::Waiting)));

        fs::write(&fetch, b"").expect("restore empty fetch marker");
        fs::write(git.join("index"), b"later").expect("later stage marker");
        assert!(
            matches!(inspect_stage(&state), Ok(Stage::Later(markers)) if markers == vec!["source/.git/index".to_owned()])
        );

        fs::remove_file(git.join("index")).expect("remove index marker");
        let release = state.join("source/release");
        fs::create_dir_all(&release).expect("source release directory");
        fs::write(release.join("ci_python.py"), b"later").expect("Python bootstrap marker");
        assert!(
            matches!(inspect_stage(&state), Ok(Stage::Later(markers)) if markers == vec!["source/release/ci_python.py".to_owned()])
        );
        fs::remove_file(release.join("ci_python.py")).expect("remove bootstrap marker");
        fs::write(state.join("ready.json"), b"later").expect("ready JSON marker");
        assert!(
            matches!(inspect_stage(&state), Ok(Stage::Later(markers)) if markers == vec!["ready.json".to_owned()])
        );
    }

    #[test]
    fn stage_gate_refuses_symlink_fetch_head_and_observes_ready_markers() {
        let temp = TempDirectory::new();
        let state = temp.path().join("state");
        fs::create_dir(&state).expect("state directory");
        fs::create_dir_all(state.join("source/.git")).expect("source git directory");
        fs::write(state.join("source/.git/FETCH_HEAD.target"), b"").expect("target file");
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            state.join("source/.git/FETCH_HEAD.target"),
            state.join("source/.git/FETCH_HEAD"),
        )
        .expect("FETCH_HEAD symlink");
        assert!(inspect_stage(&state).is_err());

        fs::remove_file(state.join("source/.git/FETCH_HEAD")).expect("remove link");
        fs::write(state.join("READY"), b"later").expect("ready marker");
        assert!(
            matches!(inspect_stage(&state), Ok(Stage::Later(markers)) if markers == vec!["READY".to_owned()])
        );
    }

    #[test]
    fn capture_verdict_accepts_only_raw_sigterm_with_a_proven_cleanup_path() {
        let accepted =
            |result, cause_name, signal, exit_code, cleanup_error: Option<&str>| CaptureOutcome {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code,
                signal,
                elapsed_ms: 1,
                result,
                cause_name,
                cause_detail: None,
                cleanup_error: cleanup_error.map(str::to_owned),
            };
        assert_eq!(
            accepted_capture_path(&accepted(
                "captured-normal",
                None,
                Some(SIGTERM),
                None,
                None
            )),
            "CapturedProcess-raw-SIGTERM-reaped"
        );
        assert_eq!(
            accepted_capture_path(&accepted(
                "capture-error",
                Some("DescendantRetainedPipe"),
                Some(SIGTERM),
                None,
                None
            )),
            "DescendantRetainedPipe-cleaned-and-reaped"
        );
        assert_eq!(
            accepted_capture_path(&accepted(
                "capture-error",
                Some("DescendantRetainedPipe"),
                Some(SIGTERM),
                None,
                Some("EPERM")
            )),
            "unqualified-capture-path"
        );
        assert_eq!(
            accepted_capture_path(&accepted("captured-normal", None, None, Some(143), None)),
            "unqualified-capture-path"
        );
        assert_eq!(
            accepted_capture_path(&accepted(
                "capture-error",
                Some("Timeout"),
                Some(SIGTERM),
                None,
                None
            )),
            "unqualified-capture-path"
        );
    }

    #[test]
    fn altered_historical_frontend_or_python_bytes_fail_the_identity_gate() {
        let pinned = b"pinned bytes";
        let expected = sha256_bytes(pinned);
        assert!(
            verify_pinned_bytes("Python", pinned, Some(pinned.len() as u64), &expected).is_ok()
        );
        assert!(
            verify_pinned_bytes(
                "Python",
                b"tamper bytes",
                Some(pinned.len() as u64),
                &expected
            )
            .is_err()
        );
        assert!(verify_pinned_bytes("historical frontend", b"tampered", None, &expected).is_err());
    }
}

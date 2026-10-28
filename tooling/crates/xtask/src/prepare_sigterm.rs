//! Maintainer-only pre-publication source-fetch interruption observation.
//! The lifecycle caller separately checks retry and sibling preservation.
//! This helper alone does not establish RC1 acceptance.

use ami_rust_core::{
    Refusal,
    digest::sha256_bytes,
    directory::Directory,
    host_platform,
    json::{JsonProfile, parse_json_value},
    ownership,
    package::{PackageRuntime, check_native_package_root},
    process_capture::{
        CaptureLimits, CaptureObservation, CaptureObservationPhase, CommandSpec, capture_observed,
    },
    signals::SigtermGuard,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    time::Duration,
};

const ENTRY_LIMIT: usize = 64;
const STREAM_LIMIT: usize = 16 * 1024 * 1024;

pub fn run(mut args: impl Iterator<Item = OsString>) -> ami_rust_core::Result<()> {
    let allowed = ["--frontend", "--state", "--home", "--tmp", "--output"];
    let mut opts = BTreeMap::new();
    while let Some(key) = args.next() {
        if !allowed.iter().any(|name| key == *name) {
            return Err(Refusal::new("unknown prepare-sigterm-driver option"));
        }
        let value = args
            .next()
            .ok_or_else(|| Refusal::new("option requires a value"))?;
        if opts.insert(key, value).is_some() {
            return Err(Refusal::new(
                "prepare-sigterm-driver options may occur only once",
            ));
        }
    }
    let frontend = PathBuf::from(take(&mut opts, "--frontend")?);
    let state = PathBuf::from(take(&mut opts, "--state")?);
    let home = PathBuf::from(take(&mut opts, "--home")?);
    let tmp = PathBuf::from(take(&mut opts, "--tmp")?);
    let output = PathBuf::from(take(&mut opts, "--output")?);
    let host = host_platform::supported_host()?;

    canonical(&frontend, "frontend")?;
    if frontend.file_name() != Some(OsStr::new("ami-rust"))
        || frontend.parent().and_then(Path::file_name) != Some(OsStr::new("bin"))
    {
        return Err(Refusal::new(
            "frontend must be the canonical package bin/ami-rust",
        ));
    }
    let root = frontend
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Refusal::new("frontend has no package root"))?;
    canonical(root, "package root")?;
    let package = check_native_package_root(
        root,
        PackageRuntime {
            host,
            cli_version: env!("CARGO_PKG_VERSION"),
        },
    )?;
    if frontend != package.path().join("bin/ami-rust")
        || package
            .pins()
            .launchers
            .get("ami-rust")
            .map(|pin| pin.path.as_str())
            != Some("bin/ami-rust")
    {
        return Err(Refusal::new(
            "frontend is not the checked public package launcher",
        ));
    }
    let launcher = package.read_file("bin/ami-rust")?;
    let launcher_sha = sha256_bytes(&launcher);
    let package_id = json!({
        "root":text(package.path())?, "host":host, "cli_version":package.pins().cli_version,
        "package_version":package.pins().package_version, "sdk_version":package.pins().sdk_version,
        "source_commit":package.pins().source_commit, "source_tree":package.pins().source_tree,
        "manifest_sha256":package.pins().manifest_sha256, "transport_sha256":package.pins().transport_sha256,
        "core_sha256":package.pins().core_sha256, "inventory_sha256":sha256_bytes(package.raw_inventory())
    });

    private_dir(&home, "home")?;
    private_dir(&tmp, "tmp")?;
    private_parent(&state, "state")?;
    private_parent(&output, "output")?;
    let _fresh_state = ownership::fresh_private_state(&state)?;
    let _fresh_output = ownership::fresh_output(&output)?;
    ownership::validate_state_package_separation(&state, package.path(), true)?;
    ownership::require_disjoint(
        &output,
        package.path(),
        "output and package must be disjoint",
    )?;
    ownership::require_disjoint(&output, &state, "output and state must be disjoint")?;

    let frontend_s = text(&frontend)?;
    let state_s = text(&state)?;
    let home_s = text(&home)?;
    let tmp_s = text(&tmp)?;
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;

    let env = BTreeMap::from([
        (
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
        ),
        (OsString::from("HOME"), home.as_os_str().to_os_string()),
        (OsString::from("TMPDIR"), tmp.as_os_str().to_os_string()),
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
        frontend.as_os_str(),
        [
            OsString::from("prepare"),
            OsString::from("--state"),
            state.as_os_str().to_os_string(),
        ],
        &home,
        env,
    );

    let (mut attempted, mut sent, mut target_pid) = (false, false, None);
    let (mut marker, mut signal_error, mut scan_error): (
        Option<PathBuf>,
        Option<String>,
        Option<String>,
    ) = (None, None, None);
    let observer_failed = std::cell::Cell::new(false);
    let signals = SigtermGuard::acquire()?;
    let capture = capture_observed(
        &spec,
        CaptureLimits {
            timeout: Duration::from_secs(120),
            stdout_bytes: STREAM_LIMIT,
            stderr_bytes: STREAM_LIMIT,
            termination_grace: Duration::from_secs(2),
        },
        || signals.requested() || observer_failed.get(),
        |seen: CaptureObservation| {
            if attempted
                || scan_error.is_some()
                || !matches!(seen.phase, CaptureObservationPhase::Running { .. })
            {
                return Ok(());
            }
            // This small bounded directory check runs every capture pass so a
            // short fetch is not missed between resource-sampling intervals.
            match active_source_fetch(&state) {
                Ok(Some(path)) => {
                    attempted = true;
                    target_pid = Some(seen.direct_pid);
                    marker = Some(path);
                    match signal_direct_child(seen.direct_pid) {
                        Ok(()) => sent = true,
                        Err(error) => {
                            signal_error = Some(error.to_string());
                            observer_failed.set(true);
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    scan_error = Some(error.to_string());
                    observer_failed.set(true);
                }
            }
            Ok(())
        },
    );
    // capture_observed has now completed its direct-child cleanup/reap path.
    let helper_signal = signals.finish_requested();
    let (helper_interrupted, helper_signal_error) = match helper_signal {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    };

    let (stdout, stderr, child_exit, child_signal, elapsed_ms, capture_error) = match capture {
        Ok(p) => {
            let exit = p.exit_code();
            let signal = p.signal();
            let elapsed = p.elapsed.as_millis();
            (p.stdout, p.stderr, exit, signal, elapsed, None)
        }
        Err(e) => {
            let (code, signal, reason) = (
                e.status.as_ref().and_then(|s| s.code()),
                e.status.as_ref().and_then(ExitStatusExt::signal),
                e.to_string(),
            );
            (
                e.stdout,
                e.stderr,
                code,
                signal,
                e.elapsed.as_millis(),
                Some(reason),
            )
        }
    };
    write_new(&output.join("stdout.raw"), &stdout)?;
    write_new(&output.join("stderr.raw"), &stderr)?;

    let (ready, ready_error) = match entry_present(&state.join("ready.json")) {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    let (failure_present, failure_valid, failure_phase, failure_error) = prepare_failure(&state);
    let private_error = ownership::existing_private_state(&state)
        .err()
        .map(|e| e.to_string());
    let passed = attempted
        && sent
        && signal_error.is_none()
        && scan_error.is_none()
        && capture_error.is_none()
        && child_exit == Some(143)
        && child_signal.is_none()
        && helper_interrupted == Some(false)
        && helper_signal_error.is_none()
        && ready == Some(false)
        && failure_present
        && failure_valid
        && private_error.is_none();
    let out_sha = sha256_bytes(&stdout);
    let err_sha = sha256_bytes(&stderr);
    let report_path = output.join("report.json");
    let report_s = text(&report_path)?;
    let report = json!({
        "schema":"ami-rust-prepare-sigterm-observation-v1",
        "status":if passed {"OBSERVED_EXPECTED_PREPARE_INTERRUPTION"} else {"PREPARE_SIGTERM_OBSERVATION_REFUSED"},
        "helper_exit_code":if passed {0} else {2}, "package":package_id,
        "launcher":{"path":frontend_s, "bytes":launcher.len(), "sha256":launcher_sha},
        "inputs":{"state":state_s, "home":home_s, "tmp":tmp_s, "output":report_s, "argv":[frontend_s,"prepare","--state",state_s]},
        "environment":{"PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "HOME":home_s, "TMPDIR":tmp_s, "LANG":"C", "LC_ALL":"C", "git_config_isolated":true},
        "capture_limits":{"timeout_seconds":120, "stdout_bytes":STREAM_LIMIT, "stderr_bytes":STREAM_LIMIT, "termination_grace_seconds":2},
        "signal":{"name":"SIGTERM", "target":"capture-owned direct child only", "marker_directory":marker.map(|p|p.to_string_lossy().into_owned()), "target_pid":target_pid, "attempted":attempted, "sent":sent, "error":signal_error, "scan_error":scan_error, "helper_interrupted":helper_interrupted, "helper_signal_error":helper_signal_error},
        "capture":{"actual_child_exit_code":child_exit, "actual_child_signal":child_signal, "elapsed_millis":elapsed_ms, "error":capture_error, "stdout":{"path":"stdout.raw","bytes":stdout.len(),"sha256":out_sha}, "stderr":{"path":"stderr.raw","bytes":stderr.len(),"sha256":err_sha}},
        "state":{"private_current_user":private_error.is_none(), "private_check_error":private_error, "ready_entry_present":ready, "ready_check_error":ready_error, "prepare_failure_present":failure_present, "prepare_failure_valid":failure_valid, "prepare_failure_phase":failure_phase, "prepare_failure_error":failure_error},
        "claim":"One actual public-frontend pre-publication source-fetch interruption case only; complete RC1 acceptance remains separate.",
        "limit":"Same-user concurrent path mutation is outside this helper's snapshot guarantee."
    });
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|e| Refusal::new(format!("cannot encode prepare SIGTERM report: {e}")))?;
    write_new(&report_path, &bytes)?;
    if !passed {
        return Err(Refusal::new(format!(
            "prepare SIGTERM observation failed; evidence retained at {}",
            output.display()
        )));
    }
    println!(
        "{}",
        json!({"schema":"ami-rust-prepare-sigterm-driver-success-v1",
        "status":"ACTUAL_FRONTEND_PREPARE_SIGTERM_FAILURE_RETAINED",
        "actual_child_exit_code":child_exit, "helper_exit_code":0, "target_pid":target_pid,
        "stdout_sha256":out_sha, "stderr_sha256":err_sha, "report":report_s,
        "claim":"One interrupted-preparation observation only; RC1 acceptance remains separate."})
    );
    Ok(())
}

fn take(opts: &mut BTreeMap<OsString, OsString>, key: &str) -> ami_rust_core::Result<OsString> {
    opts.remove(OsStr::new(key))
        .ok_or_else(|| Refusal::new(format!("missing {key}")))
}
fn canonical(path: &Path, label: &str) -> ami_rust_core::Result<()> {
    if !path.is_absolute() || fs::canonicalize(path)?.as_os_str() != path.as_os_str() {
        return Err(Refusal::new(format!(
            "{label} must be canonical and absolute"
        )));
    }
    Ok(())
}
fn private_dir(path: &Path, label: &str) -> ami_rust_core::Result<()> {
    canonical(path, label)?;
    ownership::existing_private_state(path)
        .map(|_| ())
        .map_err(|e| {
            Refusal::new(format!(
                "{label} is not a private current-user directory: {e}"
            ))
        })
}
fn private_parent(path: &Path, label: &str) -> ami_rust_core::Result<()> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} must be absolute")));
    }
    private_dir(
        path.parent()
            .ok_or_else(|| Refusal::new(format!("{label} has no parent")))?,
        label,
    )
}
fn active_source_fetch(state: &Path) -> ami_rust_core::Result<Option<PathBuf>> {
    let path = state.join("commands");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Refusal::new(format!(
                "cannot inspect commands directory: {e}"
            )));
        }
        Ok(m) if !m.file_type().is_dir() => {
            return Err(Refusal::new("commands path is not a directory"));
        }
        _ => {}
    }
    let commands = Directory::open(&path)?;
    let names = commands.names(ENTRY_LIMIT)?;
    let mut scanned = names.len();
    let mut active = Vec::new();
    for name in names {
        if name.to_str().is_some_and(|s| s.ends_with("-source-fetch")) {
            let budget = ENTRY_LIMIT.saturating_sub(scanned);
            let entries = commands.child(&name)?.names(budget)?;
            scanned += entries.len();
            if !entries
                .iter()
                .any(|e| e == OsStr::new("result.json") || e == OsStr::new("failed-process.json"))
            {
                active.push(path.join(name));
            }
        }
    }
    if active.len() > 1 {
        return Err(Refusal::new("multiple active source-fetch directories"));
    }
    Ok(active.into_iter().next())
}

#[allow(
    unsafe_code,
    reason = "This helper signals only the capture-owned positive direct PID."
)]
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}
#[allow(
    unsafe_code,
    reason = "Never signal a process group; use capture's direct child PID once."
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
    // SAFETY: capture_observed owns this positive PID; 15 is POSIX SIGTERM.
    if unsafe { kill(pid, 15) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn entry_present(path: &Path) -> std::result::Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}
fn prepare_failure(state: &Path) -> (bool, bool, Option<String>, Option<String>) {
    let path = state.join("prepare-failure.json");
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return (
                false,
                false,
                None,
                Some("prepare-failure.json is missing".into()),
            );
        }
        Err(e) => return (false, false, None, Some(e.to_string())),
    };
    if !meta.file_type().is_file() {
        return (
            true,
            false,
            None,
            Some("failure record is not a regular file".into()),
        );
    }
    let raw = match ami_rust_core::files::read_regular_bounded(&path, 64 * 1024) {
        Ok(v) => v,
        Err(e) => return (true, false, None, Some(e.to_string())),
    };
    let value: Value = match parse_json_value(&raw, JsonProfile::PackageMetadataStateSelection) {
        Ok(v) => v,
        Err(e) => return (true, false, None, Some(e.to_string())),
    };
    let phase = value["phase"].as_str().map(str::to_owned);
    let valid = value["schema"] == "ami-rust-prepare-failure-v1"
        && value["ready"] == false
        && value["state_retained"] == true
        && phase.as_deref() == Some("source-checkout");
    (
        true,
        valid,
        phase,
        (!valid).then(|| {
            "failure record is not the expected pre-publication source-checkout failure".into()
        }),
    )
}
fn text(path: &Path) -> ami_rust_core::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new("evidence paths must be UTF-8"))
}
fn write_new(path: &Path, bytes: &[u8]) -> ami_rust_core::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

//! Candidate RC2 selected-cache concurrency and semantic GC fixture.
//!
//! This is maintainer-only. It uses the existing in-process loopback registry,
//! explicit local tools, process_capture supervision, and synthetic credentials.
//! It does not qualify the component until the parent integrates and executes it.

use super::*;
use registry_fixture::{AuthPolicy, RegistryFixture};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const FIXTURE_BUDGET: Duration = Duration::from_secs(105);
const COMMAND_CAP: Duration = Duration::from_secs(30);
const STALE_DELAY: Duration = Duration::from_secs(15);
const GC_INDEX_MAX_AGE: &str = "10 seconds";
const LOG_STREAM_LIMIT: usize = 512 * 1024;

const BUILD_SCRIPT: &str = r#"
use std::{env, fs, path::PathBuf, thread, time::{Duration, Instant}};

fn main() {
    let root = PathBuf::from(env::var_os("RC2_STORAGE_BARRIER_DIR").expect("barrier dir"));
    let id = env::var("RC2_STORAGE_RUN_ID").expect("run id");
    let other = if id == "a" { "b" } else { "a" };
    fs::write(root.join(format!("entered-{id}")), b"entered").expect("write entered");
    let deadline = Instant::now() + Duration::from_secs(25);
    while !(root.join(format!("entered-{other}")).is_file()) {
        if Instant::now() >= deadline {
            panic!("second cargo did not reach the build-hook barrier");
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::write(root.join(format!("ready-{id}")), b"ready").expect("write ready");
    thread::sleep(Duration::from_millis(800));
    fs::write(root.join(format!("done-{id}")), b"done").expect("write done");
    println!("cargo:rerun-if-env-changed=RC2_STORAGE_RUN_ID");
}
"#;

enum ParallelMessage {
    Overlap {
        label: String,
        pid: u32,
        elapsed_millis: u64,
    },
    Finished(ParallelFinished),
}

struct ParallelFinished {
    label: String,
    spec: process_capture::CommandSpec,
    result: std::result::Result<process_capture::CapturedProcess, process_capture::CaptureError>,
}

pub(super) fn run(probe: &mut Probe<'_>, report: &mut Value) -> Result<()> {
    report["fixture_kind"] = json!("storage-selected-concurrency-and-semantic-gc");
    report["scope"] = json!(
        "Derived Cargo only: two supervised cargo checks must overlap while their build hooks wait at a shared barrier; Cargo clean gc then applies its actual registry-index last-use age policy."
    );
    report["limitations"] = json!([
        "No stock-control or selector-absent comparison is run here; this fixture makes no parity claim.",
        "The GC assertion covers registry-index age and deletion only, not crate, source, Git, size, automatic-GC, or failure/retry policies.",
        "The loopback registry and local crates.io replacement bound this fixture's intended inputs; they are not a general network sandbox.",
        "This bounded fixture does not establish GC contention while an active reader holds a package-cache lock; that separate case remains required."
    ]);

    let deadline = Instant::now()
        .checked_add(FIXTURE_BUDGET)
        .ok_or_else(|| Refusal::new("fixture deadline is not representable"))?;
    let tool = |name: &str| -> Result<PathBuf> {
        probe
            .tools
            .iter()
            .find(|row| row.name == name)
            .map(|row| row.path.clone())
            .ok_or_else(|| Refusal::new(format!("missing prepared {name} tool")))
    };
    let cargo = tool("derived-cargo")?;
    let rustc = tool("rustc")?;
    let rustdoc = tool("rustdoc")?;
    let git = tool("git")?;

    let temporary = probe.work.join("concurrent-gc temporary");
    let home = probe.work.join("concurrent-gc home");
    let cargo_home = probe.work.join("concurrent-gc original cargo home");
    let cache = probe.work.join("concurrent-gc selected store");
    let empty_source = probe.work.join("concurrent-gc empty crates.io source");
    let old_project = probe.work.join("concurrent-gc old project");
    let fresh_project = probe.work.join("concurrent-gc fresh project");
    let barrier = probe.work.join("concurrent-gc build-hook barrier");
    let target_a = probe.work.join("concurrent-gc target a");
    let target_b = probe.work.join("concurrent-gc target b");
    for path in [
        &temporary,
        &home,
        &cargo_home,
        &cache,
        &empty_source,
        &old_project,
        &fresh_project,
        &barrier,
        &target_a,
        &target_b,
    ] {
        create_private_directory(path)?;
    }
    create_private_directory(&old_project.join("src"))?;
    create_private_directory(&fresh_project.join("src"))?;
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o755))
        .map_err(|error| Refusal::new(format!("cannot set selected cache mode: {error}")))?;

    let old_registry = RegistryFixture::start(AuthPolicy::AcceptExpected)
        .map_err(|error| Refusal::new(format!("cannot start old loopback registry: {error}")))?;
    let fresh_registry = RegistryFixture::start(AuthPolicy::AcceptExpected)
        .map_err(|error| Refusal::new(format!("cannot start fresh loopback registry: {error}")))?;
    let old_index = old_registry.sparse_index_url();
    let fresh_index = fresh_registry.sparse_index_url();

    let config = format!(
        "[source.crates-io]\nreplace-with=\"rc2-empty\"\n[source.rc2-empty]\ndirectory={}\n[net]\nretry=0\n[registries.gc-old]\nindex={}\ncredential-provider=\"cargo:token\"\n[registries.gc-fresh]\nindex={}\ncredential-provider=\"cargo:token\"\n",
        toml_string(
            empty_source
                .to_str()
                .ok_or_else(|| { Refusal::new("empty source fixture path is not UTF-8") })?
        ),
        toml_string(&old_index),
        toml_string(&fresh_index),
    );
    write_text(&cargo_home.join("config.toml"), &config)?;
    let credentials = format!(
        "[registries.gc-old]\ntoken={}\n[registries.gc-fresh]\ntoken={}\n",
        toml_string(old_registry.expected_token()),
        toml_string(fresh_registry.expected_token()),
    );
    write_text(&cargo_home.join("credentials.toml"), &credentials)?;
    create_project(&old_project, "rc2_gc_old_app", "gc-old", false)?;
    create_project(&fresh_project, "rc2_gc_fresh_app", "gc-fresh", true)?;

    probe.set_base_env(&cargo_home, &home, &rustc, &rustdoc, &git);
    let base_env = probe.base_env.clone();
    let selected_env = with_selector(&base_env, &cache);
    let old_env = with_target(&selected_env, &target_a);
    let fresh_env = with_target(&selected_env, &target_a);
    let home_before = snapshot(&home)?;
    let cargo_home_before = snapshot(&cargo_home)?;
    let index_root = cache.join("registry/index");
    let index_before = snapshot_paths(&snapshot(&index_root)?);

    cargo_once(
        probe,
        deadline,
        "concurrent-gc-old-lock",
        &cargo,
        strings(["generate-lockfile"]),
        &old_project,
        &old_env,
        0,
    )?;
    cargo_once(
        probe,
        deadline,
        "concurrent-gc-old-fetch",
        &cargo,
        strings(["fetch", "--locked"]),
        &old_project,
        &old_env,
        0,
    )?;
    let index_after_old = snapshot_paths(&snapshot(&index_root)?);
    let old_index_paths = difference_paths(&index_after_old, &index_before);
    add_check(
        report,
        "cargo-created-old-registry-index",
        !old_index_paths.is_empty(),
        json!({"selected_root":os_metadata(cache.as_os_str()),"relative_entries":old_index_paths}),
    )?;

    // This is real elapsed time. No system clock or Cargo timestamp is edited.
    cancellable_delay(probe, deadline, STALE_DELAY)?;
    cargo_once(
        probe,
        deadline,
        "concurrent-gc-fresh-lock",
        &cargo,
        strings(["generate-lockfile"]),
        &fresh_project,
        &fresh_env,
        0,
    )?;
    cargo_once(
        probe,
        deadline,
        "concurrent-gc-fresh-fetch",
        &cargo,
        strings(["fetch", "--locked"]),
        &fresh_project,
        &fresh_env,
        0,
    )?;
    let index_before_gc = snapshot_paths(&snapshot(&index_root)?);
    let fresh_index_paths = difference_paths(&index_before_gc, &index_after_old);
    add_check(
        report,
        "cargo-created-fresh-registry-index",
        !fresh_index_paths.is_empty(),
        json!({"relative_entries":fresh_index_paths}),
    )?;

    let cache_metadata = fs::metadata(&cache)
        .map_err(|error| Refusal::new(format!("cannot inspect selected store: {error}")))?;
    let work_metadata = fs::metadata(&probe.work)
        .map_err(|error| Refusal::new(format!("cannot inspect fixture work root: {error}")))?;
    add_check(
        report,
        "selected-root-is-owned-and-canonical-mode",
        cache_metadata.uid() == work_metadata.uid()
            && cache_metadata.mode() & 0o7777 == 0o755
            && cache.is_absolute(),
        json!({
            "root":os_metadata(cache.as_os_str()),
            "root_uid":cache_metadata.uid(),
            "work_uid":work_metadata.uid(),
            "mode":format!("{:04o}",cache_metadata.mode() & 0o7777)
        }),
    )?;
    let same_selected_root = selected_cache(&old_env, &cache)
        && selected_cache(&fresh_env, &cache)
        && selected_cache(&with_target(&selected_env, &target_a), &cache)
        && selected_cache(&with_target(&selected_env, &target_b), &cache);
    add_check(
        report,
        "all-cache-commands-use-same-explicit-selected-root",
        same_selected_root,
        json!({"selected_root":os_metadata(cache.as_os_str()),"selector_absent_control_run":false}),
    )?;

    let mut concurrent_env_a = with_target(&selected_env, &target_a);
    let mut concurrent_env_b = with_target(&selected_env, &target_b);
    insert_env(
        &mut concurrent_env_a,
        "RC2_STORAGE_BARRIER_DIR",
        barrier.as_os_str(),
    );
    insert_env(
        &mut concurrent_env_b,
        "RC2_STORAGE_BARRIER_DIR",
        barrier.as_os_str(),
    );
    insert_env(&mut concurrent_env_a, "RC2_STORAGE_RUN_ID", OsStr::new("a"));
    insert_env(&mut concurrent_env_b, "RC2_STORAGE_RUN_ID", OsStr::new("b"));
    let concurrent = run_parallel_checks(
        probe,
        deadline,
        &cargo,
        &fresh_project,
        &concurrent_env_a,
        &concurrent_env_b,
        &barrier,
    )?;
    let observed_labels = concurrent
        .overlap_observations
        .iter()
        .filter_map(|row| row["cargo"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let observed_pids = concurrent
        .overlap_observations
        .iter()
        .filter_map(|row| row["direct_pid"].as_u64())
        .collect::<BTreeSet<_>>();
    let both_cargo_processes_observed = observed_labels.contains("concurrent-check-a")
        && observed_labels.contains("concurrent-check-b")
        && observed_pids.len() == 2;
    add_check(
        report,
        "two-derived-cargo-build-hooks-overlapped-live",
        both_cargo_processes_observed,
        json!({
            "overlap_observations":concurrent.overlap_observations,
            "both_cargo_processes_observed":both_cargo_processes_observed,
            "proof":"Each distinct direct Cargo PID was observed while both build-hook entered markers existed and neither done marker existed; both hooks block at the barrier until both Cargo processes reach them."
        }),
    )?;
    add_check(
        report,
        "both-overlapping-cargo-commands-succeeded",
        concurrent.successful_commands == 2,
        json!({"successful_commands":concurrent.successful_commands,"expected":2}),
    )?;

    cargo_once(
        probe,
        deadline,
        "concurrent-gc-refresh-fresh-index",
        &cargo,
        strings(["fetch", "--locked"]),
        &fresh_project,
        &fresh_env,
        0,
    )?;

    let mut nightly_gc_env = with_selector(&base_env, &cache);
    insert_env(
        &mut nightly_gc_env,
        "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS",
        OsStr::new("nightly"),
    );
    cargo_once(
        probe,
        deadline,
        "concurrent-gc-semantic-age-policy",
        &cargo,
        strings(["-Zgc", "clean", "gc", "--max-index-age", GC_INDEX_MAX_AGE]),
        &fresh_project,
        &nightly_gc_env,
        0,
    )?;
    let index_after_gc = snapshot_paths(&snapshot(&index_root)?);
    let old_removed = !old_index_paths.is_empty()
        && old_index_paths
            .iter()
            .all(|path| !index_after_gc.contains(path));
    let fresh_preserved = !fresh_index_paths.is_empty()
        && fresh_index_paths
            .iter()
            .all(|path| index_after_gc.contains(path));
    add_check(
        report,
        "cargo-gc-deletes-expired-index-and-preserves-fresh-index",
        old_removed && fresh_preserved,
        json!({
            "max_index_age":GC_INDEX_MAX_AGE,
            "old_entries_removed":old_removed,
            "fresh_entries_preserved":fresh_preserved,
            "old_entry_count":old_index_paths.len(),
            "fresh_entry_count":fresh_index_paths.len()
        }),
    )?;

    let database = cache.join(".global-cache");
    let db_header_valid = sqlite_database(&database)?;
    let db_fingerprint = if db_header_valid {
        file_fingerprint(&database)?
    } else {
        Value::Null
    };
    cargo_once(
        probe,
        deadline,
        "concurrent-gc-post-gc-cache-read",
        &cargo,
        strings(["check", "--locked", "--offline"]),
        &fresh_project,
        &concurrent_env_a,
        0,
    )?;
    add_check(
        report,
        "selected-database-and-cache-remain-usable",
        db_header_valid && !snapshot(&cache.join("registry"))?.is_empty(),
        json!({
            "sqlite_header_valid":db_header_valid,
            "database":db_fingerprint,
            "fresh_index_preserved":fresh_preserved,
            "cargo_check_after_gc_succeeded":true
        }),
    )?;
    add_check(
        report,
        "original-home-and-cargo-config-preserved",
        snapshot(&home)? == home_before && snapshot(&cargo_home)? == cargo_home_before,
        json!({
            "home_snapshot":home_before,
            "cargo_home_config_and_credentials_snapshot":cargo_home_before
        }),
    )?;

    report["fixtures"]["concurrent_gc"] = json!({
        "selected_cargo":tool_metadata_for(&probe.tools,"derived-cargo")?,
        "selected_root":os_metadata(cache.as_os_str()),
        "old_index_entries":old_index_paths,
        "fresh_index_entries":fresh_index_paths,
        "index_entries_after_gc":index_after_gc,
        "gc_policy":{"option":"--max-index-age","duration":GC_INDEX_MAX_AGE,"elapsed_age_setup_seconds":STALE_DELAY.as_secs()},
        "concurrent_commands":concurrent.successful_commands,
        "overlap_observations":concurrent.overlap_observations,
        "control_comparison":"not run",
        "selector_absent_comparison":"not run",
        "tokens_in_report_or_command_logs":false
    });
    Ok(())
}

struct ParallelSummary {
    successful_commands: usize,
    overlap_observations: Vec<Value>,
}

fn create_project(root: &Path, package: &str, registry: &str, with_hook: bool) -> Result<()> {
    let manifest = format!(
        "[package]\nname={}\nversion=\"0.1.0\"\nedition=\"2024\"\n{}\n[workspace]\n[dependencies]\nrc2-fixture-leaf={{version=\"=0.1.0\",registry={}}}\n",
        toml_string(package),
        if with_hook { "build=\"build.rs\"" } else { "" },
        toml_string(registry),
    );
    write_text(&root.join("Cargo.toml"), &manifest)?;
    write_text(&root.join("src/main.rs"), "fn main() {}\n")?;
    if with_hook {
        write_text(&root.join("build.rs"), BUILD_SCRIPT)?;
    }
    Ok(())
}

fn with_target(
    env: &std::collections::BTreeMap<OsString, OsString>,
    target: &Path,
) -> std::collections::BTreeMap<OsString, OsString> {
    let mut result = env.clone();
    insert_env(&mut result, "CARGO_TARGET_DIR", target.as_os_str());
    result
}

fn selected_cache(env: &std::collections::BTreeMap<OsString, OsString>, cache: &Path) -> bool {
    env.get(OsStr::new("AMI_RUST_CARGO_STORAGE_ROOT"))
        .is_some_and(|value| value.as_os_str() == cache.as_os_str())
}

fn cancellable_delay(probe: &Probe<'_>, deadline: Instant, duration: Duration) -> Result<()> {
    let wait_until = Instant::now()
        .checked_add(duration)
        .ok_or_else(|| Refusal::new("registry age delay is not representable"))?;
    loop {
        probe.guard.check()?;
        let now = Instant::now();
        if now >= wait_until {
            return Ok(());
        }
        if now >= deadline {
            return Err(Refusal::new(
                "concurrent GC fixture exceeded its 105-second budget during age setup",
            ));
        }
        thread::sleep(
            wait_until
                .saturating_duration_since(now)
                .min(deadline.saturating_duration_since(now))
                .min(Duration::from_millis(25)),
        );
    }
}

fn snapshot_paths(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .filter_map(|row| row["path"].as_str())
        .filter(|path| *path != ".")
        .map(str::to_owned)
        .collect()
}

fn difference_paths(left: &BTreeSet<String>, right: &BTreeSet<String>) -> BTreeSet<String> {
    left.difference(right).cloned().collect()
}

fn tool_metadata_for(tools: &[Tool], name: &str) -> Result<Value> {
    tools
        .iter()
        .find(|tool| tool.name == name)
        .map(|tool| json!({"path":os_metadata(tool.path.as_os_str()),"sha256":tool.sha256}))
        .ok_or_else(|| Refusal::new(format!("missing prepared {name} tool")))
}

fn command_limits(deadline: Instant) -> Result<process_capture::CaptureLimits> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Refusal::new(
            "concurrent GC fixture exceeded its 105-second budget",
        ));
    }
    Ok(process_capture::CaptureLimits {
        timeout: remaining.min(COMMAND_CAP),
        stdout_bytes: LOG_STREAM_LIMIT,
        stderr_bytes: LOG_STREAM_LIMIT,
        termination_grace: TERMINATION_GRACE,
    })
}

#[allow(clippy::too_many_arguments)]
fn cargo_once(
    probe: &mut Probe<'_>,
    deadline: Instant,
    label: &str,
    cargo: &Path,
    args: impl IntoIterator<Item = OsString>,
    cwd: &Path,
    env: &std::collections::BTreeMap<OsString, OsString>,
    expected_exit_code: i32,
) -> Result<()> {
    probe.guard.check()?;
    let spec =
        process_capture::CommandSpec::new(cargo.as_os_str().to_owned(), args, cwd, env.clone());
    let limits = command_limits(deadline)?;
    let result = process_capture::capture(&spec, limits, || probe.guard.requested());
    record_capture(probe, label, &spec, expected_exit_code, result)
}

fn record_capture(
    probe: &mut Probe<'_>,
    label: &str,
    spec: &process_capture::CommandSpec,
    expected_exit_code: i32,
    capture_result: std::result::Result<
        process_capture::CapturedProcess,
        process_capture::CaptureError,
    >,
) -> Result<()> {
    probe
        .record_capture(label, spec, expected_exit_code, capture_result)
        .map(|_| ())
}

fn run_parallel_checks(
    probe: &mut Probe<'_>,
    deadline: Instant,
    cargo: &Path,
    project: &Path,
    env_a: &std::collections::BTreeMap<OsString, OsString>,
    env_b: &std::collections::BTreeMap<OsString, OsString>,
    barrier: &Path,
) -> Result<ParallelSummary> {
    let limits = command_limits(deadline)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(2);
    let mut spawn_error = None;

    for (label, env) in [
        ("concurrent-check-a", env_a.clone()),
        ("concurrent-check-b", env_b.clone()),
    ] {
        let spec = process_capture::CommandSpec::new(
            cargo.as_os_str().to_owned(),
            strings(["check", "--locked", "--offline"]),
            project,
            env,
        );
        let worker_cancel = Arc::clone(&cancel);
        let worker_sender = sender.clone();
        let worker_barrier = barrier.to_path_buf();
        let worker_label = label.to_owned();
        match thread::Builder::new()
            .name(format!("rc2-{label}"))
            .spawn(move || {
                let mut overlap_sent = false;
                let result = process_capture::capture_observed(
                    &spec,
                    limits,
                    || worker_cancel.load(Ordering::Acquire),
                    |observation| {
                        if !overlap_sent && both_build_hooks_active(&worker_barrier) {
                            overlap_sent = true;
                            worker_sender
                                .send(ParallelMessage::Overlap {
                                    label: worker_label.clone(),
                                    pid: observation.direct_pid,
                                    elapsed_millis: observation.elapsed.as_millis() as u64,
                                })
                                .map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "concurrency observer disconnected",
                                    )
                                })?;
                        }
                        Ok(())
                    },
                );
                let _ = worker_sender.send(ParallelMessage::Finished(ParallelFinished {
                    label: worker_label,
                    spec,
                    result,
                }));
            }) {
            Ok(handle) => workers.push(handle),
            Err(error) => {
                cancel.store(true, Ordering::Release);
                spawn_error = Some(Refusal::new(format!(
                    "cannot start supervised Cargo observer: {error}"
                )));
                break;
            }
        }
    }
    drop(sender);

    let expected_workers = workers.len();
    let mut finished = Vec::with_capacity(expected_workers);
    let mut overlap_observations = Vec::new();
    let mut disconnected = false;
    while finished.len() < expected_workers {
        if probe.guard.requested() || Instant::now() >= deadline {
            cancel.store(true, Ordering::Release);
        }
        match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(ParallelMessage::Overlap {
                label,
                pid,
                elapsed_millis,
            }) => {
                if overlap_observations.len() < 16 {
                    overlap_observations.push(json!({
                        "cargo":label,
                        "direct_pid":pid,
                        "elapsed_millis":elapsed_millis,
                        "both_build_hooks_active":true
                    }));
                }
            }
            Ok(ParallelMessage::Finished(outcome)) => finished.push(outcome),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                disconnected = true;
                cancel.store(true, Ordering::Release);
                break;
            }
        }
    }

    let mut worker_panics = 0;
    for worker in workers {
        if worker.join().is_err() {
            worker_panics += 1;
        }
    }
    if disconnected || worker_panics != 0 || finished.len() != expected_workers {
        return Err(Refusal::new(
            "parallel Cargo observer ended without reaping every supervised command",
        ));
    }

    finished.sort_by(|left, right| left.label.cmp(&right.label));
    let mut capture_errors = Vec::new();
    let mut successful_commands = 0;
    for outcome in finished {
        match record_capture(probe, &outcome.label, &outcome.spec, 0, outcome.result) {
            Ok(()) => successful_commands += 1,
            Err(error) => capture_errors.push(error.to_string()),
        }
    }
    if let Some(error) = spawn_error {
        capture_errors.push(error.to_string());
    }
    if !capture_errors.is_empty() {
        return Err(Refusal::new(format!(
            "parallel Cargo command failure: {}",
            capture_errors.join("; ")
        )));
    }

    Ok(ParallelSummary {
        successful_commands,
        overlap_observations,
    })
}

fn both_build_hooks_active(barrier: &Path) -> bool {
    let is_plain_file = |name: &str| {
        fs::symlink_metadata(barrier.join(name))
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    };
    is_plain_file("entered-a")
        && is_plain_file("entered-b")
        && !is_plain_file("done-a")
        && !is_plain_file("done-b")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_requires_both_hooks_and_no_completed_hook() {
        let root = std::env::temp_dir().join(format!(
            "rc2-overlap-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        create_private_directory(&root).unwrap();
        assert!(!both_build_hooks_active(&root));
        write_text(&root.join("entered-a"), "entered").unwrap();
        assert!(!both_build_hooks_active(&root));
        write_text(&root.join("entered-b"), "entered").unwrap();
        assert!(both_build_hooks_active(&root));
        write_text(&root.join("done-a"), "done").unwrap();
        assert!(!both_build_hooks_active(&root));
        fs::remove_dir_all(root).unwrap();
    }
}

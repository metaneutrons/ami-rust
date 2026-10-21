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
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const FIXTURE_BUDGET: Duration = Duration::from_secs(420);
const CASE_BUDGET: Duration = Duration::from_secs(105);
const COMMAND_CAP: Duration = Duration::from_secs(30);
const STALE_DELAY: Duration = Duration::from_secs(15);
const GC_INDEX_MAX_AGE: &str = "10 seconds";
const LOG_STREAM_LIMIT: usize = 128 * 1024;
const CONTENTION_HOLD: Duration = Duration::from_millis(250);
const PACKAGE_CACHE_BLOCKING_MESSAGE: &[u8] =
    b"Blocking waiting for file lock on package cache mutation";

const BUILD_SCRIPT: &str = r#"
use std::{env, fs, path::PathBuf, thread, time::{Duration, Instant}};

fn main() {
    let root = PathBuf::from(env::var_os("RC2_STORAGE_BARRIER_DIR").expect("barrier dir"));
    let id = env::var("RC2_STORAGE_RUN_ID").expect("run id");
    let other = if id == "a" { "b" } else { "a" };
    fs::write(root.join(format!("entered-{id}")), b"entered").expect("write entered");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(root.join(format!("entered-{other}")).is_file()) {
        if Instant::now() >= deadline {
            panic!("second cargo did not reach the build-hook barrier");
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::write(root.join(format!("ready-{id}")), b"ready").expect("write ready");
    while !(root.join("release").is_file()) {
        if Instant::now() >= deadline {
            panic!("coordinator did not release Cargo build-hook barrier");
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::write(root.join(format!("done-{id}")), b"done").expect("write done");
    println!("cargo:rerun-if-env-changed=RC2_STORAGE_RUN_ID");
}
"#;

enum ConcurrentMessage {
    ReaderRunning(CaptureSample),
    GcRunning(CaptureSample),
    Terminal(WorkerTerminal),
}

struct CaptureSample {
    label: String,
    pid: u32,
    at_millis: u64,
    capture_elapsed_millis: u64,
    stdout_bytes: usize,
    stderr_bytes: usize,
    sample_due: bool,
}

enum WorkerTerminal {
    Captured(WorkerFinished),
    Panicked { label: String, at_millis: u64 },
}

struct WorkerFinished {
    label: String,
    spec: process_capture::CommandSpec,
    result: std::result::Result<process_capture::CapturedProcess, process_capture::CaptureError>,
    at_millis: u64,
}

struct ContentionSummary {
    timeline: Vec<Value>,
    reader_pids: Vec<u32>,
    gc_pid: Option<u32>,
    gc_running_samples: usize,
    gc_stderr_bytes: usize,
    gc_wait_message_found: bool,
    hold_millis: u64,
    release_order_valid: bool,
    gc_started_after_readers: bool,
    commands_started: usize,
    successful_commands: usize,
    worker_errors: Vec<String>,
}

#[derive(Clone, Copy)]
struct CaseSpec {
    id: &'static str,
    cargo_tool: &'static str,
    derived: bool,
    selector_present: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticSignature {
    old_index_created: bool,
    fresh_index_created: bool,
    expired_index_removed: bool,
    fresh_index_preserved: bool,
    sqlite_header_valid: bool,
    post_gc_offline_read_succeeded: bool,
    cache_artifacts_under_expected_root: bool,
}

impl SemanticSignature {
    fn json_value(&self) -> Value {
        json!({
            "old_index_created":self.old_index_created,
            "fresh_index_created":self.fresh_index_created,
            "expired_index_removed":self.expired_index_removed,
            "fresh_index_preserved":self.fresh_index_preserved,
            "sqlite_header_valid":self.sqlite_header_valid,
            "post_gc_offline_read_succeeded":self.post_gc_offline_read_succeeded,
            "cache_artifacts_under_expected_root":self.cache_artifacts_under_expected_root
        })
    }
}

struct CaptureWorkers {
    cancel: Arc<AtomicBool>,
    barrier: std::path::PathBuf,
    handles: Vec<JoinHandle<()>>,
    released: bool,
}

impl CaptureWorkers {
    fn new(barrier: &Path) -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            barrier: barrier.to_path_buf(),
            handles: Vec::with_capacity(3),
            released: false,
        }
    }

    fn spawn(
        &mut self,
        label: &str,
        role: WorkerRole,
        spec: process_capture::CommandSpec,
        limits: process_capture::CaptureLimits,
        sender: mpsc::Sender<ConcurrentMessage>,
        origin: Instant,
    ) -> Result<()> {
        let cancel = Arc::clone(&self.cancel);
        let barrier = self.barrier.clone();
        let worker_label = label.to_owned();
        let handle = thread::Builder::new()
            .name(format!("rc2-{label}"))
            .spawn(move || {
                let captured = panic::catch_unwind(AssertUnwindSafe(|| {
                    let mut reported = false;
                    process_capture::capture_observed(
                        &spec,
                        limits,
                        || cancel.load(Ordering::Acquire),
                        |observation| {
                            let active = both_build_hooks_waiting(&barrier);
                            let sample_due = match observation.phase {
                                process_capture::CaptureObservationPhase::Running {
                                    sample_due,
                                } => sample_due,
                                process_capture::CaptureObservationPhase::BeforeReap => false,
                            };
                            if active
                                && matches!(
                                    observation.phase,
                                    process_capture::CaptureObservationPhase::Running { .. }
                                )
                            {
                                let should_send = match role {
                                    WorkerRole::Reader => !reported,
                                    WorkerRole::Gc => {
                                        observation.stderr_bytes > 0 && (!reported || sample_due)
                                    }
                                };
                                if should_send {
                                    let sample = CaptureSample {
                                        label: worker_label.clone(),
                                        pid: observation.direct_pid,
                                        at_millis: elapsed_millis(origin),
                                        capture_elapsed_millis: observation.elapsed.as_millis()
                                            as u64,
                                        stdout_bytes: observation.stdout_bytes,
                                        stderr_bytes: observation.stderr_bytes,
                                        sample_due,
                                    };
                                    let message = match role {
                                        WorkerRole::Reader => {
                                            ConcurrentMessage::ReaderRunning(sample)
                                        }
                                        WorkerRole::Gc => ConcurrentMessage::GcRunning(sample),
                                    };
                                    sender.send(message).map_err(|_| {
                                        io::Error::new(
                                            io::ErrorKind::BrokenPipe,
                                            "concurrent Cargo observer disconnected",
                                        )
                                    })?;
                                    reported = true;
                                }
                            }
                            Ok(())
                        },
                    )
                }));
                let terminal = match captured {
                    Ok(result) => WorkerTerminal::Captured(WorkerFinished {
                        label: worker_label,
                        spec,
                        result,
                        at_millis: elapsed_millis(origin),
                    }),
                    Err(_) => WorkerTerminal::Panicked {
                        label: worker_label,
                        at_millis: elapsed_millis(origin),
                    },
                };
                let _ = sender.send(ConcurrentMessage::Terminal(terminal));
            })
            .map_err(|error| Refusal::new(format!("cannot start supervised {label}: {error}")))?;
        self.handles.push(handle);
        Ok(())
    }

    fn release(&mut self) -> Result<()> {
        write_release_marker(&self.barrier).map_err(|error| {
            Refusal::new(format!("cannot release Cargo build-hook barrier: {error}"))
        })?;
        self.released = true;
        Ok(())
    }

    fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    fn join_all(&mut self) -> usize {
        self.handles
            .drain(..)
            .map(|handle| handle.join().is_err())
            .filter(|panicked| *panicked)
            .count()
    }
}

impl Drop for CaptureWorkers {
    fn drop(&mut self) {
        self.cancel();
        if !self.released {
            let _ = write_release_marker(&self.barrier);
        }
        let _ = self.join_all();
    }
}

#[derive(Clone, Copy)]
enum WorkerRole {
    Reader,
    Gc,
}

pub(super) fn run(probe: &mut Probe<'_>, report: &mut Value) -> Result<()> {
    report["fixture_kind"] = json!("storage-selected-concurrency-and-semantic-gc");
    report["scope"] = json!(
        "Four independent control/derived Cargo and selector-present/absent cases each prove live two-reader versus GC package-cache contention and Cargo's registry-index age policy."
    );
    report["limitations"] = json!([
        "The four cases are control-selector-present, control-selector-absent, derived-selector-present, and derived-selector-absent; parity compares only semantic outcomes, not timestamps, registry ports, or raw paths.",
        "The GC assertion covers registry-index age and deletion only, not crate, source, Git, size, automatic-GC, concurrent fetch, or complete failure/retry policies.",
        "Concurrent fetch behavior and complete failure/retry qualification remain open.",
        "The loopback registry and local crates.io replacement bound this fixture's intended inputs; they are not a general network sandbox.",
        "This isolated maintainer fixture is component development only; no SDK/AROS/release acceptance."
    ]);

    let deadline = Instant::now()
        .checked_add(FIXTURE_BUDGET)
        .ok_or_else(|| Refusal::new("fixture deadline is not representable"))?;
    report["fixtures"] = json!({"concurrent_gc":{"cases":{}}});
    let cases = [
        CaseSpec {
            id: "control-selector-present",
            cargo_tool: "control-cargo",
            derived: false,
            selector_present: true,
        },
        CaseSpec {
            id: "control-selector-absent",
            cargo_tool: "control-cargo",
            derived: false,
            selector_present: false,
        },
        CaseSpec {
            id: "derived-selector-present",
            cargo_tool: "derived-cargo",
            derived: true,
            selector_present: true,
        },
        CaseSpec {
            id: "derived-selector-absent",
            cargo_tool: "derived-cargo",
            derived: true,
            selector_present: false,
        },
    ];
    let mut summaries = Vec::with_capacity(cases.len());
    for case in cases {
        probe.guard.check()?;
        let case_deadline = Instant::now()
            .checked_add(CASE_BUDGET)
            .ok_or_else(|| Refusal::new("case deadline is not representable"))?
            .min(deadline);
        if case_deadline <= Instant::now() {
            return Err(Refusal::new(
                "four-case GC fixture exceeded its 420-second budget",
            ));
        }
        let semantic = run_case(probe, report, case, case_deadline)?;
        summaries.push((case, semantic));
    }

    let control_present = find_semantic(&summaries, "control-selector-present")?;
    let derived_present = find_semantic(&summaries, "derived-selector-present")?;
    add_check(
        report,
        "control-vs-derived-selector-present-semantic-gc-parity",
        control_present == derived_present,
        json!({
            "compared_fields":"index creation, age deletion/preservation, database header, post-GC read, and expected-root artifacts",
            "control":control_present.json_value(),
            "derived":derived_present.json_value(),
            "timestamps_ports_and_raw_paths_compared":false
        }),
    )?;
    let control_absent = find_semantic(&summaries, "control-selector-absent")?;
    let derived_absent = find_semantic(&summaries, "derived-selector-absent")?;
    add_check(
        report,
        "control-vs-derived-selector-absent-semantic-gc-parity",
        control_absent == derived_absent,
        json!({
            "compared_fields":"index creation, age deletion/preservation, database header, post-GC read, and expected-root artifacts",
            "control":control_absent.json_value(),
            "derived":derived_absent.json_value(),
            "timestamps_ports_and_raw_paths_compared":false
        }),
    )?;
    report["fixtures"]["concurrent_gc"]["case_count"] = json!(cases.len());
    report["fixtures"]["concurrent_gc"]["semantic_comparison"] = json!({
        "selector_present_control_vs_derived":control_present.json_value(),
        "selector_absent_control_vs_derived":control_absent.json_value(),
        "fields":"bounded semantic outcomes only; no timestamp, registry port, or raw path equality"
    });
    Ok(())
}

fn find_semantic<'a>(
    summaries: &'a [(CaseSpec, SemanticSignature)],
    id: &str,
) -> Result<&'a SemanticSignature> {
    summaries
        .iter()
        .find(|(case, _)| case.id == id)
        .map(|(_, summary)| summary)
        .ok_or_else(|| Refusal::new(format!("missing semantic results for case {id}")))
}

fn run_case(
    probe: &mut Probe<'_>,
    report: &mut Value,
    case: CaseSpec,
    deadline: Instant,
) -> Result<SemanticSignature> {
    let prefix = format!("concurrent-gc-{}", case.id);
    let tool = |name: &str| -> Result<PathBuf> {
        probe
            .tools
            .iter()
            .find(|row| row.name == name)
            .map(|row| row.path.clone())
            .ok_or_else(|| Refusal::new(format!("missing prepared {name} tool")))
    };
    let cargo = tool(case.cargo_tool)?;
    let rustc = tool("rustc")?;
    let rustdoc = tool("rustdoc")?;
    let git = tool("git")?;

    let case_root = probe.work.join(format!("concurrent-gc {}", case.id));
    create_private_directory(&case_root)?;
    let temporary = case_root.join("temporary");
    let home = case_root.join("home");
    let cargo_home = case_root.join("original cargo home");
    let cache = case_root.join("selected store");
    let empty_source = case_root.join("empty crates.io source");
    let old_project = case_root.join("old project");
    let fresh_project = case_root.join("fresh project");
    let barrier = case_root.join("build-hook barrier");
    let target_a = case_root.join("target a");
    let target_b = case_root.join("target b");
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
    let package_suffix = case.id.replace('-', "_");
    create_project(
        &old_project,
        &format!("rc2_gc_{package_suffix}_old_app"),
        "gc-old",
        false,
    )?;
    create_project(
        &fresh_project,
        &format!("rc2_gc_{package_suffix}_fresh_app"),
        "gc-fresh",
        true,
    )?;

    probe.set_base_env(&cargo_home, &home, &rustc, &rustdoc, &git);
    let mut base_env = probe.base_env.clone();
    insert_env(&mut base_env, "CARGO_TERM_COLOR", OsStr::new("never"));
    insert_env(&mut base_env, "TMPDIR", temporary.as_os_str());
    let selected_env = if case.selector_present {
        with_selector(&base_env, &cache)
    } else {
        base_env
    };
    let expected_cache_root = if case.derived && case.selector_present {
        cache.clone()
    } else {
        cargo_home.clone()
    };
    let old_env = with_target(&selected_env, &target_a);
    let fresh_env = with_target(&selected_env, &target_a);
    let home_before = snapshot(&home)?;
    let config_before = snapshot(&cargo_home.join("config.toml"))?;
    let credentials_before = snapshot(&cargo_home.join("credentials.toml"))?;
    let cargo_home_before = if case.derived && case.selector_present {
        Some(snapshot(&cargo_home)?)
    } else {
        None
    };
    let selected_before = snapshot(&cache)?;
    let index_root = expected_cache_root.join("registry/index");
    let index_before = snapshot_paths(&snapshot(&index_root)?);

    cargo_once(
        probe,
        deadline,
        &format!("{prefix}-old-lock"),
        &cargo,
        strings(["generate-lockfile"]),
        &old_project,
        &old_env,
        0,
    )?;
    cargo_once(
        probe,
        deadline,
        &format!("{prefix}-old-fetch"),
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
        &format!("{prefix}-old-index-created-in-expected-root"),
        !old_index_paths.is_empty(),
        json!({"expected_mutable_root":os_metadata(expected_cache_root.as_os_str()),"relative_entries":old_index_paths}),
    )?;

    // This is real elapsed time. No system clock or Cargo timestamp is edited.
    cancellable_delay(probe, deadline, STALE_DELAY)?;
    cargo_once(
        probe,
        deadline,
        &format!("{prefix}-fresh-lock"),
        &cargo,
        strings(["generate-lockfile"]),
        &fresh_project,
        &fresh_env,
        0,
    )?;
    cargo_once(
        probe,
        deadline,
        &format!("{prefix}-fresh-fetch"),
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
        &format!("{prefix}-fresh-index-created-in-expected-root"),
        !fresh_index_paths.is_empty(),
        json!({"relative_entries":fresh_index_paths}),
    )?;

    let cache_metadata = fs::metadata(&cache)
        .map_err(|error| Refusal::new(format!("cannot inspect selected store: {error}")))?;
    let canonical_cache = fs::canonicalize(&cache)
        .map_err(|error| Refusal::new(format!("cannot canonicalize selected store: {error}")))?;
    let work_metadata = fs::metadata(&probe.work)
        .map_err(|error| Refusal::new(format!("cannot inspect fixture work root: {error}")))?;
    add_check(
        report,
        &format!("{prefix}-selected-root-is-owned-and-canonical-mode"),
        cache_metadata.uid() == work_metadata.uid()
            && cache_metadata.mode() & 0o7777 == 0o755
            && cache.is_absolute()
            && canonical_cache == cache,
        json!({
            "root":os_metadata(cache.as_os_str()),
            "canonical_path_matches":canonical_cache == cache,
            "root_uid":cache_metadata.uid(),
            "work_uid":work_metadata.uid(),
            "mode":format!("{:04o}",cache_metadata.mode() & 0o7777)
        }),
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
    let gc_env = with_target(&selected_env, &target_a);
    let mut nightly_gc_env = gc_env.clone();
    insert_env(
        &mut nightly_gc_env,
        "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS",
        OsStr::new("nightly"),
    );

    let cache_envs = [
        &old_env,
        &fresh_env,
        &concurrent_env_a,
        &concurrent_env_b,
        &nightly_gc_env,
    ];
    let selector_matches = cache_envs.iter().all(|env| {
        if case.selector_present {
            selected_cache(env, &cache)
        } else {
            !env.contains_key(OsStr::new("AMI_RUST_CARGO_STORAGE_ROOT"))
        }
    });
    add_check(
        report,
        &format!("{prefix}-selector-state-matches-case"),
        selector_matches,
        json!({
            "cargo_tool":case.cargo_tool,
            "derived":case.derived,
            "selector_present":case.selector_present,
            "expected_effective_root":os_metadata(expected_cache_root.as_os_str()),
            "selector_value_matches_case":selector_matches,
            "effective_root_is_proven_by_index_and_cache_artifacts":true
        }),
    )?;

    // Refresh after preparing the selected-root assertions and immediately
    // before starting the reader/GC window.
    cargo_once(
        probe,
        deadline,
        &format!("{prefix}-refresh-fresh-index"),
        &cargo,
        strings(["fetch", "--locked"]),
        &fresh_project,
        &fresh_env,
        0,
    )?;

    let contention = run_gc_contention(
        probe,
        deadline,
        &cargo,
        &fresh_project,
        &concurrent_env_a,
        &concurrent_env_b,
        &nightly_gc_env,
        &barrier,
        &prefix,
    )?;
    add_check(
        report,
        &format!("{prefix}-two-reader-pids-observed-before-gc"),
        contention.reader_pids.len() == 2 && contention.gc_started_after_readers,
        json!({"reader_pids":contention.reader_pids,"gc_started_after_readers":contention.gc_started_after_readers}),
    )?;
    add_check(
        report,
        &format!("{prefix}-gc-running-with-stderr-while-readers-held"),
        contention.gc_running_samples > 0 && contention.gc_pid.is_some(),
        json!({"gc_pid":contention.gc_pid,"running_samples":contention.gc_running_samples,"stderr_bytes":contention.gc_stderr_bytes}),
    )?;
    add_check(
        report,
        &format!("{prefix}-gc-lock-contention-held-then-released"),
        contention.release_order_valid
            && contention.hold_millis >= CONTENTION_HOLD.as_millis() as u64,
        json!({"hold_millis":contention.hold_millis,"required_millis":CONTENTION_HOLD.as_millis(),"release_order_valid":contention.release_order_valid}),
    )?;
    add_check(
        report,
        &format!("{prefix}-gc-blocking-message-in-unmodified-stderr"),
        contention.gc_wait_message_found,
        json!({"matched_phrase":"Blocking waiting for file lock on package cache mutation","unmodified_stderr":true}),
    )?;
    add_check(
        report,
        &format!("{prefix}-all-three-concurrent-commands-succeeded"),
        contention.commands_started == 3
            && contention.successful_commands == 3
            && contention.worker_errors.is_empty(),
        json!({"commands_started":contention.commands_started,"successful_final_statuses":contention.successful_commands,"worker_errors":contention.worker_errors}),
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
        &format!("{prefix}-cargo-gc-deletes-expired-index-and-preserves-fresh-index"),
        old_removed && fresh_preserved,
        json!({
            "max_index_age":GC_INDEX_MAX_AGE,
            "old_entries_removed":old_removed,
            "fresh_entries_preserved":fresh_preserved,
            "old_entry_count":old_index_paths.len(),
            "fresh_entry_count":fresh_index_paths.len()
        }),
    )?;

    let database = expected_cache_root.join(".global-cache");
    let db_header_valid = sqlite_database(&database)?;
    let db_fingerprint = if db_header_valid {
        file_fingerprint(&database)?
    } else {
        Value::Null
    };
    cargo_once(
        probe,
        deadline,
        &format!("{prefix}-post-gc-offline-cache-read"),
        &cargo,
        strings(["check", "--locked", "--offline"]),
        &fresh_project,
        &concurrent_env_a,
        0,
    )?;
    let expected_root_artifacts = plain_file(&expected_cache_root.join(".package-cache"))?
        && plain_file(&expected_cache_root.join(".package-cache-mutate"))?
        && db_header_valid
        && !snapshot(&index_root)?.is_empty();
    add_check(
        report,
        &format!("{prefix}-expected-root-locks-db-and-index-remain-usable"),
        expected_root_artifacts,
        json!({
            "sqlite_header_valid":db_header_valid,
            "database":db_fingerprint,
            "package_cache_lock_present":plain_file(&expected_cache_root.join(".package-cache"))?,
            "package_cache_mutate_lock_present":plain_file(&expected_cache_root.join(".package-cache-mutate"))?,
            "registry_index_entries_present":!snapshot(&index_root)?.is_empty(),
            "expected_mutable_root":os_metadata(expected_cache_root.as_os_str()),
            "fresh_index_preserved":fresh_preserved,
            "cargo_check_after_gc_succeeded":true
        }),
    )?;

    let home_unchanged = snapshot(&home)? == home_before;
    let config_unchanged = snapshot(&cargo_home.join("config.toml"))? == config_before;
    let credentials_unchanged =
        snapshot(&cargo_home.join("credentials.toml"))? == credentials_before;
    let original_cargo_home_unchanged = match cargo_home_before.as_ref() {
        Some(before) => snapshot(&cargo_home)? == *before,
        None => false,
    };
    add_check(
        report,
        &format!("{prefix}-home-config-and-credentials-unchanged"),
        home_unchanged && config_unchanged && credentials_unchanged,
        json!({
            "home_unchanged":home_unchanged,
            "config_unchanged":config_unchanged,
            "credentials_unchanged":credentials_unchanged
        }),
    )?;

    let selected_root_after = snapshot(&cache)?;
    let selected_root_untouched = selected_root_after == selected_before;
    if case.derived && case.selector_present {
        add_check(
            report,
            &format!("{prefix}-original-cargo-home-unchanged"),
            original_cargo_home_unchanged,
            json!({
                "whole_original_cargo_home_compared":true,
                "unchanged":original_cargo_home_unchanged
            }),
        )?;
    } else {
        add_check(
            report,
            &format!("{prefix}-unselected-store-untouched"),
            selected_root_untouched,
            json!({
                "selected_root_untouched":selected_root_untouched,
                "whole_original_cargo_home_preservation_claimed":false
            }),
        )?;
    }

    let semantic = SemanticSignature {
        old_index_created: !old_index_paths.is_empty(),
        fresh_index_created: !fresh_index_paths.is_empty(),
        expired_index_removed: old_removed,
        fresh_index_preserved: fresh_preserved,
        sqlite_header_valid: db_header_valid,
        post_gc_offline_read_succeeded: true,
        cache_artifacts_under_expected_root: expected_root_artifacts,
    };

    report["fixtures"]["concurrent_gc"]["cases"][case.id] = json!({
        "cargo_tool":case.cargo_tool,
        "cargo_tool_identity":tool_metadata_for(&probe.tools, case.cargo_tool)?,
        "derived":case.derived,
        "selector_present":case.selector_present,
        "expected_mutable_root":os_metadata(expected_cache_root.as_os_str()),
        "selected_root":os_metadata(cache.as_os_str()),
        "semantic":semantic.json_value(),
        "old_index_entries":old_index_paths,
        "fresh_index_entries":fresh_index_paths,
        "index_entries_after_gc":index_after_gc,
        "selected_root_untouched":selected_root_untouched,
        "home_unchanged":home_unchanged,
        "config_unchanged":config_unchanged,
        "credentials_unchanged":credentials_unchanged,
        "whole_original_cargo_home_compared":case.derived && case.selector_present,
        "original_cargo_home_unchanged":if case.derived && case.selector_present {Some(original_cargo_home_unchanged)} else {None},
        "gc_policy":{"option":"--max-index-age","duration":GC_INDEX_MAX_AGE,"elapsed_age_setup_seconds":STALE_DELAY.as_secs()},
        "synthetic_token_values_in_report":false,
        "contention":{
            "timeline":contention.timeline,
            "reader_pids":contention.reader_pids,
            "gc_pid":contention.gc_pid,
            "gc_running_samples_with_stderr":contention.gc_running_samples,
            "gc_stderr_bytes_at_first_sample":contention.gc_stderr_bytes,
            "gc_wait_message_found_in_unmodified_stderr":contention.gc_wait_message_found,
            "held_after_first_gc_stderr_sample_millis":contention.hold_millis,
            "release_order_valid":contention.release_order_valid,
            "gc_started_after_readers":contention.gc_started_after_readers,
            "commands_started":contention.commands_started,
            "successful_final_statuses":contention.successful_commands,
            "worker_errors":contention.worker_errors
        }
    });
    Ok(semantic)
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

#[allow(clippy::too_many_arguments)]
fn run_gc_contention(
    probe: &mut Probe<'_>,
    deadline: Instant,
    cargo: &Path,
    project: &Path,
    env_a: &std::collections::BTreeMap<OsString, OsString>,
    env_b: &std::collections::BTreeMap<OsString, OsString>,
    gc_env: &std::collections::BTreeMap<OsString, OsString>,
    barrier: &Path,
    case_prefix: &str,
) -> Result<ContentionSummary> {
    let origin = Instant::now();
    let limits = command_limits(deadline)?;
    let (sender, receiver) = mpsc::channel();
    let mut workers = CaptureWorkers::new(barrier);
    let mut timeline = Vec::new();
    let reader_a_label = format!("{case_prefix}-reader-a");
    let reader_b_label = format!("{case_prefix}-reader-b");
    let gc_label = format!("{case_prefix}-gc");

    for (label, env) in [
        (reader_a_label.as_str(), env_a.clone()),
        (reader_b_label.as_str(), env_b.clone()),
    ] {
        let spec = process_capture::CommandSpec::new(
            cargo.as_os_str().to_owned(),
            strings(["check", "--locked", "--offline"]),
            project,
            env,
        );
        workers.spawn(
            label,
            WorkerRole::Reader,
            spec,
            limits,
            sender.clone(),
            origin,
        )?;
    }

    let mut reader_labels = BTreeSet::new();
    let mut reader_pids = BTreeSet::new();
    while reader_labels.len() < 2 {
        match receive_contention_message(&receiver, probe, deadline)? {
            ConcurrentMessage::ReaderRunning(sample) => {
                if sample.label != reader_a_label && sample.label != reader_b_label {
                    return Err(Refusal::new("unexpected worker reported a reader PID"));
                }
                reader_labels.insert(sample.label.clone());
                reader_pids.insert(sample.pid);
                timeline.push(sample_event("reader_running_at_hook_barrier", &sample));
            }
            ConcurrentMessage::GcRunning(_) => {
                return Err(Refusal::new("GC observation arrived before GC was started"));
            }
            ConcurrentMessage::Terminal(terminal) => {
                return Err(Refusal::new(format!(
                    "{} finished before both live reader PIDs were observed",
                    terminal_label(&terminal)
                )));
            }
        }
    }
    if reader_pids.len() != 2 || !both_build_hooks_waiting(barrier) {
        return Err(Refusal::new(
            "Cargo reader PIDs were not distinct while both hooks waited at the barrier",
        ));
    }

    let gc_spawned_at = elapsed_millis(origin);
    timeline
        .push(json!({"event":"gc_worker_spawned_after_two_reader_pids","at_millis":gc_spawned_at}));
    let gc_spec = process_capture::CommandSpec::new(
        cargo.as_os_str().to_owned(),
        strings(["-Zgc", "clean", "gc", "--max-index-age", GC_INDEX_MAX_AGE]),
        project,
        gc_env.clone(),
    );
    workers.spawn(
        &gc_label,
        WorkerRole::Gc,
        gc_spec,
        limits,
        sender.clone(),
        origin,
    )?;

    let first_gc_sample = loop {
        match receive_contention_message(&receiver, probe, deadline)? {
            ConcurrentMessage::ReaderRunning(sample) => {
                timeline.push(sample_event("reader_running_duplicate", &sample));
            }
            ConcurrentMessage::GcRunning(sample) => {
                timeline.push(sample_event(
                    "gc_running_with_stderr_and_readers_held",
                    &sample,
                ));
                break sample;
            }
            ConcurrentMessage::Terminal(terminal) => {
                return Err(Refusal::new(format!(
                    "{} finished before GC reported lock contention",
                    terminal_label(&terminal)
                )));
            }
        }
    };
    if first_gc_sample.stderr_bytes == 0 || !both_build_hooks_waiting(barrier) {
        return Err(Refusal::new(
            "GC did not report live stderr while both reader build hooks remained held",
        ));
    }

    let hold_started = Instant::now();
    let mut gc_running_samples = 1;
    while hold_started.elapsed() < CONTENTION_HOLD {
        probe.guard.check()?;
        if Instant::now() >= deadline {
            return Err(Refusal::new(
                "concurrent GC fixture exceeded its 105-second budget during lock hold",
            ));
        }
        if !both_build_hooks_waiting(barrier) {
            return Err(Refusal::new(
                "Cargo reader hooks left the parent-controlled barrier before release",
            ));
        }
        let wait = CONTENTION_HOLD
            .saturating_sub(hold_started.elapsed())
            .min(Duration::from_millis(25));
        if let Some(message) = poll_contention_message(&receiver, probe, deadline, wait)? {
            match message {
                ConcurrentMessage::ReaderRunning(sample) => {
                    timeline.push(sample_event("reader_running_while_gc_blocked", &sample));
                }
                ConcurrentMessage::GcRunning(sample) => {
                    gc_running_samples += 1;
                    timeline.push(sample_event(
                        "gc_running_with_stderr_and_readers_held",
                        &sample,
                    ));
                }
                ConcurrentMessage::Terminal(terminal) => {
                    return Err(Refusal::new(format!(
                        "{} completed before the GC lock hold was released",
                        terminal_label(&terminal)
                    )));
                }
            }
        }
    }

    if !both_build_hooks_waiting(barrier) {
        return Err(Refusal::new(
            "Cargo reader hooks were not both held immediately before release",
        ));
    }
    workers.release()?;
    let release_at = elapsed_millis(origin);
    timeline.push(json!({"event":"parent_release_marker_written","at_millis":release_at}));

    let commands_started = workers.handles.len();
    let mut finished = Vec::with_capacity(commands_started);
    let mut finished_labels = BTreeSet::new();
    let mut worker_errors = Vec::new();
    while finished_labels.len() < commands_started {
        match receive_contention_message(&receiver, probe, deadline)? {
            ConcurrentMessage::ReaderRunning(sample) => {
                timeline.push(sample_event("reader_running_after_release", &sample));
            }
            ConcurrentMessage::GcRunning(sample) => {
                timeline.push(sample_event("gc_running_after_release", &sample));
            }
            ConcurrentMessage::Terminal(terminal) => match terminal {
                WorkerTerminal::Captured(outcome) => {
                    if !finished_labels.insert(outcome.label.clone()) {
                        return Err(Refusal::new("supervised Cargo worker reported twice"));
                    }
                    let exit_code = outcome
                        .result
                        .as_ref()
                        .ok()
                        .and_then(|captured| captured.status.code());
                    timeline.push(json!({
                        "event":"worker_finished",
                        "worker":outcome.label,
                        "at_millis":outcome.at_millis,
                        "exit_code":exit_code
                    }));
                    finished.push(outcome);
                }
                WorkerTerminal::Panicked { label, at_millis } => {
                    if !finished_labels.insert(label.clone()) {
                        return Err(Refusal::new("supervised Cargo worker reported twice"));
                    }
                    timeline.push(
                        json!({"event":"worker_panicked","worker":label,"at_millis":at_millis}),
                    );
                    worker_errors.push(format!("{label} worker panicked"));
                }
            },
        }
    }

    let worker_panics = workers.join_all();
    if worker_panics != 0 {
        worker_errors.push(format!(
            "{worker_panics} supervised observer thread(s) panicked"
        ));
    }

    finished.sort_by(|left, right| left.label.cmp(&right.label));
    let mut successful_commands = 0;
    let mut gc_wait_message_found = false;
    for outcome in finished {
        if outcome.label == gc_label
            && let Ok(captured) = &outcome.result
        {
            // The timer started at this observed byte count. Require the lock
            // message in that exact retained prefix, not in later diagnostics.
            gc_wait_message_found = captured
                .stderr
                .get(..first_gc_sample.stderr_bytes)
                .is_some_and(|prefix| {
                    prefix
                        .windows(PACKAGE_CACHE_BLOCKING_MESSAGE.len())
                        .any(|window| window == PACKAGE_CACHE_BLOCKING_MESSAGE)
                });
        }
        match probe.record_capture(&outcome.label, &outcome.spec, 0, outcome.result) {
            Ok(_) => successful_commands += 1,
            Err(error) => worker_errors.push(error.to_string()),
        }
    }

    timeline.sort_by_key(|event| event["at_millis"].as_u64().unwrap_or_default());
    let first_gc_at = first_gc_sample.at_millis;
    let hold_millis = release_at.saturating_sub(first_gc_at);
    let gc_started_after_readers =
        reader_labels.len() == 2 && reader_pids.len() == 2 && gc_spawned_at > 0 && {
            let observed_readers: Vec<&Value> = timeline
                .iter()
                .filter(|event| event["event"] == "reader_running_at_hook_barrier")
                .collect();
            observed_readers.len() == 2
                && observed_readers
                    .iter()
                    .all(|event| event["at_millis"].as_u64().unwrap_or(u64::MAX) <= gc_spawned_at)
        };
    let terminal_events: Vec<&Value> = timeline
        .iter()
        .filter(|event| event["event"] == "worker_finished" || event["event"] == "worker_panicked")
        .collect();
    let all_finished_after_release = terminal_events.len() == commands_started
        && terminal_events
            .iter()
            .all(|event| event["at_millis"].as_u64().unwrap_or_default() >= release_at);
    let release_order_valid = gc_spawned_at > 0
        && first_gc_at >= gc_spawned_at
        && release_at >= first_gc_at
        && hold_millis >= CONTENTION_HOLD.as_millis() as u64
        && all_finished_after_release;

    Ok(ContentionSummary {
        timeline,
        reader_pids: reader_pids.into_iter().collect(),
        gc_pid: Some(first_gc_sample.pid),
        gc_running_samples,
        gc_stderr_bytes: first_gc_sample.stderr_bytes,
        gc_wait_message_found,
        hold_millis,
        release_order_valid,
        gc_started_after_readers,
        commands_started,
        successful_commands,
        worker_errors,
    })
}

fn receive_contention_message(
    receiver: &mpsc::Receiver<ConcurrentMessage>,
    probe: &Probe<'_>,
    deadline: Instant,
) -> Result<ConcurrentMessage> {
    loop {
        if let Some(message) =
            poll_contention_message(receiver, probe, deadline, Duration::from_millis(25))?
        {
            return Ok(message);
        }
    }
}

fn poll_contention_message(
    receiver: &mpsc::Receiver<ConcurrentMessage>,
    probe: &Probe<'_>,
    deadline: Instant,
    wait: Duration,
) -> Result<Option<ConcurrentMessage>> {
    probe.guard.check()?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Refusal::new(
            "concurrent GC fixture exceeded its 105-second budget",
        ));
    }
    match receiver.recv_timeout(wait.min(remaining)) {
        Ok(message) => Ok(Some(message)),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(Refusal::new(
            "all concurrent Cargo observer channels disconnected before completion",
        )),
    }
}

fn sample_event(event: &str, sample: &CaptureSample) -> Value {
    json!({
        "event":event,
        "worker":sample.label,
        "direct_pid":sample.pid,
        "at_millis":sample.at_millis,
        "capture_elapsed_millis":sample.capture_elapsed_millis,
        "stdout_bytes":sample.stdout_bytes,
        "stderr_bytes":sample.stderr_bytes,
        "sample_due":sample.sample_due,
        "capture_phase":"Running",
        "both_build_hooks_held":true
    })
}

fn terminal_label(terminal: &WorkerTerminal) -> &str {
    match terminal {
        WorkerTerminal::Captured(outcome) => &outcome.label,
        WorkerTerminal::Panicked { label, .. } => label,
    }
}

fn elapsed_millis(origin: Instant) -> u64 {
    origin.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn write_release_marker(barrier: &Path) -> io::Result<()> {
    let path = barrier.join("release");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => return Ok(()),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "release marker path is not a plain file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(b"release")
}

fn both_build_hooks_waiting(barrier: &Path) -> bool {
    let is_plain_file = |name: &str| {
        fs::symlink_metadata(barrier.join(name))
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    };
    is_plain_file("ready-a")
        && is_plain_file("ready-b")
        && !is_plain_file("release")
        && !is_plain_file("done-a")
        && !is_plain_file("done-b")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_barrier_requires_both_ready_hooks_before_release() {
        let root = std::env::temp_dir().join(format!(
            "rc2-overlap-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        create_private_directory(&root).unwrap();
        assert!(!both_build_hooks_waiting(&root));
        write_text(&root.join("entered-a"), "entered").unwrap();
        write_text(&root.join("entered-b"), "entered").unwrap();
        assert!(!both_build_hooks_waiting(&root));
        write_text(&root.join("ready-a"), "ready").unwrap();
        assert!(!both_build_hooks_waiting(&root));
        write_text(&root.join("ready-b"), "ready").unwrap();
        assert!(both_build_hooks_waiting(&root));
        write_text(&root.join("release"), "release").unwrap();
        assert!(!both_build_hooks_waiting(&root));
        write_text(&root.join("done-a"), "done").unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

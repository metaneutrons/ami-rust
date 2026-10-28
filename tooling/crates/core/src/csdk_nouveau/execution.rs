//! Direct, bounded execution of a plan built from authenticated recipe inputs.
//!
//! The outer release driver owns aggregate process-tree observation, including
//! its own memory and all concurrently running compiler processes. The
//! per-command resource reports below cover one compiler process tree and
//! shared managed roots; they do not claim aggregate RSS across compiler
//! workers or include the supervising process.

use super::{
    EXPECTED_OBJECTS, SCHEMA, fail, metadata_without_symlink_components, plan_nouveau,
    require_directory, require_input_directory, require_source_file, under,
};
use crate::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_file},
    directory::Directory,
    process_capture::{CaptureCause, CaptureError, CaptureLimits, CommandSpec},
    resource_capture::{
        ResourceCaptureError, ResourceLimits, ResourceReport, SampleLimits,
        capture_with_resources_observed,
    },
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Seek, SeekFrom, Write},
    os::unix::{fs::MetadataExt, process::ExitStatusExt},
    path::{Component, Path, PathBuf},
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const PLAN_FILE: &str = "nouveau-compile-plan.json";
const PLAN_UPDATE_FILE: &str = "nouveau-compile-plan.json.update";
const LOG_DIRECTORY: &str = "nouveau-logs";
const COMPILER_ENV_DIRECTORY: &str = "compiler-environment";
const COMPILER_HOME_DIRECTORY: &str = "home";
const COMPILER_TEMP_DIRECTORY: &str = "tmp";
const MAX_JOBS: usize = 2;
const MAX_LOG_BYTES_PER_STREAM: usize = 512 * 1024;
const PARENT_SUMMARY_RESERVE: usize = 64 * 1024;
const MAX_AGGREGATE_SAVED_LOG_BYTES: usize = 16 * 1024 * 1024 - PARENT_SUMMARY_RESERVE;
const FAILURE_LOG_RESERVE: usize = MAX_JOBS * 2 * MAX_LOG_BYTES_PER_STREAM;
const MAX_REGULAR_SAVED_LOG_BYTES: usize = MAX_AGGREGATE_SAVED_LOG_BYTES - FAILURE_LOG_RESERVE;
const MAX_TOTAL_WARNING_BYTES: u64 = MAX_AGGREGATE_SAVED_LOG_BYTES as u64;
const PROCESS_GRACE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const TRUNCATION_MARKER: &[u8] =
    b"\n[truncated: retained bounded output prefix; compile attempt failed]\n";

/// Authenticated Nouveau recipe inputs and caller-owned resource policy.
///
/// `records` and `ninja_text` must come from the caller's authenticated,
/// pinned C-SDK inputs. The executor derives its private plan from these
/// values; it deliberately has no parameter for a serialized compile plan.
/// The outer release driver remains responsible for aggregate observation of
/// its own process plus all compiler workers.
pub struct NouveauCompileRequest {
    pub records: Vec<Value>,
    pub ninja_text: String,
    pub source_root: PathBuf,
    pub build_root: PathBuf,
    pub toolchain_root: PathBuf,
    pub compiler_sha256: String,
    pub work_dir: PathBuf,
    /// Only one or two simultaneous compiler jobs are accepted.
    pub jobs: usize,
    /// Overall deadline for the complete compilation pass.
    pub timeout: Duration,
    /// Per-compiler process-tree and shared-root observer limits.
    pub resource_limits: ResourceLimits,
    pub sample_limits: SampleLimits,
}

#[derive(Clone, Debug)]
struct CompileCommand {
    source: PathBuf,
    object: PathBuf,
    argv: Vec<String>,
    include_paths: Vec<PathBuf>,
}

#[derive(Clone)]
struct PathIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    label: &'static str,
}

impl PathIdentity {
    fn capture(path: &Path, label: &'static str) -> Result<Self> {
        let path = require_directory(path, label)?;
        let directory = Directory::open(&path)?;
        let metadata = directory.metadata()?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            label,
        })
    }

    fn revalidate(&self) -> Result<()> {
        let directory = Directory::open(&self.path)
            .map_err(|error| fail(format!("{} changed or became unsafe: {error}", self.label)))?;
        let metadata = directory.metadata()?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(fail(format!(
                "{} changed during Nouveau compilation",
                self.label
            )));
        }
        Ok(())
    }
}

struct LogFiles {
    stdout: File,
    stderr: File,
    reserved_bytes: usize,
}

struct RunningCommand {
    index: usize,
    worker: JoinHandle<RunResult>,
    logs: LogFiles,
}

struct RunResult {
    success: bool,
    failure: Option<String>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    status: Option<ExitStatus>,
    elapsed: Duration,
    report: ResourceReport,
    cleanup_error: Option<String>,
}

impl RunResult {
    fn preflight_failure(message: String) -> Self {
        Self {
            success: false,
            failure: Some(message),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            status: None,
            elapsed: Duration::ZERO,
            report: ResourceReport::default(),
            cleanup_error: None,
        }
    }
}

#[derive(Default)]
struct LogBudget {
    saved_bytes: usize,
}

/// Build the bounded 825-command plan internally, validate all mutation
/// boundaries, run direct clang invocations, and retain the plan and bounded
/// logs in `work_dir`.
pub fn compile_nouveau(
    request: NouveauCompileRequest,
    cancelled: impl FnMut() -> bool,
) -> Result<Value> {
    compile_nouveau_with_prefix(request, None, cancelled)
}

/// Execute the same authenticated recipes with an optional historical source
/// prefix for the producer's original-object reproduction. Counter outputs are
/// isolated beneath `build_root/historical-prefix-counter`; include paths and
/// every other compiler argument retain the normal recipe values.
pub fn compile_nouveau_with_prefix(
    request: NouveauCompileRequest,
    historical_prefix: Option<&str>,
    mut cancelled: impl FnMut() -> bool,
) -> Result<Value> {
    if request.jobs == 0 || request.jobs > MAX_JOBS {
        return Err(fail("Nouveau compile concurrency must be one or two jobs"));
    }
    if request.timeout.is_zero() {
        return Err(fail("Nouveau overall compile timeout must be positive"));
    }
    let deadline = Instant::now()
        .checked_add(request.timeout)
        .ok_or_else(|| fail("Nouveau overall compile timeout cannot be represented"))?;
    validate_resource_policy(request.resource_limits, request.sample_limits)?;
    if !is_sha256_digest(&request.compiler_sha256) {
        return Err(fail(
            "expected compiler SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }

    let mut plan = plan_nouveau(
        &request.records,
        &request.ninja_text,
        &request.source_root,
        &request.build_root,
        &request.toolchain_root,
    )?;
    if let Some(prefix) = historical_prefix {
        historical_counter_plan(&mut plan, prefix)?;
    }
    let work_dir = require_directory(&request.work_dir, "Nouveau work directory")?;
    let source_root = plan_path(&plan, "source_root")?;
    let build_root = plan_path(&plan, "build_root")?;
    let toolchain_root = plan_path(&plan, "toolchain_root")?;
    for (left, right, label) in [
        (&work_dir, &source_root, "work/source"),
        (&work_dir, &build_root, "work/build"),
        (&work_dir, &toolchain_root, "work/toolchain"),
    ] {
        require_disjoint(left, right, label)?;
    }

    let plan_file_path = work_dir.join(PLAN_FILE);
    let update_file_path = work_dir.join(PLAN_UPDATE_FILE);
    let logs_path = work_dir.join(LOG_DIRECTORY);
    let compiler_environment_path = work_dir.join(COMPILER_ENV_DIRECTORY);
    for (path, root, label) in [
        (&plan_file_path, &source_root, "plan/source"),
        (&plan_file_path, &build_root, "plan/build"),
        (&plan_file_path, &toolchain_root, "plan/toolchain"),
        (&update_file_path, &source_root, "plan update/source"),
        (&update_file_path, &build_root, "plan update/build"),
        (&update_file_path, &toolchain_root, "plan update/toolchain"),
        (&logs_path, &source_root, "logs/source"),
        (&logs_path, &build_root, "logs/build"),
        (&logs_path, &toolchain_root, "logs/toolchain"),
        (
            &compiler_environment_path,
            &source_root,
            "compiler environment/source",
        ),
        (
            &compiler_environment_path,
            &build_root,
            "compiler environment/build",
        ),
        (
            &compiler_environment_path,
            &toolchain_root,
            "compiler environment/toolchain",
        ),
    ] {
        require_disjoint(path, root, label)?;
    }
    require_fresh_path(&plan_file_path, "fresh Nouveau compile plan")?;
    require_fresh_path(&update_file_path, "fresh Nouveau compile plan update")?;
    reject_symlink_components(&logs_path, "Nouveau log directory")?;
    require_fresh_path(&logs_path, "fresh Nouveau log directory")?;
    reject_symlink_components(
        &compiler_environment_path,
        "Nouveau compiler environment directory",
    )?;
    require_fresh_path(
        &compiler_environment_path,
        "fresh Nouveau compiler environment directory",
    )?;
    let compiler_environment = compiler_environment(&toolchain_root, &work_dir)?;
    plan["compiler_environment"] = compiler_environment_json(&compiler_environment)?;
    let work_directory = Directory::open(&work_dir)?;
    write_new_json(&work_directory, PLAN_FILE, &plan)?;

    let prepared = (|| -> Result<_> {
        let commands = parse_commands(&plan)?;
        let compiler = plan_path(&plan, "compiler")?;
        let compiler_sha256 = verify_compiler(&compiler, &request.compiler_sha256)?;
        revalidate_plan_inputs(&plan, &commands)?;
        validate_fresh_outputs(&commands, &build_root)?;
        let roots = vec![
            source_root.clone(),
            build_root.clone(),
            toolchain_root.clone(),
            work_dir.clone(),
        ];
        let identities = [
            PathIdentity::capture(&source_root, "Nouveau source root")?,
            PathIdentity::capture(&build_root, "Nouveau build root")?,
            PathIdentity::capture(&toolchain_root, "Nouveau toolchain root")?,
            PathIdentity::capture(&work_dir, "Nouveau work directory")?,
        ];

        // Recheck the authenticated inputs and all fresh outputs immediately
        // before creating object parents.
        revalidate_plan_inputs(&plan, &commands)?;
        validate_fresh_outputs(&commands, &build_root)?;
        create_output_parents(&commands, &build_root)?;
        validate_fresh_outputs(&commands, &build_root)?;

        let environment_directory =
            work_directory.mkdir_new(OsStr::new(COMPILER_ENV_DIRECTORY), 0o700)?;
        environment_directory.mkdir_new(OsStr::new(COMPILER_HOME_DIRECTORY), 0o700)?;
        environment_directory.mkdir_new(OsStr::new(COMPILER_TEMP_DIRECTORY), 0o700)?;
        let logs_directory = work_directory.mkdir_new(OsStr::new(LOG_DIRECTORY), 0o700)?;
        revalidate_plan_inputs(&plan, &commands)?;
        ensure_directory_matches(&work_dir, &work_directory, "Nouveau work directory")?;
        for identity in &identities {
            identity.revalidate()?;
        }
        Ok((
            commands,
            compiler,
            compiler_sha256,
            roots,
            identities,
            logs_directory,
        ))
    })();

    let (commands, compiler, compiler_sha256, roots, identities, logs_directory) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            persist_failure(
                &mut plan,
                &work_dir,
                &work_directory,
                "FAIL_VALIDATION_OR_RUNNER",
                &error.to_string(),
            )?;
            return Err(Refusal::new(format!(
                "Nouveau compiler validation failed; plan retained at {}: {error}",
                plan_file_path.display()
            )));
        }
    };

    if cancelled() {
        let summary = empty_summary(&logs_path, Some("Nouveau compilation cancelled"));
        plan["compile"] = summary;
        plan["status"] = json!("FAIL_COMPILE");
        persist_plan(&mut plan, &work_dir, &work_directory)?;
        return Err(Refusal::new(format!(
            "Nouveau compilation cancelled; plan retained at {}",
            plan_file_path.display()
        ))
        .with_exit_code(143));
    }

    let abort = Arc::new(AtomicBool::new(false));
    let warning_bytes = Arc::new(AtomicU64::new(0));
    let run_result = run_commands(
        &commands,
        RunConfig {
            compiler: &compiler,
            working_directory: &build_root,
            work_dir: &work_dir,
            logs_directory: &logs_directory,
            roots: &roots,
            identities: &identities,
            jobs: request.jobs,
            deadline,
            resource_limits: request.resource_limits,
            sample_limits: request.sample_limits,
            abort: Arc::clone(&abort),
            warning_bytes: Arc::clone(&warning_bytes),
            environment: &compiler_environment,
        },
        &mut cancelled,
    );

    let mut summary = match run_result {
        Ok(summary) => summary,
        Err(error) => {
            persist_failure(
                &mut plan,
                &work_dir,
                &work_directory,
                "FAIL_VALIDATION_OR_RUNNER",
                &error.to_string(),
            )?;
            return Err(Refusal::new(format!(
                "Nouveau compiler runner failed; partial plan retained at {}: {error}",
                plan_file_path.display()
            )));
        }
    };
    summary["compiler_sha256_before"] = json!(compiler_sha256);
    summary["compiler_sha256_after"] = match verify_compiler(&compiler, &request.compiler_sha256) {
        Ok(value) => json!(value),
        Err(error) => {
            summary["failure"] = json!(error.to_string());
            summary["failed_index"] = Value::Null;
            plan["compile"] = summary;
            plan["status"] = json!("FAIL_VALIDATION_OR_RUNNER");
            persist_plan(&mut plan, &work_dir, &work_directory)?;
            return Err(Refusal::new(format!(
                "pinned clang-11 changed during Nouveau compilation; plan retained at {}: {error}",
                plan_file_path.display()
            )));
        }
    };
    summary["warning_bytes_captured"] = json!(warning_bytes.load(Ordering::Acquire));

    if let Some(failure) = summary["failure"].as_str().map(str::to_owned) {
        let cancelled = summary["cancelled"].as_bool().unwrap_or(false);
        plan["status"] = json!("FAIL_COMPILE");
        plan["compile"] = summary;
        persist_plan(&mut plan, &work_dir, &work_directory)?;
        let exit_code = if cancelled { 143 } else { 1 };
        return Err(Refusal::new(format!(
            "Nouveau compilation failed: {failure}; plan and bounded logs retained at {}",
            plan_file_path.display()
        ))
        .with_exit_code(exit_code));
    }

    plan["status"] = json!("NOUVEAU_825_COMPILE_COMMANDS_COMPLETE");
    plan["compile"] = summary;
    persist_plan(&mut plan, &work_dir, &work_directory)?;
    Ok(plan)
}

fn historical_counter_plan(plan: &mut Value, prefix: &str) -> Result<()> {
    if !Path::new(prefix).is_absolute() || prefix.chars().any(char::is_control) {
        return Err(fail(
            "historical prefix must be an absolute path without control characters",
        ));
    }
    let source = plan_path(plan, "source_root")?;
    let build = plan_path(plan, "build_root")?;
    let original_flag = format!("-ffile-prefix-map={}=.", source.display());
    let counter_flag = format!("-ffile-prefix-map={}={prefix}", source.display());
    let commands = plan
        .get_mut("commands")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| fail("internal Nouveau plan has no commands"))?;
    let mut objects = Vec::with_capacity(commands.len());
    for (index, command) in commands.iter_mut().enumerate() {
        let old_output = value_path(command, "object")?;
        let output = build
            .join("historical-prefix-counter")
            .join(format!("{index}.obj"));
        let output = output
            .to_str()
            .ok_or_else(|| fail("counter output must be UTF-8"))?;
        let args = command
            .get_mut("argv")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| fail("internal Nouveau command has no argv"))?;
        let flags: Vec<_> = args
            .iter()
            .enumerate()
            .filter_map(|(i, value)| (value.as_str() == Some(&original_flag)).then_some(i))
            .collect();
        let outputs: Vec<_> = args
            .iter()
            .enumerate()
            .filter_map(|(i, value)| (value.as_str() == Some("-o")).then_some(i))
            .collect();
        if flags.len() != 1
            || outputs.len() != 1
            || args.get(outputs[0] + 1).and_then(Value::as_str) != old_output.to_str()
        {
            return Err(fail(
                "historical prefix counter requires one exact mapping and output argument",
            ));
        }
        args[flags[0]] = json!(counter_flag);
        args[outputs[0] + 1] = json!(output);
        command["object"] = json!(output);
        objects.push(json!(output));
    }
    plan["ordered_object_paths"] = json!(objects);
    plan["prefix_map_replacement"] = json!(prefix);
    Ok(())
}

fn compiler_environment(
    toolchain_root: &Path,
    work_dir: &Path,
) -> Result<BTreeMap<OsString, OsString>> {
    let bin = toolchain_root.join("bin");
    let home = work_dir
        .join(COMPILER_ENV_DIRECTORY)
        .join(COMPILER_HOME_DIRECTORY);
    let temporary = work_dir
        .join(COMPILER_ENV_DIRECTORY)
        .join(COMPILER_TEMP_DIRECTORY);
    let path = [
        bin,
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/sbin"),
    ]
    .iter()
    .map(|path| {
        path.to_str()
            .ok_or_else(|| fail("Nouveau compiler environment path must be UTF-8"))
    })
    .collect::<Result<Vec<_>>>()?
    .join(":");
    let home = home
        .to_str()
        .ok_or_else(|| fail("Nouveau compiler HOME path must be UTF-8"))?;
    let temporary = temporary
        .to_str()
        .ok_or_else(|| fail("Nouveau compiler TMPDIR path must be UTF-8"))?;
    Ok(BTreeMap::from([
        (OsString::from("PATH"), OsString::from(path)),
        (OsString::from("HOME"), OsString::from(home)),
        (OsString::from("TMPDIR"), OsString::from(temporary)),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
    ]))
}

fn compiler_environment_json(environment: &BTreeMap<OsString, OsString>) -> Result<Value> {
    let mut values = serde_json::Map::new();
    for (key, value) in environment {
        let key = key
            .to_str()
            .ok_or_else(|| fail("Nouveau compiler environment key must be UTF-8"))?;
        let value = value
            .to_str()
            .ok_or_else(|| fail("Nouveau compiler environment value must be UTF-8"))?;
        values.insert(key.to_owned(), json!(value));
    }
    Ok(Value::Object(values))
}

fn validate_resource_policy(
    resource_limits: ResourceLimits,
    sample_limits: SampleLimits,
) -> Result<()> {
    if resource_limits.max_visible_rss_bytes == 0
        || resource_limits.max_workspace_bytes == 0
        || resource_limits.max_log_bytes == 0
    {
        return Err(fail("Nouveau resource limits must be positive"));
    }
    if sample_limits.max_roots < 4 {
        return Err(fail(
            "Nouveau resource sampling must allow source, build, toolchain, and work roots",
        ));
    }
    if sample_limits.max_ps_bytes == 0
        || sample_limits.max_ps_rows == 0
        || sample_limits.max_history_entries == 0
        || sample_limits.scan.max_entries == 0
        || sample_limits.scan.max_work_units == 0
    {
        return Err(fail("Nouveau resource sample bounds must be positive"));
    }
    Ok(())
}

fn parse_commands(plan: &Value) -> Result<Vec<CompileCommand>> {
    if plan.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        || plan.get("status").and_then(Value::as_str) != Some("PLANNED")
        || plan.get("object_count").and_then(Value::as_u64) != Some(EXPECTED_OBJECTS as u64)
    {
        return Err(fail(
            "internal Nouveau planner returned an invalid plan header",
        ));
    }
    let values = plan
        .get("commands")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("internal Nouveau planner returned no command array"))?;
    if values.len() != EXPECTED_OBJECTS {
        return Err(fail(
            "internal Nouveau planner returned an invalid command count",
        ));
    }
    values
        .iter()
        .map(|command| {
            let source = value_path(command, "source")?;
            let object = value_path(command, "object")?;
            let argv = string_array(command, "argv")?;
            let include_paths = string_array(command, "include_paths")?
                .into_iter()
                .map(PathBuf::from)
                .collect();
            if argv.first().map(String::as_str) != plan.get("compiler").and_then(Value::as_str) {
                return Err(fail(
                    "internal Nouveau compiler argv differs from its plan pin",
                ));
            }
            Ok(CompileCommand {
                source,
                object,
                argv,
                include_paths,
            })
        })
        .collect()
}

fn value_path(value: &Value, key: &str) -> Result<PathBuf> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| fail(format!("internal Nouveau plan has no {key} path")))
}

fn string_array(value: &Value, key: &str) -> Result<Vec<String>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| fail(format!("internal Nouveau plan has no {key} array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| fail(format!("internal Nouveau plan has an invalid {key} item")))
        })
        .collect()
}

fn plan_path(plan: &Value, key: &str) -> Result<PathBuf> {
    plan.get(key)
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| fail(format!("internal Nouveau plan has no {key} path")))
}

fn verify_compiler(compiler: &Path, expected: &str) -> Result<String> {
    let file = crate::files::open_regular_nofollow(compiler).map_err(|error| {
        fail(format!(
            "pinned clang-11 compiler is not a regular file: {error}"
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        fail(format!(
            "could not inspect pinned clang-11 compiler: {error}"
        ))
    })?;
    if metadata.mode() & 0o111 == 0 {
        return Err(fail("pinned clang-11 compiler is not executable"));
    }
    drop(file);
    let observed = sha256_file(compiler)?;
    if observed != expected {
        return Err(fail("pinned clang-11 compiler byte SHA-256 differs"));
    }
    Ok(observed)
}

fn revalidate_plan_inputs(plan: &Value, commands: &[CompileCommand]) -> Result<()> {
    for (key, label) in [
        ("source_root", "Nouveau source root"),
        ("build_root", "Nouveau build root"),
        ("toolchain_root", "Nouveau toolchain root"),
    ] {
        require_directory(&plan_path(plan, key)?, label)?;
    }
    let mut include_directories = BTreeSet::new();
    for command in commands {
        include_directories.extend(command.include_paths.iter().cloned());
    }
    for include in include_directories {
        require_input_directory(&include)?;
    }
    for command in commands {
        require_source_file(&command.source)?;
    }
    Ok(())
}

fn validate_fresh_outputs(commands: &[CompileCommand], build_root: &Path) -> Result<()> {
    if commands.len() != EXPECTED_OBJECTS
        || commands
            .iter()
            .map(|command| &command.object)
            .collect::<HashSet<_>>()
            .len()
            != EXPECTED_OBJECTS
    {
        return Err(fail(
            "compile plan exceeds the 825 unique output-file bound",
        ));
    }
    for command in commands {
        under(&command.object, build_root, "Nouveau object output")?;
        reject_symlink_components(&command.object, "Nouveau object output")?;
        require_fresh_path(&command.object, "fresh Nouveau object output")?;
    }
    Ok(())
}

fn require_fresh_path(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(fail(format!("{label} cannot be inspected: {error}"))),
        Ok(_) => Err(fail(format!("{label} required: {}", path.display()))),
    }
}

fn reject_symlink_components(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(fail(format!("{label} must be absolute and normalized")));
    }
    let mut cursor = PathBuf::from("/");
    for component in path.components() {
        if let Component::Normal(name) = component {
            cursor.push(name);
            match fs::symlink_metadata(&cursor) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(fail(format!(
                        "{label} traverses a symlink: {}",
                        cursor.display()
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(fail(format!(
                        "{label} cannot be inspected at {}: {error}",
                        cursor.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn create_output_parents(commands: &[CompileCommand], build_root: &Path) -> Result<()> {
    let root = Directory::open(build_root)?;
    let mut parents = BTreeSet::new();
    for command in commands {
        let relative = command
            .object
            .strip_prefix(build_root)
            .map_err(|_| fail("Nouveau object output escaped its build root"))?;
        let parent = relative
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf);
        if let Some(parent) = parent {
            parents.insert(parent);
        }
    }
    for parent in parents {
        let mut current = root.relative_directory("")?;
        for component in parent.components() {
            let Component::Normal(name) = component else {
                return Err(fail("Nouveau output parent is not normalized"));
            };
            current = match current.child(name) {
                Ok(directory) => directory,
                Err(_) => current.mkdir_new(name, 0o755).map_err(|error| {
                    fail(format!(
                        "could not create fresh Nouveau output parent: {error}"
                    ))
                })?,
            };
            if !current.metadata()?.is_dir() {
                return Err(fail("Nouveau output parent is not a directory"));
            }
        }
    }
    Ok(())
}

fn require_disjoint(left: &Path, right: &Path, label: &str) -> Result<()> {
    if left == right || left.strip_prefix(right).is_ok() || right.strip_prefix(left).is_ok() {
        return Err(fail(format!(
            "{label} paths overlap: {} and {}",
            left.display(),
            right.display()
        )));
    }
    Ok(())
}

fn ensure_directory_matches(path: &Path, expected: &Directory, label: &str) -> Result<()> {
    let observed = Directory::open(path)
        .map_err(|error| fail(format!("{label} changed or became unsafe: {error}")))?;
    let expected_metadata = expected.metadata()?;
    let observed_metadata = observed.metadata()?;
    if expected_metadata.dev() != observed_metadata.dev()
        || expected_metadata.ino() != observed_metadata.ino()
    {
        return Err(fail(format!("{label} changed during Nouveau compilation")));
    }
    Ok(())
}

struct RunConfig<'a> {
    compiler: &'a Path,
    working_directory: &'a Path,
    work_dir: &'a Path,
    logs_directory: &'a Directory,
    roots: &'a [PathBuf],
    identities: &'a [PathIdentity; 4],
    jobs: usize,
    deadline: Instant,
    resource_limits: ResourceLimits,
    sample_limits: SampleLimits,
    abort: Arc<AtomicBool>,
    warning_bytes: Arc<AtomicU64>,
    environment: &'a BTreeMap<OsString, OsString>,
}

fn run_commands(
    commands: &[CompileCommand],
    config: RunConfig<'_>,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Value> {
    let RunConfig {
        compiler,
        working_directory,
        work_dir,
        logs_directory,
        roots,
        identities,
        jobs,
        deadline,
        resource_limits,
        sample_limits,
        abort,
        warning_bytes,
        environment,
    } = config;
    let mut active = BTreeMap::<usize, RunningCommand>::new();
    let mut next_index = 0usize;
    let mut started = 0usize;
    let mut completed = 0usize;
    let mut log_budget = LogBudget::default();
    let mut command_reports = Vec::new();
    let mut failure: Option<(Option<usize>, String, bool)> = None;
    let mut runner_error: Option<String> = None;

    loop {
        if failure.is_none() {
            if cancelled() {
                failure = Some((
                    active.keys().next().copied().or(Some(next_index)),
                    "Nouveau compilation cancelled".to_owned(),
                    true,
                ));
            } else if (next_index < commands.len() || !active.is_empty())
                && Instant::now() >= deadline
            {
                failure = Some((
                    active.keys().next().copied().or(Some(next_index)),
                    "Nouveau overall compilation deadline expired".to_owned(),
                    false,
                ));
            }
            if failure.is_some() {
                abort.store(true, Ordering::Release);
            }
        }

        while failure.is_none() && next_index < commands.len() && active.len() < jobs {
            if cancelled() {
                failure = Some((
                    Some(next_index),
                    "Nouveau compilation cancelled".to_owned(),
                    true,
                ));
                abort.store(true, Ordering::Release);
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                failure = Some((
                    Some(next_index),
                    "Nouveau overall compilation deadline expired".to_owned(),
                    false,
                ));
                abort.store(true, Ordering::Release);
                break;
            }
            let index = next_index;
            if let Err(error) = identities.iter().try_for_each(PathIdentity::revalidate) {
                failure = Some((Some(index), error.to_string(), false));
                abort.store(true, Ordering::Release);
                break;
            }
            let mut logs = match create_log_files(logs_directory, index) {
                Ok(logs) => logs,
                Err(error) => {
                    failure = Some((Some(index), error.to_string(), false));
                    abort.store(true, Ordering::Release);
                    break;
                }
            };
            let command = commands[index].clone();
            let root_identities = identities.clone();
            let compiler = compiler.to_path_buf();
            let working_directory = working_directory.to_path_buf();
            let roots = roots.to_vec();
            let abort_for_worker = Arc::clone(&abort);
            let warning_bytes_for_worker = Arc::clone(&warning_bytes);
            let environment = environment.clone();
            let worker = thread::Builder::new()
                .name(format!("nouveau-compile-{index:04}"))
                .spawn(move || {
                    execute_one(
                        index,
                        command,
                        compiler,
                        working_directory,
                        roots,
                        root_identities,
                        remaining,
                        resource_limits,
                        sample_limits,
                        abort_for_worker,
                        warning_bytes_for_worker,
                        environment,
                    )
                });
            match worker {
                Ok(worker) => {
                    active.insert(
                        index,
                        RunningCommand {
                            index,
                            worker,
                            logs,
                        },
                    );
                    started += 1;
                    next_index += 1;
                }
                Err(error) => {
                    let message =
                        format!("could not start Nouveau compiler supervisor thread: {error}");
                    let result = RunResult::preflight_failure(message.clone());
                    if let Err(save_error) = save_failure_logs(&mut log_budget, &mut logs, &result)
                    {
                        runner_error = Some(save_error.to_string());
                    }
                    failure = Some((Some(index), message, false));
                    abort.store(true, Ordering::Release);
                    next_index += 1;
                    break;
                }
            }
        }

        let finished: Vec<usize> = active
            .iter()
            .filter_map(|(index, running)| running.worker.is_finished().then_some(*index))
            .collect();
        if finished.is_empty() {
            if active.is_empty() {
                break;
            }
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        for index in finished {
            let mut running = active
                .remove(&index)
                .expect("finished compiler remains active");
            debug_assert_eq!(index, running.index);
            let result = match running.worker.join() {
                Ok(result) => result,
                Err(_) => RunResult::preflight_failure(
                    "Nouveau compiler worker panicked after supervised cleanup".to_owned(),
                ),
            };
            let result_success = result.success;
            let result_failure = result.failure.clone();
            command_reports.push(command_report(index, &result));

            if failure.is_some() {
                if let Err(error) = save_failure_logs(&mut log_budget, &mut running.logs, &result) {
                    runner_error.get_or_insert_with(|| error.to_string());
                }
                continue;
            }
            if result_success {
                completed += 1;
                if let Err(error) = save_logs(&mut log_budget, &mut running.logs, &result, false) {
                    failure = Some((Some(index), error.to_string(), false));
                    abort.store(true, Ordering::Release);
                    if let Err(save_error) =
                        save_failure_logs(&mut log_budget, &mut running.logs, &result)
                    {
                        runner_error.get_or_insert_with(|| save_error.to_string());
                    }
                    continue;
                }
            } else {
                let message =
                    result_failure.unwrap_or_else(|| "Nouveau compiler command failed".to_owned());
                let is_cancelled = message == "Nouveau compiler command was cancelled";
                if let Err(error) = save_failure_logs(&mut log_budget, &mut running.logs, &result) {
                    runner_error.get_or_insert_with(|| error.to_string());
                }
                failure = Some((Some(index), message, is_cancelled));
                abort.store(true, Ordering::Release);
            }
        }
    }

    if let Some(error) = runner_error {
        return Err(fail(format!(
            "Nouveau compiler logs could not be retained safely: {error}"
        )));
    }

    command_reports.sort_by_key(|report| report["index"].as_u64().unwrap_or(u64::MAX));
    let failed_index = failure
        .as_ref()
        .and_then(|(index, _, _)| *index)
        .map(|index| json!(index));
    let failure_message = failure.as_ref().map(|(_, message, _)| message.clone());
    let cancelled = failure.as_ref().is_some_and(|(_, _, cancelled)| *cancelled);
    Ok(json!({
        "worker_threads_started": started,
        "worker_threads_started_semantics": "A supervisor thread was scheduled; this does not guarantee the OS process spawn succeeded.",
        "completed": completed,
        "failed_index": failed_index,
        "failure": failure_message,
        "cancelled": cancelled,
        "logs_directory": work_dir.join(LOG_DIRECTORY).display().to_string(),
        "warning_bytes_captured": warning_bytes.load(Ordering::Acquire),
        "aggregate_saved_log_bytes": log_budget.saved_bytes,
        "aggregate_saved_log_limit": MAX_AGGREGATE_SAVED_LOG_BYTES,
        "regular_saved_log_limit": MAX_REGULAR_SAVED_LOG_BYTES,
        "per_stream_capture_limit": MAX_LOG_BYTES_PER_STREAM,
        "total_warning_byte_limit": MAX_TOTAL_WARNING_BYTES,
        "resource_scope": "per compiler process tree; excludes supervising process; outer release driver owns aggregate RSS supervision",
        "compiler_runs": command_reports,
    }))
}

fn create_log_files(directory: &Directory, index: usize) -> Result<LogFiles> {
    let stem = format!("{index:04}");
    let stdout = directory.create_new_file(OsStr::new(&(stem.clone() + ".stdout.log")), 0o600)?;
    let stderr = directory.create_new_file(OsStr::new(&(stem + ".stderr.log")), 0o600)?;
    Ok(LogFiles {
        stdout,
        stderr,
        reserved_bytes: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_one(
    index: usize,
    command: CompileCommand,
    compiler: PathBuf,
    working_directory: PathBuf,
    roots: Vec<PathBuf>,
    identities: [PathIdentity; 4],
    timeout: Duration,
    resource_limits: ResourceLimits,
    sample_limits: SampleLimits,
    abort: Arc<AtomicBool>,
    warning_bytes: Arc<AtomicU64>,
    environment: BTreeMap<OsString, OsString>,
) -> RunResult {
    if let Err(error) = identities
        .iter()
        .try_for_each(PathIdentity::revalidate)
        .and_then(|()| revalidate_command(&command, &roots))
    {
        return RunResult::preflight_failure(format!(
            "Nouveau command {index} inputs changed before execution: {error}"
        ));
    }
    if abort.load(Ordering::Acquire) {
        return RunResult::preflight_failure("Nouveau compiler command was cancelled".to_owned());
    }
    let argv = command
        .argv
        .iter()
        .skip(1)
        .map(OsString::from)
        .collect::<Vec<_>>();
    // Keep the compiler path tied to the verified plan value.
    let spec = CommandSpec::new(
        compiler.as_os_str().to_os_string(),
        argv,
        working_directory,
        environment,
    );
    let mut previous_stdout = 0usize;
    let mut previous_stderr = 0usize;
    let captured = capture_with_resources_observed(
        &spec,
        CaptureLimits {
            timeout,
            stdout_bytes: MAX_LOG_BYTES_PER_STREAM,
            stderr_bytes: MAX_LOG_BYTES_PER_STREAM,
            termination_grace: PROCESS_GRACE,
        },
        resource_limits,
        sample_limits,
        &roots,
        || abort.load(Ordering::Acquire),
        |event| {
            let stdout_delta =
                event
                    .stdout_bytes
                    .checked_sub(previous_stdout)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "compiler stdout observation decreased",
                        )
                    })?;
            let stderr_delta =
                event
                    .stderr_bytes
                    .checked_sub(previous_stderr)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "compiler stderr observation decreased",
                        )
                    })?;
            previous_stdout = event.stdout_bytes;
            previous_stderr = event.stderr_bytes;
            reserve_warning_bytes(&warning_bytes, stdout_delta.saturating_add(stderr_delta))
        },
    );
    match captured {
        Ok(captured) => completed_result(command, index, captured),
        Err(ResourceCaptureError::Setup { error, report }) => RunResult {
            success: false,
            failure: Some(format!("Nouveau compiler monitor setup failed: {error}")),
            stdout: Vec::new(),
            stderr: format!("compiler monitor setup failed: {error}\n")
                .into_bytes()
                .into_iter()
                .take(MAX_LOG_BYTES_PER_STREAM)
                .collect(),
            stdout_truncated: false,
            stderr_truncated: false,
            status: None,
            elapsed: Duration::ZERO,
            report: *report,
            cleanup_error: None,
        },
        Err(ResourceCaptureError::Capture { error, report }) => {
            failed_capture_result(index, error, *report)
        }
    }
}

fn reserve_warning_bytes(total: &AtomicU64, amount: usize) -> io::Result<()> {
    let amount = u64::try_from(amount)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "warning byte count overflow"))?;
    total
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(amount)
                .filter(|next| *next <= MAX_TOTAL_WARNING_BYTES)
        })
        .map(|_| ())
        .map_err(|_| io::Error::other("total compiler warning-byte capture limit exceeded"))
}

fn completed_result(
    command: CompileCommand,
    index: usize,
    captured: crate::resource_capture::ResourceCapturedProcess,
) -> RunResult {
    let process = captured.process;
    let mut result = RunResult {
        success: process.status.success(),
        failure: (!process.status.success()).then(|| {
            format!(
                "compiler exited with status {}",
                process
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| format!(
                        "signal {}",
                        process.status.signal().unwrap_or_default()
                    ))
            )
        }),
        stdout: process.stdout,
        stderr: process.stderr,
        stdout_truncated: false,
        stderr_truncated: false,
        status: Some(process.status),
        elapsed: process.elapsed,
        report: captured.report,
        cleanup_error: None,
    };
    if result.success
        && let Err(error) = require_compiler_output(&command.object)
    {
        result.success = false;
        result.failure = Some(format!(
            "compiler returned success without a regular object at command {index}: {error}"
        ));
    }
    result
}

fn failed_capture_result(index: usize, error: CaptureError, report: ResourceReport) -> RunResult {
    let stdout_truncated = matches!(&error.cause, CaptureCause::StdoutLimitExceeded);
    let stderr_truncated = matches!(&error.cause, CaptureCause::StderrLimitExceeded);
    let detail = error.to_string();
    let cause = match &error.cause {
        CaptureCause::Cancelled => "Nouveau compiler command was cancelled".to_owned(),
        CaptureCause::Timeout => format!("Nouveau compiler command {index} timed out"),
        CaptureCause::StdoutLimitExceeded | CaptureCause::StderrLimitExceeded => {
            "compiler output exceeded the per-stream capture limit".to_owned()
        }
        CaptureCause::Observation(_) if detail.contains("warning-byte capture limit") => {
            "total compiler warning-byte capture limit exceeded".to_owned()
        }
        _ => format!("Nouveau compiler command {index} failed: {detail}"),
    };
    RunResult {
        success: false,
        failure: Some(cause),
        stdout: error.stdout,
        stderr: error.stderr,
        stdout_truncated,
        stderr_truncated,
        status: error.status,
        elapsed: error.elapsed,
        report,
        cleanup_error: error.cleanup_error.map(|error| error.to_string()),
    }
}

fn revalidate_command(command: &CompileCommand, roots: &[PathBuf]) -> Result<()> {
    for (root, label) in roots.iter().zip([
        "Nouveau source root",
        "Nouveau build root",
        "Nouveau toolchain root",
        "Nouveau work directory",
    ]) {
        require_directory(root, label)?;
    }
    require_source_file(&command.source)?;
    for include in &command.include_paths {
        require_input_directory(include)?;
    }
    reject_symlink_components(&command.object, "Nouveau object output")?;
    require_fresh_path(&command.object, "fresh Nouveau object output")?;
    Ok(())
}

fn require_compiler_output(path: &Path) -> Result<()> {
    let _metadata = metadata_without_symlink_components(path, "Nouveau compiler output")
        .map_err(|error| fail(format!("compiler output is missing or unsafe: {error}")))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| fail(format!("compiler output cannot be inspected: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(fail(format!(
            "compiler output is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn command_report(index: usize, result: &RunResult) -> Value {
    json!({
        "index": index,
        "exit_code": result.status.as_ref().and_then(ExitStatus::code),
        "signal": result.status.as_ref().and_then(|status| status.signal()),
        "elapsed_ms": result.elapsed.as_millis(),
        "success": result.success,
        "failure": result.failure,
        "cleanup_error": result.cleanup_error,
        "stdout_bytes_saved": result.stdout.len(),
        "stderr_bytes_saved": result.stderr.len(),
        "peak_visible_rss_bytes": result.report.peak_visible_rss_bytes,
        "peak_workspace_bytes": result.report.peak_workspace_bytes,
        "peak_observed_log_bytes": result.report.peak_log_bytes,
        "resource_samples": result.report.sample_count,
        "last_resource_sample_complete": result.report.last_sample_complete,
        "incomplete_process_cleanup": result.report.incomplete_cleanup,
    })
}

fn save_logs(
    budget: &mut LogBudget,
    logs: &mut LogFiles,
    result: &RunResult,
    failed: bool,
) -> Result<()> {
    let stdout = saved_stream(&result.stdout, result.stdout_truncated, failed);
    let stderr = saved_stream(&result.stderr, result.stderr_truncated, failed);
    let pair_size = stdout
        .len()
        .checked_add(stderr.len())
        .ok_or_else(|| fail("aggregate saved-log byte sum overflows"))?;
    let limit = if failed {
        MAX_AGGREGATE_SAVED_LOG_BYTES
    } else {
        MAX_REGULAR_SAVED_LOG_BYTES
    };
    reset_logs(budget, logs)?;
    let next = budget
        .saved_bytes
        .checked_add(pair_size)
        .ok_or_else(|| fail("aggregate saved-log byte sum overflows"))?;
    if next > limit {
        return Err(fail(if failed {
            "hard aggregate saved-log limit exceeded"
        } else {
            "aggregate saved-log limit exceeded"
        }));
    }

    // Charge the full prospective pair before writing. A short write therefore
    // cannot leave unaccounted bytes in the bounded log directory, and a
    // failure-log retry can replace (rather than append to) this reservation.
    budget.saved_bytes = next;
    logs.reserved_bytes = pair_size;
    logs.stdout.write_all(&stdout).map_err(|error| {
        fail(format!(
            "could not write bounded compiler stdout log: {error}"
        ))
    })?;
    logs.stderr.write_all(&stderr).map_err(|error| {
        fail(format!(
            "could not write bounded compiler stderr log: {error}"
        ))
    })?;
    logs.stdout
        .sync_all()
        .map_err(|error| fail(format!("could not sync compiler stdout log: {error}")))?;
    logs.stderr
        .sync_all()
        .map_err(|error| fail(format!("could not sync compiler stderr log: {error}")))?;
    Ok(())
}

fn reset_logs(budget: &mut LogBudget, logs: &mut LogFiles) -> Result<()> {
    for (label, file) in [("stdout", &mut logs.stdout), ("stderr", &mut logs.stderr)] {
        file.set_len(0)
            .map_err(|error| fail(format!("could not reset compiler {label} log: {error}")))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| fail(format!("could not rewind compiler {label} log: {error}")))?;
    }
    budget.saved_bytes = budget
        .saved_bytes
        .checked_sub(logs.reserved_bytes)
        .ok_or_else(|| fail("aggregate saved-log reservation accounting underflow"))?;
    logs.reserved_bytes = 0;
    Ok(())
}

fn save_failure_logs(
    budget: &mut LogBudget,
    logs: &mut LogFiles,
    result: &RunResult,
) -> Result<()> {
    match save_logs(budget, logs, result, true) {
        Err(error) if error.to_string().contains("saved-log limit exceeded") => {
            // The empty, freshly created log files remain as evidence that the
            // command was attempted when the failure reserve is exhausted.
            Ok(())
        }
        other => other,
    }
}

fn saved_stream(bytes: &[u8], truncated: bool, failed: bool) -> Vec<u8> {
    if !truncated {
        return bytes.to_vec();
    }
    if !failed {
        return Vec::new();
    }
    let prefix_len = bytes
        .len()
        .min(MAX_LOG_BYTES_PER_STREAM - TRUNCATION_MARKER.len());
    let mut saved = bytes[..prefix_len].to_vec();
    saved.extend_from_slice(TRUNCATION_MARKER);
    saved
}

fn empty_summary(logs_path: &Path, failure: Option<&str>) -> Value {
    json!({
        "worker_threads_started": 0,
        "worker_threads_started_semantics": "A supervisor thread was scheduled; this does not guarantee the OS process spawn succeeded.",
        "completed": 0,
        "failed_index": Value::Null,
        "failure": failure,
        "cancelled": failure.is_some(),
        "logs_directory": logs_path.display().to_string(),
        "warning_bytes_captured": 0,
        "aggregate_saved_log_bytes": 0,
        "aggregate_saved_log_limit": MAX_AGGREGATE_SAVED_LOG_BYTES,
        "regular_saved_log_limit": MAX_REGULAR_SAVED_LOG_BYTES,
        "per_stream_capture_limit": MAX_LOG_BYTES_PER_STREAM,
        "total_warning_byte_limit": MAX_TOTAL_WARNING_BYTES,
        "resource_scope": "per compiler process tree; excludes supervising process; outer release driver owns aggregate RSS supervision",
        "compiler_runs": [],
    })
}

fn persist_failure(
    plan: &mut Value,
    work_dir: &Path,
    work_directory: &Directory,
    status: &str,
    message: &str,
) -> Result<()> {
    plan["status"] = json!(status);
    plan["error"] = json!(message);
    persist_plan(plan, work_dir, work_directory)
}

fn persist_plan(plan: &mut Value, work_dir: &Path, work_directory: &Directory) -> Result<()> {
    ensure_directory_matches(work_dir, work_directory, "Nouveau work directory")?;
    let temporary_name = PLAN_UPDATE_FILE;
    let mut temporary = work_directory.create_new_file(OsStr::new(temporary_name), 0o600)?;
    write_json(&mut temporary, plan)?;
    temporary.sync_all().map_err(|error| {
        fail(format!(
            "could not sync updated Nouveau compile plan: {error}"
        ))
    })?;
    let temporary_path = work_dir.join(temporary_name);
    let plan_path = work_dir.join(PLAN_FILE);
    ensure_directory_matches(work_dir, work_directory, "Nouveau work directory")?;
    fs::rename(&temporary_path, &plan_path).map_err(|error| {
        fail(format!(
            "could not publish updated Nouveau compile plan: {error}"
        ))
    })?;
    File::open(work_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| fail(format!("could not sync Nouveau work directory: {error}")))?;
    Ok(())
}

fn write_new_json(directory: &Directory, name: &str, value: &Value) -> Result<()> {
    let mut file = directory.create_new_file(OsStr::new(name), 0o600)?;
    write_json(&mut file, value)?;
    file.sync_all()
        .map_err(|error| fail(format!("could not sync Nouveau compile plan: {error}")))
}

fn write_json(file: &mut File, value: &Value) -> Result<()> {
    serde_json::to_writer_pretty(&mut *file, value)
        .map_err(|error| fail(format!("could not serialize Nouveau compile plan: {error}")))?;
    file.write_all(b"\n")
        .map_err(|error| fail(format!("could not write Nouveau compile plan: {error}")))
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

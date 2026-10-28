//! Internal host component probe for the experimental Cargo storage split.
//!
//! This is a maintainer fixture, not a consumer command or a sandbox. It uses
//! only local synthetic inputs and trusted, preselected host tools.

use ami_rust_core::{
    Refusal, Result,
    digest::{self, sha256_file},
    process_capture::{self, CaptureLimits, CommandSpec},
    signals::SigtermGuard,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Component, Path, PathBuf},
    process::ExitStatus,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[path = "cargo_storage_concurrent_gc.rs"]
mod concurrent_gc;
#[path = "cargo_storage_git_helper.rs"]
mod git_helper;
#[path = "cargo_storage_lifecycle.rs"]
mod lifecycle;
#[path = "cargo_storage_nested.rs"]
mod nested;
#[path = "cargo_storage_registry.rs"]
mod registry;
#[path = "cargo_storage_registry_fixture.rs"]
mod registry_fixture;

const TIMEOUT: Duration = Duration::from_secs(1_200);
const STREAM_LIMIT: usize = 8 * 1024 * 1024;
const TERMINATION_GRACE: Duration = Duration::from_secs(2);
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug)]
struct Arguments {
    control: PathBuf,
    derived: PathBuf,
    rustc: PathBuf,
    rustdoc: PathBuf,
    work: PathBuf,
    output: PathBuf,
}

#[derive(Debug)]
struct Tool {
    name: &'static str,
    path: PathBuf,
    sha256: String,
}

struct Probe<'a> {
    guard: &'a SigtermGuard,
    work: PathBuf,
    output: PathBuf,
    logs: PathBuf,
    tools: Vec<Tool>,
    commands: Vec<Value>,
    base_env: BTreeMap<OsString, OsString>,
}

pub(super) fn run(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    execute(arguments, 0)
}

pub(super) fn run_lifecycle(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    execute(arguments, 1)
}

pub(super) fn run_registry(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    execute(arguments, 2)
}

pub(super) fn run_nested(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    execute(arguments, 3)
}

pub(super) fn run_concurrent_gc(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    execute(arguments, 4)
}

pub(super) fn run_git_helper(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    execute(arguments, 5)
}

pub(super) fn git_credential_helper(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    git_helper::helper(arguments)
}

pub(super) fn credential_provider(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    registry::provider(arguments)
}

fn execute(arguments: impl Iterator<Item = OsString>, extended: u8) -> Result<()> {
    let arguments = parse_arguments(arguments)?;
    let output = prepare_fresh_directory(&arguments.output, "output")?;
    let logs = output.join("logs");
    create_private_directory(&logs)?;
    let mut report = initial_report(&arguments);

    let prepared = (|| {
        let work = prepare_fresh_directory(&arguments.work, "work")?;
        if paths_overlap(&work, &output) {
            return Err(Refusal::new(
                "Cargo storage probe work and output directories overlap",
            ));
        }
        let tools = prepare_tools(&arguments)?;
        if tools
            .iter()
            .any(|tool| paths_overlap(&tool.path, &work) || paths_overlap(&tool.path, &output))
        {
            return Err(Refusal::new(
                "Cargo storage probe tools must be outside fresh work and output directories",
            ));
        }
        Ok((work, tools))
    })();

    let (work, tools) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            set_failure(&mut report, &error);
            write_report(&output, &report)?;
            return Err(error);
        }
    };

    report["tools"] = tool_metadata(&tools);
    report["driver_source_sha256"] = json!(digest::sha256_bytes(include_bytes!(
        "cargo_storage_probe.rs"
    )));

    let guard = match SigtermGuard::acquire() {
        Ok(guard) => guard,
        Err(error) => {
            set_failure(&mut report, &error);
            write_report(&output, &report)?;
            return Err(error);
        }
    };

    let mut probe = Probe {
        guard: &guard,
        work,
        output: output.clone(),
        logs,
        tools,
        commands: Vec::new(),
        base_env: BTreeMap::new(),
    };
    let execution = if extended == 5 {
        report["fixture_kind"] = json!("storage-git-credential-helper");
        report["additional_driver_sha256"] = json!(digest::sha256_bytes(include_bytes!(
            "cargo_storage_git_helper.rs"
        )));
        git_helper::run(&mut probe, &mut report)
    } else if extended == 4 {
        report["fixture_kind"] = json!("storage-selected-concurrency-and-semantic-gc");
        report["additional_driver_sha256"] = json!({"concurrent_gc":digest::sha256_bytes(include_bytes!("cargo_storage_concurrent_gc.rs")), "fixture":digest::sha256_bytes(include_bytes!("cargo_storage_registry_fixture.rs"))});
        concurrent_gc::run(&mut probe, &mut report)
    } else if extended == 3 {
        report["fixture_kind"] = json!("storage-nested-relative-home");
        report["additional_driver_sha256"] = json!({"nested":digest::sha256_bytes(include_bytes!("cargo_storage_nested.rs")), "fixture":digest::sha256_bytes(include_bytes!("cargo_storage_registry_fixture.rs"))});
        nested::run(&mut probe, &mut report)
    } else if extended == 2 {
        report["fixture_kind"] = json!("storage-registry-credentials");
        report["additional_driver_sha256"] = json!({"registry":digest::sha256_bytes(include_bytes!("cargo_storage_registry.rs")), "fixture":digest::sha256_bytes(include_bytes!("cargo_storage_registry_fixture.rs"))});
        registry::run(&mut probe, &mut report)
    } else if extended == 1 {
        report["fixture_kind"] = json!("storage-analysis-build-directory");
        report["additional_driver_sha256"] = json!(digest::sha256_bytes(include_bytes!(
            "cargo_storage_lifecycle.rs"
        )));
        lifecycle::run(&mut probe, &mut report)
    } else {
        run_component(&mut probe, &mut report)
    };
    report["commands"] = json!(&probe.commands);
    report["command_count"] = json!(probe.commands.len());
    let check_count = report["checks"].as_array().map_or(0, |checks| checks.len());
    report["check_count"] = json!(check_count);

    let final_error = match execution {
        Ok(()) => match guard.check() {
            Ok(()) => {
                report["status"] = json!("PASS_HOST_CARGO_STORAGE_FIXTURES_ONLY");
                None
            }
            Err(error) => {
                set_failure(&mut report, &error);
                Some(error)
            }
        },
        Err(error) => {
            set_failure(&mut report, &error);
            Some(error)
        }
    };
    report["finished_unix_millis"] = json!(unix_millis());

    // Write before restoring the handler; finish_requested catches SIGTERM
    // received during serialization and lets us replace a provisional PASS.
    write_report(&output, &report)?;
    match guard.finish_requested() {
        Ok(true) => {
            let error = Refusal::new("SIGTERM requested during Cargo storage probe");
            set_failure(&mut report, &error);
            report["sigterm_requested"] = json!(true);
            report["finished_unix_millis"] = json!(unix_millis());
            write_report(&output, &report)?;
            return Err(error);
        }
        Ok(false) => {}
        Err(error) => {
            set_failure(&mut report, &error);
            report["finished_unix_millis"] = json!(unix_millis());
            write_report(&output, &report)?;
            return Err(error);
        }
    }

    if let Some(error) = final_error {
        return Err(error);
    }
    Ok(())
}

fn parse_arguments(arguments: impl Iterator<Item = OsString>) -> Result<Arguments> {
    let mut values = BTreeMap::<String, OsString>::new();
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        let flag = argument
            .to_str()
            .ok_or_else(|| Refusal::new("Cargo storage probe option is not UTF-8"))?;
        let name = match flag {
            "--control" => "control",
            "--derived" => "derived",
            "--rustc" => "rustc",
            "--rustdoc" => "rustdoc",
            "--work" => "work",
            "--output" => "output",
            _ => {
                return Err(Refusal::new(format!(
                    "unknown Cargo storage probe option {flag:?}"
                )));
            }
        };
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new(format!("missing value for {flag}")))?;
        if values.insert(name.to_owned(), value).is_some() {
            return Err(Refusal::new(format!(
                "Cargo storage probe option {flag} appears more than once"
            )));
        }
    }
    for required in ["control", "derived", "rustc", "rustdoc", "work", "output"] {
        if !values.contains_key(required) {
            return Err(Refusal::new(format!(
                "missing required Cargo storage probe option --{required}"
            )));
        }
    }
    let take_path = |name: &str| {
        values.get(name).cloned().map(PathBuf::from).ok_or_else(|| {
            Refusal::new(format!(
                "missing required Cargo storage probe option --{name}"
            ))
        })
    };
    Ok(Arguments {
        control: take_path("control")?,
        derived: take_path("derived")?,
        rustc: take_path("rustc")?,
        rustdoc: take_path("rustdoc")?,
        work: take_path("work")?,
        output: take_path("output")?,
    })
}

fn initial_report(arguments: &Arguments) -> Value {
    json!({
        "schema": "ami-rust-cargo-storage-runtime-rust-v1",
        "status": "RUNNING",
        "rc2_accepted": false,
        "scope": "Internal host-only synthetic Cargo storage component comparison; not consumer SDK activation, full RC2 acceptance, AROS, provider authentication, publication, or containment.",
        "limitations": [
            "Uses only local synthetic Cargo and Git inputs; it does not contact registries or providers.",
            "Does not exercise nested or concurrent Cargo, installer activation, final AROS linking, or runtime qualification.",
            "Process capture bounds each child and its output pipes; aggregate memory, wall time, workspace, and log enforcement belongs to the parent coordinator."
        ],
        "requested_paths": {
            "control": os_metadata(arguments.control.as_os_str()),
            "derived": os_metadata(arguments.derived.as_os_str()),
            "rustc": os_metadata(arguments.rustc.as_os_str()),
            "rustdoc": os_metadata(arguments.rustdoc.as_os_str()),
            "work": os_metadata(arguments.work.as_os_str()),
            "output": os_metadata(arguments.output.as_os_str())
        },
        "started_unix_millis": unix_millis(),
        "commands": [],
        "checks": [],
        "fixtures": {}
    })
}

fn prepare_fresh_directory(path: &Path, name: &str) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(Refusal::new(format!(
            "Cargo storage probe {name} directory must be an absolute normalized path"
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        Refusal::new(format!(
            "Cargo storage probe {name} directory has no parent"
        ))
    })?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        Refusal::new(format!(
            "cannot resolve Cargo storage probe {name} parent {}: {error}",
            parent.display()
        ))
    })?;
    let file_name = path
        .file_name()
        .ok_or_else(|| Refusal::new(format!("Cargo storage probe {name} directory has no leaf")))?;
    if canonical_parent.join(file_name) != path {
        return Err(Refusal::new(format!(
            "Cargo storage probe {name} directory is not canonical: {}",
            path.display()
        )));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Refusal::new(format!(
                    "Cargo storage probe {name} path is not a plain directory"
                )));
            }
            let mut entries = fs::read_dir(path).map_err(|error| {
                Refusal::new(format!("cannot read fresh {name} directory: {error}"))
            })?;
            if entries.next().is_some() {
                return Err(Refusal::new(format!(
                    "Cargo storage probe {name} directory is not fresh and empty"
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)?;
        }
        Err(error) => {
            return Err(Refusal::new(format!(
                "cannot inspect Cargo storage probe {name} directory: {error}"
            )));
        }
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        Refusal::new(format!(
            "cannot canonicalize Cargo storage probe {name} directory: {error}"
        ))
    })?;
    if canonical != path {
        return Err(Refusal::new(format!(
            "Cargo storage probe {name} directory resolves through an alias"
        )));
    }
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| Refusal::new(format!("cannot create {}: {error}", path.display())))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn prepare_tools(arguments: &Arguments) -> Result<Vec<Tool>> {
    let mut tools = Vec::new();
    for (name, path) in [
        ("control-cargo", &arguments.control),
        ("derived-cargo", &arguments.derived),
        ("rustc", &arguments.rustc),
        ("rustdoc", &arguments.rustdoc),
    ] {
        tools.push(prepare_tool(name, path)?);
    }
    let git = fs::canonicalize("/usr/bin/git")
        .map_err(|error| Refusal::new(format!("cannot resolve fixed local Git tool: {error}")))?;
    tools.push(prepare_tool("git", &git)?);
    let mut unique = tools
        .iter()
        .map(|tool| tool.path.clone())
        .collect::<Vec<_>>();
    unique.sort();
    unique.dedup();
    if unique.len() != tools.len() {
        return Err(Refusal::new(
            "Cargo storage probe tool paths must identify distinct files",
        ));
    }
    Ok(tools)
}

fn prepare_tool(name: &'static str, path: &Path) -> Result<Tool> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!(
            "Cargo storage probe {name} path is not absolute"
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("cannot inspect {name} tool: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Refusal::new(format!(
            "Cargo storage probe {name} is not a regular immutable tool file"
        )));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("cannot canonicalize {name} tool: {error}")))?;
    if canonical != path {
        return Err(Refusal::new(format!(
            "Cargo storage probe {name} path is not canonical"
        )));
    }
    Ok(Tool {
        name,
        path: canonical.clone(),
        sha256: sha256_file(&canonical)
            .map_err(|error| Refusal::new(format!("cannot fingerprint {name} tool: {error}")))?,
    })
}

fn tool_metadata(tools: &[Tool]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "path": os_metadata(tool.path.as_os_str()),
                    "sha256": tool.sha256
                })
            })
            .collect(),
    )
}

impl Probe<'_> {
    fn set_base_env(
        &mut self,
        cargo_home: &Path,
        home: &Path,
        rustc: &Path,
        rustdoc: &Path,
        git: &Path,
    ) {
        let mut env = BTreeMap::new();
        let mut path_parts = vec![
            rustc
                .parent()
                .unwrap_or(Path::new("/usr/bin"))
                .to_path_buf(),
            git.parent().unwrap_or(Path::new("/usr/bin")).to_path_buf(),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr/local/bin"),
        ];
        path_parts.dedup();
        let path =
            std::env::join_paths(path_parts).unwrap_or_else(|_| OsString::from("/usr/bin:/bin"));
        env.insert("PATH".into(), path);
        env.insert("HOME".into(), home.as_os_str().to_owned());
        env.insert("CARGO_HOME".into(), cargo_home.as_os_str().to_owned());
        env.insert(
            "TMPDIR".into(),
            self.work.join("temporary").into_os_string(),
        );
        env.insert("RUSTC".into(), rustc.as_os_str().to_owned());
        env.insert("RUSTDOC".into(), rustdoc.as_os_str().to_owned());
        env.insert("CARGO_BUILD_JOBS".into(), "2".into());
        env.insert("CARGO_PROFILE_DEV_DEBUG".into(), "0".into());
        env.insert("CARGO_CACHE_RUSTC_INFO".into(), "0".into());
        env.insert("GIT_ALLOW_PROTOCOL".into(), "file".into());
        env.insert("GIT_AUTHOR_NAME".into(), "Cargo Storage Fixture".into());
        env.insert("GIT_AUTHOR_EMAIL".into(), "fixture@example.invalid".into());
        env.insert("GIT_COMMITTER_NAME".into(), "Cargo Storage Fixture".into());
        env.insert(
            "GIT_COMMITTER_EMAIL".into(),
            "fixture@example.invalid".into(),
        );
        env.insert("GIT_AUTHOR_DATE".into(), "2026-10-01T00:00:00Z".into());
        env.insert("GIT_COMMITTER_DATE".into(), "2026-10-01T00:00:00Z".into());
        env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        env.insert("LC_ALL".into(), "C".into());
        env.insert("LANG".into(), "C".into());
        env.insert("TZ".into(), "UTC".into());
        self.base_env = env;
    }

    fn command(
        &mut self,
        label: &str,
        program: &Path,
        args: impl IntoIterator<Item = OsString>,
        cwd: &Path,
        env: &BTreeMap<OsString, OsString>,
        expected_exit_code: i32,
    ) -> Result<process_capture::CapturedProcess> {
        self.guard.check()?;
        let arguments = args.into_iter().collect::<Vec<_>>();
        let spec = CommandSpec::new(
            program.as_os_str().to_owned(),
            arguments.clone(),
            cwd,
            env.clone(),
        );
        let limits = CaptureLimits {
            timeout: TIMEOUT,
            stdout_bytes: STREAM_LIMIT,
            stderr_bytes: STREAM_LIMIT,
            termination_grace: TERMINATION_GRACE,
        };
        let capture_result = process_capture::capture(&spec, limits, || self.guard.requested());
        self.record_capture(label, &spec, expected_exit_code, capture_result)
    }

    fn record_capture(
        &mut self,
        label: &str,
        spec: &CommandSpec,
        expected_exit_code: i32,
        capture_result: std::result::Result<
            process_capture::CapturedProcess,
            process_capture::CaptureError,
        >,
    ) -> Result<process_capture::CapturedProcess> {
        let program = &spec.program;
        let arguments = &spec.args;
        let cwd = &spec.cwd;
        let env = &spec.env;
        let sequence = self.commands.len() + 1;
        let stdout_path = self.logs.join(format!("{sequence:03}-{label}.stdout"));
        let stderr_path = self.logs.join(format!("{sequence:03}-{label}.stderr"));

        let (stdout, stderr, status, status_value, capture_error, elapsed_ms, successful_capture) =
            match capture_result {
                Ok(captured) => {
                    let status_value = status_metadata(&captured.status);
                    let status = Some(captured.status);
                    (
                        captured.stdout,
                        captured.stderr,
                        status,
                        status_value,
                        Value::Null,
                        captured.elapsed.as_millis() as u64,
                        true,
                    )
                }
                Err(error) => {
                    let status_value = error
                        .status
                        .as_ref()
                        .map(status_metadata)
                        .unwrap_or(Value::Null);
                    (
                        error.stdout,
                        error.stderr,
                        None,
                        status_value,
                        json!({
                            "cause": error.cause.to_string(),
                            "cleanup_error": error.cleanup_error.as_ref().map(ToString::to_string)
                        }),
                        error.elapsed.as_millis() as u64,
                        false,
                    )
                }
            };
        write_new_file(&stdout_path, &stdout)?;
        write_new_file(&stderr_path, &stderr)?;
        let stdout_log = log_metadata(&self.output, &stdout_path, &stdout);
        let stderr_log = log_metadata(&self.output, &stderr_path, &stderr);
        let exit_code = status_value["exit_code"].clone();
        let stop_reason = if successful_capture {
            Value::Null
        } else {
            capture_error.clone()
        };
        let record = json!({
            "label": label,
            "exit_code": exit_code,
            "stop_reason": stop_reason,
            "argv": std::iter::once(program.as_os_str())
                .chain(arguments.iter().map(OsString::as_os_str))
                .map(os_metadata)
                .collect::<Vec<_>>(),
            "cwd": os_metadata(cwd.as_os_str()),
            "environment": environment_metadata(env),
            "expected_exit_code": expected_exit_code,
            "status": status_value,
            "capture_error": capture_error,
            "elapsed_millis": elapsed_ms,
            "stdout_log": stdout_log,
            "stderr_log": stderr_log.clone(),
            "err_log": stderr_log,
            "stdout": log_metadata(&self.output, &stdout_path, &stdout),
            "stderr": log_metadata(&self.output, &stderr_path, &stderr)
        });
        self.commands.push(record);
        self.verify_tool_identities()?;
        if !successful_capture {
            return Err(Refusal::new(format!(
                "Cargo storage probe command {label} did not complete under capture limits"
            )));
        }
        let status = status.ok_or_else(|| {
            Refusal::new(format!(
                "Cargo storage probe command {label} has no direct-child status"
            ))
        })?;
        let actual = status.code();
        if actual != Some(expected_exit_code) {
            return Err(Refusal::new(format!(
                "Cargo storage probe command {label} exited with {actual:?}; expected {expected_exit_code}"
            )));
        }
        self.guard.check()?;
        Ok(process_capture::CapturedProcess {
            status,
            stdout,
            stderr,
            elapsed: Duration::from_millis(elapsed_ms),
        })
    }

    fn cargo(
        &mut self,
        label: &str,
        cargo: &Path,
        args: impl IntoIterator<Item = OsString>,
        cwd: &Path,
        env: &BTreeMap<OsString, OsString>,
        expected_exit_code: i32,
    ) -> Result<process_capture::CapturedProcess> {
        self.command(label, cargo, args, cwd, env, expected_exit_code)
    }

    fn verify_tool_identities(&self) -> Result<()> {
        for tool in &self.tools {
            let actual = sha256_file(&tool.path).map_err(|error| {
                Refusal::new(format!(
                    "cannot recheck {} tool after command: {error}",
                    tool.name
                ))
            })?;
            if actual != tool.sha256 {
                return Err(Refusal::new(format!(
                    "{} tool changed during Cargo storage probe",
                    tool.name
                )));
            }
        }
        Ok(())
    }
}

fn run_component(probe: &mut Probe<'_>, report: &mut Value) -> Result<()> {
    let tool = |name: &str| {
        probe
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .map(|tool| tool.path.clone())
            .ok_or_else(|| Refusal::new(format!("missing prepared {name} tool")))
    };
    let control = tool("control-cargo")?;
    let derived = tool("derived-cargo")?;
    let rustc = tool("rustc")?;
    let rustdoc = tool("rustdoc")?;
    let git = tool("git")?;
    let work = probe.work.clone();
    let temporary = work.join("temporary");
    let home = work.join("home with spaces");
    let cargo_home = work.join("cargo home with spaces");
    let control_target = work.join("control target");
    let derived_target = work.join("derived target");
    let project = work.join("application with spaces");
    let gitcrate = work.join("local git input with spaces");
    let cache = work.join("private cache with spaces and Ω");

    for directory in [
        &temporary,
        &home,
        &cargo_home,
        &control_target,
        &derived_target,
        &project,
        &gitcrate,
    ] {
        create_private_directory(directory)?;
    }
    create_private_directory(&project.join("src"))?;
    create_private_directory(&project.join(".cargo"))?;
    create_private_directory(&gitcrate.join("src"))?;
    create_private_directory(&cache)?;
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o755))
        .map_err(|error| Refusal::new(format!("cannot set fixture cache mode: {error}")))?;
    probe.set_base_env(&cargo_home, &home, &rustc, &rustdoc, &git);
    let git_env = probe.base_env.clone();

    // Fresh file:// Git input needs one local fetch. Registry resolution is
    // separately confined to an empty local source for every fixture command.
    let empty_registry = work.join("empty registry source");
    create_private_directory(&empty_registry)?;
    write_text(
        &cargo_home.join("config.toml"),
        &format!(
            "[source.crates-io]\nreplace-with=\"fixture-local-only\"\n[source.fixture-local-only]\ndirectory={}\n[env]\nRC2_HOME_MARKER=\"from-original-config-home\"\nRC2_PRECEDENCE_MARKER=\"from-home\"\n",
            toml_string(empty_registry.to_str().unwrap())
        ),
    )?;
    write_text(
        &cargo_home.join("credentials.toml"),
        "# Synthetic credential sentinel; never a real token.\n",
    )?;
    let config = project.join(".cargo/config");
    let config_base = "[env]\nRC2_ORIGIN_MARKER={value=\"relative marker with spaces\",relative=true}\nRC2_PRECEDENCE_MARKER=\"from-project\"\n";
    write_text(&config, config_base)?;
    write_text(
        &project.join("build.rs"),
        "fn main(){println!(\"cargo:rerun-if-changed=build.rs\"); println!(\"cargo:rustc-env=RC2_BUILD_HOME={}\",std::env::var(\"RC2_HOME_MARKER\").unwrap());}\n",
    )?;
    let main_source = "fn main(){println!(\"{}|{}|{}|{}|{}\",env!(\"RC2_HOME_MARKER\"),env!(\"RC2_ORIGIN_MARKER\"),env!(\"RC2_PRECEDENCE_MARKER\"),env!(\"RC2_BUILD_HOME\"),storage_fixture_dependency::value());}\n";
    write_text(&project.join("src/main.rs"), main_source)?;
    write_text(
        &gitcrate.join("Cargo.toml"),
        "[package]\nname=\"storage-fixture-dependency\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[workspace]\n",
    )?;
    write_text(&gitcrate.join("src/lib.rs"), "pub fn value()->u32{42}\n")?;

    for (label, args) in [
        (
            "git-init",
            strings(["-C", gitcrate.to_str().unwrap(), "init", "--quiet"]),
        ),
        (
            "git-add",
            strings([
                "-C",
                gitcrate.to_str().unwrap(),
                "add",
                "Cargo.toml",
                "src/lib.rs",
            ]),
        ),
        (
            "git-commit",
            strings([
                "-C",
                gitcrate.to_str().unwrap(),
                "commit",
                "--quiet",
                "-m",
                "test: pin local storage fixture dependency",
            ]),
        ),
    ] {
        probe.command(label, &git, args, &work, &git_env, 0)?;
    }
    let revision = probe
        .command(
            "git-revision",
            &git,
            strings(["-C", gitcrate.to_str().unwrap(), "rev-parse", "HEAD"]),
            &work,
            &git_env,
            0,
        )?
        .stdout;
    let revision = String::from_utf8(revision)
        .map_err(|error| Refusal::new(format!("local Git revision was not UTF-8: {error}")))?
        .trim()
        .to_owned();
    write_text(
        &project.join("Cargo.toml"),
        &format!(
            "[package]\nname=\"storage-fixture-app\"\nversion=\"0.0.0\"\nedition=\"2024\"\nbuild=\"build.rs\"\n[workspace]\n[dependencies]\nstorage-fixture-dependency={{git={},rev={}}}\n",
            toml_string(&file_uri(&gitcrate)?),
            toml_string(&revision)
        ),
    )?;
    report["fixtures"]["local_git_revision"] = json!(revision);

    let cli = strings(["--config", "env.RC2_PRECEDENCE_MARKER=\"from-cli\""]);
    let mut control_env = probe.base_env.clone();
    insert_env(
        &mut control_env,
        "CARGO_TARGET_DIR",
        control_target.as_os_str(),
    );
    let metadata_args = strings([
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--locked",
        "--offline",
    ]);
    probe.cargo(
        "control-local-lock",
        &control,
        [cli.clone(), strings(["generate-lockfile"])].concat(),
        &project,
        &control_env,
        0,
    )?;
    let original_metadata = probe
        .cargo(
            "control-metadata",
            &control,
            [cli.clone(), metadata_args.clone()].concat(),
            &project,
            &control_env,
            0,
        )?
        .stdout;
    probe.cargo(
        "control-check",
        &control,
        [cli.clone(), strings(["check", "--locked", "--offline"])].concat(),
        &project,
        &control_env,
        0,
    )?;
    probe.cargo(
        "control-build",
        &control,
        [cli.clone(), strings(["build", "--locked", "--offline"])].concat(),
        &project,
        &control_env,
        0,
    )?;
    let control_binary = control_target.join("debug/storage-fixture-app");
    let original_output = probe
        .command(
            "control-executable",
            &control_binary,
            std::iter::empty(),
            &project,
            &control_env,
            0,
        )?
        .stdout;
    let expected = format!(
        "from-original-config-home|{}|from-cli|from-original-config-home|42\n",
        project.join("relative marker with spaces").display()
    )
    .into_bytes();
    add_check(
        report,
        "control-original-config-origin-and-CLI-precedence",
        original_output == expected,
        json!({"expected_output_sha256": digest::sha256_bytes(&expected)}),
    )?;
    let home_before = snapshot(&cargo_home)?;
    let project_before = snapshot(&project)?;

    let mut selected = probe.base_env.clone();
    insert_env(
        &mut selected,
        "AMI_RUST_CARGO_STORAGE_ROOT",
        cache.as_os_str(),
    );
    insert_env(
        &mut selected,
        "CARGO_TARGET_DIR",
        derived_target.as_os_str(),
    );
    let mut selected_metadata_env = selected.clone();
    insert_env(
        &mut selected_metadata_env,
        "CARGO_TARGET_DIR",
        control_target.as_os_str(),
    );
    let derived_metadata = probe
        .cargo(
            "derived-metadata",
            &derived,
            [cli.clone(), metadata_args.clone()].concat(),
            &project,
            &selected_metadata_env,
            0,
        )?
        .stdout;
    add_check(
        report,
        "selected-metadata-byte-equal-with-same-output-path",
        original_metadata == derived_metadata,
        json!({"metadata_sha256": digest::sha256_bytes(&original_metadata)}),
    )?;
    let cache_metadata = fs::metadata(&cache)
        .map_err(|error| Refusal::new(format!("cannot inspect valid fixture cache: {error}")))?;
    let work_metadata = fs::metadata(&work)
        .map_err(|error| Refusal::new(format!("cannot inspect work directory owner: {error}")))?;
    add_check(
        report,
        "owned-0755-selected-root-accepted",
        cache_metadata.uid() == work_metadata.uid() && cache_metadata.mode() & 0o7777 == 0o755,
        json!({
            "root": os_metadata(cache.as_os_str()),
            "root_uid": cache_metadata.uid(),
            "work_uid": work_metadata.uid(),
            "mode": format!("{:04o}", cache_metadata.mode() & 0o7777)
        }),
    )?;

    probe.cargo(
        "derived-local-git-fetch",
        &derived,
        [cli.clone(), strings(["fetch", "--locked"])].concat(),
        &project,
        &selected,
        0,
    )?;
    probe.cargo(
        "derived-check",
        &derived,
        [cli.clone(), strings(["check", "--locked", "--offline"])].concat(),
        &project,
        &selected,
        0,
    )?;
    probe.cargo(
        "derived-build",
        &derived,
        [cli.clone(), strings(["build", "--locked", "--offline"])].concat(),
        &project,
        &selected,
        0,
    )?;
    let derived_binary = derived_target.join("debug/storage-fixture-app");
    let derived_output = probe
        .command(
            "derived-executable",
            &derived_binary,
            std::iter::empty(),
            &project,
            &selected,
            0,
        )?
        .stdout;
    add_check(
        report,
        "selected-config-home-relative-origin-CLI-and-build-script-equivalent",
        derived_output == original_output,
        json!({"control_output_sha256": digest::sha256_bytes(&original_output)}),
    )?;
    let binary_before_cached_build = snapshot(&derived_binary)?;
    let cached = probe.cargo(
        "derived-cached-build",
        &derived,
        [cli.clone(), strings(["build", "--locked", "--offline"])].concat(),
        &project,
        &selected,
        0,
    )?;
    add_check(
        report,
        "cached-build-reuses-executable",
        snapshot(&derived_binary)? == binary_before_cached_build
            && !cached
                .stderr
                .windows(b"Compiling ".len())
                .any(|part| part == b"Compiling "),
        json!({"binary": binary_before_cached_build}),
    )?;
    add_check(
        report,
        "original-home-unchanged-under-selected-cargo",
        snapshot(&cargo_home)? == home_before,
        json!({"snapshot": home_before}),
    )?;
    add_check(
        report,
        "project-inputs-unchanged-under-selected-cargo",
        snapshot(&project)? == project_before,
        json!({"snapshot": project_before}),
    )?;
    let required_cache_entries = [
        ".package-cache",
        ".package-cache-mutate",
        ".global-cache",
        "git/db",
        "git/checkouts",
    ];
    let cache_entries = snapshot(&cache)?;
    let cache_shapes_ok = plain_file(&cache.join(".package-cache"))?
        && plain_file(&cache.join(".package-cache-mutate"))?
        && plain_file(&cache.join(".global-cache"))?
        && plain_directory(&cache.join("git/db"))?
        && plain_directory(&cache.join("git/checkouts"))?;
    let sqlite_ok = sqlite_database(&cache.join(".global-cache"))?;
    let git_rows = snapshot(&cache.join("git/checkouts"))?;
    add_check(
        report,
        "all-cache-lock-database-and-Git-roots-use-selected-store",
        cache_shapes_ok && sqlite_ok && git_rows.len() > 1,
        json!({
            "required": required_cache_entries,
            "lock_database_and_git_shapes_valid": cache_shapes_ok,
            "global_cache_has_sqlite_header": sqlite_ok,
            "git_checkout_entries": git_rows,
            "selected_cache_snapshot": cache_entries
        }),
    )?;
    let lock_bytes = fs::read(project.join("Cargo.lock"))
        .map_err(|error| Refusal::new(format!("cannot read synthetic Cargo.lock: {error}")))?;
    add_check(
        report,
        "synthetic-lockfile-has-no-registry-dependencies",
        !lock_bytes
            .windows(b"registry+".len())
            .any(|part| part == b"registry+"),
        json!({
            "lock_sha256": digest::sha256_bytes(&lock_bytes),
            "allowed_git_protocol": "file"
        }),
    )?;

    let registry_counter = work.join("registry refusal fixture");
    create_private_directory(&registry_counter)?;
    write_text(
        &registry_counter.join("Cargo.toml"),
        "[package]\nname=\"registry-counter\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[workspace]\n[lib]\npath=\"lib.rs\"\n[dependencies]\nami-rust-rc2-unavailable-registry-fixture-17051=\"=0.0.0\"\n",
    )?;
    write_text(&registry_counter.join("lib.rs"), "pub fn value(){}\n")?;
    let registry_counter_before = snapshot(&registry_counter)?;
    let registry_refusal = probe.cargo(
        "registry-local-source-counter",
        &derived,
        strings(["generate-lockfile"]),
        &registry_counter,
        &selected,
        101,
    )?;
    add_check(
        report,
        "registry-dependency-refused-by-empty-local-source",
        contains_bytes(&registry_refusal.stderr, b"directory source")
            && contains_bytes(&registry_refusal.stderr, b"no matching package")
            && registry_counter_before == snapshot(&registry_counter)?
            && snapshot(&empty_registry)?.len() == 1,
        json!({"stderr_sha256": digest::sha256_bytes(&registry_refusal.stderr),
               "empty_registry_source": os_metadata(empty_registry.as_os_str())}),
    )?;

    let watched_before = (
        snapshot(&cargo_home)?,
        snapshot(&cache)?,
        snapshot(&project)?,
    );
    let literal_args = [
        strings([
            "--config",
            "build.build-dir=\"literal intermediate with spaces\"",
        ]),
        cli.clone(),
        metadata_args.clone(),
    ]
    .concat();
    let literal_control = probe
        .cargo(
            "template-literal-control",
            &control,
            literal_args.clone(),
            &project,
            &control_env,
            0,
        )?
        .stdout;
    let literal_derived = probe
        .cargo(
            "template-literal-derived",
            &derived,
            literal_args,
            &project,
            &selected_metadata_env,
            0,
        )?
        .stdout;
    let literal_json = parse_json(&literal_derived, "literal build directory metadata")?;
    let expected_build = project.join("literal intermediate with spaces");
    let expected_build_string = expected_build.to_string_lossy();
    add_check(
        report,
        "custom-build-dir-literal-stock-equivalence",
        literal_control == literal_derived
            && literal_json["build_directory"].as_str() == Some(expected_build_string.as_ref())
            && watched_before
                == (
                    snapshot(&cargo_home)?,
                    snapshot(&cache)?,
                    snapshot(&project)?,
                ),
        json!({
            "expected_build_directory": os_metadata(expected_build.as_os_str()),
            "metadata_sha256": digest::sha256_bytes(&literal_derived)
        }),
    )?;
    let brace_cache = work.join("cache with {literal braces} and Ω");
    create_private_directory(&brace_cache)?;
    fs::set_permissions(&brace_cache, fs::Permissions::from_mode(0o755))
        .map_err(|error| Refusal::new(format!("cannot set brace-cache mode: {error}")))?;
    let brace_before = (
        snapshot(&cargo_home)?,
        snapshot(&brace_cache)?,
        snapshot(&project)?,
    );
    let brace_env = with_selector(&selected_metadata_env, &brace_cache);
    let templated = probe
        .cargo(
            "template-cache-literal-OS-value",
            &derived,
            [
                strings([
                    "--config",
                    "build.build-dir=\"{cargo-cache-home}/intermediate/{workspace-path-hash}\"",
                ]),
                cli.clone(),
                metadata_args.clone(),
            ]
            .concat(),
            &project,
            &brace_env,
            0,
        )?
        .stdout;
    let template_json = parse_json(&templated, "cache-template build directory metadata")?;
    let build_directory = template_json["build_directory"]
        .as_str()
        .ok_or_else(|| Refusal::new("Cargo metadata omitted its build directory"))?;
    let expected_prefix = format!("{}/intermediate/", brace_cache.to_string_lossy());
    let suffix = build_directory.strip_prefix(&expected_prefix).unwrap_or("");
    add_check(
        report,
        "custom-build-dir-cache-path-is-literal-not-template-input",
        !suffix.is_empty()
            && suffix.matches('/').count() == 1
            && !build_directory.contains("{cargo-cache-home}")
            && brace_before
                == (
                    snapshot(&cargo_home)?,
                    snapshot(&brace_cache)?,
                    snapshot(&project)?,
                ),
        json!({
            "selected_cache_root": os_metadata(brace_cache.as_os_str()),
            "build_directory_lossy_for_metadata_json": build_directory,
            "suffix_components": suffix.split('/').collect::<Vec<_>>()
        }),
    )?;

    let before_unknown = (
        snapshot(&cargo_home)?,
        snapshot(&cache)?,
        snapshot(&project)?,
    );
    let unknown = probe.cargo(
        "refuse-template-unknown-variable",
        &derived,
        [
            strings(["--config", "build.build-dir=\"{unknown-variable}/out\""]),
            cli.clone(),
            metadata_args.clone(),
        ]
        .concat(),
        &project,
        &selected,
        101,
    )?;
    let unknown_marker = b"unknown-variable";
    add_check(
        report,
        "unknown-template-variable-keeps-Cargo-refusal",
        unknown
            .stderr
            .windows(unknown_marker.len())
            .any(|part| part == unknown_marker)
            && before_unknown
                == (
                    snapshot(&cargo_home)?,
                    snapshot(&cache)?,
                    snapshot(&project)?,
                ),
        json!({"stderr_sha256": digest::sha256_bytes(&unknown.stderr)}),
    )?;

    for (name, value) in [
        ("plain", toml_string(&cache.to_string_lossy())),
        (
            "force",
            format!(
                "{{value={},force=true}}",
                toml_string(&cache.to_string_lossy())
            ),
        ),
        (
            "relative",
            format!(
                "{{value={},relative=true}}",
                toml_string(&cache.to_string_lossy())
            ),
        ),
    ] {
        write_text(
            &config,
            &format!("{config_base}AMI_RUST_CARGO_STORAGE_ROOT={value}\n"),
        )?;
        let before = (
            snapshot(&cargo_home)?,
            snapshot(&cache)?,
            snapshot(&project)?,
        );
        probe.cargo(
            &format!("same-selector-{name}"),
            &derived,
            [cli.clone(), metadata_args.clone()].concat(),
            &project,
            &selected_metadata_env,
            0,
        )?;
        add_check(
            report,
            &format!("same-selector-{name}-read-only"),
            before
                == (
                    snapshot(&cargo_home)?,
                    snapshot(&cache)?,
                    snapshot(&project)?,
                ),
            json!({"resolved_selector": os_metadata(cache.as_os_str())}),
        )?;
    }

    let relative_config = work.join("relative config directory");
    create_private_directory(&relative_config)?;
    let explicit_config = relative_config.join("config.toml");
    write_text(
        &explicit_config,
        &format!(
            "[env]\nAMI_RUST_CARGO_STORAGE_ROOT={{value={},relative=true,force=true}}\n",
            toml_string(
                cache
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .as_ref()
            )
        ),
    )?;
    write_text(&config, config_base)?;
    let before_relative_origin = (
        snapshot(&cargo_home)?,
        snapshot(&cache)?,
        snapshot(&project)?,
    );
    probe.cargo(
        "same-selector-relative-origin",
        &derived,
        [
            vec!["--config".into(), explicit_config.as_os_str().to_owned()],
            cli.clone(),
            metadata_args.clone(),
        ]
        .concat(),
        &project,
        &selected_metadata_env,
        0,
    )?;
    add_check(
        report,
        "same-selector-true-relative-origin-read-only",
        before_relative_origin
            == (
                snapshot(&cargo_home)?,
                snapshot(&cache)?,
                snapshot(&project)?,
            ),
        json!({"explicit_config": os_metadata(explicit_config.as_os_str())}),
    )?;

    // The paired conflicting relative value proves the config was resolved,
    // rather than ignored in favor of the explicit selected-root environment.
    let relative_other = work.join("relative conflict cache");
    create_private_directory(&relative_other)?;
    let conflicting_config = relative_config.join("conflicting.toml");
    write_text(
        &conflicting_config,
        &format!(
            "[env]\nAMI_RUST_CARGO_STORAGE_ROOT={{value={},relative=true,force=false}}\n",
            toml_string(relative_other.file_name().unwrap().to_str().unwrap())
        ),
    )?;
    let relative_before = (
        snapshot(&cargo_home)?,
        snapshot(&cache)?,
        snapshot(&project)?,
        snapshot(&relative_other)?,
        snapshot(&conflicting_config)?,
    );
    let refused_relative = probe.cargo(
        "conflicting-selector-relative-origin",
        &derived,
        [
            vec!["--config".into(), conflicting_config.as_os_str().to_owned()],
            cli.clone(),
            metadata_args.clone(),
        ]
        .concat(),
        &project,
        &selected_metadata_env,
        101,
    )?;
    add_check(
        report,
        "conflicting-relative-origin-refused-before-mutation",
        contains_bytes(&refused_relative.stderr, b"AMI_RUST_CARGO_STORAGE_ROOT")
            && relative_before
                == (
                    snapshot(&cargo_home)?,
                    snapshot(&cache)?,
                    snapshot(&project)?,
                    snapshot(&relative_other)?,
                    snapshot(&conflicting_config)?,
                ),
        json!({"explicit_config": os_metadata(conflicting_config.as_os_str())}),
    )?;

    for force in [false, true] {
        let other = work.join("different valid cache");
        if !other.exists() {
            create_private_directory(&other)?;
            fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).map_err(|error| {
                Refusal::new(format!("cannot set conflict-cache mode: {error}"))
            })?;
        }
        write_text(
            &config,
            &format!(
                "{config_base}AMI_RUST_CARGO_STORAGE_ROOT={{value={},force={force}}}\n",
                toml_string(&other.to_string_lossy())
            ),
        )?;
        for verb in ["metadata", "check", "build"] {
            let target = work.join(format!("forbidden-conflict-{force}-{verb}"));
            let mut conflict_env = selected.clone();
            insert_env(&mut conflict_env, "CARGO_TARGET_DIR", target.as_os_str());
            let before = (
                snapshot(&cargo_home)?,
                snapshot(&cache)?,
                snapshot(&project)?,
                snapshot(&other)?,
            );
            let args = if verb == "metadata" {
                strings([
                    "metadata",
                    "--format-version",
                    "1",
                    "--no-deps",
                    "--locked",
                    "--offline",
                ])
            } else {
                strings([verb, "--locked", "--offline"])
            };
            let captured = probe.cargo(
                &format!("refuse-conflict-{force}-{verb}"),
                &derived,
                args,
                &project,
                &conflict_env,
                101,
            )?;
            let refused =
                contains_bytes(&captured.stderr, b"conflicting AMI_RUST_CARGO_STORAGE_ROOT");
            let target_absent = !path_exists(&target)?;
            let after = (
                snapshot(&cargo_home)?,
                snapshot(&cache)?,
                snapshot(&project)?,
                snapshot(&other)?,
            );
            add_check(
                report,
                &format!("conflict-{force}-{verb}-refused-before-mutation"),
                refused && target_absent && before == after,
                json!({
                    "force": force,
                    "target_was_not_created": target_absent,
                    "stderr_sha256": digest::sha256_bytes(&captured.stderr)
                }),
            )?;
        }
    }

    write_text(&config, config_base)?;
    let writable = work.join("group writable cache");
    create_private_directory(&writable)?;
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o775))
        .map_err(|error| Refusal::new(format!("cannot set invalid-root mode: {error}")))?;
    let regular_file = work.join("regular file cache");
    write_text(&regular_file, "not a directory\n")?;
    let alias = work.join("cache alias");
    std::os::unix::fs::symlink(&cache, &alias)
        .map_err(|error| Refusal::new(format!("cannot create cache alias fixture: {error}")))?;
    let mut noncanonical_root = cache.as_os_str().to_os_string();
    noncanonical_root.push("/.");
    let invalid_roots = [
        ("empty", OsString::new()),
        ("relative", OsString::from("relative cache")),
        ("missing", work.join("missing cache").into_os_string()),
        ("file", regular_file.as_os_str().to_owned()),
        ("symlink", alias.as_os_str().to_owned()),
        ("group-writable", writable.as_os_str().to_owned()),
        ("noncanonical", noncanonical_root),
    ];
    for (name, root) in invalid_roots {
        let target = work.join(format!("forbidden-root-{name}"));
        let before = (
            snapshot(&cargo_home)?,
            snapshot(&cache)?,
            snapshot(&project)?,
            snapshot(&writable)?,
        );
        let mut bad_env = probe.base_env.clone();
        insert_env(
            &mut bad_env,
            "AMI_RUST_CARGO_STORAGE_ROOT",
            root.as_os_str(),
        );
        insert_env(&mut bad_env, "CARGO_TARGET_DIR", target.as_os_str());
        let captured = probe.cargo(
            &format!("refuse-root-{name}"),
            &derived,
            strings([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--offline",
            ]),
            &project,
            &bad_env,
            101,
        )?;
        let refused = contains_bytes(&captured.stderr, b"invalid AMI_RUST_CARGO_STORAGE_ROOT");
        let target_absent = !path_exists(&target)?;
        let after = (
            snapshot(&cargo_home)?,
            snapshot(&cache)?,
            snapshot(&project)?,
            snapshot(&writable)?,
        );
        add_check(
            report,
            &format!("invalid-root-{name}-refused-before-mutation"),
            refused && target_absent && before == after,
            json!({
                "root": os_metadata(root.as_os_str()),
                "target_was_not_created": target_absent,
                "stderr_sha256": digest::sha256_bytes(&captured.stderr)
            }),
        )?;
    }

    write_text(
        &config,
        &format!("{config_base}AMI_RUST_CARGO_STORAGE_ROOT=\"ordinary-child-env-only\"\n"),
    )?;
    let absent_control = probe
        .cargo(
            "absent-selector-control-metadata",
            &control,
            [cli.clone(), metadata_args.clone()].concat(),
            &project,
            &control_env,
            0,
        )?
        .stdout;
    let absent_derived = probe
        .cargo(
            "absent-selector-derived-metadata",
            &derived,
            [cli.clone(), metadata_args.clone()].concat(),
            &project,
            &control_env,
            0,
        )?
        .stdout;
    add_check(
        report,
        "selector-absent-legacy-env-metadata-byte-equivalence",
        absent_control == absent_derived,
        json!({"metadata_sha256": digest::sha256_bytes(&absent_control)}),
    )?;

    // Restore the original fixture before the fresh failure/retry and Linux cases.
    write_text(&config, config_base)?;
    run_artifact_failure_and_retry(
        probe,
        report,
        &derived,
        &project,
        &selected,
        &derived_target.join("debug/storage-fixture-app"),
        main_source,
        &expected,
    )?;

    #[cfg(target_os = "linux")]
    run_linux_non_utf8_cases(
        probe,
        report,
        &control,
        &derived,
        &project,
        &cargo_home,
        &cache,
        &control_env,
        &selected,
        &selected_metadata_env,
        &cli,
        &metadata_args,
    )?;

    probe.verify_tool_identities()?;
    add_check(
        report,
        "immutable-tools-and-executed-source-still-match",
        true,
        json!({
            "tool_sha256": tool_metadata(&probe.tools),
            "driver_source_sha256": digest::sha256_bytes(include_bytes!("cargo_storage_probe.rs"))
        }),
    )?;

    report["fixtures"]["application"] = json!(snapshot(&project)?);
    report["fixtures"]["cargo_home"] = json!(snapshot(&cargo_home)?);
    report["fixtures"]["selected_cache"] = json!(snapshot(&cache)?);
    report["fixtures"]["local_git_input"] = json!(snapshot(&gitcrate)?);
    report["fixtures"]["invalid_root_inputs"] = json!({
        "regular_file": snapshot(&regular_file)?,
        "symlink_alias_literal_target": snapshot(&alias)?,
        "group_writable_directory": snapshot(&writable)?,
        "brace_cache": snapshot(&brace_cache)?,
        "explicit_relative_config": snapshot(&explicit_config)?
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_artifact_failure_and_retry(
    probe: &mut Probe<'_>,
    report: &mut Value,
    derived: &Path,
    project: &Path,
    selected: &BTreeMap<OsString, OsString>,
    prior_binary: &Path,
    valid_source: &str,
    expected_output: &[u8],
) -> Result<()> {
    let artifact_dir = probe.work.join("fresh artifact export");
    create_private_directory(&artifact_dir)?;
    let prior = file_fingerprint(prior_binary)?;
    let source = project.join("src/main.rs");
    let project_before = snapshot(project)?;
    let source_modified = fs::metadata(&source)?.modified()?;
    write_text(
        &source,
        "fn main(){missing_compile_symbol_for_storage_probe();}\n",
    )?;
    let args = artifact_args(&artifact_dir);
    let failure = probe.cargo(
        "fresh-artifact-compile-failure",
        derived,
        args.clone(),
        project,
        selected,
        101,
    );
    let restore = write_text(&source, valid_source);
    restore?;
    File::options()
        .write(true)
        .open(&source)?
        .set_times(fs::FileTimes::new().set_modified(source_modified))?;
    let failure = failure?;
    let empty_after_failure = snapshot(&artifact_dir)?;
    let prior_after_failure = file_fingerprint(prior_binary)?;
    add_check(
        report,
        "fresh-artifact-compile-failure-101-preserves-prior-and-emits-no-artifact",
        failure.status.code() == Some(101)
            && empty_after_failure.len() == 1
            && empty_after_failure[0]["kind"] == "dir"
            && prior_after_failure == prior
            && contains_bytes(&failure.stderr, b"missing_compile_symbol_for_storage_probe"),
        json!({
            "failed_command_exit_code": failure.status.code(),
            "artifact_directory_after_failure": empty_after_failure,
            "prior_binary_before_and_after": prior,
            "stderr_sha256": digest::sha256_bytes(&failure.stderr)
        }),
    )?;

    let retry = probe.cargo(
        "valid-artifact-export-retry",
        derived,
        args,
        project,
        selected,
        0,
    )?;
    let exported = artifact_dir.join("storage-fixture-app");
    let prior_after_retry = file_fingerprint(prior_binary)?;
    let exported_exists = plain_file(&exported)?;
    add_check(
        report,
        "valid-artifact-retry-exports-after-failure",
        exported_exists && prior_after_retry == prior,
        json!({
            "retry_exit_code": retry.status.code(),
            "exported_binary": os_metadata(exported.as_os_str()),
            "prior_binary_before_and_after_retry": prior
        }),
    )?;
    let exported_output = probe
        .command(
            "artifact-exported-executable",
            &exported,
            std::iter::empty(),
            project,
            selected,
            0,
        )?
        .stdout;
    add_check(
        report,
        "artifact-retry-executable-has-valid-fixture-output",
        exported_output == expected_output,
        json!({"output_sha256": digest::sha256_bytes(&exported_output)}),
    )?;
    add_check(
        report,
        "artifact-failure-retry-restores-project-inputs",
        snapshot(project)? == project_before,
        json!({"project_snapshot": project_before}),
    )?;
    Ok(())
}

fn artifact_args(artifact_dir: &Path) -> Vec<OsString> {
    [
        strings(["--config", "env.RC2_PRECEDENCE_MARKER=\"from-cli\""]),
        strings([
            "build",
            "-Z",
            "unstable-options",
            "--locked",
            "--offline",
            "--artifact-dir",
        ]),
        vec![artifact_dir.as_os_str().to_owned()],
    ]
    .concat()
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_linux_non_utf8_cases(
    probe: &mut Probe<'_>,
    report: &mut Value,
    control: &Path,
    derived: &Path,
    project: &Path,
    cargo_home: &Path,
    cache: &Path,
    control_env: &BTreeMap<OsString, OsString>,
    selected: &BTreeMap<OsString, OsString>,
    selected_metadata_env: &BTreeMap<OsString, OsString>,
    cli: &[OsString],
    metadata_args: &[OsString],
) -> Result<()> {
    use std::os::unix::ffi::OsStringExt;

    let work = probe.work.clone();
    let non_utf8_cache = work.join(OsString::from_vec(b"private-cache-\xff".to_vec()));
    create_private_directory(&non_utf8_cache)?;
    fs::set_permissions(&non_utf8_cache, fs::Permissions::from_mode(0o755))
        .map_err(|error| Refusal::new(format!("cannot set non-UTF-8 cache mode: {error}")))?;
    let mut non_utf8_env = selected.clone();
    insert_env(
        &mut non_utf8_env,
        "AMI_RUST_CARGO_STORAGE_ROOT",
        non_utf8_cache.as_os_str(),
    );
    let target = work.join("linux non-UTF-8 target");
    insert_env(&mut non_utf8_env, "CARGO_TARGET_DIR", target.as_os_str());
    let home_before = snapshot(cargo_home)?;
    let selected_cache_before = snapshot(cache)?;
    let metadata = probe
        .cargo(
            "linux-non-utf8-root-metadata",
            derived,
            [cli.to_vec(), metadata_args.to_vec()].concat(),
            project,
            &non_utf8_env,
            0,
        )?
        .stdout;
    parse_json(&metadata, "Linux non-UTF-8 root metadata")?;
    probe.cargo(
        "linux-non-utf8-root-local-fetch",
        derived,
        [cli.to_vec(), strings(["fetch", "--locked"])].concat(),
        project,
        &non_utf8_env,
        0,
    )?;
    let non_utf8_snapshot = snapshot(&non_utf8_cache)?;
    let metadata_root = fs::symlink_metadata(&non_utf8_cache)
        .map_err(|error| Refusal::new(format!("cannot inspect Linux non-UTF-8 cache: {error}")))?;
    let work_owner = fs::metadata(&work)
        .map_err(|error| Refusal::new(format!("cannot inspect probe work owner: {error}")))?
        .uid();
    add_check(
        report,
        "linux-non-utf8-root-preserves-bytes-and-routes-git-cache-owned-0755",
        metadata_root.uid() == work_owner
            && metadata_root.mode() & 0o7777 == 0o755
            && non_utf8_cache
                .as_os_str()
                .as_bytes()
                .ends_with(b"private-cache-\xff")
            && plain_directory(&non_utf8_cache.join("git/db"))?
            && plain_directory(&non_utf8_cache.join("git/checkouts"))?
            && non_utf8_snapshot
                .iter()
                .any(|row| row["path"] == "git/db" && row["kind"] == "dir")
            && non_utf8_snapshot
                .iter()
                .any(|row| row["path"] == "git/checkouts" && row["kind"] == "dir")
            && snapshot(&non_utf8_cache.join("git/checkouts"))?
                .iter()
                .any(|row| {
                    row["path"]
                        .as_str()
                        .is_some_and(|path| path.ends_with("src/lib.rs"))
                        && row["kind"] == "file"
                        && row["sha256"] == digest::sha256_bytes(b"pub fn value()->u32{42}\n")
                })
            && home_before == snapshot(cargo_home)?
            && selected_cache_before == snapshot(cache)?,
        json!({
            "raw_root": os_metadata(non_utf8_cache.as_os_str()),
            "cache_snapshot": non_utf8_snapshot
        }),
    )?;

    let mut same_target_env = non_utf8_env.clone();
    if let Some(target) = selected_metadata_env.get(OsStr::new("CARGO_TARGET_DIR")) {
        insert_env(&mut same_target_env, "CARGO_TARGET_DIR", target);
    }
    let literal_args = [
        strings([
            "--config",
            "build.build-dir=\"literal intermediate with spaces\"",
        ]),
        cli.to_vec(),
        metadata_args.to_vec(),
    ]
    .concat();
    let control_literal = probe
        .cargo(
            "linux-non-utf8-literal-build-dir-control",
            control,
            literal_args.clone(),
            project,
            control_env,
            0,
        )?
        .stdout;
    let derived_literal = probe
        .cargo(
            "linux-non-utf8-literal-build-dir-derived",
            derived,
            literal_args,
            project,
            &same_target_env,
            0,
        )?
        .stdout;
    let literal_json = parse_json(&derived_literal, "Linux literal build directory metadata")?;
    let literal_expected = project.join("literal intermediate with spaces");
    let literal_expected_string = literal_expected.to_string_lossy();
    add_check(
        report,
        "linux-non-utf8-cache-literal-build-dir-metadata-equivalence",
        control_literal == derived_literal
            && literal_json["build_directory"].as_str() == Some(literal_expected_string.as_ref()),
        json!({
            "literal_build_directory": os_metadata(literal_expected.as_os_str()),
            "metadata_sha256": digest::sha256_bytes(&derived_literal)
        }),
    )?;

    // The pinned compiler itself requires UTF-8 argv. Characterize the same
    // boundary through the original Cargo before checking raw template routing;
    // exit101 here is not successful compilation or a derived-Cargo regression.
    let rustc = probe
        .tools
        .iter()
        .find(|tool| tool.name == "rustc")
        .ok_or_else(|| Refusal::new("probe has no selected rustc"))?
        .path
        .clone();
    let compiler_version = probe.command(
        "linux-pinned-rustc-utf8-version",
        &rustc,
        strings(["--version"]),
        project,
        control_env,
        0,
    )?;
    let compiler_raw = probe.command(
        "linux-pinned-rustc-non-utf8-argv",
        &rustc,
        vec![
            OsString::from("--version"),
            OsString::from_vec(b"raw-\xff".to_vec()),
        ],
        project,
        control_env,
        101,
    )?;
    add_check(
        report,
        "linux-pinned-rustc-non-utf8-argv-limitation",
        compiler_version.stdout.starts_with(b"rustc 1.98.1 ")
            && pinned_non_utf8_compiler_panic(&compiler_raw.stderr),
        json!({"utf8_version_exit":0,"non_utf8_argv_exit":101,
            "unsupported_compiler_path":true,"successful_compilation":false}),
    )?;
    let mut original_raw_env = control_env.clone();
    insert_env(
        &mut original_raw_env,
        "CARGO_TARGET_DIR",
        non_utf8_cache.join("original compiler target").as_os_str(),
    );
    let original_raw = probe.cargo(
        "linux-original-cargo-non-utf8-target-check",
        control,
        [cli.to_vec(), strings(["check", "--locked", "--offline"])].concat(),
        project,
        &original_raw_env,
        101,
    )?;
    add_check(
        report,
        "linux-original-cargo-non-utf8-target-same-compiler-limitation",
        pinned_non_utf8_compiler_panic(&original_raw.stderr),
        json!({"original_cargo_exit":101,"same_pinned_compiler_panic":true,
            "successful_compilation":false}),
    )?;
    // Original Cargo legitimately touched its original store. Snapshot after
    // the control so only the subsequent derived command must preserve it.
    let home_after_original = snapshot(cargo_home)?;
    let template_check = probe.cargo(
        "linux-non-utf8-cache-template-compiler-limitation",
        derived,
        [
            strings([
                "--config",
                "build.build-dir=\"{cargo-cache-home}/intermediate/{workspace-path-hash}\"",
            ]),
            cli.to_vec(),
            strings(["check", "--locked", "--offline"]),
        ]
        .concat(),
        project,
        &same_target_env,
        101,
    )?;
    let intermediate = non_utf8_cache.join("intermediate");
    let intermediate_snapshot = snapshot(&intermediate)?;
    let cache_after_template = snapshot(&non_utf8_cache)?;
    let intermediate_has_build_effect = intermediate_snapshot
        .iter()
        .any(|row| row["path"] != "." && row["kind"] == "dir")
        && intermediate_snapshot
            .iter()
            .any(|row| row["kind"] == "file" && row["bytes"].as_u64().unwrap_or(0) > 0);
    let no_unexpanded_template = intermediate_snapshot.iter().all(|row| {
        row["path"] == "."
            || row["path"]
                .as_str()
                .is_some_and(|path| !path.contains('{') && !path.contains('}'))
    });
    let routed_root = intermediate
        .as_os_str()
        .as_bytes()
        .starts_with(non_utf8_cache.as_os_str().as_bytes())
        && intermediate
            .as_os_str()
            .as_bytes()
            .ends_with(b"private-cache-\xff/intermediate");
    add_check(
        report,
        "linux-non-utf8-cache-template-preserves-OS-root-and-compiler-limitation",
        routed_root
            && plain_directory(&intermediate)?
            && intermediate_has_build_effect
            && no_unexpanded_template
            && cache_after_template
                .iter()
                .any(|row| row["path"] == "intermediate" && row["kind"] == "dir")
            && template_check.status.code() == Some(101)
            && pinned_non_utf8_compiler_panic(&template_check.stderr)
            && home_after_original == snapshot(cargo_home)?
            && selected_cache_before == snapshot(cache)?,
        json!({
            "raw_cache_root": os_metadata(non_utf8_cache.as_os_str()),
            "intermediate_root": os_metadata(intermediate.as_os_str()),
            "intermediate_snapshot": intermediate_snapshot,
            "template_variables_expanded": no_unexpanded_template,
            "selected_cache_snapshot": cache_after_template,
            "check_stdout_sha256": digest::sha256_bytes(&template_check.stdout),
            "check_stderr_sha256": digest::sha256_bytes(&template_check.stderr),
            "metadata_json_serialization_asserted": false,
            "successful_compilation": false,
            "unsupported_compiler_path": true,
            "unchanged_original_and_direct_compiler_share_failure": true
        }),
    )?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn pinned_non_utf8_compiler_panic(stderr: &[u8]) -> bool {
    [
        b"panicked at /rustc/48a229ceaefd4985c50990b14116b6d856af0985/".as_slice(),
        b"library/std/src/env.rs:",
        b"called `Result::unwrap()` on an `Err` value:",
        b"\\xFF",
    ]
    .iter()
    .all(|needle| stderr.windows(needle.len()).any(|window| window == *needle))
}

fn add_check(report: &mut Value, name: &str, passed: bool, details: Value) -> Result<()> {
    report["checks"]
        .as_array_mut()
        .ok_or_else(|| Refusal::new("probe report checks field is not an array"))?
        .push(json!({
            "name": name,
            "passed": passed,
            "details": details
        }));
    if passed {
        Ok(())
    } else {
        Err(Refusal::new(format!(
            "Cargo storage probe check failed: {name}"
        )))
    }
}

fn snapshot(root: &Path) -> Result<Vec<Value>> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Refusal::new(format!(
                "cannot inspect fixture snapshot root {}: {error}",
                root.display()
            )));
        }
        Ok(_) => {}
    }
    let mut rows = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Refusal::new(format!(
                "cannot inspect fixture snapshot entry {}: {error}",
                path.display()
            ))
        })?;
        let relative = path
            .strip_prefix(root)
            .map_err(|error| Refusal::new(format!("snapshot path escaped its root: {error}")))?;
        let relative = if relative.as_os_str().is_empty() {
            OsStr::new(".")
        } else {
            relative.as_os_str()
        };
        let file_type = metadata.file_type();
        let mut row = json!({
            "path": relative.to_string_lossy(),
            "path_debug": format!("{relative:?}"),
            "path_unix_bytes_hex": hex(relative.as_bytes()),
            "mode": format!("{:04o}", metadata.mode() & 0o7777),
            "uid": metadata.uid(),
            "mtime_seconds": metadata.mtime(),
            "mtime_nanoseconds": metadata.mtime_nsec()
        });
        if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|error| {
                Refusal::new(format!(
                    "cannot read literal fixture symlink {}: {error}",
                    path.display()
                ))
            })?;
            row["kind"] = json!("symlink");
            row["symlink_target"] = os_metadata(target.as_os_str());
            row["symlink_target_unix_bytes_hex"] = json!(hex(target.as_os_str().as_bytes()));
        } else if file_type.is_file() {
            row["kind"] = json!("file");
            row["bytes"] = json!(metadata.len());
            row["sha256"] = json!(sha256_file(&path)?);
        } else if file_type.is_dir() {
            row["kind"] = json!("dir");
            let mut children = Vec::new();
            let entries = fs::read_dir(&path).map_err(|error| {
                Refusal::new(format!(
                    "cannot traverse fixture directory {}: {error}",
                    path.display()
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|error| {
                    Refusal::new(format!("cannot read fixture directory entry: {error}"))
                })?;
                children.push(entry.path());
            }
            children.sort_by(|left, right| {
                left.as_os_str()
                    .as_bytes()
                    .cmp(right.as_os_str().as_bytes())
            });
            stack.extend(children.into_iter().rev());
        } else {
            return Err(Refusal::new(format!(
                "unsupported special fixture entry at {}",
                path.display()
            )));
        }
        rows.push(row);
    }
    Ok(rows)
}

fn plain_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Refusal::new(format!(
            "cannot inspect expected file {}: {error}",
            path.display()
        ))),
    }
}

fn plain_directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Refusal::new(format!(
            "cannot inspect expected directory {}: {error}",
            path.display()
        ))),
    }
}

fn file_fingerprint(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("cannot inspect prior binary: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Refusal::new("prior executable is not a plain file"));
    }
    Ok(json!({
        "bytes": metadata.len(),
        "mode": format!("{:04o}", metadata.mode() & 0o7777),
        "sha256": sha256_file(path)?
    }))
}

fn sqlite_database(path: &Path) -> Result<bool> {
    if !plain_file(path)? {
        return Ok(false);
    }
    let mut file = File::open(path).map_err(|error| {
        Refusal::new(format!("cannot read Cargo global cache database: {error}"))
    })?;
    let mut header = [0_u8; SQLITE_HEADER.len()];
    let read = file
        .read(&mut header)
        .map_err(|error| Refusal::new(format!("cannot read SQLite header: {error}")))?;
    Ok(read == SQLITE_HEADER.len() && &header == SQLITE_HEADER)
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value> {
    serde_json::from_slice(bytes)
        .map_err(|error| Refusal::new(format!("cannot parse {label}: {error}")))
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

fn insert_env(env: &mut BTreeMap<OsString, OsString>, key: &str, value: &OsStr) {
    env.insert(OsString::from(key), value.to_os_string());
}

fn with_selector(env: &BTreeMap<OsString, OsString>, root: &Path) -> BTreeMap<OsString, OsString> {
    let mut selected = env.clone();
    insert_env(
        &mut selected,
        "AMI_RUST_CARGO_STORAGE_ROOT",
        root.as_os_str(),
    );
    selected
}

fn environment_metadata(env: &BTreeMap<OsString, OsString>) -> Value {
    Value::Array(
        env.iter()
            .map(|(key, value)| {
                json!({
                    "key": os_metadata(key.as_os_str()),
                    "value": os_metadata(value.as_os_str())
                })
            })
            .collect(),
    )
}

fn status_metadata(status: &ExitStatus) -> Value {
    json!({
        "success": status.success(),
        "exit_code": status.code(),
        "signal": status.signal()
    })
}

fn log_metadata(output: &Path, path: &Path, bytes: &[u8]) -> Value {
    let relative = path.strip_prefix(output).unwrap_or(path);
    json!({
        "path": relative.to_string_lossy(),
        "bytes": bytes.len(),
        "sha256": digest::sha256_bytes(bytes)
    })
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            Refusal::new(format!(
                "cannot create raw command log {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(bytes).map_err(|error| {
        Refusal::new(format!(
            "cannot write raw command log {}: {error}",
            path.display()
        ))
    })
}

fn write_text(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents)
        .map_err(|error| Refusal::new(format!("cannot write fixture {}: {error}", path.display())))
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Refusal::new(format!(
            "cannot inspect fixture path {}: {error}",
            path.display()
        ))),
    }
}

fn file_uri(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        return Err(Refusal::new("local Git fixture path is not absolute"));
    }
    let mut uri = String::from("file://");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(byte) {
            uri.push(char::from(*byte));
        } else {
            uri.push('%');
            uri.push(hex_digit(byte >> 4));
            uri.push(hex_digit(byte & 0x0f));
        }
    }
    Ok(uri)
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a TOML basic string cannot fail")
}

fn os_metadata(value: &OsStr) -> Value {
    json!({
        "display_lossy": value.to_string_lossy(),
        "debug": format!("{value:?}"),
        "unix_bytes_hex": hex(value.as_bytes())
    })
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    char::from(HEX[usize::from(value & 0x0f)])
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn set_failure(report: &mut Value, error: &Refusal) {
    report["status"] = json!("FAIL");
    report["rc2_accepted"] = json!(false);
    report["error"] = json!(error.to_string());
}

fn write_report(output: &Path, report: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report).map_err(|error| {
        Refusal::new(format!(
            "cannot serialize Cargo storage probe result: {error}"
        ))
    })?;
    let temporary = output.join("result.json.tmp");
    let final_path = output.join("result.json");
    fs::write(&temporary, bytes).map_err(|error| {
        Refusal::new(format!("cannot write Cargo storage probe result: {error}"))
    })?;
    fs::rename(&temporary, &final_path).map_err(|error| {
        Refusal::new(format!(
            "cannot publish Cargo storage probe result: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ami-rust-storage-snapshot-{label}-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        create_private_directory(&path).unwrap();
        path
    }

    #[test]
    fn compiler_path_boundary_requires_exact_original_panic_cause() {
        let actual = br#"thread 'main' (61) panicked at /rustc/48a229ceaefd4985c50990b14116b6d856af0985/library/std/src/env.rs:878:51:
called `Result::unwrap()` on an `Err` value: "raw-\xFF"
"#;
        assert!(pinned_non_utf8_compiler_panic(actual));
        assert!(!pinned_non_utf8_compiler_panic(
            b"error: could not compile fixture"
        ));
        let other_source = String::from_utf8_lossy(actual)
            .replace("48a229ceaefd4985c50990b14116b6d856af0985", "other-compiler");
        assert!(!pinned_non_utf8_compiler_panic(other_source.as_bytes()));
        let other_reason = String::from_utf8_lossy(actual).replace("raw-\\xFF", "normal-path");
        assert!(!pinned_non_utf8_compiler_panic(other_reason.as_bytes()));
    }

    #[test]
    fn snapshot_detects_equal_length_rewrite_with_restored_mtime() {
        let root = root("rewrite");
        let file = root.join("input");
        fs::write(&file, b"first").unwrap();
        let modified = fs::metadata(&file).unwrap().modified().unwrap();
        let before = snapshot(&root).unwrap();
        fs::write(&file, b"other").unwrap();
        File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let after = snapshot(&root).unwrap();
        assert_ne!(before, after);
        assert_eq!(before[1]["mtime_seconds"], after[1]["mtime_seconds"]);
        assert_eq!(
            before[1]["mtime_nanoseconds"],
            after[1]["mtime_nanoseconds"]
        );
        assert_ne!(before[1]["sha256"], after[1]["sha256"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_records_empty_directories_and_literal_symlinks() {
        let root = root("entries");
        let before = snapshot(&root).unwrap();
        fs::create_dir(root.join("empty")).unwrap();
        std::os::unix::fs::symlink("does-not-exist", root.join("literal")).unwrap();
        let after = snapshot(&root).unwrap();
        assert_ne!(before, after);
        assert_eq!(after.len(), 3);
        assert!(
            after
                .iter()
                .any(|row| row["path"] == "empty" && row["kind"] == "dir")
        );
        assert!(
            after
                .iter()
                .any(|row| row["path"] == "literal" && row["kind"] == "symlink")
        );
        fs::remove_dir_all(root).unwrap();
    }
}

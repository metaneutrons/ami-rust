//! Maintainer-only consumer execution. The installed CLI does not depend on this.
use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    files::read_regular_bounded,
    json::{JsonProfile, parse_json_value},
    process_capture::{CaptureLimits, CommandSpec, capture},
    signals::SigtermGuard,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{consumer_report, consumer_runtime};

#[derive(Debug)]
struct Tree {
    role: String,
    path: PathBuf,
}

#[derive(Debug)]
struct Spec {
    command: Vec<String>,
    expected_exit: i32,
    phase: String,
    cwd: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
    read_trees: Vec<Tree>,
    write_trees: Vec<Tree>,
    read_files: BTreeSet<PathBuf>,
    read_directories: BTreeSet<PathBuf>,
    executables: BTreeSet<PathBuf>,
    libraries: BTreeSet<PathBuf>,
    deny_exec: BTreeSet<PathBuf>,
    deny_library: BTreeSet<PathBuf>,
    component_record: Option<PathBuf>,
    derived: Option<Tree>,
    bindings: BTreeMap<PathBuf, String>,
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !["--spec", "--adapter", "--output"]
            .iter()
            .any(|value| key == *value)
        {
            return Err(Refusal::new("unknown native-consumer-observe argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("observation option needs a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("observation options may occur only once"));
        }
    }
    let input = PathBuf::from(crate::take(&mut options, "--spec")?);
    let adapter = fs::canonicalize(PathBuf::from(crate::take(&mut options, "--adapter")?))?;
    let output = PathBuf::from(crate::take(&mut options, "--output")?);
    let raw = read_regular_bounded(
        &input,
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let spec = parse_spec(&raw)?;
    let parent = output
        .parent()
        .ok_or_else(|| Refusal::new("observation output has no parent"))?;
    if !output.is_absolute()
        || fs::canonicalize(parent)? != parent
        || output.symlink_metadata().is_ok()
    {
        return Err(Refusal::new(
            "observation output must be a fresh canonical-parent path",
        ));
    }
    if spec
        .write_trees
        .iter()
        .any(|tree| overlaps(&tree.path, &output))
    {
        return Err(Refusal::new("observation output overlaps consumer writes"));
    }
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let result = execute(&spec, &raw, &adapter, &output);
    if let Err(error) = &result {
        write_new(
            &output.join("failure.json"),
            &encode_json(&json!({
                "schema":"ami-rust-consumer-observation-failure-v1", "error":error.to_string(),
                "claim":"No successful observation or milestone acceptance is established."
            }))?,
        )?;
    }
    result
}

fn execute(spec: &Spec, raw: &[u8], adapter: &Path, output: &Path) -> Result<()> {
    verify_bindings(&spec.bindings)?;
    let mut executables = spec.executables.clone();
    executables.insert(fs::canonicalize(&spec.command[0])?);
    let mut libraries = spec.libraries.clone();
    let mut reads = spec
        .read_trees
        .iter()
        .map(|tree| tree.path.clone())
        .collect::<BTreeSet<_>>();
    let components = if let Some(record) = &spec.component_record {
        component_inputs(record, &mut executables, &mut libraries, &mut reads)?
    } else {
        Value::Null
    };
    let runtime = consumer_runtime::discover(
        executables,
        libraries,
        spec.phase == "build",
        spec.phase == "cold-prepare",
        &spec.cwd,
    )?;
    let self_path = std::env::current_exe()?;
    let observer_sha = sha256_file(&self_path)?;
    let adapter_sha = sha256_file(adapter)?;
    let closure = json!({
        "schema":"ami-rust-consumer-reviewed-input-closure-v1", "spec_sha256":sha256_bytes(raw),
        "observer_sha256":observer_sha, "adapter_sha256":adapter_sha,
        "bindings":spec.bindings, "components":components, "runtime":runtime.evidence,
        "scope":"The caller selects reviewed pinned source/package inputs; these recorded hashes bind them to this invocation. This is not an independent authentication protocol or a detector of arbitrary opaque runtimes."
    });
    let closure_raw = encode_json(&closure)?;
    let closure_sha = sha256_bytes(&closure_raw);
    write_new(&output.join("closure.json"), &closure_raw)?;
    let policy = render_policy(spec, &runtime, reads, &closure_sha)?;
    let policy_path = output.join("policy.txt");
    write_new(&policy_path, policy.as_bytes())?;
    let policy_sha = sha256_bytes(policy.as_bytes());
    let reports = output.join("reports");
    fs::DirBuilder::new().mode(0o700).create(&reports)?;
    let report_dir = reports.join("command");
    let args = [
        OsString::from("--policy"),
        policy_path.clone().into_os_string(),
        OsString::from("--report-dir"),
        report_dir.clone().into_os_string(),
        OsString::from("--run"),
        OsString::from("--"),
    ]
    .into_iter()
    .chain(spec.command.iter().map(OsString::from));
    let command = CommandSpec::new(adapter.as_os_str(), args, &spec.cwd, child_env(spec));
    let signals = SigtermGuard::acquire()?;
    let captured = capture(
        &command,
        CaptureLimits {
            timeout: Duration::from_secs(1200),
            stdout_bytes: 2 * 1024 * 1024,
            stderr_bytes: 2 * 1024 * 1024,
            termination_grace: Duration::from_secs(2),
        },
        || signals.requested(),
    );
    let interrupted = signals.finish_requested()?;
    let captured = captured.map_err(|error| {
        Refusal::new(format!("consumer adapter capture/cleanup failed: {error}"))
    })?;
    if interrupted {
        return Err(Refusal::new(
            "consumer observation interrupted after owned child cleanup",
        ));
    }
    write_new(&output.join("adapter.stdout.raw"), &captured.stdout)?;
    write_new(&output.join("adapter.stderr.raw"), &captured.stderr)?;
    write_new(
        &output.join("adapter-process.json"),
        &encode_json(&json!({
            "program":adapter, "program_sha256":sha256_file(adapter)?, "exit_code":captured.exit_code(),
            "signal":captured.signal(), "elapsed_millis":captured.elapsed.as_millis(),
            "scope":"Outer existing Supervisor remains responsible for aggregate RSS, workspace, logs and deadline accounting."
        }))?,
    )?;
    if captured.signal().is_some() {
        return Err(Refusal::new("consumer adapter terminated by signal"));
    }
    let writes = spec
        .write_trees
        .iter()
        .map(|tree| tree.path.clone())
        .collect::<Vec<_>>();
    let admitted = consumer_report::admit(&consumer_report::ExpectedReport {
        report_dir: &report_dir,
        policy: &policy_path,
        policy_sha256: &policy_sha,
        command: &spec.command,
        expected_exit: spec.expected_exit,
        outer_exit: captured
            .exit_code()
            .ok_or_else(|| Refusal::new("adapter has no exit status"))?,
        network_outbound: spec.phase == "cold-prepare",
        write_roots: &writes,
    })?;
    verify_bindings(&spec.bindings)?;
    verify_driver(&self_path, &observer_sha)?;
    verify_driver(adapter, &adapter_sha)?;
    let stdout = read_regular_bounded(&report_dir.join("stdout.raw"), 1024 * 1024)?;
    let stderr = read_regular_bounded(&report_dir.join("stderr.raw"), 1024 * 1024)?;
    if admitted["stdout"]["sha256"] != sha256_bytes(&stdout)
        || admitted["stderr"]["sha256"] != sha256_bytes(&stderr)
    {
        return Err(Refusal::new("consumer capture changed after admission"));
    }
    // Replay only admitted bytes; persist PASS after both streams succeed.
    // A wrapper/setup exit 2 therefore cannot impersonate a CLI refusal 2.
    std::io::stdout().write_all(&stdout)?;
    std::io::stderr().write_all(&stderr)?;
    write_new(
        &output.join("observation.json"),
        &encode_json(&json!({
            "schema":"ami-rust-consumer-observation-v1", "status":"PASS_EXPECTED_CONSUMER_RESULT_AND_ADAPTER_EVIDENCE",
            "phase":spec.phase, "command":spec.command, "expected_exit":spec.expected_exit,
            "closure_sha256":closure_sha, "adapter_evidence":admitted,
            "claim":"This exact command and expected result passed the declared policy; complete lifecycle, both-host and milestone acceptance remain separate."
        }))?,
    )?;
    Ok(())
}

fn parse_spec(raw: &[u8]) -> Result<Spec> {
    let value = parse_json_value(raw, JsonProfile::PackageMetadataStateSelection)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("observation spec must be an object"))?;
    let fields = [
        "schema",
        "phase",
        "command",
        "expected_exit",
        "cwd",
        "home",
        "tmp",
        "read_trees",
        "write_trees",
        "read_files",
        "read_directories",
        "executables",
        "libraries",
        "deny_exec",
        "deny_library",
        "component_record",
        "derived",
        "bindings",
    ];
    if object.len() != fields.len()
        || fields.iter().any(|key| !object.contains_key(*key))
        || value["schema"] != "ami-rust-consumer-observation-spec-v1"
    {
        return Err(Refusal::new(
            "unsupported or incomplete consumer observation spec",
        ));
    }
    let phase = text(&value["phase"])?;
    if ![
        "verify",
        "install",
        "uninstall",
        "package-consistency",
        "package-authentication",
        "cold-prepare",
        "prepare-refusal",
        "check-inputs",
        "new-project",
        "lock",
        "build",
    ]
    .contains(&phase.as_str())
    {
        return Err(Refusal::new("unsupported consumer observation phase"));
    }
    let mut command = list(&value["command"])?;
    if command.is_empty() || command.len() > 1024 {
        return Err(Refusal::new("invalid observation argv"));
    }
    let command_path = fs::canonicalize(path(&Value::String(command[0].clone()))?)?;
    canonical_file(&command_path)?;
    command[0] = printable(&command_path)?.to_owned();
    let expected_exit = value["expected_exit"]
        .as_i64()
        .filter(|code| (0..=255).contains(code))
        .ok_or_else(|| Refusal::new("expected consumer exit must be an integer in 0..255"))?
        as i32;
    let component_record = optional_path(&value["component_record"])?;
    let derived = if value["derived"].is_null() {
        None
    } else {
        Some(tree(&value["derived"], true)?)
    };
    if (phase == "build" || phase == "cold-prepare") != derived.is_some() {
        return Err(Refusal::new(
            "build and cold prepare require exactly one derived-execution parent",
        ));
    }
    if let Some(tree) = &derived {
        let required = if phase == "build" {
            "consumer-build-parent"
        } else {
            "consumer-state-parent"
        };
        if tree.role != required {
            return Err(Refusal::new("derived role differs from command phase"));
        }
    }
    let mut bindings = BTreeMap::new();
    for item in value["bindings"]
        .as_array()
        .ok_or_else(|| Refusal::new("expected bindings array"))?
    {
        if item.as_object().is_none_or(|row| row.len() != 2) {
            return Err(Refusal::new("binding needs path and sha256"));
        }
        let file = path(&item["path"])?;
        canonical_file(&file)?;
        let digest = text(&item["sha256"])?;
        if !is_sha256_digest(&digest) || bindings.insert(file, digest).is_some() {
            return Err(Refusal::new(
                "invalid or duplicate observation input binding",
            ));
        }
    }
    if bindings.is_empty() || bindings.len() > 1024 {
        return Err(Refusal::new(
            "observation needs bounded reviewed input bindings",
        ));
    }
    let writes = trees(&value["write_trees"])?;
    if bindings
        .keys()
        .any(|file| writes.iter().any(|tree| overlaps(file, &tree.path)))
    {
        return Err(Refusal::new(
            "reviewed input bindings must be outside consumer writes",
        ));
    }
    Ok(Spec {
        command,
        expected_exit,
        phase,
        cwd: canonical_dir(&path(&value["cwd"])?)?,
        home: canonical_dir(&path(&value["home"])?)?,
        tmp: canonical_dir(&path(&value["tmp"])?)?,
        read_trees: trees(&value["read_trees"])?,
        write_trees: writes,
        read_files: paths(&value["read_files"])?,
        read_directories: paths(&value["read_directories"])?,
        executables: paths(&value["executables"])?,
        libraries: paths(&value["libraries"])?,
        deny_exec: paths(&value["deny_exec"])?,
        deny_library: paths(&value["deny_library"])?,
        component_record,
        derived,
        bindings,
    })
}

fn render_policy(
    spec: &Spec,
    runtime: &consumer_runtime::RuntimeInputs,
    mut reads: BTreeSet<PathBuf>,
    closure_sha: &str,
) -> Result<String> {
    let mut lines = vec!["consumer-policy-v1".to_owned()];
    // Upstream Rust install.sh redirects to this exact OS character device.
    // Warm commands and ordinary native builds need no device-write grant.
    if spec.phase == "cold-prepare" {
        lines.push("write-null /dev/null".to_owned());
    }
    let mut ancestors = BTreeSet::new();
    for executable in &runtime.executables {
        lines.push(format!(
            "exec-hash {} {}",
            printable(executable)?,
            sha256_file(executable)?
        ));
        ancestors.extend(executable.ancestors().skip(1).map(Path::to_path_buf));
    }
    let library_targets = selected_library_targets(runtime)?;
    for library in &runtime.libraries {
        let (_, digest) = library_targets
            .get(library)
            .ok_or_else(|| Refusal::new("runtime library has no discovered target binding"))?;
        // The policy path must retain the lookup spelling so the adapter can
        // resolve and verify aliases. Hash the canonical target instead: the
        // no-follow file reader correctly refuses symlink ancestors.
        lines.push(format!("read-library {} {}", printable(library)?, digest));
        ancestors.extend(
            library
                .ancestors()
                .skip(1)
                .filter(|path| path.is_dir())
                .map(Path::to_path_buf),
        );
    }
    reads.extend(runtime.read_trees.iter().cloned());
    for root in reads {
        canonical_dir(&root)?;
        lines.push(format!("read-tree work {}", printable(&root)?));
        ancestors.extend(root.ancestors().skip(1).map(Path::to_path_buf));
    }
    for file in spec
        .read_files
        .union(&runtime.read_files)
        .chain(spec.bindings.keys())
    {
        lines.push(format!("read-file {}", printable(file)?));
        ancestors.extend(
            file.ancestors()
                .skip(1)
                .filter(|path| path.is_dir())
                .map(Path::to_path_buf),
        );
    }
    for tree in &spec.write_trees {
        lines.push(format!(
            "write-tree {} {}",
            tree.role,
            printable(&tree.path)?
        ));
    }
    for executable in &spec.deny_exec {
        lines.push(format!("deny-exec {}", printable(executable)?));
    }
    for library in &spec.deny_library {
        lines.push(format!("deny-library {}", printable(library)?));
    }
    for ancestor in [&spec.cwd, &spec.home, &spec.tmp]
        .into_iter()
        .flat_map(|path| path.ancestors())
    {
        if ancestor.is_dir() {
            ancestors.insert(fs::canonicalize(ancestor)?);
        }
    }
    // Account-home and selected host-input inspection need literal directory
    // access, never an implicit subtree grant.
    for directory in &spec.read_directories {
        canonical_dir(directory)?;
        ancestors.extend(directory.ancestors().map(Path::to_path_buf));
    }
    for directory in &runtime.read_directories {
        canonical_dir(directory)?;
        ancestors.extend(directory.ancestors().map(Path::to_path_buf));
    }
    for lookup in &runtime.read_lookup_metadata {
        // Only macOS discovery emits these alias spellings. They authorize
        // metadata lookup, never data access at a newly resolved target.
        lines.push(format!("read-lookup-metadata {}", printable(lookup)?));
    }
    for directory in ancestors {
        lines.push(format!("read-directory {}", printable(&directory)?));
    }
    if let Some(tree) = &spec.derived {
        lines.push(format!(
            "exec-derived-tree {} {} {}",
            tree.role,
            printable(&tree.path)?,
            closure_sha
        ));
    }
    for (key, value) in child_env(spec) {
        let key = key
            .to_str()
            .ok_or_else(|| Refusal::new("environment key is not UTF-8"))?;
        let value = value
            .to_str()
            .ok_or_else(|| Refusal::new("environment value is not UTF-8"))?;
        lines.push(format!("env {key}={value}"));
    }
    lines.push(format!("cwd {}", printable(&spec.cwd)?));
    lines.push(format!(
        "network {}",
        if spec.phase == "cold-prepare" {
            "outbound"
        } else {
            "deny"
        }
    ));
    Ok(lines.join("\n") + "\n")
}

fn selected_library_targets(
    runtime: &consumer_runtime::RuntimeInputs,
) -> Result<BTreeMap<PathBuf, (PathBuf, String)>> {
    if runtime.libraries.is_empty() {
        return Ok(BTreeMap::new());
    }

    let rows = runtime
        .evidence
        .get("libraries")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("runtime library discovery evidence is missing"))?;
    if rows.len() != runtime.libraries.len() {
        return Err(Refusal::new(
            "runtime library discovery evidence is incomplete",
        ));
    }

    let mut targets = BTreeMap::new();
    for row in rows {
        let object = row.as_object().filter(|object| {
            object.len() == 3
                && object.contains_key("lookup_path")
                && object.contains_key("canonical_path")
                && object.contains_key("sha256")
        });
        let object =
            object.ok_or_else(|| Refusal::new("runtime library discovery row is malformed"))?;
        let lookup_text = object["lookup_path"]
            .as_str()
            .ok_or_else(|| Refusal::new("runtime library lookup path is malformed"))?;
        let canonical_text = object["canonical_path"]
            .as_str()
            .ok_or_else(|| Refusal::new("runtime library canonical path is malformed"))?;
        let digest = object["sha256"]
            .as_str()
            .filter(|value| is_sha256_digest(value))
            .ok_or_else(|| Refusal::new("runtime library digest is malformed"))?;
        let lookup = PathBuf::from(lookup_text);
        let canonical = PathBuf::from(canonical_text);
        if !lookup.is_absolute()
            || !canonical.is_absolute()
            || lookup
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || canonical
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || !runtime.libraries.contains(&lookup)
            || targets
                .insert(lookup, (canonical, digest.to_owned()))
                .is_some()
        {
            return Err(Refusal::new(
                "runtime library discovery evidence has an invalid or duplicate path",
            ));
        }
    }
    if targets.len() != runtime.libraries.len()
        || runtime
            .libraries
            .iter()
            .any(|lookup| !targets.contains_key(lookup))
    {
        return Err(Refusal::new(
            "runtime library discovery evidence does not match selected libraries",
        ));
    }

    for (lookup, (canonical, expected_digest)) in &targets {
        let resolved = fs::canonicalize(lookup).map_err(|error| {
            Refusal::new(format!(
                "could not recheck runtime library lookup {}: {error}",
                lookup.display()
            ))
        })?;
        if resolved != *canonical {
            return Err(Refusal::new(format!(
                "runtime library lookup target changed since discovery: {}",
                lookup.display()
            )));
        }
        let canonical_target = fs::canonicalize(canonical).map_err(|error| {
            Refusal::new(format!(
                "could not recheck runtime library target {}: {error}",
                canonical.display()
            ))
        })?;
        if canonical_target != *canonical {
            return Err(Refusal::new(format!(
                "runtime library target is no longer canonical: {}",
                canonical.display()
            )));
        }
        if sha256_file(canonical)? != *expected_digest {
            return Err(Refusal::new(format!(
                "runtime library target changed since discovery: {}",
                canonical.display()
            )));
        }
    }

    Ok(targets)
}

fn component_inputs(
    record: &Path,
    executables: &mut BTreeSet<PathBuf>,
    libraries: &mut BTreeSet<PathBuf>,
    reads: &mut BTreeSet<PathBuf>,
) -> Result<Value> {
    let raw = read_regular_bounded(
        record,
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let value = parse_json_value(&raw, JsonProfile::PackageMetadataStateSelection)?;
    let components = value["components"]
        .as_object()
        .ok_or_else(|| Refusal::new("component record omits components"))?;
    let required = ["cargo", "collector", "csdk", "rust", "toolchain", "vendor"];
    if components.len() != required.len()
        || required.iter().any(|key| !components.contains_key(*key))
    {
        return Err(Refusal::new(
            "component record differs from the qualified six-component set",
        ));
    }
    let triple = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        _ => return Err(Refusal::new("unsupported consumer observation host")),
    };
    for (kind, component) in components {
        let root = canonical_dir(&path(component)?)?;
        reads.insert(root.clone());
        let relative = match kind.as_str() {
            "cargo" => vec!["bin/cargo".to_owned()],
            "rust" => vec![
                "bin/rustc".to_owned(),
                "bin/rustdoc".to_owned(),
                format!("lib/rustlib/{triple}/bin/rust-lld"),
                format!("lib/rustlib/{triple}/bin/rust-objcopy"),
            ],
            "toolchain" => [
                "clang",
                "lld",
                "llvm-objcopy",
                "llvm-objdump",
                "llvm-nm",
                "llvm-ar",
            ]
            .iter()
            .map(|name| format!("bin/{name}"))
            .collect(),
            "collector" => vec!["bin/aros-collect".to_owned()],
            _ => Vec::new(),
        };
        for item in relative {
            let file = fs::canonicalize(root.join(item))?;
            canonical_file(&file)?;
            executables.insert(file);
        }
        let mut pending = vec![root];
        let mut entries = 0_usize;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                entries += 1;
                if entries > 100_000 {
                    return Err(Refusal::new(
                        "component runtime inventory exceeds entry bound",
                    ));
                }
                let file = entry.path();
                let metadata = fs::symlink_metadata(&file)?;
                if metadata.is_dir() {
                    pending.push(file);
                } else if file.is_file() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.ends_with(".dylib") || name.ends_with(".so") || name.contains(".so.") {
                        if name.to_ascii_lowercase().contains("python") {
                            return Err(Refusal::new(
                                "selected component contains an unexpected Python runtime library",
                            ));
                        }
                        libraries.insert(file);
                    }
                }
            }
        }
    }
    Ok(json!({"record":record, "sha256":sha256_bytes(&raw), "components":components}))
}

fn child_env(spec: &Spec) -> BTreeMap<OsString, OsString> {
    [
        ("PATH", OsString::from("/usr/bin:/bin:/usr/sbin:/sbin")),
        ("HOME", spec.home.clone().into_os_string()),
        ("TMPDIR", spec.tmp.clone().into_os_string()),
        ("LC_ALL", OsString::from("C")),
        ("LANG", OsString::from("C")),
        ("TZ", OsString::from("UTC")),
    ]
    .into_iter()
    .map(|(key, value)| (OsString::from(key), value))
    .collect()
}
fn verify_bindings(bindings: &BTreeMap<PathBuf, String>) -> Result<()> {
    for (path, expected) in bindings {
        if sha256_file(path)? != *expected {
            return Err(Refusal::new(format!(
                "reviewed input changed: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn verify_driver(path: &Path, expected: &str) -> Result<()> {
    if sha256_file(path)? != expected {
        return Err(Refusal::new(
            "observer or adapter changed during consumer execution",
        ));
    }
    Ok(())
}
fn encode_json(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| Refusal::new(format!("cannot serialize consumer observation: {error}")))
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?
        .write_all(raw)?;
    Ok(())
}
fn text(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .ok_or_else(|| Refusal::new("expected observation string"))?;
    if text.contains(['\n', '\r', '\0']) {
        return Err(Refusal::new(
            "observation string contains a policy delimiter",
        ));
    }
    Ok(text.to_owned())
}
fn list(value: &Value) -> Result<Vec<String>> {
    let values = value
        .as_array()
        .filter(|items| items.len() <= 1024)
        .ok_or_else(|| Refusal::new("expected bounded observation string array"))?;
    values.iter().map(text).collect()
}
fn path(value: &Value) -> Result<PathBuf> {
    let path = PathBuf::from(text(value)?);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(Refusal::new(
            "observation paths must be absolute without parent traversal",
        ));
    }
    Ok(path)
}
fn optional_path(value: &Value) -> Result<Option<PathBuf>> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(path(value)?))
    }
}
fn paths(value: &Value) -> Result<BTreeSet<PathBuf>> {
    let items = list(value)?;
    let mut paths = BTreeSet::new();
    for item in &items {
        if !paths.insert(path(&Value::String(item.clone()))?) {
            return Err(Refusal::new("duplicate observation path"));
        }
    }
    Ok(paths)
}
fn tree(value: &Value, derived: bool) -> Result<Tree> {
    if value.as_object().is_none_or(|row| row.len() != 2) {
        return Err(Refusal::new("tree needs exactly role and path"));
    }
    let role = text(&value["role"])?;
    let allowed = if derived {
        &["consumer-build-parent", "consumer-state-parent"][..]
    } else {
        &[
            "source",
            "sdk",
            "state",
            "toolchain",
            "work",
            "target",
            "home",
            "cargo-home",
            "tmp",
        ][..]
    };
    if !allowed.contains(&role.as_str()) {
        return Err(Refusal::new("unsupported observation tree role"));
    }
    Ok(Tree {
        role,
        path: canonical_dir(&path(&value["path"])?)?,
    })
}
fn trees(value: &Value) -> Result<Vec<Tree>> {
    let rows = value
        .as_array()
        .filter(|items| items.len() <= 64)
        .ok_or_else(|| Refusal::new("expected bounded observation tree array"))?;
    let result = rows
        .iter()
        .map(|row| tree(row, false))
        .collect::<Result<Vec<_>>>()?;
    if result
        .iter()
        .map(|tree| &tree.path)
        .collect::<BTreeSet<_>>()
        .len()
        != result.len()
    {
        return Err(Refusal::new("duplicate observation tree"));
    }
    Ok(result)
}
fn printable(path: &Path) -> Result<&str> {
    path.to_str()
        .filter(|text| !text.contains(['\n', '\r', '\0']))
        .ok_or_else(|| Refusal::new("path cannot be represented in policy"))
}
fn canonical_dir(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path)?.is_dir() || fs::canonicalize(path)? != path {
        return Err(Refusal::new(
            "expected a canonical real observation directory",
        ));
    }
    Ok(path.to_path_buf())
}
fn canonical_file(path: &Path) -> Result<&Path> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(Refusal::new("expected regular observation file"));
    }
    Ok(path)
}
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        root: PathBuf,
        value: Value,
        preserve: bool,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "consumer-observer-spec-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            Self::at(root, false)
        }

        fn at(root: PathBuf, preserve: bool) -> Self {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("fixture root must be fresh");
            let root = root.canonicalize().expect("canonical root");
            let binding = root.join("reviewed-input");
            fs::write(&binding, b"reviewed input\n").expect("input");
            let value = json!({"schema":"ami-rust-consumer-observation-spec-v1", "phase":"verify",
                "command":[std::env::current_exe().expect("test executable"), "--fixture"], "expected_exit":0,
                "cwd":root, "home":root, "tmp":root, "read_trees":[], "write_trees":[], "read_files":[], "read_directories":[],
                "executables":[], "libraries":[], "deny_exec":[], "deny_library":[],
                "component_record":null, "derived":null,
                "bindings":[{"path":binding,"sha256":sha256_bytes(b"reviewed input\n")}]});
            Self {
                root,
                value,
                preserve,
            }
        }
        fn parse(&self) -> Result<Spec> {
            parse_spec(&serde_json::to_vec(&self.value).expect("JSON"))
        }
    }

    fn aliased_library_runtime(
        fixture: &Fixture,
    ) -> (PathBuf, PathBuf, consumer_runtime::RuntimeInputs) {
        let target_dir = fixture.root.join("library-target");
        fs::create_dir(&target_dir).expect("library target directory");
        let target = target_dir.join("libfixture.so");
        fs::write(&target, b"runtime library bytes\n").expect("library target");

        let alias_dir = fixture.root.join("library-alias");
        std::os::unix::fs::symlink(&target_dir, &alias_dir).expect("library alias directory");
        let lookup = alias_dir.join("libfixture.so");
        let canonical = fs::canonicalize(&lookup).expect("canonical library target");
        let digest = sha256_file(&canonical).expect("canonical library digest");
        let evidence = json!({"libraries":[{
            "lookup_path":lookup,
            "canonical_path":canonical,
            "sha256":digest,
        }]});
        let runtime = consumer_runtime::RuntimeInputs {
            executables: BTreeSet::new(),
            libraries: BTreeSet::from([lookup.clone()]),
            read_files: BTreeSet::new(),
            read_directories: BTreeSet::new(),
            read_lookup_metadata: BTreeSet::new(),
            read_trees: BTreeSet::new(),
            evidence,
        };
        (lookup, canonical, runtime)
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if !self.preserve {
                fs::remove_dir_all(&self.root).expect("remove own fixture");
            }
        }
    }
    #[test]
    fn selects_only_explicit_phase_and_accepts_expected_cli_refusal_status() {
        let mut fixture = Fixture::new();
        assert!(fixture.parse().is_ok());
        fixture.value["expected_exit"] = json!(2);
        let spec = fixture.parse().expect("expected CLI refusal");
        assert_eq!(spec.expected_exit, 2);
        for invalid in [json!(-1), json!(256), json!(true), json!(2.0)] {
            fixture.value["expected_exit"] = invalid;
            assert!(fixture.parse().is_err());
        }
    }
    #[test]
    fn refuses_unknown_fields_duplicates_and_policy_delimiters() {
        let mut fixture = Fixture::new();
        fixture.value["extra"] = json!("unsupported");
        assert!(fixture.parse().is_err());
        fixture
            .value
            .as_object_mut()
            .expect("object")
            .remove("extra");
        fixture.value["command"][1] = json!("--fixture\nnetwork outbound");
        assert!(fixture.parse().is_err());
        assert!(parse_spec(br#"{"schema":"a","schema":"b"}"#).is_err());
    }
    #[test]
    fn changed_reviewed_binding_is_refused_before_policy_execution() {
        let fixture = Fixture::new();
        let spec = fixture.parse().expect("spec");
        verify_bindings(&spec.bindings).expect("original input");
        fs::write(
            spec.bindings.keys().next().expect("binding"),
            b"altered input",
        )
        .expect("alter");
        assert!(verify_bindings(&spec.bindings).is_err());
    }

    #[test]
    fn observer_and_adapter_identity_checks_reject_changed_bytes() {
        let fixture = Fixture::new();
        let file = fixture.root.join("adapter-fixture");
        fs::write(&file, b"original driver").expect("write driver");
        let digest = sha256_file(&file).expect("digest");
        verify_driver(&file, &digest).expect("unchanged driver");
        fs::write(&file, b"changed driver").expect("change driver");
        assert!(verify_driver(&file, &digest).is_err());
    }

    #[test]
    fn aliased_library_policy_keeps_lookup_spelling_and_binds_canonical_digest() {
        let fixture = Fixture::new();
        let (lookup, canonical, runtime) = aliased_library_runtime(&fixture);
        let digest = sha256_file(&canonical).expect("canonical digest");

        assert!(
            sha256_file(&lookup)
                .expect_err("no-follow file reader refuses alias ancestor")
                .to_string()
                .contains("could not open a path component without following links")
        );
        let policy = render_policy(
            &fixture.parse().expect("spec"),
            &runtime,
            BTreeSet::new(),
            &"a".repeat(64),
        )
        .expect("alias policy");
        assert!(policy.contains(&format!("read-library {} {}\n", lookup.display(), digest)));
        assert!(!policy.contains(&format!("read-library {} ", canonical.display())));
    }

    #[test]
    fn aliased_library_policy_refuses_lookup_retargeting_after_discovery() {
        let fixture = Fixture::new();
        let (lookup, _, runtime) = aliased_library_runtime(&fixture);
        let alias_dir = lookup.parent().expect("alias parent");
        fs::remove_file(alias_dir).expect("remove alias");

        let replacement_dir = fixture.root.join("replacement-target");
        fs::create_dir(&replacement_dir).expect("replacement directory");
        fs::write(
            replacement_dir.join("libfixture.so"),
            b"other library bytes\n",
        )
        .expect("replacement target");
        std::os::unix::fs::symlink(&replacement_dir, alias_dir).expect("retarget alias");

        let error = render_policy(
            &fixture.parse().expect("spec"),
            &runtime,
            BTreeSet::new(),
            &"a".repeat(64),
        )
        .expect_err("changed lookup must refuse");
        assert!(
            error
                .to_string()
                .contains("runtime library lookup target changed since discovery")
        );
    }

    #[test]
    fn aliased_library_policy_refuses_canonical_target_mutation_after_discovery() {
        let fixture = Fixture::new();
        let (_, canonical, runtime) = aliased_library_runtime(&fixture);
        fs::write(&canonical, b"mutated library bytes\n").expect("mutate target");

        let error = render_policy(
            &fixture.parse().expect("spec"),
            &runtime,
            BTreeSet::new(),
            &"a".repeat(64),
        )
        .expect_err("changed target must refuse");
        assert!(
            error
                .to_string()
                .contains("runtime library target changed since discovery")
        );
    }

    #[test]
    fn aliased_library_policy_requires_complete_well_formed_discovery_evidence() {
        let fixture = Fixture::new();
        let (_, _, mut runtime) = aliased_library_runtime(&fixture);
        let original_evidence = runtime.evidence.clone();
        runtime.evidence = json!({"libraries":[]});
        assert!(
            render_policy(
                &fixture.parse().expect("spec"),
                &runtime,
                BTreeSet::new(),
                &"a".repeat(64),
            )
            .expect_err("missing row must refuse")
            .to_string()
            .contains("runtime library discovery evidence is incomplete")
        );

        runtime.evidence = original_evidence;
        runtime.evidence["libraries"][0]["sha256"] = json!("not-a-digest");
        assert!(
            render_policy(
                &fixture.parse().expect("spec"),
                &runtime,
                BTreeSet::new(),
                &"a".repeat(64),
            )
            .expect_err("malformed digest must refuse")
            .to_string()
            .contains("runtime library digest is malformed")
        );
    }

    #[test]
    fn reviewed_binding_cannot_be_inside_a_consumer_write_tree() {
        let mut fixture = Fixture::new();
        fixture.value["write_trees"] = json!([{"role":"work","path":fixture.root}]);
        assert!(fixture.parse().is_err());
    }
    #[test]
    fn build_requires_its_own_derived_parent_and_other_phases_reject_it() {
        let mut fixture = Fixture::new();
        fixture.value["phase"] = json!("build");
        assert!(fixture.parse().is_err());
        fixture.value["derived"] = json!({"role":"consumer-build-parent", "path":fixture.root});
        assert!(fixture.parse().is_ok());
        fixture.value["derived"]["role"] = json!("consumer-state-parent");
        assert!(fixture.parse().is_err());
        fixture.value["phase"] = json!("verify");
        assert!(fixture.parse().is_err());
    }
    #[test]
    fn explicit_directory_read_is_literal_and_never_a_subtree_grant() {
        let mut fixture = Fixture::new();
        fixture.value["read_directories"] = json!([fixture.root]);
        let runtime = consumer_runtime::RuntimeInputs {
            executables: BTreeSet::new(),
            libraries: BTreeSet::new(),
            read_files: BTreeSet::new(),
            read_directories: BTreeSet::new(),
            read_lookup_metadata: BTreeSet::new(),
            read_trees: BTreeSet::new(),
            evidence: Value::Null,
        };
        let policy = render_policy(
            &fixture.parse().expect("spec"),
            &runtime,
            BTreeSet::new(),
            &"a".repeat(64),
        )
        .expect("literal directory policy");
        assert!(policy.contains(&format!("read-directory {}\n", fixture.root.display())));
        assert!(!policy.contains("read-tree "));
        fixture.value["read_directories"] = json!([]);
        let mut runtime_directory = runtime;
        runtime_directory
            .read_directories
            .insert(fixture.root.clone());
        let runtime_policy = render_policy(
            &fixture.parse().expect("spec without explicit directory"),
            &runtime_directory,
            BTreeSet::new(),
            &"a".repeat(64),
        )
        .expect("runtime directory policy");
        assert!(runtime_policy.contains(&format!("read-directory {}\n", fixture.root.display())));
        assert!(!runtime_policy.contains("read-tree ") && !runtime_policy.contains("exec-hash "));
        fixture.value["read_directories"] = json!([fixture.root.join("not-present")]);
        assert!(
            render_policy(
                &fixture.parse().expect("syntactic spec"),
                &runtime_directory,
                BTreeSet::new(),
                &"a".repeat(64)
            )
            .is_err()
        );
    }

    #[test]
    fn rendered_policy_binds_derived_execution_and_explicit_network_phase() {
        let mut fixture = Fixture::new();
        fixture.value["phase"] = json!("cold-prepare");
        fixture.value["derived"] = json!({"role":"consumer-state-parent", "path":fixture.root});
        let spec = fixture.parse().expect("spec");
        let runtime = consumer_runtime::RuntimeInputs {
            executables: BTreeSet::new(),
            libraries: BTreeSet::new(),
            read_files: BTreeSet::new(),
            read_directories: BTreeSet::new(),
            read_lookup_metadata: BTreeSet::new(),
            read_trees: BTreeSet::new(),
            evidence: Value::Null,
        };
        let policy =
            render_policy(&spec, &runtime, BTreeSet::new(), &"a".repeat(64)).expect("policy");
        assert!(policy.contains("network outbound\n"));
        assert!(policy.contains("write-null /dev/null\n"));
        assert!(policy.contains("exec-derived-tree consumer-state-parent "));
        assert!(!policy.contains("env DYLD_") && !policy.contains("env LD_"));
        let fixture = Fixture::new();
        let policy = render_policy(
            &fixture.parse().expect("spec"),
            &runtime,
            BTreeSet::new(),
            &"b".repeat(64),
        )
        .expect("policy");
        assert!(policy.contains("network deny\n") && !policy.contains("exec-derived-tree "));
        assert!(!policy.contains("write-null "));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn create_private_directory(path: &Path) -> std::result::Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| format!("diagnostic path has no parent: {}", path.display()))?;
        if !path.is_absolute()
            || fs::canonicalize(parent).map_err(|error| error.to_string())? != parent
            || fs::symlink_metadata(path).is_ok()
        {
            return Err(format!(
                "diagnostic directory must be fresh under a canonical parent: {}",
                path.display()
            ));
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|error| error.to_string())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn write_diagnostic_json(path: &Path, value: &Value) -> std::result::Result<(), String> {
        let mut raw = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
        raw.push(b'\n');
        write_new(path, &raw).map_err(|error| error.to_string())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn diagnostic_json_file(path: &Path) -> Value {
        read_regular_bounded(path, 2 * 1024 * 1024)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or(Value::Null)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn required_diagnostic_path(name: &str) -> std::result::Result<PathBuf, String> {
        let path =
            PathBuf::from(std::env::var_os(name).ok_or_else(|| {
                format!("missing required diagnostic environment variable {name}")
            })?);
        if !path.is_absolute() {
            return Err(format!("{name} must be an absolute path"));
        }
        Ok(path)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn run_raw_adapter_case(
        label: &str,
        output: &Path,
        adapter: &Path,
        policy: &Path,
        spec: &Spec,
        command: &[String],
    ) -> std::result::Result<Value, String> {
        create_private_directory(output)?;
        let report_dir = output.join("reports/command");
        let arguments = [
            OsString::from("--policy"),
            policy.as_os_str().to_os_string(),
            OsString::from("--report-dir"),
            report_dir.as_os_str().to_os_string(),
            OsString::from("--run"),
            OsString::from("--"),
        ]
        .into_iter()
        .chain(command.iter().map(OsString::from));
        let adapter_command =
            CommandSpec::new(adapter.as_os_str(), arguments, &spec.cwd, child_env(spec));
        use std::os::unix::process::ExitStatusExt;
        let captured = capture(
            &adapter_command,
            CaptureLimits {
                timeout: Duration::from_secs(90),
                stdout_bytes: 1024 * 1024,
                stderr_bytes: 1024 * 1024,
                termination_grace: Duration::from_secs(2),
            },
            || false,
        );
        let (outer_exit, outer_signal, stdout, stderr, capture_error) = match captured {
            Ok(captured) => (
                captured.exit_code(),
                captured.signal(),
                captured.stdout,
                captured.stderr,
                Value::Null,
            ),
            Err(error) => {
                let message = error.to_string();
                (
                    error.status.as_ref().and_then(|status| status.code()),
                    error.status.as_ref().and_then(ExitStatusExt::signal),
                    error.stdout,
                    error.stderr,
                    json!(message),
                )
            }
        };
        write_new(&output.join("adapter.stdout.raw"), &stdout)
            .map_err(|error| error.to_string())?;
        write_new(&output.join("adapter.stderr.raw"), &stderr)
            .map_err(|error| error.to_string())?;
        let report_path = report_dir.join("report.json");
        let report = diagnostic_json_file(&report_path);
        let summary = json!({
            "label":label,
            "command":command,
            "policy_path":policy,
            "outer_exit_code":outer_exit,
            "outer_signal":outer_signal,
            "capture_error":capture_error,
            "child_exit_code":report.get("child_exit_code").cloned().unwrap_or(Value::Null),
            "child_signal":report.get("child_signal").cloned().unwrap_or(Value::Null),
            "launch_error":report.get("launch_error").cloned().unwrap_or(Value::Null),
            "evidence_failures":report.get("evidence_failures").cloned().unwrap_or(Value::Null),
            "report_path":report_path,
            "stdout_path":output.join("reports/command/stdout.raw"),
            "stderr_path":output.join("reports/command/stderr.raw"),
            "adapter_stdout_path":output.join("adapter.stdout.raw"),
            "adapter_stderr_path":output.join("adapter.stderr.raw"),
        });
        write_diagnostic_json(&output.join("case.json"), &summary)?;
        Ok(summary)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn run_linux_git_https_transport_diagnostic() -> std::result::Result<(), String> {
        const URL: &str = "https://github.com/metaneutrons/ami-rust";
        let artifact_root =
            required_diagnostic_path("AMI_RUST_LINUX_GIT_DIAGNOSTIC_ARTIFACT_ROOT")?;
        create_private_directory(&artifact_root)?;
        let mut fixture = Fixture::at(artifact_root.join("fixture"), true);
        let home = fixture.root.join("home");
        let tmp = fixture.root.join("tmp");
        let write_root = fixture.root.join("state-writes");
        let derived = write_root.join("derived");
        for path in [&home, &tmp, &write_root, &derived] {
            create_private_directory(path)?;
        }

        let adapter = fs::canonicalize(required_diagnostic_path(
            "AMI_RUST_LINUX_GIT_DIAGNOSTIC_ADAPTER",
        )?)
        .map_err(|error| error.to_string())?;
        if !fs::metadata(&adapter)
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("configured consumer adapter is not a regular file".to_owned());
        }
        fixture.value["phase"] = json!("cold-prepare");
        fixture.value["command"] = json!([
            "/usr/bin/git",
            "ls-remote",
            "--exit-code",
            URL,
            "refs/heads/main"
        ]);
        fixture.value["expected_exit"] = json!(0);
        fixture.value["cwd"] = json!(fixture.root);
        fixture.value["home"] = json!(home);
        fixture.value["tmp"] = json!(tmp);
        fixture.value["executables"] = json!(["/usr/bin/env"]);
        fixture.value["write_trees"] = json!([{"role":"state", "path":write_root}]);
        fixture.value["derived"] = json!({"role":"consumer-state-parent", "path":derived});
        let raw = serde_json::to_vec_pretty(&fixture.value).map_err(|error| error.to_string())?;
        write_new(&artifact_root.join("spec.json"), &raw).map_err(|error| error.to_string())?;
        let spec = fixture.parse().map_err(|error| error.to_string())?;

        let mut executables = spec.executables.clone();
        executables.insert(fs::canonicalize(&spec.command[0]).map_err(|error| error.to_string())?);
        let runtime =
            consumer_runtime::discover(executables, spec.libraries.clone(), false, true, &spec.cwd)
                .map_err(|error| error.to_string())?;
        write_diagnostic_json(
            &artifact_root.join("runtime-discovery.json"),
            &runtime.evidence,
        )?;
        let exec_path = runtime.evidence["queries"]
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row["label"] == "system git --exec-path")
            })
            .and_then(|row| row["stdout"].as_str())
            .ok_or_else(|| "runtime discovery omitted Git --exec-path evidence".to_owned())?;
        let helper_dir = PathBuf::from(exec_path);
        let canonical_helper = fs::canonicalize(helper_dir.join("git-remote-http"))
            .map_err(|error| error.to_string())?;
        let alias_helper = helper_dir.join("git-remote-https");
        let alias_target = fs::canonicalize(&alias_helper).map_err(|error| error.to_string())?;
        if alias_target != canonical_helper
            || !runtime.executables.contains(&canonical_helper)
            || !runtime
                .executables
                .contains(&fs::canonicalize("/usr/bin/env").map_err(|e| e.to_string())?)
        {
            return Err(
                "runtime discovery did not bind Git, env and the helper alias target".to_owned(),
            );
        }
        write_diagnostic_json(
            &artifact_root.join("helper-resolution.json"),
            &json!({
                "git_exec_path":helper_dir,
                "canonical_helper":canonical_helper,
                "literal_https_alias":alias_helper,
                "literal_https_alias_target":alias_target,
                "same_target":true,
                "source":"consumer_runtime::discover query evidence",
            }),
        )?;

        let main_output = artifact_root.join("git-ls-remote");
        create_private_directory(&main_output)?;
        let main_result = execute(&spec, &raw, &adapter, &main_output);
        let policy = main_output.join("policy.txt");
        if !policy.is_file() {
            return Err(format!(
                "Git observation did not write its exact policy; partial evidence remains in {}: {main_result:?}",
                main_output.display()
            ));
        }
        let main_report_path = main_output.join("reports/command/report.json");
        let main_report = diagnostic_json_file(&main_report_path);
        let main_case = json!({
            "label":"git-ls-remote",
            "command":spec.command,
            "expected_exit":0,
            "execute_result":main_result.as_ref().map(|_| "admitted").unwrap_or("not-admitted"),
            "execute_error":main_result.err().map(|error| error.to_string()),
            "adapter_process":diagnostic_json_file(&main_output.join("adapter-process.json")),
            "child_exit_code":main_report.get("child_exit_code").cloned().unwrap_or(Value::Null),
            "child_signal":main_report.get("child_signal").cloned().unwrap_or(Value::Null),
            "launch_error":main_report.get("launch_error").cloned().unwrap_or(Value::Null),
            "evidence_failures":main_report.get("evidence_failures").cloned().unwrap_or(Value::Null),
            "report_path":main_report_path,
            "stdout_path":main_output.join("reports/command/stdout.raw"),
            "stderr_path":main_output.join("reports/command/stderr.raw"),
            "executed_policy":policy,
            "executed_policy_sha256":sha256_file(&policy).map_err(|error| error.to_string())?,
            "claim":"Raw observation only; the expected exit-0 result is not assumed.",
        });
        write_diagnostic_json(&main_output.join("case.json"), &main_case)?;

        let policy = main_output.join("policy.txt");
        let positive = run_raw_adapter_case(
            "git-version-positive-spawn",
            &artifact_root.join("git-version"),
            &adapter,
            &policy,
            &spec,
            &["/usr/bin/git".into(), "--version".into()],
        )?;
        let canonical = run_raw_adapter_case(
            "canonical-http-helper-empty-stdin",
            &artifact_root.join("canonical-helper"),
            &adapter,
            &policy,
            &spec,
            &[
                "/usr/bin/env".into(),
                canonical_helper.display().to_string(),
                "origin".into(),
                URL.into(),
            ],
        )?;
        let alias = run_raw_adapter_case(
            "literal-https-alias-empty-stdin",
            &artifact_root.join("https-alias"),
            &adapter,
            &policy,
            &spec,
            &[
                "/usr/bin/env".into(),
                alias_helper.display().to_string(),
                "origin".into(),
                URL.into(),
            ],
        )?;
        write_diagnostic_json(
            &artifact_root.join("diagnostic-result.json"),
            &json!({
                "schema":"ami-rust-linux-git-transport-diagnostic-v1",
                "status":"DIAGNOSTIC_CASES_RECORDED_NO_ACCEPTANCE_CLAIM",
                "host":"linux-x86_64",
                "spec_path":artifact_root.join("spec.json"),
                "runtime_discovery_path":artifact_root.join("runtime-discovery.json"),
                "helper_resolution_path":artifact_root.join("helper-resolution.json"),
                "cases":[main_case, positive, canonical, alias],
                "policy":"The direct controls reuse the exact policy written by the Git command observation.",
                "claim":"This distinguishes real Git, a native positive spawn, the canonical HTTP helper and the literal HTTPS alias under one cold-prepare policy. It is diagnostic evidence only; it does not establish RC1 or resource acceptance.",
            }),
        )?;
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "PR-only Linux Git HTTPS transport diagnostic; not an acceptance gate"]
    fn linux_git_https_transport_diagnostic() {
        let artifact =
            std::env::var_os("AMI_RUST_LINUX_GIT_DIAGNOSTIC_ARTIFACT_ROOT").map(PathBuf::from);
        if let Err(error) = run_linux_git_https_transport_diagnostic() {
            if let Some(artifact) = artifact.filter(|path| path.is_dir()) {
                let _ = write_diagnostic_json(
                    &artifact.join("diagnostic-failure.json"),
                    &json!({
                        "status":"DIAGNOSTIC_INCOMPLETE",
                        "error":error,
                        "claim":"No acceptance claim is established; partial evidence is retained.",
                    }),
                );
            }
            panic!("Linux Git transport diagnostic setup failed; inspect retained output: {error}");
        }
    }
}

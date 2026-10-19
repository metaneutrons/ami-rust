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
    let mut ancestors = BTreeSet::new();
    for executable in &runtime.executables {
        lines.push(format!(
            "exec-hash {} {}",
            printable(executable)?,
            sha256_file(executable)?
        ));
        ancestors.extend(executable.ancestors().skip(1).map(Path::to_path_buf));
    }
    for library in &runtime.libraries {
        lines.push(format!(
            "read-library {} {}",
            printable(library)?,
            sha256_file(library)?
        ));
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
    // Account-home resolution needs literal directory access, never a home subtree.
    for directory in &spec.read_directories {
        canonical_dir(directory)?;
        ancestors.extend(directory.ancestors().map(Path::to_path_buf));
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
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "consumer-observer-spec-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("fixture root");
            let root = root.canonicalize().expect("canonical root");
            let binding = root.join("reviewed-input");
            fs::write(&binding, b"reviewed input\n").expect("input");
            let value = json!({"schema":"ami-rust-consumer-observation-spec-v1", "phase":"verify",
                "command":[std::env::current_exe().expect("test executable"), "--fixture"], "expected_exit":0,
                "cwd":root, "home":root, "tmp":root, "read_trees":[], "write_trees":[], "read_files":[], "read_directories":[],
                "executables":[], "libraries":[], "deny_exec":[], "deny_library":[],
                "component_record":null, "derived":null,
                "bindings":[{"path":binding,"sha256":sha256_bytes(b"reviewed input\n")}]});
            Self { root, value }
        }
        fn parse(&self) -> Result<Spec> {
            parse_spec(&serde_json::to_vec(&self.value).expect("JSON"))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("remove own fixture");
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
        fixture.value["read_directories"] = json!([fixture.root.join("not-present")]);
        assert!(
            render_policy(
                &fixture.parse().expect("syntactic spec"),
                &runtime,
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
            read_trees: BTreeSet::new(),
            evidence: Value::Null,
        };
        let policy =
            render_policy(&spec, &runtime, BTreeSet::new(), &"a".repeat(64)).expect("policy");
        assert!(policy.contains("network outbound\n"));
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
    }
}

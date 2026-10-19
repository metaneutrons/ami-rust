// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
struct ExecRule {
    path: PathBuf,
    expected_sha256: Option<String>,
    expected_closure_sha256: Option<String>,
    deferred: bool,
}

#[derive(Clone, Debug)]
struct ExecDerivedTree {
    role: String,
    path: PathBuf,
    source_closure_sha256: String,
}

#[derive(Clone, Debug)]
struct ReadLibraryRule {
    path: PathBuf,
    expected_sha256: String,
    pre_run_sha256: String,
}

#[derive(Debug, Default)]
struct Policy {
    exec: Vec<ExecRule>,
    exec_derived_trees: Vec<ExecDerivedTree>,
    deny_exec: Vec<PathBuf>,
    deny_library: Vec<PathBuf>,
    read_files: Vec<PathBuf>,
    read_directories: Vec<PathBuf>,
    read_libraries: Vec<ReadLibraryRule>,
    read_trees: Vec<(String, PathBuf)>,
    write_trees: Vec<(String, PathBuf)>,
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    network_outbound: bool,
}

#[derive(Debug)]
struct Capture {
    saved: usize,
    total: u64,
    truncated: bool,
    write_error: Option<String>,
}

struct ExecHashCheck {
    path: PathBuf,
    expected_sha256: Option<String>,
    expected_closure_sha256: Option<String>,
    hash_verified_before_run: bool,
    hash_deferred_until_materialized: bool,
    path_missing_before_run: bool,
    post_run_sha256: Option<String>,
    post_run_hash_matches: Option<bool>,
}

struct ReadLibraryHashCheck {
    path: PathBuf,
    expected_sha256: String,
    pre_run_sha256: String,
    post_run_sha256: Option<String>,
    post_run_hash_matches: bool,
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub(crate) fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--control") {
        if let Err(error) = control(&args[1..]) {
            eprintln!("adapter control error: {error}");
            process::exit(2);
        }
        return;
    }
    match run(&args) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("consumer-enforcement-adapter: {error}");
            process::exit(2);
        }
    }
}

fn run(args: &[String]) -> Result<i32, String> {
    if env::consts::OS != "macos" {
        return Err(format!(
            "macOS adapter only; host is {}-{}",
            env::consts::OS,
            env::consts::ARCH
        ));
    }
    let sep = args.iter().position(|arg| arg == "--").ok_or_else(|| {
        "usage: adapter --policy FILE --report-dir DIR --run -- /absolute/command [args...]"
            .to_owned()
    })?;
    if sep == 0 || sep + 1 >= args.len() {
        return Err("the --run command vector is empty".to_owned());
    }
    let pre = &args[..sep];
    if !pre.iter().any(|arg| arg == "--run") {
        return Err("expected --run before --".to_owned());
    }
    let policy_path = option(pre, "--policy").ok_or_else(|| "missing --policy FILE".to_owned())?;
    let report_dir_arg =
        option(pre, "--report-dir").ok_or_else(|| "missing --report-dir DIR".to_owned())?;
    let report_dir_arg = absolute_path(report_dir_arg)?;
    fs::create_dir_all(&report_dir_arg).map_err(|e| format!("create report directory: {e}"))?;
    let report_dir =
        fs::canonicalize(&report_dir_arg).map_err(|e| format!("resolve report directory: {e}"))?;
    let policy_path = existing_file(policy_path)?;
    let policy_text = fs::read_to_string(&policy_path).map_err(|e| format!("read policy: {e}"))?;
    let policy = parse_policy(&policy_text)?;
    validate_report_isolation(&report_dir, &policy)?;
    let command_path = existing_executable(&args[sep + 1])?;
    if !policy.exec.iter().any(|item| item.path == command_path) {
        return Err(format!(
            "command is not an exact exec allowlist member: {}",
            command_path.display()
        ));
    }
    if policy.deny_exec.contains(&command_path) {
        return Err(format!(
            "command is explicitly denied: {}",
            command_path.display()
        ));
    }
    let profile = build_profile(&policy);
    let profile_path = report_dir.join("profile.sb");
    write_new(&profile_path, profile.as_bytes())?;

    let stdout_path = report_dir.join("stdout.raw");
    let stderr_path = report_dir.join("stderr.raw");
    let stdout_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_path)
        .map_err(|e| format!("create bounded stdout capture: {e}"))?;
    let stderr_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
        .map_err(|e| format!("create bounded stderr capture: {e}"))?;

    let started = now_micros();
    let mut sandbox_args = vec!["-f".to_owned(), profile_path.display().to_string()];
    sandbox_args.push(command_path.display().to_string());
    sandbox_args.extend(args[sep + 2..].iter().cloned());

    let mut child_command = Command::new(SANDBOX_EXEC);
    child_command
        .args(&sandbox_args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &policy.env {
        child_command.env(name, value);
    }
    if let Some(cwd) = &policy.cwd {
        child_command.current_dir(cwd);
    }

    let launch = child_command.spawn();
    let (status, out_capture, err_capture) = match launch {
        Ok(mut child) => {
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "sandbox stdout pipe missing".to_owned())?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| "sandbox stderr pipe missing".to_owned())?;
            let out_thread = capture_stream(stdout, stdout_file);
            let err_thread = capture_stream(stderr, stderr_file);
            let status = child
                .wait()
                .map_err(|e| format!("wait for sandbox command: {e}"))?;
            let out = out_thread
                .join()
                .map_err(|_| "stdout capture thread panicked".to_owned())?
                .map_err(|e| format!("capture stdout: {e}"))?;
            let err = err_thread
                .join()
                .map_err(|_| "stderr capture thread panicked".to_owned())?
                .map_err(|e| format!("capture stderr: {e}"))?;
            (Some(status), out, err)
        }
        Err(error) => {
            drop(stdout_file);
            drop(stderr_file);
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return Err(format!("launch /usr/bin/sandbox-exec: {error}"));
        }
    };
    let finished = now_micros();
    let code = status.as_ref().and_then(|s| s.code());
    let signal = status.as_ref().and_then(|s| s.signal());
    let adapter_code = code.unwrap_or_else(|| 128 + signal.unwrap_or(1));
    let replay_error = replay_bounded(&stdout_path, &stderr_path).err();
    let hash_checks = verify_exec_hashes(&policy);
    let library_hash_checks = verify_read_library_hashes(&policy);
    let mut evidence_failures = Vec::new();
    for check in &hash_checks {
        if check.expected_sha256.is_some() && check.post_run_hash_matches != Some(true) {
            evidence_failures.push(format!(
                "declared executable hash did not match after run: {}",
                check.path.display()
            ));
        }
    }
    for check in &library_hash_checks {
        if !check.post_run_hash_matches {
            evidence_failures.push(format!(
                "declared library hash did not match after run: {}",
                check.path.display()
            ));
        }
    }
    for (label, capture) in [("stdout", &out_capture), ("stderr", &err_capture)] {
        if let Some(error) = &capture.write_error {
            evidence_failures.push(format!("{label} raw capture write failed: {error}"));
        }
    }
    if let Some(error) = &replay_error {
        evidence_failures.push(format!("bounded output replay failed: {error}"));
    }
    let report_path = report_dir.join("report.json");
    let report = report_json(
        &policy_path,
        &profile_path,
        &command_path,
        &args[sep + 2..],
        started,
        finished,
        code,
        signal,
        &stdout_path,
        &stderr_path,
        &out_capture,
        &err_capture,
        replay_error.as_deref(),
        &evidence_failures,
        &hash_checks,
        &library_hash_checks,
        &policy,
    );
    match write_new(&report_path, report.as_bytes()) {
        Ok(()) => eprintln!(
            "consumer-enforcement-adapter report: {}",
            report_path.display()
        ),
        Err(error) => {
            eprintln!(
                "consumer-enforcement-adapter qualification evidence failed: report write failed: {error}; original child exit_code={code:?} signal={signal:?}"
            );
            return Ok(125);
        }
    }
    if !evidence_failures.is_empty() {
        eprintln!(
            "consumer-enforcement-adapter qualification evidence failed; original child exit_code={code:?} signal={signal:?}"
        );
        for failure in &evidence_failures {
            eprintln!("  {failure}");
        }
        return Ok(125);
    }
    Ok(adapter_code)
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn parse_policy(text: &str) -> Result<Policy, String> {
    let mut policy = Policy::default();
    let mut exec_seen = BTreeSet::new();
    let mut denied_exec = BTreeSet::new();
    let mut future_exec = Vec::new();
    let mut future_derived = Vec::new();
    let mut pending_exec_derived_trees = Vec::new();
    let mut library_seen = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line == "consumer-policy-v1" {
            continue;
        }
        let (kind, rest) = line
            .split_once(' ')
            .ok_or_else(|| format!("policy line {} must have a directive and value", index + 1))?;
        let rest = rest.trim();
        match kind {
            "exec" => {
                let path = existing_executable(rest)?;
                if !exec_seen.insert(path.clone()) {
                    return Err(format!("duplicate exec path {}", path.display()));
                }
                policy.exec.push(ExecRule {
                    path,
                    expected_sha256: None,
                    expected_closure_sha256: None,
                    deferred: false,
                });
            }
            "exec-hash" => {
                let (path_text, hash) = rest
                    .rsplit_once(' ')
                    .ok_or_else(|| format!("{} requires PATH SHA256", kind))?;
                validate_hash(hash)?;
                let path = existing_executable(path_text)?;
                let actual = sha256_file(&path)?;
                if actual != hash {
                    return Err(format!(
                        "exec hash mismatch for {}: expected {hash}, got {actual}",
                        path.display()
                    ));
                }
                if !exec_seen.insert(path.clone()) {
                    return Err(format!("duplicate exec path {}", path.display()));
                }
                policy.exec.push(ExecRule {
                    path,
                    expected_sha256: Some(hash.to_ascii_lowercase()),
                    expected_closure_sha256: None,
                    deferred: false,
                });
            }
            "exec-future" => {
                let (path_text, hash) = rest
                    .rsplit_once(' ')
                    .ok_or_else(|| "exec-future requires PATH SHA256".to_owned())?;
                validate_hash(hash)?;
                future_exec.push((path_text.to_owned(), hash.to_ascii_lowercase()));
            }
            "exec-derived" => {
                let (path_text, closure_hash) = rest
                    .rsplit_once(' ')
                    .ok_or_else(|| "exec-derived requires PATH SOURCE_CLOSURE_SHA256".to_owned())?;
                validate_hash(closure_hash)?;
                future_derived.push((path_text.to_owned(), closure_hash.to_ascii_lowercase()));
            }
            "exec-derived-tree" => {
                let (role, rest) = rest.split_once(' ').ok_or_else(|| {
                    "exec-derived-tree requires ROLE EXISTING_EMPTY_PRIVATE_PARENT SOURCE_CLOSURE_SHA256"
                        .to_owned()
                })?;
                if !["consumer-state-parent", "consumer-build-parent"].contains(&role) {
                    return Err(format!("unreviewed executable-tree role {role:?}"));
                }
                let (path, closure_hash) = rest.rsplit_once(' ').ok_or_else(|| {
                    "exec-derived-tree requires ROLE EXISTING_EMPTY_PRIVATE_PARENT SOURCE_CLOSURE_SHA256"
                        .to_owned()
                })?;
                validate_hash(closure_hash)?;
                pending_exec_derived_trees.push((
                    role.to_owned(),
                    path.to_owned(),
                    closure_hash.to_ascii_lowercase(),
                ));
            }
            "deny-exec" => policy.deny_exec.push(existing_or_future_path(rest)?),
            "deny-library" => policy.deny_library.push(existing_or_future_path(rest)?),
            "read-file" => policy.read_files.push(existing_or_future_path(rest)?),
            "read-directory" => policy.read_directories.push(existing_directory(rest)?),
            "read-library" => {
                let (path_text, hash) = rest
                    .rsplit_once(' ')
                    .ok_or_else(|| "read-library requires PATH SHA256".to_owned())?;
                validate_hash(hash)?;
                let path = existing_regular_file(path_text)?;
                let actual = sha256_file(&path)?;
                if actual != hash.to_ascii_lowercase() {
                    return Err(format!(
                        "read-library hash mismatch for {}: expected {hash}, got {actual}",
                        path.display()
                    ));
                }
                if !library_seen.insert(path.clone()) {
                    return Err(format!("duplicate read-library path {}", path.display()));
                }
                policy.read_libraries.push(ReadLibraryRule {
                    path,
                    expected_sha256: hash.to_ascii_lowercase(),
                    pre_run_sha256: actual,
                });
            }
            "read-tree" => {
                let (role, path) = rest
                    .split_once(' ')
                    .ok_or_else(|| "read-tree requires ROLE PATH".to_owned())?;
                if ![
                    "sdk",
                    "source",
                    "toolchain",
                    "collector",
                    "cargo",
                    "vendor",
                    "state",
                    "work",
                    "home",
                    "tmp",
                    "output",
                    "target-generated-buildscripts",
                    "artifact",
                ]
                .contains(&role)
                {
                    return Err(format!("unreviewed read-tree role {role:?}"));
                }
                policy
                    .read_trees
                    .push((role.to_owned(), existing_directory(path)?));
            }
            "write-tree" => {
                let (role, path) = rest
                    .split_once(' ')
                    .ok_or_else(|| "write-tree requires ROLE PATH".to_owned())?;
                if ![
                    "state",
                    "work",
                    "home",
                    "tmp",
                    "output",
                    "target",
                    "cargo-home",
                    "artifact",
                ]
                .contains(&role)
                {
                    return Err(format!("unreviewed write-tree role {role:?}"));
                }
                policy
                    .write_trees
                    .push((role.to_owned(), existing_directory(path)?));
            }
            "env" => {
                let (name, value) = rest
                    .split_once('=')
                    .ok_or_else(|| "env requires NAME=VALUE".to_owned())?;
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!("invalid environment name {name:?}"));
                }
                if name.starts_with("DYLD_")
                    || name.starts_with("LD_")
                    || name.starts_with("BASH_FUNC_")
                    || ["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"].contains(&name)
                {
                    return Err(format!(
                        "unsafe loader or shell-startup environment variable {name:?}"
                    ));
                }
                policy.env.insert(name.to_owned(), value.to_owned());
            }
            "cwd" => policy.cwd = Some(existing_directory(rest)?),
            "network" => match rest {
                "outbound" => policy.network_outbound = true,
                "deny" => policy.network_outbound = false,
                _ => return Err("network must be outbound or deny".to_owned()),
            },
            _ => {
                return Err(format!(
                    "unknown policy directive {kind:?} at line {}",
                    index + 1
                ));
            }
        }
    }
    for (role, path_text, closure_hash) in pending_exec_derived_trees {
        let path = existing_empty_private_parent(&path_text)?;
        let is_within_owned_root = policy.write_trees.iter().any(|(write_role, root)| {
            ["work", "state", "target"].contains(&write_role.as_str())
                && path.starts_with(root)
                && path != *root
        });
        if !is_within_owned_root {
            return Err(format!(
                "exec-derived-tree must be a strict descendant of a declared work/state/target write-tree: {}",
                path.display()
            ));
        }
        if policy
            .exec_derived_trees
            .iter()
            .any(|tree: &ExecDerivedTree| paths_overlap(&tree.path, &path))
        {
            return Err(format!(
                "exec-derived-tree roots may not overlap: {}",
                path.display()
            ));
        }
        policy.exec_derived_trees.push(ExecDerivedTree {
            role,
            path,
            source_closure_sha256: closure_hash,
        });
    }
    for (path_text, hash) in future_exec {
        let path = future_executable_under_write_roots(&path_text, &policy.write_trees)?;
        let deferred = !Path::new(&path_text).exists();
        if !deferred {
            existing_executable(&path_text)?;
            let actual = sha256_file(&path)?;
            if actual != hash {
                return Err(format!(
                    "exec-future hash mismatch for {}: expected {hash}, got {actual}",
                    path.display()
                ));
            }
        }
        if !exec_seen.insert(path.clone()) {
            return Err(format!("duplicate exec path {}", path.display()));
        }
        policy.exec.push(ExecRule {
            path,
            expected_sha256: Some(hash),
            expected_closure_sha256: None,
            deferred,
        });
    }
    for (path_text, closure_hash) in future_derived {
        let path = future_executable_under_write_roots(&path_text, &policy.write_trees)?;
        let deferred = !Path::new(&path_text).exists();
        if !deferred {
            existing_executable(&path_text)?;
        }
        if !exec_seen.insert(path.clone()) {
            return Err(format!("duplicate exec path {}", path.display()));
        }
        policy.exec.push(ExecRule {
            path,
            expected_sha256: None,
            expected_closure_sha256: Some(closure_hash),
            deferred,
        });
    }
    if policy.exec.is_empty() {
        return Err("policy has no exact exec allowlist entries".to_owned());
    }
    for path in &policy.deny_exec {
        let normalized = normalize_rule_path(path)?;
        if exec_seen.contains(&normalized)
            || policy
                .exec_derived_trees
                .iter()
                .any(|tree| paths_overlap(&tree.path, &normalized))
        {
            return Err(format!(
                "path overlaps an allowed executable path/tree and is denied for exec: {}",
                normalized.display()
            ));
        }
        denied_exec.insert(normalized);
    }
    policy.deny_exec = denied_exec.into_iter().collect();
    dedup_paths(&mut policy.deny_library)?;
    dedup_paths(&mut policy.read_files)?;
    dedup_paths(&mut policy.read_directories)?;
    for denied in &policy.deny_library {
        let overlaps_mapping = policy
            .read_libraries
            .iter()
            .any(|library| paths_overlap(&library.path, denied));
        let overlaps_read = policy
            .read_files
            .iter()
            .any(|path| paths_overlap(path, denied))
            || policy
                .read_trees
                .iter()
                .any(|(_, root)| paths_overlap(root, denied))
            || policy
                .write_trees
                .iter()
                .any(|(_, root)| paths_overlap(root, denied))
            || policy
                .exec
                .iter()
                .any(|rule| paths_overlap(&rule.path, denied))
            || policy
                .exec_derived_trees
                .iter()
                .any(|tree| paths_overlap(&tree.path, denied));
        if overlaps_mapping || overlaps_read {
            return Err(format!(
                "deny-library overlaps a read, mapping, or executable allowance: {}",
                denied.display()
            ));
        }
    }
    for library in &policy.read_libraries {
        let overlaps_execution = policy
            .exec
            .iter()
            .any(|rule| paths_overlap(&rule.path, &library.path))
            || policy
                .exec_derived_trees
                .iter()
                .any(|tree| paths_overlap(&tree.path, &library.path));
        let overlaps_write = policy
            .write_trees
            .iter()
            .any(|(_, root)| paths_overlap(root, &library.path));
        if overlaps_execution || overlaps_write {
            return Err(format!(
                "read-library overlaps an executable or writable allowance: {}",
                library.path.display()
            ));
        }
    }
    Ok(policy)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn dedup_paths(paths: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut set = BTreeSet::new();
    for path in paths.iter() {
        set.insert(normalize_rule_path(path)?);
    }
    *paths = set.into_iter().collect();
    Ok(())
}

fn existing_file(path: &str) -> Result<PathBuf, String> {
    let path = absolute_path(path)?;
    let canonical =
        fs::canonicalize(&path).map_err(|e| format!("resolve {}: {e}", path.display()))?;
    if !canonical.is_file() {
        return Err(format!("not a file: {}", canonical.display()));
    }
    Ok(canonical)
}

fn existing_regular_file(path: &str) -> Result<PathBuf, String> {
    let canonical = existing_file(path)?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("inspect regular file {}: {error}", canonical.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("not a regular file: {}", canonical.display()));
    }
    Ok(canonical)
}

fn existing_empty_private_parent(path: &str) -> Result<PathBuf, String> {
    let requested = absolute_path(path)?;
    let canonical = fs::canonicalize(&requested)
        .map_err(|error| format!("resolve private parent {}: {error}", requested.display()))?;
    if canonical != requested {
        return Err(format!(
            "exec-derived-tree parent must be supplied by its canonical path: {}",
            requested.display()
        ));
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("inspect private parent {}: {error}", canonical.display()))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "exec-derived-tree parent is not a directory: {}",
            canonical.display()
        ));
    }
    // SAFETY: geteuid has no preconditions and returns the effective user ID.
    let effective_uid = unsafe { geteuid() };
    if metadata.uid() != effective_uid {
        return Err(format!(
            "exec-derived-tree parent is not owned by the current effective user: {}",
            canonical.display()
        ));
    }
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(format!(
            "exec-derived-tree parent must have mode 0700: {}",
            canonical.display()
        ));
    }
    if fs::read_dir(&canonical)
        .map_err(|error| {
            format!(
                "inspect private parent contents {}: {error}",
                canonical.display()
            )
        })?
        .next()
        .is_some()
    {
        return Err(format!(
            "exec-derived-tree parent must be empty at policy load: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn existing_executable(path: &str) -> Result<PathBuf, String> {
    let canonical = existing_file(path)?;
    let metadata = fs::metadata(&canonical).map_err(|e| e.to_string())?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("not executable: {}", canonical.display()));
    }
    Ok(canonical)
}

fn existing_directory(path: &str) -> Result<PathBuf, String> {
    let path = absolute_path(path)?;
    let canonical = fs::canonicalize(&path)
        .map_err(|e| format!("resolve directory {}: {e}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("not a directory: {}", canonical.display()));
    }
    Ok(canonical)
}

fn existing_or_future_path(path: &str) -> Result<PathBuf, String> {
    if Path::new(path).exists() {
        let path = absolute_path(path)?;
        return fs::canonicalize(&path).map_err(|e| format!("resolve {}: {e}", path.display()));
    }
    future_executable(path)
}

fn future_executable(path: &str) -> Result<PathBuf, String> {
    resolve_future_path(path)
}

fn future_executable_under_write_roots(
    path: &str,
    write_trees: &[(String, PathBuf)],
) -> Result<PathBuf, String> {
    let candidate = resolve_future_path(path)?;
    if !write_trees
        .iter()
        .any(|(_, root)| candidate.starts_with(root))
    {
        return Err(format!(
            "future exec path must be inside an explicitly declared write-tree: {}",
            candidate.display()
        ));
    }
    Ok(candidate)
}

fn resolve_future_path(path: &str) -> Result<PathBuf, String> {
    let requested = absolute_path(path)?;
    if requested
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "path with .. is not accepted: {}",
            requested.display()
        ));
    }
    if requested.exists() {
        return fs::canonicalize(&requested)
            .map_err(|e| format!("resolve {}: {e}", requested.display()));
    }

    let mut existing = requested.as_path();
    let mut missing = Vec::<OsString>::new();
    while !existing.exists() {
        if fs::symlink_metadata(existing).is_ok() {
            return Err(format!(
                "unresolvable symlink in future path: {}",
                existing.display()
            ));
        }
        let name = existing
            .file_name()
            .ok_or_else(|| format!("future path has no filename: {}", requested.display()))?;
        missing.push(name.to_os_string());
        existing = existing.parent().ok_or_else(|| {
            format!(
                "future path has no existing ancestor: {}",
                requested.display()
            )
        })?;
    }
    let mut resolved = fs::canonicalize(existing)
        .map_err(|e| format!("resolve future path ancestor {}: {e}", existing.display()))?;
    if !missing.is_empty() && !resolved.is_dir() {
        return Err(format!(
            "future path ancestor is not a directory: {}",
            resolved.display()
        ));
    }
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn absolute_path(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    Ok(path.to_path_buf())
}

fn normalize_rule_path(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        fs::canonicalize(path).map_err(|e| format!("resolve policy path {}: {e}", path.display()))
    } else {
        future_executable(&path.to_string_lossy())
    }
}

fn validate_report_isolation(report_dir: &Path, policy: &Policy) -> Result<(), String> {
    for (_, writable) in &policy.write_trees {
        if report_dir.starts_with(writable) || writable.starts_with(report_dir) {
            return Err(format!(
                "report directory overlaps child writable tree: {}",
                writable.display()
            ));
        }
    }
    Ok(())
}

fn build_profile(policy: &Policy) -> String {
    let mut out = String::from(
        "(version 1)\n(deny default)\n(import \"system.sb\")\n(allow process-fork)\n(allow process-info*)\n(allow signal)\n",
    );
    for path in &policy.deny_exec {
        out.push_str(&format!(
            "(deny process-exec (literal \"{}\"))\n",
            scheme_escape(&path.display().to_string())
        ));
    }
    for path in &policy.deny_library {
        out.push_str(&format!(
            "(deny file-read-data file-map-executable (literal \"{}\"))\n",
            scheme_escape(&path.display().to_string())
        ));
    }
    if policy.network_outbound {
        out.push_str("(allow network-outbound)\n");
    }
    for rule in &policy.exec {
        out.push_str(&format!(
            "(allow file-read* file-map-executable (literal \"{}\"))\n",
            scheme_escape(&rule.path.display().to_string())
        ));
    }
    for library in &policy.read_libraries {
        out.push_str(&format!(
            "(allow file-read* file-map-executable (literal \"{}\"))\n",
            scheme_escape(&library.path.display().to_string())
        ));
    }
    for path in &policy.read_files {
        out.push_str(&format!(
            "(allow file-read* (literal \"{}\"))\n",
            scheme_escape(&path.display().to_string())
        ));
    }
    for path in &policy.read_directories {
        out.push_str(&format!(
            "(allow file-read* (literal \"{}\"))\n",
            scheme_escape(&path.display().to_string())
        ));
    }
    for (_, path) in &policy.read_trees {
        out.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            scheme_escape(&path.display().to_string())
        ));
    }
    for (_, path) in &policy.write_trees {
        out.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            scheme_escape(&path.display().to_string())
        ));
    }
    for tree in &policy.exec_derived_trees {
        out.push_str(&format!(
            "(allow file-read* file-map-executable (subpath \"{}\"))\n",
            scheme_escape(&tree.path.display().to_string())
        ));
    }
    let mut executable_scopes = policy
        .exec
        .iter()
        .map(|item| {
            format!(
                "(literal \"{}\")",
                scheme_escape(&item.path.display().to_string())
            )
        })
        .collect::<Vec<_>>();
    executable_scopes.extend(policy.exec_derived_trees.iter().map(|tree| {
        format!(
            "(subpath \"{}\")",
            scheme_escape(&tree.path.display().to_string())
        )
    }));
    out.push_str(&format!(
        "(allow process-exec\n  {})\n",
        executable_scopes.join("\n  ")
    ));
    out
}

fn capture_stream<R: Read + Send + 'static>(
    mut input: R,
    mut output: File,
) -> thread::JoinHandle<io::Result<Capture>> {
    thread::spawn(move || {
        let mut total = 0u64;
        let mut saved = 0usize;
        let mut write_error = None;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total += read as u64;
            if saved < MAX_CAPTURE_BYTES && write_error.is_none() {
                let count = (MAX_CAPTURE_BYTES - saved).min(read);
                let mut offset = 0;
                while offset < count {
                    match output.write(&buffer[offset..count]) {
                        Ok(0) => {
                            write_error = Some("raw output write returned zero bytes".to_owned());
                            break;
                        }
                        Ok(written) => {
                            saved += written;
                            offset += written;
                        }
                        Err(error) => {
                            write_error = Some(error.to_string());
                            break;
                        }
                    }
                }
            }
        }
        if let Err(error) = output.flush() {
            if write_error.is_none() {
                write_error = Some(error.to_string());
            }
        }
        Ok(Capture {
            saved,
            total,
            truncated: total > saved as u64,
            write_error,
        })
    })
}

fn replay_bounded(stdout: &Path, stderr: &Path) -> Result<(), String> {
    io::stdout()
        .write_all(&fs::read(stdout).map_err(|e| e.to_string())?)
        .and_then(|_| io::stdout().flush())
        .map_err(|e| format!("replay stdout: {e}"))?;
    io::stderr()
        .write_all(&fs::read(stderr).map_err(|e| e.to_string())?)
        .and_then(|_| io::stderr().flush())
        .map_err(|e| format!("replay stderr: {e}"))?;
    Ok(())
}

fn report_json(
    policy_path: &Path,
    profile_path: &Path,
    command: &Path,
    args: &[String],
    started: u128,
    finished: u128,
    code: Option<i32>,
    signal: Option<i32>,
    stdout_path: &Path,
    stderr_path: &Path,
    out: &Capture,
    err: &Capture,
    replay_error: Option<&str>,
    evidence_failures: &[String],
    hash_checks: &[ExecHashCheck],
    library_hash_checks: &[ReadLibraryHashCheck],
    policy: &Policy,
) -> String {
    let argv = std::iter::once(command.display().to_string())
        .chain(args.iter().cloned())
        .map(|s| json(&s))
        .collect::<Vec<_>>()
        .join(",");
    let execs = hash_checks.iter().map(|check| {
        let identity = if check.expected_sha256.is_some() {
            "binary-sha256"
        } else if check.expected_closure_sha256.is_some() {
            "reviewed-source-closure"
        } else {
            "literal-path-only"
        };
        format!(
            "{{\"path\":{},\"identity\":{},\"expected_sha256\":{},\"expected_closure_sha256\":{},\"closure_digest_verification\":{},\"hash_verified_before_run\":{},\"hash_deferred_until_materialized\":{},\"path_missing_before_run\":{},\"post_run_sha256\":{},\"post_run_hash_matches\":{}}}",
            json(&check.path.display().to_string()),
            json(identity),
            check.expected_sha256.as_ref().map(|s| json(s)).unwrap_or_else(|| "null".to_owned()),
            check.expected_closure_sha256.as_ref().map(|s| json(s)).unwrap_or_else(|| "null".to_owned()),
            check.expected_closure_sha256.as_ref().map(|_| json("declared by policy; not verified by adapter")).unwrap_or_else(|| "null".to_owned()),
            check.hash_verified_before_run,
            check.expected_sha256.is_some() && check.hash_deferred_until_materialized,
            check.path_missing_before_run,
            check.post_run_sha256.as_ref().map(|s| json(s)).unwrap_or_else(|| "null".to_owned()),
            check.post_run_hash_matches.map(|matched| matched.to_string()).unwrap_or_else(|| "null".to_owned())
        )
    }).collect::<Vec<_>>().join(",");
    let read_library_mappings = library_hash_checks
        .iter()
        .map(|check| {
            format!(
                "{{\"path\":{},\"identity\":\"library-sha256\",\"expected_sha256\":{},\"permissions\":[\"file-read*\",\"file-map-executable\"],\"process_exec\":false,\"hash_verified_before_run\":{},\"pre_run_sha256\":{},\"post_run_sha256\":{},\"post_run_hash_matches\":{}}}",
                json(&check.path.display().to_string()),
                json(&check.expected_sha256),
                check.pre_run_sha256 == check.expected_sha256,
                json(&check.pre_run_sha256),
                check.post_run_sha256.as_ref().map(|hash| json(hash)).unwrap_or_else(|| "null".to_owned()),
                check.post_run_hash_matches,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let exec_derived_trees = policy
        .exec_derived_trees
        .iter()
        .map(|tree| {
            format!(
                "{{\"role\":{},\"path\":{},\"source_closure_sha256\":{},\"source_closure_verification\":\"declared by policy; not verified by adapter\",\"semantics\":\"descendants may be process-executed\"}}",
                json(&tree.role),
                json(&tree.path.display().to_string()),
                json(&tree.source_closure_sha256)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let read_trees = policy
        .read_trees
        .iter()
        .map(|(role, path)| {
            format!(
                "{{\"role\":{},\"path\":{}}}",
                json(role),
                json(&path.display().to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let read_directories = policy
        .read_directories
        .iter()
        .map(|path| {
            format!(
                "{{\"path\":{},\"permissions\":[\"file-read*\"],\"scope\":\"literal-directory-only\"}}",
                json(&path.display().to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let write_trees = policy
        .write_trees
        .iter()
        .map(|(role, path)| {
            format!(
                "{{\"role\":{},\"path\":{}}}",
                json(role),
                json(&path.display().to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let evidence = evidence_failures
        .iter()
        .map(|failure| json(failure))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\n  \"schema\":\"consumer-enforcement-adapter-a1\",\n  \"mechanism\":\"/usr/bin/sandbox-exec, deny default, exact process-exec allowlist plus declared private derived-output subtrees\",\n  \"policy\":{},\n  \"profile\":{},\n  \"command\":[{}],\n  \"started_unix_micros\":{},\n  \"finished_unix_micros\":{},\n  \"exit_code\":{},\n  \"signal\":{},\n  \"stdout\":{{\"path\":{},\"bytes_captured\":{},\"bytes_total\":{},\"truncated\":{},\"write_error\":{}}},\n  \"stderr\":{{\"path\":{},\"bytes_captured\":{},\"bytes_total\":{},\"truncated\":{},\"write_error\":{}}},\n  \"network_outbound_allowed\":{},\n  \"exec_allowlist\":[{}],\n  \"read_library_mappings\":[{}],\n  \"exec_derived_trees\":[{}],\n  \"deny_exec\":[{}],\n  \"deny_library\":[{}],\n  \"read_directories\":[{}],\n  \"read_trees\":[{}],\n  \"write_trees\":[{}],\n  \"environment_names\":[{}],\n  \"cwd\":{},\n  \"output_replay_error\":{},\n  \"qualification_evidence_valid\":{},\n  \"evidence_failures\":[{}]\n}}\n",
        json(&policy_path.display().to_string()),
        json(&profile_path.display().to_string()),
        argv,
        started,
        finished,
        code.map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_owned()),
        signal
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_owned()),
        json(&stdout_path.display().to_string()),
        out.saved,
        out.total,
        out.truncated,
        out.write_error
            .as_ref()
            .map(|error| json(error))
            .unwrap_or_else(|| "null".to_owned()),
        json(&stderr_path.display().to_string()),
        err.saved,
        err.total,
        err.truncated,
        err.write_error
            .as_ref()
            .map(|error| json(error))
            .unwrap_or_else(|| "null".to_owned()),
        policy.network_outbound,
        execs,
        read_library_mappings,
        exec_derived_trees,
        policy
            .deny_exec
            .iter()
            .map(|p| json(&p.display().to_string()))
            .collect::<Vec<_>>()
            .join(","),
        policy
            .deny_library
            .iter()
            .map(|p| json(&p.display().to_string()))
            .collect::<Vec<_>>()
            .join(","),
        read_directories,
        read_trees,
        write_trees,
        policy
            .env
            .keys()
            .map(|k| json(k))
            .collect::<Vec<_>>()
            .join(","),
        policy
            .cwd
            .as_ref()
            .map(|p| json(&p.display().to_string()))
            .unwrap_or_else(|| "null".to_owned()),
        replay_error.map(json).unwrap_or_else(|| "null".to_owned()),
        evidence_failures.is_empty(),
        evidence
    )
}

fn verify_exec_hashes(policy: &Policy) -> Vec<ExecHashCheck> {
    policy
        .exec
        .iter()
        .map(|item| {
            let post = if item.expected_sha256.is_some() && item.path.is_file() {
                sha256_file(&item.path).ok()
            } else {
                None
            };
            let matches = item
                .expected_sha256
                .as_ref()
                .map(|expected| post.as_ref() == Some(expected));
            ExecHashCheck {
                path: item.path.clone(),
                expected_sha256: item.expected_sha256.clone(),
                expected_closure_sha256: item.expected_closure_sha256.clone(),
                hash_verified_before_run: item.expected_sha256.is_some() && !item.deferred,
                hash_deferred_until_materialized: item.deferred,
                path_missing_before_run: item.deferred,
                post_run_sha256: post,
                post_run_hash_matches: matches,
            }
        })
        .collect()
}

fn verify_read_library_hashes(policy: &Policy) -> Vec<ReadLibraryHashCheck> {
    policy
        .read_libraries
        .iter()
        .map(|library| {
            let remains_canonical =
                fs::canonicalize(&library.path).ok().as_deref() == Some(library.path.as_path());
            let remains_regular = fs::symlink_metadata(&library.path)
                .is_ok_and(|metadata| metadata.file_type().is_file());
            let post_run_sha256 = if remains_canonical && remains_regular {
                sha256_file(&library.path).ok()
            } else {
                None
            };
            let post_run_hash_matches =
                post_run_sha256.as_deref() == Some(library.expected_sha256.as_str());
            ReadLibraryHashCheck {
                path: library.path.clone(),
                expected_sha256: library.expected_sha256.clone(),
                pre_run_sha256: library.pre_run_sha256.clone(),
                post_run_sha256,
                post_run_hash_matches,
            }
        })
        .collect()
}

fn control(args: &[String]) -> Result<(), String> {
    let mode = args.first().map(String::as_str).unwrap_or_default();
    match mode {
        "direct" => {
            let python = required(args, "--python")?;
            match Command::new(python)
                .args(["-I", "-S", "-c", "print('ADAPTER_DIRECT_PYTHON_MARKER')"])
                .output()
            {
                Err(error) => println!(
                    "DIRECT_REFUSED path={python} raw_os_error={:?}",
                    error.raw_os_error()
                ),
                Ok(output) => {
                    println!(
                        "DIRECT_ESCAPE status={:?} output={}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stdout)
                    );
                    process::exit(91);
                }
            }
        }
        "transitive" => {
            let python = required(args, "--python")?;
            let self_path = env::current_exe().map_err(|e| e.to_string())?;
            let output = Command::new(self_path)
                .args(["--control", "direct", "--python", python])
                .output()
                .map_err(|e| format!("launch native descendant: {e}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            if output.status.success()
                && stdout.contains("DIRECT_REFUSED")
                && !stdout.contains("ADAPTER_DIRECT_PYTHON_MARKER")
            {
                println!(
                    "TRANSITIVE_REFUSED descendant_exit={} {}",
                    output.status.code().unwrap_or(-1),
                    stdout.trim()
                );
            } else {
                println!(
                    "TRANSITIVE_ESCAPE descendant_exit={:?} {}",
                    output.status.code(),
                    stdout.trim()
                );
                process::exit(92);
            }
        }
        "shebang" => {
            let script = required(args, "--script")?;
            match Command::new(script).output() {
                Err(error) => println!(
                    "SHEBANG_REFUSED path={script} raw_os_error={:?}",
                    error.raw_os_error()
                ),
                Ok(output) => {
                    println!(
                        "SHEBANG_ESCAPE status={:?} output={}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stdout)
                    );
                    process::exit(93);
                }
            }
        }
        "positive-write" => {
            let path = required(args, "--path")?;
            let output = Command::new("/usr/bin/touch")
                .arg(path)
                .status()
                .map_err(|e| e.to_string())?;
            if output.success() {
                println!("NATIVE_WRITE_OK path={path}");
            } else {
                println!("NATIVE_WRITE_FAILED status={output:?}");
                process::exit(output.code().unwrap_or(1));
            }
        }
        "future-materialize" => {
            let source = required(args, "--source")?;
            let target = PathBuf::from(required(args, "--path")?);
            let delete_after = args.iter().any(|arg| arg == "--delete-after");
            if target.exists() {
                return Err(format!(
                    "future-exec destination already exists: {}",
                    target.display()
                ));
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("create nested future-exec parent: {e}"))?;
            }
            fs::copy(source, &target).map_err(|e| format!("materialize future executable: {e}"))?;
            let mut permissions = fs::metadata(&target)
                .map_err(|e| e.to_string())?
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&target, permissions).map_err(|e| e.to_string())?;
            match Command::new(&target).status() {
                Ok(status) if status.success() => {
                    if delete_after {
                        fs::remove_file(&target)
                            .map_err(|e| format!("remove transient executable after run: {e}"))?;
                        println!(
                            "FUTURE_EXEC_OK path={} removed_after_execution=true",
                            target.display()
                        );
                    } else {
                        println!("FUTURE_EXEC_OK path={}", target.display());
                    }
                }
                Ok(status) => {
                    println!(
                        "FUTURE_EXEC_NONZERO path={} status={status:?}",
                        target.display()
                    );
                    process::exit(status.code().unwrap_or(1));
                }
                Err(error) => {
                    println!(
                        "FUTURE_EXEC_REFUSED path={} error={error}",
                        target.display()
                    );
                    process::exit(95);
                }
            }
        }
        "embedded" => {
            let binary = required(args, "--binary")?;
            match Command::new(binary).output() {
                Err(error) => println!(
                    "EMBEDDED_REFUSED path={binary} raw_os_error={:?}",
                    error.raw_os_error()
                ),
                Ok(output)
                    if !output.status.success()
                        && !String::from_utf8_lossy(&output.stderr).is_empty() =>
                {
                    println!(
                        "EMBEDDED_LIBRARY_REFUSED status={:?} stderr={}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Ok(output) => {
                    println!(
                        "EMBEDDED_ESCAPE status={:?} stdout={}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stdout)
                    );
                    process::exit(94);
                }
            }
        }
        _ => return Err(format!("unknown control mode {mode:?}")),
    }
    Ok(())
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))
}

fn now_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn scheme_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn json(value: &str) -> String {
    let mut result = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c <= '\u{1f}' => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

fn validate_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid SHA-256 {hash:?}"));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("read for SHA-256 {}: {e}", path.display()))?;
    Ok(hex(&sha256(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut data = input.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(bytes.try_into().expect("four bytes"));
        }
        for i in 16..64 {
            let a = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let b = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(a)
                .wrapping_add(w[i - 7])
                .wrapping_add(b);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_test_root(label: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "consumer-adapter-macos-a1-{label}-{}-{}",
            process::id(),
            now_micros()
        ));
        fs::create_dir_all(&path).expect("create private test root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("restrict private test root");
        fs::canonicalize(path).expect("canonicalize test root")
    }

    fn create_private_directory(path: &Path) {
        fs::create_dir_all(path).expect("create test directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("set test directory mode");
    }

    fn executable_path() -> PathBuf {
        fs::canonicalize(env::current_exe().expect("test executable path"))
            .expect("canonicalize test executable")
    }

    fn test_capture() -> Capture {
        Capture {
            saved: 0,
            total: 0,
            truncated: false,
            write_error: None,
        }
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn read_library_is_hashed_and_reported_separately_without_process_exec() {
        let root = private_test_root("read-library");
        let library = root.join("libfixture.dylib");
        fs::write(&library, b"signed fixture library").expect("write library fixture");
        let digest = sha256_file(&library).expect("hash fixture library");
        let executable = executable_path();
        let policy_text = format!(
            "consumer-policy-v1\nexec {}\nread-library {} {}\n",
            executable.display(),
            library.display(),
            digest
        );
        let policy = parse_policy(&policy_text).expect("accept matching library hash");
        assert_eq!(policy.read_libraries.len(), 1);
        assert_eq!(policy.read_libraries[0].path, library);
        assert!(policy.exec.iter().all(|rule| rule.path != library));

        let profile = build_profile(&policy);
        assert!(profile.contains(&format!(
            "(allow file-read* file-map-executable (literal \"{}\"))",
            library.display()
        )));
        let process_exec = profile
            .split("(allow process-exec")
            .nth(1)
            .expect("process-exec rule")
            .split(')')
            .next()
            .expect("process-exec rule body");
        assert!(!process_exec.contains(&library.display().to_string()));

        let checks = verify_read_library_hashes(&policy);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].pre_run_sha256, digest);
        assert!(checks[0].post_run_hash_matches);
        let report = report_json(
            Path::new("/policy"),
            Path::new("/profile"),
            &executable,
            &[],
            1,
            2,
            Some(0),
            None,
            Path::new("/stdout"),
            Path::new("/stderr"),
            &test_capture(),
            &test_capture(),
            None,
            &[],
            &verify_exec_hashes(&policy),
            &checks,
            &policy,
        );
        let exact_exec_field = report
            .split("\"exec_allowlist\":[")
            .nth(1)
            .and_then(|tail| tail.split(']').next())
            .expect("exec allowlist field");
        assert!(!exact_exec_field.contains(&library.display().to_string()));
        assert!(report.contains(&format!(
            "\"path\":\"{}\",\"identity\":\"library-sha256\"",
            library.display()
        )));
        assert!(report.contains("\"process_exec\":false"));
        assert!(report.contains("\"permissions\":[\"file-read*\",\"file-map-executable\"]"));

        fs::write(&library, b"changed library").expect("mutate library fixture");
        assert!(!verify_read_library_hashes(&policy)[0].post_run_hash_matches);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn read_library_rejects_bad_hash_and_explicit_deny_overlap() {
        let root = private_test_root("read-library-invalid");
        let library = root.join("libfixture.dylib");
        fs::write(&library, b"fixture").expect("write library fixture");
        let executable = executable_path();
        let wrong_hash = "0".repeat(64);
        let mismatch = format!(
            "consumer-policy-v1\nexec {}\nread-library {} {}\n",
            executable.display(),
            library.display(),
            wrong_hash
        );
        assert!(
            parse_policy(&mismatch)
                .expect_err("reject incorrect library hash")
                .contains("read-library hash mismatch")
        );

        let digest = sha256_file(&library).expect("hash fixture library");
        let overlap = format!(
            "consumer-policy-v1\nexec {}\nread-library {} {}\ndeny-library {}\n",
            executable.display(),
            library.display(),
            digest,
            library.display()
        );
        assert!(
            parse_policy(&overlap)
                .expect_err("reject library map denied by policy")
                .contains("deny-library overlaps")
        );

        let file_overlap = format!(
            "consumer-policy-v1\nexec {}\nread-file {}\ndeny-library {}\n",
            executable.display(),
            library.display(),
            library.display()
        );
        assert!(
            parse_policy(&file_overlap)
                .expect_err("reject file-data allowance for denied library")
                .contains("deny-library overlaps")
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn read_directory_allows_literal_parent_without_masking_denied_descendant() {
        let root = private_test_root("read-directory");
        let runtime = root.join("runtime");
        create_private_directory(&runtime);
        let library = runtime.join("libpython-fixture.dylib");
        fs::write(&library, b"denied library bytes").expect("write denied library fixture");
        let executable = executable_path();
        let policy_text = format!(
            "consumer-policy-v1\nexec {}\nread-directory {}\ndeny-library {}\n",
            executable.display(),
            runtime.display(),
            library.display()
        );
        let policy = parse_policy(&policy_text).expect("directory-only parent access is safe");
        assert_eq!(policy.read_directories, vec![runtime.clone()]);
        assert!(policy.read_files.iter().all(|path| path != &runtime));

        let profile = build_profile(&policy);
        assert!(profile.contains(&format!(
            "(allow file-read* (literal \"{}\"))",
            runtime.display()
        )));
        assert!(!profile.contains(&format!("(subpath \"{}\")", runtime.display())));
        assert!(!profile.contains(&format!(
            "(allow file-map-executable (literal \"{}\"))",
            runtime.display()
        )));

        let report = report_json(
            Path::new("/policy"),
            Path::new("/profile"),
            &executable,
            &[],
            1,
            2,
            Some(0),
            None,
            Path::new("/stdout"),
            Path::new("/stderr"),
            &test_capture(),
            &test_capture(),
            None,
            &[],
            &verify_exec_hashes(&policy),
            &[],
            &policy,
        );
        assert!(report.contains(&format!(
            "\"read_directories\":[{{\"path\":\"{}\",\"permissions\":[\"file-read*\"],\"scope\":\"literal-directory-only\"}}]",
            runtime.display()
        )));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn exec_derived_tree_requires_empty_private_descendant_and_marks_closure_as_declared() {
        let root = private_test_root("derived-tree-positive");
        let work = root.join("work");
        let parent = work.join("consumer-state");
        create_private_directory(&work);
        create_private_directory(&parent);
        let future_tool = parent.join("fresh-state/tool");
        let executable = executable_path();
        let digest = "a".repeat(64);
        let policy_text = format!(
            "consumer-policy-v1\nexec {}\nwrite-tree work {}\nexec-derived {} {}\nexec-derived-tree consumer-state-parent {} {}\n",
            executable.display(),
            work.display(),
            future_tool.display(),
            digest,
            parent.display(),
            digest
        );
        let policy = parse_policy(&policy_text).expect("accept empty private output parent");
        assert!(
            !future_tool.exists(),
            "future output tree must remain absent"
        );
        assert_eq!(policy.exec_derived_trees.len(), 1);
        assert_eq!(policy.exec_derived_trees[0].path, parent);
        let future_exec = policy
            .exec
            .iter()
            .find(|rule| rule.path == future_tool)
            .expect("deferred future setup executable");
        assert!(future_exec.deferred);
        assert_eq!(
            future_exec.expected_closure_sha256.as_deref(),
            Some(digest.as_str())
        );
        let profile = build_profile(&policy);
        assert!(profile.contains(&format!(
            "(allow process-exec\n  (literal \"{}\")\n  (literal \"{}\")\n  (subpath \"{}\"))",
            executable.display(),
            future_tool.display(),
            parent.display()
        )));

        let report = report_json(
            Path::new("/policy"),
            Path::new("/profile"),
            &executable,
            &[],
            1,
            2,
            Some(0),
            None,
            Path::new("/stdout"),
            Path::new("/stderr"),
            &test_capture(),
            &test_capture(),
            None,
            &[],
            &verify_exec_hashes(&policy),
            &[],
            &policy,
        );
        assert!(report.contains(
            "\"source_closure_verification\":\"declared by policy; not verified by adapter\""
        ));
        assert!(report.contains(&digest));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn exec_derived_tree_rejects_nonempty_wrong_mode_and_unscoped_parents() {
        let root = private_test_root("derived-tree-reject");
        let work = root.join("work");
        create_private_directory(&work);
        let executable = executable_path();
        let digest = "b".repeat(64);

        let nonempty = work.join("nonempty-parent");
        create_private_directory(&nonempty);
        fs::write(nonempty.join("owned.txt"), b"owned").expect("populate parent");
        let policy_text = format!(
            "consumer-policy-v1\nexec {}\nwrite-tree work {}\nexec-derived-tree consumer-build-parent {} {}\n",
            executable.display(),
            work.display(),
            nonempty.display(),
            digest
        );
        assert!(
            parse_policy(&policy_text)
                .expect_err("reject nonempty parent")
                .contains("must be empty")
        );

        let wrong_mode = work.join("wrong-mode-parent");
        create_private_directory(&wrong_mode);
        fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o755))
            .expect("make parent too broad");
        let policy_text = format!(
            "consumer-policy-v1\nexec {}\nwrite-tree work {}\nexec-derived-tree consumer-build-parent {} {}\n",
            executable.display(),
            work.display(),
            wrong_mode.display(),
            digest
        );
        assert!(
            parse_policy(&policy_text)
                .expect_err("reject shared parent permissions")
                .contains("mode 0700")
        );

        let outside = root.join("outside-parent");
        create_private_directory(&outside);
        let policy_text = format!(
            "consumer-policy-v1\nexec {}\nwrite-tree work {}\nexec-derived-tree consumer-build-parent {} {}\n",
            executable.display(),
            work.display(),
            outside.display(),
            digest
        );
        assert!(
            parse_policy(&policy_text)
                .expect_err("reject parent outside owned write-tree")
                .contains("strict descendant")
        );
        fs::remove_dir_all(root).expect("remove test root");
    }
}

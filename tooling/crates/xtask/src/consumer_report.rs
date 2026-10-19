//! Admission checks for consumer enforcement adapter reports.
//!
//! The caller reserves a fresh report path below a private
//! `output/reports` tree before launch and supplies the policy digest and
//! child write roots from the policy it launched. This module validates the
//! resulting bounded evidence after the adapter exits.

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    files::read_regular_bounded,
    json::{JsonProfile, parse_json_value},
};
use serde_json::{Map, Value, json};

const REPORT_SCHEMA: &str = "consumer-enforcement-adapter-a1";
const MACOS_MECHANISM: &str = "/usr/bin/sandbox-exec, deny default, exact process-exec allowlist plus declared private derived-output subtrees";
const LINUX_BACKEND: &str = "Landlock path-beneath allow rules and seccomp-BPF on Linux x86-64";
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

// macOS and Linux both define uid_t as an unsigned 32-bit integer.
#[allow(
    unsafe_code,
    reason = "geteuid is needed to compare private evidence ownership with the caller's effective UID"
)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

/// Caller-supplied facts captured before the adapter launch.
pub(super) struct ExpectedReport<'a> {
    pub report_dir: &'a Path,
    pub policy: &'a Path,
    pub policy_sha256: &'a str,
    pub command: &'a [String],
    pub expected_exit: i32,
    pub outer_exit: i32,
    pub network_outbound: bool,
    pub write_roots: &'a [PathBuf],
}

/// Validate one completed adapter run and return a compact evidence summary.
pub(super) fn admit(expected: &ExpectedReport<'_>) -> Result<Value> {
    if expected.command.is_empty() || expected.command[0].is_empty() {
        return Err(Refusal::new(
            "consumer adapter admission: expected child argv must be nonempty",
        ));
    }
    if expected.outer_exit != expected.expected_exit {
        return Err(Refusal::new(format!(
            "consumer adapter admission: outer exit {} differs from expected {}",
            expected.outer_exit, expected.expected_exit
        )));
    }
    if !is_sha256_digest(expected.policy_sha256) {
        return Err(Refusal::new(
            "consumer adapter admission: pre-launch policy digest is invalid",
        ));
    }

    let uid = effective_uid();
    let report_dir = canonical_evidence_directory(expected.report_dir, uid, "report directory")?;
    let reports_dir = report_dir.parent().ok_or_else(|| {
        Refusal::new("consumer adapter admission: report directory has no parent")
    })?;
    if reports_dir.file_name().and_then(|name| name.to_str()) != Some("reports") {
        return Err(Refusal::new(
            "consumer adapter admission: report directory must be below output/reports",
        ));
    }
    let reports_dir = canonical_private_directory(reports_dir, uid, "private reports directory")?;
    let output_dir = reports_dir.parent().ok_or_else(|| {
        Refusal::new("consumer adapter admission: reports directory has no parent")
    })?;
    canonical_private_directory(output_dir, uid, "private output directory")?;

    let policy = canonical_regular_file(expected.policy, None, "selected policy")?;
    let policy_sha256 = sha256_file(&policy)?;
    if policy_sha256 != expected.policy_sha256 {
        return Err(Refusal::new(
            "consumer adapter admission: selected policy changed after its pre-launch digest was recorded",
        ));
    }

    let expected_writes = normalized_write_roots(expected.write_roots)?;
    for write_root in &expected_writes {
        if paths_overlap(&reports_dir, write_root) {
            return Err(Refusal::new(
                "consumer adapter admission: private report tree overlaps a child-writable tree",
            ));
        }
    }

    let report_path = report_dir.join("report.json");
    let report_metadata = regular_file_metadata(&report_path, Some(uid), "adapter report")?;
    if report_metadata.len() > MAX_REPORT_BYTES as u64 {
        return Err(Refusal::new(
            "consumer adapter admission: adapter report exceeds the 2 MiB limit",
        ));
    }
    let report_raw = read_regular_bounded(&report_path, MAX_REPORT_BYTES)?;
    let report = parse_json_value(&report_raw, JsonProfile::VerifierOutput)?;
    let report_object = report.as_object().ok_or_else(|| {
        Refusal::new("consumer adapter admission: adapter report must be a JSON object")
    })?;

    if string_field(report_object, "schema")? != REPORT_SCHEMA {
        return Err(Refusal::new(
            "consumer adapter admission: unsupported adapter report schema",
        ));
    }
    if string_field(report_object, "policy")? != policy.display().to_string() {
        return Err(Refusal::new(
            "consumer adapter admission: adapter used a different policy path",
        ));
    }
    let reported_command = string_array_field(report_object, "command")?;
    if reported_command.as_slice() != expected.command {
        return Err(Refusal::new(
            "consumer adapter admission: adapter child argv differs from the requested command",
        ));
    }
    if bool_field(report_object, "network_outbound_allowed")? != expected.network_outbound {
        return Err(Refusal::new(
            "consumer adapter admission: reported outbound-network policy differs from the phase expectation",
        ));
    }
    if !bool_field(report_object, "qualification_evidence_valid")? {
        return Err(Refusal::new(
            "consumer adapter admission: adapter did not validate its qualification evidence",
        ));
    }
    if !array_field(report_object, "evidence_failures")?.is_empty() {
        return Err(Refusal::new(
            "consumer adapter admission: adapter reported evidence failures",
        ));
    }
    if !field(report_object, "output_replay_error")?.is_null() {
        return Err(Refusal::new(
            "consumer adapter admission: adapter output replay failed",
        ));
    }

    let backend = match (
        report_object.contains_key("mechanism"),
        report_object.contains_key("backend"),
    ) {
        (true, false) => {
            admit_macos_report(report_object, &report_dir, expected.expected_exit)?;
            "macos"
        }
        (false, true) => {
            admit_linux_report(
                report_object,
                &report_dir,
                expected.expected_exit,
                expected.network_outbound,
            )?;
            "linux"
        }
        _ => {
            return Err(Refusal::new(
                "consumer adapter admission: report does not identify exactly one supported a1 backend",
            ));
        }
    };

    let reported_writes = report_write_roots(report_object)?;
    if reported_writes != expected_writes {
        return Err(Refusal::new(
            "consumer adapter admission: adapter write-tree evidence differs from the policy's child write roots",
        ));
    }

    let (stdout, stdout_sha256) = admit_capture(report_object, &report_dir, "stdout", uid)?;
    let (stderr, stderr_sha256) = admit_capture(report_object, &report_dir, "stderr", uid)?;
    if backend == "macos" {
        let profile_path = report_dir.join("profile.sb");
        regular_file_metadata(&profile_path, Some(uid), "macOS sandbox profile")?;
    }

    Ok(json!({
        "path": report_path.display().to_string(),
        "report_sha256": sha256_bytes(&report_raw),
        "schema": REPORT_SCHEMA,
        "backend": backend,
        "policy_path": policy.display().to_string(),
        "policy_sha256": policy_sha256,
        "child_exit_code": expected.expected_exit,
        "outer_exit_code": expected.outer_exit,
        "network_outbound_allowed": expected.network_outbound,
        "stdout": {
            "path": stdout.display().to_string(),
            "sha256": stdout_sha256,
        },
        "stderr": {
            "path": stderr.display().to_string(),
            "sha256": stderr_sha256,
        },
    }))
}

fn admit_macos_report(
    report: &Map<String, Value>,
    report_dir: &Path,
    expected_exit: i32,
) -> Result<()> {
    if string_field(report, "mechanism")? != MACOS_MECHANISM {
        return Err(Refusal::new(
            "consumer adapter admission: unsupported macOS adapter mechanism",
        ));
    }
    let expected_profile = report_dir.join("profile.sb").display().to_string();
    if string_field(report, "profile")? != expected_profile {
        return Err(Refusal::new(
            "consumer adapter admission: macOS profile path differs from the per-command report directory",
        ));
    }
    if i32_field(report, "exit_code")? != expected_exit || !field(report, "signal")?.is_null() {
        return Err(Refusal::new(format!(
            "consumer adapter admission: macOS child status/signal differs from expected exit {expected_exit}"
        )));
    }
    Ok(())
}

fn admit_linux_report(
    report: &Map<String, Value>,
    report_dir: &Path,
    expected_exit: i32,
    expected_network_outbound: bool,
) -> Result<()> {
    if string_field(report, "backend")? != LINUX_BACKEND {
        return Err(Refusal::new(
            "consumer adapter admission: unsupported Linux adapter backend",
        ));
    }
    if string_field(report, "report_directory")? != report_dir.display().to_string() {
        return Err(Refusal::new(
            "consumer adapter admission: Linux report-directory identity differs from the requested directory",
        ));
    }
    if !field(report, "launch_error")?.is_null() {
        return Err(Refusal::new(
            "consumer adapter admission: Linux adapter reported a child launch error",
        ));
    }
    if i32_field(report, "child_exit_code")? != expected_exit
        || !field(report, "child_signal")?.is_null()
    {
        return Err(Refusal::new(format!(
            "consumer adapter admission: Linux child status/signal differs from expected exit {expected_exit}"
        )));
    }
    let seccomp = field(report, "seccomp")?.as_object().ok_or_else(|| {
        Refusal::new("consumer adapter admission: Linux seccomp evidence must be an object")
    })?;
    for flag in [
        "tsync",
        "execveat_denied",
        "memfd_create_denied",
        "x32_syscalls_denied",
    ] {
        if !bool_field(seccomp, flag)? {
            return Err(Refusal::new(format!(
                "consumer adapter admission: Linux seccomp evidence lacks required {flag} enforcement"
            )));
        }
    }
    if bool_field(seccomp, "network_denied")? != !expected_network_outbound {
        return Err(Refusal::new(
            "consumer adapter admission: Linux seccomp network policy differs from the phase expectation",
        ));
    }
    Ok(())
}

fn admit_capture(
    report: &Map<String, Value>,
    report_dir: &Path,
    name: &str,
    uid: u32,
) -> Result<(PathBuf, String)> {
    let capture = field(report, name)?.as_object().ok_or_else(|| {
        Refusal::new(format!(
            "consumer adapter admission: {name} capture evidence must be an object"
        ))
    })?;
    let path = report_dir.join(format!("{name}.raw"));
    if string_field(capture, "path")? != path.display().to_string() {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {name} capture path differs from the report directory"
        )));
    }
    let metadata = regular_file_metadata(&path, Some(uid), &format!("{name} capture"))?;
    if metadata.len() > MAX_CAPTURE_BYTES as u64 {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {name} capture exceeds the 1 MiB limit"
        )));
    }
    let captured = u64_field(capture, "bytes_captured")?;
    let total = u64_field(capture, "bytes_total")?;
    if captured != total || metadata.len() != captured {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {name} capture is incomplete"
        )));
    }
    if bool_field(capture, "truncated")? || !field(capture, "write_error")?.is_null() {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {name} capture was truncated or could not be written"
        )));
    }
    let raw = read_regular_bounded(&path, MAX_CAPTURE_BYTES)?;
    if raw.len() as u64 != captured {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {name} capture changed while it was read"
        )));
    }
    Ok((path, sha256_bytes(&raw)))
}

fn report_write_roots(report: &Map<String, Value>) -> Result<BTreeSet<PathBuf>> {
    let rows = array_field(report, "write_trees")?;
    let mut roots = BTreeSet::new();
    for row in rows {
        let object = row.as_object().ok_or_else(|| {
            Refusal::new("consumer adapter admission: write-tree row must be an object")
        })?;
        let path_text = string_field(object, "path")?;
        let path = Path::new(path_text);
        let normalized = normalize_absolute_path(path)?;
        if path != normalized.as_path() {
            return Err(Refusal::new(
                "consumer adapter admission: reported write-tree path is not canonical",
            ));
        }
        if !roots.insert(normalized) {
            return Err(Refusal::new(
                "consumer adapter admission: adapter reported duplicate write trees",
            ));
        }
    }
    Ok(roots)
}

fn normalized_write_roots(paths: &[PathBuf]) -> Result<BTreeSet<PathBuf>> {
    let mut roots = BTreeSet::new();
    for path in paths {
        let normalized = normalize_absolute_path(path)?;
        if !roots.insert(normalized) {
            return Err(Refusal::new(
                "consumer adapter admission: caller supplied duplicate child write roots",
            ));
        }
    }
    Ok(roots)
}

/// Canonicalize existing prefixes and append missing leaves, like the adapter.
fn normalize_absolute_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(
            "consumer adapter admission: child write paths must be absolute",
        ));
    }
    let mut lexical = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if !lexical.pop() {
                    return Err(Refusal::new(
                        "consumer adapter admission: invalid child write path",
                    ));
                }
            }
            Component::Normal(name) => lexical.push(name),
            Component::Prefix(_) => {
                return Err(Refusal::new(
                    "consumer adapter admission: unsupported child write path prefix",
                ));
            }
        }
    }

    let mut existing = lexical.clone();
    let mut suffix = Vec::new();
    while fs::symlink_metadata(&existing).is_err() {
        let name = existing.file_name().ok_or_else(|| {
            Refusal::new("consumer adapter admission: child write path has no existing ancestor")
        })?;
        suffix.push(name.to_os_string());
        if !existing.pop() {
            return Err(Refusal::new(
                "consumer adapter admission: child write path has no existing ancestor",
            ));
        }
    }
    let metadata = fs::symlink_metadata(&existing).map_err(|error| {
        Refusal::new(format!(
            "consumer adapter admission: cannot inspect child write path ancestor: {error}"
        ))
    })?;
    let mut normalized = fs::canonicalize(&existing).map_err(|error| {
        Refusal::new(format!(
            "consumer adapter admission: cannot canonicalize child write path: {error}"
        ))
    })?;
    if metadata.file_type().is_file() && !suffix.is_empty() {
        return Err(Refusal::new(
            "consumer adapter admission: child write path descends from a regular file",
        ));
    }
    for component in suffix.into_iter().rev() {
        normalized.push(component);
    }
    Ok(normalized)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn canonical_private_directory(path: &Path, uid: u32, label: &str) -> Result<PathBuf> {
    canonical_directory(path, uid, label, 0o077)
}

fn canonical_evidence_directory(path: &Path, uid: u32, label: &str) -> Result<PathBuf> {
    canonical_directory(path, uid, label, 0o022)
}

fn canonical_directory(
    path: &Path,
    uid: u32,
    label: &str,
    forbidden_permission_bits: u32,
) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {label} must be an absolute path"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Refusal::new(format!(
            "consumer adapter admission: cannot inspect {label}: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {label} is missing, not a directory, or a symlink"
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        Refusal::new(format!(
            "consumer adapter admission: cannot canonicalize {label}: {error}"
        ))
    })?;
    if canonical.as_path() != path {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {label} is not a canonical path"
        )));
    }
    if metadata.uid() != uid || metadata.mode() & forbidden_permission_bits != 0 {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {label} must be owned by the effective user and have restricted permissions"
        )));
    }
    Ok(canonical)
}

fn canonical_regular_file(path: &Path, uid: Option<u32>, label: &str) -> Result<PathBuf> {
    regular_file_metadata(path, uid, label)?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        Refusal::new(format!(
            "consumer adapter admission: cannot canonicalize {label}: {error}"
        ))
    })?;
    if canonical.as_path() != path {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {label} is not a canonical path"
        )));
    }
    Ok(canonical)
}

fn regular_file_metadata(path: &Path, uid: Option<u32>, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Refusal::new(format!(
            "consumer adapter admission: cannot inspect {label}: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {label} is missing or is not a regular file"
        )));
    }
    if uid.is_some_and(|expected| metadata.uid() != expected) {
        return Err(Refusal::new(format!(
            "consumer adapter admission: {label} is not owned by the effective user"
        )));
    }
    Ok(metadata)
}

#[allow(
    unsafe_code,
    reason = "geteuid takes no pointers and only reads the current process credentials"
)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no pointers and only reads the current process UID.
    unsafe { geteuid() }
}

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    object.get(key).ok_or_else(|| {
        Refusal::new(format!(
            "consumer adapter admission: report is missing {key}"
        ))
    })
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    field(object, key)?.as_str().ok_or_else(|| {
        Refusal::new(format!(
            "consumer adapter admission: report field {key} must be a string"
        ))
    })
}

fn bool_field(object: &Map<String, Value>, key: &str) -> Result<bool> {
    field(object, key)?.as_bool().ok_or_else(|| {
        Refusal::new(format!(
            "consumer adapter admission: report field {key} must be a boolean"
        ))
    })
}

fn i32_field(object: &Map<String, Value>, key: &str) -> Result<i32> {
    let value = field(object, key)?.as_i64().ok_or_else(|| {
        Refusal::new(format!(
            "consumer adapter admission: report field {key} must be an integer"
        ))
    })?;
    i32::try_from(value).map_err(|_| {
        Refusal::new(format!(
            "consumer adapter admission: report field {key} is outside the exit-code range"
        ))
    })
}

fn u64_field(object: &Map<String, Value>, key: &str) -> Result<u64> {
    field(object, key)?.as_u64().ok_or_else(|| {
        Refusal::new(format!(
            "consumer adapter admission: report field {key} must be a nonnegative integer"
        ))
    })
}

fn array_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>> {
    field(object, key)?.as_array().ok_or_else(|| {
        Refusal::new(format!(
            "consumer adapter admission: report field {key} must be an array"
        ))
    })
}

fn string_array_field(object: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    array_field(object, key)?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                Refusal::new(format!(
                    "consumer adapter admission: report array {key} must contain only strings"
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ExpectedReport, MAX_CAPTURE_BYTES, admit};
    use ami_rust_core::digest::sha256_bytes;
    use serde_json::{Value, json};
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, fs::symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy)]
    enum Backend {
        Macos,
        Linux,
    }

    struct Fixture {
        root: PathBuf,
        report_dir: PathBuf,
        policy: PathBuf,
        policy_sha256: String,
        command: Vec<String>,
        write_roots: Vec<PathBuf>,
        backend: Backend,
    }

    impl Fixture {
        fn new(backend: Backend, child_exit: i32) -> Self {
            let root = unique_temp_dir();
            let output = root.join("output");
            let reports = output.join("reports");
            let report_dir = reports.join("run-1");
            let write_root = output.join("work");
            for directory in [&output, &reports, &report_dir, &write_root] {
                fs::create_dir(directory).expect("create fixture directory");
                let mode = if directory == &report_dir {
                    0o755
                } else {
                    0o700
                };
                fs::set_permissions(directory, fs::Permissions::from_mode(mode))
                    .expect("set fixture directory permissions");
            }
            let policy = output.join("policy.txt");
            fs::write(&policy, b"consumer-policy-v1\n").expect("write fixture policy");
            fs::set_permissions(&policy, fs::Permissions::from_mode(0o600))
                .expect("make fixture policy private");
            let report_dir = fs::canonicalize(report_dir).expect("canonical report directory");
            let policy = fs::canonicalize(policy).expect("canonical policy");
            let write_roots = vec![fs::canonicalize(write_root).expect("canonical write root")];
            let command = vec!["/bin/example".to_owned(), "--flag".to_owned()];
            let policy_sha256 = sha256_bytes(b"consumer-policy-v1\n");
            let fixture = Self {
                root,
                report_dir,
                policy,
                policy_sha256,
                command,
                write_roots,
                backend,
            };
            fixture.write_capture("stdout", b"child stdout");
            fixture.write_capture("stderr", b"child stderr");
            if matches!(backend, Backend::Macos) {
                let profile = fixture.report_dir.join("profile.sb");
                fs::write(profile, b"(version 1)\n").expect("write fixture profile");
            }
            fixture.write_report(fixture.report(child_exit, false));
            fixture
        }

        fn expected(&self, expected_exit: i32, outer_exit: i32) -> ExpectedReport<'_> {
            ExpectedReport {
                report_dir: &self.report_dir,
                policy: &self.policy,
                policy_sha256: &self.policy_sha256,
                command: &self.command,
                expected_exit,
                outer_exit,
                network_outbound: false,
                write_roots: &self.write_roots,
            }
        }

        fn report(&self, child_exit: i32, network_outbound: bool) -> Value {
            let stdout = self.capture_value("stdout", b"child stdout");
            let stderr = self.capture_value("stderr", b"child stderr");
            let mut report = json!({
                "schema": "consumer-enforcement-adapter-a1",
                "policy": self.policy.display().to_string(),
                "command": self.command,
                "stdout": stdout,
                "stderr": stderr,
                "network_outbound_allowed": network_outbound,
                "write_trees": [{"role": "work", "path": self.write_roots[0].display().to_string()}],
                "output_replay_error": null,
                "qualification_evidence_valid": true,
                "evidence_failures": [],
            });
            match self.backend {
                Backend::Macos => {
                    report["mechanism"] = json!(
                        "/usr/bin/sandbox-exec, deny default, exact process-exec allowlist plus declared private derived-output subtrees"
                    );
                    report["profile"] =
                        json!(self.report_dir.join("profile.sb").display().to_string());
                    report["exit_code"] = json!(child_exit);
                    report["signal"] = Value::Null;
                }
                Backend::Linux => {
                    report["backend"] =
                        json!("Landlock path-beneath allow rules and seccomp-BPF on Linux x86-64");
                    report["report_directory"] = json!(self.report_dir.display().to_string());
                    report["launch_error"] = Value::Null;
                    report["child_exit_code"] = json!(child_exit);
                    report["child_signal"] = Value::Null;
                    report["seccomp"] = json!({
                        "tsync": true,
                        "execveat_denied": true,
                        "memfd_create_denied": true,
                        "x32_syscalls_denied": true,
                        "network_denied": !network_outbound,
                    });
                }
            }
            report
        }

        fn capture_value(&self, name: &str, bytes: &[u8]) -> Value {
            json!({
                "path": self.report_dir.join(format!("{name}.raw")).display().to_string(),
                "bytes_captured": bytes.len(),
                "bytes_total": bytes.len(),
                "truncated": false,
                "write_error": null,
            })
        }

        fn write_capture(&self, name: &str, bytes: &[u8]) {
            let path = self.report_dir.join(format!("{name}.raw"));
            fs::write(&path, bytes).expect("write fixture capture");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("make fixture capture private");
        }

        fn write_report(&self, report: Value) {
            let path = self.report_dir.join("report.json");
            fs::write(
                &path,
                serde_json::to_vec(&report).expect("serialize fixture report"),
            )
            .expect("write fixture report");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("make fixture report private");
        }

        fn read_report(&self) -> Value {
            serde_json::from_slice(
                &fs::read(self.report_dir.join("report.json")).expect("read fixture report"),
            )
            .expect("parse fixture report")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("remove fixture directory");
        }
    }

    fn unique_temp_dir() -> PathBuf {
        let base = std::env::temp_dir();
        for _ in 0..100 {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                "ami-rust-consumer-report-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("make fixture root private");
                    return path;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create fixture root: {error}"),
            }
        }
        panic!("could not allocate a unique fixture root")
    }

    #[test]
    fn admits_macos_and_linux_reports_for_exit_zero_and_two() {
        for backend in [Backend::Macos, Backend::Linux] {
            for child_exit in [0, 2] {
                let fixture = Fixture::new(backend, child_exit);
                let summary = admit(&fixture.expected(child_exit, child_exit)).unwrap();
                assert_eq!(summary["child_exit_code"], child_exit);
                assert_eq!(summary["outer_exit_code"], child_exit);
                assert_eq!(
                    summary["backend"],
                    match backend {
                        Backend::Macos => "macos",
                        Backend::Linux => "linux",
                    }
                );
                assert_eq!(summary["policy_sha256"], fixture.policy_sha256);
                assert!(summary["report_sha256"].as_str().is_some());
                assert!(summary["stdout"]["sha256"].as_str().is_some());
                assert!(summary["stderr"]["sha256"].as_str().is_some());
            }
        }
    }

    #[test]
    fn preserves_an_empty_argument_after_a_nonempty_executable() {
        let mut fixture = Fixture::new(Backend::Linux, 0);
        fixture.command.push(String::new());
        let mut report = fixture.read_report();
        report["command"] = json!(fixture.command);
        fixture.write_report(report);
        assert!(admit(&fixture.expected(0, 0)).is_ok());
    }

    #[test]
    fn rejects_missing_report_even_when_outer_exit_is_two() {
        let fixture = Fixture::new(Backend::Linux, 2);
        fs::remove_file(fixture.report_dir.join("report.json")).expect("remove report");
        assert!(admit(&fixture.expected(2, 2)).is_err());
    }

    #[test]
    fn rejects_child_status_mismatch() {
        let fixture = Fixture::new(Backend::Macos, 0);
        let mut report = fixture.read_report();
        report["exit_code"] = json!(2);
        fixture.write_report(report);
        assert!(admit(&fixture.expected(0, 0)).is_err());
    }

    #[test]
    fn rejects_false_evidence_and_wrong_command_or_network_policy() {
        let fixture = Fixture::new(Backend::Macos, 0);
        let mut report = fixture.read_report();
        report["qualification_evidence_valid"] = json!(false);
        fixture.write_report(report);
        assert!(admit(&fixture.expected(0, 0)).is_err());

        let fixture = Fixture::new(Backend::Macos, 0);
        let mut report = fixture.read_report();
        report["command"][0] = json!("/bin/other");
        fixture.write_report(report);
        assert!(admit(&fixture.expected(0, 0)).is_err());

        let fixture = Fixture::new(Backend::Linux, 0);
        let mut report = fixture.read_report();
        report["seccomp"]["network_denied"] = json!(false);
        fixture.write_report(report);
        assert!(admit(&fixture.expected(0, 0)).is_err());
    }

    #[test]
    fn rejects_truncated_or_overlong_capture_evidence() {
        let fixture = Fixture::new(Backend::Linux, 0);
        let mut report = fixture.read_report();
        report["stdout"]["truncated"] = json!(true);
        fixture.write_report(report);
        assert!(admit(&fixture.expected(0, 0)).is_err());

        let fixture = Fixture::new(Backend::Linux, 0);
        let mut report = fixture.read_report();
        report["stdout"]["bytes_total"] = json!(MAX_CAPTURE_BYTES + 1);
        fixture.write_report(report);
        assert!(admit(&fixture.expected(0, 0)).is_err());
    }

    #[test]
    fn rejects_policy_tampering_after_the_prelaunch_digest() {
        let fixture = Fixture::new(Backend::Linux, 0);
        fs::write(&fixture.policy, b"changed after launch\n").expect("tamper policy");
        assert!(admit(&fixture.expected(0, 0)).is_err());
    }

    #[test]
    fn rejects_symlinked_or_public_report_evidence() {
        let fixture = Fixture::new(Backend::Linux, 0);
        let stdout = fixture.report_dir.join("stdout.raw");
        fs::remove_file(&stdout).expect("remove capture");
        symlink(fixture.policy.as_path(), &stdout).expect("replace capture with symlink");
        assert!(admit(&fixture.expected(0, 0)).is_err());

        let fixture = Fixture::new(Backend::Linux, 0);
        fs::set_permissions(&fixture.report_dir, fs::Permissions::from_mode(0o777))
            .expect("make report directory writable by others");
        assert!(admit(&fixture.expected(0, 0)).is_err());
    }
}

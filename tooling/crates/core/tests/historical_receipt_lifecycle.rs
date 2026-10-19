//! Ignored, maintainer-only paired replay of historical receipt uninstall behavior.
//! Python is an oracle for this test, never a consumer runtime dependency.

use ami_rust_core::{digest::sha256_bytes, host_platform::supported_host, records::Host};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const INSTALL_SHA256: &str = "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984";
const TEST_INSTALL_SHA256: &str =
    "379ba1ab0f3795dd880c17ec46705bf976da9b21bc9a57f7884c573e73bcd64c";
const TARFILE_SHA256: &str = "f0891b6936a39e5a41bd857fc149191fbe30ca84e5958f203682e76e218ff2a4";
const MAX_CHILD_OUTPUT_BYTES: usize = 1024 * 1024;

fn fail(message: impl Into<String>) -> ! {
    panic!("historical receipt lifecycle replay: {}", message.into())
}

fn canonical_directory(path: &Path, label: &str) -> PathBuf {
    assert!(path.is_absolute(), "{label} must be absolute");
    assert!(!path.is_symlink(), "{label} must not be a symlink");
    assert!(path.is_dir(), "{label} must be a directory");
    let canonical = path.canonicalize().expect("canonicalize directory");
    assert_eq!(path, canonical, "{label} must already be canonical");
    canonical
}

fn canonical_executable(path: PathBuf, label: &str) -> PathBuf {
    assert!(path.is_absolute(), "{label} must be absolute");
    let metadata = fs::symlink_metadata(&path).expect("stat executable");
    assert!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file"
    );
    assert_ne!(
        metadata.permissions().mode() & 0o111,
        0,
        "{label} must be executable"
    );
    assert_eq!(
        path.canonicalize().expect("canonicalize executable"),
        path,
        "{label} must already be canonical"
    );
    path
}

fn source_root() -> PathBuf {
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = package
        .join("../../..")
        .canonicalize()
        .expect("resolve selected source root from linked core package");
    let selected = PathBuf::from(
        env::var_os("AMI_RUST_DIFFERENTIAL_SOURCE").expect("explicit selected source root"),
    );
    let selected = canonical_directory(&selected, "selected source root");
    assert_eq!(
        selected, expected,
        "selected source root differs from this compiled core checkout"
    );
    selected
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(
        &fs::read(path).unwrap_or_else(|error| fail(format!("read {}: {error}", path.display()))),
    )
}

fn hash_core_sources(source: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, directory: &Path, output: &mut BTreeMap<String, String>) {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .expect("read core source directory")
            .map(|entry| entry.expect("read core source entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let metadata = fs::symlink_metadata(&path).expect("stat core source entry");
            assert!(
                !metadata.file_type().is_symlink(),
                "core source tree contains a symlink: {}",
                path.display()
            );
            if metadata.is_dir() {
                walk(root, &path, output);
            } else if metadata.is_file()
                && path.extension().is_some_and(|extension| extension == "rs")
            {
                let relative = path
                    .strip_prefix(root)
                    .expect("core source descendant")
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(relative, sha256_file(&path));
            }
        }
    }

    let core = source.join("tooling/crates/core");
    let mut output = BTreeMap::new();
    for path in [
        core.join("build.rs"),
        core.join("src/macos_process_snapshot.c"),
    ] {
        if path.exists() {
            let relative = path
                .strip_prefix(source)
                .expect("core source descendant")
                .to_string_lossy()
                .replace('\\', "/");
            output.insert(relative, sha256_file(&path));
        }
    }
    let selector = source.join("tooling/macos-host-selection.rs");
    assert!(
        selector.is_file() && !selector.is_symlink(),
        "shared macOS host-selection source must be a regular file"
    );
    output.insert(
        "tooling/macos-host-selection.rs".to_owned(),
        sha256_file(&selector),
    );
    let rust_root = core.join("src");
    walk(source, &rust_root, &mut output);
    assert!(!output.is_empty(), "core source tree is empty");
    output
}

fn package_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn verify_pinned_runtime(source: &Path, python: PathBuf) -> (PathBuf, Value, &'static str) {
    let python = canonical_executable(python, "AMI_RUST_HISTORICAL_PYTHON");
    let host = match supported_host().expect("supported host") {
        Host::MacosAarch64 => "macos-aarch64",
        Host::LinuxX86_64 => "linux-x86_64",
    };
    let ci_path = source.join("release/ci-python-inputs.json");
    let ci: Value = serde_json::from_slice(&fs::read(&ci_path).expect("read tracked Python pins"))
        .expect("parse tracked Python input pins");
    assert_eq!(ci["schema"], "ami-rust-ci-python-inputs-v1");
    assert_eq!(ci["version"], "3.12.15");
    let runtime = &ci["hosts"][host];
    assert_eq!(runtime["runtime_relative_path"], "python/bin/python3.12");
    let raw = fs::read(&python).expect("read pinned Python executable");
    assert_eq!(
        raw.len() as u64,
        runtime["runtime_bytes"].as_u64().expect("Python byte pin")
    );
    assert_eq!(
        sha256_bytes(&raw),
        runtime["runtime_sha256"].as_str().expect("Python SHA pin")
    );
    (python, ci, host)
}

fn fresh_work_directory() -> PathBuf {
    let path = PathBuf::from(
        env::var_os("AMI_RUST_DIFFERENTIAL_WORK").expect("fresh private output directory"),
    );
    assert!(path.is_absolute(), "output directory must be absolute");
    assert!(
        !path.exists() && !path.is_symlink(),
        "output directory must be fresh"
    );
    fs::create_dir(&path).expect("create output directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("protect output directory");
    for name in ["home", "tmp"] {
        let child = path.join(name);
        fs::create_dir(&child).expect("create private helper directory");
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700))
            .expect("protect helper directory");
    }
    path
}

fn paired_state<'a>(case: &'a Value, field: &str) -> &'a Value {
    case.get(field)
        .expect("complete paired filesystem snapshot")
}

#[test]
#[ignore = "Explicit historical v1 receipt lifecycle pair using the pinned Python oracle"]
fn paired_historical_receipt_lifecycle() {
    let source = source_root();
    let python_value =
        PathBuf::from(env::var_os("AMI_RUST_HISTORICAL_PYTHON").expect("explicit pinned Python"));
    let (python, ci, host) = verify_pinned_runtime(&source, python_value);
    let helper = package_file("tests/support/historical_receipt_lifecycle.py");
    let test_source = package_file("tests/historical_receipt_lifecycle.rs");
    assert!(
        helper.is_file() && !helper.is_symlink(),
        "helper must be a regular file"
    );
    let helper_hash_before = sha256_file(&helper);
    let test_hash_before = sha256_file(&test_source);
    let source_hashes_before = hash_core_sources(&source);
    let work = fresh_work_directory();
    let test_binary = env::current_exe().expect("current integration-test binary");

    let child = Command::new(&python)
        .args(["-I", "-B"])
        .arg(&helper)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", work.join("home"))
        .env("TMPDIR", work.join("tmp"))
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("AMI_RUST_DIFFERENTIAL_SOURCE", &source)
        .env("AMI_RUST_DIFFERENTIAL_WORK", &work)
        .env("AMI_RUST_HISTORICAL_PYTHON", &python)
        .env("AMI_RUST_DIFFERENTIAL_TEST_BINARY", &test_binary)
        .env("AMI_RUST_CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"))
        .current_dir(&work)
        .output()
        .expect("launch pinned historical Python helper");
    fs::write(work.join("helper.stdout.raw"), &child.stdout)
        .expect("preserve Python helper stdout");
    fs::write(work.join("helper.stderr.raw"), &child.stderr)
        .expect("preserve Python helper stderr");
    assert!(
        child.stdout.len() <= MAX_CHILD_OUTPUT_BYTES,
        "Python helper stdout exceeds 1 MiB"
    );
    assert!(
        child.stderr.len() <= MAX_CHILD_OUTPUT_BYTES,
        "Python helper stderr exceeds 1 MiB"
    );
    assert!(
        child.status.success(),
        "historical receipt helper failed with {:?}: {}",
        child.status.code(),
        String::from_utf8_lossy(&child.stderr)
    );

    let report_bytes = fs::read(work.join("report.json")).expect("read paired lifecycle report");
    let report: Value = serde_json::from_slice(&report_bytes).expect("parse lifecycle report");
    assert_eq!(
        report["schema"],
        "ami-rust-historical-receipt-lifecycle-pair-v1"
    );
    assert_eq!(report["status"], "pass");
    assert_eq!(report["case_count"], 2);
    assert_eq!(report["python_runtime"]["host"], host);
    assert_eq!(
        report["python_runtime"]["sha256"],
        ci["hosts"][host]["runtime_sha256"]
    );
    assert_eq!(report["python_runtime"]["tarfile_sha256"], TARFILE_SHA256);
    assert_eq!(
        report["historical_source_sha256"]["release/install.py"],
        INSTALL_SHA256
    );
    assert_eq!(
        report["historical_source_sha256"]["release/test_install.py"],
        TEST_INSTALL_SHA256
    );

    let cases = report["cases"].as_array().expect("paired cases");
    assert_eq!(cases.len(), 2);
    let positive = cases
        .iter()
        .find(|case| case["name"] == "positive-historical-v1-uninstall")
        .expect("positive uninstall case");
    assert_eq!(positive["decision"], "both accepted");
    assert_eq!(positive["pin_retained"], true);
    assert_eq!(positive["adjacent_user_data_preserved"], true);
    assert_eq!(
        paired_state(positive, "pre_state_python"),
        paired_state(positive, "pre_state_rust")
    );
    assert_eq!(
        paired_state(positive, "post_state_python"),
        paired_state(positive, "post_state_rust")
    );
    assert_ne!(
        paired_state(positive, "pre_state_python"),
        paired_state(positive, "post_state_python"),
        "accepted uninstall must change the install tree"
    );

    let stale = cases
        .iter()
        .find(|case| case["name"] == "stale-external-receipt-pin")
        .expect("stale receipt pin counter-case");
    assert_eq!(stale["decision"], "both refused");
    assert_eq!(stale["legacy_exit"], 2);
    assert_eq!(stale["rust_wrapper_exit"], 2);
    assert_eq!(stale["filesystem_unchanged"], true);
    assert_eq!(
        paired_state(stale, "pre_state_python"),
        paired_state(stale, "pre_state_rust")
    );
    assert_eq!(
        paired_state(stale, "pre_state_python"),
        paired_state(stale, "post_state_python")
    );
    assert_eq!(
        paired_state(stale, "pre_state_rust"),
        paired_state(stale, "post_state_rust")
    );

    let source_hashes_after = hash_core_sources(&source);
    let helper_hash_after = sha256_file(&helper);
    let test_hash_after = sha256_file(&test_source);
    assert_eq!(
        source_hashes_before, source_hashes_after,
        "core source changed during replay"
    );
    assert_eq!(
        helper_hash_before, helper_hash_after,
        "helper changed during replay"
    );
    assert_eq!(
        test_hash_before, test_hash_after,
        "test source changed during replay"
    );
    assert_eq!(
        report["source_bindings"]["core_before"],
        json!(source_hashes_before)
    );
    assert_eq!(
        report["source_bindings"]["core_after"],
        json!(source_hashes_after)
    );
    assert_eq!(
        report["source_bindings"]["python_helper_sha256_before"],
        helper_hash_before
    );
    assert_eq!(
        report["source_bindings"]["python_helper_sha256_after"],
        helper_hash_after
    );
    assert_eq!(
        report["source_bindings"]["rust_test_sha256_before"],
        test_hash_before
    );
    assert_eq!(
        report["source_bindings"]["rust_test_sha256_after"],
        test_hash_after
    );

    let binding = json!({
        "schema": "ami-rust-historical-receipt-lifecycle-binding-v1",
        "source_root": source,
        "core_source_hashes_before": source_hashes_before,
        "core_source_hashes_after": source_hashes_after,
        "rust_test_sha256": test_hash_before,
        "python_helper_sha256": helper_hash_before,
        "test_binary_sha256": sha256_file(&test_binary),
        "python_runtime_manifest": ci,
        "python_host": host,
        "python_executable_sha256": sha256_file(&python),
        "tarfile_sha256": TARFILE_SHA256,
        "report_sha256": sha256_bytes(&report_bytes),
        "scope": "Maintainer-only historical v1 receipt lifecycle pair; not v3 CLI acceptance"
    });
    fs::write(
        work.join("binding.json"),
        serde_json::to_vec_pretty(&binding).expect("serialize runtime binding"),
    )
    .expect("preserve runtime binding");
}

#[test]
#[ignore = "Isolated selected-core child, launched only by paired_historical_receipt_lifecycle"]
fn paired_historical_receipt_lifecycle_child() {
    let _source = source_root();
    let plan_path = PathBuf::from(
        env::var_os("AMI_RUST_RECEIPT_LIFECYCLE_PLAN").expect("explicit lifecycle plan path"),
    );
    assert!(
        plan_path.is_absolute() && plan_path.is_file(),
        "plan must be an absolute file"
    );
    let plan: Value = serde_json::from_slice(&fs::read(&plan_path).expect("read lifecycle plan"))
        .expect("parse lifecycle plan");
    let result = bridge_result(&plan);
    let mut result_path = plan_path;
    result_path.set_extension("result.json");
    fs::write(
        &result_path,
        serde_json::to_vec(&result).expect("serialize Rust bridge result"),
    )
    .expect("preserve bridge result");
    match result["status"].as_str() {
        Some("ok") => {}
        Some("refusal") => std::process::exit(result["exit_code"].as_i64().unwrap_or(2) as i32),
        _ => std::process::exit(3),
    }
}

fn bridge_result(plan: &Value) -> Value {
    match plan["operation"].as_str() {
        Some("publish") => publish_pair(plan),
        Some("native-uninstall") => native_uninstall(plan),
        _ => json!({"status":"bridge-error", "reason":"unknown operation"}),
    }
}

fn required_path(plan: &Value, name: &str) -> Result<PathBuf, String> {
    let value = plan[name]
        .as_str()
        .ok_or_else(|| format!("missing {name}"))?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("{name} must be absolute"))
    }
}

fn publish_pair(plan: &Value) -> Value {
    use ami_rust_core::transaction::{InstallFile, publish_install};

    let get = |name| required_path(plan, name);
    let (prefix, bundle, receipt_source, receipt_pin) = match (
        get("prefix"),
        get("bundle"),
        get("receipt_source"),
        get("receipt_pin"),
    ) {
        (Ok(prefix), Ok(bundle), Ok(receipt_source), Ok(receipt_pin)) => {
            (prefix, bundle, receipt_source, receipt_pin)
        }
        (Err(error), _, _, _)
        | (_, Err(error), _, _)
        | (_, _, Err(error), _)
        | (_, _, _, Err(error)) => return json!({"status":"bridge-error", "reason":error}),
    };
    let receipt = match fs::read(receipt_source) {
        Ok(bytes) => bytes,
        Err(error) => return json!({"status":"bridge-error", "reason":error.to_string()}),
    };
    let Some(specs) = plan["files"].as_array() else {
        return json!({"status":"bridge-error", "reason":"files must be an array"});
    };
    let mut owned = Vec::<(String, Vec<u8>, u32)>::with_capacity(specs.len());
    for spec in specs {
        let (Some(path), Some(source), Some(mode)) = (
            spec["path"].as_str(),
            spec["source"].as_str(),
            spec["mode"].as_u64(),
        ) else {
            return json!({"status":"bridge-error", "reason":"invalid file row"});
        };
        let source = PathBuf::from(source);
        if !source.is_absolute() || mode > u32::MAX as u64 {
            return json!({"status":"bridge-error", "reason":"file source/mode is invalid"});
        }
        match fs::read(source) {
            Ok(bytes) => owned.push((path.to_owned(), bytes, mode as u32)),
            Err(error) => return json!({"status":"bridge-error", "reason":error.to_string()}),
        }
    }
    let files: Vec<_> = owned
        .iter()
        .map(|(path, contents, mode)| InstallFile {
            path,
            contents,
            mode: *mode,
        })
        .collect();
    match publish_install(&prefix, &bundle, Some(&receipt_pin), &files, &receipt) {
        Ok(published) => json!({
            "status":"ok",
            "prefix":published.prefix,
            "receipt_sha256":published.receipt_sha256,
            "receipt_pin":published.receipt_pin,
        }),
        Err(failure) => json!({
            "status":"refusal",
            "exit_code":failure.exit_code(),
            "reason":failure.reason.to_string(),
        }),
    }
}

fn native_uninstall(plan: &Value) -> Value {
    let (Some(prefix), Some(receipt_sha256)) =
        (plan["prefix"].as_str(), plan["receipt_sha256"].as_str())
    else {
        return json!({"status":"bridge-error", "reason":"missing prefix or receipt digest"});
    };
    let prefix = PathBuf::from(prefix);
    if !prefix.is_absolute() {
        return json!({"status":"bridge-error", "reason":"prefix must be absolute"});
    }
    match ami_rust_core::native_install::uninstall(&prefix, receipt_sha256) {
        Ok(()) => json!({"status":"ok"}),
        Err(failure) => json!({
            "status":"refusal",
            "exit_code":2,
            "reason":failure.reason.to_string(),
            "recovery":failure.recovery.map(|item| json!({
                "entry_name":item.entry_name.to_string_lossy(),
                "last_known_parent":item.last_known_parent,
                "verified_path":item.verified_path,
            })),
        }),
    }
}

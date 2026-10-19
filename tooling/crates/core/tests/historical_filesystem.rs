//! Explicit maintainer differential replay for historical inventory and SDK TAR behavior.
//! The pinned Python runtime is a comparison oracle, never a consumer child.

use ami_rust_core::{
    compression::{DecodeLimits, copy_xz},
    digest::sha256_bytes,
    host_platform::supported_host,
    inventory::{FileIdentity, InventoryLimits, LinkIdentity, verify_complete},
    publisher_tar::{ExpectedFile, verify_publisher_sdk_tar},
    records::Host,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const TARFILE_SHA256: &str = "f0891b6936a39e5a41bd857fc149191fbe30ca84e5958f203682e76e218ff2a4";
const FIXTURE_DIGESTS_SHA256: &str =
    "3fa952f9167b2b54ec694b26f1271cfccd1949b5634cc041132957b623d548a0";
const MAX_CHILD_OUTPUT_BYTES: usize = 1024 * 1024;

fn fail(message: impl Into<String>) -> ! {
    panic!("historical filesystem replay: {}", message.into())
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
        .expect("resolve repository root from core package");
    let selected = PathBuf::from(
        env::var_os("AMI_RUST_DIFFERENTIAL_SOURCE").expect("explicit selected source root"),
    );
    let selected = canonical_directory(&selected, "selected source root");
    assert_eq!(
        selected, expected,
        "source root differs from this compiled core checkout"
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
    let root = source.join("tooling/crates/core/src");
    let mut output = BTreeMap::new();
    walk(&root, &root, &mut output);
    assert!(!output.is_empty(), "core source tree is empty");
    output
}

fn package_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn verify_fixture_manifest() -> Value {
    let embedded = include_bytes!("fixtures/historical_filesystem/fixture-digests.json");
    assert_eq!(
        sha256_bytes(embedded),
        FIXTURE_DIGESTS_SHA256,
        "fixture digest ledger changed"
    );
    let path = package_file("tests/fixtures/historical_filesystem/fixture-digests.json");
    let current = fs::read(&path).expect("read fixture digest ledger");
    assert_eq!(
        current, embedded,
        "fixture digest ledger changed after compilation"
    );
    serde_json::from_slice(&current).expect("parse fixture digest ledger")
}

fn verify_pinned_runtime(source: &Path, python: PathBuf) -> (PathBuf, Value, &'static str) {
    let python = canonical_executable(python, "AMI_RUST_HISTORICAL_PYTHON");
    let host = match supported_host().expect("supported host") {
        Host::MacosAarch64 => "macos-aarch64",
        Host::LinuxX86_64 => "linux-x86_64",
    };
    let ci_path = source.join("release/ci-python-inputs.json");
    let ci: Value =
        serde_json::from_slice(&fs::read(&ci_path).expect("read tracked Python input pins"))
            .expect("parse tracked Python input pins");
    assert_eq!(ci["schema"], "ami-rust-ci-python-inputs-v1");
    assert_eq!(ci["version"], "3.12.15");
    let runtime = &ci["hosts"][host];
    assert_eq!(runtime["runtime_relative_path"], "python/bin/python3.12");
    let raw = fs::read(&python).expect("read pinned Python executable bytes");
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

#[test]
#[ignore = "Explicit 50-case historical filesystem replay with the pinned Python oracle"]
fn paired_historical_filesystem() {
    let source = source_root();
    let python_value =
        PathBuf::from(env::var_os("AMI_RUST_HISTORICAL_PYTHON").expect("explicit pinned Python"));
    let (python, ci, host) = verify_pinned_runtime(&source, python_value);
    let fixture_manifest = verify_fixture_manifest();
    assert_eq!(
        fixture_manifest["inventory_cases"]
            .as_object()
            .expect("inventory cases")
            .len(),
        14
    );
    assert_eq!(
        fixture_manifest["archive_cases"]
            .as_object()
            .expect("archive cases")
            .len(),
        36
    );
    let helper = package_file("tests/support/historical_filesystem.py");
    assert!(
        helper.is_file() && !helper.is_symlink(),
        "historical filesystem helper must be a regular file"
    );
    let helper_hash_before = sha256_file(&helper);
    let test_source = package_file("tests/historical_filesystem.rs");
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
    assert!(
        child.stdout.len() <= MAX_CHILD_OUTPUT_BYTES,
        "Python helper stdout exceeds 1 MiB"
    );
    assert!(
        child.stderr.len() <= MAX_CHILD_OUTPUT_BYTES,
        "Python helper stderr exceeds 1 MiB"
    );
    fs::write(work.join("coordinator.stdout.raw"), &child.stdout)
        .expect("preserve Python helper stdout");
    fs::write(work.join("coordinator.stderr.raw"), &child.stderr)
        .expect("preserve Python helper stderr");
    assert!(
        child.status.success(),
        "historical filesystem helper failed with {:?}: {}",
        child.status.code(),
        String::from_utf8_lossy(&child.stderr)
    );

    let report_path = work.join("report.json");
    let report_bytes = fs::read(&report_path).expect("read paired filesystem report");
    let report: Value =
        serde_json::from_slice(&report_bytes).expect("parse paired filesystem report");
    assert_eq!(report["status"], "pass");
    assert_eq!(report["case_counts"]["inventory"], 14);
    assert_eq!(report["case_counts"]["archive"], 36);
    assert_eq!(report["case_counts"]["total"], 50);
    assert_eq!(report["decision_counts"]["decision_equal"], 50);
    assert_eq!(report["decision_counts"]["exit_equal"], 50);
    assert_eq!(report["decision_counts"]["python_accept"], 17);
    assert_eq!(report["decision_counts"]["rust_accept"], 17);
    assert_eq!(report["decision_counts"]["archive_full_report_equal"], 14);
    assert_eq!(report["python_runtime"]["tarfile_sha256"], TARFILE_SHA256);

    let source_hashes_after = hash_core_sources(&source);
    let helper_hash_after = sha256_file(&helper);
    let test_hash_after = sha256_file(&test_source);
    assert_eq!(
        source_hashes_before, source_hashes_after,
        "core sources changed during replay"
    );
    assert_eq!(
        helper_hash_before, helper_hash_after,
        "Python helper changed during replay"
    );
    assert_eq!(
        test_hash_before, test_hash_after,
        "Rust test source changed during replay"
    );
    assert_eq!(
        fs::read(package_file(
            "tests/fixtures/historical_filesystem/fixture-digests.json"
        ))
        .unwrap(),
        include_bytes!("fixtures/historical_filesystem/fixture-digests.json")
    );

    let binding = json!({
        "schema": "ami-rust-historical-filesystem-binding-v1",
        "source_root": source,
        "source_hashes_before": source_hashes_before,
        "source_hashes_after": source_hashes_after,
        "rust_test_source_sha256": test_hash_before,
        "python_helper_sha256": helper_hash_before,
        "fixture_digest_manifest_sha256": sha256_bytes(include_bytes!("fixtures/historical_filesystem/fixture-digests.json")),
        "test_binary_sha256": sha256_file(&test_binary),
        "python_runtime_manifest": ci,
        "python_host": host,
        "python_executable_sha256": sha256_file(&python),
        "tarfile_sha256": TARFILE_SHA256,
        "report_sha256": sha256_bytes(&report_bytes),
        "scope": "Maintainer-only inventory and publisher TAR differential; not consumer command or no-Python acceptance"
    });
    fs::write(
        work.join("binding.json"),
        serde_json::to_vec_pretty(&binding).expect("serialize runtime binding"),
    )
    .expect("preserve runtime binding");
}

#[test]
#[ignore = "Isolated selected-core child, launched only by paired_historical_filesystem"]
fn filesystem_core_cases() {
    let _source = source_root();
    let plan_path =
        PathBuf::from(env::var_os("AMI_RUST_FILESYSTEM_CASE_PLAN").expect("private case plan"));
    let result_path = PathBuf::from(
        env::var_os("AMI_RUST_FILESYSTEM_RUST_RESULT").expect("private Rust result path"),
    );
    assert!(
        plan_path.is_absolute() && plan_path.is_file(),
        "case plan must be an absolute file"
    );
    assert!(
        result_path.is_absolute() && !result_path.exists(),
        "Rust case result must be fresh"
    );
    let plan: Value = serde_json::from_slice(&fs::read(&plan_path).expect("read case plan"))
        .expect("parse case plan");
    let cases = plan["cases"].as_array().expect("case array");
    assert_eq!(
        cases.len(),
        50,
        "case plan must contain 50 inventory/TAR pairs"
    );
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let kind = case["kind"].as_str().expect("case kind");
        let name = case["case"].as_str().expect("case name");
        let (accepted, semantic_report, error) = match kind {
            "inventory" => run_inventory_case(case),
            "archive" => run_archive_case(case),
            _ => fail(format!("unknown case kind {kind:?}")),
        };
        results.push(json!({
            "kind": kind,
            "case": name,
            "decision": if accepted { "accept" } else { "refuse" },
            "decision_exit_code": if accepted { 0 } else { 2 },
            "semantic_report": semantic_report,
            "error": error,
        }));
    }
    let result = json!({"status":"ok","case_count":results.len(),"cases":results});
    fs::write(
        &result_path,
        serde_json::to_vec_pretty(&result).expect("serialize Rust case results"),
    )
    .expect("write Rust case results");
}

fn inventory_inputs(value: &Value) -> (Vec<FileIdentity>, Vec<LinkIdentity>) {
    let files = value["files"]
        .as_array()
        .expect("inventory files")
        .iter()
        .map(|row| FileIdentity {
            path: row["path"].as_str().expect("file path").to_owned(),
            bytes: row["bytes"].as_u64().expect("file bytes"),
            sha256: row["sha256"].as_str().expect("file SHA").to_owned(),
            mode: row
                .get("mode")
                .and_then(Value::as_u64)
                .map(|mode| u32::try_from(mode).expect("mode fits u32")),
        })
        .collect();
    let links = value
        .get("symlinks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|row| LinkIdentity {
            path: row["path"].as_str().expect("symlink path").to_owned(),
            target: row["target"].as_str().expect("symlink target").to_owned(),
        })
        .collect();
    (files, links)
}

fn run_inventory_case(case: &Value) -> (bool, Option<Value>, Option<String>) {
    let root = Path::new(case["root"].as_str().expect("inventory root"));
    let manifest: Value = serde_json::from_slice(
        &fs::read(case["inventory"].as_str().expect("inventory manifest"))
            .unwrap_or_else(|error| fail(format!("read inventory: {error}"))),
    )
    .expect("parse inventory");
    let (files, links) = inventory_inputs(&manifest);
    match verify_complete(
        root,
        &files,
        &links,
        InventoryLimits {
            max_tree_entries: 100_000,
            max_link_resolution_steps: 100_000,
        },
    ) {
        Ok(measured) => (
            true,
            Some(json!({
                "files": measured.files,
                "symlinks": measured.symlinks,
                "directories": measured.directories,
                "file_bytes": measured.file_bytes,
            })),
            None,
        ),
        Err(error) => (false, None, Some(error.to_string())),
    }
}

fn run_archive_case(case: &Value) -> (bool, Option<Value>, Option<String>) {
    let archive_path = Path::new(case["archive"].as_str().expect("archive path"));
    let inventory_path = Path::new(case["inventory"].as_str().expect("archive inventory"));
    let archive =
        fs::read(archive_path).unwrap_or_else(|error| fail(format!("read archive: {error}")));
    let inventory: Value = serde_json::from_slice(
        &fs::read(inventory_path)
            .unwrap_or_else(|error| fail(format!("read archive inventory: {error}"))),
    )
    .expect("parse archive inventory");
    let expected: Vec<ExpectedFile<'_>> = inventory
        .as_array()
        .expect("inventory rows")
        .iter()
        .map(|row| ExpectedFile {
            path: row["path"].as_str().expect("expected path"),
            size: usize::try_from(row["bytes"].as_u64().expect("expected bytes"))
                .expect("file size fits usize"),
            sha256: row["sha256"].as_str().expect("expected SHA"),
        })
        .collect();
    let mut decoded = Vec::new();
    let result = copy_xz(
        &archive,
        &mut decoded,
        DecodeLimits {
            max_compressed_bytes: archive.len(),
            max_decoded_bytes: 16 * 1024 * 1024,
            max_xz_memory_kib: 65_536,
        },
    )
    .map_err(|error| error.to_string())
    .and_then(|_| verify_publisher_sdk_tar(&decoded, &expected).map_err(|error| error.to_string()));
    match result {
        Ok(files) => {
            let report: BTreeMap<String, Value> = files.into_iter().map(|file| (
                file.path,
                json!({"bytes":file.contents.len(),"sha256":sha256_bytes(file.contents),"mode":file.mode}),
            )).collect();
            (
                true,
                Some(serde_json::to_value(report).expect("archive report")),
                None,
            )
        }
        Err(error) => (false, None, Some(error)),
    }
}

//! Explicit maintainer comparison; historical Python is never a consumer child.
use ami_rust_core::{digest::sha256_bytes, host_platform::supported_host, records::Host};
use serde_json::Value;
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
#[path = "support/transaction_bridge.rs"]
mod transaction_bridge;

fn verify_runtime(source: &Path, python: &Path) {
    assert!(
        python.is_absolute(),
        "explicit absolute historical interpreter required"
    );
    assert_eq!(fs::canonicalize(python).unwrap(), python);
    assert!(fs::symlink_metadata(python).unwrap().is_file());
    let pin: Value =
        serde_json::from_slice(&fs::read(source.join("release/ci-python-inputs.json")).unwrap())
            .unwrap();
    let host = match supported_host().unwrap() {
        Host::MacosAarch64 => "macos-aarch64",
        Host::LinuxX86_64 => "linux-x86_64",
    };
    let raw = fs::read(python).unwrap();
    assert_eq!(
        raw.len() as u64,
        pin["hosts"][host]["runtime_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        sha256_bytes(&raw),
        pin["hosts"][host]["runtime_sha256"].as_str().unwrap()
    );
    for (path, hash) in [
        (
            "release/install.py",
            "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984",
        ),
        (
            "release/test_install.py",
            "379ba1ab0f3795dd880c17ec46705bf976da9b21bc9a57f7884c573e73bcd64c",
        ),
    ] {
        assert_eq!(
            sha256_bytes(&fs::read(source.join(path)).unwrap()),
            hash,
            "historical source drift: {path}"
        );
    }
}

#[test]
#[ignore = "Explicit historical qualification with the pinned internal Python runtime"]
fn paired_historical_transactions() {
    let source =
        PathBuf::from(env::var_os("AMI_RUST_DIFFERENTIAL_SOURCE").expect("explicit source root"));
    assert_eq!(
        fs::canonicalize(&source).unwrap(),
        fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).unwrap(),
        "historical source must be the checkout linked into this test binary"
    );
    let python = PathBuf::from(
        env::var_os("AMI_RUST_HISTORICAL_PYTHON").expect("explicit pinned interpreter"),
    );
    verify_runtime(&source, &python);
    let work = PathBuf::from(
        env::var_os("AMI_RUST_DIFFERENTIAL_WORK").expect("fresh private output directory"),
    );
    assert!(work.is_absolute());
    assert!(!work.exists());
    fs::create_dir(&work).unwrap();
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    let home = work.join("home");
    let tmp = work.join("tmp");
    for p in [&home, &tmp] {
        fs::create_dir(p).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let helper =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/historical_transactions.py");
    let test = env::current_exe().unwrap();
    let out = Command::new(&python)
        .args(["-I", "-B"])
        .arg(&helper)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", &home)
        .env("TMPDIR", &tmp)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("AMI_RUST_DIFFERENTIAL_SOURCE", &source)
        .env("AMI_RUST_DIFFERENTIAL_WORK", &work)
        .env("AMI_RUST_DIFFERENTIAL_TEST_BINARY", &test)
        .current_dir(&work)
        .output()
        .unwrap();
    fs::write(work.join("coordinator.stdout.log"), &out.stdout).unwrap();
    fs::write(work.join("coordinator.stderr.log"), &out.stderr).unwrap();
    assert!(
        out.status.success(),
        "historical comparison failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value =
        serde_json::from_slice(&fs::read(work.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "pass");
    assert_eq!(report["case_count"], 9);
    assert_eq!(report["cases"].as_array().unwrap().len(), 9);
    let binding = serde_json::json!({"schema":"ami-rust-live-transaction-comparison-v1","cases":9,
        "test_binary_sha256":sha256_bytes(&fs::read(&test).unwrap()),
        "python_helper_sha256":sha256_bytes(&fs::read(&helper).unwrap()),
        "bridge_source_sha256":sha256_bytes(&fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/transaction_bridge.rs")).unwrap()),
        "report_sha256":sha256_bytes(&fs::read(work.join("report.json")).unwrap()),
        "scope":"Current-host filesystem API effects only; not native-v3 authentication or full consumer/no-Python acceptance"});
    fs::write(
        work.join("binding.json"),
        serde_json::to_vec_pretty(&binding).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "Isolated Rust child, launched only by paired_historical_transactions"]
fn transaction_bridge_child() {
    assert!(env::var_os("AMI_RUST_TRANSACTION_PLAN").is_some());
    transaction_bridge::main();
}

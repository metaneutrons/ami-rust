//! Opt-in real-verifier control using a retained independently pinned package.
//! This authenticates its outer assets, not the host CLI or a native-v2 SDK.
use ami_rust_core::{
    digest::sha256_bytes,
    package::{PackageRuntime, check_native_package_root},
    publisher::outer::verify_outer_package,
    records::Host,
};
use serde_json::Value;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

#[test]
#[ignore = "requires AMI_RUST_OUTER_FIXTURE_PACKAGE, _POLICY and _INPUTS with real pinned verifiers"]
fn actual_outer_verifiers_accept_retained_assets_and_reject_an_altered_signature() {
    let package_path = PathBuf::from(std::env::var_os("AMI_RUST_OUTER_FIXTURE_PACKAGE").unwrap());
    let policy = PathBuf::from(std::env::var_os("AMI_RUST_OUTER_FIXTURE_POLICY").unwrap());
    let inputs = fs::read(PathBuf::from(
        std::env::var_os("AMI_RUST_OUTER_FIXTURE_INPUTS").unwrap(),
    ))
    .unwrap();
    let runtime = || PackageRuntime {
        host: Host::current().unwrap(),
        cli_version: env!("CARGO_PKG_VERSION"),
    };
    let package = check_native_package_root(&package_path, runtime()).unwrap();
    let verified = verify_outer_package(&package, &policy, &inputs, || false).unwrap();
    assert_eq!(verified.resource_reports().len(), 6);
    assert_eq!(verified.selected_proofs().len(), 4);
    assert!(
        verified
            .selected_proofs()
            .values()
            .all(|rows| !rows.is_empty())
    );
    assert_eq!(
        sha256_bytes(verified.archive()),
        verified.record().archive.sha256
    );

    let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
    let scratch = parent.join(format!(
        "ami-rust-outer-counterprobe-{}",
        std::process::id()
    ));
    fs::DirBuilder::new().mode(0o700).create(&scratch).unwrap();
    // Copy the checked inventory explicitly; no original proof or release asset
    // is ever edited. Updating consistency pins lets the real crypto tool see
    // the deliberately damaged signature rather than an earlier hash refusal.
    for row in &package.inventory().files {
        let target = scratch.join(&row.path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(package_path.join(&row.path), target).unwrap();
    }
    let mut proofs: Value =
        serde_json::from_slice(&fs::read(scratch.join("proofs.json")).unwrap()).unwrap();
    let payload = verified.record().archive.name.clone();
    let row = proofs["subjects"][&payload]
        .as_array_mut()
        .unwrap()
        .first_mut()
        .unwrap();
    let relative = format!("proofs/{}", row["path"].as_str().unwrap());
    let proof_path = scratch.join(&relative);
    let old_digest = row["sha256"].as_str().unwrap().to_owned();
    let mut proof: Value = serde_json::from_slice(&fs::read(&proof_path).unwrap()).unwrap();
    let signature = proof["dsseEnvelope"]["signatures"][0]["sig"]
        .as_str()
        .unwrap();
    let mut altered = signature.to_owned();
    let first = if signature.starts_with('A') { "B" } else { "A" };
    altered.replace_range(..1, first);
    proof["dsseEnvelope"]["signatures"][0]["sig"] = Value::String(altered);
    let raw = serde_json::to_vec(&proof).unwrap();
    fs::write(&proof_path, &raw).unwrap();
    let new_digest = sha256_bytes(&raw);
    row["sha256"] = Value::String(new_digest.clone());
    row["bytes"] = Value::from(raw.len());
    fs::write(
        scratch.join("proofs.json"),
        serde_json::to_vec(&proofs).unwrap(),
    )
    .unwrap();
    let mut pins: Value =
        serde_json::from_slice(&fs::read(scratch.join("pins.json")).unwrap()).unwrap();
    let pinned = pins["publisher_proofs"][&payload].as_array_mut().unwrap();
    let identity = pinned
        .iter_mut()
        .find(|row| row["sha256"] == old_digest)
        .unwrap();
    identity["sha256"] = Value::String(new_digest);
    identity["bytes"] = Value::from(raw.len());
    fs::write(
        scratch.join("pins.json"),
        serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let mut inventory: Value = serde_json::from_slice(package.raw_inventory()).unwrap();
    for row in inventory["files"].as_array_mut().unwrap() {
        let raw = fs::read(scratch.join(row["path"].as_str().unwrap())).unwrap();
        row["bytes"] = Value::from(raw.len());
        row["sha256"] = Value::String(sha256_bytes(&raw));
    }
    fs::write(
        scratch.join("inventory.json"),
        serde_json::to_vec(&inventory).unwrap(),
    )
    .unwrap();
    let altered_package = check_native_package_root(&scratch, runtime()).unwrap();
    let error = match verify_outer_package(&altered_package, &policy, &inputs, || false) {
        Ok(_) => panic!("altered real GitHub signature was accepted"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("unambiguous authenticated pinned-run statement"),
        "{error}"
    );
    assert!(
        error.to_string().contains("completed verifier captures=1"),
        "{error}"
    );
    assert_eq!(
        package.read_file("proofs.json").unwrap(),
        fs::read(package_path.join("proofs.json")).unwrap()
    );
    fs::remove_dir_all(&scratch).unwrap();
    println!(
        "Real outer authentication: four GH + two Cosign PASS; isolated altered GH signature REFUSED"
    );
}

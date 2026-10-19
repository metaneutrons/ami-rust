//! Opt-in compatibility check against the immutable, Python-produced R1 bytes.
//! This reads historical data; it never executes Cargo or a historical helper.
use ami_rust_core::{
    cargo_archive::{CargoArchiveSpec, extract_flat_cargo_archive},
    compression::{DecodeLimits, copy_xz},
    digest::sha256_bytes,
    directory::Directory,
    inventory::FileIdentity,
    json::{JsonProfile, parse_json_value},
};
use serde_json::Value;
use std::{
    collections::BTreeMap, ffi::OsStr, fs, io::Read, os::unix::fs::DirBuilderExt, path::PathBuf,
};

#[test]
#[ignore = "requires AMI_RUST_RETAINED_R1_BUNDLE containing exact accepted R1 archives"]
fn extracts_both_accepted_cargo_archives_and_refuses_an_altered_copy() {
    let bundle = PathBuf::from(std::env::var_os("AMI_RUST_RETAINED_R1_BUNDLE").unwrap());
    let baseline = parse_json_value(
        include_bytes!("../../../fixtures/accepted-r1-inputs.json"),
        JsonProfile::SdkComponentManifest,
    )
    .unwrap();
    let sdk = fs::read(bundle.join("sdk.tar.xz")).unwrap();
    assert_eq!(sdk.len(), 598_584);
    assert_eq!(
        sha256_bytes(&sdk),
        "087f69659f1d0d5136b2c07789488c23dd52ca7b38b21579183620a5fbc61dd4"
    );
    let mut decoded = Vec::new();
    copy_xz(
        &sdk,
        &mut decoded,
        DecodeLimits {
            max_compressed_bytes: 16 * 1024 * 1024,
            max_decoded_bytes: 16 * 1024 * 1024,
            max_xz_memory_kib: 64 * 1024,
        },
    )
    .unwrap();
    let mut profiles = BTreeMap::new();
    for entry in tar::Archive::new(decoded.as_slice()).entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_str().unwrap().to_owned();
        if name.ends_with("/cargo.json") {
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).unwrap();
            assert!(profiles.insert(name, raw).is_none());
        }
    }
    let scratch = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("ami-rust-retained-cargo-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&scratch).unwrap();
    let root = Directory::open(&scratch).unwrap();
    for host in ["linux-x86_64", "macos-aarch64"] {
        let row = baseline["component_manifests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["host"] == host && row["component"] == "cargo")
            .unwrap();
        let raw = &profiles[row["path"].as_str().unwrap()];
        assert_eq!(raw.len() as u64, row["bytes"].as_u64().unwrap());
        assert_eq!(sha256_bytes(raw), row["sha256"].as_str().unwrap());
        let profile: Value = parse_json_value(raw, JsonProfile::SdkComponentManifest).unwrap();
        let files: Vec<FileIdentity> = serde_json::from_value(profile["files"].clone()).unwrap();
        let pin = baseline["runtime_acquisition"]["authenticated_bundle_cargo_assets"]["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == format!("cargo-{host}.tar.xz"))
            .unwrap();
        let archive = bundle.join(pin["path"].as_str().unwrap());
        let spec = |name| CargoArchiveSpec {
            destination_name: name,
            compressed_bytes: pin["bytes"].as_u64().unwrap(),
            compressed_sha256: pin["sha256"].as_str().unwrap(),
            files: &files,
            links: &[],
        };
        let receipt = extract_flat_cargo_archive(
            fs::File::open(&archive).unwrap(),
            &root,
            spec(OsStr::new(host)),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(receipt.measurement.files, 2);
        assert_eq!(receipt.measurement.symlinks, 0);
        let mut changed = fs::read(&archive).unwrap();
        changed[0] ^= 1;
        let changed_path = scratch.join("altered.tar.xz");
        fs::write(&changed_path, changed).unwrap();
        let error = extract_flat_cargo_archive(
            fs::File::open(&changed_path).unwrap(),
            &root,
            spec(OsStr::new("must-not-exist")),
            || Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("SHA-256"), "{error}");
        assert!(!scratch.join("must-not-exist").exists());
        fs::remove_file(&changed_path).unwrap();
        println!("{host}: accepted R1 archive/profile PASS; altered copy REFUSED");
    }
    fs::remove_dir_all(&scratch).unwrap();
}

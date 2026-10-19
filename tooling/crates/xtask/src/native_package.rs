//! Compose an unsigned native package-v2 directory from retained records and
//! already-selected payload bytes.
//!
//! This checks record-to-byte consistency and package roles. It does not
//! authenticate a publisher, accept licenses, qualify a release, or publish
//! the returned files.

use std::collections::{BTreeMap, BTreeSet};

use ami_rust_core::{
    Refusal, Result,
    digest::sha256_bytes,
    package::check_native_header,
    package_records::{
        NativePackagePins, parse_native_package_inventory, parse_native_package_pins,
        parse_native_package_proofs,
    },
};
use serde_json::Value;

const INVENTORY_SCHEMA: &str = "ami-rust-package-inventory-v2";
const INVENTORY_PATH: &str = "inventory.json";
const PINS_PATH: &str = "pins.json";
const PROOFS_PATH: &str = "proofs.json";
const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MEMBER_BYTES: usize = 128 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 16_384;
const REQUIRED_NOTICES: [&str; 3] = ["LICENSE-MIT", "LICENSE-APACHE", "THIRD-PARTY-NOTICES.md"];
const LAUNCHER_PATHS: [&str; 2] = ["bin/ami-rust", "bin/cargo-ami"];

/// Unsigned files for one native package-v2 root.
///
/// `files` contains `inventory.json`; `inventory` is the same byte string for
/// callers that need to write it separately. Modes are `0755` for the two
/// paths in `LAUNCHER_PATHS` and `0644` for every other file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePackageDraft {
    pub files: BTreeMap<String, Vec<u8>>,
    pub inventory: Vec<u8>,
}

/// Assemble a byte-consistent unsigned native package-v2 file set.
///
/// `assets` is keyed by each pinned release-asset filename. `proofs` is keyed
/// by the flat proof filename named by `proofs_raw`. `notices` contains only
/// the three required notice files, nonempty `licenses/*` texts, and optional
/// `README.md`. `launcher` is copied to both pinned frontend paths because
/// the package contract requires identical statically-linked frontend bytes.
pub fn assemble_native_package(
    pins_raw: &[u8],
    proofs_raw: &[u8],
    launcher: &[u8],
    assets: &BTreeMap<String, Vec<u8>>,
    proofs: &BTreeMap<String, Vec<u8>>,
    notices: &BTreeMap<String, Vec<u8>>,
) -> Result<NativePackageDraft> {
    let pins = parse_native_package_pins(pins_raw)?;
    let proof_identities = parse_native_package_proofs(proofs_raw, &pins)?;
    if pins_raw.len() > MAX_METADATA_BYTES || proofs_raw.len() > MAX_METADATA_BYTES {
        return Err(Refusal::new("native package records exceed 2 MiB"));
    }
    verify_launcher(launcher, &pins)?;
    verify_assets(assets, &pins)?;
    verify_proofs(proofs, &proof_identities)?;
    validate_notice_roles(notices)?;
    check_input_byte_bound(pins_raw, proofs_raw, launcher, assets, proofs, notices)?;

    let mut files = BTreeMap::new();
    insert_file(&mut files, PINS_PATH, pins_raw.to_vec())?;
    insert_file(&mut files, PROOFS_PATH, proofs_raw.to_vec())?;
    for path in LAUNCHER_PATHS {
        insert_file(&mut files, path, launcher.to_vec())?;
    }
    for (path, contents) in assets {
        insert_file(&mut files, &format!("assets/{path}"), contents.clone())?;
    }
    for (path, contents) in proofs {
        insert_file(&mut files, &format!("proofs/{path}"), contents.clone())?;
    }
    for (path, contents) in notices {
        let raw = if path == "THIRD-PARTY-NOTICES.md" {
            crate::native_notices::render_notice(
                contents,
                &pins.source_commit,
                &format!(
                    "https://github.com/metaneutrons/ami-rust/blob/{}/tooling/third-party/inventory.json",
                    pins.source_commit
                ),
                "licenses/",
            )?
        } else {
            contents.clone()
        };
        insert_file(&mut files, path, raw)?;
    }

    if package_tree_entries(&files) > MAX_TREE_ENTRIES {
        return Err(Refusal::new(
            "native package exceeds its 16,384-entry tree profile",
        ));
    }

    let rows = files
        .iter()
        .map(|(path, contents)| {
            serde_json::json!({
                "path": path,
                "bytes": contents.len(),
                "sha256": sha256_bytes(contents),
                "mode": file_mode(path),
            })
        })
        .collect::<Vec<_>>();
    let inventory_value = serde_json::json!({
        "schema": INVENTORY_SCHEMA,
        "cli_version": pins.cli_version,
        "sdk_version": pins.sdk_version,
        "package_version": pins.package_version,
        "host": pins.host,
        "files": rows,
    });
    let inventory = canonical_json_line(&inventory_value)?;
    if inventory.len() > MAX_METADATA_BYTES {
        return Err(Refusal::new("native package inventory exceeds 2 MiB"));
    }
    // Reuse the consumer parser for inventory schema, path, digest, mode,
    // version, duplicate, and complete byte-total validation.
    let parsed_inventory = parse_native_package_inventory(&inventory)?;
    if parsed_inventory.cli_version != pins.cli_version
        || parsed_inventory.sdk_version != pins.sdk_version
        || parsed_inventory.package_version != pins.package_version
        || parsed_inventory.host != pins.host
    {
        return Err(Refusal::new(
            "native package inventory identity differs from its pins",
        ));
    }

    let total = files
        .values()
        .map(|contents| contents.len() as u64)
        .chain(std::iter::once(inventory.len() as u64))
        .try_fold(0_u64, |sum, bytes| sum.checked_add(bytes))
        .ok_or_else(|| Refusal::new("native package byte total overflow"))?;
    if total > MAX_PACKAGE_BYTES {
        return Err(Refusal::new(
            "native package exceeds its 512 MiB container profile",
        ));
    }
    insert_file(&mut files, INVENTORY_PATH, inventory.clone())?;

    Ok(NativePackageDraft { files, inventory })
}

fn verify_launcher(launcher: &[u8], pins: &NativePackagePins) -> Result<()> {
    let bytes = launcher.len() as u64;
    for name in ["ami-rust", "cargo-ami"] {
        let pin = pins
            .launchers
            .get(name)
            .ok_or_else(|| Refusal::new(format!("native launcher pin is missing: {name}")))?;
        if pin.path != format!("bin/{name}") || pin.bytes != bytes {
            return Err(Refusal::new(format!(
                "native launcher bytes differ from the {name} pin"
            )));
        }
    }
    check_native_header(launcher, pins.host)?;
    let digest = sha256_bytes(launcher);
    if pins
        .launchers
        .values()
        .any(|pin| pin.sha256.as_str() != digest.as_str())
    {
        return Err(Refusal::new(
            "native launcher bytes differ from their pinned digest",
        ));
    }
    Ok(())
}

fn verify_assets(assets: &BTreeMap<String, Vec<u8>>, pins: &NativePackagePins) -> Result<()> {
    let expected = pins
        .assets
        .iter()
        .map(|pin| pin.path.as_str())
        .collect::<BTreeSet<_>>();
    let actual = assets.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(Refusal::new(
            "native package assets do not match the exact pinned asset set",
        ));
    }
    for pin in &pins.assets {
        verify_bytes(
            assets
                .get(&pin.path)
                .ok_or_else(|| Refusal::new("pinned native package asset is missing"))?,
            pin.bytes,
            pin.sha256.as_str(),
            &format!("native package asset {}", pin.path),
        )?;
    }
    Ok(())
}

fn verify_proofs(
    proofs: &BTreeMap<String, Vec<u8>>,
    proof_identities: &BTreeMap<String, ami_rust_core::package_records::AssetPin>,
) -> Result<()> {
    let expected = proof_identities
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actual = proofs.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(Refusal::new(
            "native package proof bytes do not match the exact proof record set",
        ));
    }
    for (path, identity) in proof_identities {
        verify_bytes(
            proofs
                .get(path)
                .ok_or_else(|| Refusal::new("pinned native package proof is missing"))?,
            identity.bytes,
            identity.sha256.as_str(),
            &format!("native package proof {path}"),
        )?;
    }
    Ok(())
}

fn validate_notice_roles(notices: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for required in REQUIRED_NOTICES {
        let contents = notices.get(required).ok_or_else(|| {
            Refusal::new(format!(
                "required native package notice is missing: {required}"
            ))
        })?;
        if contents.is_empty() {
            return Err(Refusal::new(format!(
                "required native package notice is empty: {required}"
            )));
        }
    }

    let mut license_count = 0;
    for (path, contents) in notices {
        let allowed = REQUIRED_NOTICES.contains(&path.as_str())
            || path == "README.md"
            || path
                .strip_prefix("licenses/")
                .is_some_and(|suffix| !suffix.is_empty());
        if !allowed {
            return Err(Refusal::new(format!(
                "native package notice has no permitted role: {path}"
            )));
        }
        if path.starts_with("licenses/") {
            if contents.is_empty() || contents.len() > MAX_MEMBER_BYTES {
                return Err(Refusal::new(format!(
                    "native package third-party license has an invalid size: {path}"
                )));
            }
            license_count += 1;
        }
        if contents.len() > MAX_MEMBER_BYTES {
            return Err(Refusal::new(format!(
                "native package notice exceeds 128 MiB: {path}"
            )));
        }
        if path == "README.md" && contents.len() > MAX_METADATA_BYTES {
            return Err(Refusal::new("native package README exceeds 2 MiB"));
        }
    }
    if license_count == 0 {
        return Err(Refusal::new(
            "native package requires at least one licenses/ file",
        ));
    }
    Ok(())
}

fn check_input_byte_bound(
    pins_raw: &[u8],
    proofs_raw: &[u8],
    launcher: &[u8],
    assets: &BTreeMap<String, Vec<u8>>,
    proofs: &BTreeMap<String, Vec<u8>>,
    notices: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let mut total = 0_u64;
    for contents in [pins_raw, proofs_raw, launcher, launcher]
        .into_iter()
        .chain(assets.values().map(Vec::as_slice))
        .chain(proofs.values().map(Vec::as_slice))
        .chain(notices.values().map(Vec::as_slice))
    {
        total = total
            .checked_add(contents.len() as u64)
            .ok_or_else(|| Refusal::new("native package byte total overflow"))?;
        if total > MAX_PACKAGE_BYTES {
            return Err(Refusal::new(
                "native package exceeds its 512 MiB container profile",
            ));
        }
    }
    Ok(())
}

fn verify_bytes(
    contents: &[u8],
    expected_bytes: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<()> {
    if contents.len() as u64 != expected_bytes || sha256_bytes(contents) != expected_sha256 {
        return Err(Refusal::new(format!(
            "{label} differs from its pinned identity"
        )));
    }
    Ok(())
}

fn insert_file(files: &mut BTreeMap<String, Vec<u8>>, path: &str, contents: Vec<u8>) -> Result<()> {
    if files.insert(path.to_owned(), contents).is_some() {
        return Err(Refusal::new(format!(
            "duplicate native package path: {path}"
        )));
    }
    Ok(())
}

fn file_mode(path: &str) -> u32 {
    if LAUNCHER_PATHS.contains(&path) {
        0o755
    } else {
        0o644
    }
}

/// Return the contract mode for an assembled package path.
pub fn native_package_file_mode(path: &str) -> u32 {
    file_mode(path)
}

fn package_tree_entries(files: &BTreeMap<String, Vec<u8>>) -> usize {
    let mut entries = BTreeSet::new();
    let inventory_path = INVENTORY_PATH.to_owned();
    for path in files.keys().chain(std::iter::once(&inventory_path)) {
        let components = path.split('/').collect::<Vec<_>>();
        for length in 1..=components.len() {
            entries.insert(components[..length].join("/"));
        }
    }
    entries.len()
}

fn canonical_json_line(value: &Value) -> Result<Vec<u8>> {
    let mut raw = serde_json::to_vec(value).map_err(|error| {
        Refusal::new(format!(
            "could not serialize native package inventory: {error}"
        ))
    })?;
    raw.push(b'\n');
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ami_rust_core::{digest::sha256_bytes, records::Host};
    use serde_json::{Map, json};

    const SDK_VERSION: &str = "0.2.0";

    struct Fixture {
        pins_raw: Vec<u8>,
        proofs_raw: Vec<u8>,
        launcher: Vec<u8>,
        assets: BTreeMap<String, Vec<u8>>,
        proofs: BTreeMap<String, Vec<u8>>,
        notices: BTreeMap<String, Vec<u8>>,
    }

    impl Fixture {
        fn new() -> Self {
            let launcher = macos_header();
            let assets = BTreeMap::from([
                ("SHA256SUMS".to_owned(), b"checksum fixture\n".to_vec()),
                (
                    format!("ami-rust-{SDK_VERSION}-release.tar.xz"),
                    b"archive fixture\n".to_vec(),
                ),
                (
                    format!("ami-rust-{SDK_VERSION}-release.tar.xz.sigstore.json"),
                    b"archive signature fixture\n".to_vec(),
                ),
                (
                    format!("ami-rust-{SDK_VERSION}-release.tar.xz.spdx.json"),
                    b"archive SPDX fixture\n".to_vec(),
                ),
                (
                    format!("ami-rust-{SDK_VERSION}-transport.json"),
                    b"transport fixture\n".to_vec(),
                ),
                (
                    format!("ami-rust-{SDK_VERSION}-transport.json.sigstore.json"),
                    b"transport signature fixture\n".to_vec(),
                ),
            ]);
            let proof_path = "fixture.json".to_owned();
            let proof_bytes = b"{\"proof\":\"fixture\"}\n".to_vec();
            let proofs = BTreeMap::from([(proof_path.clone(), proof_bytes.clone())]);
            let proof_identity = json!({
                "path": proof_path,
                "bytes": proof_bytes.len(),
                "sha256": sha256_bytes(&proof_bytes),
            });
            let pinned_proof_identity = json!({
                "bytes": proof_bytes.len(),
                "sha256": sha256_bytes(&proof_bytes),
            });
            let mut proof_rows = Map::new();
            let mut publisher_proofs = Map::new();
            for subject in proof_subjects() {
                proof_rows.insert(subject.to_owned(), json!([proof_identity.clone()]));
                publisher_proofs.insert(subject.to_owned(), json!([pinned_proof_identity.clone()]));
            }
            let proofs_raw = json_line(&json!({
                "schema": "ami-rust-package-proofs-v2",
                "subjects": proof_rows,
            }));

            let mut assets_rows = Vec::new();
            for (path, contents) in &assets {
                assets_rows.push(json!({
                    "path": path,
                    "bytes": contents.len(),
                    "sha256": sha256_bytes(contents),
                }));
            }
            let mut launchers = Map::new();
            let launcher_digest = sha256_bytes(&launcher);
            for (name, path) in [("ami-rust", "bin/ami-rust"), ("cargo-ami", "bin/cargo-ami")] {
                launchers.insert(
                    name.to_owned(),
                    json!({
                        "path": path,
                        "bytes": launcher.len(),
                        "sha256": launcher_digest,
                    }),
                );
            }
            let transport_path = format!("ami-rust-{SDK_VERSION}-transport.json");
            let transport_sha256 = sha256_bytes(&assets[&transport_path]);
            let pins = json!({
                "schema": "ami-rust-package-inputs-v2",
                "cli_version": "0.2.0-dev",
                "sdk_version": SDK_VERSION,
                "packaging_revision": 1,
                "package_version": "0.2.0-1",
                "packaging_tag": "v0.2.0+packaging.1",
                "sdk_tag": "v0.2.0",
                "repository": "metaneutrons/ami-rust",
                "source_commit": "1111111111111111111111111111111111111111",
                "source_tree": "2222222222222222222222222222222222222222",
                "sdk_run_id": 1,
                "sdk_run_attempt": 1,
                "manifest_sha256": "a".repeat(64),
                "transport_sha256": transport_sha256,
                "assets": assets_rows,
                "hosts": {
                    "apt": "linux-x86_64",
                    "homebrew": "macos-aarch64",
                },
                "maintainer": "synthetic native package fixture",
                "publisher_proofs": publisher_proofs,
                "host": "macos-aarch64",
                "launchers": launchers,
                "core_sha256": launcher_digest,
            });
            let pins_raw = json_line(&pins);
            let notices = BTreeMap::from([
                ("LICENSE-MIT".to_owned(), b"MIT text\n".to_vec()),
                ("LICENSE-APACHE".to_owned(), b"Apache text\n".to_vec()),
                (
                    "THIRD-PARTY-NOTICES.md".to_owned(),
                    b"Notice text\n".to_vec(),
                ),
                (
                    "licenses/dependency.txt".to_owned(),
                    b"License text\n".to_vec(),
                ),
                ("README.md".to_owned(), b"Native package fixture\n".to_vec()),
            ]);
            Self {
                pins_raw,
                proofs_raw,
                launcher,
                assets,
                proofs,
                notices,
            }
        }

        fn assemble(&self) -> Result<NativePackageDraft> {
            assemble_native_package(
                &self.pins_raw,
                &self.proofs_raw,
                &self.launcher,
                &self.assets,
                &self.proofs,
                &self.notices,
            )
        }
    }

    fn proof_subjects() -> [&'static str; 4] {
        [
            "SHA256SUMS",
            "ami-rust-0.2.0-release.tar.xz",
            "ami-rust-0.2.0-release.tar.xz.spdx.json",
            "ami-rust-0.2.0-transport.json",
        ]
    }

    fn json_line(value: &Value) -> Vec<u8> {
        let mut raw = serde_json::to_vec(value).expect("fixture JSON serializes");
        raw.push(b'\n');
        raw
    }

    fn macos_header() -> Vec<u8> {
        let mut raw = vec![0_u8; 64];
        raw[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        raw[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
        raw[12..16].copy_from_slice(&2_u32.to_le_bytes());
        raw
    }

    #[test]
    fn assembles_deterministic_inventory_and_exact_payload_bytes() {
        let fixture = Fixture::new();
        let first = fixture.assemble().expect("consistent package draft");
        let second = fixture.assemble().expect("deterministic package draft");
        assert_eq!(first, second);
        assert_eq!(first.files["bin/ami-rust"], fixture.launcher);
        assert_eq!(first.files["bin/cargo-ami"], fixture.launcher);
        assert_eq!(first.files["pins.json"], fixture.pins_raw);
        assert_eq!(first.files["proofs.json"], fixture.proofs_raw);
        assert_eq!(first.files["inventory.json"], first.inventory);
        assert_eq!(file_mode("bin/ami-rust"), 0o755);
        assert_eq!(file_mode("bin/cargo-ami"), 0o755);
        assert_eq!(file_mode("licenses/dependency.txt"), 0o644);
        let parsed = parse_native_package_inventory(&first.inventory).unwrap();
        assert_eq!(parsed.host, Host::MacosAarch64);
        assert!(
            parsed
                .files
                .iter()
                .any(|row| row.path == "assets/SHA256SUMS")
        );
        assert!(
            parsed
                .files
                .iter()
                .any(|row| row.path == "proofs/fixture.json")
        );
    }

    #[test]
    fn rejects_mismatched_launcher_asset_proof_and_notice_inputs() {
        let fixture = Fixture::new();

        let mut wrong_launcher = fixture.launcher.clone();
        wrong_launcher.push(0);
        assert!(
            assemble_native_package(
                &fixture.pins_raw,
                &fixture.proofs_raw,
                &wrong_launcher,
                &fixture.assets,
                &fixture.proofs,
                &fixture.notices,
            )
            .is_err()
        );

        let mut wrong_assets = fixture.assets.clone();
        wrong_assets.insert("SHA256SUMS".to_owned(), b"changed\n".to_vec());
        assert!(
            assemble_native_package(
                &fixture.pins_raw,
                &fixture.proofs_raw,
                &fixture.launcher,
                &wrong_assets,
                &fixture.proofs,
                &fixture.notices,
            )
            .is_err()
        );

        let mut wrong_proofs = fixture.proofs.clone();
        wrong_proofs.insert("fixture.json".to_owned(), b"changed\n".to_vec());
        assert!(
            assemble_native_package(
                &fixture.pins_raw,
                &fixture.proofs_raw,
                &fixture.launcher,
                &fixture.assets,
                &wrong_proofs,
                &fixture.notices,
            )
            .is_err()
        );

        let mut wrong_notices = fixture.notices.clone();
        wrong_notices.insert("bin/python".to_owned(), b"not allowed\n".to_vec());
        assert!(
            assemble_native_package(
                &fixture.pins_raw,
                &fixture.proofs_raw,
                &fixture.launcher,
                &fixture.assets,
                &fixture.proofs,
                &wrong_notices,
            )
            .is_err()
        );
    }
}

//! Prepare unsigned native outer release assets from a retained inner bundle.
//!
//! This module checks release, policy, authentication-metadata, and byte
//! relationships before composing the transport capsule. It does not verify
//! signatures or authenticate any publisher claim; callers must do that
//! independently before treating the resulting assets as trusted.

use std::{collections::BTreeMap, io::Write};

use ami_rust_core::{
    Refusal, Result,
    digest::sha256_bytes,
    json::{JsonProfile, parse_json_value},
    public_transport::{
        MAX_NATIVE_TRANSPORT_ARCHIVE_BYTES, MAX_NATIVE_TRANSPORT_BYTES, MAX_NATIVE_TRANSPORT_FILES,
        canonical_header, parse_native_transport_record,
    },
    publisher_metadata::parse_authentication_metadata,
    publisher_policy::{parse_inputs_manifest, parse_publisher_policy},
    release_manifest::{NativeReleaseManifest, ReleaseFile, parse_native_release_manifest},
};
use lzma_rust2::{XzOptions, XzWriter};
use serde_json::{Map, Value};

const RELEASE_MANIFEST_PATH: &str = "release.json";
const AUTHENTICATION_PATH: &str = ".auth/authentication.json";
const INPUTS_PATH: &str = ".auth/inputs.json";
const SBOM_PATH: &str = "sbom.spdx.json";
const TAR_BLOCK_BYTES: usize = 512;
const TAR_RECORD_BYTES: usize = 10 * 1024;
const TAR_END_BYTES: usize = 2 * TAR_BLOCK_BYTES;
const XZ_PRESET: u32 = 6;

/// Prepared outer payload assets. The archive and transport record are
/// unsigned until separate protected and publishing steps sign them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeOuterDraft {
    /// Exactly the versioned release archive, its byte-identical SPDX
    /// companion, and the versioned native transport record.
    pub assets: BTreeMap<String, Vec<u8>>,
}

/// Prepare the exact three unsigned native outer assets from a retained inner
/// publisher bundle and independently supplied publisher policy bytes.
///
/// `files` must contain the exact file set declared by the authentication
/// metadata, including `release.json`, `.auth/inputs.json`, assets, and proof
/// bundles. Signature verification is the caller's responsibility.
pub fn prepare_native_outer(
    files: &BTreeMap<String, Vec<u8>>,
    policy_raw: &[u8],
) -> Result<NativeOuterDraft> {
    let manifest_raw = required_file(files, RELEASE_MANIFEST_PATH)?;
    let release = parse_native_release_manifest(manifest_raw, true)?;
    if release.qualification_only {
        return Err(Refusal::new(
            "native outer assets require a production release manifest",
        ));
    }

    let policy = parse_publisher_policy(policy_raw)?;
    let (producer_run_id, producer_run_attempt) = verify_declared_producer(&release, &policy)?;
    verify_release_assets(&release.assets, files)?;

    let inputs_raw = required_file(files, INPUTS_PATH)?;
    if sha256_bytes(inputs_raw) != policy.inputs_manifest_sha256.as_str() {
        return Err(Refusal::new(
            "outer input material manifest digest differs from publisher policy",
        ));
    }
    parse_inputs_manifest(inputs_raw)?;

    let authentication_raw = required_file(files, AUTHENTICATION_PATH)?;
    let manifest_sha256 = sha256_bytes(manifest_raw);
    let authentication = parse_authentication_metadata(
        authentication_raw,
        &manifest_sha256,
        &release.assets,
        &policy,
    )?;
    let producer_run_id = producer_run_id.to_string();
    let producer_run_attempt = producer_run_attempt.to_string();
    if authentication.declared_run.run_id.as_decimal() != producer_run_id.as_str()
        || authentication.declared_run.run_attempt.as_decimal() != producer_run_attempt.as_str()
    {
        return Err(Refusal::new(
            "authentication metadata run differs from the native release producer claim",
        ));
    }
    if files
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != authentication.expected_files
    {
        return Err(Refusal::new(
            "native outer input files differ from exact authentication metadata",
        ));
    }
    check_transport_bounds(files.len(), file_bytes_total(files)?)?;

    let sbom = required_file(files, SBOM_PATH)?.to_vec();
    let version = release.version;
    let archive_name = format!("ami-rust-{version}-release.tar.xz");
    let transport_name = format!("ami-rust-{version}-transport.json");

    let tar = encode_canonical_tar(files)?;
    let archive = compress_xz(&tar)?;
    if archive.is_empty() || archive.len() > MAX_NATIVE_TRANSPORT_ARCHIVE_BYTES {
        return Err(Refusal::new(
            "native outer XZ archive exceeds its 64 MiB container profile",
        ));
    }
    let transport = encode_transport_record(&archive_name, &archive, files)?;

    let mut assets = BTreeMap::new();
    assets.insert(archive_name.clone(), archive);
    assets.insert(format!("{archive_name}.spdx.json"), sbom);
    assets.insert(transport_name, transport);
    if assets.len() != 3 {
        return Err(Refusal::new(
            "native outer output does not contain exactly three prepared assets",
        ));
    }
    Ok(NativeOuterDraft { assets })
}

fn verify_declared_producer(
    release: &NativeReleaseManifest,
    policy: &ami_rust_core::publisher_policy::PublisherPolicy,
) -> Result<(u64, u64)> {
    let value = parse_json_value(
        release.producer.get().as_bytes(),
        JsonProfile::ReleaseManifestAndInstallReceipt,
    )?;
    let producer = value
        .as_object()
        .ok_or_else(|| Refusal::new("native release producer identity must be an object"))?;
    if string_field(producer, "repository")? != policy.repository
        || string_field(producer, "workflow")? != policy.workflow
        || string_field(producer, "source_sha")? != policy.source_sha
        || string_field(producer, "workflow_sha")? != policy.workflow_sha
    {
        return Err(Refusal::new(
            "native release producer source/workflow differs from publisher policy",
        ));
    }
    let run_id = number_field(producer, "run_id")?;
    let run_attempt = number_field(producer, "run_attempt")?;
    Ok((run_id, run_attempt))
}

fn verify_release_assets(assets: &[ReleaseFile], files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for asset in assets {
        let contents = required_file(files, &asset.path)?;
        if contents.len() as u64 != asset.bytes || sha256_bytes(contents) != asset.sha256.as_str() {
            return Err(Refusal::new(format!(
                "native release asset bytes differ from its manifest row: {}",
                asset.path
            )));
        }
    }
    let sbom = assets
        .iter()
        .find(|asset| asset.path == SBOM_PATH)
        .ok_or_else(|| Refusal::new("native release manifest omits sbom.spdx.json"))?;
    let sbom_bytes = required_file(files, SBOM_PATH)?;
    if sbom.bytes != sbom_bytes.len() as u64 || sbom.sha256.as_str() != sha256_bytes(sbom_bytes) {
        return Err(Refusal::new(
            "native release SBOM bytes differ from its manifest row",
        ));
    }
    Ok(())
}

fn check_transport_bounds(file_count: usize, total_bytes: u64) -> Result<()> {
    if file_count == 0 || file_count > MAX_NATIVE_TRANSPORT_FILES {
        return Err(Refusal::new(
            "native transport requires 1 to 512 input files",
        ));
    }
    if total_bytes > MAX_NATIVE_TRANSPORT_BYTES {
        return Err(Refusal::new(
            "native transport input files exceed the 64 MiB total",
        ));
    }
    Ok(())
}

fn file_bytes_total(files: &BTreeMap<String, Vec<u8>>) -> Result<u64> {
    files.values().try_fold(0_u64, |total, contents| {
        total
            .checked_add(contents.len() as u64)
            .ok_or_else(|| Refusal::new("native transport file total overflow"))
    })
}

fn encode_canonical_tar(files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut unpadded = TAR_END_BYTES;
    for contents in files.values() {
        let size = contents
            .len()
            .checked_add(TAR_BLOCK_BYTES - 1)
            .ok_or_else(|| Refusal::new("native outer TAR member size overflow"))?
            / TAR_BLOCK_BYTES
            * TAR_BLOCK_BYTES;
        unpadded = unpadded
            .checked_add(TAR_BLOCK_BYTES)
            .and_then(|total| total.checked_add(size))
            .ok_or_else(|| Refusal::new("native outer TAR size overflow"))?;
    }
    let tar_len = unpadded
        .checked_add(TAR_RECORD_BYTES - 1)
        .ok_or_else(|| Refusal::new("native outer TAR record padding overflow"))?
        / TAR_RECORD_BYTES
        * TAR_RECORD_BYTES;
    let mut tar = Vec::new();
    tar.try_reserve_exact(tar_len)
        .map_err(|_| Refusal::new("could not reserve bounded native outer TAR buffer"))?;

    for (path, contents) in files {
        let header = canonical_header(path, contents.len() as u64)?;
        tar.extend_from_slice(&header);
        tar.extend_from_slice(contents);
        let padding = (TAR_BLOCK_BYTES - contents.len() % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
        tar.resize(
            tar.len()
                .checked_add(padding)
                .ok_or_else(|| Refusal::new("native outer TAR padding overflow"))?,
            0,
        );
    }
    tar.resize(
        tar.len()
            .checked_add(TAR_END_BYTES)
            .ok_or_else(|| Refusal::new("native outer TAR trailer overflow"))?,
        0,
    );
    tar.resize(tar_len, 0);
    Ok(tar)
}

fn compress_xz(tar: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(XZ_PRESET))
        .map_err(|error| Refusal::new(format!("could not initialize outer XZ encoder: {error}")))?;
    encoder
        .write_all(tar)
        .map_err(|error| Refusal::new(format!("could not encode outer XZ archive: {error}")))?;
    encoder
        .finish()
        .map_err(|error| Refusal::new(format!("could not finish outer XZ archive: {error}")))
}

fn encode_transport_record(
    archive_name: &str,
    archive: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>> {
    let rows = files
        .iter()
        .map(|(path, contents)| {
            serde_json::json!({
                "path": path,
                "bytes": contents.len(),
                "sha256": sha256_bytes(contents),
            })
        })
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "archive": {
            "name": archive_name,
            "bytes": archive.len(),
            "sha256": sha256_bytes(archive),
        },
        "files": rows,
    });
    let mut raw = serde_json::to_vec_pretty(&value)
        .map_err(|error| Refusal::new(format!("could not serialize native transport: {error}")))?;
    raw.push(b'\n');
    let parsed = parse_native_transport_record(&raw)?;
    if parsed.archive.name != archive_name
        || parsed.archive.bytes != archive.len() as u64
        || parsed.archive.sha256 != sha256_bytes(archive)
    {
        return Err(Refusal::new(
            "generated transport record differs from native archive bytes",
        ));
    }
    Ok(raw)
}

fn required_file<'a>(files: &'a BTreeMap<String, Vec<u8>>, path: &str) -> Result<&'a [u8]> {
    files
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| Refusal::new(format!("native outer input is missing {path}")))
}

fn string_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("native producer field {name} must be a string")))
}

fn number_field(object: &Map<String, Value>, name: &str) -> Result<u64> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|number| *number > 0)
        .ok_or_else(|| Refusal::new(format!("native producer field {name} must be positive")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ami_rust_core::{digest::sha256_bytes, public_transport::parse_native_transport_record};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    const VERSION: &str = "0.2.0";
    const SOURCE: &str = "1111111111111111111111111111111111111111";

    struct Fixture {
        files: BTreeMap<String, Vec<u8>>,
        policy_raw: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let inputs_raw = line(&json!({
                "schema": "ami-rust-publisher-inputs-v1",
                "materials": [{
                    "uri": "https://example.invalid/input.tar",
                    "digest": {"sha256": "a".repeat(64)},
                }],
            }));
            let policy_raw = line(&json!({
                "schema": "ami-rust-publisher-trust-v2",
                "repository": "metaneutrons/ami-rust",
                "workflow": ".github/workflows/sdk-qualify.yml",
                "workflow_sha": SOURCE,
                "source_sha": SOURCE,
                "source_ref": "refs/heads/main",
                "oidc_issuer": "https://token.actions.githubusercontent.com",
                "cert_identity": "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
                "inputs_manifest_sha256": sha256_bytes(&inputs_raw),
                "allowed_host_profiles": ["linux-x86_64", "macos-aarch64"],
                "gh": {"path": "/usr/bin/gh", "sha256": "b".repeat(64)},
                "cosign": {"path": "/usr/bin/cosign", "sha256": "c".repeat(64)},
                "gh_trusted_roots": {"path": "/etc/gh-roots.jsonl", "sha256": "d".repeat(64)},
                "cosign_trusted_root": {"path": "/etc/cosign-root.json", "sha256": "e".repeat(64)},
            }));
            let policy = parse_publisher_policy(&policy_raw).expect("synthetic policy is valid");

            let mut assets = BTreeMap::from([
                (
                    "sdk.tar.xz".to_owned(),
                    b"native SDK archive fixture\n".to_vec(),
                ),
                ("SHAUTIL".to_owned(), b"checksum utility fixture\n".to_vec()),
                (SBOM_PATH.to_owned(), b"SPDX fixture\n".to_vec()),
                (
                    "bin/ami-rust-linux".to_owned(),
                    b"synthetic Linux frontend bytes\n".to_vec(),
                ),
                (
                    "bin/ami-rust-macos".to_owned(),
                    b"synthetic macOS frontend bytes\n".to_vec(),
                ),
            ]);
            let asset_rows = assets
                .iter()
                .map(|(path, contents)| {
                    json!({
                        "path": path,
                        "bytes": contents.len(),
                        "sha256": sha256_bytes(contents),
                    })
                })
                .collect::<Vec<_>>();
            let sdk_digest = "f".repeat(64);
            let producer = json!({
                "kind": "protected-github-actions",
                "repository": "metaneutrons/ami-rust",
                "workflow": ".github/workflows/sdk-qualify.yml",
                "source_sha": SOURCE,
                "workflow_sha": SOURCE,
                "run_id": 123,
                "run_attempt": 2,
                "acceptance": "R1 acceptance and publication are separate gates",
            });
            let mut host_launchers = serde_json::Map::new();
            for (host, path) in [
                ("linux-x86_64", "bin/ami-rust-linux"),
                ("macos-aarch64", "bin/ami-rust-macos"),
            ] {
                let contents = &assets[path];
                host_launchers.insert(
                    host.to_owned(),
                    json!({
                        "path": path,
                        "bytes": contents.len(),
                        "sha256": sha256_bytes(contents),
                    }),
                );
            }
            let manifest_raw = line(&json!({
                "schema": "ami-rust-release-v2",
                "version": VERSION,
                "qualification_only": false,
                "sdk_archive": "sdk.tar.xz",
                "sdk_manifest_sha256": sdk_digest,
                "assets": asset_rows,
                "sdk_files": [{
                    "path": "contract/sdk.json",
                    "bytes": 1,
                    "sha256": sdk_digest,
                }],
                "producer": producer,
                "host_launchers": Value::Object(host_launchers),
            }));

            let subjects = ["release.json", "sdk.tar.xz", "SHAUTIL"];
            let gh_attestations = subjects
                .iter()
                .map(|subject| {
                    let name = match *subject {
                        "release.json" => "release",
                        "sdk.tar.xz" => "sdk",
                        _ => "shautil",
                    };
                    json!({
                        "path": subject,
                        "host_profile": "linux-x86_64",
                        "bundle": format!(".auth/gh/{name}.json"),
                    })
                })
                .collect::<Vec<_>>();
            let cosign_bundles = subjects
                .iter()
                .map(|subject| {
                    let name = match *subject {
                        "release.json" => "release",
                        "sdk.tar.xz" => "sdk",
                        _ => "shautil",
                    };
                    json!({
                        "path": subject,
                        "bundle": format!(".auth/cosign/{name}.json"),
                    })
                })
                .collect::<Vec<_>>();
            let authentication_raw = line(&json!({
                "schema": "ami-rust-authentication-v2",
                "manifest_sha256": sha256_bytes(&manifest_raw),
                "workflow_runs": [{
                    "run_id": 123,
                    "run_attempt": 2,
                    "host_profile": "linux-x86_64",
                }],
                "gh_attestations": gh_attestations,
                "cosign_bundles": cosign_bundles,
            }));
            let mut files = BTreeMap::from([
                (RELEASE_MANIFEST_PATH.to_owned(), manifest_raw),
                (AUTHENTICATION_PATH.to_owned(), authentication_raw),
                (INPUTS_PATH.to_owned(), inputs_raw),
            ]);
            files.append(&mut assets);
            for name in ["release", "sdk", "shautil"] {
                files.insert(
                    format!(".auth/gh/{name}.json"),
                    format!("{{\"kind\":\"gh-{name}\"}}\n").into_bytes(),
                );
                files.insert(
                    format!(".auth/cosign/{name}.json"),
                    format!("{{\"kind\":\"cosign-{name}\"}}\n").into_bytes(),
                );
            }
            // Ensure the synthetic manifest is bound to the exact policy
            // identity supplied to the composer.
            assert_eq!(policy.source_sha, SOURCE);
            Self { files, policy_raw }
        }

        fn prepare(&self) -> Result<NativeOuterDraft> {
            prepare_native_outer(&self.files, &self.policy_raw)
        }
    }

    fn line(value: &Value) -> Vec<u8> {
        let mut raw = serde_json::to_vec(value).expect("fixture JSON serializes");
        raw.push(b'\n');
        raw
    }

    #[test]
    fn prepares_three_deterministic_assets_and_canonical_transport() {
        let fixture = Fixture::new();
        let first = fixture.prepare().expect("consistent outer draft");
        let second = fixture.prepare().expect("deterministic outer draft");
        assert_eq!(first, second);

        let archive_name = format!("ami-rust-{VERSION}-release.tar.xz");
        let transport_name = format!("ami-rust-{VERSION}-transport.json");
        assert_eq!(first.assets.len(), 3);
        assert_eq!(
            first.assets[&format!("{archive_name}.spdx.json")],
            fixture.files[SBOM_PATH]
        );
        let record = parse_native_transport_record(&first.assets[&transport_name]).unwrap();
        assert_eq!(record.archive.name, archive_name);
        assert_eq!(
            record.archive.sha256,
            sha256_bytes(&first.assets[&archive_name])
        );
        assert_eq!(record.files.len(), fixture.files.len());
        assert_eq!(
            record
                .files
                .iter()
                .map(|row| row.path.clone())
                .collect::<BTreeSet<_>>(),
            fixture.files.keys().cloned().collect::<BTreeSet<_>>(),
        );
    }

    #[test]
    fn refuses_changed_missing_and_unlisted_files_and_transport_bounds() {
        let fixture = Fixture::new();

        let mut changed = fixture.files.clone();
        changed.insert("SHAUTIL".to_owned(), b"changed utility\n".to_vec());
        assert!(prepare_native_outer(&changed, &fixture.policy_raw).is_err());

        let mut missing = fixture.files.clone();
        missing.remove(SBOM_PATH);
        assert!(prepare_native_outer(&missing, &fixture.policy_raw).is_err());

        let mut unlisted = fixture.files.clone();
        unlisted.insert("unexpected/extra.txt".to_owned(), b"extra\n".to_vec());
        assert!(prepare_native_outer(&unlisted, &fixture.policy_raw).is_err());

        assert!(check_transport_bounds(MAX_NATIVE_TRANSPORT_FILES + 1, 0).is_err());
        assert!(check_transport_bounds(1, MAX_NATIVE_TRANSPORT_BYTES + 1).is_err());
    }

    #[test]
    fn refuses_path_aliases_and_policy_input_digest_mismatches() {
        let fixture = Fixture::new();
        let mut invalid_path_manifest: Value =
            serde_json::from_slice(&fixture.files[RELEASE_MANIFEST_PATH]).unwrap();
        invalid_path_manifest["assets"][0]["path"] = json!("../outside");
        let changed_manifest = line(&invalid_path_manifest);
        let mut invalid_path = fixture.files.clone();
        invalid_path.insert(RELEASE_MANIFEST_PATH.to_owned(), changed_manifest);
        assert!(prepare_native_outer(&invalid_path, &fixture.policy_raw).is_err());

        let mut wrong_inputs = fixture.files.clone();
        wrong_inputs.insert(INPUTS_PATH.to_owned(), b"{}\n".to_vec());
        assert!(prepare_native_outer(&wrong_inputs, &fixture.policy_raw).is_err());
    }
}

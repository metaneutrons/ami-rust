//! Complete the byte-only stage after the protected signer has emitted every
//! declared signature.  Authentication and draft staging remain separate.

use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes},
    files::{open_regular_nofollow, read_regular_bounded},
    json::{JsonProfile, parse_json_value},
    toolchain_release::{UnsignedPayloadReadback, parse_toolchain_release},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const READBACK_SCHEMA: &str = "ami-rust-toolchain-inventory-readback-v1";
const READBACK_STATUS: &str = "UNSIGNED_PAYLOADS_MATCH_INVENTORY";
const READBACK_SCOPE: &str =
    "unsigned payload bytes only; no signatures/authentication/release acceptance";
const RESULT_SCHEMA: &str = "ami-rust-toolchain-final-candidate-bytes-v1";
const RESULT_STATUS: &str = "BYTES_ONLY_NOT_CRYPTO_VERIFIED";
const CHECKSUMS: &str = "SHA256SUMS";
const INVENTORY: &str = "toolchain-release.json";

#[derive(Deserialize)]
struct InventoryReadback {
    schema: String,
    status: String,
    inventory_sha256: String,
    readback: UnsignedPayloadReadback,
    expected_final_assets: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    device: u64,
    inode: u64,
    bytes: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Clone)]
struct FileIdentity {
    name: String,
    bytes: u64,
    sha256: String,
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut assembly_root = None;
    while let Some(option) = arguments.next() {
        if option != "--assembly-root" || assembly_root.is_some() {
            return Err(usage());
        }
        assembly_root = Some(PathBuf::from(arguments.next().ok_or_else(usage)?));
    }
    let assembly_root = canonical_directory(&PathBuf::from(assembly_root.ok_or_else(usage)?))?;
    let started = Instant::now();
    let result = finalize(&assembly_root, || deadline(started))?;
    println!(
        "{}",
        json!({"status": RESULT_STATUS, "mode": "finalize", "file_count": result["file_count"]})
    );
    Ok(())
}

fn usage() -> Refusal {
    Refusal::new("usage: ami-rust-xtask toolchain-publisher-finalize --assembly-root DIRECTORY")
}

fn deadline(started: Instant) -> Result<()> {
    if started.elapsed() >= Duration::from_secs(1200) {
        Err(Refusal::new(
            "publisher finalization exceeded the existing command deadline",
        ))
    } else {
        Ok(())
    }
}

fn finalize(root: &Path, check: impl Fn() -> Result<()>) -> Result<Value> {
    check()?;
    let candidate = canonical_child_directory(root, "candidate")?;
    let readback_path = regular_child(root, "unsigned-readback.json")?;
    let readback_raw = read_regular_bounded(
        &readback_path,
        JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes(),
    )?;
    let readback: InventoryReadback = serde_json::from_value(parse_json_value(
        &readback_raw,
        JsonProfile::ReleaseManifestAndInstallReceipt,
    )?)
    .map_err(|error| Refusal::new(format!("invalid unsigned inventory readback: {error}")))?;
    validate_readback_shape(&readback)?;

    let inventory_path = regular_child(&candidate, INVENTORY)?;
    let inventory_raw = read_regular_bounded(
        &inventory_path,
        JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes(),
    )?;
    if sha256_bytes(&inventory_raw) != readback.inventory_sha256 {
        return Err(Refusal::new(
            "toolchain-release.json does not match inventory_sha256",
        ));
    }
    let release = parse_toolchain_release(&inventory_raw)?;
    let expected: BTreeSet<_> = release.expected_assets().into_iter().collect();
    if expected.len() != release.expected_assets().len()
        || expected != readback.expected_final_assets.iter().cloned().collect()
    {
        return Err(Refusal::new(
            "unsigned inventory readback final assets differ from the release inventory",
        ));
    }
    let raw_expected: BTreeMap<_, _> = release
        .unsigned_payloads()
        .into_iter()
        .map(|artifact| {
            (
                artifact.name.clone(),
                (artifact.bytes, artifact.sha256.as_str().to_owned()),
            )
        })
        .collect();
    if raw_expected.len() != release.unsigned_payloads().len()
        || raw_expected.len() as u64 != readback.readback.file_count
        || raw_expected.len() + 1 >= expected.len()
    {
        return Err(Refusal::new(
            "unsigned inventory readback count is inconsistent",
        ));
    }
    let mut raw_total = 0_u64;
    let mut raw_observed = BTreeMap::new();
    for row in &readback.readback.files {
        if raw_observed
            .insert(row.name.clone(), (row.bytes, row.sha256.clone()))
            .is_some()
        {
            return Err(Refusal::new(
                "unsigned inventory readback contains duplicate files",
            ));
        }
        raw_total = raw_total
            .checked_add(row.bytes)
            .ok_or_else(|| Refusal::new("unsigned inventory byte total overflow"))?;
    }
    if raw_total != readback.readback.total_bytes || raw_observed != raw_expected {
        return Err(Refusal::new(
            "unsigned inventory readback differs from the release inventory",
        ));
    }

    let prechecksum: BTreeSet<_> = expected
        .iter()
        .filter(|name| name.as_str() != CHECKSUMS)
        .cloned()
        .collect();
    if directory_names(&candidate, &check)? != prechecksum {
        return Err(Refusal::new(format!(
            "signature output does not contain exactly the expected {} pre-checksum assets",
            prechecksum.len()
        )));
    }
    let before = scan_directory(&candidate, &check)?;
    let mut identities = BTreeMap::new();
    for name in &prechecksum {
        check()?;
        let identity = hash_candidate_file(&candidate, name, &before, &check)?;
        if let Some((bytes, digest)) = raw_expected.get(name)
            && (identity.bytes != *bytes || identity.sha256 != *digest)
        {
            return Err(Refusal::new(format!(
                "raw payload bytes do not match the release inventory: {name}"
            )));
        }
        identities.insert(name.clone(), identity);
    }
    let sums = checksum_bytes(&identities)?;
    write_new(&candidate.join(CHECKSUMS), &sums)?;
    let final_snapshots = scan_directory(&candidate, &check)?;
    if final_snapshots.len() != expected.len()
        || final_snapshots.keys().cloned().collect::<BTreeSet<_>>() != expected
    {
        return Err(Refusal::new(
            "candidate directory changed while adding SHA256SUMS",
        ));
    }
    let checksum = hash_candidate_file(&candidate, CHECKSUMS, &final_snapshots, &check)?;
    if checksum.bytes != sums.len() as u64 || checksum.sha256 != sha256_bytes(&sums) {
        return Err(Refusal::new("SHA256SUMS changed after it was written"));
    }
    identities.insert(CHECKSUMS.to_owned(), checksum);
    if identities.len() != expected.len() || checksum_bytes(&identities)? != sums {
        return Err(Refusal::new(
            "SHA256SUMS is not the canonical sorted checksum list for the other candidate assets",
        ));
    }
    if scan_directory(&candidate, &check)? != final_snapshots {
        return Err(Refusal::new(
            "candidate directory or file identities changed during readback",
        ));
    }

    let files: Vec<_> = identities
        .values()
        .map(|row| json!({"name": row.name, "bytes": row.bytes, "sha256": row.sha256}))
        .collect();
    let total_bytes = identities.values().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.bytes)
            .ok_or_else(|| Refusal::new("candidate total byte count overflow"))
    })?;
    let release_tag = if release.package_revision == 1 {
        format!("v{}", release.version)
    } else {
        format!(
            "v{}+packaging.{}",
            release.version, release.package_revision
        )
    };
    let result = json!({
        "schema": RESULT_SCHEMA,
        "status": RESULT_STATUS,
        "source": release.source,
        "version": release.version,
        "release_tag": release_tag,
        "inventory_sha256": readback.inventory_sha256,
        "file_count": files.len(),
        "total_bytes": total_bytes,
        "files": files,
        "claim": "Byte-level consistency only. The caller authenticates the Rust readback; this result does not verify SPDX content, licenses, signatures, attestations, registry/source authenticity, publication, or RC3 acceptance."
    });
    write_new(
        &root.join("all-subjects.sha256"),
        &all_subjects(&identities)?,
    )?;
    write_new(
        &root.join("final-byte-readback.json"),
        &canonical_json(&result)?,
    )?;
    Ok(result)
}

fn validate_readback_shape(readback: &InventoryReadback) -> Result<()> {
    if readback.schema != READBACK_SCHEMA
        || readback.status != READBACK_STATUS
        || readback.readback.scope != READBACK_SCOPE
        || !is_sha256_digest(&readback.inventory_sha256)
    {
        return Err(Refusal::new(
            "unsigned inventory readback has an unsupported schema",
        ));
    }
    if readback
        .expected_final_assets
        .iter()
        .any(|name| !safe_name(name))
        || readback
            .expected_final_assets
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != readback.expected_final_assets.len()
        || !readback
            .expected_final_assets
            .iter()
            .any(|name| name == INVENTORY)
        || !readback
            .expected_final_assets
            .iter()
            .any(|name| name == CHECKSUMS)
    {
        return Err(Refusal::new(
            "unsigned inventory readback asset names are invalid",
        ));
    }
    if readback
        .readback
        .files
        .iter()
        .any(|row| !safe_name(&row.name) || row.bytes == 0 || !is_sha256_digest(&row.sha256))
    {
        return Err(Refusal::new(
            "unsigned inventory readback file identity is invalid",
        ));
    }
    Ok(())
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.ends_with('.')
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("directory is missing or unreadable: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Refusal::new("directory must be a real directory"));
    }
    let canonical = fs::canonicalize(path)?;
    let after = fs::symlink_metadata(&canonical)?;
    if after.file_type().is_symlink() || !after.is_dir() {
        return Err(Refusal::new("directory must resolve to a real directory"));
    }
    Ok(canonical)
}

fn canonical_child_directory(parent: &Path, name: &str) -> Result<PathBuf> {
    canonical_directory(&parent.join(name))
}

fn regular_child(parent: &Path, name: &str) -> Result<PathBuf> {
    let path = parent.join(name);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| Refusal::new(format!("required file is missing: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Refusal::new("required input must be a regular file"));
    }
    Ok(path)
}

fn directory_names(root: &Path, check: &impl Fn() -> Result<()>) -> Result<BTreeSet<String>> {
    Ok(scan_directory(root, check)?.into_keys().collect())
}

fn scan_directory(
    root: &Path,
    check: &impl Fn() -> Result<()>,
) -> Result<BTreeMap<String, Snapshot>> {
    check()?;
    let root_before = snapshot(&fs::symlink_metadata(root)?);
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        check()?;
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Refusal::new("candidate directory has a non-UTF-8 filename"))?;
        if !safe_name(&name) {
            return Err(Refusal::new("candidate directory has an unsafe filename"));
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Refusal::new(format!(
                "candidate entry is not a regular file: {name}"
            )));
        }
        if files.insert(name, snapshot(&metadata)).is_some() {
            return Err(Refusal::new(
                "candidate directory contains duplicate filenames",
            ));
        }
    }
    if snapshot(&fs::symlink_metadata(root)?) != root_before {
        return Err(Refusal::new(
            "candidate directory changed during directory scan",
        ));
    }
    Ok(files)
}

fn snapshot(metadata: &fs::Metadata) -> Snapshot {
    Snapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn hash_candidate_file(
    root: &Path,
    name: &str,
    expected: &BTreeMap<String, Snapshot>,
    check: &impl Fn() -> Result<()>,
) -> Result<FileIdentity> {
    let snapshot_before = expected
        .get(name)
        .ok_or_else(|| Refusal::new("candidate asset is absent from the directory snapshot"))?;
    let path = root.join(name);
    if snapshot(&fs::symlink_metadata(&path)?) != *snapshot_before {
        return Err(Refusal::new(format!(
            "candidate asset changed before readback: {name}"
        )));
    }
    let mut file = open_regular_nofollow(&path)?;
    let opened = snapshot(&file.metadata()?);
    if opened != *snapshot_before {
        return Err(Refusal::new(format!(
            "candidate asset changed while opening: {name}"
        )));
    }
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check()?;
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                bytes = bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| Refusal::new("candidate asset byte count overflow"))?;
                digest.update(&buffer[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read candidate asset: {error}"
                )));
            }
        }
    }
    if bytes != opened.bytes
        || snapshot(&file.metadata()?) != opened
        || snapshot(&fs::symlink_metadata(&path)?) != *snapshot_before
    {
        return Err(Refusal::new(format!(
            "candidate asset changed during readback: {name}"
        )));
    }
    let sha256: [u8; 32] = digest.finalize().into();
    Ok(FileIdentity {
        name: name.to_owned(),
        bytes,
        sha256: hex_digest(&sha256),
    })
}

fn checksum_bytes(identities: &BTreeMap<String, FileIdentity>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for row in identities.values() {
        if row.name == CHECKSUMS {
            continue;
        }
        bytes.extend_from_slice(format!("{}  {}\n", row.sha256, row.name).as_bytes());
    }
    Ok(bytes)
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn all_subjects(identities: &BTreeMap<String, FileIdentity>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for row in identities.values() {
        bytes.extend_from_slice(format!("{}  {}\n", row.sha256, row.name).as_bytes());
    }
    Ok(bytes)
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| Refusal::new(format!("could not serialize final readback: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

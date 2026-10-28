//! Streaming readback of the raw, unsigned payload files declared by an RC3
//! toolchain inventory. This verifies bytes only; it does not authenticate or
//! accept a release.

use super::{Artifact, ToolchainRelease};
use crate::{Refusal, Result, digest::encode_hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
};

const READBACK_SCOPE: &str =
    "unsigned payload bytes only; no signatures/authentication/release acceptance";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPayloadReadback {
    pub scope: String,
    pub file_count: u64,
    pub total_bytes: u64,
    pub files: Vec<UnsignedPayloadFileReadback>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPayloadFileReadback {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Verify the exact flat set of raw payloads declared by a release inventory.
/// Files are opened without following links and hashed through those same file
/// descriptors, with a per-file read ceiling of the declared size plus one.
/// The directory rescan is not an atomic snapshot and does not protect against
/// mutation by the same UID or root. The caller supplies cancellation/deadline
/// enforcement, checked before each file and each 64 KiB read; declared lengths
/// do not establish a trusted CPU/time budget.
pub fn verify_unsigned_payloads(
    root: &Path,
    release: &ToolchainRelease,
    mut cancellation_check: impl FnMut() -> Result<()>,
) -> Result<UnsignedPayloadReadback> {
    cancellation_check()?;
    release.validate()?;
    let artifacts = release.unsigned_payloads();
    let expected_names: BTreeSet<String> = artifacts
        .iter()
        .map(|artifact| artifact.name.clone())
        .collect();
    if expected_names.len() != artifacts.len() {
        return Err(Refusal::new(
            "toolchain release unsigned payload names are not unique",
        ));
    }

    let names_before = flat_names(root, expected_names.len())?;
    if names_before != expected_names {
        return Err(Refusal::new(
            "unsigned payload directory does not contain exactly the declared files",
        ));
    }

    let mut total_bytes = 0_u64;
    let mut files = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        cancellation_check()?;
        let path = root.join(&artifact.name);
        let (bytes, sha256) = hash_declared_file(&path, artifact, &mut cancellation_check)?;
        if bytes != artifact.bytes || sha256 != artifact.sha256.as_str() {
            return Err(Refusal::new(format!(
                "unsigned payload bytes do not match the release inventory: {}",
                artifact.name
            )));
        }
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or_else(|| Refusal::new("unsigned payload byte total overflow"))?;
        files.push(UnsignedPayloadFileReadback {
            name: artifact.name.clone(),
            bytes,
            sha256,
        });
    }

    cancellation_check()?;
    let names_after = flat_names(root, expected_names.len())?;
    if names_after != names_before {
        return Err(Refusal::new(
            "unsigned payload directory entries changed during readback",
        ));
    }

    files.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(UnsignedPayloadReadback {
        scope: READBACK_SCOPE.to_owned(),
        file_count: u64::try_from(files.len())
            .map_err(|_| Refusal::new("unsigned payload count cannot be represented"))?,
        total_bytes,
        files,
    })
}

fn flat_names(root: &Path, expected_count: usize) -> Result<BTreeSet<String>> {
    let entries = fs::read_dir(root).map_err(|error| {
        Refusal::new(format!(
            "could not read unsigned payload directory: {error}"
        ))
    })?;
    let mut names = BTreeSet::new();
    for entry in entries {
        if names.len() >= expected_count {
            return Err(Refusal::new("unsigned payload directory has extra entries"));
        }
        let entry = entry.map_err(|error| {
            Refusal::new(format!(
                "could not inspect unsigned payload directory: {error}"
            ))
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Refusal::new("unsigned payload directory has a non-UTF-8 entry name"))?;
        names.insert(name);
    }
    Ok(names)
}

fn hash_declared_file(
    path: &Path,
    artifact: &Artifact,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<(u64, String)> {
    let read_limit = artifact
        .bytes
        .checked_add(1)
        .ok_or_else(|| Refusal::new("unsigned payload byte limit cannot be incremented"))?;
    let mut file = crate::files::open_regular_nofollow(path)?;
    let before = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect opened payload: {error}")))?;
    if !before.file_type().is_file() {
        return Err(Refusal::new("unsigned payload is not a regular file"));
    }
    if before.len() != artifact.bytes {
        return Err(Refusal::new(
            "unsigned payload size does not match the release inventory",
        ));
    }
    let before = FileSnapshot::from_metadata(&before);

    let mut total = 0_u64;
    let mut over_limit = false;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        cancellation_check()?;
        let remaining = read_limit
            .checked_sub(total)
            .ok_or_else(|| Refusal::new("unsigned payload read limit accounting failed"))?;
        if remaining == 0 {
            over_limit = true;
            break;
        }
        let read_size = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| Refusal::new("unsigned payload read size cannot be represented"))?;
        match file.read(&mut buffer[..read_size]) {
            Ok(0) => break,
            Ok(read) => {
                let read_u64 = u64::try_from(read)
                    .map_err(|_| Refusal::new("unsigned payload read size overflow"))?;
                total = total
                    .checked_add(read_u64)
                    .ok_or_else(|| Refusal::new("unsigned payload byte count overflow"))?;
                digest.update(&buffer[..read]);
                if total > artifact.bytes {
                    over_limit = true;
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read opened unsigned payload: {error}"
                )));
            }
        }
    }

    let after = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not reinspect opened payload: {error}")))?;
    if !after.file_type().is_file() || FileSnapshot::from_metadata(&after) != before {
        return Err(Refusal::new(
            "unsigned payload metadata changed while it was being read",
        ));
    }
    if over_limit || total > artifact.bytes {
        return Err(Refusal::new(
            "unsigned payload exceeds its declared byte limit",
        ));
    }
    if total != artifact.bytes {
        return Err(Refusal::new(
            "unsigned payload size does not match the release inventory",
        ));
    }

    let digest: [u8; 32] = digest.finalize().into();
    Ok((total, encode_hex(&digest)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileSnapshot {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{READBACK_SCOPE, verify_unsigned_payloads};
    use crate::toolchain_release::{ReleaseHost, ToolchainRelease, parse_toolchain_release};
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        fs, io,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    ".ami-rust-unsigned-payload-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        let canonical = fs::canonicalize(&path).expect("canonical fixture path");
                        assert_eq!(canonical, path, "fixture path must be canonical");
                        return Self(path);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create unsigned payload fixture: {error}"),
                }
            }
            panic!("could not allocate a unique unsigned payload fixture");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove unsigned payload fixture");
        }
    }

    struct Fixture {
        root: TempDir,
        release: ToolchainRelease,
        payloads: BTreeMap<String, Vec<u8>>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TempDir::new();
            let mut payloads = BTreeMap::new();
            let hosts: Vec<_> = ReleaseHost::ALL
                .into_iter()
                .map(|host| {
                    let base = format!("ami-rust-toolchain-0.2.0-{}", host.key());
                    json!({
                        "host": host,
                        "rustup": {
                            "rustc": artifact(format!("ami-rust-rustc-0.2.0-{}.tar.xz", host.key()), &mut payloads),
                            "cargo": artifact(format!("ami-rust-cargo-0.2.0-{}.tar.xz", host.key()), &mut payloads),
                            "rust_std": artifact(format!("ami-rust-rust-std-0.2.0-{}.tar.xz", host.key()), &mut payloads),
                        },
                        "archive": artifact(format!("{base}.tar.xz"), &mut payloads),
                        "inventory": artifact(format!("{base}.manifest.json"), &mut payloads),
                        "debian": host.debian_architecture().map(|arch| {
                            artifact(format!("ami-rust_0.2.0-1_{arch}.deb"), &mut payloads)
                        }),
                    })
                })
                .collect();
            let crates: Vec<_> = super::super::CRATES
                .into_iter()
                .map(|name| {
                    json!({
                        "name": name,
                        "version": "0.2.0",
                        "archive": artifact(format!("{name}-0.2.0.crate"), &mut payloads),
                        "dependencies": match name {
                            "aros-native-build" => vec!["aros-elf"],
                            "aros" => vec!["aros-sys"],
                            "aros-mui-sys" => vec!["aros-sys"],
                            "aros-mui" => vec!["aros", "aros-sys", "aros-mui-sys"],
                            _ => Vec::<&str>::new(),
                        },
                    })
                })
                .collect();
            let mut value = json!({
                "schema": "ami-rust-toolchain-release-v2",
                "version": "0.2.0",
                "package_revision": 1,
                "target": "x86_64-aros",
                "source": {"commit": "1".repeat(40), "tree": "2".repeat(40), "epoch": 1792870000_u64},
                "hosts": hosts,
                "rustup_distribution": {
                    "channel": "0.2.0", "catalog_commit": "3".repeat(40),
                    "rust_version": "1.100.0-nightly (330d31712 2026-09-17)",
                    "cargo_version": "1.99.0 (3efb1f477 2026-07-17)", "release_tag": "v0.2.0",
                    "manifest": artifact("channel-rust-0.2.0.toml".to_owned(), &mut payloads),
                    "checksum": artifact("channel-rust-0.2.0.toml.sha256".to_owned(), &mut payloads),
                },
                "crates": crates,
                "sources": artifact("ami-rust-0.2.0-sources.tar.xz".to_owned(), &mut payloads),
                "vendor": artifact("ami-rust-0.2.0-vendor.tar.xz".to_owned(), &mut payloads),
                "homebrew_formula": artifact("ami-rust.rb".to_owned(), &mut payloads),
            });
            let release: ToolchainRelease = serde_json::from_value(value.clone()).unwrap();
            let rendered = release.rustup_manifest_files().unwrap();
            for (key, name, contents) in [
                ("manifest", rendered.manifest_name, rendered.manifest),
                ("checksum", rendered.checksum_name, rendered.checksum),
            ] {
                value["rustup_distribution"][key] = json!({"name":name,"bytes":contents.len(),"sha256":crate::digest::sha256_bytes(contents.as_bytes())});
                payloads.insert(name, contents.into_bytes());
            }
            assert_eq!(payloads.len(), 28);
            for (name, bytes) in &payloads {
                fs::write(root.path().join(name), bytes).expect("write payload fixture");
            }
            let release = parse_toolchain_release(&serde_json::to_vec(&value).unwrap())
                .expect("parse valid release fixture");
            Self {
                root,
                release,
                payloads,
            }
        }
    }

    fn artifact(name: String, payloads: &mut BTreeMap<String, Vec<u8>>) -> Value {
        let contents = format!("unsigned fixture payload: {name}").into_bytes();
        let bytes = u64::try_from(contents.len()).expect("fixture payload length");
        let sha256 = crate::digest::sha256_bytes(&contents);
        payloads.insert(name.clone(), contents);
        json!({"name": name, "bytes": bytes, "sha256": sha256})
    }

    #[test]
    fn verifies_exact_unsigned_raw_payload_set_and_actual_digests() {
        let fixture = Fixture::new();
        let readback =
            verify_unsigned_payloads(fixture.root.path(), &fixture.release, || Ok(())).unwrap();
        let expected_total = fixture
            .payloads
            .values()
            .map(|bytes| u64::try_from(bytes.len()).unwrap())
            .sum::<u64>();
        assert_eq!(readback.scope, READBACK_SCOPE);
        assert_eq!(readback.file_count, 28);
        assert_eq!(readback.total_bytes, expected_total);
        assert_eq!(readback.files.len(), 28);
        for row in &readback.files {
            let bytes = &fixture.payloads[&row.name];
            assert_eq!(row.bytes, u64::try_from(bytes.len()).unwrap());
            assert_eq!(row.sha256, crate::digest::sha256_bytes(bytes));
        }
        assert_eq!(
            serde_json::to_value(&readback).unwrap()["files"][0]["name"],
            readback.files[0].name
        );
    }

    #[test]
    fn refuses_a_one_byte_payload_corruption() {
        let fixture = Fixture::new();
        let name = "ami-rust.rb";
        let path = fixture.root.path().join(name);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(
            verify_unsigned_payloads(fixture.root.path(), &fixture.release, || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("unsigned payload bytes do not match")
        );
    }

    #[test]
    fn refuses_a_missing_payload() {
        let fixture = Fixture::new();
        let name = "ami-rust.rb";
        fs::remove_file(fixture.root.path().join(name)).unwrap();
        assert!(
            verify_unsigned_payloads(fixture.root.path(), &fixture.release, || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("does not contain exactly the declared files")
        );
    }

    #[test]
    fn refuses_an_extra_directory_entry() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.path().join("extra-directory")).unwrap();
        assert!(
            verify_unsigned_payloads(fixture.root.path(), &fixture.release, || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("extra entries")
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_in_place_of_a_payload() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let linked_name = "ami-rust.rb";
        let target_name = "ami-rust-0.2.0-sources.tar.xz";
        let linked_path = fixture.root.path().join(linked_name);
        let target_path = fixture.root.path().join(target_name);
        fs::remove_file(&linked_path).unwrap();
        symlink(target_path, linked_path).unwrap();
        assert!(
            verify_unsigned_payloads(fixture.root.path(), &fixture.release, || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("without following links")
        );
    }
    #[test]
    fn stops_when_the_caller_cancels_during_streaming() {
        let fixture = Fixture::new();
        let mut polls = 0;
        let error = verify_unsigned_payloads(fixture.root.path(), &fixture.release, || {
            polls += 1;
            if polls == 4 {
                Err(crate::Refusal::new("fixture readback deadline reached"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(polls, 4);
        assert!(
            error
                .to_string()
                .contains("fixture readback deadline reached")
        );
    }
}

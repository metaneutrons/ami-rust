//! Synthetic package consistency tests. The frontend files are header-only
//! fixtures, not complete runnable images; no fixture bytes are executed.
use super::*;
use crate::{digest::sha256_bytes, records::Host};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, OpenOptions, Permissions},
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const CLI_VERSION: &str = "0.2.0-dev";
const SDK_VERSION: &str = "0.2.0";
const PACKAGE_VERSION: &str = "0.2.0-1";
const ASSET_NAMES: [&str; 6] = [
    "SHA256SUMS",
    "ami-rust-0.2.0-release.tar.xz",
    "ami-rust-0.2.0-release.tar.xz.sigstore.json",
    "ami-rust-0.2.0-release.tar.xz.spdx.json",
    "ami-rust-0.2.0-transport.json",
    "ami-rust-0.2.0-transport.json.sigstore.json",
];
const PROOF_SUBJECTS: [&str; 4] = [
    "SHA256SUMS",
    "ami-rust-0.2.0-release.tar.xz",
    "ami-rust-0.2.0-release.tar.xz.spdx.json",
    "ami-rust-0.2.0-transport.json",
];
const PROOF_PATH: &str = "fixture.json";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct FixtureDir {
    parent: PathBuf,
    root: PathBuf,
}

impl FixtureDir {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
        for _ in 0..100 {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let parent = base.join(format!(
                "ami-rust package fixture {} {sequence}",
                std::process::id()
            ));
            match fs::create_dir(&parent) {
                Ok(()) => {
                    fs::set_permissions(&parent, Permissions::from_mode(0o700))
                        .expect("make fixture parent private");
                    let root = parent.join("native package root with spaces");
                    fs::create_dir(&root).expect("create package root");
                    fs::set_permissions(&root, Permissions::from_mode(0o700))
                        .expect("make package root private");
                    return Self { parent, root };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create package fixture directory: {error}"),
            }
        }
        panic!("could not allocate a unique package fixture directory");
    }

    fn relocate(&mut self) {
        let moved = self.parent.join("relocated package root with spaces");
        fs::rename(&self.root, &moved).expect("relocate package root");
        self.root = moved;
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.parent).expect("remove package fixture directory");
    }
}

#[derive(Clone)]
struct FixtureFile {
    bytes: Vec<u8>,
    mode: u32,
}

struct NativePackageFixture {
    dir: FixtureDir,
    host: Host,
    files: BTreeMap<String, FixtureFile>,
    pins: Value,
    proofs: Value,
    sdk_run_id: String,
    sdk_run_attempt: String,
}

impl NativePackageFixture {
    fn new(host: Host) -> Self {
        let header = native_header(host);
        let mut files = BTreeMap::new();
        for name in ["ami-rust", "cargo-ami"] {
            files.insert(
                format!("bin/{name}"),
                FixtureFile {
                    bytes: header.clone(),
                    mode: 0o755,
                },
            );
        }
        for (path, bytes) in [
            ("LICENSE-MIT", b"MIT fixture license text\n".as_slice()),
            (
                "LICENSE-APACHE",
                b"Apache fixture license text\n".as_slice(),
            ),
            (
                "THIRD-PARTY-NOTICES.md",
                b"Third-party fixture notice\n".as_slice(),
            ),
            (
                "licenses/fixture.txt",
                b"Fixture third-party text\n".as_slice(),
            ),
            ("assets/SHA256SUMS", b"checksum fixture\n".as_slice()),
            (
                "assets/ami-rust-0.2.0-release.tar.xz",
                b"archive fixture\n".as_slice(),
            ),
            (
                "assets/ami-rust-0.2.0-release.tar.xz.sigstore.json",
                b"archive signature fixture\n".as_slice(),
            ),
            (
                "assets/ami-rust-0.2.0-release.tar.xz.spdx.json",
                b"archive SPDX fixture\n".as_slice(),
            ),
            (
                "assets/ami-rust-0.2.0-transport.json",
                b"transport fixture\n".as_slice(),
            ),
            (
                "assets/ami-rust-0.2.0-transport.json.sigstore.json",
                b"transport signature fixture\n".as_slice(),
            ),
            ("proofs/fixture.json", b"{}".as_slice()),
        ] {
            files.insert(
                path.to_owned(),
                FixtureFile {
                    bytes: bytes.to_vec(),
                    mode: 0o644,
                },
            );
        }

        let pins = json!({
            "schema": "ami-rust-package-inputs-v2",
            "cli_version": CLI_VERSION,
            "sdk_version": SDK_VERSION,
            "packaging_revision": 1,
            "package_version": PACKAGE_VERSION,
            "packaging_tag": "v0.2.0+packaging.1",
            "sdk_tag": "v0.2.0",
            "repository": "metaneutrons/ami-rust",
            "source_commit": "1111111111111111111111111111111111111111",
            "source_tree": "2222222222222222222222222222222222222222",
            "sdk_run_id": 1,
            "sdk_run_attempt": 1,
            "manifest_sha256": "a".repeat(64),
            "transport_sha256": "b".repeat(64),
            "assets": [],
            "hosts": {
                "apt": "linux-x86_64",
                "homebrew": "macos-aarch64"
            },
            "maintainer": "synthetic package fixture",
            "publisher_proofs": {},
            "host": host_name(host),
            "launchers": {},
            "core_sha256": "0".repeat(64)
        });
        let mut fixture = Self {
            dir: FixtureDir::new(),
            host,
            files,
            pins,
            proofs: Value::Null,
            sdk_run_id: "1".to_owned(),
            sdk_run_attempt: "1".to_owned(),
        };
        fixture.reindex_payloads();
        fixture.write_records_and_inventory();
        fixture
    }

    fn runtime(&self) -> PackageRuntime<'_> {
        PackageRuntime {
            host: self.host,
            cli_version: CLI_VERSION,
        }
    }

    fn root(&self) -> &Path {
        &self.dir.root
    }

    fn reindex_payloads(&mut self) {
        let mut asset_rows = Vec::new();
        for name in ASSET_NAMES {
            let path = format!("assets/{name}");
            let file = self.files.get(&path).expect("fixture asset exists");
            asset_rows.push(json!({
                "path": name,
                "bytes": file.bytes.len(),
                "sha256": sha256_bytes(&file.bytes)
            }));
        }
        self.pins["assets"] = json!(asset_rows);
        let transport = self
            .files
            .get("assets/ami-rust-0.2.0-transport.json")
            .expect("fixture transport exists");
        self.pins["transport_sha256"] = json!(sha256_bytes(&transport.bytes));

        let mut launcher_rows = Map::new();
        let mut launcher_digest = None;
        for name in ["ami-rust", "cargo-ami"] {
            let path = format!("bin/{name}");
            let file = self.files.get(&path).expect("fixture launcher exists");
            let digest = sha256_bytes(&file.bytes);
            launcher_digest.get_or_insert_with(|| digest.clone());
            launcher_rows.insert(
                name.to_owned(),
                json!({
                    "path": path,
                    "bytes": file.bytes.len(),
                    "sha256": digest
                }),
            );
        }
        self.pins["launchers"] = Value::Object(launcher_rows);
        self.pins["core_sha256"] = json!(launcher_digest.expect("launcher digest"));

        let proof = self
            .files
            .get("proofs/fixture.json")
            .expect("fixture proof exists");
        let proof_identity = json!({
            "path": PROOF_PATH,
            "bytes": proof.bytes.len(),
            "sha256": sha256_bytes(&proof.bytes)
        });
        let pinned_identity = json!({
            "bytes": proof.bytes.len(),
            "sha256": sha256_bytes(&proof.bytes)
        });
        let mut proof_subjects = Map::new();
        let mut pinned_subjects = Map::new();
        for subject in PROOF_SUBJECTS {
            proof_subjects.insert(subject.to_owned(), json!([proof_identity.clone()]));
            pinned_subjects.insert(subject.to_owned(), json!([pinned_identity.clone()]));
        }
        self.pins["publisher_proofs"] = Value::Object(pinned_subjects);
        self.proofs = json!({
            "schema": "ami-rust-package-proofs-v2",
            "subjects": proof_subjects
        });
    }

    fn pins_bytes(&self) -> Vec<u8> {
        let mut raw = json_bytes(&self.pins);
        replace_counter(&mut raw, "sdk_run_id", &self.sdk_run_id);
        replace_counter(&mut raw, "sdk_run_attempt", &self.sdk_run_attempt);
        raw
    }

    fn write_records_and_inventory(&mut self) {
        let pins = self.pins_bytes();
        let proofs = json_bytes(&self.proofs);
        let mut all_files = self.files.clone();
        all_files.insert(
            "pins.json".to_owned(),
            FixtureFile {
                bytes: pins,
                mode: 0o644,
            },
        );
        all_files.insert(
            "proofs.json".to_owned(),
            FixtureFile {
                bytes: proofs,
                mode: 0o644,
            },
        );
        let inventory_files = all_files
            .iter()
            .map(|(path, file)| {
                json!({
                    "path": path,
                    "bytes": file.bytes.len(),
                    "sha256": sha256_bytes(&file.bytes),
                    "mode": file.mode
                })
            })
            .collect::<Vec<_>>();
        let inventory = json!({
            "schema": "ami-rust-package-inventory-v2",
            "cli_version": self.pins["cli_version"],
            "sdk_version": self.pins["sdk_version"],
            "package_version": self.pins["package_version"],
            "host": self.pins["host"],
            "files": inventory_files
        });
        all_files.insert(
            "inventory.json".to_owned(),
            FixtureFile {
                bytes: json_bytes(&inventory),
                mode: 0o644,
            },
        );

        let _ = fs::remove_dir_all(&self.dir.root);
        fs::create_dir(&self.dir.root).expect("recreate package root");
        fs::set_permissions(&self.dir.root, Permissions::from_mode(0o700))
            .expect("make package root private");
        write_tree(&self.dir.root, &all_files);
    }

    fn refresh(&mut self) {
        self.reindex_payloads();
        self.write_records_and_inventory();
    }

    fn relocate(&mut self) {
        self.dir.relocate();
    }

    fn replace_launchers(&mut self, bytes: Vec<u8>) {
        for name in ["ami-rust", "cargo-ami"] {
            self.files.insert(
                format!("bin/{name}"),
                FixtureFile {
                    bytes: bytes.clone(),
                    mode: 0o755,
                },
            );
        }
        self.reindex_payloads();
        self.write_records_and_inventory();
    }
}

fn json_bytes(value: &Value) -> Vec<u8> {
    let mut raw = serde_json::to_vec(value).expect("serialize fixture JSON");
    raw.push(b'\n');
    raw
}

fn replace_counter(raw: &mut Vec<u8>, field: &str, decimal: &str) {
    let needle = format!("\"{field}\":1").into_bytes();
    let replacement = format!("\"{field}\":{decimal}");
    let matches = raw
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == needle).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "counter field should occur exactly once");
    let start = matches[0];
    raw.splice(start..start + needle.len(), replacement.bytes());
}

fn write_tree(root: &Path, files: &BTreeMap<String, FixtureFile>) {
    for (relative, fixture) in files {
        let path = root.join(relative);
        let relative_parent = Path::new(relative).parent().expect("relative parent");
        let mut directory = root.to_path_buf();
        for component in relative_parent.components() {
            directory.push(component.as_os_str());
            if !directory.exists() {
                fs::create_dir(&directory).expect("create package subdirectory");
            }
            fs::set_permissions(&directory, Permissions::from_mode(0o755))
                .expect("set package subdirectory mode");
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create package fixture file");
        file.write_all(&fixture.bytes)
            .expect("write package fixture file");
        drop(file);
        fs::set_permissions(&path, Permissions::from_mode(fixture.mode))
            .expect("set package fixture file mode");
    }
}

fn write_extra_file(path: &Path, bytes: &[u8], mode: u32) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create extra fixture parent");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create extra fixture file");
    file.write_all(bytes).expect("write extra fixture file");
    drop(file);
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("set extra fixture mode");
}

fn replace_file(path: &Path, bytes: &[u8], mode: u32) {
    let current_mode = fs::metadata(path).expect("inspect fixture file").mode() & 0o7777;
    fs::set_permissions(path, Permissions::from_mode(current_mode | 0o200))
        .expect("temporarily make fixture file writable");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open fixture file for replacement");
    file.write_all(bytes).expect("replace fixture bytes");
    drop(file);
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("restore fixture mode");
}

fn native_header(host: Host) -> Vec<u8> {
    match host {
        Host::LinuxX86_64 => linux_pie_header(0x400000, 1),
        Host::MacosAarch64 => mach_o_header(),
    }
}

fn linux_pie_header(entry: u64, program_header_count: u16) -> Vec<u8> {
    let length = if program_header_count == 0 { 64 } else { 120 };
    let mut bytes = vec![0_u8; length];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    bytes[7] = 0; // System V ABI.
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN / PIE.
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // x86-64.
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff.
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize.
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize.
    bytes[56..58].copy_from_slice(&program_header_count.to_le_bytes());
    if program_header_count > 0 {
        // One synthetic executable PT_LOAD covers e_entry. This is only a
        // structurally valid header fixture; the bytes are never executed.
        let header = &mut bytes[64..120];
        header[0..4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD.
        header[4..8].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X.
        header[8..16].copy_from_slice(&0_u64.to_le_bytes()); // p_offset.
        header[16..24].copy_from_slice(&0x400000_u64.to_le_bytes()); // p_vaddr.
        header[24..32].copy_from_slice(&0x400000_u64.to_le_bytes()); // p_paddr.
        header[32..40].copy_from_slice(&(length as u64).to_le_bytes()); // p_filesz.
        header[40..48].copy_from_slice(&(length as u64).to_le_bytes()); // p_memsz.
        header[48..56].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_align.
    }
    bytes
}

fn mach_o_header() -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];
    bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]); // MH_MAGIC_64, little endian.
    bytes[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes()); // ARM64.
    bytes[12..16].copy_from_slice(&2_u32.to_le_bytes()); // MH_EXECUTE.
    bytes
}

fn host_name(host: Host) -> &'static str {
    match host {
        Host::LinuxX86_64 => "linux-x86_64",
        Host::MacosAarch64 => "macos-aarch64",
    }
}

fn other_host(host: Host) -> Host {
    match host {
        Host::LinuxX86_64 => Host::MacosAarch64,
        Host::MacosAarch64 => Host::LinuxX86_64,
    }
}

fn check(fixture: &NativePackageFixture) -> Result<CheckedNativePackage> {
    check_native_package_root(fixture.root(), fixture.runtime())
}

#[test]
fn accepts_explicit_linux_and_macos_package_headers_without_executing_them() {
    for host in [Host::LinuxX86_64, Host::MacosAarch64] {
        let fixture = NativePackageFixture::new(host);
        let package = check(&fixture).expect("consistent native package fixture");
        assert_eq!(package.pins().cli_version, CLI_VERSION);
        assert_eq!(package.pins().sdk_version, SDK_VERSION);
        assert_eq!(package.pins().package_version, PACKAGE_VERSION);
        assert_eq!(package.pins().host, host);
        assert_eq!(package.pins().sdk_run_id.as_decimal(), "1");
        assert_eq!(package.pins().sdk_run_attempt.as_decimal(), "1");
        assert_eq!(package.inventory().files.len(), 15);
        let ami = package.read_file("bin/ami-rust").unwrap();
        let cargo = package.read_file("bin/cargo-ami").unwrap();
        assert_eq!(ami, cargo);
        assert_eq!(ami, native_header(host));
        assert_eq!(package.read_file("proofs/fixture.json").unwrap(), b"{}");
        assert_eq!(package.path(), fixture.root());
    }
}

#[test]
fn package_input_schema_and_workflow_counters_follow_v2_contract() {
    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    let raw = fs::read(fixture.root().join("pins.json")).unwrap();
    let pins = parse_native_package_pins(&raw).unwrap();
    assert_eq!(pins.cli_version, "0.2.0-dev");
    assert_eq!(pins.sdk_version, "0.2.0");
    assert_eq!(pins.package_version, "0.2.0-1");
    assert_eq!(pins.sdk_run_id.as_decimal(), "1");
    assert_eq!(pins.sdk_run_attempt.as_decimal(), "1");

    let mut large = raw.clone();
    let exact_counter = "9".repeat(4300);
    replace_counter(&mut large, "sdk_run_id", &exact_counter);
    let parsed = parse_native_package_pins(&large).expect("4300 digit exact positive counter");
    assert_eq!(parsed.sdk_run_id.as_decimal(), exact_counter);

    let mut too_large = raw.clone();
    replace_counter(&mut too_large, "sdk_run_id", &"9".repeat(4301));
    assert!(parse_native_package_pins(&too_large).is_err());
    let mut zero = raw.clone();
    replace_counter(&mut zero, "sdk_run_id", "0");
    assert!(parse_native_package_pins(&zero).is_err());
    let mut exponent = raw.clone();
    replace_counter(&mut exponent, "sdk_run_id", "1e0");
    assert!(parse_native_package_pins(&exponent).is_err());
    let mut wrong_schema = raw;
    let from = b"ami-rust-package-inputs-v2";
    let to = b"ami-rust-package-inputs-v1";
    let start = wrong_schema
        .windows(from.len())
        .position(|window| window == from)
        .unwrap();
    wrong_schema[start..start + from.len()].copy_from_slice(to);
    assert!(parse_native_package_pins(&wrong_schema).is_err());
}

#[test]
fn actual_executable_and_public_aliases_find_relocated_root_with_spaces() {
    let mut fixture = NativePackageFixture::new(Host::MacosAarch64);
    fixture.relocate();
    let alias_dir = fixture.dir.parent.join("public aliases with spaces");
    fs::create_dir(&alias_dir).expect("create public alias directory");
    fs::set_permissions(&alias_dir, Permissions::from_mode(0o700)).unwrap();
    let ami_alias = alias_dir.join("ami");
    let cargo_alias = alias_dir.join("cargo-ami");
    symlink(fixture.root().join("bin/ami-rust"), &ami_alias).unwrap();
    symlink(fixture.root().join("bin/cargo-ami"), &cargo_alias).unwrap();

    for executable in [
        fixture.root().join("bin/ami-rust"),
        fixture.root().join("bin/cargo-ami"),
        ami_alias,
        cargo_alias,
    ] {
        let package = package_from_executable(&executable, fixture.runtime())
            .expect("actual executable path resolves to owned package root");
        assert_eq!(package.path(), fixture.root());
    }
}

#[test]
fn refuses_runtime_host_cli_and_inventory_version_mismatches() {
    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    let wrong_host = PackageRuntime {
        host: Host::LinuxX86_64,
        cli_version: CLI_VERSION,
    };
    assert!(check_native_package_root(fixture.root(), wrong_host).is_err());
    let wrong_cli = PackageRuntime {
        host: fixture.host,
        cli_version: "0.2.1-dev",
    };
    assert!(check_native_package_root(fixture.root(), wrong_cli).is_err());

    let inventory_path = fixture.root().join("inventory.json");
    let mut inventory: Value = serde_json::from_slice(&fs::read(&inventory_path).unwrap()).unwrap();
    inventory["cli_version"] = json!("0.2.1-dev");
    replace_file(&inventory_path, &json_bytes(&inventory), 0o644);
    assert!(check(&fixture).is_err());
}

#[test]
fn refuses_unlisted_extra_and_missing_payload_files() {
    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    write_extra_file(&fixture.root().join("unlisted.txt"), b"extra\n", 0o644);
    assert!(check(&fixture).is_err());

    let fixture = NativePackageFixture::new(Host::LinuxX86_64);
    fs::remove_file(fixture.root().join("assets/SHA256SUMS")).unwrap();
    assert!(check(&fixture).is_err());
}

#[test]
fn refuses_internal_file_directory_and_root_symlinks_and_fifo() {
    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    let outside = fixture.dir.parent.join("outside bytes");
    write_extra_file(&outside, b"not package content", 0o600);
    let checksum = fixture.root().join("assets/SHA256SUMS");
    fs::remove_file(&checksum).unwrap();
    symlink(&outside, &checksum).unwrap();
    assert!(check(&fixture).is_err());

    let fixture = NativePackageFixture::new(Host::LinuxX86_64);
    symlink(
        fixture.root().join("assets"),
        fixture.root().join("linked-assets"),
    )
    .unwrap();
    assert!(check(&fixture).is_err());

    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    create_fifo(&fixture.root().join("unexpected.fifo"));
    assert!(check(&fixture).is_err());

    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    let root_alias = fixture.dir.parent.join("linked package root");
    symlink(fixture.root(), &root_alias).unwrap();
    assert!(check_native_package_root(&root_alias, fixture.runtime()).is_err());
}

#[test]
fn refuses_unrecognized_python_named_file_even_when_inventory_lists_it() {
    let mut fixture = NativePackageFixture::new(Host::MacosAarch64);
    // Data-only countercontrol; the bytes are never executed.
    fixture.files.insert(
        "bin/python".to_owned(),
        FixtureFile {
            bytes: b"synthetic unrecognized package-role file\n".to_vec(),
            mode: 0o644,
        },
    );
    fixture.refresh();
    let error = check(&fixture).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("file has no native package role")
    );
}

#[test]
fn refuses_header_only_scripts_wrong_host_and_malformed_linux_pies_after_reindexing() {
    for host in [Host::LinuxX86_64, Host::MacosAarch64] {
        let mut script = NativePackageFixture::new(host);
        script.replace_launchers(b"#!/bin/sh\nexit 0\n".to_vec());
        assert!(check(&script).is_err());

        let mut wrong_host = NativePackageFixture::new(host);
        wrong_host.replace_launchers(native_header(other_host(host)));
        assert!(check(&wrong_host).is_err());
    }

    // These files are structurally consistent with their freshly rebuilt
    // digests/inventory, but are not executable ELF PIE headers.
    for (entry, phnum) in [(0, 1), (0x400000, 0)] {
        let mut malformed = NativePackageFixture::new(Host::LinuxX86_64);
        malformed.replace_launchers(linux_pie_header(entry, phnum));
        assert!(check(&malformed).is_err());
    }
}

#[test]
fn checked_read_refuses_unlisted_bytes_mode_and_symlink_changes() {
    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    let package = check(&fixture).unwrap();
    assert!(package.read_file("unlisted.txt").is_err());
    let asset = fixture.root().join("assets/SHA256SUMS");
    replace_file(&asset, b"changed bytes\n", 0o644);
    assert!(package.read_file("assets/SHA256SUMS").is_err());
    drop(package);

    let fixture = NativePackageFixture::new(Host::LinuxX86_64);
    let package = check(&fixture).unwrap();
    let asset = fixture.root().join("assets/SHA256SUMS");
    fs::set_permissions(&asset, Permissions::from_mode(0o600)).unwrap();
    assert!(package.read_file("assets/SHA256SUMS").is_err());
    drop(package);

    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    let package = check(&fixture).unwrap();
    let asset = fixture.root().join("assets/SHA256SUMS");
    let outside = fixture.dir.parent.join("replacement outside file");
    write_extra_file(&outside, b"replacement", 0o600);
    fs::remove_file(&asset).unwrap();
    symlink(outside, &asset).unwrap();
    assert!(package.read_file("assets/SHA256SUMS").is_err());
}

#[test]
fn refuses_missing_or_empty_license_text() {
    let mut missing = NativePackageFixture::new(Host::MacosAarch64);
    missing.files.remove("LICENSE-MIT");
    missing.refresh();
    assert!(check(&missing).is_err());

    let mut empty = NativePackageFixture::new(Host::LinuxX86_64);
    empty.files.insert(
        "LICENSE-MIT".to_owned(),
        FixtureFile {
            bytes: Vec::new(),
            mode: 0o644,
        },
    );
    empty.refresh();
    assert!(check(&empty).is_err());

    let mut no_third_party = NativePackageFixture::new(Host::MacosAarch64);
    no_third_party.files.remove("licenses/fixture.txt");
    no_third_party.refresh();
    assert!(check(&no_third_party).is_err());
}

#[test]
fn current_host_profile_is_explicitly_supported() {
    let host = Host::current().expect("supported test host");
    let fixture = NativePackageFixture::new(host);
    let package = check(&fixture).expect("current host header and package fixture");
    assert_eq!(package.pins().host, host);
}

#[test]
fn accepts_current_host_compiler_executable_header_without_running_fixture_copy() {
    let host = Host::current().expect("supported test host");
    let mut fixture = NativePackageFixture::new(host);
    let compiler_test_executable = fs::read(std::env::current_exe().expect("test executable path"))
        .expect("read current test executable bytes");
    fixture.replace_launchers(compiler_test_executable.clone());

    let package =
        check(&fixture).expect("current host compiler output passes structural admission");
    assert_eq!(
        package.read_file("bin/ami-rust").unwrap(),
        compiler_test_executable
    );
    assert_eq!(
        package.read_file("bin/cargo-ami").unwrap(),
        compiler_test_executable
    );
    // The package copy is inspected as data only; the test runner does not
    // launch either synthetic package path or claim this is the CLI identity.
}

#[allow(unsafe_code)]
fn create_fifo(path: &Path) {
    let encoded = CString::new(path.as_os_str().as_bytes()).expect("fixture path without NUL");
    // SAFETY: `encoded` is a live NUL-terminated path and this test owns its
    // private temporary parent; the created FIFO is only a special-file input.
    assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
}

#[test]
fn refuses_writable_payload_directories_and_wrong_initial_file_modes() {
    let fixture = NativePackageFixture::new(Host::MacosAarch64);
    fs::set_permissions(fixture.root().join("assets"), Permissions::from_mode(0o775)).unwrap();
    assert!(
        check(&fixture)
            .unwrap_err()
            .to_string()
            .contains("unsafe ownership/write permissions")
    );

    let fixture = NativePackageFixture::new(Host::LinuxX86_64);
    fs::set_permissions(
        fixture.root().join("inventory.json"),
        Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(check(&fixture).is_err());

    let mut fixture = NativePackageFixture::new(Host::LinuxX86_64);
    fixture.files.get_mut("assets/SHA256SUMS").unwrap().mode = 0o755;
    fixture.refresh();
    assert!(
        check(&fixture)
            .unwrap_err()
            .to_string()
            .contains("unexpected role/mode")
    );
}

#[test]
fn elf_structural_admission_checks_executable_ranges_without_loader_claim() {
    let valid = linux_pie_header(0x400000, 1);
    assert!(check_native_header(&valid, Host::LinuxX86_64).is_ok());
    let mut fixed_address = valid.clone();
    fixed_address[16..18].copy_from_slice(&2_u16.to_le_bytes());
    assert!(check_native_header(&fixed_address, Host::LinuxX86_64).is_ok());
    let mut malformed = Vec::new();
    let mut header = valid.clone();
    header[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    malformed.push(header);
    let mut header = valid.clone();
    header[54..56].copy_from_slice(&55_u16.to_le_bytes());
    malformed.push(header);
    let mut header = valid.clone();
    header[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
    malformed.push(header);
    let mut header = valid.clone();
    header[68..72].copy_from_slice(&4_u32.to_le_bytes()); // Read-only PT_LOAD.
    malformed.push(header);
    let mut header = valid.clone();
    header[24..32].copy_from_slice(&0x400078_u64.to_le_bytes()); // Entry exactly at range end.
    malformed.push(header);
    let mut header = valid.clone();
    header[104..112].copy_from_slice(&119_u64.to_le_bytes()); // filesz > memsz.
    malformed.push(header);
    let mut header = valid.clone();
    header[72..80].copy_from_slice(&u64::MAX.to_le_bytes()); // File-end overflow.
    malformed.push(header);
    let mut header = valid;
    header[80..88].copy_from_slice(&u64::MAX.to_le_bytes()); // Virtual-end overflow.
    malformed.push(header);
    for header in malformed {
        assert!(check_native_header(&header, Host::LinuxX86_64).is_err());
    }
}

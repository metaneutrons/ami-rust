//! Native package byte/metadata consistency and relocatable root discovery.
//!
//! This is not publisher authentication. The package manager/distributor is
//! trusted separately. Reads are anchored and bounded, but no claim is made of
//! a snapshot against an owner/admin changing a live installation. Consumers
//! use retained record bytes and rechecked file reads before copying/execution.

use crate::{
    Refusal, Result,
    digest::sha256_bytes,
    directory::{Directory, EntryType},
    inventory::{FileIdentity, InventoryLimits, Measurement, verify_complete_directory},
    json::JsonProfile,
    package_records::{
        AssetPin, NativePackageInventory, NativePackagePins, parse_native_package_inventory,
        parse_native_package_pins, parse_native_package_proofs,
    },
    publisher_files::{read_bundle_file, read_open_regular},
    records::Host,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 16_384;
const REQUIRED: [&str; 7] = [
    "bin/ami-rust",
    "bin/cargo-ami",
    "pins.json",
    "proofs.json",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "THIRD-PARTY-NOTICES.md",
];

/// Caller-selected identity of the actual executing native frontend. Use the
/// compiled CLI version and supported host, not values inferred from pins.
pub struct PackageRuntime<'a> {
    pub host: Host,
    pub cli_version: &'a str,
}

/// Private construction means the initial complete consistency pass succeeded.
/// No field asserts publisher authenticity, license acceptance or SDK readiness.
pub struct CheckedNativePackage {
    root: Directory,
    path: PathBuf,
    pins: NativePackagePins,
    inventory: NativePackageInventory,
    raw_pins: Vec<u8>,
    raw_inventory: Vec<u8>,
    raw_proofs: Vec<u8>,
    measurement: Measurement,
}

impl std::fmt::Debug for CheckedNativePackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedNativePackage")
            .field("path", &self.path)
            .field("measurement", &self.measurement)
            .finish_non_exhaustive()
    }
}

impl CheckedNativePackage {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn pins(&self) -> &NativePackagePins {
        &self.pins
    }
    pub fn inventory(&self) -> &NativePackageInventory {
        &self.inventory
    }
    pub fn measurement(&self) -> &Measurement {
        &self.measurement
    }
    pub fn raw_inventory(&self) -> &[u8] {
        &self.raw_inventory
    }

    /// Retain a checked file's immutable bytes. Records use their original
    /// retained bytes; other files are opened afresh and checked against that
    /// inventory before returning. Unlisted files can never enter a copy.
    pub fn read_file(&self, relative: &str) -> Result<Vec<u8>> {
        match relative {
            "inventory.json" => return Ok(self.raw_inventory.clone()),
            "pins.json" => return Ok(self.raw_pins.clone()),
            "proofs.json" => return Ok(self.raw_proofs.clone()),
            _ => {}
        }
        let identity = self
            .inventory
            .files
            .iter()
            .find(|row| row.path == relative)
            .ok_or_else(|| Refusal::new("file is absent from the checked package inventory"))?;
        let limit = usize::try_from(identity.bytes)
            .map_err(|_| Refusal::new("package file cannot fit in memory"))?;
        let (parent, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
        let file = self
            .root
            .relative_directory(parent)?
            .regular(OsStr::new(leaf))?;
        let metadata = file.metadata()?;
        if Some(metadata.mode() & 0o7777) != identity.mode || !trusted_uid(metadata.uid()) {
            return Err(Refusal::new(
                "package file owner/mode changed after validation",
            ));
        }
        // Content and ownership/mode refer to this same descriptor. The reader
        // checks ordinary metadata changes across the bounded content read.
        let raw = read_open_regular(file, limit)?;
        if raw.len() as u64 != identity.bytes || sha256_bytes(&raw) != identity.sha256 {
            return Err(Refusal::new(
                "package file changed after consistency validation",
            ));
        }
        if ["bin/ami-rust", "bin/cargo-ami"].contains(&relative) {
            check_native_header(&raw, self.pins.host)?;
        }
        Ok(raw)
    }
}

/// Check a supplied root against explicit runtime identity. This does not
/// discover the running executable or prove OS-version compatibility.
pub fn check_native_package_root(
    root: &Path,
    runtime: PackageRuntime<'_>,
) -> Result<CheckedNativePackage> {
    canonical_root(root)?;
    let directory = Directory::open(root)?;
    let profile = JsonProfile::PackageMetadataStateSelection.max_bytes();
    let raw_pins = read_bundle_file(&directory, "pins.json", profile)?;
    let pins = parse_native_package_pins(&raw_pins)?;
    if pins.host != runtime.host || pins.cli_version != runtime.cli_version {
        return Err(Refusal::new(
            "native package host/CLI differs from the executing runtime",
        ));
    }
    let raw_inventory = read_bundle_file(&directory, "inventory.json", profile)?;
    let inventory = parse_native_package_inventory(&raw_inventory)?;
    if inventory.cli_version != pins.cli_version
        || inventory.sdk_version != pins.sdk_version
        || inventory.package_version != pins.package_version
        || inventory.host != pins.host
    {
        return Err(Refusal::new(
            "native package identity differs from its inventory",
        ));
    }
    let raw_proofs = read_bundle_file(&directory, "proofs.json", profile)?;
    let proofs = parse_native_package_proofs(&raw_proofs, &pins)?;
    validate_roles(&pins, &inventory.files, &proofs)?;
    for (name, raw) in [("pins.json", &raw_pins), ("proofs.json", &raw_proofs)] {
        let row = inventory
            .files
            .iter()
            .find(|row| row.path == name)
            .ok_or_else(|| Refusal::new("missing package control-file inventory row"))?;
        if row.bytes != raw.len() as u64 || row.sha256 != sha256_bytes(raw) {
            return Err(Refusal::new(
                "package record differs from its inventory identity",
            ));
        }
    }
    let mut files = inventory.files.clone();
    files.push(FileIdentity {
        path: "inventory.json".to_owned(),
        bytes: raw_inventory.len() as u64,
        sha256: sha256_bytes(&raw_inventory),
        mode: Some(0o644),
    });
    let total = files
        .iter()
        .try_fold(0_u64, |n, row| n.checked_add(row.bytes))
        .ok_or_else(|| Refusal::new("package byte count overflow"))?;
    if total > MAX_PACKAGE_BYTES {
        return Err(Refusal::new(
            "native package exceeds its container byte profile",
        ));
    }
    check_owned_tree(&directory)?;
    let measurement = verify_complete_directory(
        &directory,
        &files,
        &[],
        InventoryLimits {
            max_tree_entries: MAX_TREE_ENTRIES,
            max_link_resolution_steps: 0,
        },
    )?;
    canonical_root(root)?;
    let reopened = Directory::open(root)?;
    let before = directory.metadata()?;
    let after = reopened.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Refusal::new("package root changed during verification"));
    }
    let package = CheckedNativePackage {
        root: directory,
        path: root.to_path_buf(),
        pins,
        inventory,
        raw_pins,
        raw_inventory,
        raw_proofs,
        measurement,
    };
    // Both frontend rows have identical digests. Inspect one of their checked
    // byte strings to reject script wrappers and the wrong native architecture.
    package.read_file("bin/ami-rust")?;
    Ok(package)
}

/// Discover the owned payload from an actual OS executable path. Symlinked
/// public entrypoints are resolved once; symlinks inside the payload refuse.
/// argv[0] is deliberately not used for this operation or rewritten for Cargo.
pub fn package_from_executable(
    executable: &Path,
    runtime: PackageRuntime<'_>,
) -> Result<CheckedNativePackage> {
    if !executable.is_absolute() {
        return Err(Refusal::new("actual executable path must be absolute"));
    }
    let executable = fs::canonicalize(executable)
        .map_err(|e| Refusal::new(format!("could not resolve actual executable: {e}")))?;
    let name = executable
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| ["ami-rust", "cargo-ami"].contains(name))
        .ok_or_else(|| Refusal::new("actual executable does not have a native frontend name"))?;
    let bin = executable
        .parent()
        .filter(|p| p.file_name() == Some(OsStr::new("bin")))
        .ok_or_else(|| Refusal::new("native frontend must reside in the owned bin directory"))?;
    let root = bin
        .parent()
        .ok_or_else(|| Refusal::new("missing native package root"))?;
    let package = check_native_package_root(root, runtime)?;
    let expected = &package.pins.launchers[name];
    if expected.path != format!("bin/{name}") {
        return Err(Refusal::new(
            "actual executable is not the declared frontend",
        ));
    }
    package.read_file(&expected.path)?;
    Ok(package)
}

fn canonical_root(root: &Path) -> Result<()> {
    if !root.is_absolute() || fs::canonicalize(root)?.as_os_str() != root.as_os_str() {
        return Err(Refusal::new(
            "package root must be a canonical absolute directory without symlinks",
        ));
    }
    Ok(())
}

/// Header admission only, not an OS-loader test or proof of runtime closure.
fn check_native_header(raw: &[u8], host: Host) -> Result<()> {
    if raw.len() < 64 {
        return Err(Refusal::new(
            "native frontend is shorter than its host header",
        ));
    }
    let u16_at = |offset| u16::from_le_bytes([raw[offset], raw[offset + 1]]);
    let u32_at = |offset| {
        u32::from_le_bytes(
            raw[offset..offset + 4]
                .try_into()
                .expect("fixed header range"),
        )
    };
    let valid = match host {
        Host::LinuxX86_64 => {
            raw[..7] == [0x7f, b'E', b'L', b'F', 2, 1, 1]
                && [0, 3].contains(&raw[7])
                && [2, 3].contains(&u16_at(16))
                && u16_at(18) == 62
                && u32_at(20) == 1
                && u16_at(52) == 64
                && elf_executable_entry(raw)
        }
        Host::MacosAarch64 => {
            raw[..4] == [0xcf, 0xfa, 0xed, 0xfe] && u32_at(4) == 0x0100_000c && u32_at(12) == 2
        }
    };
    if !valid {
        return Err(Refusal::new(
            "frontend is not a native executable for the selected host",
        ));
    }
    Ok(())
}

// An ET_DYN kind alone also admits ordinary DSOs. Require an entrypoint in a
// bounded executable PT_LOAD range; this remains structural header admission,
// not validation of every loader rule or evidence that the image executes.
fn elf_executable_entry(raw: &[u8]) -> bool {
    let u16_at = |offset| u16::from_le_bytes([raw[offset], raw[offset + 1]]);
    let u64_at = |offset| {
        u64::from_le_bytes(
            raw[offset..offset + 8]
                .try_into()
                .expect("bounded ELF header"),
        )
    };
    let entry = u64_at(24);
    let Ok(start) = usize::try_from(u64_at(32)) else {
        return false;
    };
    let count = usize::from(u16_at(56));
    if entry == 0 || start < 64 || u16_at(54) != 56 || !(1..=4096).contains(&count) {
        return false;
    }
    let Some(end) = count
        .checked_mul(56)
        .and_then(|bytes| start.checked_add(bytes))
    else {
        return false;
    };
    let Some(headers) = raw.get(start..end) else {
        return false;
    };
    let mut entry_loaded = false;
    for header in headers.chunks_exact(56) {
        let u32_at = |offset| {
            u32::from_le_bytes(
                header[offset..offset + 4]
                    .try_into()
                    .expect("bounded program header"),
            )
        };
        let u64_at = |offset| {
            u64::from_le_bytes(
                header[offset..offset + 8]
                    .try_into()
                    .expect("bounded program header"),
            )
        };
        if u32_at(0) != 1 {
            continue;
        } // PT_LOAD
        let offset = u64_at(8);
        let address = u64_at(16);
        let file_size = u64_at(32);
        let memory_size = u64_at(40);
        let Some(file_end) = offset.checked_add(file_size) else {
            return false;
        };
        let Some(memory_end) = address.checked_add(memory_size) else {
            return false;
        };
        if file_size > memory_size || file_end > raw.len() as u64 {
            return false;
        }
        entry_loaded |= u32_at(4) & 1 != 0 && entry >= address && entry < memory_end;
    }
    entry_loaded
}

fn validate_roles(
    pins: &NativePackagePins,
    files: &[FileIdentity],
    proofs: &BTreeMap<String, AssetPin>,
) -> Result<()> {
    let rows: BTreeMap<_, _> = files.iter().map(|row| (row.path.as_str(), row)).collect();
    for required in REQUIRED {
        if !rows.contains_key(required) {
            return Err(Refusal::new(format!(
                "incomplete native package control files: {required}"
            )));
        }
    }
    let mut permitted: BTreeSet<String> = REQUIRED.into_iter().map(str::to_owned).collect();
    permitted.insert("README.md".to_owned());
    for (prefix, pins) in [
        ("assets", pins.assets.iter().collect::<Vec<_>>()),
        ("proofs", proofs.values().collect()),
    ] {
        for pin in pins {
            let path = format!("{prefix}/{}", pin.path);
            let row = rows.get(path.as_str()).ok_or_else(|| {
                Refusal::new("pinned package asset/proof is missing from inventory")
            })?;
            if row.bytes != pin.bytes || row.sha256 != pin.sha256.as_str() {
                return Err(Refusal::new(
                    "package asset/proof differs from its input pin",
                ));
            }
            permitted.insert(path);
        }
    }
    for pin in pins.launchers.values() {
        let row = rows[pin.path.as_str()];
        if row.bytes != pin.bytes || row.sha256 != pin.sha256.as_str() {
            return Err(Refusal::new("native launcher differs from its package pin"));
        }
    }
    let mut licenses = 0;
    for row in files {
        let binary = ["bin/ami-rust", "bin/cargo-ami"].contains(&row.path.as_str());
        if row.mode != Some(if binary { 0o755 } else { 0o644 }) {
            return Err(Refusal::new(
                "native package file has an unexpected role/mode",
            ));
        }
        if row.path.starts_with("licenses/") {
            if row.bytes == 0 {
                return Err(Refusal::new("empty third-party license text"));
            }
            licenses += 1;
        } else if !permitted.contains(&row.path) {
            return Err(Refusal::new("file has no native package role"));
        }
        if ["LICENSE-MIT", "LICENSE-APACHE", "THIRD-PARTY-NOTICES.md"].contains(&row.path.as_str())
            && row.bytes == 0
        {
            return Err(Refusal::new("missing native package license/notice text"));
        }
    }
    if licenses == 0 {
        return Err(Refusal::new(
            "native package has no third-party license text directory",
        ));
    }
    Ok(())
}

fn check_owned_tree(root: &Directory) -> Result<()> {
    let mut pending = vec![String::new()];
    let mut count = 0_usize;
    while let Some(path) = pending.pop() {
        let directory = root.relative_directory(&path)?;
        let info = directory.metadata()?;
        if !trusted_uid(info.uid()) || info.mode() & 0o022 != 0 {
            return Err(Refusal::new(
                "native payload directory has unsafe ownership/write permissions",
            ));
        }
        for name in directory.names(MAX_TREE_ENTRIES - count)? {
            count += 1;
            let identity = directory.classify_entry(&name)?;
            match identity.entry_type() {
                EntryType::Directory => {
                    let name = name
                        .to_str()
                        .ok_or_else(|| Refusal::new("package path is not UTF-8"))?;
                    pending.push(if path.is_empty() {
                        name.to_owned()
                    } else {
                        format!("{path}/{name}")
                    });
                }
                EntryType::RegularFile => {
                    let file = directory.open_regular_matching(&name, identity)?;
                    let info = file.metadata()?;
                    if !trusted_uid(info.uid()) || info.mode() & 0o022 != 0 {
                        return Err(Refusal::new(
                            "native payload file has unsafe ownership/write permissions",
                        ));
                    }
                }
                _ => {
                    return Err(Refusal::new(
                        "native package contains a linked or special entry",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn trusted_uid(uid: u32) -> bool {
    // SAFETY: getuid reads the caller's real UID without pointers or mutation.
    uid == 0 || uid == unsafe { libc::getuid() }
}

#[cfg(test)]
#[path = "package_tests.rs"]
mod tests;

//! Verification of the fixed, locally composed native-build toolchain prefix.
//!
//! The embedded inventories describe expected bytes and symlink text. This is
//! a local consistency check, not publisher authentication or an execution
//! sandbox.

use crate::{Refusal, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

const TARGET: &str = "x86_64-aros";
const RUST_CARGO_PATH: &str = "bin/cargo";
const COMPOSED_CARGO_PATH: &str = "bin/cargo";
const COLLECTOR_INVENTORY_PATH: &str = "bin/aros-collect";
const COMPOSED_COLLECTOR_PATH: &str = "bin/collect-aros";
const TARGET_SPEC_PATH: &str = "lib/rustlib/x86_64-aros/x86_64-aros.json";
const TARGET_LIBRARY_ROOT: &str = "lib/rustlib/x86_64-aros/lib";

/// A verified toolchain prefix used by the native build crate.
///
/// The root is canonicalized once by [`Toolchain::open`]. All component paths
/// are then derived from that canonical root and remain private so callers
/// cannot accidentally substitute a different tool.
#[derive(Clone, Debug)]
pub struct Toolchain {
    root: PathBuf,
    rustc: PathBuf,
    cargo: PathBuf,
    toolchain_root: PathBuf,
    sdk_root: PathBuf,
    collector: PathBuf,
    target_spec: PathBuf,
    host: &'static str,
    source_date_epoch: u64,
    identity: String,
}

impl Toolchain {
    /// Open and verify the fixed composed prefix at `root`.
    pub fn open(root: &Path) -> Result<Self> {
        let host = current_host()?;
        let root = fs::canonicalize(root).map_err(|error| {
            Refusal::new(format!(
                "could not resolve native toolchain root {}: {error}",
                root.display()
            ))
        })?;
        ensure_real_directory(&root, "native toolchain root")?;

        let pins = Pins::for_host(host)?;
        verify_prefix(&root, &pins)?;

        Ok(Self {
            rustc: root.join("bin/rustc"),
            cargo: root.join(COMPOSED_CARGO_PATH),
            toolchain_root: root.join("libexec/aros/llvm"),
            sdk_root: root.join("lib/aros/c-sdk"),
            collector: root.join(COMPOSED_COLLECTOR_PATH),
            target_spec: root.join(TARGET_SPEC_PATH),
            root,
            host,
            source_date_epoch: pins.source_date_epoch,
            identity: pins.identity,
        })
    }

    /// Revalidate every pinned input under the canonical root.
    pub fn recheck(&self) -> Result<()> {
        if current_host()? != self.host {
            return Err(Refusal::new(
                "native toolchain host identity changed after it was opened",
            ));
        }
        ensure_real_directory(&self.root, "native toolchain root")?;
        verify_prefix(&self.root, &Pins::for_host(self.host)?)
    }

    /// Return the canonical composed-prefix root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the pinned Rust compiler path.
    pub fn rustc(&self) -> &Path {
        &self.rustc
    }

    /// Return the pinned Cargo path.
    pub fn cargo(&self) -> &Path {
        &self.cargo
    }

    /// Return the exact LLVM component root.
    pub fn toolchain_root(&self) -> &Path {
        &self.toolchain_root
    }

    /// Return the exact C SDK root.
    pub fn sdk_root(&self) -> &Path {
        &self.sdk_root
    }

    /// Return the pinned AROS collector path.
    pub fn collector(&self) -> &Path {
        &self.collector
    }

    /// Return the pinned `x86_64-aros` target specification path.
    pub fn target_spec(&self) -> &Path {
        &self.target_spec
    }

    /// Return the pinned source-date epoch for reproducible native outputs.
    pub fn source_date_epoch(&self) -> u64 {
        self.source_date_epoch
    }

    /// Stable host and target identity derived from the embedded pin bytes.
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Return the pinned native-build host key for the running host.
pub fn current_host() -> Result<&'static str> {
    host_for_target(std::env::consts::OS, std::env::consts::ARCH)
}

fn host_for_target(os: &str, arch: &str) -> Result<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Ok("macos-aarch64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        _ => Err(Refusal::new(
            "native build supports only macOS aarch64 and Linux x86_64/aarch64 hosts",
        )),
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Inventory {
    #[serde(default)]
    files: Vec<FilePin>,
    #[serde(default)]
    symlinks: Vec<SymlinkPin>,
}

#[derive(Clone, Debug, Deserialize)]
struct FilePin {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SymlinkPin {
    path: String,
    target: String,
}

#[derive(Deserialize)]
struct TargetPin {
    schema: String,
    target: String,
    source_date_epoch: u64,
    spec_sha256: String,
    status: String,
}

#[derive(Deserialize)]
struct TargetLibrariesPin {
    schema: String,
    target: String,
    files: Vec<FilePin>,
    #[serde(default)]
    symlinks: Vec<SymlinkPin>,
}

#[derive(Clone, Copy)]
struct EmbeddedPins {
    rust: &'static str,
    cargo: &'static str,
    collector: &'static str,
    llvm: &'static str,
    csdk: &'static str,
    target: &'static str,
    target_libraries: &'static str,
}

struct Pins {
    rust: Inventory,
    cargo: Inventory,
    collector: Inventory,
    llvm: Inventory,
    csdk: Inventory,
    target_libraries: Inventory,
    target_spec_sha256: String,
    source_date_epoch: u64,
    identity: String,
}

impl Pins {
    fn for_host(host: &'static str) -> Result<Self> {
        let embedded = embedded_pins_for_host(host)?;
        let rust = parse_inventory("Rust sysroot", embedded.rust)?;
        let cargo = parse_inventory("Cargo", embedded.cargo)?;
        let collector = parse_inventory("collector", embedded.collector)?;
        let llvm = parse_inventory("LLVM toolchain", embedded.llvm)?;
        let csdk = parse_inventory("C SDK", embedded.csdk)?;
        let target: TargetPin = parse_pin("target", embedded.target)?;
        let target_libraries: TargetLibrariesPin =
            parse_pin("target libraries", embedded.target_libraries)?;

        if target.schema != "aros-native-build-target-v1" || target.target != TARGET {
            return Err(Refusal::new(
                "embedded native-build target pin has an unsupported schema or target",
            ));
        }
        if target.status != "DEVELOPMENT_CANDIDATE_NOT_RELEASE_QUALIFICATION" {
            return Err(Refusal::new(
                "embedded native-build target pin has an unexpected qualification status",
            ));
        }
        validate_sha256(&target.spec_sha256, "target specification pin")?;
        if target_libraries.schema != "aros-target-library-candidate-v1"
            || target_libraries.target != TARGET
        {
            return Err(Refusal::new(
                "embedded target-library pin has an unsupported schema or target",
            ));
        }

        let identity = input_identity(host, &embedded);
        Ok(Self {
            rust,
            cargo,
            collector,
            llvm,
            csdk,
            target_libraries: Inventory {
                files: target_libraries.files,
                symlinks: target_libraries.symlinks,
            },
            target_spec_sha256: target.spec_sha256,
            source_date_epoch: target.source_date_epoch,
            identity,
        })
    }
}

fn embedded_pins_for_host(host: &str) -> Result<EmbeddedPins> {
    match host {
        "macos-aarch64" => Ok(EmbeddedPins {
            rust: include_str!("../pins/macos-aarch64/rust-runtime-v2.json"),
            cargo: include_str!("../pins/macos-aarch64/cargo.json"),
            collector: include_str!("../pins/macos-aarch64/collector.json"),
            llvm: include_str!("../pins/macos-aarch64/toolchain.json"),
            csdk: include_str!("../pins/macos-aarch64/csdk.json"),
            target: include_str!("../pins/target.json"),
            target_libraries: include_str!("../pins/target-libraries.json"),
        }),
        "linux-x86_64" => Ok(EmbeddedPins {
            rust: include_str!("../pins/linux-x86_64/rust.json"),
            cargo: include_str!("../pins/linux-x86_64/cargo.json"),
            collector: include_str!("../pins/linux-x86_64/collector.json"),
            llvm: include_str!("../pins/linux-x86_64/toolchain.json"),
            csdk: include_str!("../pins/linux-x86_64/csdk.json"),
            target: include_str!("../pins/target.json"),
            target_libraries: include_str!("../pins/target-libraries.json"),
        }),
        "linux-aarch64" => Ok(EmbeddedPins {
            rust: include_str!("../pins/linux-aarch64/rust.json"),
            cargo: include_str!("../pins/linux-aarch64/cargo.json"),
            collector: include_str!("../pins/linux-aarch64/collector.json"),
            llvm: include_str!("../pins/linux-aarch64/toolchain.json"),
            csdk: include_str!("../pins/linux-aarch64/csdk.json"),
            target: include_str!("../pins/target.json"),
            target_libraries: include_str!("../pins/target-libraries.json"),
        }),
        _ => Err(Refusal::new(
            "no native-build input pins are embedded for this host",
        )),
    }
}

fn parse_inventory(name: &str, json: &str) -> Result<Inventory> {
    parse_pin(name, json)
}

fn parse_pin<T: for<'de> Deserialize<'de>>(name: &str, json: &str) -> Result<T> {
    serde_json::from_str(json)
        .map_err(|error| Refusal::new(format!("embedded {name} pin is invalid: {error}")))
}

fn input_identity(host: &str, pins: &EmbeddedPins) -> String {
    let inputs = [
        ("rust", pins.rust),
        ("cargo", pins.cargo),
        ("collector", pins.collector),
        ("llvm", pins.llvm),
        ("csdk", pins.csdk),
        ("target", pins.target),
        ("target-libraries", pins.target_libraries),
    ];
    let mut digest = Sha256::new();
    digest.update(b"aros-native-build-input-identity-v1\0");
    for (label, bytes) in inputs {
        digest.update((label.len() as u64).to_be_bytes());
        digest.update(label.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes.as_bytes());
    }
    let final_digest = digest.finalize();
    format!("{host}:{TARGET}:sha256:{}", hex_digest(&final_digest))
}

fn verify_prefix(root: &Path, pins: &Pins) -> Result<()> {
    ensure_real_directory(root, "native toolchain root")?;

    unique_file_pin(&pins.rust, RUST_CARGO_PATH, "Rust sysroot")?;
    verify_inventory_members(root, &pins.rust, "Rust sysroot", Some(RUST_CARGO_PATH))?;
    let cargo = unique_file_pin(&pins.cargo, COMPOSED_CARGO_PATH, "Cargo")?;
    verify_file(
        root,
        COMPOSED_CARGO_PATH,
        Some(cargo.bytes),
        &cargo.sha256,
        "Cargo",
    )?;

    let llvm_root = ensure_directory_chain(root, "libexec/aros/llvm", "LLVM toolchain")?;
    verify_exact_tree(&llvm_root, &pins.llvm, "LLVM toolchain")?;

    let sdk_root = ensure_directory_chain(root, "lib/aros/c-sdk", "C SDK")?;
    verify_exact_tree(&sdk_root, &pins.csdk, "C SDK")?;

    let collector = unique_file_pin(&pins.collector, COLLECTOR_INVENTORY_PATH, "collector")?;
    verify_file(
        root,
        COMPOSED_COLLECTOR_PATH,
        Some(collector.bytes),
        &collector.sha256,
        "collector",
    )?;

    verify_root_tool_links(root)?;

    let target_spec = parse_relative_path(TARGET_SPEC_PATH)?;
    ensure_parent_directories(root, &target_spec, "AROS target specification")?;
    verify_file(
        root,
        TARGET_SPEC_PATH,
        None,
        &pins.target_spec_sha256,
        "AROS target specification",
    )?;

    let target_libraries =
        ensure_directory_chain(root, TARGET_LIBRARY_ROOT, "AROS target libraries")?;
    verify_exact_tree(
        &target_libraries,
        &pins.target_libraries,
        "AROS target libraries",
    )
}

/// Verify every listed member while permitting the composed AROS subtrees and
/// tools to coexist with the complete Rust sysroot inventory.
fn verify_inventory_members(
    root: &Path,
    inventory: &Inventory,
    label: &str,
    skip_file: Option<&str>,
) -> Result<()> {
    let expected = expected_entries(inventory, label)?;
    for (path, entry) in expected {
        match entry {
            ExpectedEntry::File(file) if Some(path.as_str()) != skip_file => {
                verify_file(root, &path, Some(file.bytes), &file.sha256, label)?;
            }
            ExpectedEntry::File(_) => {}
            ExpectedEntry::Symlink(link) => {
                verify_symlink(root, root, &path, &link.target, label)?;
            }
        }
    }
    Ok(())
}

fn verify_exact_tree(root: &Path, inventory: &Inventory, label: &str) -> Result<()> {
    ensure_real_directory(root, label)?;
    let expected = expected_entries(inventory, label)?;
    let mut seen = BTreeSet::new();
    walk_exact_tree(root, root, "", &expected, &mut seen, label)?;

    if seen.len() != expected.len() {
        let missing = expected
            .keys()
            .find(|path| !seen.contains(*path))
            .map(String::as_str)
            .unwrap_or("unknown entry");
        return Err(Refusal::new(format!(
            "{label} inventory entry is missing: {missing}"
        )));
    }
    Ok(())
}

fn walk_exact_tree(
    tree_root: &Path,
    directory: &Path,
    prefix: &str,
    expected: &BTreeMap<String, ExpectedEntry>,
    seen: &mut BTreeSet<String>,
    label: &str,
) -> Result<()> {
    let entries = fs::read_dir(directory).map_err(|error| {
        Refusal::new(format!(
            "could not read {label} directory {}: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            Refusal::new(format!("could not read a {label} directory entry: {error}"))
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            Refusal::new(format!("{label} contains a path that is not valid UTF-8"))
        })?;
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        parse_relative_path(&relative).map_err(|_| {
            Refusal::new(format!(
                "{label} contains a non-normalized path: {relative}"
            ))
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Refusal::new(format!(
                "could not inspect {label} entry {}: {error}",
                path.display()
            ))
        })?;

        if metadata.file_type().is_symlink() {
            let Some(ExpectedEntry::Symlink(link)) = expected.get(&relative) else {
                return Err(Refusal::new(format!(
                    "{label} has an unexpected symlink: {relative}"
                )));
            };
            verify_symlink(tree_root, tree_root, &relative, &link.target, label)?;
            seen.insert(relative);
        } else if metadata.is_file() {
            let Some(ExpectedEntry::File(file)) = expected.get(&relative) else {
                return Err(Refusal::new(format!(
                    "{label} has an unexpected file: {relative}"
                )));
            };
            verify_file(tree_root, &relative, Some(file.bytes), &file.sha256, label)?;
            seen.insert(relative);
        } else if metadata.is_dir() {
            let child_prefix = format!("{relative}/");
            if expected
                .keys()
                .any(|expected_path| expected_path.starts_with(&child_prefix))
            {
                walk_exact_tree(tree_root, &path, &relative, expected, seen, label)?;
            } else {
                let mut children = fs::read_dir(&path).map_err(|error| {
                    Refusal::new(format!(
                        "could not inspect extra {label} directory {}: {error}",
                        path.display()
                    ))
                })?;
                if let Some(child) = children.next() {
                    child.map_err(|error| {
                        Refusal::new(format!(
                            "could not inspect extra {label} directory {}: {error}",
                            path.display()
                        ))
                    })?;
                    return Err(Refusal::new(format!(
                        "{label} has an unexpected non-empty directory: {relative}"
                    )));
                }
            }
        } else {
            return Err(Refusal::new(format!(
                "{label} has an unsupported filesystem entry: {relative}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone)]
enum ExpectedEntry {
    File(FilePin),
    Symlink(SymlinkPin),
}

fn expected_entries(inventory: &Inventory, label: &str) -> Result<BTreeMap<String, ExpectedEntry>> {
    let mut expected = BTreeMap::new();
    for file in &inventory.files {
        parse_relative_path(&file.path).map_err(|_| {
            Refusal::new(format!(
                "{label} inventory has a non-normalized file path: {}",
                file.path
            ))
        })?;
        validate_sha256(&file.sha256, label)?;
        if expected
            .insert(file.path.clone(), ExpectedEntry::File(file.clone()))
            .is_some()
        {
            return Err(Refusal::new(format!(
                "{label} inventory repeats path {}",
                file.path
            )));
        }
    }
    for link in &inventory.symlinks {
        parse_relative_path(&link.path).map_err(|_| {
            Refusal::new(format!(
                "{label} inventory has a non-normalized symlink path: {}",
                link.path
            ))
        })?;
        validate_symlink_target(&link.path, &link.target, label)?;
        if expected
            .insert(link.path.clone(), ExpectedEntry::Symlink(link.clone()))
            .is_some()
        {
            return Err(Refusal::new(format!(
                "{label} inventory repeats path {}",
                link.path
            )));
        }
    }
    Ok(expected)
}

fn unique_file_pin<'a>(inventory: &'a Inventory, path: &str, label: &str) -> Result<&'a FilePin> {
    let matches = inventory.files.iter().filter(|file| file.path == path);
    let mut matches = matches;
    let pin = matches
        .next()
        .ok_or_else(|| Refusal::new(format!("embedded {label} inventory is missing {path}")))?;
    if matches.next().is_some() {
        return Err(Refusal::new(format!(
            "embedded {label} inventory repeats {path}"
        )));
    }
    parse_relative_path(&pin.path)?;
    validate_sha256(&pin.sha256, label)?;
    Ok(pin)
}

fn verify_file(
    root: &Path,
    relative: &str,
    expected_bytes: Option<u64>,
    expected_sha256: &str,
    label: &str,
) -> Result<()> {
    let relative_path = parse_relative_path(relative)?;
    ensure_parent_directories(root, &relative_path, label)?;
    let path = root.join(&relative_path);
    let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
        Refusal::new(format!(
            "could not inspect {label} file {}: {error}",
            path.display()
        ))
    })?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(Refusal::new(format!(
            "{label} input is not a regular file: {}",
            path.display()
        )));
    }
    if let Some(expected) = expected_bytes
        && path_metadata.len() != expected
    {
        return Err(Refusal::new(format!(
            "{label} input has the wrong size: {}",
            path.display()
        )));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| {
            Refusal::new(format!(
                "could not open {label} input without following symlinks {}: {error}",
                path.display()
            ))
        })?;
    let before = file.metadata().map_err(|error| {
        Refusal::new(format!(
            "could not inspect opened {label} input {}: {error}",
            path.display()
        ))
    })?;
    if !before.is_file() {
        return Err(Refusal::new(format!(
            "{label} input changed to a non-regular file: {}",
            path.display()
        )));
    }
    if before.dev() != path_metadata.dev() || before.ino() != path_metadata.ino() {
        return Err(Refusal::new(format!(
            "{label} input changed while it was being opened: {}",
            path.display()
        )));
    }

    let mut digest = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            Refusal::new(format!(
                "could not read {label} input {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        count = count.checked_add(read as u64).ok_or_else(|| {
            Refusal::new(format!("{label} input size overflow: {}", path.display()))
        })?;
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|error| {
        Refusal::new(format!(
            "could not recheck {label} input {}: {error}",
            path.display()
        ))
    })?;
    let final_path_metadata = fs::symlink_metadata(&path).map_err(|error| {
        Refusal::new(format!(
            "could not recheck {label} path {}: {error}",
            path.display()
        ))
    })?;
    let stable = before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && count == after.len()
        && final_path_metadata.is_file()
        && !final_path_metadata.file_type().is_symlink()
        && final_path_metadata.dev() == after.dev()
        && final_path_metadata.ino() == after.ino();
    if !stable {
        return Err(Refusal::new(format!(
            "{label} input changed while it was being verified: {}",
            path.display()
        )));
    }
    if expected_bytes.is_some_and(|expected| count != expected) {
        return Err(Refusal::new(format!(
            "{label} input has the wrong size: {}",
            path.display()
        )));
    }

    let final_digest = digest.finalize();
    let actual = hex_digest(&final_digest);
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err(Refusal::new(format!(
            "{label} input does not match its embedded SHA-256 pin: {}",
            path.display()
        )));
    }
    Ok(())
}

fn verify_symlink(
    tree_root: &Path,
    containment_root: &Path,
    relative: &str,
    expected_target: &str,
    label: &str,
) -> Result<()> {
    validate_symlink_target(relative, expected_target, label)?;
    let relative_path = parse_relative_path(relative)?;
    ensure_parent_directories(tree_root, &relative_path, label)?;
    let path = tree_root.join(&relative_path);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        Refusal::new(format!(
            "could not inspect {label} symlink {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_symlink() {
        return Err(Refusal::new(format!(
            "{label} input is not the required symlink: {}",
            path.display()
        )));
    }
    let actual_target = fs::read_link(&path).map_err(|error| {
        Refusal::new(format!(
            "could not read {label} symlink {}: {error}",
            path.display()
        ))
    })?;
    if actual_target.as_os_str().as_bytes() != expected_target.as_bytes() {
        return Err(Refusal::new(format!(
            "{label} symlink has unexpected target text: {}",
            path.display()
        )));
    }
    let destination = fs::canonicalize(&path).map_err(|error| {
        Refusal::new(format!(
            "could not resolve {label} symlink {}: {error}",
            path.display()
        ))
    })?;
    if !destination.starts_with(containment_root) {
        return Err(Refusal::new(format!(
            "{label} symlink resolves outside its verified root: {}",
            path.display()
        )));
    }
    let destination_metadata = fs::metadata(&destination).map_err(|error| {
        Refusal::new(format!(
            "could not inspect {label} symlink destination {}: {error}",
            destination.display()
        ))
    })?;
    if !destination_metadata.is_file() {
        return Err(Refusal::new(format!(
            "{label} symlink does not resolve to a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn verify_root_tool_links(root: &Path) -> Result<()> {
    let bin = ensure_directory_chain(root, "bin", "tool links")?;
    let llvm_root = root.join("libexec/aros/llvm");
    let required = ["llvm-objdump", "llvm-nm", "llvm-ar", "llvm-strip", "ld.lld"];
    for name in required {
        let relative = format!("bin/{name}");
        let target = format!("../libexec/aros/llvm/bin/{name}");
        verify_symlink(root, root, &relative, &target, "tool link")?;

        let link_destination = fs::canonicalize(bin.join(name)).map_err(|error| {
            Refusal::new(format!("could not resolve tool link {relative}: {error}"))
        })?;
        let expected_destination =
            fs::canonicalize(llvm_root.join("bin").join(name)).map_err(|error| {
                Refusal::new(format!("could not resolve LLVM tool {name}: {error}"))
            })?;
        if link_destination != expected_destination || !link_destination.starts_with(root) {
            return Err(Refusal::new(format!(
                "tool link {relative} does not resolve to the pinned LLVM component"
            )));
        }
    }
    Ok(())
}

fn ensure_directory_chain(root: &Path, relative: &str, label: &str) -> Result<PathBuf> {
    ensure_real_directory(root, "native toolchain root")?;
    let relative = parse_relative_path(relative)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        ensure_real_directory(&current, label)?;
    }
    Ok(current)
}

fn ensure_parent_directories(root: &Path, relative: &Path, label: &str) -> Result<()> {
    ensure_real_directory(root, "native toolchain root")?;
    let mut current = root.to_path_buf();
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    for component in parent.components() {
        current.push(component.as_os_str());
        ensure_real_directory(&current, label)?;
    }
    Ok(())
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Refusal::new(format!(
            "could not inspect {label} directory {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Refusal::new(format!(
            "{label} path is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn parse_relative_path(value: &str) -> Result<PathBuf> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains('\0')
        || value.starts_with('/')
        || value.contains("//")
    {
        return Err(Refusal::new(
            "inventory path is not a normalized relative path",
        ));
    }
    let mut path = PathBuf::new();
    for component in value.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Refusal::new(
                "inventory path is not a normalized relative path",
            ));
        }
        path.push(component);
    }
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(Refusal::new(
            "inventory path is not a normalized relative path",
        ));
    }
    Ok(path)
}

fn validate_symlink_target(link_path: &str, target: &str, label: &str) -> Result<()> {
    parse_relative_path(link_path)?;
    if target.is_empty()
        || target.starts_with('/')
        || target.contains('\\')
        || target.contains('\0')
    {
        return Err(Refusal::new(format!(
            "{label} inventory has an invalid symlink target for {link_path}"
        )));
    }

    let parent = Path::new(link_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let mut depth = parent.components().count() as isize;
    for component in target.split('/') {
        if component.is_empty() {
            return Err(Refusal::new(format!(
                "{label} inventory has an invalid symlink target for {link_path}"
            )));
        }
        match component {
            "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return Err(Refusal::new(format!(
                        "{label} inventory symlink escapes its component: {link_path}"
                    )));
                }
            }
            _ => depth += 1,
        }
    }
    if depth == 0 {
        return Err(Refusal::new(format!(
            "{label} inventory symlink resolves to its component root: {link_path}"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Refusal::new(format!(
            "{label} inventory contains an invalid SHA-256 digest"
        )));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        FilePin, Inventory, Pins, SymlinkPin, TARGET_SPEC_PATH, embedded_pins_for_host,
        expected_entries, host_for_target, input_identity, parse_relative_path, verify_exact_tree,
        verify_file, verify_inventory_members,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    fn digest_text(text: &str) -> String {
        let digest = Sha256::digest(text.as_bytes());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn native_host_and_embedded_pin_selection_cover_three_hosts_only() {
        assert_eq!(
            host_for_target("macos", "aarch64").unwrap(),
            "macos-aarch64"
        );
        assert_eq!(host_for_target("linux", "x86_64").unwrap(), "linux-x86_64");
        assert_eq!(
            host_for_target("linux", "aarch64").unwrap(),
            "linux-aarch64"
        );
        for (os, arch) in [
            ("linux", "arm64"),
            ("macos", "x86_64"),
            ("windows", "aarch64"),
        ] {
            assert!(host_for_target(os, arch).is_err(), "accepted {os}/{arch}");
        }
        assert!(Pins::for_host("linux-arm64").is_err());
        assert!(embedded_pins_for_host("linux-riscv64").is_err());
        assert_eq!(
            super::current_host().unwrap(),
            host_for_target(std::env::consts::OS, std::env::consts::ARCH).unwrap()
        );
    }

    #[test]
    fn macos_runtime_and_linux_aarch64_profiles_are_exact_candidates() {
        let arm = embedded_pins_for_host("linux-aarch64").unwrap();
        let expected = [
            (
                "rust",
                "862be6c4c1d29c59fc774e2d38f046672fcd0aa0978a869be9af2752fb4f76ee",
                arm.rust,
            ),
            (
                "cargo",
                "857d1fa31e24d23c6792f79471a454dcdd644e01f18e3dec9b2cb78314e1da87",
                arm.cargo,
            ),
            (
                "collector",
                "52ea287e4fdf80eaa58a6d459828f1cb0d778b7201affe0dfde65f5ffec29e55",
                arm.collector,
            ),
            (
                "LLVM/C SDK toolchain",
                "be3dc1a696882367f4ff39ad393bf3ae66d6ee25fd73f8042eccfcb738defd68",
                arm.llvm,
            ),
            (
                "C SDK",
                "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
                arm.csdk,
            ),
            (
                "target",
                "33fdd3d97053370eb3db9e05ea75721dafcfc7f4b5f8c218acaab1911984c341",
                arm.target,
            ),
            (
                "target libraries",
                "4759fc1a0f2f74e1a624a6c7b62b5d9949d873f1ce05a61ba9825891bf327183",
                arm.target_libraries,
            ),
        ];
        for (name, expected_sha256, bytes) in expected {
            assert_eq!(
                digest_text(bytes),
                expected_sha256,
                "{name} pin bytes changed"
            );
        }

        let pins = Pins::for_host("linux-aarch64").unwrap();
        assert_eq!(pins.rust.files.len(), 3882);
        assert_eq!(pins.rust.symlinks.len(), 2);
        assert_eq!(pins.cargo.files.len(), 1);
        assert_eq!(pins.cargo.files[0].path, "bin/cargo");
        assert_eq!(pins.cargo.files[0].bytes, 45863336);
        assert_eq!(
            pins.cargo.files[0].sha256,
            "2f8a507ec5bef7fe41a04c18aee06e359ff7f3b70d17d98007c9014114e17d9b"
        );
        assert_eq!(pins.collector.files.len(), 10);
        assert_eq!(pins.llvm.files.len(), 2754);
        assert_eq!(pins.llvm.symlinks.len(), 134);
        assert_eq!(pins.csdk.files.len(), 2835);
        assert!(
            pins.identity
                .starts_with("linux-aarch64:x86_64-aros:sha256:")
        );

        let mac = Pins::for_host("macos-aarch64").unwrap();
        assert_eq!(mac.rust.symlinks.len(), 3);
        assert_eq!(
            mac.rust
                .symlinks
                .iter()
                .find(|link| link.path == "lib/rustlib/aarch64-apple-darwin/lib/libLLVM.dylib")
                .map(|link| link.target.as_str()),
            Some("../../../libLLVM.dylib")
        );

        let existing_hosts = [
            (
                "macos-aarch64",
                [
                    "02eecb396c56bd134cb4dc732d30898b03ab9a84ad1143f5d09c0a6b25fc466e",
                    "2f081118d19e93b95304c95440d82d1f3d022fb063e4ae7ad1b89285ceddbe39",
                    "34e7e069a72ac84d980f15c797b4250f324eee19088f55d135c9e4eafa0d88de",
                    "28237af9576e852451fcdf0470a904edb34a70232feb41d0c56be246313baadf",
                    "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
                ],
            ),
            (
                "linux-x86_64",
                [
                    "7a88373f28d19d6d61494587240681999adfb2bec964b4c3d74fae9718f097e8",
                    "85f5bb754c7f11429dc1a58a2adc1256b9ad4da1f7a47926629e1f94dd92ead8",
                    "0e97967a63d6ec868edcf26e2b2c08a9c36a292416aa0f7ae016564369551caa",
                    "a68f0d3d6b6d9e9678dca0af25b083d6b00f67fd4f806adcb6a2e16af1a19a6d",
                    "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
                ],
            ),
        ];
        for (host, hashes) in existing_hosts {
            let pins = embedded_pins_for_host(host).unwrap();
            let actual =
                [pins.rust, pins.cargo, pins.collector, pins.llvm, pins.csdk].map(digest_text);
            assert_eq!(actual, hashes, "existing {host} pins changed");
            Pins::for_host(host).unwrap();
        }
    }

    #[test]
    fn every_linux_aarch64_pin_participates_in_input_identity() {
        let pins = embedded_pins_for_host("linux-aarch64").unwrap();
        let identity = input_identity("linux-aarch64", &pins);
        let mut rust = pins;
        rust.rust = changed_text(pins.rust);
        assert_ne!(
            input_identity("linux-aarch64", &rust),
            identity,
            "rust missing from identity"
        );
        let mut cargo = pins;
        cargo.cargo = changed_text(pins.cargo);
        assert_ne!(
            input_identity("linux-aarch64", &cargo),
            identity,
            "cargo missing from identity"
        );
        let mut collector = pins;
        collector.collector = changed_text(pins.collector);
        assert_ne!(
            input_identity("linux-aarch64", &collector),
            identity,
            "collector missing from identity"
        );
        let mut llvm = pins;
        llvm.llvm = changed_text(pins.llvm);
        assert_ne!(
            input_identity("linux-aarch64", &llvm),
            identity,
            "llvm missing from identity"
        );
        let mut csdk = pins;
        csdk.csdk = changed_text(pins.csdk);
        assert_ne!(
            input_identity("linux-aarch64", &csdk),
            identity,
            "csdk missing from identity"
        );
        let mut target = pins;
        target.target = changed_text(pins.target);
        assert_ne!(
            input_identity("linux-aarch64", &target),
            identity,
            "target missing from identity"
        );
        let mut libraries = pins;
        libraries.target_libraries = changed_text(pins.target_libraries);
        assert_ne!(
            input_identity("linux-aarch64", &libraries),
            identity,
            "target libraries missing from identity"
        );
        assert_ne!(input_identity("linux-x86_64", &pins), identity);
    }

    fn changed_text(text: &'static str) -> &'static str {
        Box::leak(format!("{text} ").into_boxed_str())
    }

    #[test]
    fn pinned_target_spec_member_accepts_exact_bytes_and_rejects_corruption() {
        let pins = Pins::for_host("linux-aarch64").unwrap();
        let temp = TempDirectory::new();
        let target_spec = include_bytes!("../tests/fixtures/x86_64-aros.json");
        let path = temp.0.join(TARGET_SPEC_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, target_spec).unwrap();
        verify_file(
            &temp.0,
            TARGET_SPEC_PATH,
            None,
            &pins.target_spec_sha256,
            "AROS target specification",
        )
        .unwrap();

        let mut corrupted = target_spec.to_vec();
        corrupted[0] ^= 1;
        fs::write(&path, corrupted).unwrap();
        assert!(
            verify_file(
                &temp.0,
                TARGET_SPEC_PATH,
                None,
                &pins.target_spec_sha256,
                "AROS target specification"
            )
            .is_err()
        );
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aros-native-build-inputs-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn file_pin(path: &str, bytes: &[u8]) -> FilePin {
        let digest = Sha256::digest(bytes);
        let mut sha256 = String::with_capacity(64);
        for byte in digest.iter() {
            use std::fmt::Write as _;
            write!(&mut sha256, "{:02x}", *byte).expect("format digest");
        }
        FilePin {
            path: path.to_owned(),
            bytes: bytes.len() as u64,
            sha256,
        }
    }

    fn inventory(files: Vec<FilePin>, symlinks: Vec<SymlinkPin>) -> Inventory {
        Inventory { files, symlinks }
    }

    #[test]
    fn rejects_traversal_and_non_normalized_inventory_paths() {
        for bad in ["", "/etc/passwd", "../escape", "a/../b", "a//b", "a/./b"] {
            assert!(parse_relative_path(bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(
            parse_relative_path("lib/rustlib/file").unwrap(),
            PathBuf::from("lib/rustlib/file")
        );
    }

    #[test]
    fn rust_alias_inventory_survives_relocation_and_rejects_bad_links() {
        use std::os::unix::fs::symlink;

        let temp = TempDirectory::new();
        let original_root = temp.0.join("prefix");
        let target = b"pinned AROS target spec";
        let linker = b"pinned aros-link";
        let hosts = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"];
        fs::create_dir_all(original_root.join("lib/rustlib/x86_64-aros")).unwrap();
        fs::create_dir_all(original_root.join("bin")).unwrap();
        fs::write(
            original_root.join("lib/rustlib/x86_64-aros/x86_64-aros.json"),
            target,
        )
        .unwrap();
        fs::write(original_root.join("bin/aros-link"), linker).unwrap();

        let mut aliases = vec![SymlinkPin {
            path: "lib/rustlib/x86_64-aros/target.json".to_owned(),
            target: "x86_64-aros.json".to_owned(),
        }];
        for host in hosts {
            let path = format!("lib/rustlib/{host}/bin/aros-link");
            fs::create_dir_all(original_root.join(format!("lib/rustlib/{host}/bin"))).unwrap();
            symlink("../../../../bin/aros-link", original_root.join(&path)).unwrap();
            aliases.push(SymlinkPin {
                path,
                target: "../../../../bin/aros-link".to_owned(),
            });
        }
        symlink(
            "x86_64-aros.json",
            original_root.join("lib/rustlib/x86_64-aros/target.json"),
        )
        .unwrap();
        let expected = inventory(
            vec![
                file_pin("lib/rustlib/x86_64-aros/x86_64-aros.json", target),
                file_pin("bin/aros-link", linker),
            ],
            aliases,
        );
        verify_inventory_members(&original_root, &expected, "Rust sysroot", None).unwrap();

        let root = temp.0.join("relocated prefix with spaces");
        fs::rename(&original_root, &root).unwrap();
        verify_inventory_members(&root, &expected, "Rust sysroot", None).unwrap();

        let target_alias = root.join("lib/rustlib/x86_64-aros/target.json");
        fs::remove_file(&target_alias).unwrap();
        assert!(verify_inventory_members(&root, &expected, "Rust sysroot", None).is_err());
        symlink("wrong.json", &target_alias).unwrap();
        assert!(verify_inventory_members(&root, &expected, "Rust sysroot", None).is_err());
        fs::remove_file(&target_alias).unwrap();
        let outside_target = temp.0.join("outside-target.json");
        fs::write(&outside_target, target).unwrap();
        symlink("../../../../outside-target.json", &target_alias).unwrap();
        let canonical_root = fs::canonicalize(&root).unwrap();
        assert!(
            !fs::canonicalize(&target_alias)
                .unwrap()
                .starts_with(&canonical_root)
        );
        assert!(verify_inventory_members(&root, &expected, "Rust sysroot", None).is_err());
    }

    #[test]
    fn exact_tree_detects_content_changes_and_unexpected_files() {
        let temp = TempDirectory::new();
        fs::write(temp.0.join("known"), b"pinned").unwrap();
        let expected = inventory(vec![file_pin("known", b"pinned")], vec![]);
        verify_exact_tree(&temp.0, &expected, "fixture").unwrap();

        fs::write(temp.0.join("known"), b"changed").unwrap();
        assert!(verify_exact_tree(&temp.0, &expected, "fixture").is_err());

        fs::write(temp.0.join("known"), b"pinned").unwrap();
        fs::write(temp.0.join("unexpected"), b"extra").unwrap();
        assert!(verify_exact_tree(&temp.0, &expected, "fixture").is_err());
    }

    #[test]
    fn exact_tree_rejects_a_symlink_in_place_of_a_pinned_file() {
        use std::os::unix::fs::symlink;

        let temp = TempDirectory::new();
        fs::write(temp.0.join("contents"), b"pinned").unwrap();
        symlink("contents", temp.0.join("known")).unwrap();
        let expected = inventory(vec![file_pin("known", b"pinned")], vec![]);
        assert!(verify_exact_tree(&temp.0, &expected, "fixture").is_err());
    }

    #[test]
    fn validates_inventory_paths_before_tree_checks() {
        let bad = inventory(
            vec![FilePin {
                path: "../escape".to_owned(),
                bytes: 0,
                sha256: "0".repeat(64),
            }],
            vec![],
        );
        assert!(expected_entries(&bad, "fixture").is_err());
    }

    #[test]
    fn rejects_symlink_targets_that_escape_the_component_root() {
        let bad = inventory(
            vec![],
            vec![SymlinkPin {
                path: "bin/tool".to_owned(),
                target: "../../outside".to_owned(),
            }],
        );
        assert!(expected_entries(&bad, "fixture").is_err());
    }
}

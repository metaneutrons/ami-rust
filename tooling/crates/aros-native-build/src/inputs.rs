//! Verification of the fixed, locally composed native-build toolchain prefix.
//!
//! The embedded inventories describe expected regular-file bytes and relative
//! link edges. Link paths must be materialized as regular copies under the
//! shared portable view. This is a local consistency check, not publisher
//! authentication or an execution sandbox.

use crate::portable_view::{
    PORTABLE_VIEW_JSON, PortableFile, PortableInventory, PortableLink, derive_portable_inventory,
    normalize_portable_mode,
};
use crate::public_view::{PUBLIC_VIEW_JSON, PublicViewPolicy};
use crate::recipe::ArosAbi;
use crate::{Refusal, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const ABI1_TARGET: &str = "x86_64-unknown-aros-abi1";
const ABI11_TARGET: &str = "x86_64-unknown-aros-abi11";
const RUST_CARGO_PATH: &str = "bin/cargo";
const SOURCE_LINKER_PATH: &str = "bin/aros-link";
const SOURCE_LINKER_LIMIT: u64 = 128 * 1024 * 1024;
const LLVM_ROOT: &str = "libexec/aros/llvm";
const CSDK_ROOT: &str = "lib/aros/c-sdk";
const ABI11_CSDK_ROOT: &str = "lib/aros/c-sdk-abi11";
const ROOT_LLVM_ALIASES: [&str; 5] = ["llvm-objdump", "llvm-nm", "llvm-ar", "llvm-strip", "ld.lld"];
const COMPOSED_CARGO_PATH: &str = "bin/cargo";
const COLLECTOR_INVENTORY_PATH: &str = "bin/aros-collect";
const COMPOSED_COLLECTOR_PATH: &str = crate::portable_view::COLLECTOR_DESTINATION_PATH;
const LEGACY_TARGET_ALIAS_PATH: &str = "lib/rustlib/x86_64-aros/target.json";
const ABI1_TARGET_SPEC_PATH: &str =
    "lib/rustlib/x86_64-unknown-aros-abi1/x86_64-unknown-aros-abi1.json";
const ABI11_TARGET_SPEC_PATH: &str =
    "lib/rustlib/x86_64-unknown-aros-abi11/x86_64-unknown-aros-abi11.json";
const ABI1_TARGET_ALIAS_PATH: &str = "lib/rustlib/x86_64-unknown-aros-abi1/target.json";
const ABI11_TARGET_ALIAS_PATH: &str = "lib/rustlib/x86_64-unknown-aros-abi11/target.json";
const ABI1_TARGET_LIBRARY_ROOT: &str = "lib/rustlib/x86_64-unknown-aros-abi1/lib";
const ABI11_TARGET_LIBRARY_ROOT: &str = "lib/rustlib/x86_64-unknown-aros-abi11/lib";

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
    collector: PathBuf,
    linker_identity: PortableFile,
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
        let linker_identity = verify_prefix(&root, &pins, None)?;

        Ok(Self {
            rustc: root.join("bin/rustc"),
            cargo: root.join(COMPOSED_CARGO_PATH),
            toolchain_root: root.join("libexec/aros/llvm"),
            collector: root.join(COMPOSED_COLLECTOR_PATH),
            linker_identity,
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
        verify_prefix(
            &self.root,
            &Pins::for_host(self.host)?,
            Some(&self.linker_identity),
        )
        .map(|_| ())
    }

    /// Check that the running linker is one of this prefix's two exact copies.
    pub(crate) fn verify_link_executable(&self, executable: &Path) -> Result<()> {
        let host_alias = host_linker_alias(self.host)?;
        let candidate = if executable == self.root.join(SOURCE_LINKER_PATH) {
            SOURCE_LINKER_PATH.to_owned()
        } else if executable == self.root.join(&host_alias) {
            host_alias
        } else {
            return Err(Refusal::new(
                "native object record belongs to a different selected linker prefix; rebuild its Cargo build script",
            ));
        };
        let observed = read_executable_identity(&self.root, &candidate)?;
        if !same_file_identity(&observed, &self.linker_identity) {
            return Err(Refusal::new(
                "target linker executable does not match the selected root executable copy",
            ));
        }
        Ok(())
    }

    /// Check Cargo's linker selection against only this prefix's root linker
    /// or exact host-specific regular copy. A bare `aros-link` selects the
    /// host slot rustc uses for bundled tools.
    pub(crate) fn verify_selected_linker(&self, linker: &Path) -> Result<()> {
        let host_alias = host_linker_alias(self.host)?;
        let candidate = if linker == Path::new("aros-link") {
            host_alias
        } else if linker == self.root.join(SOURCE_LINKER_PATH) {
            SOURCE_LINKER_PATH.to_owned()
        } else if linker == self.root.join(&host_alias) {
            host_alias
        } else {
            return Err(Refusal::new("Cargo selected a different target linker"));
        };
        self.verify_link_executable(&self.root.join(candidate))
    }

    /// Return the source-built root linker's stable local identity.
    pub(crate) fn source_linker_identity(&self) -> &PortableFile {
        &self.linker_identity
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

    /// Return the exact C SDK root selected for one admitted AROS ABI.
    pub fn sdk_root(&self, abi: ArosAbi) -> PathBuf {
        self.root.join(match abi {
            ArosAbi::Abi1 => CSDK_ROOT,
            ArosAbi::Abi11 => ABI11_CSDK_ROOT,
        })
    }

    /// Return the pinned AROS collector path.
    pub fn collector(&self) -> &Path {
        &self.collector
    }

    /// Return the pinned target specification path selected for one AROS ABI.
    pub fn target_spec(&self, abi: ArosAbi) -> PathBuf {
        self.root.join(match abi {
            ArosAbi::Abi1 => ABI1_TARGET_SPEC_PATH,
            ArosAbi::Abi11 => ABI11_TARGET_SPEC_PATH,
        })
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
    abi11_csdk: &'static str,
    abi1_target: &'static str,
    abi11_target: &'static str,
    abi1_target_libraries: &'static str,
    abi11_target_libraries: &'static str,
}

struct TargetInputs {
    name: String,
    libraries: Inventory,
    spec_sha256: String,
}

struct Pins {
    rust: Inventory,
    cargo: Inventory,
    collector: Inventory,
    llvm: Inventory,
    csdk: Inventory,
    abi11_csdk: Inventory,
    targets: [TargetInputs; 2],
    source_date_epoch: u64,
    identity: String,
    public_view: PublicViewPolicy,
}

impl Pins {
    fn for_host(host: &'static str) -> Result<Self> {
        let embedded = embedded_pins_for_host(host)?;
        let public_view = PublicViewPolicy::embedded()?;
        let rust = public_inventory(
            parse_inventory("Rust sysroot", embedded.rust)?,
            "rust",
            &public_view,
        )?;
        let cargo = parse_inventory("Cargo", embedded.cargo)?;
        let collector = parse_inventory("collector", embedded.collector)?;
        let llvm = public_inventory(
            parse_inventory("LLVM toolchain", embedded.llvm)?,
            "llvm",
            &public_view,
        )?;
        let csdk = parse_inventory("C SDK", embedded.csdk)?;
        let abi11_csdk = parse_inventory("ABI11 C SDK", embedded.abi11_csdk)?;
        let (abi1, abi1_epoch) = parse_target_inputs(
            ABI1_TARGET,
            embedded.abi1_target,
            embedded.abi1_target_libraries,
        )?;
        let (abi11, abi11_epoch) = parse_target_inputs(
            ABI11_TARGET,
            embedded.abi11_target,
            embedded.abi11_target_libraries,
        )?;
        if abi1_epoch != abi11_epoch {
            return Err(Refusal::new(
                "embedded ABI target pins use different source-date epochs",
            ));
        }

        let identity = input_identity(host, &embedded);
        Ok(Self {
            rust,
            cargo,
            collector,
            llvm,
            csdk,
            abi11_csdk,
            targets: [abi1, abi11],
            source_date_epoch: abi1_epoch,
            identity,
            public_view,
        })
    }
}

fn parse_target_inputs(
    expected_target: &str,
    target_raw: &str,
    libraries_raw: &str,
) -> Result<(TargetInputs, u64)> {
    let target: TargetPin = parse_pin("target", target_raw)?;
    let libraries: TargetLibrariesPin = parse_pin("target libraries", libraries_raw)?;
    if target.schema != "aros-native-build-target-v1" || target.target != expected_target {
        return Err(Refusal::new(
            "embedded native-build target pin has an unsupported schema or target",
        ));
    }
    if target.status != "RELEASE_CANDIDATE_NOT_PUBLISHED" {
        return Err(Refusal::new(
            "embedded native-build target pin has an unexpected qualification status",
        ));
    }
    validate_sha256(&target.spec_sha256, "target specification pin")?;
    if libraries.schema != "aros-target-library-candidate-v1" || libraries.target != expected_target
    {
        return Err(Refusal::new(
            "embedded target-library pin has an unsupported schema or target",
        ));
    }
    Ok((
        TargetInputs {
            name: target.target,
            libraries: Inventory {
                files: libraries.files,
                symlinks: libraries.symlinks,
            },
            spec_sha256: target.spec_sha256,
        },
        target.source_date_epoch,
    ))
}

fn embedded_pins_for_host(host: &str) -> Result<EmbeddedPins> {
    match host {
        "macos-aarch64" => Ok(EmbeddedPins {
            rust: include_str!("../pins/macos-aarch64/rust-runtime-v2.json"),
            cargo: include_str!("../pins/macos-aarch64/cargo.json"),
            collector: include_str!("../pins/macos-aarch64/collector.json"),
            llvm: include_str!("../pins/macos-aarch64/toolchain.json"),
            csdk: include_str!("../pins/macos-aarch64/csdk.json"),
            abi11_csdk: include_str!("../../../../release/abi11-csdk/profile.json"),
            abi1_target: include_str!("../pins/x86_64-unknown-aros-abi1.json"),
            abi11_target: include_str!("../pins/x86_64-unknown-aros-abi11.json"),
            abi1_target_libraries: include_str!("../pins/x86_64-unknown-aros-abi1-libraries.json"),
            abi11_target_libraries: include_str!(
                "../pins/x86_64-unknown-aros-abi11-libraries.json"
            ),
        }),
        "linux-x86_64" => Ok(EmbeddedPins {
            rust: include_str!("../pins/linux-x86_64/rust.json"),
            cargo: include_str!("../pins/linux-x86_64/cargo.json"),
            collector: include_str!("../pins/linux-x86_64/collector.json"),
            llvm: include_str!("../pins/linux-x86_64/toolchain.json"),
            csdk: include_str!("../pins/linux-x86_64/csdk.json"),
            abi11_csdk: include_str!("../../../../release/abi11-csdk/profile.json"),
            abi1_target: include_str!("../pins/x86_64-unknown-aros-abi1.json"),
            abi11_target: include_str!("../pins/x86_64-unknown-aros-abi11.json"),
            abi1_target_libraries: include_str!(
                "../pins/linux-x86_64/x86_64-unknown-aros-abi1-libraries.json"
            ),
            abi11_target_libraries: include_str!(
                "../pins/linux-x86_64/x86_64-unknown-aros-abi11-libraries.json"
            ),
        }),
        "linux-aarch64" => Ok(EmbeddedPins {
            rust: include_str!("../pins/linux-aarch64/rust.json"),
            cargo: include_str!("../pins/linux-aarch64/cargo.json"),
            collector: include_str!("../pins/linux-aarch64/collector.json"),
            llvm: include_str!("../pins/linux-aarch64/toolchain.json"),
            csdk: include_str!("../pins/linux-aarch64/csdk.json"),
            abi11_csdk: include_str!("../../../../release/abi11-csdk/profile.json"),
            abi1_target: include_str!("../pins/x86_64-unknown-aros-abi1.json"),
            abi11_target: include_str!("../pins/x86_64-unknown-aros-abi11.json"),
            abi1_target_libraries: include_str!(
                "../pins/linux-aarch64/x86_64-unknown-aros-abi1-libraries.json"
            ),
            abi11_target_libraries: include_str!(
                "../pins/linux-aarch64/x86_64-unknown-aros-abi11-libraries.json"
            ),
        }),
        _ => Err(Refusal::new(
            "no native-build input pins are embedded for this host",
        )),
    }
}

fn parse_inventory(name: &str, json: &str) -> Result<Inventory> {
    parse_pin(name, json)
}

fn public_inventory(
    mut parent: Inventory,
    component: &str,
    policy: &PublicViewPolicy,
) -> Result<Inventory> {
    // Validate the complete parent before deriving a different expected tree.
    // Original embedded profile bytes remain part of the input identity.
    expected_entries(&parent, component)?;
    for exclusion in policy
        .exclusions()
        .iter()
        .filter(|row| row.component == component)
    {
        let row = unique_file_pin(&parent, &exclusion.path, component)?;
        policy.lookup(component, &row.path, row.bytes, &row.sha256)?;
    }
    parent.files.retain(|row| {
        !policy
            .exclusions()
            .iter()
            .any(|excluded| excluded.component == component && excluded.path == row.path)
    });
    Ok(parent)
}

fn parse_pin<T: for<'de> Deserialize<'de>>(name: &str, json: &str) -> Result<T> {
    serde_json::from_str(json)
        .map_err(|error| Refusal::new(format!("embedded {name} pin is invalid: {error}")))
}

fn input_identity(host: &str, pins: &EmbeddedPins) -> String {
    input_identity_with_views(host, pins, PUBLIC_VIEW_JSON, PORTABLE_VIEW_JSON)
}

fn input_identity_with_views(
    host: &str,
    pins: &EmbeddedPins,
    public_view: &str,
    portable_view: &str,
) -> String {
    let inputs = [
        ("rust", pins.rust),
        ("cargo", pins.cargo),
        ("collector", pins.collector),
        ("llvm", pins.llvm),
        ("csdk", pins.csdk),
        ("abi11-csdk", pins.abi11_csdk),
        ("abi1-target", pins.abi1_target),
        ("abi11-target", pins.abi11_target),
        ("abi1-target-libraries", pins.abi1_target_libraries),
        ("abi11-target-libraries", pins.abi11_target_libraries),
        ("public-view", public_view),
        ("portable-view", portable_view),
    ];
    let mut digest = Sha256::new();
    digest.update(b"aros-native-build-input-identity-v4\0");
    for (label, bytes) in inputs {
        digest.update((label.len() as u64).to_be_bytes());
        digest.update(label.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes.as_bytes());
    }
    let final_digest = digest.finalize();
    format!(
        "{host}:{ABI1_TARGET}+{ABI11_TARGET}:sha256:{}",
        hex_digest(&final_digest)
    )
}

fn verify_prefix(
    root: &Path,
    pins: &Pins,
    expected_linker: Option<&PortableFile>,
) -> Result<PortableFile> {
    ensure_real_directory(root, "native toolchain root")?;
    refuse_reintroduced_public_helper(root, crate::portable_view::COLLECTOR_SOURCE_PATH)?;

    for (relative, _) in crate::portable_view::OMITTED_ROOT_TOOL_ALIASES {
        refuse_reintroduced_public_helper(root, relative)?;
    }
    for excluded in pins.public_view.exclusions() {
        let path = match excluded.component.as_str() {
            "rust" => excluded.path.clone(),
            "llvm" => format!("{LLVM_ROOT}/{}", excluded.path),
            _ => return Err(Refusal::new("unsupported public-view component")),
        };
        refuse_reintroduced_public_helper(root, &path)?;
    }

    let linker_identity = read_executable_identity(root, SOURCE_LINKER_PATH)?;
    if expected_linker.is_some_and(|expected| !same_file_identity(expected, &linker_identity)) {
        return Err(Refusal::new(
            "root aros-link executable changed after the native toolchain was opened",
        ));
    }

    let portable = compose_portable_inventory(pins, &linker_identity)?;
    const EXACT_TREES: [(&str, &str); 5] = [
        (LLVM_ROOT, "LLVM toolchain"),
        (CSDK_ROOT, "ABI1 C SDK"),
        (ABI11_CSDK_ROOT, "ABI11 C SDK"),
        (ABI1_TARGET_LIBRARY_ROOT, "ABI1 target libraries"),
        (ABI11_TARGET_LIBRARY_ROOT, "ABI11 target libraries"),
    ];
    verify_inventory_members(
        root,
        &portable,
        "native build input",
        &EXACT_TREES.map(|(prefix, _)| prefix),
    )?;

    for (prefix, label) in EXACT_TREES {
        let component_root = ensure_directory_chain(root, prefix, label)?;
        let inventory = inventory_under_prefix(&portable, prefix, label)?;
        verify_exact_tree(&component_root, &inventory, label)?;
    }
    verify_materialized_link_modes(root, &portable)?;

    Ok(linker_identity)
}

fn compose_portable_inventory(
    pins: &Pins,
    linker_identity: &PortableFile,
) -> Result<PortableInventory> {
    // Validate component-relative paths and link targets before placing their
    // rows into the composed root namespace.
    expected_entries(&pins.rust, "Rust sysroot")?;
    unique_file_pin(&pins.rust, RUST_CARGO_PATH, "Rust sysroot")?;
    expected_entries(&pins.cargo, "Cargo")?;
    expected_entries(&pins.collector, "collector")?;
    expected_entries(&pins.llvm, "LLVM toolchain")?;
    expected_entries(&pins.csdk, "ABI1 C SDK")?;
    expected_entries(&pins.abi11_csdk, "ABI11 C SDK")?;
    for target in &pins.targets {
        expected_entries(&target.libraries, "AROS target libraries")?;
    }

    let mut files = Vec::new();
    let mut links = Vec::new();

    for file in &pins.rust.files {
        if file.path != RUST_CARGO_PATH {
            files.push(portable_file(file, file.path.clone()));
        }
    }
    append_links(
        &mut links,
        &pins
            .rust
            .symlinks
            .iter()
            .filter(|link| link.path != LEGACY_TARGET_ALIAS_PATH)
            .cloned()
            .collect::<Vec<_>>(),
        "",
    );

    let cargo = unique_file_pin(&pins.cargo, COMPOSED_CARGO_PATH, "Cargo")?;
    files.push(portable_file(cargo, COMPOSED_CARGO_PATH.to_owned()));

    let collector = unique_file_pin(&pins.collector, COLLECTOR_INVENTORY_PATH, "collector")?;
    files.push(portable_file(
        collector,
        crate::portable_view::COLLECTOR_SOURCE_PATH.to_owned(),
    ));

    append_files(&mut files, &pins.llvm.files, LLVM_ROOT);
    append_links(&mut links, &pins.llvm.symlinks, LLVM_ROOT);
    append_files(&mut files, &pins.csdk.files, CSDK_ROOT);
    append_links(&mut links, &pins.csdk.symlinks, CSDK_ROOT);
    append_files(&mut files, &pins.abi11_csdk.files, ABI11_CSDK_ROOT);
    append_links(&mut links, &pins.abi11_csdk.symlinks, ABI11_CSDK_ROOT);
    for (target, prefix) in pins
        .targets
        .iter()
        .zip([ABI1_TARGET_LIBRARY_ROOT, ABI11_TARGET_LIBRARY_ROOT])
    {
        append_files(&mut files, &target.libraries.files, prefix);
        append_links(&mut links, &target.libraries.symlinks, prefix);
    }

    files.extend(target_spec_identities(pins)?);
    links.extend([
        PortableLink {
            path: ABI1_TARGET_ALIAS_PATH.to_owned(),
            target: format!("{ABI1_TARGET}.json"),
        },
        PortableLink {
            path: ABI11_TARGET_ALIAS_PATH.to_owned(),
            target: format!("{ABI11_TARGET}.json"),
        },
    ]);
    files.push(linker_identity.clone());
    for name in ROOT_LLVM_ALIASES {
        links.push(PortableLink {
            path: format!("bin/{name}"),
            target: format!("../{LLVM_ROOT}/bin/{name}"),
        });
    }

    derive_portable_inventory(&files, &links)
}

fn portable_file(pin: &FilePin, path: String) -> PortableFile {
    PortableFile {
        path,
        bytes: pin.bytes,
        sha256: pin.sha256.clone(),
        mode: None,
    }
}

fn append_files(output: &mut Vec<PortableFile>, files: &[FilePin], prefix: &str) {
    for file in files {
        output.push(portable_file(file, format!("{prefix}/{}", file.path)));
    }
}

fn append_links(output: &mut Vec<PortableLink>, links: &[SymlinkPin], prefix: &str) {
    for link in links {
        let path = if prefix.is_empty() {
            link.path.clone()
        } else {
            format!("{prefix}/{}", link.path)
        };
        output.push(PortableLink {
            path,
            target: link.target.clone(),
        });
    }
}

fn target_spec_identities(pins: &Pins) -> Result<Vec<PortableFile>> {
    let definitions: [(&str, &str, &[u8]); 2] = [
        (
            ABI1_TARGET,
            ABI1_TARGET_SPEC_PATH,
            include_bytes!("../../../../targets/x86_64-unknown-aros-abi1.json"),
        ),
        (
            ABI11_TARGET,
            ABI11_TARGET_SPEC_PATH,
            include_bytes!("../../../../targets/x86_64-unknown-aros-abi11.json"),
        ),
    ];
    definitions
        .into_iter()
        .zip(&pins.targets)
        .map(|((name, path, bytes), pin)| {
            let actual_sha256 = hex_digest(&Sha256::digest(bytes));
            if pin.name != name || actual_sha256 != pin.spec_sha256 {
                return Err(Refusal::new(
                    "embedded target specification does not match its fixed target pin",
                ));
            }
            Ok(PortableFile {
                path: path.to_owned(),
                bytes: bytes.len() as u64,
                sha256: pin.spec_sha256.clone(),
                mode: None,
            })
        })
        .collect()
}

fn inventory_under_prefix(
    portable: &PortableInventory,
    prefix: &str,
    label: &str,
) -> Result<Inventory> {
    let prefix = format!("{prefix}/");
    let files = portable
        .files
        .iter()
        .filter_map(|file| {
            file.path.strip_prefix(&prefix).map(|path| FilePin {
                path: path.to_owned(),
                bytes: file.bytes,
                sha256: file.sha256.clone(),
            })
        })
        .collect::<Vec<_>>();
    if files.is_empty() {
        return Err(Refusal::new(format!("derived {label} inventory is empty")));
    }
    Ok(Inventory {
        files,
        symlinks: Vec::new(),
    })
}

fn host_rust_triple(host: &str) -> Result<&'static str> {
    match host {
        "macos-aarch64" => Ok("aarch64-apple-darwin"),
        "linux-x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "linux-aarch64" => Ok("aarch64-unknown-linux-gnu"),
        _ => Err(Refusal::new(
            "no Rust host triple is pinned for this native host",
        )),
    }
}

fn host_linker_alias(host: &str) -> Result<String> {
    Ok(format!(
        "lib/rustlib/{}/bin/aros-link",
        host_rust_triple(host)?
    ))
}

fn same_file_identity(left: &PortableFile, right: &PortableFile) -> bool {
    left.bytes == right.bytes && left.sha256 == right.sha256 && left.mode == right.mode
}

fn refuse_reintroduced_public_helper(root: &Path, relative: &str) -> Result<()> {
    let relative = parse_relative_path(relative)?;
    let mut path = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not check public-view omission: {error}"
                )));
            }
            Ok(metadata) => {
                if components.peek().is_none() {
                    return Err(Refusal::new(format!(
                        "excluded public-view helper is present: {}",
                        path.display()
                    )));
                }
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(Refusal::new(
                        "public-view omission parent is not a real directory",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Verify regular-view rows outside the three separately exact subtrees.
/// Rust root membership deliberately permits unrelated rustup administration
/// files to coexist with the pinned SDK rows.
fn verify_inventory_members(
    root: &Path,
    inventory: &PortableInventory,
    label: &str,
    exact_prefixes: &[&str],
) -> Result<()> {
    for file in &inventory.files {
        if exact_prefixes
            .iter()
            .any(|prefix| file.path.starts_with(&format!("{prefix}/")))
        {
            continue;
        }
        verify_portable_file(root, file, label)?;
    }
    Ok(())
}

fn verify_portable_file(root: &Path, file: &PortableFile, label: &str) -> Result<()> {
    verify_file_with_mode(
        root,
        &file.path,
        Some(file.bytes),
        &file.sha256,
        label,
        file.mode,
    )
}

fn verify_materialized_link_modes(root: &Path, inventory: &PortableInventory) -> Result<()> {
    for materialized in &inventory.materialized_links {
        let source_mode = regular_portable_mode(root, &materialized.resolved_file.path)?;
        let copy_mode = regular_portable_mode(root, &materialized.original.path)?;
        if source_mode != copy_mode {
            return Err(Refusal::new(format!(
                "portable copy mode differs from its resolved regular source: {}",
                materialized.original.path
            )));
        }
    }
    Ok(())
}

fn regular_portable_mode(root: &Path, relative: &str) -> Result<u32> {
    let relative_path = parse_relative_path(relative)?;
    ensure_parent_directories(root, &relative_path, "portable regular-file copy")?;
    let path = root.join(relative_path);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        Refusal::new(format!(
            "could not inspect portable regular-file copy {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Refusal::new(format!(
            "portable view entry is not a regular file: {}",
            path.display()
        )));
    }
    let mode = metadata.mode() & 0o7777;
    if normalize_portable_mode(mode) != mode {
        return Err(Refusal::new(format!(
            "portable copy mode is not normalized: {}",
            path.display()
        )));
    }
    Ok(mode)
}

fn verify_exact_tree(root: &Path, inventory: &Inventory, label: &str) -> Result<()> {
    ensure_real_directory(root, label)?;
    let expected = expected_entries(inventory, label)?;
    if expected
        .values()
        .any(|entry| matches!(entry, ExpectedEntry::Symlink))
    {
        return Err(Refusal::new(format!(
            "{label} portable inventory contains a symbolic link"
        )));
    }
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
            return Err(Refusal::new(format!(
                "{label} contains a symbolic link in the regular-file view: {relative}"
            )));
        } else if metadata.is_file() {
            let Some(ExpectedEntry::File(file)) = expected.get(&relative) else {
                return Err(Refusal::new(format!(
                    "{label} has an unexpected file: {relative}"
                )));
            };
            verify_file_with_mode(
                tree_root,
                &relative,
                Some(file.bytes),
                &file.sha256,
                label,
                None,
            )?;
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
    Symlink,
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
            .insert(link.path.clone(), ExpectedEntry::Symlink)
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

fn verify_file_with_mode(
    root: &Path,
    relative: &str,
    expected_bytes: Option<u64>,
    expected_sha256: &str,
    label: &str,
    expected_mode: Option<u32>,
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
    let path_mode = path_metadata.mode() & 0o7777;
    if normalize_portable_mode(path_mode) != path_mode {
        return Err(Refusal::new(format!(
            "{label} input mode is not normalized by the portable-view policy: {}",
            path.display()
        )));
    }
    if expected_mode.is_some_and(|expected| path_mode != expected) {
        return Err(Refusal::new(format!(
            "{label} input has the wrong portable mode: {}",
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
    if before.dev() != path_metadata.dev()
        || before.ino() != path_metadata.ino()
        || before.mode() & 0o7777 != path_mode
    {
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
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.mode() == after.mode()
        && count == after.len()
        && final_path_metadata.is_file()
        && !final_path_metadata.file_type().is_symlink()
        && final_path_metadata.dev() == after.dev()
        && final_path_metadata.ino() == after.ino()
        && final_path_metadata.len() == after.len()
        && final_path_metadata.modified().ok() == after.modified().ok()
        && final_path_metadata.ctime() == after.ctime()
        && final_path_metadata.ctime_nsec() == after.ctime_nsec()
        && final_path_metadata.mode() == after.mode();
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
            "{label} input does not match its expected SHA-256 identity: {}",
            path.display()
        )));
    }
    Ok(())
}

// The source-built linker has no embedded publisher pin; this records its local,
// no-follow identity for comparison with the copied host alias and object record.
fn read_executable_identity(root: &Path, relative: &str) -> Result<PortableFile> {
    read_executable_identity_checked(root, relative, || Ok(()))
}

// Keep directory descriptors alive and require unchanged path/descriptor state
// before and after the leaf read. This refuses concurrent parent replacement;
// it is a local consistency check, not a filesystem execution sandbox.
struct IdentityParent {
    path: PathBuf,
    file: fs::File,
    before: fs::Metadata,
}

fn same_parent_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_dir()
        && right.is_dir()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn capture_identity_parents(root: &Path, relative: &Path) -> Result<Vec<IdentityParent>> {
    let mut paths = vec![root.to_path_buf()];
    let mut path = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            path.push(component);
            paths.push(path.clone());
        }
    }
    let mut parents = Vec::with_capacity(paths.len());
    for path in paths {
        let named = fs::symlink_metadata(&path)?;
        if !named.is_dir() || named.file_type().is_symlink() {
            return Err(Refusal::new(
                "linker identity parent is not a real directory",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let before = file.metadata()?;
        if !same_parent_state(&named, &before) {
            return Err(Refusal::new(
                "linker identity parent changed while being opened",
            ));
        }
        parents.push(IdentityParent { path, file, before });
    }
    recheck_identity_parents(&parents)?;
    Ok(parents)
}

fn recheck_identity_parents(parents: &[IdentityParent]) -> Result<()> {
    for parent in parents {
        let named = fs::symlink_metadata(&parent.path)?;
        if named.file_type().is_symlink()
            || !same_parent_state(&parent.before, &parent.file.metadata()?)
            || !same_parent_state(&parent.before, &named)
        {
            return Err(Refusal::new(
                "linker identity parent changed during capture",
            ));
        }
    }
    Ok(())
}

fn read_executable_identity_checked(
    root: &Path,
    relative: &str,
    after_parent_capture: impl FnOnce() -> Result<()>,
) -> Result<PortableFile> {
    let relative_path = parse_relative_path(relative)?;
    ensure_parent_directories(root, &relative_path, "root aros-link executable")?;
    let parents = capture_identity_parents(root, &relative_path)?;
    after_parent_capture()?;
    recheck_identity_parents(&parents)?;
    let path = root.join(&relative_path);
    let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
        Refusal::new(format!(
            "could not inspect root aros-link executable {}: {error}",
            path.display()
        ))
    })?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(Refusal::new(format!(
            "root aros-link is not a regular file: {}",
            path.display()
        )));
    }
    if path_metadata.len() == 0 || path_metadata.len() > SOURCE_LINKER_LIMIT {
        return Err(Refusal::new(
            "root aros-link must be nonempty and within the 128 MiB identity limit",
        ));
    }
    let source_mode = path_metadata.mode() & 0o7777;
    if source_mode & 0o111 == 0 {
        return Err(Refusal::new("root aros-link is not executable"));
    }
    if normalize_portable_mode(source_mode) != source_mode {
        return Err(Refusal::new(
            "root aros-link permissions do not match the portable-view policy",
        ));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| {
            Refusal::new(format!(
                "could not open root aros-link without following symlinks {}: {error}",
                path.display()
            ))
        })?;
    let before = file.metadata().map_err(|error| {
        Refusal::new(format!(
            "could not inspect opened root aros-link {}: {error}",
            path.display()
        ))
    })?;
    if !before.is_file()
        || before.dev() != path_metadata.dev()
        || before.ino() != path_metadata.ino()
        || before.len() != path_metadata.len()
        || before.modified().ok() != path_metadata.modified().ok()
        || before.ctime() != path_metadata.ctime()
        || before.ctime_nsec() != path_metadata.ctime_nsec()
        || before.mode() != path_metadata.mode()
    {
        return Err(Refusal::new(
            "root aros-link changed while it was being opened",
        ));
    }

    let mut digest = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            Refusal::new(format!(
                "could not read root aros-link executable {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| Refusal::new("root aros-link size overflow"))?;
        if count > SOURCE_LINKER_LIMIT {
            return Err(Refusal::new(
                "root aros-link exceeds the 128 MiB identity limit",
            ));
        }
        digest.update(&buffer[..read]);
    }

    let after = file.metadata().map_err(|error| {
        Refusal::new(format!(
            "could not recheck root aros-link executable {}: {error}",
            path.display()
        ))
    })?;
    let final_path_metadata = fs::symlink_metadata(&path).map_err(|error| {
        Refusal::new(format!(
            "could not recheck root aros-link path {}: {error}",
            path.display()
        ))
    })?;
    let stable = before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.mode() == after.mode()
        && count == after.len()
        && final_path_metadata.is_file()
        && !final_path_metadata.file_type().is_symlink()
        && final_path_metadata.dev() == after.dev()
        && final_path_metadata.ino() == after.ino()
        && final_path_metadata.len() == after.len()
        && final_path_metadata.modified().ok() == after.modified().ok()
        && final_path_metadata.ctime() == after.ctime()
        && final_path_metadata.ctime_nsec() == after.ctime_nsec()
        && final_path_metadata.mode() == after.mode();
    if !stable {
        return Err(Refusal::new(
            "root aros-link changed while its identity was being read",
        ));
    }
    if after.mode() & 0o111 == 0 {
        return Err(Refusal::new("root aros-link lost its executable mode"));
    }

    recheck_identity_parents(&parents)?;
    Ok(PortableFile {
        path: relative.to_owned(),
        bytes: count,
        sha256: hex_digest(&digest.finalize()),
        mode: Some(after.mode() & 0o7777),
    })
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
        ABI1_TARGET_SPEC_PATH, FilePin, Inventory, Pins, SymlinkPin, Toolchain,
        embedded_pins_for_host, expected_entries, host_for_target, input_identity,
        parse_relative_path, verify_exact_tree, verify_file_with_mode,
    };
    use crate::portable_view::{
        PORTABLE_VIEW_JSON, PortableFile, PortableInventory, PortableLink, ResolvedLink,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
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
    fn all_host_profiles_select_official_cargo_and_both_abis() {
        let arm = embedded_pins_for_host("linux-aarch64").unwrap();
        let expected = [
            (
                "rust",
                "862be6c4c1d29c59fc774e2d38f046672fcd0aa0978a869be9af2752fb4f76ee",
                arm.rust,
            ),
            (
                "cargo",
                "f588f2aa96bf359a4a609d1d691ae9fa5f765022c0950e76acc9011d06701b5b",
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
                "5840e8bc7cb7b810a6948d8f9042a992a18ec000351d21e697538489c146367f",
                arm.abi1_target,
            ),
            (
                "target libraries",
                "d08f304dc4cb87577cb76043eb7d38259a6b791ebe14f27f9a3c5e66a045645b",
                arm.abi1_target_libraries,
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
        assert_eq!(pins.rust.files.len(), 3871);
        assert_eq!(pins.rust.symlinks.len(), 2);
        assert_eq!(pins.cargo.files.len(), 1);
        assert_eq!(pins.cargo.files[0].path, "bin/cargo");
        assert_eq!(pins.cargo.files[0].bytes, 35521536);
        assert_eq!(
            pins.cargo.files[0].sha256,
            "44a4f14309e8d807e9e514f2c3b95be5ec0717887b5e6edadf112b8f7235c371"
        );
        assert_eq!(pins.collector.files.len(), 10);
        assert_eq!(pins.llvm.files.len(), 2743);
        assert_eq!(pins.llvm.symlinks.len(), 134);
        assert_eq!(pins.csdk.files.len(), 2835);
        assert!(pins.identity.starts_with(
            "linux-aarch64:x86_64-unknown-aros-abi1+x86_64-unknown-aros-abi11:sha256:"
        ));

        let mac = Pins::for_host("macos-aarch64").unwrap();
        assert_eq!(mac.rust.symlinks.len(), 3);

        let linux_x86 = embedded_pins_for_host("linux-x86_64").unwrap();
        assert_eq!(
            digest_text(linux_x86.abi1_target_libraries),
            "21dcb704b18c6df0a68f71521048bdd492126615a7403f960e79e09025251046"
        );
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
                    "7430a2e83d3f10b71beb899bed2d0f0013cc7b078e9831866660e00ac10ffc2c",
                    "34e7e069a72ac84d980f15c797b4250f324eee19088f55d135c9e4eafa0d88de",
                    "28237af9576e852451fcdf0470a904edb34a70232feb41d0c56be246313baadf",
                    "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
                ],
            ),
            (
                "linux-x86_64",
                [
                    "7a88373f28d19d6d61494587240681999adfb2bec964b4c3d74fae9718f097e8",
                    "14a92260987110a97c6e8413e4af2520d23186ea7d116736f399d624496195b6",
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
        let mut abi11_csdk = pins;
        abi11_csdk.abi11_csdk = changed_text(pins.abi11_csdk);
        assert_ne!(
            input_identity("linux-aarch64", &abi11_csdk),
            identity,
            "ABI11 C SDK missing from identity"
        );
        let mut target = pins;
        target.abi1_target = changed_text(pins.abi1_target);
        assert_ne!(
            input_identity("linux-aarch64", &target),
            identity,
            "ABI1 target missing from identity"
        );
        let mut target = pins;
        target.abi11_target = changed_text(pins.abi11_target);
        assert_ne!(input_identity("linux-aarch64", &target), identity);
        let mut libraries = pins;
        libraries.abi1_target_libraries = changed_text(pins.abi1_target_libraries);
        assert_ne!(input_identity("linux-aarch64", &libraries), identity);
        let mut libraries = pins;
        libraries.abi11_target_libraries = changed_text(pins.abi11_target_libraries);
        assert_ne!(input_identity("linux-aarch64", &libraries), identity);
        assert_ne!(input_identity("linux-x86_64", &pins), identity);
    }

    #[test]
    fn public_view_derives_all_three_hosts_without_rewriting_parent_pins() {
        let policy = super::PublicViewPolicy::embedded().unwrap();
        for host in ["macos-aarch64", "linux-x86_64", "linux-aarch64"] {
            let embedded = embedded_pins_for_host(host).unwrap();
            for (component, raw) in [("rust", embedded.rust), ("llvm", embedded.llvm)] {
                let parent: Inventory = super::parse_inventory(component, raw).unwrap();
                let derived = super::public_inventory(parent.clone(), component, &policy).unwrap();
                assert_eq!(parent.files.len() - derived.files.len(), 11);
                assert_eq!(parent.symlinks.len(), derived.symlinks.len());
                for row in &derived.files {
                    let original = parent
                        .files
                        .iter()
                        .find(|original| original.path == row.path)
                        .unwrap();
                    assert_eq!((&row.sha256, row.bytes), (&original.sha256, original.bytes));
                }
                if component == "rust" {
                    assert_eq!(
                        derived
                            .files
                            .iter()
                            .filter(|row| row.path.starts_with("lib/rustlib/src/rust/")
                                && row.path.ends_with(".py"))
                            .count(),
                        5
                    );
                }
                let excluded = policy
                    .exclusions()
                    .iter()
                    .find(|row| row.component == component)
                    .unwrap();
                let mut changed = parent.clone();
                changed
                    .files
                    .iter_mut()
                    .find(|row| row.path == excluded.path)
                    .unwrap()
                    .bytes += 1;
                assert!(super::public_inventory(changed, component, &policy).is_err());
                let mut missing = parent.clone();
                missing.files.retain(|row| row.path != excluded.path);
                assert!(super::public_inventory(missing, component, &policy).is_err());
            }
            assert_ne!(
                input_identity(host, &embedded),
                super::input_identity_with_views(
                    host,
                    &embedded,
                    "changed-public-view",
                    PORTABLE_VIEW_JSON,
                )
            );
            assert_ne!(
                input_identity(host, &embedded),
                super::input_identity_with_views(
                    host,
                    &embedded,
                    super::PUBLIC_VIEW_JSON,
                    "changed-portable-view",
                )
            );
        }
    }

    #[test]
    fn excluded_public_helpers_cannot_be_reintroduced_as_files_links_or_parent_aliases() {
        use std::os::unix::fs::symlink;
        let temp = TempDirectory::new();
        let relative = "lib/rustlib/etc/rust_types.py";
        super::refuse_reintroduced_public_helper(&temp.0, relative).unwrap();
        let parent = temp.0.join("lib/rustlib/etc");
        fs::create_dir_all(&parent).unwrap();
        super::refuse_reintroduced_public_helper(&temp.0, relative).unwrap();
        let helper = parent.join("rust_types.py");
        fs::write(&helper, b"helper").unwrap();
        assert!(super::refuse_reintroduced_public_helper(&temp.0, relative).is_err());
        fs::remove_file(&helper).unwrap();
        symlink("missing", &helper).unwrap();
        assert!(super::refuse_reintroduced_public_helper(&temp.0, relative).is_err());
        fs::remove_file(&helper).unwrap();
        fs::remove_dir(&parent).unwrap();
        symlink("missing", &parent).unwrap();
        assert!(super::refuse_reintroduced_public_helper(&temp.0, relative).is_err());
    }

    fn changed_text(text: &'static str) -> &'static str {
        Box::leak(format!("{text} ").into_boxed_str())
    }

    #[test]
    fn pinned_target_spec_member_accepts_exact_bytes_and_rejects_corruption() {
        let pins = Pins::for_host("linux-aarch64").unwrap();
        let temp = TempDirectory::new();
        let target_spec = include_bytes!("../../../../targets/x86_64-unknown-aros-abi1.json");
        let path = temp.0.join(ABI1_TARGET_SPEC_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, target_spec).unwrap();
        verify_file_with_mode(
            &temp.0,
            ABI1_TARGET_SPEC_PATH,
            None,
            &pins.targets[0].spec_sha256,
            "AROS target specification",
            None,
        )
        .unwrap();

        let mut corrupted = target_spec.to_vec();
        corrupted[0] ^= 1;
        fs::write(&path, corrupted).unwrap();
        assert!(
            verify_file_with_mode(
                &temp.0,
                ABI1_TARGET_SPEC_PATH,
                None,
                &pins.targets[0].spec_sha256,
                "AROS target specification",
                None,
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
    fn portable_regular_copy_graph_matches_all_three_embedded_hosts() {
        let hosts = ["macos-aarch64", "linux-x86_64", "linux-aarch64"];
        let linker_identity = PortableFile {
            path: "bin/aros-link".to_owned(),
            bytes: 15,
            sha256: digest_text("source-built linker"),
            mode: Some(0o775),
        };

        for host in hosts {
            let pins = Pins::for_host(host).unwrap();
            let portable = super::compose_portable_inventory(&pins, &linker_identity).unwrap();
            assert!(portable.files.len() > 9_000, "{host}");
            for path in [
                super::ABI1_TARGET_ALIAS_PATH,
                super::ABI11_TARGET_ALIAS_PATH,
            ] {
                assert!(
                    portable.files.iter().any(|file| file.path == path),
                    "{host}: {path}"
                );
            }
            assert!(
                portable
                    .files
                    .iter()
                    .all(|file| file.path != super::LEGACY_TARGET_ALIAS_PATH),
                "{host}"
            );
            assert_eq!(
                portable
                    .omitted_files
                    .iter()
                    .map(|file| file.path.as_str())
                    .collect::<Vec<_>>(),
                [
                    "lib/rustlib/components",
                    "lib/rustlib/rust-installer-version"
                ]
            );

            for materialized in &portable.materialized_links {
                let copy = portable
                    .files
                    .iter()
                    .find(|file| file.path == materialized.original.path)
                    .expect("each source link has a regular-file copy");
                assert_eq!(copy.bytes, materialized.resolved_file.bytes, "{host}");
                assert_eq!(copy.sha256, materialized.resolved_file.sha256, "{host}");
                assert_eq!(
                    copy.mode,
                    materialized
                        .resolved_file
                        .mode
                        .map(super::normalize_portable_mode),
                    "{host}"
                );
            }

            let cargo = super::unique_file_pin(&pins.cargo, "bin/cargo", "Cargo").unwrap();
            let cargo_copy = portable
                .files
                .iter()
                .find(|file| file.path == "bin/cargo")
                .unwrap();
            assert_eq!(cargo_copy.bytes, cargo.bytes, "{host}");
            assert_eq!(cargo_copy.sha256, cargo.sha256, "{host}");

            for (path, sha256) in [
                (
                    super::ABI1_TARGET_SPEC_PATH,
                    "0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807",
                ),
                (
                    super::ABI11_TARGET_SPEC_PATH,
                    "5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9",
                ),
            ] {
                let target = portable
                    .files
                    .iter()
                    .find(|file| file.path == path)
                    .unwrap();
                assert_eq!(target.sha256, sha256);
            }

            let root_linker = portable
                .files
                .iter()
                .find(|file| file.path == "bin/aros-link")
                .unwrap();
            assert_eq!(root_linker.mode, Some(0o755), "{host}");
            let alias = portable
                .files
                .iter()
                .find(|file| file.path == super::host_linker_alias(host).unwrap())
                .unwrap();
            assert!(super::same_file_identity(root_linker, alias), "{host}");

            assert_eq!(portable.omitted_generated_aliases.len(), 5, "{host}");
            for name in super::ROOT_LLVM_ALIASES {
                assert!(
                    !portable
                        .files
                        .iter()
                        .any(|file| file.path == format!("bin/{name}")),
                    "{host}: root alias must be omitted"
                );
                assert!(
                    portable
                        .files
                        .iter()
                        .any(|file| file.path == format!("libexec/aros/llvm/bin/{name}")),
                    "{host}: canonical tool is required"
                );
            }
            assert!(
                portable
                    .files
                    .windows(2)
                    .all(|rows| rows[0].path < rows[1].path)
            );
        }
    }

    #[test]
    fn materialized_copy_modes_must_match_the_resolved_regular_source() {
        let temp = TempDirectory::new();
        let root = temp.0.join("prefix");
        let source = root.join("bin/aros-link");
        let alias = root.join("lib/rustlib/x86_64-unknown-linux-gnu/bin/aros-link");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(alias.parent().unwrap()).unwrap();
        fs::write(&source, b"same bytes").unwrap();
        fs::write(&alias, b"same bytes").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o644)).unwrap();
        let inventory = PortableInventory {
            files: Vec::new(),
            materialized_links: vec![ResolvedLink {
                original: PortableLink {
                    path: "lib/rustlib/x86_64-unknown-linux-gnu/bin/aros-link".to_owned(),
                    target: "../../../../bin/aros-link".to_owned(),
                },
                resolved_file: PortableFile {
                    path: "bin/aros-link".to_owned(),
                    bytes: 10,
                    sha256: digest_text("same bytes"),
                    mode: Some(0o755),
                },
            }],
            omitted_files: Vec::new(),
            omitted_generated_aliases: Vec::new(),
            relocated_files: Vec::new(),
        };

        assert!(super::verify_materialized_link_modes(&root, &inventory).is_err());
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o755)).unwrap();
        super::verify_materialized_link_modes(&root, &inventory).unwrap();
    }

    #[test]
    fn file_verification_rejects_modes_outside_the_portable_normal_form() {
        let temp = TempDirectory::new();
        let path = temp.0.join("known");
        fs::write(&path, b"pinned").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        let pin = file_pin("known", b"pinned");
        assert!(
            verify_file_with_mode(
                &temp.0,
                &pin.path,
                Some(pin.bytes),
                &pin.sha256,
                "fixture",
                None,
            )
            .is_err()
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        verify_file_with_mode(
            &temp.0,
            &pin.path,
            Some(pin.bytes),
            &pin.sha256,
            "fixture",
            None,
        )
        .unwrap();
    }

    #[test]
    fn running_linker_accepts_only_root_executable_or_exact_host_copy_with_matching_bytes() {
        let temp = TempDirectory::new();
        let root = temp.0.join("prefix");
        let host_alias = "lib/rustlib/x86_64-unknown-linux-gnu/bin/aros-link";
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join(host_alias).parent().unwrap()).unwrap();
        fs::write(root.join("bin/aros-link"), b"pinned linker bytes").unwrap();
        fs::write(root.join(host_alias), b"pinned linker bytes").unwrap();
        for path in [root.join("bin/aros-link"), root.join(host_alias)] {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let root = fs::canonicalize(root).unwrap();
        let linker_identity = super::read_executable_identity(&root, "bin/aros-link").unwrap();
        let toolchain = Toolchain {
            root: root.clone(),
            rustc: root.join("bin/rustc"),
            cargo: root.join("bin/cargo"),
            toolchain_root: root.join("libexec/aros/llvm"),
            collector: root.join(super::COMPOSED_COLLECTOR_PATH),
            linker_identity,
            host: "linux-x86_64",
            source_date_epoch: 0,
            identity: "fixture identity".to_owned(),
        };

        toolchain
            .verify_link_executable(&root.join("bin/aros-link"))
            .unwrap();
        toolchain
            .verify_link_executable(&root.join(host_alias))
            .unwrap();
        toolchain
            .verify_selected_linker(Path::new("aros-link"))
            .unwrap();
        toolchain
            .verify_selected_linker(&root.join("bin/aros-link"))
            .unwrap();
        toolchain
            .verify_selected_linker(&root.join(host_alias))
            .unwrap();

        let other_prefix = temp.0.join("other-prefix");
        fs::create_dir_all(other_prefix.join("bin")).unwrap();
        let wrong_prefix = other_prefix.join("bin/aros-link");
        fs::write(&wrong_prefix, b"pinned linker bytes").unwrap();
        fs::set_permissions(&wrong_prefix, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(toolchain.verify_link_executable(&wrong_prefix).is_err());
        assert!(toolchain.verify_selected_linker(&wrong_prefix).is_err());

        let wrong_host = root.join("lib/rustlib/other-host/bin/aros-link");
        fs::create_dir_all(wrong_host.parent().unwrap()).unwrap();
        fs::write(&wrong_host, b"pinned linker bytes").unwrap();
        fs::set_permissions(&wrong_host, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(toolchain.verify_link_executable(&wrong_host).is_err());
        assert!(toolchain.verify_selected_linker(&wrong_host).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let external_bin = temp.0.join("external-bin");
            symlink(root.join("bin"), &external_bin).unwrap();
            assert!(
                toolchain
                    .verify_selected_linker(&external_bin.join("aros-link"))
                    .is_err()
            );
        }

        fs::write(root.join(host_alias), b"different linker bytes").unwrap();
        assert!(
            toolchain
                .verify_link_executable(&root.join(host_alias))
                .is_err()
        );
        assert!(
            toolchain
                .verify_selected_linker(&root.join(host_alias))
                .is_err()
        );
        fs::write(root.join(host_alias), b"pinned linker bytes").unwrap();
        for mode in [0o644, 0o775] {
            fs::set_permissions(root.join(host_alias), fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                toolchain
                    .verify_selected_linker(Path::new("aros-link"))
                    .is_err()
            );
        }
        fs::remove_file(root.join(host_alias)).unwrap();
        std::os::unix::fs::symlink(root.join("bin/aros-link"), root.join(host_alias)).unwrap();
        assert!(
            toolchain
                .verify_selected_linker(Path::new("aros-link"))
                .is_err()
        );
        fs::write(root.join("bin/aros-link"), b"").unwrap();
        assert!(super::read_executable_identity(&root, "bin/aros-link").is_err());
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
    #[test]
    fn linker_identity_refuses_parent_substitution_during_capture() {
        let temp = TempDirectory::new();
        let root = temp.0.join("prefix");
        let external = temp.0.join("external");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(&external).unwrap();
        for path in [root.join("bin/aros-link"), external.join("aros-link")] {
            fs::write(&path, b"same executable bytes").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        super::read_executable_identity(&root, "bin/aros-link").unwrap();
        let result = super::read_executable_identity_checked(&root, "bin/aros-link", || {
            fs::rename(root.join("bin"), root.join("old-bin")).unwrap();
            std::os::unix::fs::symlink(&external, root.join("bin")).unwrap();
            Ok(())
        });
        assert!(result.is_err());
    }
}

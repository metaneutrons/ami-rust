//! Complete local component selection for a retained native SDK.
//!
//! Inventories are read only through an externally pinned installation. This
//! module never provisions a component, rewrites a lock or selects global Rust.
use crate::{
    Refusal, Result,
    digest::sha256_bytes,
    directory::Directory,
    inventory::{
        FileIdentity, InventoryLimits, LinkIdentity, Measurement, verify_complete_directory,
    },
    json::{JsonProfile, parse_json_value},
    native_install::CheckedNativeInstallation,
    ownership,
    records::{Host, SelectionV2},
    sdk::{InstalledSdkRecipe, installed_recipe},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentInventory {
    files: Vec<FileIdentity>,
    #[serde(default)]
    symlinks: Vec<LinkIdentity>,
}

pub struct SelectedComponent {
    path: PathBuf,
    root: Directory,
    inventory: ComponentInventory,
    measurement: Measurement,
}

impl SelectedComponent {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn measurement(&self) -> &Measurement {
        &self.measurement
    }

    /// Select an inventoried executable or a completely verified in-component
    /// alias. Preserve the alias path for tools that dispatch using argv[0].
    pub fn executable(&self, relative: &str) -> Result<PathBuf> {
        use std::os::unix::fs::MetadataExt;
        let resolved = if self
            .inventory
            .files
            .iter()
            .any(|file| file.path == relative)
        {
            relative.to_owned()
        } else {
            crate::inventory::verified_link_destination(
                &self.root,
                &self.inventory.files,
                &self.inventory.symlinks,
                relative,
                InventoryLimits {
                    max_tree_entries: 100_000,
                    max_link_resolution_steps: 100_000,
                },
            )?
        };
        let row = self
            .inventory
            .files
            .iter()
            .find(|row| row.path == resolved)
            .ok_or_else(|| {
                Refusal::new("selected executable is absent from component inventory")
            })?;
        let (parent, leaf) = resolved.rsplit_once('/').unwrap_or(("", resolved.as_str()));
        let mut file = self
            .root
            .relative_directory(parent)?
            .regular(OsStr::new(leaf))?;
        let metadata = file.metadata()?;
        if metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o6022 != 0
            || row
                .mode
                .is_some_and(|mode| mode != metadata.mode() & 0o7777)
        {
            return Err(Refusal::new(
                "selected component file is not a safe executable",
            ));
        }
        // LLVM executables can be large. Do not retain a second whole binary
        // in the consumer process just to select a previously verified tool.
        let mut hash = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if read == 0 {
                break;
            }
            count = count
                .checked_add(read as u64)
                .filter(|count| *count <= row.bytes)
                .ok_or_else(|| Refusal::new("selected executable exceeds inventoried size"))?;
            hash.update(&buffer[..read]);
        }
        let actual: [u8; 32] = hash.finalize().into();
        let after = file.metadata()?;
        if count != row.bytes
            || crate::digest::encode_hex(&actual) != row.sha256
            || metadata.len() != after.len()
            || metadata.mode() != after.mode()
            || metadata.mtime() != after.mtime()
            || metadata.mtime_nsec() != after.mtime_nsec()
        {
            return Err(Refusal::new("selected component executable changed"));
        }
        let path = self.path.join(relative);
        // Includes effective access checks and secure owner/ancestor policy.
        ownership::protected_regular_file(&self.path.join(&resolved), true)?;
        Ok(path)
    }
}

pub struct SelectedInputs {
    pub host: Host,
    pub recipe: InstalledSdkRecipe,
    components: BTreeMap<String, SelectedComponent>,
}

impl SelectedInputs {
    pub fn component(&self, name: &str) -> Result<&SelectedComponent> {
        self.components
            .get(name)
            .ok_or_else(|| Refusal::new("unknown selected component role"))
    }

    pub fn recheck(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        for component in self.components.values() {
            let root = ownership::protected_directory(&component.path)?;
            let before = component.root.metadata()?;
            let after = root.metadata()?;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err(Refusal::new("selected component root changed"));
            }
            verify_component(&component.root, &component.inventory)?;
        }
        Ok(())
    }
}

/// Verify all six distinct components against the inventory files bound to the
/// retained SDK. Accepted-baseline pin admission is a separate prepare step;
/// this result alone does not authorize a new native compiler identity.
pub fn verify_selection(
    installation: &CheckedNativeInstallation,
    selection: &SelectionV2,
) -> Result<SelectedInputs> {
    selection.host.ensure_current()?;
    if selection.install_receipt_sha256.as_str() != installation.receipt_digest() {
        return Err(Refusal::new(
            "selection belongs to a different installation receipt",
        ));
    }
    let recipe = installed_recipe(installation, selection.host)?;
    let mut components = BTreeMap::new();
    for (name, path) in selection.components.entries() {
        let root = ownership::protected_directory(path)?;
        ownership::require_disjoint(
            path,
            installation.path(),
            "component root overlaps installed SDK",
        )?;
        for prior in components.values() {
            let prior: &SelectedComponent = prior;
            ownership::require_disjoint(path, &prior.path, "selected component roots overlap")?;
            use std::os::unix::fs::MetadataExt;
            let before = prior.root.metadata()?;
            let after = root.metadata()?;
            if before.dev() == after.dev() && before.ino() == after.ino() {
                return Err(Refusal::new(
                    "selected component roots alias the same directory",
                ));
            }
        }
        let (manifest, digest) = recipe
            .component_manifests
            .get(name)
            .ok_or_else(|| Refusal::new("SDK recipe omits component inventory"))?;
        let raw = installation.read_file(&format!("sdk/{manifest}"))?;
        if sha256_bytes(&raw) != *digest {
            return Err(Refusal::new("component inventory differs from SDK profile"));
        }
        let inventory = parse_inventory(&raw)?;
        let measurement = verify_component(&root, &inventory)?;
        components.insert(
            name.to_owned(),
            SelectedComponent {
                path: path.to_path_buf(),
                root,
                inventory,
                measurement,
            },
        );
    }
    installation.recheck()?;
    Ok(SelectedInputs {
        host: selection.host,
        recipe,
        components,
    })
}

fn parse_inventory(raw: &[u8]) -> Result<ComponentInventory> {
    let value = parse_json_value(raw, JsonProfile::SdkComponentManifest)?;
    serde::Deserialize::deserialize(value)
        .map_err(|error| Refusal::new(format!("invalid component inventory: {error}")))
}

fn verify_component(root: &Directory, inventory: &ComponentInventory) -> Result<Measurement> {
    verify_complete_directory(
        root,
        &inventory.files,
        &inventory.symlinks,
        InventoryLimits {
            max_tree_entries: 100_000,
            max_link_resolution_steps: 100_000,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_component_inventory_shapes_parse_without_python() {
        let inventories: [&[u8]; 12] = [
            include_bytes!("../../../../host/profiles/macos-aarch64/rust.json"),
            include_bytes!("../../../../host/profiles/macos-aarch64/cargo.json"),
            include_bytes!("../../../../host/profiles/macos-aarch64/toolchain.json"),
            include_bytes!("../../../../host/profiles/macos-aarch64/collector.json"),
            include_bytes!("../../../../host/profiles/macos-aarch64/csdk.json"),
            include_bytes!("../../../../host/profiles/macos-aarch64/vendor.json"),
            include_bytes!("../../../../host/profiles/linux-x86_64/rust.json"),
            include_bytes!("../../../../host/profiles/linux-x86_64/cargo.json"),
            include_bytes!("../../../../host/profiles/linux-x86_64/toolchain.json"),
            include_bytes!("../../../../host/profiles/linux-x86_64/collector.json"),
            include_bytes!("../../../../host/profiles/linux-x86_64/csdk.json"),
            include_bytes!("../../../../host/profiles/linux-x86_64/vendor.json"),
        ];
        for raw in inventories {
            assert!(!parse_inventory(raw).unwrap().files.is_empty());
        }
        assert!(parse_inventory(br#"{"files":[],"files":[]}"#).is_err());
        assert!(parse_inventory(br#"{"files":[],"driver":"python"}"#).is_err());
    }
}

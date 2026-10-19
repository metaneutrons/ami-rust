//! Verify a native ready state against its own retained package identity.
//! An upgraded package never silently takes over another version's state.
use crate::{
    Refusal, Result,
    directory::Directory,
    json::JsonProfile,
    native_install::CheckedNativeInstallation,
    ownership,
    package::CheckedNativePackage,
    publisher_files::read_bundle_file,
    records::{PackageStateV2, SelectionV2, StateStatus, parse_package_state, parse_selection},
    selected_inputs::{SelectedInputs, verify_selection},
};
use std::path::{Path, PathBuf};

pub struct ReadyInputs {
    path: PathBuf,
    root: Directory,
    pub state: PackageStateV2,
    pub installation: CheckedNativeInstallation,
    pub selection: SelectionV2,
    pub selected: SelectedInputs,
}

impl ReadyInputs {
    pub fn open(state_path: &Path, package: &CheckedNativePackage) -> Result<Self> {
        ownership::validate_state_package_separation(state_path, package.path(), false)?;
        let root = ownership::existing_private_state(state_path)?;
        let state_raw = read_bundle_file(
            &root,
            "ready.json",
            JsonProfile::PackageMetadataStateSelection.max_bytes(),
        )?;
        let state = parse_package_state(&state_raw)?;
        let pins = package.pins();
        let cli = &pins.launchers["ami-rust"].sha256;
        if state.status != StateStatus::Ready
            || state.host != pins.host
            || state.sdk_version != pins.sdk_version
            || state.package_version != pins.package_version
            || state.source_commit != pins.source_commit
            || state.manifest_sha256 != pins.manifest_sha256
            || state.cli_sha256 != *cli
            || state.core_sha256 != pins.core_sha256
        {
            return Err(Refusal::new(
                "state is incomplete or belongs to another SDK/package; use its retained launcher",
            ));
        }
        let prefix = installed_prefix(state_path, &state.sdk_version)?;
        let installation =
            CheckedNativeInstallation::open(&prefix, state.install_receipt_sha256.as_str())?;
        if installation.receipt().release_manifest_sha256 != state.manifest_sha256
            || installation.receipt().version != state.sdk_version
        {
            return Err(Refusal::new("ready state does not bind the installed SDK"));
        }
        let native = installation
            .receipt()
            .native
            .as_ref()
            .ok_or_else(|| Refusal::new("ready state requires a native installation"))?;
        if native.host != state.host
            || native.cli_sha256 != state.cli_sha256
            || native.core_sha256 != state.core_sha256
        {
            return Err(Refusal::new(
                "ready state CLI differs from the retained installed launcher",
            ));
        }
        let selection_raw = read_bundle_file(
            &root,
            "selection.json",
            JsonProfile::PackageMetadataStateSelection.max_bytes(),
        )?;
        let selection = parse_selection(&selection_raw)?;
        crate::baseline::InitialBaseline::load()?.admit_initial_sdk(&installation, state.host)?;
        let selected = verify_selection(&installation, &selection)?;
        let ready = Self {
            path: state_path.to_path_buf(),
            root,
            state,
            installation,
            selection,
            selected,
        };
        ready.recheck_root()?;
        Ok(ready)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn recheck_root(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let root = ownership::existing_private_state(&self.path)?;
        let before = self.root.metadata()?;
        let after = root.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(Refusal::new("ready state root identity changed"));
        }
        Ok(())
    }
}

pub fn installed_prefix(state: &Path, sdk_version: &str) -> Result<PathBuf> {
    if sdk_version.is_empty()
        || sdk_version.len() > 64
        || !sdk_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+_-".contains(&byte))
    {
        return Err(Refusal::new(
            "SDK version cannot name a native state prefix",
        ));
    }
    Ok(state.join(format!("sdk-{sdk_version}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_version_never_selects_an_external_path() {
        assert_eq!(
            installed_prefix(Path::new("/state"), "0.2.0").unwrap(),
            Path::new("/state/sdk-0.2.0")
        );
        for version in [
            "",
            "../sdk",
            "/sdk",
            "x/../../elsewhere",
            "x\\elsewhere",
            "x\n",
        ] {
            assert!(installed_prefix(Path::new("/state"), version).is_err());
        }
    }
}

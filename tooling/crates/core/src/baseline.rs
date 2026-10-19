//! Admission of the unchanged initial target inputs, independently of a new
//! native SDK's version/source identity and its rewritten host implementation.
use crate::{
    Refusal, Result,
    digest::sha256_bytes,
    json::{JsonProfile, parse_json_value},
    native_install::CheckedNativeInstallation,
    records::Host,
    sdk::{InstalledSdkRecipe, installed_recipe},
};
use serde_json::Value;
use std::collections::BTreeSet;

const BASELINE: &[u8] = include_bytes!("../../../fixtures/accepted-r1-inputs.json");

pub struct InitialBaseline {
    data: Value,
}

impl InitialBaseline {
    pub fn load() -> Result<Self> {
        let data = parse_json_value(BASELINE, JsonProfile::SdkComponentManifest)?;
        if data["schema"] != "ami-rust-accepted-r1-inputs-v1" {
            return Err(Refusal::new("unsupported compiled initial baseline record"));
        }
        Ok(Self { data })
    }

    /// Fixed archive/verifier metadata, usable for bootstrap without trusting
    /// arbitrary acquisition instructions from a downloaded SDK manifest.
    pub fn runtime_acquisition(&self) -> &Value {
        &self.data["runtime_acquisition"]
    }

    pub fn admit_initial_sdk(
        &self,
        installation: &CheckedNativeInstallation,
        host: Host,
    ) -> Result<InstalledSdkRecipe> {
        let recipe = installed_recipe(installation, host)?;
        let report = &installation
            .receipt()
            .authentication
            .as_ref()
            .ok_or_else(|| Refusal::new("native SDK omits retained authentication evidence"))?
            .report;
        self.check_recipe(&recipe, host, &report.source_sha)?;
        // A new release has a new source identity. Its *target file bytes* and
        // component inventories must still be the qualified initial inputs.
        for row in rows(&self.data["component_manifests"])? {
            check_file(installation, row)?;
        }
        let expected = rows(&self.data["sdk_target_inputs"]["files"])?;
        let paths = expected
            .iter()
            .map(|row| string(row, "path"))
            .collect::<Result<BTreeSet<_>>>()?;
        let actual = installation
            .file_identities()
            .filter_map(|row| row.path.strip_prefix("sdk/"))
            .filter(|path| target_input(path))
            .collect::<BTreeSet<_>>();
        if actual != paths {
            return Err(Refusal::new(
                "native SDK target-source file set differs from accepted initial inputs",
            ));
        }
        for row in expected {
            check_file(installation, row)?;
        }
        for row in
            rows(&self.data["runtime_acquisition"]["authenticated_bundle_cargo_assets"]["assets"])?
        {
            let path = string(row, "path")?;
            let bytes = installation.read_file(&format!("payload/{path}"))?;
            check_identity(&bytes, row)?;
        }
        installation.recheck()?;
        Ok(recipe)
    }

    fn check_recipe(
        &self,
        recipe: &InstalledSdkRecipe,
        host: Host,
        publisher_source: &str,
    ) -> Result<()> {
        let target = &self.data["sdk_target"];
        if recipe.rust_commit != string(target, "rust_commit")?
            || recipe.rust_llvm != string(target, "rust_llvm")?
            || recipe.source_date_epoch != counter(target, "source_date_epoch")?
            || recipe.source_identity != publisher_source
        {
            return Err(Refusal::new(
                "native SDK compiler/epoch or publisher source binding differs",
            ));
        }
        let host_name = match host {
            Host::LinuxX86_64 => "linux-x86_64",
            Host::MacosAarch64 => "macos-aarch64",
        };
        for row in rows(&self.data["component_manifests"])? {
            if string(row, "host")? != host_name {
                continue;
            }
            let name = string(row, "component")?;
            let expected = (
                string(row, "path")?.to_owned(),
                string(row, "sha256")?.to_owned(),
            );
            if recipe.component_manifests.get(name) != Some(&expected) {
                return Err(Refusal::new(format!(
                    "native {name} profile differs from the accepted initial baseline"
                )));
            }
        }
        Ok(())
    }
}

fn target_input(path: &str) -> bool {
    matches!(path, "Cargo.toml" | "Cargo.lock")
        || ["native/", "targets/", "crates/", "examples/", "tests/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

fn check_file(installation: &CheckedNativeInstallation, row: &Value) -> Result<()> {
    let path = string(row, "path")?;
    let bytes = installation.read_file(&format!("sdk/{path}"))?;
    check_identity(&bytes, row)
}

fn check_identity(bytes: &[u8], row: &Value) -> Result<()> {
    if bytes.len() as u64 != counter(row, "bytes")? || sha256_bytes(bytes) != string(row, "sha256")?
    {
        return Err(Refusal::new(format!(
            "initial baseline file differs: {}",
            string(row, "path")?
        )));
    }
    Ok(())
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("compiled baseline misses {key}")))
}
fn counter(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(format!("compiled baseline misses {key}")))
}
fn rows(value: &Value) -> Result<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| Refusal::new("compiled baseline misses inventory rows"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unchanged_recipe_passes_new_source_binding_but_changed_compiler_or_template_refuses() {
        let baseline = InitialBaseline::load().unwrap();
        for (host, key) in [
            (Host::LinuxX86_64, "linux-x86_64"),
            (Host::MacosAarch64, "macos-aarch64"),
        ] {
            let data = &baseline.data;
            let mut recipe = InstalledSdkRecipe {
                version: "0.2.0".into(),
                rust_commit: data["sdk_target"]["rust_commit"].as_str().unwrap().into(),
                rust_llvm: data["sdk_target"]["rust_llvm"].as_str().unwrap().into(),
                source_identity: "a".repeat(40),
                source_date_epoch: data["sdk_target"]["source_date_epoch"].as_u64().unwrap(),
                component_manifests: rows(&data["component_manifests"])
                    .unwrap()
                    .iter()
                    .filter(|row| row["host"] == key)
                    .map(|row| {
                        (
                            row["component"].as_str().unwrap().to_owned(),
                            (
                                row["path"].as_str().unwrap().to_owned(),
                                row["sha256"].as_str().unwrap().to_owned(),
                            ),
                        )
                    })
                    .collect(),
            };
            baseline
                .check_recipe(&recipe, host, &"a".repeat(40))
                .unwrap();
            assert!(
                baseline
                    .check_recipe(&recipe, host, &"b".repeat(40))
                    .is_err()
            );
            recipe.rust_commit = "0".repeat(40);
            assert!(
                baseline
                    .check_recipe(&recipe, host, &"a".repeat(40))
                    .is_err()
            );
            recipe.rust_commit = data["sdk_target"]["rust_commit"].as_str().unwrap().into();
            recipe.component_manifests.get_mut("cargo").unwrap().1 = "0".repeat(64);
            assert!(
                baseline
                    .check_recipe(&recipe, host, &"a".repeat(40))
                    .is_err()
            );
        }
        assert_eq!(
            rows(&baseline.data["component_manifests"]).unwrap().len(),
            12
        );
        assert_eq!(
            rows(&baseline.data["sdk_target_inputs"]["files"])
                .unwrap()
                .len(),
            56
        );
    }
}

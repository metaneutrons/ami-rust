//! Bind reviewed host build-input notices and a new SPDX document to the
//! signed native release. This records inputs; release licence acceptance and
//! an exact linked standard-library closure remain separate gates.
use std::collections::{BTreeMap, BTreeSet};

use ami_rust_core::{
    Refusal, Result,
    digest::sha256_bytes,
    json::{JsonProfile, parse_json_value},
    release_manifest::parse_native_release_manifest,
};
use serde_json::{Value, json};

use crate::native_release::NativeReleaseDraft;

const REVIEWED_INVENTORY: &[u8] = include_bytes!("../../../third-party/inventory.json");
const TOOLING_INPUTS: &[u8] = include_bytes!("../../../../release/native-tooling-inputs.json");

pub fn bind_native_notices(
    mut draft: NativeReleaseDraft,
    notices: &BTreeMap<String, Vec<u8>>,
) -> Result<NativeReleaseDraft> {
    let inventory = checked_notices(notices)?;
    let mut manifest = parse_json_value(
        &draft.manifest,
        JsonProfile::ReleaseManifestAndInstallReceipt,
    )?;
    let old_sbom = draft
        .assets
        .remove("sbom.spdx.json")
        .ok_or_else(|| Refusal::new("native composition omitted the original component SBOM"))?;
    let old = parse_json_value(&old_sbom, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let old_namespace = old["documentNamespace"]
        .as_str()
        .ok_or_else(|| Refusal::new("original SPDX document has no namespace"))?;
    let sbom = native_sbom(
        &manifest,
        &inventory,
        old_namespace,
        &sha256_bytes(&old_sbom),
    )?;
    draft
        .assets
        .insert("legacy-sbom.spdx.json".to_owned(), old_sbom);
    draft
        .assets
        .insert("sbom.spdx.json".to_owned(), canonical(&sbom)?);
    let source = text(&manifest["producer"], "source_sha")?;
    for (path, raw) in notices {
        // Preserve the reviewed inventory's relative license paths inside a
        // dedicated directory. Rewrite only source-document links for shipping.
        let destination = format!("native-tooling/{path}");
        let contents = if path == "THIRD-PARTY-NOTICES.md" {
            render_notice(raw, source, "inventory.json", "licenses/")?
        } else {
            raw.clone()
        };
        if draft.assets.insert(destination, contents).is_some() {
            return Err(Refusal::new(
                "native notice collides with retained release data",
            ));
        }
    }
    if draft.assets.len() > 512
        || draft.assets.values().map(Vec::len).sum::<usize>() > 64 * 1024 * 1024
    {
        return Err(Refusal::new(
            "native notices exceed the release container profile",
        ));
    }
    manifest["assets"] = Value::Array(
        draft
            .assets
            .iter()
            .map(|(path, raw)| {
                json!({
                    "path":path, "bytes":raw.len(), "sha256":sha256_bytes(raw),
                })
            })
            .collect(),
    );
    draft.manifest = canonical(&manifest)?;
    parse_native_release_manifest(&draft.manifest, true)?;
    draft.manifest_sha256 = sha256_bytes(&draft.manifest);
    Ok(draft)
}

fn checked_notices(notices: &BTreeMap<String, Vec<u8>>) -> Result<Value> {
    if notices.get("inventory.json").map(Vec::as_slice) != Some(REVIEWED_INVENTORY) {
        return Err(Refusal::new(
            "native notice inventory differs from the reviewed source input",
        ));
    }
    let inventory = parse_json_value(REVIEWED_INVENTORY, JsonProfile::SdkComponentManifest)?;
    let inputs = parse_json_value(TOOLING_INPUTS, JsonProfile::SdkComponentManifest)?;
    let packages = inventory["packages"]
        .as_array()
        .filter(|rows| rows.len() == 29)
        .ok_or_else(|| Refusal::new("native notice inventory must cover all 29 locked packages"))?;
    let registry = inputs["registry_crates"]
        .as_array()
        .ok_or_else(|| Refusal::new("native registry inputs are missing"))?;
    let identity = |row: &Value| -> Result<(String, String, String)> {
        Ok((
            text(row, "name")?.to_owned(),
            text(row, "version")?.to_owned(),
            row["sha256"]
                .as_str()
                .or_else(|| row["crate_archive"]["sha256"].as_str())
                .ok_or_else(|| Refusal::new("native crate archive checksum missing"))?
                .to_owned(),
        ))
    };
    if packages
        .iter()
        .map(identity)
        .collect::<Result<BTreeSet<_>>>()?
        != registry
            .iter()
            .map(identity)
            .collect::<Result<BTreeSet<_>>>()?
    {
        return Err(Refusal::new(
            "native notices select a different registry closure",
        ));
    }
    let mut expected = BTreeSet::from([
        "inventory.json".to_owned(),
        "THIRD-PARTY-NOTICES.md".to_owned(),
    ]);
    let texts = inventory["unique_license_texts"]
        .as_array()
        .ok_or_else(|| Refusal::new("reviewed licence texts are missing"))?;
    let supplemental =
        &inventory["host_rust_toolchain_review"]["supplemental_standard_library_notice"];
    for row in texts.iter().chain(std::iter::once(supplemental)) {
        let path = row["path"]
            .as_str()
            .or_else(|| row["copied_path"].as_str())
            .ok_or_else(|| Refusal::new("reviewed notice path is missing"))?;
        if !path.starts_with("licenses/") || !expected.insert(path.to_owned()) {
            return Err(Refusal::new(
                "native notice path has an invalid or duplicate role",
            ));
        }
        let raw = notices
            .get(path)
            .ok_or_else(|| Refusal::new("reviewed notice text is missing"))?;
        if raw.is_empty()
            || row["bytes"].as_u64() != Some(raw.len() as u64)
            || row["sha256"].as_str() != Some(sha256_bytes(raw).as_str())
        {
            return Err(Refusal::new(
                "native notice text differs from its reviewed bytes",
            ));
        }
    }
    if notices.keys().cloned().collect::<BTreeSet<_>>() != expected
        || notices["THIRD-PARTY-NOTICES.md"].is_empty()
    {
        return Err(Refusal::new(
            "native notice input has missing or unowned files",
        ));
    }
    Ok(inventory)
}

fn native_sbom(
    manifest: &Value,
    inventory: &Value,
    old_namespace: &str,
    old_digest: &str,
) -> Result<Value> {
    let version = text(manifest, "version")?;
    let source = text(&manifest["producer"], "source_sha")?;
    let package = |id: &str, name: &str, version: &str, licence: &str, url: &str| {
        json!({
            "SPDXID":id, "name":name, "versionInfo":version, "downloadLocation":url,
            "filesAnalyzed":false, "licenseConcluded":"NOASSERTION", "licenseDeclared":licence,
            "copyrightText":"NOASSERTION",
        })
    };
    let mut packages = vec![
        package(
            "SPDXRef-NativeRelease",
            "ami-rust",
            version,
            "MIT OR Apache-2.0",
            &format!("https://github.com/metaneutrons/ami-rust/tree/{source}"),
        ),
        package(
            "SPDXRef-HostRust",
            "Rust standard library build input",
            "1.98.1",
            "NOASSERTION",
            "NOASSERTION",
        ),
    ];
    let mut relationships = vec![
        json!({"spdxElementId":"SPDXRef-DOCUMENT", "relationshipType":"DESCRIBES", "relatedSpdxElement":"SPDXRef-NativeRelease"}),
        json!({"spdxElementId":"SPDXRef-HostRust", "relationshipType":"BUILD_DEPENDENCY_OF", "relatedSpdxElement":"SPDXRef-NativeRelease"}),
    ];
    for row in inventory["packages"]
        .as_array()
        .ok_or_else(|| Refusal::new("notice packages missing"))?
    {
        let name = text(row, "name")?;
        let version = text(row, "version")?;
        // Cargo permits underscores in names; SPDX element IDs do not.
        let id = format!(
            "SPDXRef-HostCrate-{}",
            sha256_bytes(format!("{name}@{version}").as_bytes())
        );
        let declared = text(row, "declared_license")?;
        // Preserve the reviewed upstream spelling in the input inventory and
        // comment, but emit the SPDX equivalent of Cargo's historical alias.
        let licence = if declared == "MIT/Apache-2.0" {
            "MIT OR Apache-2.0"
        } else {
            declared
        };
        let mut entry = package(
            &id,
            name,
            version,
            licence,
            &format!("https://static.crates.io/crates/{name}/{name}-{version}.crate"),
        );
        entry["checksums"] =
            json!([{"algorithm":"SHA256", "checksumValue":row["crate_archive"]["sha256"]}]);
        entry["comment"] = json!(format!(
            "Reviewed locked host build input; original Cargo license declaration: {declared}. This inventory does not assert that all crate code is linked into each launcher."
        ));
        packages.push(entry);
        relationships.push(json!({"spdxElementId":id, "relationshipType":"BUILD_DEPENDENCY_OF", "relatedSpdxElement":"SPDXRef-NativeRelease"}));
    }
    let files = manifest["host_launchers"].as_object()
        .ok_or_else(|| Refusal::new("native SPDX has no host launcher identities"))?.iter().map(|(host,row)| {
            let id = format!("SPDXRef-Launcher-{}", host.replace('_', "-"));
            relationships.push(json!({"spdxElementId":"SPDXRef-NativeRelease", "relationshipType":"CONTAINS", "relatedSpdxElement":id}));
            json!({"SPDXID":id, "fileName":row["path"], "checksums":[{"algorithm":"SHA256", "checksumValue":row["sha256"]}],
                "licenseConcluded":"NOASSERTION", "copyrightText":"NOASSERTION"})
        }).collect::<Vec<_>>();
    Ok(json!({
        "spdxVersion":"SPDX-2.3", "dataLicense":"CC0-1.0", "SPDXID":"SPDXRef-DOCUMENT",
        "name":format!("ami-rust-{version}-native-host-build-inputs"),
        "documentNamespace":format!("https://spdx.org/spdxdocs/ami-rust-native-{source}-{}", sha256_bytes(&canonical(manifest)?)),
        "creationInfo":{"created":"2026-10-19T00:00:00Z", "creators":["Tool: ami-rust-xtask"]},
        "documentComment":"Native release and reviewed host build inputs. The exact original component SPDX is retained as legacy-sbom.spdx.json; final licence and linked standard-library closure acceptance remain separate gates.",
        "externalDocumentRefs":[{"externalDocumentId":"DocumentRef-AcceptedComponents", "spdxDocument":old_namespace,
            "checksum":{"algorithm":"SHA256", "checksumValue":old_digest}}],
        "packages":packages, "files":files, "relationships":relationships,
    }))
}

/// Adjust repository-only documentation links for a distribution layout;
/// upstream license text bytes are never passed through this renderer.
pub(crate) fn render_notice(
    raw: &[u8],
    source: &str,
    inventory_link: &str,
    licence_prefix: &str,
) -> Result<Vec<u8>> {
    let text =
        std::str::from_utf8(raw).map_err(|_| Refusal::new("notice document is not UTF-8"))?;
    let base = format!("https://github.com/metaneutrons/ami-rust/blob/{source}");
    Ok(text
        .replace("](inventory.json)", &format!("]({inventory_link})"))
        .replace("](../../docs/", &format!("]({base}/docs/"))
        .replace("](../../tools/", &format!("]({base}/tools/"))
        .replace("](../Cargo.lock)", &format!("]({base}/tooling/Cargo.lock)"))
        .replace("licenses/", licence_prefix)
        .into_bytes())
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .filter(|text| !text.is_empty())
        .ok_or_else(|| Refusal::new(format!("native notice field is missing: {name}")))
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut raw =
        serde_json::to_vec_pretty(value).map_err(|error| Refusal::new(error.to_string()))?;
    raw.push(b'\n');
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_inventory_emits_spdx_identifiers_and_license_expressions() {
        let inventory: Value = serde_json::from_slice(REVIEWED_INVENTORY).unwrap();
        let manifest = json!({"version":"0.2.0", "producer":{"source_sha":"a".repeat(40)},
            "host_launchers":{"linux-x86_64":{"path":"bin/ami-rust-linux", "sha256":"b".repeat(64)},
                              "macos-aarch64":{"path":"bin/ami-rust-macos", "sha256":"c".repeat(64)}}});
        let sbom = native_sbom(
            &manifest,
            &inventory,
            "https://example.invalid/legacy",
            &"d".repeat(64),
        )
        .unwrap();
        let mut ids = BTreeSet::from(["SPDXRef-DOCUMENT".to_owned()]);
        for row in sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .chain(sbom["files"].as_array().unwrap())
        {
            let id = row["SPDXID"].as_str().unwrap();
            assert!(id.starts_with("SPDXRef-"));
            assert!(
                id.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
            );
            assert!(ids.insert(id.to_owned()));
        }
        for row in sbom["relationships"].as_array().unwrap() {
            for field in ["spdxElementId", "relatedSpdxElement"] {
                assert!(ids.contains(row[field].as_str().unwrap()));
            }
        }
        let packages = sbom["packages"].as_array().unwrap();
        assert_eq!(
            packages
                .iter()
                .find(|row| row["name"] == "filetime")
                .unwrap()["licenseDeclared"],
            "MIT OR Apache-2.0"
        );
        assert!(
            packages
                .iter()
                .find(|row| row["name"] == "filetime")
                .unwrap()["comment"]
                .as_str()
                .unwrap()
                .contains("MIT/Apache-2.0")
        );
        for row in packages {
            assert!(!row["licenseDeclared"].as_str().unwrap().contains('/'));
        }
        assert!(packages.iter().any(|row| row["name"] == "serde_core"));
    }

    #[test]
    fn actual_reviewed_notice_bytes_pass_and_changed_or_extra_bytes_refuse() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third-party");
        let mut notices = crate::read_directory_map(&std::fs::canonicalize(root).unwrap()).unwrap();
        let inventory = checked_notices(&notices).unwrap();
        assert_eq!(inventory["packages"].as_array().unwrap().len(), 29);
        let rendered = render_notice(
            &notices["THIRD-PARTY-NOTICES.md"],
            &"a".repeat(40),
            "inventory.json",
            "licenses/",
        )
        .unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.contains("](inventory.json)"));
        assert!(!rendered.contains("](../../"));
        assert!(!rendered.contains("](../Cargo.lock)"));
        assert!(rendered.contains("/blob/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/docs/"));
        let path = inventory["unique_license_texts"][0]["path"]
            .as_str()
            .unwrap();
        let original = notices[path].clone();
        notices.get_mut(path).unwrap().push(0);
        assert!(
            checked_notices(&notices)
                .unwrap_err()
                .to_string()
                .contains("reviewed bytes")
        );
        notices.insert(path.to_owned(), original);
        notices.insert("unowned.py".to_owned(), b"inert counterprobe".to_vec());
        assert!(checked_notices(&notices).is_err());
    }
}

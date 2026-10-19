//! Structural parsing for the frozen publisher policy and input-material list.
//!
//! These types preserve policy and ordered material claims. Parsing performs
//! no path resolution, file access, digest verification, process execution, or
//! publisher authentication; callers must perform those checks before using
//! any policy path or treating a material as verified.

use crate::{
    Refusal, Result,
    digest::is_sha256_digest,
    json::{JsonProfile, parse_json_value},
    records::{Host, Sha256},
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{collections::BTreeSet, path::Path};

const POLICY_SCHEMA: &str = "ami-rust-publisher-trust-v2";
const INPUTS_SCHEMA: &str = "ami-rust-publisher-inputs-v1";
const REPOSITORY: &str = "metaneutrons/ami-rust";
const WORKFLOW: &str = ".github/workflows/sdk-qualify.yml";
const SOURCE_REF: &str = "refs/heads/main";
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// A pinned policy path and its expected file digest.
///
/// The path is only checked for absolute lexical normalization. Its existence,
/// target type, executable bit, resolution and bytes remain caller checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PinnedPolicyFile {
    pub path: String,
    pub sha256: Sha256,
}

/// Structurally validated, externally supplied publisher policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublisherPolicy {
    pub schema: String,
    pub repository: String,
    pub workflow: String,
    pub workflow_sha: String,
    pub source_sha: String,
    pub source_ref: String,
    pub oidc_issuer: String,
    pub cert_identity: String,
    pub inputs_manifest_sha256: Sha256,
    pub allowed_host_profiles: Vec<Host>,
    pub gh: PinnedPolicyFile,
    pub cosign: PinnedPolicyFile,
    pub gh_trusted_roots: PinnedPolicyFile,
    pub cosign_trusted_root: PinnedPolicyFile,
}

/// One ordered pinned external material from the publisher inputs manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PinnedMaterial {
    pub uri: String,
    pub digest: PinnedMaterialDigest,
}

/// Supported digest shape for one external material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PinnedMaterialDigest {
    Sha256 {
        sha256: Sha256,
    },
    GitCommit {
        #[serde(rename = "gitCommit")]
        git_commit: String,
    },
}

/// Structurally validated publisher input manifest. `materials` retains source
/// order for reporting; SLSA dependency comparison uses exact set equality.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublisherInputsManifest {
    pub schema: String,
    pub materials: Vec<PinnedMaterial>,
}

/// Parse the exact frozen publisher policy schema.
///
/// Tool and trusted-root paths remain untrusted strings until callers resolve
/// and verify their filesystem identities, executable modes and bytes.
pub fn parse_publisher_policy(raw: &[u8]) -> Result<PublisherPolicy> {
    let value = parse_json_value(raw, JsonProfile::PublisherPolicyAndAuthenticationMetadata)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("publisher policy must be an object"))?;
    let expected = [
        "schema",
        "repository",
        "workflow",
        "workflow_sha",
        "source_sha",
        "source_ref",
        "oidc_issuer",
        "cert_identity",
        "inputs_manifest_sha256",
        "allowed_host_profiles",
        "gh",
        "cosign",
        "gh_trusted_roots",
        "cosign_trusted_root",
    ];
    if !exact_fields(object, &expected) {
        return Err(Refusal::new(
            "publisher policy has unknown or missing fields",
        ));
    }

    let schema = required_string(object.get("schema"), "publisher policy schema")?;
    let repository = required_string(object.get("repository"), "publisher repository")?;
    let workflow = required_string(object.get("workflow"), "publisher workflow")?;
    let source_ref = required_string(object.get("source_ref"), "publisher source ref")?;
    let oidc_issuer = required_string(object.get("oidc_issuer"), "publisher OIDC issuer")?;
    if schema != POLICY_SCHEMA
        || repository != REPOSITORY
        || workflow != WORKFLOW
        || source_ref != SOURCE_REF
        || oidc_issuer != OIDC_ISSUER
    {
        return Err(Refusal::new(
            "publisher policy constants do not match this verifier",
        ));
    }

    let workflow_sha = required_string(object.get("workflow_sha"), "publisher workflow SHA")?;
    if !is_lower_hex(workflow_sha, 40) {
        return Err(Refusal::new("invalid policy workflow_sha"));
    }
    let source_sha = required_string(object.get("source_sha"), "publisher source SHA")?;
    if !is_lower_hex(source_sha, 40) {
        return Err(Refusal::new("invalid policy source_sha"));
    }
    let inputs_manifest_sha256 = parse_sha256(
        object.get("inputs_manifest_sha256"),
        "policy inputs_manifest_sha256",
    )?;
    let cert_identity = required_string(
        object.get("cert_identity"),
        "publisher certificate identity",
    )?;
    let expected_identity = format!("https://github.com/{REPOSITORY}/{WORKFLOW}@{SOURCE_REF}");
    if cert_identity != expected_identity {
        return Err(Refusal::new(
            "publisher policy certificate identity mismatch",
        ));
    }
    let allowed_host_profiles = parse_allowed_hosts(object.get("allowed_host_profiles"))?;

    Ok(PublisherPolicy {
        schema: schema.to_owned(),
        repository: repository.to_owned(),
        workflow: workflow.to_owned(),
        workflow_sha: workflow_sha.to_owned(),
        source_sha: source_sha.to_owned(),
        source_ref: source_ref.to_owned(),
        oidc_issuer: oidc_issuer.to_owned(),
        cert_identity: cert_identity.to_owned(),
        inputs_manifest_sha256,
        allowed_host_profiles,
        gh: parse_pinned_file(object.get("gh"), "gh")?,
        cosign: parse_pinned_file(object.get("cosign"), "cosign")?,
        gh_trusted_roots: parse_pinned_file(object.get("gh_trusted_roots"), "gh_trusted_roots")?,
        cosign_trusted_root: parse_pinned_file(
            object.get("cosign_trusted_root"),
            "cosign_trusted_root",
        )?,
    })
}

/// Parse the exact frozen inputs manifest and retain materials in input order.
/// The manifest's digest binding to policy is a caller responsibility.
pub fn parse_inputs_manifest(raw: &[u8]) -> Result<PublisherInputsManifest> {
    let value = parse_json_value(raw, JsonProfile::PublisherPolicyAndAuthenticationMetadata)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("pinned inputs manifest must be an object"))?;
    if !exact_fields(object, &["schema", "materials"]) {
        return Err(Refusal::new(
            "pinned inputs manifest has unknown or missing fields",
        ));
    }
    let schema = required_string(object.get("schema"), "pinned inputs manifest schema")?;
    if schema != INPUTS_SCHEMA {
        return Err(Refusal::new("pinned inputs manifest schema mismatch"));
    }
    let rows = object
        .get("materials")
        .and_then(Value::as_array)
        .filter(|rows| !rows.is_empty() && rows.len() <= 512)
        .ok_or_else(|| Refusal::new("pinned inputs manifest must contain 1 to 512 materials"))?;

    let mut materials = Vec::with_capacity(rows.len());
    let mut seen_uris = BTreeSet::new();
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| Refusal::new("invalid pinned material row"))?;
        if !exact_fields(row, &["uri", "digest"]) {
            return Err(Refusal::new("invalid pinned material row"));
        }
        let uri = required_string(row.get("uri"), "pinned material URI")?;
        if uri.is_empty()
            || uri.len() > 2_048
            || !uri.bytes().all(|byte| (33..=126).contains(&byte))
            || !["https://", "git+https://", "oci://"]
                .iter()
                .any(|prefix| uri.starts_with(prefix))
        {
            return Err(Refusal::new("invalid pinned material URI"));
        }
        if !seen_uris.insert(uri.to_owned()) {
            return Err(Refusal::new(format!(
                "duplicate pinned material URI: {uri}"
            )));
        }
        materials.push(PinnedMaterial {
            uri: uri.to_owned(),
            digest: parse_material_digest(row.get("digest"), uri)?,
        });
    }
    let main_source_uri = format!("git+https://github.com/{REPOSITORY}@{SOURCE_REF}");
    if materials
        .iter()
        .any(|material| material.uri == main_source_uri)
    {
        return Err(Refusal::new(
            "main repository source must be represented by the exact source policy pin",
        ));
    }

    Ok(PublisherInputsManifest {
        schema: schema.to_owned(),
        materials,
    })
}

fn exact_fields(object: &Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field))
}

fn required_string<'a>(value: Option<&'a Value>, label: &str) -> Result<&'a str> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("{label} must be a string")))
}

fn parse_sha256(value: Option<&Value>, label: &str) -> Result<Sha256> {
    let value = required_string(value, label)?;
    if !is_sha256_digest(value) {
        return Err(Refusal::new(format!("invalid {label}")));
    }
    serde_json::from_value(Value::String(value.to_owned()))
        .map_err(|error| Refusal::new(format!("invalid {label}: {error}")))
}

fn parse_allowed_hosts(value: Option<&Value>) -> Result<Vec<Host>> {
    let values = value
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| Refusal::new("invalid allowed_host_profiles policy"))?;
    let mut hosts = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let name = value
            .as_str()
            .ok_or_else(|| Refusal::new("invalid allowed_host_profiles policy"))?;
        let host = match name {
            "linux-x86_64" => Host::LinuxX86_64,
            "macos-aarch64" => Host::MacosAarch64,
            _ => return Err(Refusal::new("invalid allowed_host_profiles policy")),
        };
        if !seen.insert(name) {
            return Err(Refusal::new("invalid allowed_host_profiles policy"));
        }
        hosts.push(host);
    }
    Ok(hosts)
}

fn parse_pinned_file(value: Option<&Value>, label: &str) -> Result<PinnedPolicyFile> {
    let entry = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new(format!("invalid pinned {label} entry")))?;
    if !exact_fields(entry, &["path", "sha256"]) {
        return Err(Refusal::new(format!("invalid pinned {label} entry")));
    }
    let path = required_string(entry.get("path"), &format!("{label} path"))?;
    if !is_normalized_absolute_path(path) {
        return Err(Refusal::new(format!(
            "{label} path must be a normalized absolute path"
        )));
    }
    Ok(PinnedPolicyFile {
        path: path.to_owned(),
        sha256: parse_sha256(entry.get("sha256"), &format!("{label} SHA-256"))?,
    })
}

fn parse_material_digest(value: Option<&Value>, uri: &str) -> Result<PinnedMaterialDigest> {
    let digests = value
        .and_then(Value::as_object)
        .filter(|digests| digests.len() == 1)
        .ok_or_else(|| Refusal::new(format!("invalid pinned material digest: {uri}")))?;
    match digests
        .iter()
        .next()
        .map(|(key, value)| (key.as_str(), value))
    {
        Some(("sha256", value)) => Ok(PinnedMaterialDigest::Sha256 {
            sha256: parse_sha256(Some(value), &format!("pinned material digest: {uri}"))?,
        }),
        Some(("gitCommit", value)) => {
            let digest = required_string(Some(value), &format!("pinned material digest: {uri}"))?;
            if !is_lower_hex(digest, 40) {
                return Err(Refusal::new(format!(
                    "unsupported or invalid pinned material digest: {uri}"
                )));
            }
            Ok(PinnedMaterialDigest::GitCommit {
                git_commit: digest.to_owned(),
            })
        }
        _ => Err(Refusal::new(format!(
            "unsupported or invalid pinned material digest: {uri}"
        ))),
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Match POSIX `normpath` lexically without resolving the path on disk.
fn is_normalized_absolute_path(path: &str) -> bool {
    if !Path::new(path).is_absolute() {
        return false;
    }
    let preserve_double_slash = path.starts_with("//") && !path.starts_with("///");
    let root = if preserve_double_slash { "//" } else { "/" };
    let components = &path[if preserve_double_slash { 2 } else { 1 }..];
    let mut normalized_components: Vec<&str> = Vec::new();
    for component in components.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                normalized_components.pop();
            }
            _ => normalized_components.push(component),
        }
    }
    let normalized = if normalized_components.is_empty() {
        root.to_owned()
    } else {
        format!("{root}{}", normalized_components.join("/"))
    };
    path == normalized
}

#[cfg(test)]
mod tests {
    use super::{
        PinnedMaterialDigest, PublisherInputsManifest, PublisherPolicy, parse_inputs_manifest,
        parse_publisher_policy,
    };
    use serde_json::{Value, json};

    const POLICY_CERT_IDENTITY: &str = "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main";

    fn policy_value() -> Value {
        json!({
            "schema":"ami-rust-publisher-trust-v2",
            "repository":"metaneutrons/ami-rust",
            "workflow":".github/workflows/sdk-qualify.yml",
            "workflow_sha":"a".repeat(40),
            "source_sha":"b".repeat(40),
            "source_ref":"refs/heads/main",
            "oidc_issuer":"https://token.actions.githubusercontent.com",
            "cert_identity":POLICY_CERT_IDENTITY,
            "inputs_manifest_sha256":"c".repeat(64),
            "allowed_host_profiles":["macos-aarch64", "linux-x86_64"],
            "gh":{"path":"/tools/gh", "sha256":"d".repeat(64)},
            "cosign":{"path":"/tools/cosign", "sha256":"e".repeat(64)},
            "gh_trusted_roots":{"path":"/trust/gh.jsonl", "sha256":"f".repeat(64)},
            "cosign_trusted_root":{"path":"/trust/cosign.json", "sha256":"0".repeat(64)}
        })
    }

    fn inputs_value() -> Value {
        json!({
            "schema":"ami-rust-publisher-inputs-v1",
            "materials":[
                {"uri":"https://example.invalid/archive.tar", "digest":{"sha256":"a".repeat(64)}},
                {"uri":"git+https://example.invalid/source.git", "digest":{"gitCommit":"b".repeat(40)}},
                {"uri":"oci://example.invalid/image:tag", "digest":{"sha256":"c".repeat(64)}}
            ]
        })
    }

    fn encode(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("serialize fixture")
    }

    fn parse_policy(value: &Value) -> crate::Result<PublisherPolicy> {
        parse_publisher_policy(&encode(value))
    }

    fn parse_inputs(value: &Value) -> crate::Result<PublisherInputsManifest> {
        parse_inputs_manifest(&encode(value))
    }

    #[test]
    fn parses_policy_constants_hosts_and_normalized_paths_without_filesystem_access() {
        let policy = parse_policy(&policy_value()).expect("structural policy parse");
        assert_eq!(policy.cert_identity, POLICY_CERT_IDENTITY);
        assert_eq!(policy.allowed_host_profiles.len(), 2);
        assert_eq!(policy.gh.path, "/tools/gh");
        assert_eq!(policy.gh_trusted_roots.path, "/trust/gh.jsonl");
        // Structural parsing does not require these paths to exist.
        let _: Value = serde_json::to_value(policy).expect("serialize policy");
    }

    #[test]
    fn refuses_policy_field_constant_digest_host_and_path_mismatches() {
        let mut value = policy_value();
        value["future"] = json!(true);
        assert!(parse_policy(&value).is_err());

        let mut value = policy_value();
        value
            .as_object_mut()
            .expect("policy object")
            .remove("source_sha");
        assert!(parse_policy(&value).is_err());

        for (field, wrong) in [
            ("schema", "wrong-schema"),
            ("repository", "someone/else"),
            ("workflow", "other.yml"),
            ("source_ref", "refs/heads/other"),
            ("oidc_issuer", "https://other.invalid"),
            ("cert_identity", "https://wrong.invalid"),
        ] {
            let mut value = policy_value();
            value[field] = json!(wrong);
            assert!(parse_policy(&value).is_err(), "accepted wrong {field}");
        }

        for bad in ["A".repeat(40), "a".repeat(39), "g".repeat(40)] {
            let mut value = policy_value();
            value["workflow_sha"] = json!(bad);
            assert!(parse_policy(&value).is_err());
        }
        let mut value = policy_value();
        value["inputs_manifest_sha256"] = json!("A".repeat(64));
        assert!(parse_policy(&value).is_err());

        let mut value = policy_value();
        value["allowed_host_profiles"] = json!([]);
        assert!(parse_policy(&value).is_err());
        let mut value = policy_value();
        value["allowed_host_profiles"] = json!(["linux-x86_64"]);
        assert_eq!(
            parse_policy(&value)
                .expect("one supported host")
                .allowed_host_profiles
                .len(),
            1
        );
        let mut value = policy_value();
        value["allowed_host_profiles"] = json!(["linux-x86_64", "linux-x86_64"]);
        assert!(parse_policy(&value).is_err());
        let mut value = policy_value();
        value["allowed_host_profiles"] = json!(["windows-x86_64"]);
        assert!(parse_policy(&value).is_err());

        for path in ["tools/gh", "/tools/../gh", "/tools//gh", "/tools/./gh"] {
            let mut value = policy_value();
            value["gh"]["path"] = json!(path);
            assert!(parse_policy(&value).is_err(), "accepted path {path}");
        }
        let mut value = policy_value();
        value["gh"]["sha256"] = json!("z".repeat(64));
        assert!(parse_policy(&value).is_err());
        let mut value = policy_value();
        value["cosign"]["extra"] = json!(true);
        assert!(parse_policy(&value).is_err());
    }

    #[test]
    fn parses_ordered_input_materials_with_exact_digest_shapes() {
        let manifest = parse_inputs(&inputs_value()).expect("inputs manifest");
        assert_eq!(manifest.materials.len(), 3);
        assert_eq!(
            manifest.materials[0].uri,
            "https://example.invalid/archive.tar"
        );
        assert!(matches!(
            &manifest.materials[1].digest,
            PinnedMaterialDigest::GitCommit { .. }
        ));
        let _: Value = serde_json::to_value(manifest).expect("serialize materials");
    }

    #[test]
    fn refuses_bad_input_schema_rows_uris_digests_and_material_counts() {
        let mut value = inputs_value();
        value["schema"] = json!("future-inputs-v2");
        assert!(parse_inputs(&value).is_err());

        let mut value = inputs_value();
        value["extra"] = json!(true);
        assert!(parse_inputs(&value).is_err());

        let mut value = inputs_value();
        value["materials"][0]["unknown"] = json!("field");
        assert!(parse_inputs(&value).is_err());

        for uri in [
            "",
            "HTTPS://example.invalid/file",
            "https://example.invalid/a b",
            "https://example.invalid/é",
            "file:///tmp/archive",
        ] {
            let mut value = inputs_value();
            value["materials"][0]["uri"] = json!(uri);
            assert!(parse_inputs(&value).is_err(), "accepted URI {uri:?}");
        }

        let mut value = inputs_value();
        value["materials"][0]["uri"] = json!(format!("https://{}", "x".repeat(2_040)));
        assert_eq!(
            parse_inputs(&value).expect("2048-byte URI").materials.len(),
            3
        );
        let mut value = inputs_value();
        value["materials"][0]["uri"] = json!(format!("https://{}", "x".repeat(2_041)));
        assert!(parse_inputs(&value).is_err());

        let mut value = inputs_value();
        let duplicate_uri = value["materials"][0]["uri"].clone();
        value["materials"][1]["uri"] = duplicate_uri;
        assert!(parse_inputs(&value).is_err());

        let mut value = inputs_value();
        value["materials"][0]["digest"] = json!({"sha256":"A".repeat(64)});
        assert!(parse_inputs(&value).is_err());
        let mut value = inputs_value();
        value["materials"][0]["digest"] =
            json!({"gitCommit":"a".repeat(40), "sha256":"b".repeat(64)});
        assert!(parse_inputs(&value).is_err());
        let mut value = inputs_value();
        value["materials"][0]["digest"] = json!({"tree":"a".repeat(40)});
        assert!(parse_inputs(&value).is_err());
        let mut value = inputs_value();
        value["materials"][1]["digest"] = json!({"gitCommit":"A".repeat(40)});
        assert!(parse_inputs(&value).is_err());

        let mut value = inputs_value();
        value["materials"] = json!([]);
        assert!(parse_inputs(&value).is_err());
        let row = inputs_value()["materials"][0].clone();
        value["materials"] = Value::Array(vec![row.clone(); 512]);
        for (index, row) in value["materials"]
            .as_array_mut()
            .expect("material rows")
            .iter_mut()
            .enumerate()
        {
            row["uri"] = json!(format!("https://example.invalid/{index}"));
        }
        assert_eq!(
            parse_inputs(&value).expect("512 materials").materials.len(),
            512
        );

        value["materials"] = Value::Array(vec![row; 513]);
        for (index, row) in value["materials"]
            .as_array_mut()
            .expect("material rows")
            .iter_mut()
            .enumerate()
        {
            row["uri"] = json!(format!("https://example.invalid/{index}"));
        }
        assert!(parse_inputs(&value).is_err());

        let mut too_large = serde_json::to_vec(&inputs_value()).expect("valid fixture");
        too_large.resize(1_048_577, b' ');
        assert!(parse_inputs_manifest(&too_large).is_err());
    }

    #[test]
    fn excludes_the_main_repository_uri_and_rejects_private_raw_wrapper_shapes() {
        let mut value = inputs_value();
        value["materials"][0]["uri"] =
            json!("git+https://github.com/metaneutrons/ami-rust@refs/heads/main");
        assert!(parse_inputs(&value).is_err());

        let mut value = inputs_value();
        value["materials"][0]["uri"] = json!({
            "$serde_json::private::RawValue":"https://example.invalid/archive.tar"
        });
        assert!(parse_inputs(&value).is_err());
    }

    #[test]
    fn strict_tree_rejects_duplicate_policy_and_material_keys() {
        let policy = serde_json::to_string(&policy_value()).expect("policy fixture");
        let duplicate = policy.replace(
            "\"schema\":\"ami-rust-publisher-trust-v2\"",
            "\"schema\":\"ami-rust-publisher-trust-v2\",\"schema\":\"ami-rust-publisher-trust-v2\"",
        );
        assert!(parse_publisher_policy(duplicate.as_bytes()).is_err());

        let inputs = serde_json::to_string(&inputs_value()).expect("inputs fixture");
        let duplicate = inputs.replace(
            "\"uri\":\"https://example.invalid/archive.tar\"",
            "\"uri\":\"https://example.invalid/archive.tar\",\"uri\":\"https://example.invalid/archive.tar\"",
        );
        assert!(parse_inputs_manifest(duplicate.as_bytes()).is_err());
    }
}

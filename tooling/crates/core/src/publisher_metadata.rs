//! Structural parsing for publisher authentication metadata.
//!
//! This module validates declared workflow and bundle mappings only. It does
//! not inspect bundle files, authenticate a publisher, verify signatures,
//! hash the release manifest or resolve filesystem paths. Callers must do
//! those checks before treating any returned claim as evidence.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Refusal, Result,
    digest::is_sha256_digest,
    json::{JsonProfile, parse_json_value},
    publisher_policy::PublisherPolicy,
    records::Host,
    release_manifest::ReleaseFile,
    workflow_counter::PositiveCounter,
};

const AUTHENTICATION_SCHEMA: &str = "ami-rust-authentication-v2";
const INPUTS_MANIFEST_PATH: &str = ".auth/inputs.json";
const AUTHENTICATION_PATH: &str = ".auth/authentication.json";
const REQUIRED_SUBJECTS: [&str; 3] = ["release.json", "sdk.tar.xz", "SHAUTIL"];

/// One workflow identity declared by the authentication metadata.
///
/// These values remain claims until an external verifier authenticates the
/// corresponding provenance evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeclaredWorkflowRun {
    pub run_id: PositiveCounter,
    pub run_attempt: PositiveCounter,
    pub host_profile: Host,
}

/// Structurally checked authentication metadata and the bundle file layout it
/// declares. The maps associate each direct subject with its bundle path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticationMetadata {
    pub declared_run: DeclaredWorkflowRun,
    pub gh_bundles: BTreeMap<String, String>,
    pub cosign_bundles: BTreeMap<String, String>,
    pub expected_files: BTreeSet<String>,
    pub allowed_directories: BTreeSet<String>,
}

#[derive(Deserialize)]
struct CounterEnvelope<'a> {
    #[serde(borrow)]
    workflow_runs: Vec<CounterRun<'a>>,
}

#[derive(Deserialize)]
struct CounterRun<'a> {
    #[serde(borrow)]
    run_id: &'a RawValue,
    #[serde(borrow)]
    run_attempt: &'a RawValue,
}

/// Parse one bounded authentication metadata document against the exact raw
/// release-manifest digest, parsed assets, and already parsed publisher policy.
/// The returned run and subject mappings are declared claims, not verified
/// provenance or signature results.
pub fn parse_authentication_metadata(
    raw: &[u8],
    manifest_sha256: &str,
    assets: &[ReleaseFile],
    policy: &PublisherPolicy,
) -> Result<AuthenticationMetadata> {
    let profile = JsonProfile::PublisherPolicyAndAuthenticationMetadata;
    crate::json::check_raw_value_prepass(raw, profile)?;

    // Borrow the two integer lexemes before serde_json::Value can round a
    // Python-valid integer above u64. The complete strict tree pass follows.
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    deserializer.disable_recursion_limit();
    let counters: CounterEnvelope<'_> = CounterEnvelope::deserialize(&mut deserializer)
        .map_err(|error| Refusal::new(format!("invalid workflow counter envelope: {error}")))?;
    deserializer
        .end()
        .map_err(|error| Refusal::new(format!("invalid workflow counter envelope: {error}")))?;
    if counters.workflow_runs.len() != 1 {
        return Err(Refusal::new(
            "exactly one declared workflow run is required per host bundle",
        ));
    }
    let counter_row = &counters.workflow_runs[0];
    let (validation_copy, counter_values) = crate::workflow_counter::validation_copy(
        raw,
        &[counter_row.run_id, counter_row.run_attempt],
    )?;
    let mut counter_values = counter_values.into_iter();
    let run_id = counter_values
        .next()
        .ok_or_else(|| Refusal::new("workflow run ID is missing"))?;
    let run_attempt = counter_values
        .next()
        .ok_or_else(|| Refusal::new("workflow run attempt is missing"))?;
    if counter_values.next().is_some() {
        return Err(Refusal::new("unexpected workflow counter token"));
    }

    // This strict pass checks duplicate keys and the complete JSON tree.
    // parse_json_value keeps serde's private marker-like keys as ordinary data.
    let value = parse_json_value(&validation_copy, profile)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("authentication metadata must be an object"))?;
    if !exact_fields(
        object,
        &[
            "schema",
            "manifest_sha256",
            "workflow_runs",
            "gh_attestations",
            "cosign_bundles",
        ],
    ) {
        return Err(Refusal::new(
            "authentication metadata has unknown or missing fields",
        ));
    }

    if required_string(object.get("schema"), "authentication schema")? != AUTHENTICATION_SCHEMA {
        return Err(Refusal::new("authentication metadata schema mismatch"));
    }
    if !is_sha256_digest(manifest_sha256) {
        return Err(Refusal::new("invalid supplied release manifest SHA-256"));
    }
    let bound_manifest = required_string(
        object.get("manifest_sha256"),
        "authentication manifest SHA-256",
    )?;
    if !is_sha256_digest(bound_manifest) || bound_manifest != manifest_sha256 {
        return Err(Refusal::new(
            "authentication metadata does not bind this manifest",
        ));
    }

    let run_rows = object
        .get("workflow_runs")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == 1)
        .ok_or_else(|| Refusal::new("exactly one declared workflow run is required"))?;
    let run = run_rows[0]
        .as_object()
        .ok_or_else(|| Refusal::new("invalid workflow run metadata"))?;
    if !exact_fields(run, &["run_id", "run_attempt", "host_profile"]) {
        return Err(Refusal::new("invalid workflow run metadata"));
    }
    let host_profile = parse_host(run.get("host_profile"))?;
    if !policy.allowed_host_profiles.contains(&host_profile) {
        return Err(Refusal::new("workflow run host is not allowed by policy"));
    }
    let declared_run = DeclaredWorkflowRun {
        run_id,
        run_attempt,
        host_profile,
    };

    let asset_paths = validate_assets(assets)?;
    if !asset_paths.contains("sdk.tar.xz") || !asset_paths.contains("SHAUTIL") {
        return Err(Refusal::new(
            "required GH/Cosign subjects are absent from manifest",
        ));
    }

    let required_subjects: BTreeSet<String> = REQUIRED_SUBJECTS
        .iter()
        .map(|subject| (*subject).to_owned())
        .collect();
    let gh_bundles = parse_gh_mappings(
        object.get("gh_attestations"),
        &required_subjects,
        host_profile,
    )?;
    let cosign_bundles = parse_cosign_mappings(
        object.get("cosign_bundles"),
        &required_subjects,
        &asset_paths,
    )?;

    let mut proof_paths = Vec::with_capacity(6);
    proof_paths.extend(gh_bundles.values().cloned());
    proof_paths.extend(cosign_bundles.values().cloned());
    if proof_paths.len() != 6 {
        return Err(Refusal::new(
            "three distinct GH and three distinct Cosign bundle paths are required",
        ));
    }
    let mut folded_proof_paths = BTreeSet::new();
    if proof_paths
        .iter()
        .any(|path| !folded_proof_paths.insert(path.to_ascii_lowercase()))
    {
        return Err(Refusal::new(
            "three distinct GH and three distinct Cosign bundle paths are required",
        ));
    }

    let mut expected_files = BTreeSet::new();
    let mut folded_files = BTreeSet::new();
    for fixed in ["release.json", AUTHENTICATION_PATH, INPUTS_MANIFEST_PATH] {
        insert_expected_file(&mut expected_files, &mut folded_files, fixed)?;
    }
    for path in &asset_paths {
        insert_expected_file(&mut expected_files, &mut folded_files, path)?;
    }
    for path in &proof_paths {
        insert_expected_file(&mut expected_files, &mut folded_files, path)?;
    }

    let allowed_directories = expected_directories(&expected_files)?;
    Ok(AuthenticationMetadata {
        declared_run,
        gh_bundles,
        cosign_bundles,
        expected_files,
        allowed_directories,
    })
}

fn parse_gh_mappings(
    value: Option<&Value>,
    required_subjects: &BTreeSet<String>,
    selected_host: Host,
) -> Result<BTreeMap<String, String>> {
    let rows = value
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == required_subjects.len())
        .ok_or_else(|| {
            Refusal::new("GitHub mappings must cover exactly the three authenticated subjects")
        })?;
    let mut bundles = BTreeMap::new();
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| Refusal::new("invalid GitHub attestation mapping"))?;
        if !exact_fields(row, &["path", "host_profile", "bundle"]) {
            return Err(Refusal::new("invalid GitHub attestation mapping"));
        }
        let subject = required_string(row.get("path"), "GitHub subject")?;
        if !required_subjects.contains(subject) {
            return Err(Refusal::new(
                "GitHub attestation names an unexpected subject",
            ));
        }
        let host = parse_host(row.get("host_profile"))?;
        if host != selected_host {
            return Err(Refusal::new(
                "GitHub attestation host does not match the selected workflow run",
            ));
        }
        let bundle = required_string(row.get("bundle"), "GitHub bundle path")?;
        validate_bundle_path(bundle, ".auth/gh/")?;
        if bundles
            .insert(subject.to_owned(), bundle.to_owned())
            .is_some()
        {
            return Err(Refusal::new("duplicate GitHub subject mapping"));
        }
    }
    if bundles.len() != required_subjects.len()
        || !required_subjects
            .iter()
            .all(|subject| bundles.contains_key(subject))
    {
        return Err(Refusal::new(
            "the selected host run must attest exactly release.json, sdk.tar.xz and SHAUTIL",
        ));
    }
    Ok(bundles)
}

fn parse_cosign_mappings(
    value: Option<&Value>,
    required_subjects: &BTreeSet<String>,
    asset_paths: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    let rows = value
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == required_subjects.len())
        .ok_or_else(|| {
            Refusal::new("Cosign bundle mapping must cover exactly the required subjects")
        })?;
    let mut bundles = BTreeMap::new();
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| Refusal::new("invalid Cosign bundle mapping"))?;
        if !exact_fields(row, &["path", "bundle"]) {
            return Err(Refusal::new("invalid Cosign bundle mapping"));
        }
        let subject = required_string(row.get("path"), "Cosign subject")?;
        if !required_subjects.contains(subject) {
            return Err(Refusal::new("unexpected Cosign subject"));
        }
        if subject != "release.json" && !asset_paths.contains(subject) {
            return Err(Refusal::new(format!(
                "Cosign subject is absent from manifest: {subject}"
            )));
        }
        let bundle = required_string(row.get("bundle"), "Cosign bundle path")?;
        validate_bundle_path(bundle, ".auth/cosign/")?;
        if bundles
            .insert(subject.to_owned(), bundle.to_owned())
            .is_some()
        {
            return Err(Refusal::new("duplicate Cosign subject mapping"));
        }
    }
    if bundles.len() != required_subjects.len()
        || !required_subjects
            .iter()
            .all(|subject| bundles.contains_key(subject))
    {
        return Err(Refusal::new("incomplete Cosign subjects"));
    }
    Ok(bundles)
}

fn validate_assets(assets: &[ReleaseFile]) -> Result<BTreeSet<String>> {
    if assets.is_empty() {
        return Err(Refusal::new("manifest asset inventory is empty"));
    }
    let mut paths = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for asset in assets {
        let path = validate_bundle_relative_path(&asset.path)?;
        if path == "release.json" || path == ".auth" || path.starts_with(".auth/") {
            return Err(Refusal::new(format!(
                "duplicate or reserved manifest asset: {path}"
            )));
        }
        if !folded.insert(path.to_ascii_lowercase()) {
            return Err(Refusal::new(format!(
                "duplicate or case-colliding manifest asset: {path}"
            )));
        }
        paths.insert(path.to_owned());
    }
    for path in &paths {
        let mut parent = String::new();
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            if folded.contains(&parent.to_ascii_lowercase()) {
                return Err(Refusal::new(format!(
                    "manifest file/directory path conflict: {path}"
                )));
            }
        }
    }
    Ok(paths)
}

fn validate_bundle_path(path: &str, prefix: &str) -> Result<()> {
    validate_bundle_relative_path(path)?;
    if !path.starts_with(prefix) || !path.ends_with(".json") {
        return Err(Refusal::new(format!(
            "bundle path must be under {prefix} and end in .json"
        )));
    }
    Ok(())
}

/// Match verify_publisher.py's _rel_path lexical rules. This is deliberately
/// not filesystem validation; path resolution and symlink checks are caller
/// responsibilities.
pub(crate) fn validate_bundle_relative_path(path: &str) -> Result<&str> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || !path.bytes().all(|byte| (0x20..0x7f).contains(&byte))
    {
        return Err(Refusal::new("invalid authentication bundle path"));
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > 24
        || components.iter().any(|component| {
            component.is_empty()
                || *component == "."
                || *component == ".."
                || component.len() > 120
                || component.ends_with('.')
                || !component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
                })
        })
    {
        return Err(Refusal::new("nonportable authentication bundle path"));
    }
    Ok(path)
}

fn insert_expected_file(
    expected: &mut BTreeSet<String>,
    folded: &mut BTreeSet<String>,
    path: &str,
) -> Result<()> {
    if !folded.insert(path.to_ascii_lowercase()) || !expected.insert(path.to_owned()) {
        return Err(Refusal::new(format!(
            "duplicate or case-colliding authentication bundle file: {path}"
        )));
    }
    Ok(())
}

fn expected_directories(files: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let folded_files: BTreeSet<String> =
        files.iter().map(|path| path.to_ascii_lowercase()).collect();
    let mut directories = BTreeSet::new();
    let mut folded_directories = BTreeMap::<String, String>::new();
    for path in files {
        let mut parent = String::new();
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            let folded = parent.to_ascii_lowercase();
            if folded_files.contains(&folded) {
                return Err(Refusal::new(format!(
                    "authentication bundle file/directory path conflict: {path}"
                )));
            }
            if let Some(previous) = folded_directories.get(&folded) {
                if previous != &parent {
                    return Err(Refusal::new(format!(
                        "case-colliding authentication bundle directory: {parent}"
                    )));
                }
            } else {
                folded_directories.insert(folded, parent.clone());
            }
            directories.insert(parent.clone());
        }
    }
    Ok(directories)
}

fn parse_host(value: Option<&Value>) -> Result<Host> {
    match value.and_then(Value::as_str) {
        Some("linux-x86_64") => Ok(Host::LinuxX86_64),
        Some("macos-aarch64") => Ok(Host::MacosAarch64),
        _ => Err(Refusal::new("invalid workflow host profile")),
    }
}

fn exact_fields(object: &Map<String, Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}

fn required_string<'a>(value: Option<&'a Value>, label: &str) -> Result<&'a str> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("{label} must be a string")))
}

#[cfg(test)]
mod tests {
    use super::{AuthenticationMetadata, parse_authentication_metadata};
    use crate::{
        publisher_policy::parse_publisher_policy, release_manifest::parse_release_manifest,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    const MANIFEST_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn policy() -> crate::publisher_policy::PublisherPolicy {
        let value = json!({
            "schema": "ami-rust-publisher-trust-v2",
            "repository": "metaneutrons/ami-rust",
            "workflow": ".github/workflows/sdk-qualify.yml",
            "workflow_sha": "1".repeat(40),
            "source_sha": "2".repeat(40),
            "source_ref": "refs/heads/main",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "cert_identity": "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
            "inputs_manifest_sha256": "3".repeat(64),
            "allowed_host_profiles": ["macos-aarch64", "linux-x86_64"],
            "gh": {"path": "/usr/bin/gh", "sha256": "4".repeat(64)},
            "cosign": {"path": "/usr/bin/cosign", "sha256": "5".repeat(64)},
            "gh_trusted_roots": {"path": "/etc/gh-roots.jsonl", "sha256": "6".repeat(64)},
            "cosign_trusted_root": {"path": "/etc/cosign-root.json", "sha256": "7".repeat(64)}
        });
        parse_publisher_policy(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn assets() -> Vec<crate::release_manifest::ReleaseFile> {
        let value = json!({
            "schema": "ami-rust-release-v1",
            "version": "1.0.0",
            "qualification_only": false,
            "sdk_archive": "sdk.tar.xz",
            "sdk_manifest_sha256": "c".repeat(64),
            "assets": [
                {"path": "sdk.tar.xz", "bytes": 12, "sha256": "8".repeat(64)},
                {"path": "SHAUTIL", "bytes": 4, "sha256": "9".repeat(64)},
                {"path": "docs/readme.txt", "bytes": 3, "sha256": "b".repeat(64)}
            ],
            "sdk_files": [
                {"path": "contract/sdk.json", "bytes": 1, "sha256": "c".repeat(64)}
            ],
            "producer": {"fixture": true},
            "host_interpreters": {
                "linux-x86_64": {"sha256": "d".repeat(64)},
                "macos-aarch64": {"sha256": "e".repeat(64)}
            }
        });
        parse_release_manifest(&serde_json::to_vec(&value).unwrap(), true)
            .unwrap()
            .assets
    }

    fn valid_auth() -> Value {
        let subjects = ["release.json", "sdk.tar.xz", "SHAUTIL"];
        json!({
            "schema": "ami-rust-authentication-v2",
            "manifest_sha256": MANIFEST_SHA,
            "workflow_runs": [{
                "run_id": 123456789,
                "run_attempt": 2,
                "host_profile": "macos-aarch64"
            }],
            "gh_attestations": subjects.iter().map(|subject| json!({
                "path": subject,
                "host_profile": "macos-aarch64",
                "bundle": format!(".auth/gh/gh-{}.json", subject.replace('.', "-"))
            })).collect::<Vec<_>>(),
            "cosign_bundles": subjects.iter().map(|subject| json!({
                "path": subject,
                "bundle": format!(".auth/cosign/cosign-{}.json", subject.replace('.', "-"))
            })).collect::<Vec<_>>()
        })
    }

    fn raw(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn parse(value: &Value) -> crate::Result<AuthenticationMetadata> {
        parse_authentication_metadata(&raw(value), MANIFEST_SHA, &assets(), &policy())
    }

    fn assert_refused(value: &Value) {
        assert!(parse(value).is_err(), "accepted fixture: {value}");
    }

    #[test]
    fn parses_declared_run_mappings_and_expected_tree_without_authenticating_them() {
        let parsed = parse(&valid_auth()).unwrap();
        assert_eq!(parsed.declared_run.run_id.as_decimal(), "123456789");
        assert_eq!(parsed.declared_run.run_attempt.as_decimal(), "2");
        assert_eq!(
            parsed.declared_run.host_profile,
            crate::records::Host::MacosAarch64
        );
        assert_eq!(parsed.gh_bundles.len(), 3);
        assert_eq!(parsed.cosign_bundles.len(), 3);
        assert!(parsed.expected_files.contains("release.json"));
        assert!(parsed.expected_files.contains(".auth/authentication.json"));
        assert!(parsed.expected_files.contains(".auth/inputs.json"));
        assert!(parsed.expected_files.contains("docs/readme.txt"));
        assert_eq!(
            parsed.allowed_directories,
            BTreeSet::from([
                ".auth".to_owned(),
                ".auth/cosign".to_owned(),
                ".auth/gh".to_owned(),
                "docs".to_owned(),
            ])
        );
    }

    #[test]
    fn rejects_schema_unknown_fields_and_manifest_binding_errors() {
        let mut value = valid_auth();
        value["schema"] = json!("ami-rust-authentication-v1");
        assert_refused(&value);

        let mut value = valid_auth();
        value["future"] = json!(true);
        assert_refused(&value);

        let mut value = valid_auth();
        value["manifest_sha256"] = json!("A".repeat(64));
        assert_refused(&value);

        let value = valid_auth();
        assert!(
            parse_authentication_metadata(&raw(&value), "not-a-digest", &assets(), &policy())
                .is_err()
        );
        assert!(
            parse_authentication_metadata(&raw(&value), &"f".repeat(64), &assets(), &policy())
                .is_err()
        );
    }

    #[test]
    fn rejects_disallowed_or_mismatched_hosts_and_invalid_subject_sets() {
        let mut value = valid_auth();
        value["workflow_runs"][0]["host_profile"] = json!("plan9-i386");
        assert_refused(&value);

        let mut value = valid_auth();
        value["workflow_runs"][0]["host_profile"] = json!("linux-x86_64");
        assert_refused(&value);

        let mut value = valid_auth();
        value["gh_attestations"][0]["host_profile"] = json!("linux-x86_64");
        assert_refused(&value);

        let mut value = valid_auth();
        value["gh_attestations"][0]["path"] = json!("unexpected.bin");
        assert_refused(&value);

        let mut value = valid_auth();
        value["cosign_bundles"][0]["path"] = json!("unexpected.bin");
        assert_refused(&value);

        let mut value = valid_auth();
        value["cosign_bundles"][1]["path"] = json!("release.json");
        assert_refused(&value);
    }

    #[test]
    fn rejects_nonportable_aliasing_and_reserved_asset_paths() {
        let mut value = valid_auth();
        value["gh_attestations"][0]["bundle"] = json!(".auth/gh/shared.json");
        value["gh_attestations"][1]["bundle"] = json!(".auth/gh/SHARED.json");
        assert_refused(&value);

        let mut value = valid_auth();
        value["gh_attestations"][0]["bundle"] = json!(".auth/gh/../bad.json");
        assert_refused(&value);

        let mut value = valid_auth();
        value["gh_attestations"][0]["bundle"] = json!(".auth/gh/branch.json");
        value["gh_attestations"][1]["bundle"] = json!(".auth/gh/branch.json/child.json");
        assert_refused(&value);

        let mut reserved_assets = assets();
        reserved_assets[0].path = ".auth/asset.json".to_owned();
        assert!(
            parse_authentication_metadata(
                &raw(&valid_auth()),
                MANIFEST_SHA,
                &reserved_assets,
                &policy()
            )
            .is_err()
        );
    }

    #[test]
    fn preserves_python_valid_large_workflow_integer_lexemes() {
        let source = String::from_utf8(raw(&valid_auth())).unwrap();
        let u64_plus_one = source.replace("123456789", "18446744073709551616");
        let parsed = parse_authentication_metadata(
            u64_plus_one.as_bytes(),
            MANIFEST_SHA,
            &assets(),
            &policy(),
        )
        .unwrap();
        assert_eq!(
            parsed.declared_run.run_id.as_decimal(),
            "18446744073709551616"
        );

        let four_thousand_three_hundred = format!("1{}", "9".repeat(4_299));
        let source = String::from_utf8(raw(&valid_auth())).unwrap();
        let exact = source.replace("123456789", &four_thousand_three_hundred);
        let parsed =
            parse_authentication_metadata(exact.as_bytes(), MANIFEST_SHA, &assets(), &policy())
                .unwrap();
        assert_eq!(
            parsed.declared_run.run_id.as_decimal(),
            four_thousand_three_hundred
        );

        let too_long = format!("1{}", "9".repeat(4_300));
        let over_limit = source.replace("123456789", &too_long);
        assert!(
            parse_authentication_metadata(
                over_limit.as_bytes(),
                MANIFEST_SHA,
                &assets(),
                &policy()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_noninteger_counters_and_duplicate_json_keys() {
        let source = String::from_utf8(raw(&valid_auth())).unwrap();
        for token in ["1.0", "1e10", "-1", "0"] {
            let hostile = source.replace("123456789", token);
            assert!(
                parse_authentication_metadata(
                    hostile.as_bytes(),
                    MANIFEST_SHA,
                    &assets(),
                    &policy()
                )
                .is_err(),
                "accepted run_id token {token}"
            );
        }

        let duplicate = source.replacen(
            "\"schema\":\"ami-rust-authentication-v2\"",
            "\"schema\":\"ami-rust-authentication-v2\",\"schema\":\"ami-rust-authentication-v2\"",
            1,
        );
        assert!(
            parse_authentication_metadata(duplicate.as_bytes(), MANIFEST_SHA, &assets(), &policy())
                .is_err()
        );
    }

    #[test]
    fn treats_private_raw_value_marker_as_an_ordinary_unknown_field() {
        let mut value = valid_auth();
        value["$serde_json::private::RawValue"] = json!({"secret": true});
        let error = parse(&value).unwrap_err().to_string();
        assert!(error.contains("unknown or missing fields"), "{error}");
    }

    #[test]
    fn checks_raw_json_container_depth_before_typed_validation() {
        let source = String::from_utf8(raw(&valid_auth())).unwrap();
        let mut at_limit = source[..source.len() - 1].to_owned();
        at_limit.push_str(",\"extra\":");
        at_limit.push_str(&"[".repeat(127));
        at_limit.push_str("null");
        at_limit.push_str(&"]".repeat(127));
        at_limit.push('}');
        let error =
            parse_authentication_metadata(at_limit.as_bytes(), MANIFEST_SHA, &assets(), &policy())
                .unwrap_err()
                .to_string();
        assert!(error.contains("unknown or missing fields"), "{error}");

        let mut over_limit = source[..source.len() - 1].to_owned();
        over_limit.push_str(",\"extra\":");
        over_limit.push_str(&"[".repeat(128));
        over_limit.push_str("null");
        over_limit.push_str(&"]".repeat(128));
        over_limit.push('}');
        let error = parse_authentication_metadata(
            over_limit.as_bytes(),
            MANIFEST_SHA,
            &assets(),
            &policy(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("depth"), "{error}");
    }
}

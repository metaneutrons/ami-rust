//! Closed installation receipt records. Parsing establishes structural
//! consistency only: it does not verify a publisher, an external receipt pin,
//! release-manifest binding, installed bytes, or ownership.
//!
//! Legacy v1/v2 records are inspection/uninstall inputs only. Only v3 may bind
//! a native Rust driver, after those separate checks pass.

use crate::{
    Refusal, Result,
    json::{JsonProfile, parse_json_value},
    records::{Host, Sha256},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const POLICY_EVIDENCE: &str = "environment and runnerEnvironment are signed SLSA predicate claims verified under the exact pinned workflow SHA; they are not independent Fulcio certificate fields";
pub(crate) const VERIFICATION_MODE: &str =
    "offline pinned GH bundle/custom root and Cosign bundle/trusted root";
const MAX_LEGACY_INVENTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_NATIVE_INVENTORY_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptKind {
    LegacyQualificationV1,
    HistoricalProductionV2,
    NativeV3,
}

impl ReceiptKind {
    pub fn is_native_schema(self) -> bool {
        self == Self::NativeV3
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: Sha256,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub report: PublisherReport,
    pub external_policy_sha256: Sha256,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublisherReport {
    pub schema: String,
    pub verified: bool,
    pub repository: String,
    pub workflow: String,
    pub workflow_sha: String,
    pub source_sha: String,
    pub source_ref: String,
    pub manifest_sha256: Sha256,
    pub workflow_runs: Vec<WorkflowRun>,
    pub attested_subjects: Vec<String>,
    pub manifest_bound_assets: Vec<String>,
    pub cosign_subjects: Vec<String>,
    pub publisher_policy_evidence: String,
    pub verification_mode: String,
    pub elapsed_seconds: serde_json::Number,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowRun {
    pub run_id: PositiveCounter,
    pub run_attempt: PositiveCounter,
    pub host_profile: Host,
}

pub use crate::workflow_counter::PositiveCounter;

#[derive(Deserialize)]
struct CounterEnvelope<'a> {
    #[serde(borrow)]
    authentication: Option<CounterAuthentication<'a>>,
}
#[derive(Deserialize)]
struct CounterAuthentication<'a> {
    #[serde(borrow)]
    report: CounterReport<'a>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CounterReport<'a> {
    #[serde(borrow)]
    workflow_runs: Vec<CounterRun<'a>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CounterRun<'a> {
    #[serde(borrow)]
    run_id: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    run_attempt: &'a serde_json::value::RawValue,
}

type CounterPair = (PositiveCounter, PositiveCounter);

fn counter_validation_copy(raw: &[u8]) -> Result<(Vec<u8>, Vec<CounterPair>)> {
    if raw.len() > JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes() {
        return Err(Refusal::new("oversized installation receipt"));
    }
    check_prepass_depth(raw)?;
    // This bounded typed prepass borrows numeric tokens only. It never marks a
    // record valid: the complete duplicate/depth/exact-schema pass follows.
    // Ignored fields are not interpreted or followed. raw_value does not alter
    // serde_json's global number behavior, unlike arbitrary_precision.
    let envelope: CounterEnvelope<'_> = serde_json::from_slice(raw)
        .map_err(|error| Refusal::new(format!("invalid receipt counter envelope: {error}")))?;
    let tokens: Vec<_> = envelope
        .authentication
        .into_iter()
        .flat_map(|authentication| authentication.report.workflow_runs)
        .flat_map(|run| [run.run_id, run.run_attempt])
        .collect();
    let (copy, counters) = crate::workflow_counter::validation_copy(raw, &tokens)?;
    let mut counters = counters.into_iter();
    let mut pairs = Vec::new();
    while let Some(id) = counters.next() {
        let attempt = counters
            .next()
            .ok_or_else(|| Refusal::new("incomplete workflow counter pair"))?;
        pairs.push((id, attempt));
    }
    Ok((copy, pairs))
}

fn check_prepass_depth(raw: &[u8]) -> Result<()> {
    crate::json::check_raw_value_prepass(raw, JsonProfile::ReleaseManifestAndInstallReceipt)
}

#[derive(Debug)]
pub struct NativeIdentity {
    pub host: Host,
    pub cli_sha256: Sha256,
    pub core_sha256: Sha256,
}

#[derive(Debug)]
pub struct InstallReceipt {
    pub kind: ReceiptKind,
    pub publisher: String,
    pub release_manifest_sha256: Sha256,
    pub sdk_manifest_sha256: Sha256,
    pub version: String,
    pub inventory: Vec<ReceiptFile>,
    pub authentication: Option<Authentication>,
    pub native: Option<NativeIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    #[serde(rename = "schema")]
    _schema: String,
    publisher: String,
    release_manifest_sha256: Sha256,
    sdk_manifest_sha256: Sha256,
    version: String,
    inventory: Vec<ReceiptFile>,
    authentication: Option<Authentication>,
    host: Option<Host>,
    cli_sha256: Option<Sha256>,
    core_sha256: Option<Sha256>,
}

pub fn parse_install_receipt(raw: &[u8]) -> Result<InstallReceipt> {
    let (validation, counters) = counter_validation_copy(raw)?;
    let value = parse_json_value(&validation, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("installation receipt must be an object"))?;
    let kind = match object.get("schema").and_then(|schema| schema.as_str()) {
        Some("ami-rust-install-receipt-v1") => ReceiptKind::LegacyQualificationV1,
        Some("ami-rust-install-receipt-v2") => ReceiptKind::HistoricalProductionV2,
        Some("ami-rust-install-receipt-v3") => ReceiptKind::NativeV3,
        _ => {
            return Err(Refusal::new(
                "incompatible or missing installation receipt schema",
            ));
        }
    };
    let mut fields = BTreeSet::from([
        "schema",
        "publisher",
        "release_manifest_sha256",
        "sdk_manifest_sha256",
        "version",
        "inventory",
    ]);
    if kind != ReceiptKind::LegacyQualificationV1 {
        fields.insert("authentication");
    }
    if kind == ReceiptKind::NativeV3 {
        fields.extend(["host", "cli_sha256", "core_sha256"]);
    }
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != fields {
        return Err(Refusal::new(
            "installation receipt fields do not match its exact schema",
        ));
    }
    let mut wire = Wire::deserialize(value)
        .map_err(|error| Refusal::new(format!("invalid installation receipt: {error}")))?;
    if let Some(authentication) = &mut wire.authentication {
        if authentication.report.workflow_runs.len() != counters.len() {
            return Err(Refusal::new(
                "workflow counter envelope differs from the validated receipt",
            ));
        }
        for (run, (id, attempt)) in authentication.report.workflow_runs.iter_mut().zip(counters) {
            run.run_id = id;
            run.run_attempt = attempt;
        }
    }
    if !valid_version(&wire.version) {
        return Err(Refusal::new("invalid receipt version"));
    }
    if kind == ReceiptKind::LegacyQualificationV1 {
        if wire.publisher.is_empty()
            || wire.publisher.len() > 200
            || !wire
                .publisher
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte))
        {
            return Err(Refusal::new("invalid legacy receipt publisher"));
        }
    } else if wire.publisher != "metaneutrons.ami-rust.github" {
        return Err(Refusal::new("invalid production receipt publisher"));
    }
    if kind != ReceiptKind::LegacyQualificationV1 {
        let authentication = wire
            .authentication
            .as_ref()
            .ok_or_else(|| Refusal::new("production receipt requires authentication evidence"))?;
        validate_authentication(authentication, &wire.release_manifest_sha256)?;
    }
    validate_inventory(&wire.inventory, kind)?;
    let native = if kind == ReceiptKind::NativeV3 {
        let host = wire
            .host
            .ok_or_else(|| Refusal::new("native receipt requires a host"))?;
        let cli_sha256 = wire
            .cli_sha256
            .ok_or_else(|| Refusal::new("native receipt requires CLI identity"))?;
        let core_sha256 = wire
            .core_sha256
            .ok_or_else(|| Refusal::new("native receipt requires core identity"))?;
        if cli_sha256 != core_sha256 {
            return Err(Refusal::new("static CLI and shared-core identities differ"));
        }
        Some(NativeIdentity {
            host,
            cli_sha256,
            core_sha256,
        })
    } else {
        None
    };
    Ok(InstallReceipt {
        kind,
        publisher: wire.publisher,
        release_manifest_sha256: wire.release_manifest_sha256,
        sdk_manifest_sha256: wire.sdk_manifest_sha256,
        version: wire.version,
        inventory: wire.inventory,
        authentication: wire.authentication,
        native,
    })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+_-".contains(&byte))
}

fn validate_inventory(files: &[ReceiptFile], kind: ReceiptKind) -> Result<()> {
    if files.is_empty() || files.len() > 2002 {
        return Err(Refusal::new("invalid receipt inventory length"));
    }
    let mut paths = BTreeMap::new();
    let mut total = 0_u64;
    let max_inventory_bytes = if kind == ReceiptKind::NativeV3 {
        MAX_NATIVE_INVENTORY_BYTES
    } else {
        MAX_LEGACY_INVENTORY_BYTES
    };
    for file in files {
        crate::publisher_tar::validate_portable_path(file.path.as_bytes())?;
        if !(file.path.starts_with("sdk/") || file.path.starts_with("payload/")) {
            return Err(Refusal::new("receipt path is outside sdk/ and payload/"));
        }
        if paths
            .insert(file.path.to_ascii_lowercase(), &file.path)
            .is_some()
        {
            return Err(Refusal::new("duplicate or case-colliding receipt file"));
        }
        total = total
            .checked_add(file.bytes)
            .filter(|total| *total <= max_inventory_bytes)
            .ok_or_else(|| Refusal::new("receipt inventory exceeds its byte profile"))?;
    }
    for file in files {
        for (offset, _) in file.path.match_indices('/') {
            if paths.contains_key(&file.path[..offset].to_ascii_lowercase()) {
                return Err(Refusal::new("receipt file is also a directory ancestor"));
            }
        }
    }
    for required in [
        "payload/release.json",
        "payload/release.json.sig",
        "sdk/contract/sdk.json",
    ] {
        if !files.iter().any(|file| file.path == required) {
            return Err(Refusal::new("receipt inventory omits required metadata"));
        }
    }
    Ok(())
}

fn validate_authentication(authentication: &Authentication, manifest: &Sha256) -> Result<()> {
    let report = &authentication.report;
    if report.schema != "ami-rust-publisher-verification-v2"
        || !report.verified
        || report.repository != "metaneutrons/ami-rust"
        || report.workflow != ".github/workflows/sdk-qualify.yml"
        || report.source_ref != "refs/heads/main"
        || &report.manifest_sha256 != manifest
        || report.publisher_policy_evidence != POLICY_EVIDENCE
        || report.verification_mode != VERIFICATION_MODE
    {
        return Err(Refusal::new(
            "publisher report identity or manifest binding mismatch",
        ));
    }
    for commit in [&report.workflow_sha, &report.source_sha] {
        if commit.len() != 40
            || !commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Refusal::new("invalid publisher report commit identity"));
        }
    }
    let direct = ["SHAUTIL", "release.json", "sdk.tar.xz"];
    if report.attested_subjects != direct || report.cosign_subjects != direct {
        return Err(Refusal::new("publisher report subject identity mismatch"));
    }
    if report.manifest_bound_assets.is_empty()
        || report
            .manifest_bound_assets
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(Refusal::new(
            "invalid publisher report manifest-bound assets",
        ));
    }
    if report.workflow_runs.len() != 1 {
        return Err(Refusal::new(
            "publisher report requires exactly one positive workflow run",
        ));
    }
    if !report
        .elapsed_seconds
        .as_f64()
        .is_some_and(|value| value.is_finite() && (0.0..=300.0).contains(&value))
    {
        return Err(Refusal::new("invalid publisher report elapsed time"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture(version: u8) -> Value {
        let mut value = json!({
            "schema":format!("ami-rust-install-receipt-v{version}"),
            "publisher":if version == 1 { "fixture-publisher" } else { "metaneutrons.ami-rust.github" },
            "release_manifest_sha256":"a".repeat(64), "sdk_manifest_sha256":"b".repeat(64),
            "version":"0.2.0-dev", "inventory": [
                {"path":"payload/release.json", "bytes":0, "sha256":"c".repeat(64)},
                {"path":"payload/release.json.sig", "bytes":0, "sha256":"d".repeat(64)},
                {"path":"sdk/contract/sdk.json", "bytes":0, "sha256":"e".repeat(64)}
            ]
        });
        if version != 1 {
            value["authentication"] = json!({"external_policy_sha256":"f".repeat(64), "report":{
                "schema":"ami-rust-publisher-verification-v2", "verified":true,
                "repository":"metaneutrons/ami-rust", "workflow":".github/workflows/sdk-qualify.yml",
                "workflowSha":"1".repeat(40), "sourceSha":"2".repeat(40), "sourceRef":"refs/heads/main",
                "manifestSha256":"a".repeat(64),
                "workflowRuns":[{"runId":39181868987_u64, "runAttempt":1, "hostProfile":"linux-x86_64"}],
                "attestedSubjects":["SHAUTIL","release.json","sdk.tar.xz"],
                "cosignSubjects":["SHAUTIL","release.json","sdk.tar.xz"],
                "manifestBoundAssets":["SHAUTIL","sdk.tar.xz"],
                "publisherPolicyEvidence":POLICY_EVIDENCE, "verificationMode":VERIFICATION_MODE, "elapsedSeconds":0.5
            }});
        }
        if version == 3 {
            value["host"] = json!("macos-aarch64");
            value["cli_sha256"] = json!("3".repeat(64));
            value["core_sha256"] = json!("3".repeat(64));
        }
        value
    }
    fn parse(value: &Value) -> Result<InstallReceipt> {
        parse_install_receipt(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn raw_value_wrapper_cannot_replace_the_actual_receipt_root() {
        for version in 1..=3 {
            let wrapped = json!({"$serde_json::private::RawValue":fixture(version).to_string()});
            assert!(
                parse(&wrapped).is_err(),
                "accepted wrapped receipt v{version}"
            );
        }
    }

    #[test]
    fn matches_fourteen_pinned_historical_receipt_fixtures() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/receipts");
        let oracle: Value =
            serde_json::from_slice(&std::fs::read(root.join("oracle.json")).unwrap()).unwrap();
        let cases = oracle["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 14);
        let mut names = BTreeSet::new();
        for case in cases {
            let name = case["case"].as_str().unwrap();
            assert!(names.insert(name));
            let raw = std::fs::read(root.join(case["input"].as_str().unwrap())).unwrap();
            assert_eq!(
                crate::digest::sha256_bytes(&raw),
                case["input_sha256"].as_str().unwrap()
            );
            let result = parse_install_receipt(&raw);
            assert_eq!(
                result.is_ok(),
                case["decision"] == "accept",
                "{name}: {result:?}"
            );
            if let Ok(receipt) = result {
                let schema = match receipt.kind {
                    ReceiptKind::LegacyQualificationV1 => "ami-rust-install-receipt-v1",
                    ReceiptKind::HistoricalProductionV2 => "ami-rust-install-receipt-v2",
                    ReceiptKind::NativeV3 => panic!("historical oracle does not accept v3"),
                };
                assert_eq!(
                    json!({"schema":schema,"publisher":receipt.publisher,"version":receipt.version,
                    "release_manifest_sha256":receipt.release_manifest_sha256,
                    "sdk_manifest_sha256":receipt.sdk_manifest_sha256}),
                    case["receipt"]
                );
                let mut inventory = receipt.inventory;
                inventory.sort_by(|left, right| left.path.cmp(&right.path));
                assert_eq!(
                    serde_json::to_value(inventory).unwrap(),
                    case["typed_inventory"],
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn preserves_large_workflow_counter_tokens_under_the_pinned_oracle_digit_bound() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/receipts/integers");
        let oracle: Value =
            serde_json::from_slice(&std::fs::read(root.join("oracle.json")).unwrap()).unwrap();
        let cases = oracle["results"].as_array().unwrap();
        assert_eq!(cases.len(), 6);
        for case in cases {
            let raw = std::fs::read(root.join(case["input"].as_str().unwrap())).unwrap();
            assert_eq!(
                crate::digest::sha256_bytes(&raw),
                case["input_sha256"].as_str().unwrap()
            );
            let result = parse_install_receipt(&raw);
            assert_eq!(
                result.is_ok(),
                case["decision"] == "accept",
                "{}: {result:?}",
                case["case"]
            );
            if let Ok(receipt) = result {
                let envelope: CounterEnvelope<'_> = serde_json::from_slice(&raw).unwrap();
                let counters = envelope.authentication.unwrap().report.workflow_runs;
                let report = receipt.authentication.unwrap().report;
                assert_eq!(
                    report.workflow_runs[0].run_id.as_decimal(),
                    counters[0].run_id.get()
                );
                assert_eq!(
                    serde_json::to_string(&report.workflow_runs[0].run_id).unwrap(),
                    counters[0].run_id.get()
                );
            }
        }
    }

    #[test]
    fn large_counter_prepass_does_not_hide_duplicates_or_reinterpret_json_objects() {
        let base = serde_json::to_string(&fixture(2)).unwrap();
        let digits = "9".repeat(4300);
        let raw = base.replace("39181868987", &digits);
        assert!(
            parse_install_receipt(
                raw.replace("\"verified\":true", "\"verified\":true,\"verified\":true")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_install_receipt(
                raw.replace("\"runAttempt\":1", "\"runAttempt\":1,\"runAttempt\":1")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_install_receipt(
                raw.replace("\"bytes\":0", "\"bytes\":0,\"bytes\":0")
                    .as_bytes()
            )
            .is_err()
        );
        for object in [
            "{\"$serde_json::private::Number\":\"1\"}",
            "{\"$serde_json::private::RawValue\":\"1\"}",
        ] {
            assert!(parse_install_receipt(base.replace("39181868987", object).as_bytes()).is_err());
        }
    }

    #[test]
    fn counter_prepass_enforces_exact_depth_before_ignored_children() {
        let depth = crate::json::JSON_MAX_CONTAINER_DEPTH;
        let exact = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(check_prepass_depth(exact.as_bytes()).is_ok());
        assert!(check_prepass_depth(format!("[{exact}]").as_bytes()).is_err());
        let quoted =
            serde_json::to_vec(&format!("{}\\\"{}", "[".repeat(1000), "}".repeat(1000))).unwrap();
        assert!(check_prepass_depth(&quoted).is_ok());
        let hostile = format!(
            "{{\"ignored\":{}0{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(
            counter_validation_copy(hostile.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("container depth")
        );
    }

    #[test]
    fn parses_all_three_schemas_and_never_promotes_historical_drivers() {
        for version in 1..=3 {
            let parsed = parse(&fixture(version)).unwrap();
            assert_eq!(parsed.kind.is_native_schema(), version == 3);
            assert_eq!(parsed.authentication.is_some(), version != 1);
            assert_eq!(parsed.native.is_some(), version == 3);
        }
    }

    #[test]
    fn exact_schema_fields_refuse_legacy_null_extensions_and_missing_native_identity() {
        for version in 1..=3 {
            let mut value = fixture(version);
            value["schema"] = json!("ami-rust-install-receipt-v999");
            assert!(parse(&value).is_err());
            let mut value = fixture(version);
            value.as_object_mut().unwrap().remove("schema");
            assert!(parse(&value).is_err());
            let mut value = fixture(version);
            value["unknown"] = Value::Null;
            assert!(parse(&value).is_err());
        }
        let mut value = fixture(1);
        value["authentication"] = Value::Null;
        assert!(parse(&value).is_err());
        for key in ["host", "cli_sha256", "core_sha256", "authentication"] {
            let mut value = fixture(3);
            value.as_object_mut().unwrap().remove(key);
            assert!(parse(&value).is_err());
            let mut value = fixture(3);
            value[key] = Value::Null;
            assert!(parse(&value).is_err());
        }
        let mut value = fixture(3);
        value["core_sha256"] = json!("4".repeat(64));
        assert!(parse(&value).is_err());
    }

    #[test]
    fn inventory_refuses_bad_types_paths_identity_and_ancestor_collisions() {
        for invalid in [
            json!(true),
            json!(-1),
            json!(0.5),
            json!(64 * 1024 * 1024 + 1_u64),
        ] {
            let mut value = fixture(1);
            value["inventory"][0]["bytes"] = invalid;
            assert!(parse(&value).is_err());
        }
        for path in [
            "sdk/../escape",
            "sdk/CON",
            "payload/outside.",
            "outside/file",
            "sdk/ü",
        ] {
            let mut value = fixture(1);
            value["inventory"][0]["path"] = json!(path);
            assert!(parse(&value).is_err());
        }
        for path in [
            "sdk/contract/sdk.json",
            "SDK/contract/sdk.json",
            "sdk/contract",
        ] {
            let mut value = fixture(1);
            value["inventory"][0]["path"] = json!(path);
            assert!(parse(&value).is_err());
        }
        let mut value = fixture(1);
        value["inventory"][0]["sha256"] = json!("A".repeat(64));
        assert!(parse(&value).is_err());
        let mut value = fixture(1);
        value["inventory"].as_array_mut().unwrap().pop();
        assert!(parse(&value).is_err());
        let mut value = fixture(1);
        value["inventory"][0]["mode"] = json!(0o644);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn inventory_count_and_total_profile_accept_exact_boundary_only() {
        let mut value = fixture(1);
        value["inventory"][0]["bytes"] = json!(64 * 1024 * 1024_u64);
        assert!(parse(&value).is_ok());
        value["inventory"][1]["bytes"] = json!(1);
        assert!(parse(&value).is_err());

        let mut historical = fixture(2);
        historical["inventory"][0]["bytes"] = json!(64 * 1024 * 1024_u64 + 1);
        assert!(parse(&historical).is_err());

        let mut native = fixture(3);
        native["inventory"][0]["bytes"] = json!(64 * 1024 * 1024_u64 + 1);
        assert!(parse(&native).is_ok());
        native["inventory"][0]["bytes"] = json!(128 * 1024 * 1024_u64);
        assert!(parse(&native).is_ok());
        native["inventory"][1]["bytes"] = json!(1);
        assert!(parse(&native).is_err());

        let mut value = fixture(1);
        for index in 3..2002 {
            value["inventory"].as_array_mut().unwrap().push(
                json!({"path":format!("sdk/file-{index}"),"bytes":0,"sha256":"0".repeat(64)}),
            );
        }
        assert!(parse(&value).is_ok());
        value["inventory"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":"sdk/excess","bytes":0,"sha256":"0".repeat(64)}));
        assert!(parse(&value).is_err());
    }

    #[test]
    fn rejects_nested_unknown_keys_duplicate_keys_and_nonfinite_authentication() {
        for path in [
            "/authentication",
            "/authentication/report",
            "/authentication/report/workflowRuns/0",
        ] {
            let mut value = fixture(2);
            value.pointer_mut(path).unwrap()["extra"] = json!(true);
            assert!(parse(&value).is_err());
        }
        let raw = serde_json::to_string(&fixture(2)).unwrap();
        assert!(
            parse_install_receipt(
                raw.replace("\"verified\":true", "\"verified\":true,\"verified\":true")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_install_receipt(
                raw.replace("\"elapsedSeconds\":0.5", "\"elapsedSeconds\":1e999")
                    .as_bytes()
            )
            .is_err()
        );
        let mut value = fixture(2);
        value["authentication"]["report"]["elapsedSeconds"] = json!(true);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn publisher_reports_refuse_identity_subject_run_and_manifest_mismatch() {
        for (key, invalid) in [
            ("repository", json!("other/repo")),
            ("verified", json!(false)),
            ("manifestSha256", json!("f".repeat(64))),
            ("workflowSha", json!("A".repeat(40))),
            ("elapsedSeconds", json!(301)),
            ("sourceRef", json!("refs/heads/untrusted")),
            ("attestedSubjects", json!(["release.json"])),
            ("cosignSubjects", json!(["release.json"])),
            ("manifestBoundAssets", json!(["sdk.tar.xz", "SHAUTIL"])),
            ("workflowRuns", json!([])),
        ] {
            let mut value = fixture(2);
            value["authentication"]["report"][key] = invalid;
            assert!(parse(&value).is_err(), "{key}");
        }
        for invalid in [json!(0), json!(true), json!(-1), json!(1.0)] {
            let mut value = fixture(2);
            value["authentication"]["report"]["workflowRuns"][0]["runId"] = invalid;
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn legacy_publisher_and_version_use_the_frozen_ascii_rules() {
        for publisher in ["", "not publisher", "ü", &"x".repeat(201)] {
            let mut value = fixture(1);
            value["publisher"] = json!(publisher);
            assert!(parse(&value).is_err());
        }
        for version in ["", ".invalid", "not version", &"x".repeat(65)] {
            let mut value = fixture(1);
            value["version"] = json!(version);
            assert!(parse(&value).is_err());
        }
    }
}

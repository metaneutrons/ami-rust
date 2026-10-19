//! Check claims returned by a successful, separately pinned GH verifier.
//! This pure parser does not verify a signature or execute a verifier. Raw
//! bundle claims cannot substitute for the successful external CLI boundary.
use crate::{
    Refusal, Result,
    digest::is_sha256_digest,
    json::{JsonProfile, parse_json_value},
    publisher_policy::{PinnedMaterial, PublisherPolicy},
    records::Host,
    workflow_counter::PositiveCounter,
};
use serde_json::{Map, Value, json};

const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
const BUILD_TYPE: &str = "https://actions.github.io/buildtypes/workflow/v1";

pub struct PublisherClaimContext<'a> {
    pub policy: &'a PublisherPolicy,
    pub run_id: &'a PositiveCounter,
    pub run_attempt: &'a PositiveCounter,
    pub host: Host,
    pub subject: &'a str,
    pub subject_sha256: &'a str,
    pub materials: &'a [PinnedMaterial],
}

fn refuse(message: &str) -> Refusal {
    Refusal::new(message)
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| Refusal::new(format!("invalid {label}")))
}

fn exact(value: &Map<String, Value>, fields: &[&str]) -> bool {
    value.len() == fields.len() && fields.iter().all(|field| value.contains_key(*field))
}

fn member<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| Refusal::new(format!("missing publisher claim: {field}")))
}

/// Check the one-result GH JSON format, subject and frozen signed workflow
/// claims. The caller must have obtained these bytes from the exact pinned
/// successful command, with the policy identity selectors and trusted root.
pub fn check_github_output(raw: &[u8], context: PublisherClaimContext<'_>) -> Result<()> {
    if !["release.json", "sdk.tar.xz", "SHAUTIL"].contains(&context.subject) {
        return Err(refuse("invalid expected publisher subject"));
    }
    check_expected_github_output(raw, context)
}

/// The public transport has a separate, closed four-subject contract. It does
/// not acquire the inner bundle's installation authority through this parser.
pub fn check_outer_github_output(
    raw: &[u8],
    context: PublisherClaimContext<'_>,
    sdk_version: &str,
) -> Result<()> {
    if sdk_version.is_empty()
        || sdk_version.len() > 64
        || !sdk_version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+_-".contains(&b))
    {
        return Err(refuse("invalid outer SDK version"));
    }
    let payload = format!("ami-rust-{sdk_version}-release.tar.xz");
    let subjects = [
        payload.clone(),
        format!("{payload}.spdx.json"),
        format!("ami-rust-{sdk_version}-transport.json"),
        "SHA256SUMS".to_owned(),
    ];
    if !subjects.iter().any(|subject| subject == context.subject)
        || context.host != Host::LinuxX86_64
    {
        return Err(refuse("invalid outer publisher subject or host"));
    }
    check_expected_github_output(raw, context)
}

fn check_expected_github_output(raw: &[u8], context: PublisherClaimContext<'_>) -> Result<()> {
    if !is_sha256_digest(context.subject_sha256) {
        return Err(refuse("invalid expected publisher subject digest"));
    }
    let output = parse_json_value(raw, JsonProfile::VerifierOutput)?;
    let rows = output
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or_else(|| refuse("GH output must contain exactly one result"))?;
    let row = object(&rows[0], "GH result")?;
    if !exact(row, &["attestation", "verificationResult"])
        || !member(row, "attestation")?.is_object()
    {
        return Err(refuse("malformed GH result"));
    }
    let verification = object(member(row, "verificationResult")?, "GH verification result")?;
    let signature = object(member(verification, "signature")?, "verified signature")?;
    if !member(signature, "certificate")?.is_object() {
        return Err(refuse("verified result lacks a certificate object"));
    }
    let statement = object(member(verification, "statement")?, "verified statement")?;
    if member(statement, "predicateType")?.as_str() != Some(PREDICATE_TYPE) {
        return Err(refuse("GitHub attestation predicate type mismatch"));
    }
    let subjects = member(statement, "subject")?
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or_else(|| refuse("each GH result must authenticate exactly one subject"))?;
    let subject = object(&subjects[0], "SLSA subject")?;
    if !exact(subject, &["name", "digest"])
        || member(subject, "name")?.as_str() != Some(context.subject)
    {
        return Err(refuse("SLSA subject name mismatch"));
    }
    let digest = object(member(subject, "digest")?, "subject digest")?;
    if !exact(digest, &["sha256"])
        || member(digest, "sha256")?.as_str() != Some(context.subject_sha256)
    {
        return Err(refuse("SLSA subject digest mismatch"));
    }
    let predicate = object(member(statement, "predicate")?, "SLSA predicate")?;
    if !exact(predicate, &["buildDefinition", "runDetails"]) {
        return Err(refuse("invalid SLSA predicate fields"));
    }
    let definition = object(member(predicate, "buildDefinition")?, "build definition")?;
    if member(definition, "buildType")?.as_str() != Some(BUILD_TYPE) {
        return Err(refuse("SLSA build type mismatch"));
    }
    let policy = context.policy;
    let external = object(
        member(definition, "externalParameters")?,
        "workflow parameters",
    )?;
    let expected_workflow = json!({"repository":format!("https://github.com/{}",policy.repository),
        "path":policy.workflow,"ref":policy.source_ref});
    if member(external, "workflow")? != &expected_workflow {
        return Err(refuse("SLSA workflow parameters mismatch"));
    }
    let dependencies = member(definition, "resolvedDependencies")?
        .as_array()
        .ok_or_else(|| refuse("SLSA dependencies must be an array"))?;
    let mut expected_dependencies = vec![json!({
        "uri":format!("git+https://github.com/{}@{}",policy.repository,policy.source_ref),
        "digest":{"gitCommit":policy.source_sha}
    })];
    for material in context.materials {
        expected_dependencies
            .push(serde_json::to_value(material).map_err(|error| Refusal::new(error.to_string()))?);
    }
    let expected_unique = expected_dependencies
        .iter()
        .enumerate()
        .all(|(index, value)| !expected_dependencies[..index].contains(value));
    // Compare JSON values, not struct serialization order. Equal length and
    // unique expected rows also exclude duplicate or extra actual materials.
    if !expected_unique
        || dependencies.len() != expected_dependencies.len()
        || !expected_dependencies
            .iter()
            .all(|row| dependencies.contains(row))
    {
        return Err(refuse(
            "SLSA resolved dependencies differ from policy and inputs",
        ));
    }
    let internal = object(
        member(definition, "internalParameters")?,
        "internal parameters",
    )?;
    if !exact(internal, &["github", "publisherPolicy"]) {
        return Err(refuse("invalid SLSA internal parameter fields"));
    }
    if member(internal, "github")?
        != &json!({"event_name":"workflow_dispatch",
        "repository_id":"1421182484","repository_owner_id":"436979",
        "runner_environment":"github-hosted"})
    {
        return Err(refuse("SLSA protected GitHub build parameters mismatch"));
    }
    let expected_publisher = json!({"environment":"release","runnerEnvironment":"github-hosted",
        "repository":policy.repository,"workflow":policy.workflow,"workflowSha":policy.workflow_sha,
        "sourceSha":policy.source_sha,"sourceRef":policy.source_ref,
        "inputsManifestSha256":policy.inputs_manifest_sha256,"hostProfile":context.host});
    if member(internal, "publisherPolicy")? != &expected_publisher {
        return Err(refuse(
            "signed publisher policy differs from external policy",
        ));
    }
    let details = object(member(predicate, "runDetails")?, "run details")?;
    let metadata = object(member(details, "metadata")?, "run metadata")?;
    let invocation = format!(
        "https://github.com/{}/actions/runs/{}/attempts/{}",
        policy.repository,
        context.run_id.as_decimal(),
        context.run_attempt.as_decimal()
    );
    if !exact(metadata, &["invocationId"])
        || member(metadata, "invocationId")?.as_str() != Some(invocation.as_str())
    {
        return Err(refuse("SLSA invocation identity mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        digest::sha256_bytes,
        publisher_policy::{parse_inputs_manifest, parse_publisher_policy},
    };
    use std::{collections::BTreeSet, fs, path::Path};

    #[test]
    fn matches_seventy_pinned_synthetic_claim_decisions_without_running_python_or_verifiers() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/publisher-claims");
        let context: Value =
            serde_json::from_slice(&fs::read(root.join("context.json")).unwrap()).unwrap();
        let oracle: Value =
            serde_json::from_slice(&fs::read(root.join("oracle.json")).unwrap()).unwrap();
        let policy_value = json!({
            "schema":"ami-rust-publisher-trust-v2", "repository":"metaneutrons/ami-rust",
            "workflow":".github/workflows/sdk-qualify.yml", "source_ref":"refs/heads/main",
            "workflow_sha":context["policy"]["workflow_sha"], "source_sha":context["policy"]["source_sha"],
            "oidc_issuer":"https://token.actions.githubusercontent.com",
            "cert_identity":"https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
            "inputs_manifest_sha256":context["policy"]["inputs_manifest_sha256"],
            "allowed_host_profiles":["macos-aarch64","linux-x86_64"],
            "gh":{"path":"/fixture/gh","sha256":"0".repeat(64)},
            "cosign":{"path":"/fixture/cosign","sha256":"0".repeat(64)},
            "gh_trusted_roots":{"path":"/fixture/gh-roots","sha256":"0".repeat(64)},
            "cosign_trusted_root":{"path":"/fixture/cosign-root","sha256":"0".repeat(64)}
        });
        let policy = parse_publisher_policy(&serde_json::to_vec(&policy_value).unwrap()).unwrap();
        let inputs = parse_inputs_manifest(
            &serde_json::to_vec(&json!({
                "schema":"ami-rust-publisher-inputs-v1", "materials":context["input_materials"]
            }))
            .unwrap(),
        )
        .unwrap();
        let id = PositiveCounter::parse(&context["run"]["run_id"].to_string()).unwrap();
        let attempt = PositiveCounter::parse(&context["run"]["run_attempt"].to_string()).unwrap();
        let host: Host = serde_json::from_value(context["host"].clone()).unwrap();
        let subject = context["subject_paths"][0].as_str().unwrap();
        let digest = context["manifest"][subject][1].as_str().unwrap();
        let cases = oracle["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 70);
        let mut names = BTreeSet::new();
        let mut accepted = 0;
        for case in cases {
            let name = case["name"].as_str().unwrap();
            assert!(names.insert(name));
            let raw = fs::read(root.join(case["file"].as_str().unwrap())).unwrap();
            assert_eq!(sha256_bytes(&raw), case["sha256"].as_str().unwrap());
            let result = check_github_output(
                &raw,
                PublisherClaimContext {
                    policy: &policy,
                    run_id: &id,
                    run_attempt: &attempt,
                    host,
                    subject,
                    subject_sha256: digest,
                    materials: &inputs.materials,
                },
            );
            assert_eq!(
                result.is_ok(),
                case["actual"] == "accept",
                "{name}: {result:?}"
            );
            accepted += usize::from(result.is_ok());
        }
        assert_eq!(accepted, 9);
    }
}

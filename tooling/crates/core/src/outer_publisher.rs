//! Authenticate the six packaged public assets before transport extraction.
//! This capability is separate from inner release-v2 installation authority.
use super::*;
use crate::{
    package::CheckedNativePackage,
    public_transport::{NativeTransportRecord, parse_native_transport_record},
    publisher_claims::check_outer_github_output,
    records::Host,
    workflow_counter::PositiveCounter,
};
use serde_json::Value;

type OuterClaims = (
    Value,
    BTreeMap<String, Vec<String>>,
    BTreeMap<String, Vec<String>>,
);

/// Successful outer verification retains the exact bytes the tools checked.
/// An inner bundle must still pass its independent publisher verification.
pub struct VerifiedOuterPackage {
    assets: BTreeMap<String, Vec<u8>>,
    pins: crate::package_records::NativePackagePins,
    policy_sha256: String,
    record: NativeTransportRecord,
    predicate: Value,
    selected: BTreeMap<String, Vec<String>>,
    ignored: BTreeMap<String, Vec<String>>,
    resource_reports: Vec<ResourceReport>,
}

impl VerifiedOuterPackage {
    pub fn record(&self) -> &NativeTransportRecord {
        &self.record
    }
    pub fn archive(&self) -> &[u8] {
        &self.assets[&self.record.archive.name]
    }
    pub fn predicate(&self) -> &Value {
        &self.predicate
    }
    pub fn selected_proofs(&self) -> &BTreeMap<String, Vec<String>> {
        &self.selected
    }
    pub fn ignored_proofs(&self) -> &BTreeMap<String, Vec<String>> {
        &self.ignored
    }
    pub fn resource_reports(&self) -> &[ResourceReport] {
        &self.resource_reports
    }

    /// Bind the independently authenticated native inner bundle to this outer
    /// capsule and its distributor pins before any installation is authorised.
    pub fn bind_inner(&self, bundle: VerifiedPublisherBundle) -> Result<VerifiedPublisherBundle> {
        let pins = &self.pins;
        let report = &bundle.authentication().report;
        let run = report.workflow_runs.as_slice();
        if sha256_bytes(bundle.raw_manifest()) != pins.manifest_sha256.as_str()
            || bundle.manifest().version != pins.sdk_version
            || report.source_sha != pins.source_commit
            || report.workflow_sha != pins.source_commit
            || bundle.authentication().external_policy_sha256.as_str() != self.policy_sha256
            || run.len() != 1
            || run[0].run_id != pins.sdk_run_id
            || run[0].run_attempt != pins.sdk_run_attempt
            || run[0].host_profile != Host::LinuxX86_64
        {
            return Err(Refusal::new(
                "inner publisher manifest, source, policy or run differs from outer pins",
            ));
        }
        #[derive(serde::Deserialize)]
        struct Producer<'a> {
            source_sha: String,
            workflow_sha: String,
            #[serde(borrow)]
            run_id: &'a serde_json::value::RawValue,
            #[serde(borrow)]
            run_attempt: &'a serde_json::value::RawValue,
        }
        let producer: Producer<'_> = serde_json::from_str(bundle.manifest().producer.get())
            .map_err(|e| Refusal::new(format!("inner producer identity is invalid: {e}")))?;
        if producer.source_sha != pins.source_commit
            || producer.workflow_sha != pins.source_commit
            || PositiveCounter::parse(producer.run_id.get())? != pins.sdk_run_id
            || PositiveCounter::parse(producer.run_attempt.get())? != pins.sdk_run_attempt
        {
            return Err(Refusal::new(
                "inner producer identity differs from authenticated outer predicate",
            ));
        }
        let launcher = bundle.manifest().host_launchers.for_host(pins.host);
        if launcher.sha256 != pins.core_sha256 || launcher.bytes != pins.launchers["ami-rust"].bytes
        {
            return Err(Refusal::new(
                "inner native launcher differs from the executing package",
            ));
        }
        let outer_sbom = format!("ami-rust-{}-release.tar.xz.spdx.json", pins.sdk_version);
        if bundle.assets().get("sbom.spdx.json") != self.assets.get(&outer_sbom) {
            return Err(Refusal::new(
                "outer SBOM differs from authenticated inner SBOM",
            ));
        }
        Ok(bundle)
    }
}

/// The distributor/package manager supplies the package trust boundary. The
/// source-derived policy and input materials are independently supplied; no
/// candidate file can select its own verifier, trust roots or publisher source.
pub fn verify_outer_package(
    package: &CheckedNativePackage,
    policy_path: &Path,
    trusted_inputs: &[u8],
    cancelled: impl FnMut() -> bool,
) -> Result<VerifiedOuterPackage> {
    verify_outer_package_scoped(package, policy_path, trusted_inputs, None, cancelled)
}

pub(crate) fn verify_outer_package_in_workspace(
    package: &CheckedNativePackage,
    policy_path: &Path,
    trusted_inputs: &[u8],
    workspace: &Path,
    cancelled: impl FnMut() -> bool,
) -> Result<VerifiedOuterPackage> {
    crate::ownership::existing_private_state(workspace)?;
    verify_outer_package_scoped(
        package,
        policy_path,
        trusted_inputs,
        Some(workspace),
        cancelled,
    )
}

fn verify_outer_package_scoped(
    package: &CheckedNativePackage,
    policy_path: &Path,
    trusted_inputs: &[u8],
    workspace: Option<&Path>,
    mut cancelled: impl FnMut() -> bool,
) -> Result<VerifiedOuterPackage> {
    let mut observer = Observation {
        started: Instant::now(),
        cancelled: &mut cancelled,
        resource_reports: Vec::new(),
        managed_workspace: workspace.map(Path::to_path_buf),
    };
    observer.check()?;
    let pins = package.pins();
    let policy_raw = read_protected(
        policy_path,
        JsonProfile::PublisherPolicyAndAuthenticationMetadata,
    )?;
    let policy = parse_publisher_policy(&policy_raw)?;
    if policy.source_sha != pins.source_commit
        || policy.workflow_sha != pins.source_commit
        || !policy.allowed_host_profiles.contains(&Host::LinuxX86_64)
        || sha256_bytes(trusted_inputs) != policy.inputs_manifest_sha256.as_str()
    {
        return Err(Refusal::new(
            "outer publisher policy differs from independent package/source pins",
        ));
    }
    let inputs = parse_inputs_manifest(trusted_inputs)?;
    if policy_path.starts_with(package.path()) {
        return Err(Refusal::new(
            "outer publisher policy must be outside the package",
        ));
    }
    for (pin, executable) in pins_for_policy(&policy) {
        if Path::new(&pin.path).starts_with(package.path()) {
            return Err(Refusal::new(
                "outer publisher tools and roots must be outside the package",
            ));
        }
        check_pin(pin, executable, &mut observer)?;
    }
    check_trusted_roots(&policy)?;
    let mut assets = BTreeMap::new();
    for asset in &pins.assets {
        observer.check()?;
        assets.insert(
            asset.path.clone(),
            package.read_file(&format!("assets/{}", asset.path))?,
        );
    }
    let payload = format!("ami-rust-{}-release.tar.xz", pins.sdk_version);
    let transport = format!("ami-rust-{}-transport.json", pins.sdk_version);
    let subjects = [
        payload.clone(),
        format!("{payload}.spdx.json"),
        transport.clone(),
        "SHA256SUMS".to_owned(),
    ];
    let checksums = assets
        .iter()
        .filter(|(name, _)| name.as_str() != "SHA256SUMS")
        .map(|(name, raw)| format!("{}  {name}\n", sha256_bytes(raw)))
        .collect::<String>();
    if assets.get("SHA256SUMS").map(Vec::as_slice) != Some(checksums.as_bytes())
        || sha256_bytes(&assets[&transport]) != pins.transport_sha256.as_str()
    {
        return Err(Refusal::new(
            "outer asset checksums or transport pin differ",
        ));
    }
    let record = parse_native_transport_record(&assets[&transport])?;
    if record.archive.name != payload
        || record.archive.bytes != assets[&payload].len() as u64
        || record.archive.sha256 != sha256_bytes(&assets[&payload])
    {
        return Err(Refusal::new(
            "outer transport does not bind the exact packaged payload",
        ));
    }
    for subject in [&payload, &transport] {
        require_json_object(
            &assets[&format!("{subject}.sigstore.json")],
            JsonProfile::CosignBundle,
            "outer Cosign bundle",
        )?;
    }
    // The checked package already binds every path, size, digest and subject.
    // Preserve the index association rather than choosing a proof by listing order.
    let proof_raw = package.read_file("proofs.json")?;
    crate::package_records::parse_native_package_proofs(&proof_raw, pins)?;
    let proof_index = parse_json_value(&proof_raw, JsonProfile::PackageMetadataStateSelection)?;
    let mut staged = assets.clone();
    let mut proofs = BTreeMap::<String, Vec<String>>::new();
    for subject in &subjects {
        let rows = proof_index["subjects"][subject]
            .as_array()
            .ok_or_else(|| Refusal::new("outer proof subject index is missing"))?;
        let mut paths = Vec::new();
        for row in rows {
            let path = row["path"]
                .as_str()
                .ok_or_else(|| Refusal::new("outer proof path is missing"))?;
            let raw = package.read_file(&format!("proofs/{path}"))?;
            require_json_object(
                &raw,
                JsonProfile::GithubAttestationBundle,
                "outer GitHub proof",
            )?;
            let staged_path = format!(".auth/outer/{}.json", sha256_bytes(&raw));
            paths.push(staged_path.clone());
            staged.insert(staged_path, raw);
        }
        proofs.insert(subject.clone(), paths);
    }
    let home = PublisherHome::new()?;
    let result = (|| -> Result<OuterClaims> {
        let path = home.stage_bundle(&staged)?;
        let root = Directory::open(&path)?;
        let mut selected = BTreeMap::new();
        let mut ignored = BTreeMap::new();
        let mut expected_predicate = None;
        // The payload selects a unique cryptographically valid run before the
        // other subjects are considered. The independent package run must agree.
        for subject in &subjects {
            let mut accepted = BTreeMap::<String, Value>::new();
            let mut accepted_runs = BTreeSet::new();
            let mut selected_rows = Vec::new();
            let mut ignored_rows = Vec::new();
            for proof in &proofs[subject] {
                observer.check()?;
                recheck_subject(&root, subject, proof, &staged)?;
                check_pin(&policy.gh, true, &mut observer)?;
                check_pin(&policy.gh_trusted_roots, false, &mut observer)?;
                let metadata = metadata_for_proof(subject, proof, pins);
                let output = run_verifier_attempt(
                    &policy.gh,
                    gh_arguments(&path, subject, &metadata, &policy),
                    &home,
                    &mut observer,
                )?;
                let proof_digest = sha256_bytes(&staged[proof]);
                if !output.status.success() {
                    ignored_rows.push(proof_digest);
                    continue;
                }
                let parsed = (|| -> Result<(Value, PositiveCounter, PositiveCounter)> {
                    let statement = statement_from_output(&output.stdout)?;
                    let (run, attempt) = statement_run(&statement, &policy)?;
                    check_outer_github_output(
                        &output.stdout,
                        PublisherClaimContext {
                            policy: &policy,
                            run_id: &run,
                            run_attempt: &attempt,
                            host: Host::LinuxX86_64,
                            subject,
                            subject_sha256: &sha256_bytes(&assets[subject]),
                            materials: &inputs.materials,
                        },
                        &pins.sdk_version,
                    )?;
                    Ok((statement, run, attempt))
                })();
                let Ok((statement, run, attempt)) = parsed else {
                    ignored_rows.push(proof_digest);
                    continue;
                };
                if subject != &payload
                    && (run != pins.sdk_run_id || attempt != pins.sdk_run_attempt)
                {
                    ignored_rows.push(proof_digest);
                    continue;
                }
                accepted_runs
                    .insert((run.as_decimal().to_owned(), attempt.as_decimal().to_owned()));
                let claim =
                    serde_json::to_vec(&statement).map_err(|e| Refusal::new(e.to_string()))?;
                accepted.insert(sha256_bytes(&claim), statement);
                selected_rows.push(proof_digest);
            }
            if accepted.len() != 1
                || accepted_runs.len() != 1
                || !accepted_runs.contains(&(
                    pins.sdk_run_id.as_decimal().to_owned(),
                    pins.sdk_run_attempt.as_decimal().to_owned(),
                ))
            {
                return Err(Refusal::new(format!(
                    "outer {subject} lacks one unambiguous authenticated pinned-run statement"
                )));
            }
            let (_, statement) = accepted
                .pop_first()
                .ok_or_else(|| Refusal::new("outer statement is missing"))?;
            let predicate = statement
                .get("predicate")
                .ok_or_else(|| Refusal::new("outer statement predicate is missing"))?;
            if expected_predicate
                .as_ref()
                .is_some_and(|expected| expected != predicate)
            {
                return Err(Refusal::new(
                    "outer subjects have different authenticated predicates",
                ));
            }
            expected_predicate = Some(predicate.clone());
            selected.insert(subject.clone(), selected_rows);
            ignored.insert(subject.clone(), ignored_rows);
        }
        for subject in [&payload, &transport] {
            let proof = format!("{subject}.sigstore.json");
            recheck_subject(&root, subject, &proof, &staged)?;
            check_pin(&policy.cosign, true, &mut observer)?;
            check_pin(&policy.cosign_trusted_root, false, &mut observer)?;
            let mut metadata = metadata_for_proof(subject, &proof, pins);
            metadata.cosign_bundles.insert(subject.clone(), proof);
            run_verifier(
                &policy.cosign,
                cosign_arguments(&path, subject, &metadata, &policy),
                &home,
                &mut observer,
            )?;
        }
        for (name, raw) in &staged {
            observer.check()?;
            if read_bundle_file(&root, name, raw.len())? != *raw {
                return Err(Refusal::new("outer verifier snapshot changed"));
            }
        }
        for (name, raw) in &assets {
            if package.read_file(&format!("assets/{name}"))? != *raw {
                return Err(Refusal::new("outer packaged asset changed"));
            }
        }
        if package.read_file("proofs.json")? != proof_raw
            || read_protected(
                policy_path,
                JsonProfile::PublisherPolicyAndAuthenticationMetadata,
            )? != policy_raw
        {
            return Err(Refusal::new("outer proof index or external policy changed"));
        }
        for (pin, executable) in pins_for_policy(&policy) {
            check_pin(pin, executable, &mut observer)?;
        }
        let predicate =
            expected_predicate.ok_or_else(|| Refusal::new("outer predicate is missing"))?;
        if predicate != expected_predicate_value(&policy, pins, &inputs.materials)? {
            return Err(Refusal::new(
                "outer predicate differs from the exact pinned publisher recipe",
            ));
        }
        Ok((predicate, selected, ignored))
    })();
    let summary = completed_resource_summary(&observer.resource_reports);
    let cleanup = home.finish();
    let (predicate, selected, ignored) = match (result, cleanup) {
        (Ok(value), Ok(())) => value,
        (Err(error), Ok(())) | (Ok(_), Err(error)) => {
            return Err(Refusal::new(format!("{error}; {summary}")));
        }
        (Err(error), Err(cleanup)) => {
            return Err(Refusal::new(format!(
                "{error}; cleanup failed: {cleanup}; {summary}"
            )));
        }
    };
    observer.check()?;
    Ok(VerifiedOuterPackage {
        assets,
        pins: pins.clone(),
        policy_sha256: sha256_bytes(&policy_raw),
        record,
        predicate,
        selected,
        ignored,
        resource_reports: observer.resource_reports,
    })
}

fn expected_predicate_value(
    policy: &PublisherPolicy,
    pins: &crate::package_records::NativePackagePins,
    materials: &[crate::publisher_policy::PinnedMaterial],
) -> Result<Value> {
    let mut dependencies = vec![serde_json::json!({
        "uri": format!("git+https://github.com/{}@{}", policy.repository, policy.source_ref),
        "digest": {"gitCommit": policy.source_sha},
    })];
    for row in materials {
        dependencies.push(serde_json::to_value(row).map_err(|e| Refusal::new(e.to_string()))?);
    }
    Ok(serde_json::json!({
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {"workflow": {
                "repository": format!("https://github.com/{}", policy.repository),
                "path": policy.workflow, "ref": policy.source_ref,
            }},
            "internalParameters": {
                "github": {"event_name":"workflow_dispatch", "repository_id":"1421182484",
                    "repository_owner_id":"436979", "runner_environment":"github-hosted"},
                "publisherPolicy": {
                    "environment":"release", "runnerEnvironment":"github-hosted",
                    "repository":policy.repository, "workflow":policy.workflow,
                    "workflowSha":policy.workflow_sha, "sourceSha":policy.source_sha,
                    "sourceRef":policy.source_ref, "inputsManifestSha256":policy.inputs_manifest_sha256,
                    "hostProfile":"linux-x86_64",
                },
            },
            "resolvedDependencies": dependencies,
        },
        "runDetails": {
            "builder":{"id":policy.cert_identity},
            "metadata":{"invocationId":format!("https://github.com/{}/actions/runs/{}/attempts/{}",
                policy.repository, pins.sdk_run_id.as_decimal(), pins.sdk_run_attempt.as_decimal())},
        },
    }))
}

fn pins_for_policy(policy: &PublisherPolicy) -> [(&PinnedPolicyFile, bool); 4] {
    super::pins(policy)
}

fn metadata_for_proof(
    subject: &str,
    proof: &str,
    pins: &crate::package_records::NativePackagePins,
) -> AuthenticationMetadata {
    AuthenticationMetadata {
        declared_run: crate::publisher_metadata::DeclaredWorkflowRun {
            run_id: pins.sdk_run_id.clone(),
            run_attempt: pins.sdk_run_attempt.clone(),
            host_profile: Host::LinuxX86_64,
        },
        gh_bundles: BTreeMap::from([(subject.to_owned(), proof.to_owned())]),
        cosign_bundles: BTreeMap::new(),
        expected_files: BTreeSet::new(),
        allowed_directories: BTreeSet::new(),
    }
}

fn statement_from_output(raw: &[u8]) -> Result<Value> {
    let value = parse_json_value(raw, JsonProfile::VerifierOutput)?;
    value
        .as_array()
        .filter(|rows| rows.len() == 1)
        .and_then(|rows| rows[0].get("verificationResult"))
        .and_then(|result| result.get("statement"))
        .filter(|statement| statement.is_object())
        .cloned()
        .ok_or_else(|| Refusal::new("outer GitHub output omits its unique verified statement"))
}

fn statement_run(
    statement: &Value,
    policy: &PublisherPolicy,
) -> Result<(PositiveCounter, PositiveCounter)> {
    let invocation = statement["predicate"]["runDetails"]["metadata"]["invocationId"]
        .as_str()
        .ok_or_else(|| Refusal::new("outer invocation ID is missing"))?;
    let prefix = format!("https://github.com/{}/actions/runs/", policy.repository);
    let (run, attempt) = invocation
        .strip_prefix(&prefix)
        .and_then(|tail| tail.split_once("/attempts/"))
        .ok_or_else(|| Refusal::new("outer invocation ID is not canonical"))?;
    let run = PositiveCounter::parse(run)?;
    let attempt = PositiveCounter::parse(attempt)?;
    if invocation
        != format!(
            "{prefix}{}/attempts/{}",
            run.as_decimal(),
            attempt.as_decimal()
        )
    {
        return Err(Refusal::new(
            "outer invocation integer spelling is not canonical",
        ));
    }
    Ok((run, attempt))
}

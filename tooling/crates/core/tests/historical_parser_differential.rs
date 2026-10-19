use ami_rust_core::{
    digest::sha256_bytes,
    publisher_claims::{PublisherClaimContext, check_github_output},
    publisher_policy::{parse_inputs_manifest, parse_publisher_policy},
    receipts::{InstallReceipt, PositiveCounter, ReceiptKind, parse_install_receipt},
    records::Host,
    release_manifest::parse_release_manifest,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

const TOTAL_CASES: usize = 131;
// These inert oracle records were generated on macOS. Their provenance stays
// fixed when the same functions are replayed by the separately pinned Linux
// interpreter. verify_pinned_python checks the actual current-host executable.
const ORACLE_ORIGIN_PYTHON_SHA256: &str =
    "aed8ed802d0387d6831dead5885840e4e2ff3a7984dd7297e9a5f4466e9cda1d";

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn host_profile() -> &'static str {
    match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => "macos-aarch64",
        ("linux", "x86_64") => "linux-x86_64",
        _ => panic!("historical parser replay does not support this host"),
    }
}

fn verify_pinned_python() -> Value {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let source_root = source_root.canonicalize().expect("canonical source root");
    let python = PathBuf::from(
        env::var_os("AMI_RUST_HISTORICAL_PYTHON")
            .expect("AMI_RUST_HISTORICAL_PYTHON is required for explicit qualification"),
    );
    assert!(
        python.is_absolute(),
        "historical Python path must be absolute"
    );
    assert_eq!(
        python.canonicalize().expect("canonical historical Python"),
        python,
        "historical Python path must already be canonical"
    );
    let metadata = fs::metadata(&python).expect("historical Python metadata");
    assert!(
        metadata.is_file(),
        "historical Python must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            metadata.permissions().mode() & 0o111,
            0,
            "historical Python must be executable"
        );
    }
    let raw = fs::read(&python).expect("historical Python bytes");
    let inputs_path = source_root.join("release/ci-python-inputs.json");
    let inputs_raw = fs::read(&inputs_path).expect("current CI Python input pin");
    let pin: Value = serde_json::from_slice(&inputs_raw).unwrap();
    let runtime = &pin["hosts"][host_profile()];
    assert_eq!(
        string(runtime, "runtime_relative_path"),
        "python/bin/python3.12"
    );
    assert_eq!(
        raw.len() as u64,
        runtime["runtime_bytes"].as_u64().expect("runtime byte pin"),
        "historical Python byte length differs from the current host pin"
    );
    assert_eq!(
        sha256_bytes(&raw),
        string(runtime, "runtime_sha256"),
        "historical Python digest differs from the current host pin"
    );
    json!({
        "host": host_profile(),
        "path": python,
        "bytes": raw.len(),
        "sha256": sha256_bytes(&raw),
        "version": string(&pin, "version"),
        "ci_python_inputs_sha256": sha256_bytes(&inputs_raw),
    })
}

fn receipt_semantics(receipt: &InstallReceipt) -> Value {
    let schema = match receipt.kind {
        ReceiptKind::LegacyQualificationV1 => "ami-rust-install-receipt-v1",
        ReceiptKind::HistoricalProductionV2 => "ami-rust-install-receipt-v2",
        ReceiptKind::NativeV3 => panic!("historical parser corpus must not contain native-v3"),
    };
    let mut inventory: Vec<_> = receipt
        .inventory
        .iter()
        .map(|file| {
            json!({
                "path": file.path,
                "bytes": file.bytes,
                "sha256": file.sha256.as_str(),
            })
        })
        .collect();
    inventory.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let workflow_runs: Vec<_> = receipt
        .authentication
        .as_ref()
        .into_iter()
        .flat_map(|auth| auth.report.workflow_runs.iter())
        .map(|run| {
            json!({
                "run_id": run.run_id.as_decimal(),
                "run_attempt": run.run_attempt.as_decimal(),
                "host_profile": serde_json::to_value(run.host_profile).unwrap(),
            })
        })
        .collect();
    json!({
        "schema": schema,
        "publisher": receipt.publisher,
        "release_manifest_sha256": receipt.release_manifest_sha256.as_str(),
        "sdk_manifest_sha256": receipt.sdk_manifest_sha256.as_str(),
        "version": receipt.version,
        "inventory": inventory,
        "workflow_runs": workflow_runs,
    })
}

fn assert_oracle_receipt_semantics(actual: &Value, case: &Value, label: &str) {
    for key in [
        "schema",
        "publisher",
        "release_manifest_sha256",
        "sdk_manifest_sha256",
        "version",
    ] {
        assert_eq!(actual[key], case["receipt"][key], "{label}: {key}");
    }
    assert_eq!(
        actual["inventory"], case["typed_inventory"],
        "{label}: inventory"
    );
}

fn case_input(
    root: &Path,
    corpus: &str,
    case: &Value,
    input_key: &str,
    digest_key: &str,
) -> (Vec<u8>, String) {
    let input = string(case, input_key);
    let expected = string(case, digest_key);
    let raw = fs::read(root.join(corpus).join(input))
        .unwrap_or_else(|error| panic!("could not read {corpus}/{input}: {error}"));
    let actual = sha256_bytes(&raw);
    assert_eq!(actual, expected, "{corpus}/{input} changed");
    (raw, actual)
}

#[test]
#[ignore = "explicit maintainer historical Python comparison; invoke through replay_historical_oracles.py"]
fn historical_python_differential_corpus() {
    let runtime = verify_pinned_python();
    let fixture_root = PathBuf::from(
        env::var_os("AMI_RUST_HISTORICAL_FIXTURE_ROOT")
            .expect("AMI_RUST_HISTORICAL_FIXTURE_ROOT is required"),
    );
    assert!(fixture_root.is_absolute(), "fixture root must be absolute");
    assert_eq!(
        fixture_root.canonicalize().expect("canonical fixture root"),
        fixture_root,
        "fixture root must already be canonical"
    );
    let result_path = PathBuf::from(
        env::var_os("AMI_RUST_HISTORICAL_RUST_RESULT")
            .expect("AMI_RUST_HISTORICAL_RUST_RESULT is required"),
    );
    assert!(
        result_path.is_absolute(),
        "Rust result path must be absolute"
    );
    assert!(!result_path.exists(), "Rust result path must be fresh");

    let manifest_oracle_path = fixture_root.join("release-manifests/oracle.json");
    let manifest_oracle_raw = fs::read(&manifest_oracle_path).expect("manifest oracle bytes");
    let manifest_oracle: Value = serde_json::from_slice(&manifest_oracle_raw).unwrap();
    assert_eq!(
        string(&manifest_oracle, "schema"),
        "ami-rust-release-manifest-static-oracles-v1"
    );
    assert_eq!(
        string(&manifest_oracle, "historical_python_sha256"),
        ORACLE_ORIGIN_PYTHON_SHA256,
        "manifest oracle origin Python pin changed"
    );
    assert_eq!(
        string(&manifest_oracle, "historical_source_sha256"),
        "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984"
    );

    let receipt_oracle_path = fixture_root.join("receipts/oracle.json");
    let receipt_oracle_raw = fs::read(&receipt_oracle_path).expect("receipt oracle bytes");
    let receipt_oracle: Value = serde_json::from_slice(&receipt_oracle_raw).unwrap();
    assert_eq!(
        receipt_oracle["runtime"]["sha256"], ORACLE_ORIGIN_PYTHON_SHA256,
        "receipt oracle origin Python pin changed"
    );
    assert_eq!(
        receipt_oracle["source"]["sha256"],
        "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984"
    );

    let integer_oracle_path = fixture_root.join("receipts/integers/oracle.json");
    let integer_oracle_raw = fs::read(&integer_oracle_path).expect("integer oracle bytes");
    let integer_oracle: Value = serde_json::from_slice(&integer_oracle_raw).unwrap();
    assert_eq!(
        integer_oracle["runtime"]["sha256"], ORACLE_ORIGIN_PYTHON_SHA256,
        "integer oracle origin Python pin changed"
    );
    assert_eq!(
        integer_oracle["source"]["sha256"],
        "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984"
    );
    assert_eq!(
        integer_oracle["runtime"]["sys_get_int_max_str_digits"],
        4300
    );

    let claims_root = fixture_root.join("publisher-claims");
    let context_raw = fs::read(claims_root.join("context.json")).expect("claims context bytes");
    let context: Value = serde_json::from_slice(&context_raw).unwrap();
    let claims_oracle_path = claims_root.join("oracle.json");
    let claims_oracle_raw = fs::read(&claims_oracle_path).expect("claims oracle bytes");
    let claims_oracle: Value = serde_json::from_slice(&claims_oracle_raw).unwrap();
    assert_eq!(
        sha256_bytes(&context_raw),
        string(&claims_oracle, "context_sha256"),
        "publisher claims context changed"
    );

    let policy_value = json!({
        "schema": "ami-rust-publisher-trust-v2",
        "repository": "metaneutrons/ami-rust",
        "workflow": ".github/workflows/sdk-qualify.yml",
        "source_ref": "refs/heads/main",
        "workflow_sha": context["policy"]["workflow_sha"],
        "source_sha": context["policy"]["source_sha"],
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "cert_identity": "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
        "inputs_manifest_sha256": context["policy"]["inputs_manifest_sha256"],
        "allowed_host_profiles": ["macos-aarch64", "linux-x86_64"],
        "gh": {"path":"/fixture/gh", "sha256":"0".repeat(64)},
        "cosign": {"path":"/fixture/cosign", "sha256":"0".repeat(64)},
        "gh_trusted_roots": {"path":"/fixture/gh-roots", "sha256":"0".repeat(64)},
        "cosign_trusted_root": {"path":"/fixture/cosign-root", "sha256":"0".repeat(64)},
    });
    let policy = parse_publisher_policy(&serde_json::to_vec(&policy_value).unwrap()).unwrap();
    let inputs = parse_inputs_manifest(
        &serde_json::to_vec(&json!({
            "schema":"ami-rust-publisher-inputs-v1",
            "materials":context["input_materials"],
        }))
        .unwrap(),
    )
    .unwrap();
    let run_id: PositiveCounter = serde_json::from_value(context["run"]["run_id"].clone()).unwrap();
    let run_attempt: PositiveCounter =
        serde_json::from_value(context["run"]["run_attempt"].clone()).unwrap();
    let host: Host = serde_json::from_value(context["host"].clone()).unwrap();
    let subject = context["subject_paths"][0].as_str().expect("claim subject");
    let subject_sha256 = context["manifest"][subject][1]
        .as_str()
        .expect("claim digest");

    let mut all = Vec::with_capacity(TOTAL_CASES);
    let mut unique = BTreeSet::new();
    let mut corpus_counts = serde_json::Map::new();
    let mut manifest_differences = 0;

    let manifest_cases = manifest_oracle["cases"].as_array().expect("manifest cases");
    assert_eq!(
        manifest_cases.len(),
        41,
        "manifest case inventory must be complete"
    );
    let mut manifest_accept = 0;
    let mut manifest_refuse = 0;
    for case in manifest_cases {
        let name = string(case, "name");
        assert!(
            unique.insert(format!("manifest:{name}")),
            "duplicate manifest case {name}"
        );
        let (raw, digest) = case_input(
            &fixture_root,
            "release-manifests",
            case,
            "input",
            "input_sha256",
        );
        let historical = case["historical_acceptance"]
            .as_bool()
            .expect("historical manifest decision");
        let declared_native = case["native_acceptance"]
            .as_bool()
            .expect("native manifest decision");
        let result = parse_release_manifest(&raw, case["production"].as_bool().unwrap());
        let native_accepts = result.is_ok();
        assert_eq!(
            native_accepts, declared_native,
            "manifest {name}: {result:?}"
        );
        let difference = historical != declared_native;
        if difference {
            manifest_differences += 1;
            assert!(
                case["intentional_difference"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty()),
                "manifest {name}: undeclared difference"
            );
        } else {
            assert!(
                case["intentional_difference"].is_null(),
                "manifest {name}: stray difference note"
            );
        }
        if native_accepts {
            manifest_accept += 1;
        } else {
            manifest_refuse += 1;
        }
        all.push(json!({
            "corpus":"manifest", "name":name, "input_sha256":digest,
            "historical_decision":if historical {"accept"} else {"refuse"},
            "current_rust_decision":if native_accepts {"accept"} else {"refuse"},
            "declared_native_decision":if declared_native {"accept"} else {"refuse"},
            "intentional_difference":case["intentional_difference"],
        }));
    }
    assert_eq!(
        manifest_differences, 2,
        "exactly two declared manifest differences are expected"
    );
    assert!(
        manifest_accept > 0 && manifest_refuse > 0,
        "manifest corpus needs positive and refusal controls"
    );
    corpus_counts.insert(
        "manifest".into(),
        json!({"cases":41,"native_accept":manifest_accept,"native_refuse":manifest_refuse}),
    );

    let receipt_cases = receipt_oracle["cases"].as_array().expect("receipt cases");
    assert_eq!(
        receipt_cases.len(),
        14,
        "receipt case inventory must be complete"
    );
    let mut receipt_accept = 0;
    let mut receipt_refuse = 0;
    for case in receipt_cases {
        let name = string(case, "case");
        assert!(
            unique.insert(format!("receipt:{name}")),
            "duplicate receipt case {name}"
        );
        let (raw, digest) = case_input(&fixture_root, "receipts", case, "input", "input_sha256");
        let historical = string(case, "decision") == "accept";
        let result = parse_install_receipt(&raw);
        let native_accepts = result.is_ok();
        assert_eq!(native_accepts, historical, "receipt {name}: {result:?}");
        let semantics = result.map(|receipt| receipt_semantics(&receipt));
        if native_accepts {
            receipt_accept += 1;
            assert_oracle_receipt_semantics(semantics.as_ref().unwrap(), case, name);
        } else {
            receipt_refuse += 1;
        }
        all.push(json!({
            "corpus":"receipt", "name":name, "input_sha256":digest,
            "historical_decision":if historical {"accept"} else {"refuse"},
            "current_rust_decision":if native_accepts {"accept"} else {"refuse"},
            "common_receipt_semantics":semantics.ok(),
        }));
    }
    assert!(
        receipt_accept > 0 && receipt_refuse > 0,
        "receipt corpus needs positive and refusal controls"
    );
    corpus_counts.insert(
        "receipt".into(),
        json!({"cases":14,"native_accept":receipt_accept,"native_refuse":receipt_refuse}),
    );

    let integer_cases = integer_oracle["results"]
        .as_array()
        .expect("receipt integer cases");
    assert_eq!(
        integer_cases.len(),
        6,
        "receipt integer case inventory must be complete"
    );
    let mut integer_accept = 0;
    let mut integer_refuse = 0;
    for case in integer_cases {
        let name = string(case, "case");
        assert!(
            unique.insert(format!("receipt-integer:{name}")),
            "duplicate receipt integer case {name}"
        );
        let (raw, digest) = case_input(
            &fixture_root,
            "receipts/integers",
            case,
            "input",
            "input_sha256",
        );
        let historical = string(case, "decision") == "accept";
        let result = parse_install_receipt(&raw);
        let native_accepts = result.is_ok();
        assert_eq!(
            native_accepts, historical,
            "receipt integer {name}: {result:?}"
        );
        let semantics = result.map(|receipt| receipt_semantics(&receipt));
        if native_accepts {
            integer_accept += 1;
        } else {
            integer_refuse += 1;
        }
        all.push(json!({
            "corpus":"receipt-integer", "name":name, "input_sha256":digest,
            "historical_decision":if historical {"accept"} else {"refuse"},
            "current_rust_decision":if native_accepts {"accept"} else {"refuse"},
            "common_receipt_semantics":semantics.ok(),
        }));
    }
    assert!(
        integer_accept > 0 && integer_refuse > 0,
        "receipt integer corpus needs positive and refusal controls"
    );
    corpus_counts.insert(
        "receipt-integer".into(),
        json!({"cases":6,"native_accept":integer_accept,"native_refuse":integer_refuse}),
    );

    let claim_cases = claims_oracle["cases"]
        .as_array()
        .expect("publisher claim cases");
    assert_eq!(
        claim_cases.len(),
        70,
        "publisher claim inventory must be complete"
    );
    let mut claim_accept = 0;
    let mut claim_refuse = 0;
    for case in claim_cases {
        let name = string(case, "name");
        assert!(
            unique.insert(format!("publisher-claim:{name}")),
            "duplicate publisher claim case {name}"
        );
        let file = string(case, "file");
        let expected_digest = string(case, "sha256");
        let raw = fs::read(claims_root.join(file))
            .unwrap_or_else(|error| panic!("could not read claim {file}: {error}"));
        let digest = sha256_bytes(&raw);
        assert_eq!(digest, expected_digest, "publisher claim {name} changed");
        assert_eq!(
            string(case, "expected"),
            string(case, "actual"),
            "frozen claim oracle mismatch for {name}"
        );
        let result = check_github_output(
            &raw,
            PublisherClaimContext {
                policy: &policy,
                run_id: &run_id,
                run_attempt: &run_attempt,
                host,
                subject,
                subject_sha256,
                materials: &inputs.materials,
            },
        );
        let native_accepts = result.is_ok();
        let historical = string(case, "expected") == "accept";
        assert_eq!(
            native_accepts, historical,
            "publisher claim {name}: {result:?}"
        );
        if native_accepts {
            claim_accept += 1;
        } else {
            claim_refuse += 1;
        }
        all.push(json!({
            "corpus":"publisher-claim", "name":name, "input_sha256":digest,
            "historical_decision":if historical {"accept"} else {"refuse"},
            "current_rust_decision":if native_accepts {"accept"} else {"refuse"},
        }));
    }
    assert!(
        claim_accept > 0 && claim_refuse > 0,
        "publisher claims corpus needs positive and refusal controls"
    );
    corpus_counts.insert(
        "publisher-claim".into(),
        json!({"cases":70,"native_accept":claim_accept,"native_refuse":claim_refuse}),
    );

    assert_eq!(all.len(), TOTAL_CASES, "case count must not be filtered");
    assert_eq!(
        unique.len(),
        TOTAL_CASES,
        "corpus-scoped case identities must be unique"
    );
    let report = json!({
        "schema":"ami-rust-current-core-historical-parser-differential-v1",
        "status":"PASS_CURRENT_RUST_ORACLE_SIDE",
        "host":host_profile(),
        "historical_python_runtime":runtime,
        "fixture_oracles":{
            "manifest_sha256":sha256_bytes(&manifest_oracle_raw),
            "receipt_sha256":sha256_bytes(&receipt_oracle_raw),
            "receipt_integer_sha256":sha256_bytes(&integer_oracle_raw),
            "publisher_claims_sha256":sha256_bytes(&claims_oracle_raw),
            "publisher_claims_context_sha256":sha256_bytes(&context_raw),
        },
        "counts":{"manifest":41,"receipt":14,"receipt_integer":6,"publisher_claim":70,"total":TOTAL_CASES,"unique":unique.len(),"intentional_manifest_differences":manifest_differences},
        "native_controls":corpus_counts,
        "cases":all,
    });
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    assert!(
        bytes.len() <= 8 * 1024 * 1024,
        "Rust replay output exceeds its bound"
    );
    fs::write(&result_path, [bytes.as_slice(), b"\n"].concat()).expect("write Rust replay result");
}

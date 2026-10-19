use ami_rust_core::{digest::sha256_bytes, release_manifest::parse_release_manifest};
use serde::Deserialize;
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Deserialize)]
struct Oracle {
    schema: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    input: String,
    input_sha256: String,
    production: bool,
    historical_acceptance: bool,
    native_acceptance: bool,
    intentional_difference: Option<String>,
}

#[test]
fn pinned_historical_manifest_cases_and_declared_contract_differences() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/release-manifests");
    let oracle: Oracle =
        serde_json::from_slice(&fs::read(root.join("oracle.json")).unwrap()).unwrap();
    assert_eq!(oracle.schema, "ami-rust-release-manifest-static-oracles-v1");
    assert_eq!(oracle.cases.len(), 41);
    let mut names = BTreeSet::new();
    let mut differences = 0;
    for case in oracle.cases {
        assert!(names.insert(case.name.clone()));
        let raw = fs::read(root.join(&case.input)).unwrap();
        assert_eq!(sha256_bytes(&raw), case.input_sha256, "{}", case.name);
        let result = parse_release_manifest(&raw, case.production);
        assert_eq!(
            result.is_ok(),
            case.native_acceptance,
            "{}: {result:?}",
            case.name,
        );
        if case.historical_acceptance != case.native_acceptance {
            differences += 1;
            assert!(
                case.intentional_difference
                    .is_some_and(|reason| !reason.is_empty())
            );
        } else {
            assert!(case.intentional_difference.is_none());
        }
    }
    assert_eq!(differences, 2);
}

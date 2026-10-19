//! Frozen historical observer decisions; no interpreter runs in this test.
use ami_rust_core::process_snapshot::{observe_scope, parse_ps_snapshot};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    schema: String,
    oracle_commit: String,
    oracle_path: String,
    oracle_function: String,
    oracle_source_sha256: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    pid: u32,
    prior: Vec<u32>,
    groups: Vec<u32>,
    rows: Vec<[u64; 4]>,
    expected: Expected,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Expected {
    root_present: bool,
    rss_bytes: u64,
    process_ids: Vec<u32>,
    process_groups: Vec<u32>,
}

#[test]
fn reproduces_all_frozen_historical_scope_and_rss_decisions() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/process_scope_oracles.json")).unwrap();
    assert_eq!(fixture.schema, "ami-rust-process-scope-oracles-v1");
    assert_eq!(
        fixture.oracle_commit,
        "8c5de39f26838d838b41dec5a89c9a888dbc20d5"
    );
    assert_eq!(fixture.oracle_path, "release/ci_sdk.py");
    assert_eq!(fixture.oracle_function, "Supervisor._sample_scope");
    assert_eq!(
        fixture.oracle_source_sha256,
        "873ec820c1bb30b3751854b5526741f5d679fd9577c8964dab462ec559e6aee1"
    );
    assert_eq!(fixture.cases.len(), 98);
    for case in fixture.cases {
        let raw = case
            .rows
            .iter()
            .map(|row| format!("{} {} {} {}\n", row[0], row[1], row[2], row[3]))
            .collect::<String>();
        let snapshot = parse_ps_snapshot(raw.as_bytes(), 65_536, 512).unwrap();
        let scope = observe_scope(&snapshot, case.pid, &case.prior, &case.groups, 1024).unwrap();
        let actual = Expected {
            root_present: scope.root_present,
            rss_bytes: scope.rss_bytes,
            process_ids: scope.process_ids,
            process_groups: scope.process_groups,
        };
        assert_eq!(actual, case.expected, "historical fixture {}", case.name);
    }
}

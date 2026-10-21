//! Nested Cargo with a literal relative CARGO_HOME, exercised only in fresh fixtures.
use super::registry_fixture::{AuthPolicy, RegistryFixture};
use super::*;

const LITERAL_CARGO_HOME: &str = "relative-cargo-home";
const OUTER_MARKER: &str = "outer-cwd-marker";
const NESTED_MARKER: &str = "nested-cwd-marker";
const OUTER_TOKEN: &str = "Bearer rc2-outer-only";
const WRONG_NESTED_TOKEN: &str = "Bearer rc2-nested-wrong-only";

pub(super) fn run(probe: &mut Probe<'_>, report: &mut Value) -> Result<()> {
    report["scope"] = json!(
        "Nested host Cargo with literal relative CARGO_HOME and a synthetic loopback sparse registry; component evidence only."
    );
    report["limitations"] = json!([
        "The outer package has no registry dependency; registry package data is materialized by the nested invocation.",
        "The fixture records selector propagation and nested registry paths, not a separate outer registry write.",
        "Selector-absent comparison covers stable fixture observations only, not full Cargo equivalence.",
        "These are nested registry/configuration component observations; full Cargo lock/GC concurrency and RC2 activation remain separate qualification."
    ]);

    let tool = |name: &str| -> Result<PathBuf> {
        probe
            .tools
            .iter()
            .find(|row| row.name == name)
            .map(|row| row.path.clone())
            .ok_or_else(|| Refusal::new(format!("missing {name} fixture tool")))
    };
    let control = tool("control-cargo")?;
    let derived = tool("derived-cargo")?;
    let rustc = tool("rustc")?;
    let rustdoc = tool("rustdoc")?;
    let git = tool("git")?;
    create_private_directory(&probe.work.join("temporary"))?;

    // Fail first, then prove recovery in a fresh isomorphic success fixture.
    let wrong = run_case(
        probe,
        report,
        "nested-wrong-token",
        &derived,
        &derived,
        &rustc,
        &rustdoc,
        &git,
        true,
        true,
    )?;
    let control_selected = run_case(
        probe,
        report,
        "control-selected",
        &control,
        &derived,
        &rustc,
        &rustdoc,
        &git,
        true,
        false,
    )?;
    let derived_selected_retry = run_case(
        probe,
        report,
        "derived-selected-fresh-correct-token-retry",
        &derived,
        &derived,
        &rustc,
        &rustdoc,
        &git,
        true,
        false,
    )?;
    let control_absent = run_case(
        probe,
        report,
        "control-absent",
        &control,
        &derived,
        &rustc,
        &rustdoc,
        &git,
        false,
        false,
    )?;
    let derived_absent = run_case(
        probe,
        report,
        "derived-absent",
        &derived,
        &derived,
        &rustc,
        &rustdoc,
        &git,
        false,
        false,
    )?;

    require(
        report,
        "nested-wrong-token-rejected-without-crate-and-fresh-retry-succeeds",
        wrong["expected_nested_failure"] == true
            && wrong["protected_auth_mismatch_observed"] == true
            && wrong["download_auth_mismatch"] == true
            && wrong["archive_present"] == false
            && wrong["source_present"] == false
            && derived_selected_retry["expected_nested_failure"] == false
            && derived_selected_retry["archive_present"] == true
            && derived_selected_retry["source_present"] == true
            && derived_selected_retry["case"] != wrong["case"],
        json!({
            "wrong_token_case": wrong,
            "fresh_correct_token_case": derived_selected_retry
        }),
    )?;

    let mut control_absent_stable = control_absent.clone();
    let mut derived_absent_stable = derived_absent.clone();
    control_absent_stable
        .as_object_mut()
        .unwrap()
        .remove("case");
    derived_absent_stable
        .as_object_mut()
        .unwrap()
        .remove("case");
    require(
        report,
        "selector-absent-stable-observation-parity",
        control_absent_stable == derived_absent_stable,
        json!({
            "control": control_absent_stable,
            "derived": derived_absent_stable
        }),
    )?;

    report["fixtures"]["nested_relative_cargo_home"] = json!({
        "wrong_token": wrong,
        "control_selected": control_selected,
        "derived_selected_fresh_correct_token_retry": derived_selected_retry,
        "control_absent": control_absent,
        "derived_absent": derived_absent
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    probe: &mut Probe<'_>,
    report: &mut Value,
    name: &str,
    cargo: &Path,
    derived: &Path,
    rustc: &Path,
    rustdoc: &Path,
    git: &Path,
    selected: bool,
    expect_nested_failure: bool,
) -> Result<Value> {
    let root = probe.work.join(name);
    create_private_directory(&root)?;
    let outer = root.join("outer working directory");
    let nested = root.join("nested working directory");
    let home = root.join("fixture home");
    let selected_root = root.join("selected store");
    let empty_source = root.join("empty crates.io source");
    let outer_target = root.join("outer target with spaces");
    let nested_target = root.join("nested target with spaces");
    for directory in [
        &outer,
        &nested,
        &home,
        &selected_root,
        &empty_source,
        &outer_target,
        &nested_target,
    ] {
        create_private_directory(directory)?;
    }
    create_private_directory(&outer.join("src"))?;
    create_private_directory(&nested.join("src"))?;

    let outer_cargo_home = outer.join(LITERAL_CARGO_HOME);
    let nested_cargo_home = nested.join(LITERAL_CARGO_HOME);
    create_private_directory(&outer_cargo_home)?;
    create_private_directory(&nested_cargo_home)?;

    let server = RegistryFixture::start(AuthPolicy::AcceptExpected)?;
    let index = server.sparse_index_url();
    for (cargo_home, marker, token) in [
        (&outer_cargo_home, OUTER_MARKER, OUTER_TOKEN),
        (&nested_cargo_home, NESTED_MARKER, server.expected_token()),
    ] {
        write_text(
            &cargo_home.join("config.toml"),
            &format!(
                "[source.crates-io]\nreplace-with=\"fixture-local-only\"\n[source.fixture-local-only]\ndirectory={}\n[net]\nretry=0\n[registries.{}]\nindex={}\ncredential-provider=\"cargo:token\"\n[env]\nRC2_CWD_MARKER={{value={},force=true}}\n",
                toml_string(
                    empty_source
                        .to_str()
                        .ok_or_else(|| Refusal::new("empty source path is not UTF-8"))?
                ),
                registry_fixture::REGISTRY_NAME,
                toml_string(&index),
                toml_string(marker)
            ),
        )?;
        write_text(
            &cargo_home.join("credentials.toml"),
            &format!(
                "[registries.{}]\ntoken={}\n",
                registry_fixture::REGISTRY_NAME,
                toml_string(token)
            ),
        )?;
    }

    write_text(
        &outer.join("Cargo.toml"),
        "[package]\nname=\"rc2-nested-host\"\nversion=\"0.1.0\"\nedition=\"2024\"\nbuild=\"build.rs\"\n[workspace]\n",
    )?;
    write_text(
        &outer.join("src/main.rs"),
        "fn main(){println!(\"outer-built\");}\n",
    )?;
    write_text(
        &nested.join("Cargo.toml"),
        &format!(
            "[package]\nname=\"rc2-nested-app\"\nversion=\"0.1.0\"\nedition=\"2024\"\nbuild=\"build.rs\"\n[workspace]\n[dependencies]\n{}={{version=\"={}\",registry={}}}\n",
            registry_fixture::CRATE_NAME,
            registry_fixture::CRATE_VERSION,
            toml_string(registry_fixture::REGISTRY_NAME)
        ),
    )?;
    write_text(
        &nested.join("src/main.rs"),
        "fn main(){println!(\"nested-built\");}\n",
    )?;
    write_text(&nested.join("build.rs"), NESTED_BUILD_SCRIPT)?;
    write_text(&outer.join("build.rs"), OUTER_BUILD_SCRIPT)?;

    let outer_config = outer_cargo_home.join("config.toml");
    let outer_credentials = outer_cargo_home.join("credentials.toml");
    let nested_config = nested_cargo_home.join("config.toml");
    let nested_credentials = nested_cargo_home.join("credentials.toml");

    // A valid lockfile is prepared with the correct nested credential. The
    // negative case then changes only the nested token before the real fetch.
    probe.set_base_env(Path::new(LITERAL_CARGO_HOME), &home, rustc, rustdoc, git);
    let base_env = if selected {
        with_selector(&probe.base_env, &selected_root)
    } else {
        probe.base_env.clone()
    };
    let mut lock_env = base_env.clone();
    insert_env(&mut lock_env, "CARGO_TARGET_DIR", nested_target.as_os_str());
    probe.cargo(
        &format!("{name}-nested-lock"),
        cargo,
        strings(["generate-lockfile"]),
        &nested,
        &lock_env,
        0,
    )?;
    if expect_nested_failure {
        write_text(
            &nested_credentials,
            &format!(
                "[registries.{}]\ntoken={}\n",
                registry_fixture::REGISTRY_NAME,
                toml_string(WRONG_NESTED_TOKEN)
            ),
        )?;
    }

    let initial_files = [
        file_fingerprint(&outer_config)?,
        file_fingerprint(&outer_credentials)?,
        file_fingerprint(&nested_config)?,
        file_fingerprint(&nested_credentials)?,
    ];
    require(
        report,
        &format!("{name}-distinct-cwd-config-and-credential-inputs"),
        initial_files[0]["sha256"] != initial_files[2]["sha256"]
            && initial_files[1]["sha256"] != initial_files[3]["sha256"],
        json!({
            "outer_config": initial_files[0],
            "outer_credentials": initial_files[1],
            "nested_config": initial_files[2],
            "nested_credentials": initial_files[3]
        }),
    )?;

    let outer_home_before = snapshot(&outer_cargo_home)?;
    let nested_home_before = snapshot(&nested_cargo_home)?;

    let mut outer_env = base_env.clone();
    insert_env(&mut outer_env, "CARGO_TARGET_DIR", outer_target.as_os_str());
    insert_env(&mut outer_env, "RC2_NESTED_CARGO", cargo.as_os_str());
    insert_env(&mut outer_env, "RC2_NESTED_CWD", nested.as_os_str());
    insert_env(
        &mut outer_env,
        "RC2_NESTED_TARGET",
        nested_target.as_os_str(),
    );
    insert_env(
        &mut outer_env,
        "RC2_EXPECT_NESTED_FAILURE",
        OsStr::new(if expect_nested_failure {
            "true"
        } else {
            "false"
        }),
    );

    probe.cargo(
        &format!("{name}-outer-lock"),
        cargo,
        strings(["generate-lockfile"]),
        &outer,
        &outer_env,
        0,
    )?;
    probe.cargo(
        &format!("{name}-outer-build"),
        cargo,
        [
            strings(["build", "--locked", "--target-dir"]),
            vec![outer_target.as_os_str().to_owned()],
        ]
        .concat(),
        &outer,
        &outer_env,
        0,
    )?;

    let outer_marker_file = find_snapshot_file(
        &outer_target.join("debug/build"),
        "out/outer-observation.txt",
    )?
    .ok_or_else(|| Refusal::new("outer build script did not write its observation"))?;
    let outer_observation = read_key_values(&outer_marker_file)?;
    let selector_expected = expected_selector(selected, &selected_root);
    require(
        report,
        &format!("{name}-outer-home-and-literal-cargo-home-observed"),
        outer_observation.get("outer_marker").map(String::as_str) == Some(OUTER_MARKER)
            && outer_observation.get("cargo_home").map(String::as_str) == Some(LITERAL_CARGO_HOME)
            && outer_observation
                .get("nested_cargo_is_absolute")
                .map(String::as_str)
                == Some("true")
            && outer_observation.get("selector_value").map(String::as_str)
                == Some(selector_expected.as_str())
            && outer_observation
                .get("nested_fetch_exit")
                .map(String::as_str)
                == Some(if expect_nested_failure { "101" } else { "0" })
            && outer_observation
                .get("nested_build_exit")
                .map(String::as_str)
                == Some(if expect_nested_failure { "-1" } else { "0" }),
        json!({
            "outer_marker": outer_observation.get("outer_marker"),
            "cargo_home_literal_preserved": outer_observation.get("cargo_home"),
            "nested_cargo_is_absolute": outer_observation.get("nested_cargo_is_absolute"),
            "selector_value_matches": true,
            "nested_fetch_exit": outer_observation.get("nested_fetch_exit"),
            "nested_build_exit": outer_observation.get("nested_build_exit")
        }),
    )?;

    let outer_binary = outer_target.join("debug/rc2-nested-host");
    let outer_run = probe.command(
        &format!("{name}-outer-executable"),
        &outer_binary,
        Vec::<OsString>::new(),
        &outer,
        &outer_env,
        0,
    )?;
    require(
        report,
        &format!("{name}-outer-build-completed"),
        outer_run.stdout == b"outer-built\n",
        json!({"outer_stdout_sha256": digest::sha256_bytes(&outer_run.stdout)}),
    )?;

    let nested_observation_file = find_snapshot_file(
        &nested_target.join("debug/build"),
        "out/nested-observation.txt",
    )?;
    let nested_observation = if expect_nested_failure {
        Value::Null
    } else {
        let path = nested_observation_file
            .as_ref()
            .ok_or_else(|| Refusal::new("nested build script did not write its observation"))?;
        let values = read_key_values(path)?;
        require(
            report,
            &format!("{name}-nested-home-marker-and-literal-cargo-home-observed"),
            values.get("nested_marker").map(String::as_str) == Some(NESTED_MARKER)
                && values.get("cargo_home").map(String::as_str) == Some(LITERAL_CARGO_HOME)
                && values.get("selector_value").map(String::as_str)
                    == Some(selector_expected.as_str())
                && values.get("target_dir").map(String::as_str) == nested_target.to_str(),
            json!({
                "nested_marker": values.get("nested_marker"),
                "cargo_home_literal_preserved": values.get("cargo_home"),
                "selector_value_matches": true,
                "nested_target_dir_separate": true
            }),
        )?;
        let nested_binary = nested_target.join("debug/rc2-nested-app");
        let nested_run = probe.command(
            &format!("{name}-nested-executable"),
            &nested_binary,
            Vec::<OsString>::new(),
            &nested,
            &lock_env,
            0,
        )?;
        require(
            report,
            &format!("{name}-nested-build-completed"),
            nested_run.stdout == b"nested-built\n",
            json!({"nested_stdout_sha256": digest::sha256_bytes(&nested_run.stdout)}),
        )?;
        json!(values)
    };

    let store = if selected && cargo == derived {
        selected_root.as_path()
    } else {
        nested_cargo_home.as_path()
    };
    let registry_snapshot = if path_exists(&store.join("registry"))? {
        snapshot(&store.join("registry"))?
    } else {
        Vec::new()
    };
    let archive_present = registry_snapshot.iter().any(|row| {
        row["kind"] == "file"
            && row["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("rc2-fixture-leaf-0.1.0.crate"))
            && row["sha256"] == server.crate_checksum()
    });
    let source_present = registry_snapshot.iter().any(|row| {
        row["kind"] == "file"
            && row["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("rc2-fixture-leaf-0.1.0/src/lib.rs"))
    });
    let index_present = registry_snapshot.iter().any(|row| {
        row["kind"] == "file"
            && row["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("rc2-fixture-leaf"))
    });
    let selected_registry_present = path_exists(&selected_root.join("registry"))?;
    let outer_registry_present = path_exists(&outer_cargo_home.join("registry"))?;
    let nested_registry_present = path_exists(&nested_cargo_home.join("registry"))?;
    let expected_selected_store = selected && cargo == derived;
    let expected_registry_location = if expected_selected_store {
        selected_registry_present && !outer_registry_present && !nested_registry_present
    } else {
        nested_registry_present && !outer_registry_present && !selected_registry_present
    };
    let routes = server.sanitized_observations();
    let protected_routes = routes
        .iter()
        .filter(|row| row["route"] != "/index/config.json")
        .collect::<Vec<_>>();
    let protected_auth_mismatch_observed = protected_routes
        .iter()
        .any(|row| row["authorization_matches"] == false);
    let protected_auth_all_matched = !protected_routes.is_empty()
        && protected_routes
            .iter()
            .all(|row| row["authorization_matches"] == true);
    let download_auth_matched = protected_routes.iter().any(|row| {
        row["route"] == "/api/rc2-fixture-leaf/0.1.0/download"
            && row["authorization_matches"] == true
    });
    let download_auth_mismatch = protected_routes.iter().any(|row| {
        row["route"] == "/api/rc2-fixture-leaf/0.1.0/download"
            && row["authorization_matches"] == false
    });
    let config_credentials_preserved = [
        (&outer_config, &initial_files[0]),
        (&outer_credentials, &initial_files[1]),
        (&nested_config, &initial_files[2]),
        (&nested_credentials, &initial_files[3]),
    ]
    .into_iter()
    .all(|(path, before)| file_fingerprint(path).is_ok_and(|after| after == *before));
    let selected_snapshot = snapshot(&selected_root)?;
    let no_credentials_under_selected_root = selected_snapshot.iter().all(|row| {
        !row["path"]
            .as_str()
            .is_some_and(|path| path == "credentials.toml" || path.ends_with("/credentials.toml"))
    });
    if expected_selected_store {
        require(
            report,
            &format!("{name}-complete-relative-homes-preserved-and-locks-routed"),
            outer_home_before == snapshot(&outer_cargo_home)?
                && nested_home_before == snapshot(&nested_cargo_home)?
                && plain_file(&selected_root.join(".package-cache"))?
                && plain_file(&selected_root.join(".package-cache-mutate"))?
                && sqlite_database(&selected_root.join(".global-cache"))?,
            json!({"outer_home_snapshot":outer_home_before,
                "nested_home_snapshot":nested_home_before,
                "selected_store_snapshot":selected_snapshot,
                "scope":"Nested derived-selected complete home preservation and actual lock/database paths; not concurrent GC semantics"}),
        )?;
    }

    require(
        report,
        &format!("{name}-registry-auth-and-correct-storage-root"),
        expected_registry_location
            && index_present
            && if expect_nested_failure {
                protected_auth_mismatch_observed
                    && download_auth_mismatch
                    && !archive_present
                    && !source_present
            } else {
                protected_auth_all_matched
                    && download_auth_matched
                    && archive_present
                    && source_present
            }
            && no_credentials_under_selected_root
            && config_credentials_preserved,
        json!({
            "expected_registry_location": expected_registry_location,
            "selected_registry_present": selected_registry_present,
            "outer_relative_home_registry_present": outer_registry_present,
            "nested_relative_home_registry_present": nested_registry_present,
            "index_present": index_present,
            "archive_present": archive_present,
            "source_present": source_present,
            "protected_auth_all_matched": protected_auth_all_matched,
            "protected_auth_mismatch_observed": protected_auth_mismatch_observed,
            "download_auth_matched": download_auth_matched,
            "download_auth_mismatch": download_auth_mismatch,
            "routes": routes,
            "config_credentials_preserved": config_credentials_preserved,
            "no_credentials_under_selected_root": no_credentials_under_selected_root,
            "registry_entries": registry_snapshot
        }),
    )?;

    let summary = json!({
        "case": name,
        "selected": selected,
        "expected_nested_failure": expect_nested_failure,
        "outer_marker": outer_observation.get("outer_marker"),
        "outer_cargo_home_literal_preserved": outer_observation.get("cargo_home").map(String::as_str) == Some(LITERAL_CARGO_HOME),
        "nested_marker": nested_observation.get("nested_marker"),
        "nested_cargo_home_literal_preserved": if expect_nested_failure {
            Value::Null
        } else {
            json!(nested_observation["cargo_home"] == LITERAL_CARGO_HOME)
        },
        "registry_store": if expected_selected_store { "selected-root" } else { "nested-relative-cargo-home" },
        "registry_location_correct": expected_registry_location,
        "index_present": index_present,
        "archive_present": archive_present,
        "source_present": source_present,
        "protected_auth_all_matched": protected_auth_all_matched,
        "protected_auth_mismatch_observed": protected_auth_mismatch_observed,
        "download_auth_matched": download_auth_matched,
        "download_auth_mismatch": download_auth_mismatch,
        "config_credentials_preserved": config_credentials_preserved,
        "credentials_absent_from_selected_root": no_credentials_under_selected_root
    });
    Ok(summary)
}

fn expected_selector(selected: bool, selected_root: &Path) -> String {
    if selected {
        selected_root.to_string_lossy().into_owned()
    } else {
        "<unset>".to_owned()
    }
}

fn find_snapshot_file(root: &Path, suffix: &str) -> Result<Option<PathBuf>> {
    let rows = snapshot(root)?;
    let mut matches = rows
        .iter()
        .filter(|row| row["kind"] == "file")
        .filter_map(|row| row["path"].as_str())
        .filter(|path| path.ends_with(suffix))
        .map(|path| root.join(path))
        .collect::<Vec<_>>();
    matches.sort();
    if matches.len() > 1 {
        return Err(Refusal::new(format!(
            "nested relative-home fixture has multiple artifacts ending in {suffix}"
        )));
    }
    Ok(matches.pop())
}

fn read_key_values(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path)
        .map_err(|error| Refusal::new(format!("cannot read fixture observation: {error}")))?;
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Refusal::new("malformed fixture observation record"))?;
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Refusal::new(
                "duplicate key in nested relative-home fixture observation",
            ));
        }
    }
    Ok(values)
}

fn require(report: &mut Value, name: &str, passed: bool, observation: Value) -> Result<()> {
    report["checks"]
        .as_array_mut()
        .ok_or_else(|| Refusal::new("missing nested fixture checks array"))?
        .push(json!({"name":name,"passed":passed,"observation":observation}));
    if passed {
        Ok(())
    } else {
        Err(Refusal::new(format!(
            "nested relative-home fixture check failed: {name}"
        )))
    }
}

const OUTER_BUILD_SCRIPT: &str = r#"
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let marker = env::var("RC2_CWD_MARKER").expect("outer Cargo home marker missing");
    let cargo_home = env::var("CARGO_HOME").expect("inherited CARGO_HOME missing");
    assert_eq!(cargo_home, "relative-cargo-home");
    let cargo = PathBuf::from(env::var_os("RC2_NESTED_CARGO").expect("nested Cargo path missing"));
    assert!(cargo.is_absolute());
    let nested = PathBuf::from(env::var_os("RC2_NESTED_CWD").expect("nested cwd missing"));
    let target = env::var_os("RC2_NESTED_TARGET").expect("nested target missing");
    let outer_target = env::var_os("CARGO_TARGET_DIR").expect("outer target missing");
    assert_ne!(target, outer_target);
    let mode = env::var("RC2_EXPECT_NESTED_FAILURE").expect("nested mode missing");
    let selector = env::var("AMI_RUST_CARGO_STORAGE_ROOT")
        .unwrap_or_else(|_| "<unset>".to_owned());

    let fetch = Command::new(&cargo)
        .args(["fetch", "--locked"])
        .current_dir(&nested)
        .env("CARGO_TARGET_DIR", &target)
        .output()
        .expect("could not start nested Cargo fetch");
    let fetch_code = fetch.status.code().unwrap_or(-1);
    let build_code = if mode == "true" {
        assert_eq!(fetch_code, 101, "nested Cargo fetch did not fail as expected");
        -1
    } else {
        assert!(fetch.status.success(), "nested Cargo fetch failed");
        let build = Command::new(&cargo)
            .args(["build", "--locked"])
            .current_dir(&nested)
            .env("CARGO_TARGET_DIR", &target)
            .output()
            .expect("could not start nested Cargo build");
        let code = build.status.code().unwrap_or(-1);
        assert!(build.status.success(), "nested Cargo build failed");
        code
    };
    let observation = format!(
        "outer_marker={}\ncargo_home={}\nnested_cargo_is_absolute=true\nselector_value={}\nnested_fetch_exit={}\nnested_build_exit={}\n",
        marker, cargo_home, selector, fetch_code, build_code
    );
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("outer-observation.txt"), observation)
        .expect("cannot write outer observation");
}
"#;

const NESTED_BUILD_SCRIPT: &str = r#"
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let marker = env::var("RC2_CWD_MARKER").expect("nested Cargo home marker missing");
    let cargo_home = env::var("CARGO_HOME").expect("inherited CARGO_HOME missing");
    assert_eq!(cargo_home, "relative-cargo-home");
    let selector = env::var("AMI_RUST_CARGO_STORAGE_ROOT")
        .unwrap_or_else(|_| "<unset>".to_owned());
    let target_dir = env::var("CARGO_TARGET_DIR").expect("nested target directory missing");
    let observation = format!(
        "nested_marker={}\ncargo_home={}\nselector_value={}\ntarget_dir={}\n",
        marker, cargo_home, selector, target_dir
    );
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("nested-observation.txt"), observation)
        .expect("cannot write nested observation");
}
"#;

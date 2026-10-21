//! Synthetic registry credential lookup through the actual selected Cargo.
use super::*;
use registry_fixture::{AuthPolicy, RegistryFixture};
use std::io::BufRead;

pub(super) fn provider(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    if arguments.count() != 0 {
        return Err(Refusal::new("unexpected credential fixture CLI arguments"));
    }
    let mut output = std::io::stdout().lock();
    output.write_all(b"{\"v\":[1]}\n")?;
    output.flush()?;
    let mut input = std::io::stdin().lock().take(16 * 1024);
    let mut line = Vec::new();
    input.read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        return Err(Refusal::new(
            "incomplete or oversized credential fixture request",
        ));
    }
    let request: Value = serde_json::from_slice(&line)
        .map_err(|_| Refusal::new("invalid credential fixture request JSON"))?;
    let args = request["args"]
        .as_array()
        .ok_or_else(|| Refusal::new("credential fixture has no argument list"))?;
    if args.len() != 4
        || args[0] != "--rc2-synthetic-provider"
        || !matches!(args[1].as_str(), Some("ok" | "not-found"))
    {
        return Err(Refusal::new("credential fixture argument contract differs"));
    }
    let directory = PathBuf::from(
        args[2]
            .as_str()
            .ok_or_else(|| Refusal::new("credential observation path is not a string"))?,
    );
    let expected_index = args[3]
        .as_str()
        .ok_or_else(|| Refusal::new("credential fixture index is not a string"))?;
    if !expected_index.starts_with("sparse+http://127.0.0.1:")
        || !expected_index.ends_with("/index/")
        || request["v"] != 1
        || request["kind"] != "get"
        || request["operation"] != "read"
        || request["registry"]["name"] != registry_fixture::REGISTRY_NAME
        || request["registry"]["index-url"] != expected_index
        || !directory.is_absolute()
        || !plain_directory(&directory)?
    {
        return Err(Refusal::new(
            "credential fixture only supports its synthetic Get(Read) request",
        ));
    }
    let observation = json!({"v":1,"kind":"get","operation":"read","registry_name":registry_fixture::REGISTRY_NAME,"index_url":expected_index,"arguments_match":true,"mode":args[1]});
    let bytes =
        serde_json::to_vec(&observation).map_err(|error| Refusal::new(error.to_string()))?;
    write_new_file(
        &directory.join(format!("request-{}.json", std::process::id())),
        &bytes,
    )?;
    let response = if args[1] == "not-found" {
        json!({"Err":{"kind":"not-found"}})
    } else {
        json!({"Ok":{"kind":"get","token":registry_fixture::SYNTHETIC_AUTHORIZATION,"cache":"never","operation_independent":false}})
    };
    serde_json::to_writer(&mut output, &response)
        .map_err(|error| Refusal::new(error.to_string()))?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

pub(super) fn run(probe: &mut Probe<'_>, report: &mut Value) -> Result<()> {
    report["scope"] = json!(
        "Actual host Cargo synthetic loopback registry Get(Read) and credentials-file lookup only; not real credential stores, full RC2, AROS or publication."
    );
    report["limitations"] = json!([
        "No real secrets, external registry/provider, Git authentication, nested/concurrent Cargo or SDK activation.",
        "The loopback fixture is not a general network sandbox."
    ]);
    let tool = |name: &str| -> Result<PathBuf> {
        probe
            .tools
            .iter()
            .find(|row| row.name == name)
            .map(|row| row.path.clone())
            .ok_or_else(|| Refusal::new(format!("missing {name}")))
    };
    let control = tool("control-cargo")?;
    let derived = tool("derived-cargo")?;
    let rustc = tool("rustc")?;
    let rustdoc = tool("rustdoc")?;
    let git = tool("git")?;
    let provider = fs::canonicalize(std::env::current_exe()?)?;
    create_private_directory(&probe.work.join("temporary"))?;
    let mut observations = Vec::new();
    for credential in ["provider", "credentials-file"] {
        for (name, cargo, selected) in [
            ("control-selected", &control, true),
            ("derived-selected", &derived, true),
            ("control-absent", &control, false),
            ("derived-absent", &derived, false),
        ] {
            let case = format!("{credential}-{name}");
            let observation = case_run(
                probe,
                report,
                &case,
                cargo,
                &rustc,
                &rustdoc,
                &git,
                &provider,
                credential,
                selected,
                AuthPolicy::AcceptExpected,
                false,
            )?;
            observations.push(observation);
        }
    }
    case_run(
        probe,
        report,
        "provider-not-found",
        &derived,
        &rustc,
        &rustdoc,
        &git,
        &provider,
        "provider",
        true,
        AuthPolicy::AcceptExpected,
        true,
    )?;
    case_run(
        probe,
        report,
        "server-auth-refusal",
        &derived,
        &rustc,
        &rustdoc,
        &git,
        &provider,
        "credentials-file",
        true,
        AuthPolicy::RejectAll,
        false,
    )?;
    for (left, right) in [(2, 3), (6, 7)] {
        require(
            report,
            &format!(
                "{}-selector-absent-stable-equivalence",
                if left == 2 {
                    "provider"
                } else {
                    "credentials-file"
                }
            ),
            observations[left] == observations[right],
            json!({"control":observations[left],"derived":observations[right]}),
        )?;
    }
    report["fixtures"]["registry"] = json!(observations);
    Ok(())
}

// This explicit internal-fixture argument list keeps every case's selection visible.
#[allow(clippy::too_many_arguments)]
fn case_run(
    probe: &mut Probe<'_>,
    report: &mut Value,
    name: &str,
    cargo: &Path,
    rustc: &Path,
    rustdoc: &Path,
    git: &Path,
    provider: &Path,
    credential: &str,
    selected: bool,
    policy: AuthPolicy,
    missing: bool,
) -> Result<Value> {
    let root = probe.work.join(name);
    create_private_directory(&root)?;
    let home = root.join("home");
    let cargo_home = root.join("original cargo home");
    let cache = root.join("selected store");
    let project = root.join("project with spaces");
    let empty = root.join("empty source");
    let requests = root.join("provider observations with spaces");
    for directory in [&home, &cargo_home, &cache, &project, &empty, &requests] {
        create_private_directory(directory)?;
    }
    create_private_directory(&project.join("src"))?;
    write_text(
        &project.join("Cargo.toml"),
        "[package]\nname=\"rc2_registry_app\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[workspace]\n[dependencies]\nrc2-fixture-leaf={version=\"=0.1.0\",registry=\"rc2-fixture\"}\n",
    )?;
    write_text(&project.join("src/main.rs"), "fn main(){}\n")?;
    if !selected {
        create_private_directory(&project.join(".cargo"))?;
        write_text(
            &project.join(".cargo/config.toml"),
            "[env]\nAMI_RUST_CARGO_STORAGE_ROOT=\"ordinary-child-env-only\"\n",
        )?;
    }
    let server = RegistryFixture::start(policy)?;
    let index = server.sparse_index_url();
    let provider_config = if credential == "provider" {
        serde_json::to_string(&vec![
            provider
                .to_str()
                .ok_or_else(|| Refusal::new("provider path is not UTF-8"))?,
            "--rc2-synthetic-provider",
            if missing { "not-found" } else { "ok" },
            requests
                .to_str()
                .ok_or_else(|| Refusal::new("request path is not UTF-8"))?,
            index.as_str(),
        ])
        .map_err(|error| Refusal::new(error.to_string()))?
    } else {
        "\"cargo:token\"".to_owned()
    };
    let config = format!(
        "[source.crates-io]\nreplace-with=\"local-empty\"\n[source.local-empty]\ndirectory={}\n[net]\nretry=0\n[registries.rc2-fixture]\nindex={}\ncredential-provider={}\n",
        toml_string(empty.to_str().unwrap()),
        toml_string(&index),
        provider_config
    );
    write_text(&cargo_home.join("config.toml"), &config)?;
    let credentials = if credential == "credentials-file" {
        format!(
            "[registries.rc2-fixture]\ntoken={}\n",
            toml_string(server.expected_token())
        )
    } else {
        "# Synthetic provider, no stored token.\n".to_owned()
    };
    write_text(&cargo_home.join("credentials.toml"), &credentials)?;
    let before = [
        file_fingerprint(&cargo_home.join("config.toml"))?,
        file_fingerprint(&cargo_home.join("credentials.toml"))?,
    ];
    probe.set_base_env(&cargo_home, &home, rustc, rustdoc, git);
    let env = if selected {
        with_selector(&probe.base_env, &cache)
    } else {
        probe.base_env.clone()
    };
    let expected_failure = missing || policy == AuthPolicy::RejectAll;
    probe.cargo(
        &format!("{name}-lock"),
        cargo,
        strings(["generate-lockfile"]),
        &project,
        &env,
        if expected_failure { 101 } else { 0 },
    )?;
    if !expected_failure {
        probe.cargo(
            &format!("{name}-fetch"),
            cargo,
            strings(["fetch", "--locked"]),
            &project,
            &env,
            0,
        )?;
        probe.cargo(
            &format!("{name}-check"),
            cargo,
            strings(["check", "--locked"]),
            &project,
            &env,
            0,
        )?;
    }
    let store = if selected
        && cargo
            == probe
                .tools
                .iter()
                .find(|row| row.name == "derived-cargo")
                .unwrap()
                .path
    {
        &cache
    } else {
        &cargo_home
    };
    let wrong = if store == &cache { &cargo_home } else { &cache };
    let files = if path_exists(&store.join("registry"))? {
        snapshot(&store.join("registry"))?
    } else {
        Vec::new()
    };
    let archive_present = files.iter().any(|row| {
        row["kind"] == "file"
            && row["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("rc2-fixture-leaf-0.1.0.crate"))
            && row["sha256"] == server.crate_checksum()
    });
    let source_present = files.iter().any(|row| {
        row["kind"] == "file"
            && row["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("rc2-fixture-leaf-0.1.0/src/lib.rs"))
    });
    let requests = fs::read_dir(&requests)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let provider_requests = requests
        .iter()
        .map(|path| {
            fs::read(path).and_then(|bytes| {
                serde_json::from_slice::<Value>(&bytes).map_err(std::io::Error::other)
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let routes = server.sanitized_observations();
    let (matched, unmatched) = server.authorization_counts();
    let auth_routes = routes
        .iter()
        .filter(|row| row["route"] != "/index/config.json")
        .collect::<Vec<_>>();
    require(
        report,
        &format!("{name}-original-config-credentials-preserved"),
        before
            == [
                file_fingerprint(&cargo_home.join("config.toml"))?,
                file_fingerprint(&cargo_home.join("credentials.toml"))?,
            ],
        json!({"config":before[0],"credentials":before[1]}),
    )?;
    require(
        report,
        &format!("{name}-auth-and-storage-effects"),
        !path_exists(&wrong.join("registry"))?
            && !path_exists(&cache.join("credentials.toml"))?
            && if expected_failure {
                !archive_present && !source_present
            } else {
                archive_present
                    && source_present
                    && matched > 0
                    && auth_routes
                        .iter()
                        .all(|row| row["authorization_matches"] == true)
            },
        json!({"archive_present":archive_present,"source_present":source_present,"matched_authorization_requests":matched,"nonmatching_authorization_requests":unmatched,"routes":routes,"provider_requests":provider_requests,"expected_failure":expected_failure}),
    )?;
    require(
        report,
        &format!("{name}-provider-request-contract"),
        if credential == "provider" {
            provider_requests.len() >= if missing { 1 } else { 2 }
                && provider_requests.iter().all(|request| {
                    provider_request_matches(
                        request,
                        &index,
                        if missing { "not-found" } else { "ok" },
                    )
                })
        } else {
            provider_requests.is_empty()
        },
        json!({"observed_provider_requests":provider_requests.len(),"provider_expected":credential=="provider"}),
    )?;
    if policy == AuthPolicy::RejectAll {
        require(
            report,
            "matching-token-server-refusal-observed",
            protected_authorization_matched(&routes),
            json!({"matching_request_rejected":true}),
        )?;
    }
    Ok(
        json!({"credential":credential,"selected":selected,"archive_present":archive_present,"source_present":source_present,"provider_used":!provider_requests.is_empty(),"config_credentials_preserved":true,"expected_failure":expected_failure}),
    )
}

fn require(report: &mut Value, name: &str, passed: bool, observation: Value) -> Result<()> {
    report["checks"]
        .as_array_mut()
        .ok_or_else(|| Refusal::new("missing registry checks array"))?
        .push(json!({"name":name,"passed":passed,"observation":observation}));
    if passed {
        Ok(())
    } else {
        Err(Refusal::new(format!(
            "registry fixture check failed: {name}"
        )))
    }
}

fn provider_request_matches(request: &Value, index: &str, mode: &str) -> bool {
    request["v"] == 1
        && request["kind"] == "get"
        && request["operation"] == "read"
        && request["registry_name"] == registry_fixture::REGISTRY_NAME
        && request["arguments_match"] == true
        && request["index_url"] == index
        && request["mode"] == mode
}

fn protected_authorization_matched(routes: &[Value]) -> bool {
    routes.iter().any(|row| {
        matches!(
            row["route"].as_str(),
            Some("/index/rc/2-/rc2-fixture-leaf" | "/api/rc2-fixture-leaf/0.1.0/download")
        ) && row["authorization_matches"] == true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_provider_requires_the_requested_failure_mode() {
        let index = "sparse+http://127.0.0.1:12345/index/";
        let mut request = json!({"v":1,"kind":"get","operation":"read","registry_name":"rc2-fixture","arguments_match":true,"index_url":index,"mode":"not-found"});
        assert!(provider_request_matches(&request, index, "not-found"));
        request["mode"] = json!("ok");
        assert!(!provider_request_matches(&request, index, "not-found"));
        assert!(provider_request_matches(&request, index, "ok"));
    }

    #[test]
    fn config_authorization_cannot_prove_a_protected_request_was_rejected() {
        let mut routes = vec![json!({"route":"/index/config.json","authorization_matches":true})];
        assert!(!protected_authorization_matched(&routes));
        routes.push(json!({"route":"/index/rc/2-/rc2-fixture-leaf","authorization_matches":true}));
        assert!(protected_authorization_matched(&routes));
        routes[1]["authorization_matches"] = json!(false);
        assert!(!protected_authorization_matched(&routes));
    }
}

//! Actual build-directory writes and enabled analysis-log routing.
//! These are disposable host fixtures, not SDK activation evidence.
use super::*;

pub(super) fn run(probe: &mut Probe<'_>, report: &mut Value) -> Result<()> {
    report["scope"] = json!(
        "Host-only synthetic build-directory and analysis-log routing; not full RC2, SDK, AROS or publication acceptance."
    );
    report["limitations"] = json!([
        "No registry, provider, nested/concurrent Cargo, activation or AROS evidence.",
        "Selector-absent comparison covers bounded summary parity; full output/config/diagnostic equivalence remains open.",
        "Uses pinned Cargo's test-only nightly override for unstable analysis features."
    ]);
    let selected_tool = |name: &str| -> Result<PathBuf> {
        probe
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .map(|tool| tool.path.clone())
            .ok_or_else(|| Refusal::new(format!("missing {name} fixture tool")))
    };
    let control = selected_tool("control-cargo")?;
    let derived = selected_tool("derived-cargo")?;
    let rustc = selected_tool("rustc")?;
    let rustdoc = selected_tool("rustdoc")?;
    let git = selected_tool("git")?;
    create_private_directory(&probe.work.join("temporary"))?;
    create_private_directory(&probe.output.join("analysis-logs"))?;
    let mut observations = Vec::new();
    for (name, cargo, selected) in [
        ("control-selected", &control, true),
        ("derived-selected", &derived, true),
        ("control-absent", &control, false),
        ("derived-absent", &derived, false),
    ] {
        let root = probe.work.join(name);
        create_private_directory(&root)?;
        let home = root.join("home");
        let cargo_home = root.join("cargo home");
        let cache = root.join("selected store");
        let project = root.join("project with spaces");
        let empty = root.join("empty source");
        for directory in [&home, &cargo_home, &cache, &project, &empty] {
            create_private_directory(directory)?;
        }
        create_private_directory(&project.join("src"))?;
        create_private_directory(&project.join(".cargo"))?;
        write_text(
            &project.join("Cargo.toml"),
            "[package]\nname=\"rc2_lifecycle_fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[workspace]\n",
        )?;
        write_text(
            &project.join("src/main.rs"),
            "fn main(){println!(\"rc2-lifecycle-ok\");}\n",
        )?;
        // This ordinary child-only environment entry must not activate storage.
        write_text(
            &project.join(".cargo/config.toml"),
            if selected {
                "# No selector conflict.\n"
            } else {
                "[env]\nAMI_RUST_CARGO_STORAGE_ROOT=\"ordinary-child-env-only\"\n"
            },
        )?;
        let config = cargo_home.join("config.toml");
        let base = format!(
            "[source.crates-io]\nreplace-with=\"local-empty\"\n[source.local-empty]\ndirectory={}\n[build]\nbuild-dir=\"{{cargo-cache-home}}/intermediates/{{workspace-path-hash}}\"\n",
            toml_string(
                empty
                    .to_str()
                    .ok_or_else(|| Refusal::new("fixture path is not UTF-8"))?
            )
        );
        write_text(&config, &base)?;
        write_text(
            &cargo_home.join("credentials.toml"),
            "# No credential is used by this fixture.\n",
        )?;
        let initial_config = file_fingerprint(&config)?;
        let project_config = file_fingerprint(&project.join(".cargo/config.toml"))?;
        let credentials_before = file_fingerprint(&cargo_home.join("credentials.toml"))?;
        probe.set_base_env(&cargo_home, &home, &rustc, &rustdoc, &git);
        let env = if selected {
            with_selector(&probe.base_env, &cache)
        } else {
            probe.base_env.clone()
        };
        let store = if selected && name.starts_with("derived-") {
            &cache
        } else {
            &cargo_home
        };
        let store_identity = directory_identity(store)?;
        let other = if store == &cache { &cargo_home } else { &cache };
        probe.cargo(
            &format!("{name}-lock"),
            cargo,
            strings(["generate-lockfile", "--offline"]),
            &project,
            &env,
            0,
        )?;
        probe.cargo(
            &format!("{name}-build"),
            cargo,
            strings(["build", "--locked", "--offline"]),
            &project,
            &env,
            0,
        )?;
        require(
            report,
            &format!("{name}-initial-config-preserved"),
            file_fingerprint(&config)? == initial_config
                && file_fingerprint(&project.join(".cargo/config.toml"))? == project_config,
            json!({"config":initial_config,"project_config":project_config}),
        )?;
        let build_files = snapshot(&store.join("intermediates"))?;
        let has_object = build_files.iter().any(|row| {
            row["kind"] == "file"
                && row["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(".o") || path.ends_with(".rmeta"))
        });
        require(
            report,
            &format!("{name}-actual-build-directory-writes"),
            has_object && !path_exists(&other.join("intermediates"))?,
            json!({"store":os_metadata(store.as_os_str()),"entries":build_files}),
        )?;
        let binary = project.join("target/debug/rc2_lifecycle_fixture");
        let run = probe.command(
            &format!("{name}-executable"),
            &binary,
            Vec::<OsString>::new(),
            &project,
            &env,
            0,
        )?;
        require(
            report,
            &format!("{name}-actual-executable"),
            run.stdout == b"rc2-lifecycle-ok\n",
            json!({"stdout":String::from_utf8_lossy(&run.stdout)}),
        )?;
        // Config enabled alone is deliberately insufficient on stable Cargo.
        write_text(
            &config,
            &(base.clone() + "[build.analysis]\nenabled=true\n"),
        )?;
        let disabled_config = file_fingerprint(&config)?;
        let ignored = probe.cargo(
            &format!("{name}-analysis-disabled-control"),
            cargo,
            strings(["check", "--locked", "--offline"]),
            &project,
            &env,
            0,
        )?;
        require(
            report,
            &format!("{name}-analysis-disabled-refusal"),
            contains_bytes(&ignored.stderr, b"ignoring 'build.analysis'")
                && !path_exists(&store.join("log"))?
                && !path_exists(&other.join("log"))?,
            json!({"warning_observed":true,"new_analysis_log":false}),
        )?;
        require(
            report,
            &format!("{name}-disabled-config-preserved"),
            file_fingerprint(&config)? == disabled_config
                && file_fingerprint(&project.join(".cargo/config.toml"))? == project_config,
            json!({"config":disabled_config,"project_config":project_config}),
        )?;
        write_text(
            &config,
            &(base.clone() + "[unstable]\nbuild-analysis=true\n[build.analysis]\nenabled=true\n"),
        )?;
        let enabled_config = file_fingerprint(&config)?;
        let mut nightly_env = env.clone();
        insert_env(
            &mut nightly_env,
            "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS",
            OsStr::new("nightly"),
        );
        probe.cargo(
            &format!("{name}-analysis-check"),
            cargo,
            strings(["check", "--locked", "--offline", "-Zbuild-analysis"]),
            &project,
            &nightly_env,
            0,
        )?;
        let logs = analysis_logs(&store.join("log"))?;
        let wrong_store_log = path_exists(&other.join("log"))?;
        let routing_check_name = format!("{name}-enabled-jsonl-log-routing");
        require(
            report,
            &routing_check_name,
            logs.len() == 1 && !wrong_store_log,
            json!({"logs":logs,"wrong_store_log":wrong_store_log}),
        )?;
        let sessions = probe.cargo(
            &format!("{name}-analysis-sessions"),
            cargo,
            strings(["report", "sessions", "-Zbuild-analysis"]),
            &project,
            &nightly_env,
            0,
        )?;
        let session_id = logs
            .first()
            .and_then(|log| log["session_id"].as_str())
            .ok_or_else(|| Refusal::new("missing analysis session id"))?;
        let retained_logs = retain_analysis_logs(&probe.output, name, &store.join("log"), &logs)?;
        record_retained_analysis_logs(report, &routing_check_name, &retained_logs)?;
        require(
            report,
            &format!("{name}-analysis-report-finds-session"),
            contains_bytes(&sessions.stderr, session_id.as_bytes()),
            json!({"session_id":session_id,"reported":true,"retained_logs":retained_logs}),
        )?;
        require(
            report,
            &format!("{name}-original-config-credentials-unchanged-by-Cargo"),
            file_fingerprint(&config)? == enabled_config
                && file_fingerprint(&project.join(".cargo/config.toml"))? == project_config
                && file_fingerprint(&cargo_home.join("credentials.toml"))? == credentials_before,
            json!({"config":enabled_config,"credentials":credentials_before}),
        )?;
        require(
            report,
            &format!("{name}-store-root-identity-preserved"),
            directory_identity(store)? == store_identity,
            json!({"identity":store_identity}),
        )?;
        observations.push(json!({"case":name,"selected":selected,"build_written":has_object,"executable_stdout":String::from_utf8_lossy(&run.stdout),"analysis_log_count":logs.len(),"report_session_found":true,"credentials_preserved":true}));
    }
    // Compare stable behavior, never timestamps or host-local session identifiers.
    let mut control = observations[2].clone();
    let mut derived = observations[3].clone();
    control.as_object_mut().unwrap().remove("case");
    derived.as_object_mut().unwrap().remove("case");
    require(
        report,
        "selector-absent-build-analysis-summary-parity",
        control == derived,
        json!({"control":control,"derived":derived}),
    )?;
    report["fixtures"]["lifecycle"] = json!(observations);
    Ok(())
}

fn require(report: &mut Value, name: &str, passed: bool, observation: Value) -> Result<()> {
    let rows = report["checks"]
        .as_array_mut()
        .ok_or_else(|| Refusal::new("missing lifecycle checks array"))?;
    rows.push(json!({"name":name,"passed":passed,"observation":observation}));
    if passed {
        Ok(())
    } else {
        Err(Refusal::new(format!(
            "storage lifecycle check failed: {name}"
        )))
    }
}

fn record_retained_analysis_logs(
    report: &mut Value,
    check_name: &str,
    logs: &[Value],
) -> Result<()> {
    let checks = report["checks"]
        .as_array_mut()
        .ok_or_else(|| Refusal::new("missing lifecycle checks array"))?;
    let check = checks
        .iter_mut()
        .rev()
        .find(|check| check["name"].as_str() == Some(check_name))
        .ok_or_else(|| Refusal::new("missing analysis log routing check"))?;
    check["observation"]["retained_logs"] = json!(logs);
    Ok(())
}

fn analysis_logs(directory: &Path) -> Result<Vec<Value>> {
    if !plain_directory(directory)? {
        return Err(Refusal::new("analysis log root is not a plain directory"));
    }
    let mut files = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    let mut result = Vec::new();
    for path in files {
        if !plain_file(&path)? || path.extension() != Some(OsStr::new("jsonl")) {
            return Err(Refusal::new(
                "unexpected entry in Cargo analysis log fixture",
            ));
        }
        let bytes = read_plain_file_stably(&path)?;
        if bytes.is_empty() || bytes.len() > STREAM_LIMIT {
            return Err(Refusal::new(
                "empty or oversized Cargo analysis log fixture",
            ));
        }
        let mut lines = 0;
        let records = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        for line in records.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                return Err(Refusal::new("empty JSONL record in Cargo analysis log"));
            }
            let value: Value = serde_json::from_slice(line)
                .map_err(|error| Refusal::new(format!("invalid Cargo analysis JSONL: {error}")))?;
            if !value.is_object() {
                return Err(Refusal::new("Cargo analysis line is not an object"));
            }
            lines += 1;
        }
        if lines == 0 {
            return Err(Refusal::new("analysis log has no JSON object records"));
        }
        result.push(json!({"session_id":path.file_stem().and_then(OsStr::to_str).ok_or_else(|| Refusal::new("analysis session is not UTF-8"))?,"file_name":path.file_name().and_then(OsStr::to_str).ok_or_else(|| Refusal::new("analysis log filename is not UTF-8"))?,"bytes":bytes.len(),"sha256":digest::sha256_bytes(&bytes),"json_lines":lines}));
    }
    Ok(result)
}

fn retain_analysis_logs(
    output: &Path,
    case: &str,
    source_directory: &Path,
    logs: &[Value],
) -> Result<Vec<Value>> {
    let output_identity = directory_identity(output)?;
    let source_directory_identity = directory_identity(source_directory)?;
    let analysis_root = output.join("analysis-logs");
    let analysis_root_identity = directory_identity(&analysis_root)?;
    let case_directory = analysis_root.join(case);
    create_private_directory(&case_directory)?;
    let case_directory_identity = directory_identity(&case_directory)?;
    let mut retained = Vec::with_capacity(logs.len());

    for log in logs {
        let file_name = log["file_name"]
            .as_str()
            .ok_or_else(|| Refusal::new("missing analysis log filename"))?;
        let session_id = log["session_id"]
            .as_str()
            .ok_or_else(|| Refusal::new("missing analysis session id"))?;
        let expected_bytes = log["bytes"]
            .as_u64()
            .ok_or_else(|| Refusal::new("missing analysis log byte count"))?;
        let expected_sha256 = log["sha256"]
            .as_str()
            .ok_or_else(|| Refusal::new("missing analysis log digest"))?;
        let source = source_directory.join(file_name);
        let source_bytes = read_plain_file_stably(&source)?;
        if source_bytes.len() as u64 != expected_bytes
            || digest::sha256_bytes(&source_bytes) != expected_sha256
        {
            return Err(Refusal::new(
                "Cargo analysis log changed after JSONL validation",
            ));
        }

        let destination = case_directory.join(file_name);
        write_new_file(&destination, &source_bytes)?;
        let copied_bytes = verify_retained_log_file(&destination, expected_bytes, expected_sha256)?;
        if copied_bytes != source_bytes {
            return Err(Refusal::new(
                "retained Cargo analysis log differs from its source bytes",
            ));
        }
        if directory_identity(output)? != output_identity
            || directory_identity(source_directory)? != source_directory_identity
            || directory_identity(&analysis_root)? != analysis_root_identity
            || directory_identity(&case_directory)? != case_directory_identity
        {
            return Err(Refusal::new(
                "analysis log retention directory identity changed during copy",
            ));
        }
        let relative_destination = destination
            .strip_prefix(output)
            .map_err(|error| Refusal::new(format!("retained log escaped output: {error}")))?
            .to_str()
            .ok_or_else(|| Refusal::new("retained analysis log path is not UTF-8"))?;
        retained.push(json!({
            "session_id": session_id,
            "destination": relative_destination,
            "bytes": copied_bytes.len(),
            "sha256": digest::sha256_bytes(&copied_bytes),
            "json_lines": log["json_lines"]
        }));
    }
    Ok(retained)
}

fn verify_retained_log_file(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<Vec<u8>> {
    let bytes = read_plain_file_stably(path)?;
    if bytes.len() as u64 != expected_bytes || digest::sha256_bytes(&bytes) != expected_sha256 {
        return Err(Refusal::new(
            "retained Cargo analysis log failed read-back verification",
        ));
    }
    Ok(bytes)
}

fn read_plain_file_stably(path: &Path) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        Refusal::new(format!(
            "cannot inspect analysis log {}: {error}",
            path.display()
        ))
    })?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(Refusal::new("analysis log is not a plain file"));
    }
    if before.len() > STREAM_LIMIT as u64 {
        return Err(Refusal::new(
            "Cargo analysis log exceeds the retention limit",
        ));
    }
    let file = OpenOptions::new().read(true).open(path).map_err(|error| {
        Refusal::new(format!(
            "cannot open analysis log {}: {error}",
            path.display()
        ))
    })?;
    let opened = file
        .metadata()
        .map_err(|error| Refusal::new(format!("cannot inspect open analysis log: {error}")))?;
    if !same_file_identity(&before, &opened) {
        return Err(Refusal::new("analysis log changed while it was opened"));
    }
    let mut bytes = Vec::new();
    let mut limited = file.take(STREAM_LIMIT as u64 + 1);
    limited.read_to_end(&mut bytes).map_err(|error| {
        Refusal::new(format!(
            "cannot read analysis log {}: {error}",
            path.display()
        ))
    })?;
    if bytes.len() > STREAM_LIMIT {
        return Err(Refusal::new(
            "Cargo analysis log exceeds the retention limit",
        ));
    }
    let after_file = limited
        .get_ref()
        .metadata()
        .map_err(|error| Refusal::new(format!("cannot re-inspect open analysis log: {error}")))?;
    let after_path = fs::symlink_metadata(path).map_err(|error| {
        Refusal::new(format!(
            "cannot re-inspect analysis log {}: {error}",
            path.display()
        ))
    })?;
    if !after_path.is_file()
        || after_path.file_type().is_symlink()
        || !same_file_identity(&opened, &after_file)
        || !same_file_identity(&opened, &after_path)
        || before.len() != bytes.len() as u64
        || opened.len() != bytes.len() as u64
        || after_file.len() != bytes.len() as u64
        || after_path.len() != bytes.len() as u64
    {
        return Err(Refusal::new("analysis log changed while it was read"));
    }
    Ok(bytes)
}

fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn directory_identity(path: &Path) -> Result<(u64, u64, u32, u32)> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || fs::canonicalize(path)? != path {
        return Err(Refusal::new(
            "storage root is no longer a canonical plain directory",
        ));
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_log_requires_plain_directory_and_object_records() {
        let root = std::env::temp_dir().join(format!(
            "ami-rust-analysis-log-counter-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        create_private_directory(&root).unwrap();
        let real = root.join("real");
        create_private_directory(&real).unwrap();
        let file = real.join("fixture-session.jsonl");
        fs::write(&file, b"{\"event\":\"fixture\"}\n").unwrap();
        let identity = directory_identity(&real).unwrap();
        let valid = analysis_logs(&real).unwrap();
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0]["json_lines"], 1);
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(
            analysis_logs(&linked)
                .unwrap_err()
                .to_string()
                .contains("plain directory")
        );
        assert!(directory_identity(&linked).is_err());
        assert_eq!(directory_identity(&real).unwrap(), identity);
        assert_eq!(analysis_logs(&real).unwrap(), valid);
        fs::write(&file, b"\n\n").unwrap();
        assert!(
            analysis_logs(&real)
                .unwrap_err()
                .to_string()
                .contains("empty JSONL")
        );
        fs::write(&file, b"{\"event\":\"fixture\"}\n\n").unwrap();
        assert!(
            analysis_logs(&real)
                .unwrap_err()
                .to_string()
                .contains("empty JSONL")
        );
        fs::write(&file, b"[]\n").unwrap();
        assert!(
            analysis_logs(&real)
                .unwrap_err()
                .to_string()
                .contains("not an object")
        );
        fs::rename(&real, root.join("old-real")).unwrap();
        create_private_directory(&real).unwrap();
        assert_ne!(directory_identity(&real).unwrap(), identity);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn analysis_log_retention_preserves_bytes_and_rejects_tampering() {
        let root = std::env::temp_dir().join(format!(
            "ami-rust-analysis-log-retention-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        create_private_directory(&root).unwrap();
        let source = root.join("source");
        let output = root.join("output");
        create_private_directory(&source).unwrap();
        create_private_directory(&output).unwrap();
        create_private_directory(&output.join("analysis-logs")).unwrap();
        let bytes = b"{\"event\": \"fixture\"}\r\n{\"event\":\"second\"}\n";
        let source_file = source.join("fixture-session.jsonl");
        fs::write(&source_file, bytes).unwrap();
        let logs = analysis_logs(&source).unwrap();
        let retained = retain_analysis_logs(&output, "fixture-case", &source, &logs).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(
            retained[0]["destination"],
            "analysis-logs/fixture-case/fixture-session.jsonl"
        );
        assert_eq!(retained[0]["bytes"], bytes.len());
        assert_eq!(retained[0]["sha256"], digest::sha256_bytes(bytes));
        let destination = output.join("analysis-logs/fixture-case/fixture-session.jsonl");
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert!(retain_analysis_logs(&output, "fixture-case", &source, &logs).is_err());

        fs::write(
            &destination,
            b"{\"event\": \"example\"}\r\n{\"event\":\"second\"}\n",
        )
        .unwrap();
        assert!(
            verify_retained_log_file(
                &destination,
                bytes.len() as u64,
                &digest::sha256_bytes(bytes)
            )
            .unwrap_err()
            .to_string()
            .contains("read-back verification")
        );
        fs::remove_dir_all(root).unwrap();
    }
}

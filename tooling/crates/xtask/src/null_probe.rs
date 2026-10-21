#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "requires the previously extracted pinned Linux rustc component and host adapter"]
fn linux_pinned_rustc_null_stderr_regression() {
    if let Err(error) = run_linux_pinned_rustc_null_stderr_probe() {
        panic!("pinned Linux rustc null-stderr regression failed: {error}");
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
fn run_linux_pinned_rustc_null_stderr_probe() -> std::result::Result<(), String> {
    let artifacts = required_diagnostic_path("AMI_RUST_NULL_PROBE_ARTIFACT_ROOT")?;
    create_private_directory(&artifacts)?;
    let result_path = artifacts.join("probe-result.json");
    match run_linux_pinned_rustc_null_stderr_probe_inner(&artifacts) {
        Ok(mut result) => {
            result["status"] = json!("PASS");
            write_diagnostic_json(&result_path, &result)?;
            Ok(())
        }
        Err(error) => {
            let evidence_path = artifacts.join("probe-observations.json");
            let evidence = diagnostic_json_file(&evidence_path);
            write_diagnostic_json(
                &result_path,
                &json!({
                    "schema":"ami-rust-linux-pinned-rustc-null-stderr-probe-v1",
                    "status":"FAIL",
                    "host":"linux-x86_64",
                    "positive_gate_passed":evidence["positive_gate_passed"].as_bool().unwrap_or(false),
                    "counter_gate_passed":evidence["counter_gate_passed"].as_bool().unwrap_or(false),
                    "ordinary_metadata_equal":evidence["ordinary_metadata_equal"].as_bool().unwrap_or(false),
                    "source_bindings_unchanged":evidence["source_bindings_unchanged"].as_bool().unwrap_or(false),
                    "cleanup_gate_passed":evidence["cleanup_gate_passed"].as_bool().unwrap_or(false),
                    "evidence_path":evidence_path,
                    "error":error,
                    "claim":"No pinned Linux rustc null-stderr regression pass is established."
                }),
            )?;
            Err(error)
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
fn run_linux_pinned_rustc_null_stderr_probe_inner(
    artifacts: &Path,
) -> std::result::Result<Value, String> {
    use std::os::unix::fs::PermissionsExt;

    let work = required_diagnostic_path("AMI_RUST_NULL_PROBE_WORK_ROOT")?;
    if overlaps(artifacts, &work) {
        return Err("null-probe work and evidence roots overlap".to_owned());
    }
    create_private_directory(&work)?;
    let component = fs::canonicalize(required_diagnostic_path("AMI_RUST_HOST_LINK_COMPONENT")?)
        .map_err(|error| format!("resolve pinned rustc component: {error}"))?;
    if !fs::symlink_metadata(&component)
        .map_err(|error| format!("inspect pinned rustc component: {error}"))?
        .file_type()
        .is_dir()
    {
        return Err("configured pinned rustc component is not a directory".to_owned());
    }
    let adapter = fs::canonicalize(required_diagnostic_path("AMI_RUST_HOST_LINK_ADAPTER")?)
        .map_err(|error| format!("resolve host enforcement adapter: {error}"))?;
    let adapter_metadata = fs::symlink_metadata(&adapter)
        .map_err(|error| format!("inspect host enforcement adapter: {error}"))?;
    if !adapter_metadata.file_type().is_file() || adapter_metadata.permissions().mode() & 0o111 == 0
    {
        return Err("configured host enforcement adapter is not a regular executable".to_owned());
    }
    let rustc = fs::canonicalize(component.join("bin/rustc"))
        .map_err(|error| format!("resolve pinned rustc: {error}"))?;
    let rustc_metadata =
        fs::symlink_metadata(&rustc).map_err(|error| format!("inspect pinned rustc: {error}"))?;
    if !rustc_metadata.file_type().is_file() || rustc_metadata.permissions().mode() & 0o111 == 0 {
        return Err("pinned rustc is not a regular executable".to_owned());
    }

    let home = work.join("home");
    let tmp = work.join("tmp");
    let build = work.join("build");
    let derived = build.join("derived");
    for path in [&home, &tmp, &build, &derived] {
        create_private_directory(path)?;
    }
    let source = artifacts.join("null-probe.rs");
    // The rustc installer component contains no rust-std payload. An empty
    // no_core library exercises metadata emission without adding a new input.
    let source_bytes = b"#![feature(no_core)]\n#![no_core]\n";
    write_new(&source, source_bytes).map_err(|error| error.to_string())?;
    let output = build.join("null-probe.rmeta");
    let child_result = home.join("null-probe-child-result.json");
    let source_sha256 = sha256_bytes(source_bytes);
    let rustc_sha256 = sha256_file(&rustc).map_err(|error| error.to_string())?;
    let rustc_args = vec![
        "--crate-name".to_owned(),
        "ami_rust_null_probe".to_owned(),
        "--crate-type".to_owned(),
        "lib".to_owned(),
        "--emit".to_owned(),
        "metadata".to_owned(),
        "--edition".to_owned(),
        "2021".to_owned(),
        source.display().to_string(),
        "-o".to_owned(),
        output.display().to_string(),
    ];
    let child_input = artifacts.join("null-probe-child-input.json");
    let input_value = json!({
        "schema":"ami-rust-linux-null-probe-child-input-v1",
        "compiler":rustc,
        "compiler_sha256":rustc_sha256,
        "source":source,
        "source_sha256":source_sha256,
        "cwd":build,
        "rustc_args":rustc_args,
        "output":output,
        "child_result":child_result,
        "expected_outcomes":{
            "production_build_policy":{"kind":"exit","code":0,"metadata_nonempty":true},
            "counterpolicy":{"kind":"spawn_error","error_kind":"PermissionDenied","raw_os_error":13,"metadata_exists":false}
        }
    });
    write_diagnostic_json(&child_input, &input_value)?;
    let child_input_sha256 = sha256_file(&child_input).map_err(|error| error.to_string())?;

    let test_binary = fs::canonicalize(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| format!("canonicalize test binary: {error}"))?;
    let env_path = fs::canonicalize("/usr/bin/env")
        .map_err(|error| format!("resolve /usr/bin/env: {error}"))?;
    let mut fixture = Fixture::at(artifacts.join("fixture"), true);
    fixture.value["phase"] = json!("build");
    fixture.value["command"] = json!([
        env_path,
        format!("AMI_RUST_NULL_PROBE_INPUT={}", child_input.display()),
        test_binary,
        "--ignored",
        "--exact",
        "consumer_observe::tests::linux_pinned_rustc_null_stderr_child",
        "--test-threads=1",
        "--quiet"
    ]);
    fixture.value["expected_exit"] = json!(0);
    fixture.value["cwd"] = json!(build);
    fixture.value["home"] = json!(home);
    fixture.value["tmp"] = json!(tmp);
    fixture.value["read_trees"] = json!([{"role":"toolchain", "path":component}]);
    fixture.value["write_trees"] = json!([
        {"role":"home", "path":home},
        {"role":"tmp", "path":tmp},
        {"role":"work", "path":build}
    ]);
    fixture.value["read_files"] = json!([source, child_input]);
    fixture.value["executables"] = json!([env_path, test_binary, rustc]);
    fixture.value["libraries"] = json!([]);
    fixture.value["read_directories"] = json!([]);
    fixture.value["deny_exec"] = json!([]);
    fixture.value["deny_library"] = json!([]);
    fixture.value["component_record"] = Value::Null;
    fixture.value["derived"] = json!({"role":"consumer-build-parent", "path":derived});
    fixture.value["bindings"] = json!([
        {"path":test_binary,"sha256":sha256_file(&test_binary).map_err(|error| error.to_string())?},
        {"path":adapter,"sha256":sha256_file(&adapter).map_err(|error| error.to_string())?},
        {"path":rustc,"sha256":rustc_sha256},
        {"path":source,"sha256":source_sha256},
        {"path":child_input,"sha256":child_input_sha256}
    ]);
    let raw_spec = serde_json::to_vec_pretty(&fixture.value)
        .map_err(|error| format!("encode null-probe observation spec: {error}"))?;
    write_new(&artifacts.join("null-probe-spec.json"), &raw_spec)
        .map_err(|error| error.to_string())?;
    let spec = fixture.parse().map_err(|error| error.to_string())?;
    if spec.phase != "build" || spec.write_trees.len() != 3 || !spec.read_files.contains(&source) {
        return Err("parsed null-probe spec differs from its declared build roots".to_owned());
    }
    verify_bindings(&spec.bindings).map_err(|error| error.to_string())?;

    let runtime = consumer_runtime::discover(
        spec.executables.clone(),
        spec.libraries.clone(),
        true,
        false,
        &work,
    )
    .map_err(|error| format!("discover pinned null-probe runtime: {error}"))?;
    let closure = json!({
        "schema":"ami-rust-consumer-reviewed-input-closure-v1",
        "spec_sha256":sha256_bytes(&raw_spec),
        "observer_sha256":sha256_file(&test_binary).map_err(|error| error.to_string())?,
        "adapter_sha256":sha256_file(&adapter).map_err(|error| error.to_string())?,
        "bindings":spec.bindings,
        "components":Value::Null,
        "runtime":runtime.evidence,
        "scope":"Pinned Linux rustc null-stderr process admission only; this does not establish a Rust host build or RC1 acceptance."
    });
    let closure_raw = serde_json::to_vec_pretty(&closure)
        .map_err(|error| format!("encode null-probe input closure: {error}"))?;
    let closure_sha256 = sha256_bytes(&closure_raw);
    write_new(&artifacts.join("null-probe-closure.json"), &closure_raw)
        .map_err(|error| error.to_string())?;
    write_diagnostic_json(&artifacts.join("runtime-discovery.json"), &runtime.evidence)?;
    let reads = spec
        .read_trees
        .iter()
        .map(|tree| tree.path.clone())
        .collect();
    let policy = render_policy(&spec, &runtime, reads, &closure_sha256)
        .map_err(|error| format!("render production build policy: {error}"))?;
    let policy_path = artifacts.join("positive-policy.txt");
    write_new(&policy_path, policy.as_bytes()).map_err(|error| error.to_string())?;
    let counter_policy_path = artifacts.join("counter-policy.txt");
    let policy_delta =
        null_probe_copy_policy_without_write_null(&policy_path, &counter_policy_path)?;
    let args = spec.command.clone();
    let rustc_args = input_value["rustc_args"]
        .as_array()
        .ok_or_else(|| "child input omitted rustc argument array".to_owned())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid rustc argument".to_owned())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let ordinary = run_cold_runtime_native_command(
        "ordinary-unconfined-null-probe-rustc",
        &rustc,
        &rustc_args,
        &build,
        &work,
        &artifacts.join("ordinary-command"),
        Duration::from_secs(90),
    )?;
    let ordinary_raw = read_regular_bounded(&output, 4 * 1024 * 1024)
        .map_err(|error| format!("read ordinary unconfined metadata: {error}"))?;
    write_new(&artifacts.join("ordinary-unconfined.rmeta"), &ordinary_raw)
        .map_err(|error| error.to_string())?;
    let ordinary_output_removed = null_probe_remove_owned_file(&output)?;

    let positive_case = run_raw_adapter_case(
        "pinned-rustc-null-stderr-production-build-policy",
        &artifacts.join("positive-case"),
        &adapter,
        &policy_path,
        &spec,
        &args,
    )?;
    let positive_report = diagnostic_json_file(Path::new(
        positive_case["report_path"].as_str().unwrap_or_default(),
    ));
    let positive_child = diagnostic_json_file(&child_result);
    let positive_child_raw = read_regular_bounded(&child_result, 256 * 1024)
        .map_err(|error| format!("read positive nested rustc result: {error}"))?;
    write_new(
        &artifacts.join("positive-child-result.json"),
        &positive_child_raw,
    )
    .map_err(|error| error.to_string())?;
    let positive_raw = read_regular_bounded(&output, 4 * 1024 * 1024)
        .map_err(|error| format!("read positive nested rustc metadata: {error}"))?;
    write_new(&artifacts.join("positive.rmeta"), &positive_raw)
        .map_err(|error| error.to_string())?;
    let positive_output_removed = null_probe_remove_owned_file(&output)?;
    let positive_child_result_removed = null_probe_remove_owned_file(&child_result)?;
    let positive_cleanup_passed = positive_output_removed && positive_child_result_removed;

    let counter_case = run_raw_adapter_case(
        "pinned-rustc-null-stderr-counterpolicy",
        &artifacts.join("counter-case"),
        &adapter,
        &counter_policy_path,
        &spec,
        &args,
    )?;
    let counter_report = diagnostic_json_file(Path::new(
        counter_case["report_path"].as_str().unwrap_or_default(),
    ));
    let counter_child = diagnostic_json_file(&child_result);
    let counter_child_raw = read_regular_bounded(&child_result, 256 * 1024)
        .map_err(|error| format!("read counter nested rustc result: {error}"))?;
    write_new(
        &artifacts.join("counter-child-result.json"),
        &counter_child_raw,
    )
    .map_err(|error| error.to_string())?;
    let counter_output = null_probe_file_summary(&output);
    let counter_child_result_removed = null_probe_remove_owned_file(&child_result)?;
    let no_counter_metadata = !output.exists();

    let unchanged = verify_bindings(&spec.bindings).is_ok()
        && sha256_file(&test_binary).ok() == spec.bindings.get(&test_binary).cloned()
        && sha256_file(&adapter).ok() == spec.bindings.get(&adapter).cloned();
    let ordinary_metadata_equal = ordinary_raw == positive_raw;
    let ordinary_gate_passed = ordinary["exit_code"].as_i64() == Some(0)
        && ordinary["signal"].is_null()
        && ordinary["capture_error"].is_null();
    let positive_gate_passed = ordinary_gate_passed
        && positive_case["outer_exit_code"].as_i64() == Some(0)
        && positive_case["outer_signal"].is_null()
        && positive_case["capture_error"].is_null()
        && successful_linux_adapter_report(&positive_report, 0)
        && positive_report["write_null"]["post_run_identity_matches"].as_bool() == Some(true)
        && positive_child["invocation"]["kind"] == "exit"
        && positive_child["invocation"]["code"].as_i64() == Some(0)
        && positive_child["output"]["regular"].as_bool() == Some(true)
        && positive_child["output"]["bytes"].as_u64().unwrap_or(0) > 0
        && positive_child["compiler_sha256_after"] == rustc_sha256
        && positive_child["source_sha256_after"] == source_sha256
        && ordinary_metadata_equal;
    let counter_gate_passed = counter_case["outer_exit_code"].as_i64() == Some(0)
        && counter_case["outer_signal"].is_null()
        && counter_case["capture_error"].is_null()
        && successful_linux_adapter_report(&counter_report, 0)
        && counter_report["write_null"].is_null()
        && counter_child["invocation"]["kind"] == "spawn_error"
        && counter_child["invocation"]["error_kind"] == "PermissionDenied"
        && counter_child["invocation"]["raw_os_error"].as_i64() == Some(13)
        && counter_child["output"]["exists"].as_bool() == Some(false)
        && no_counter_metadata
        && counter_child["compiler_sha256_after"] == rustc_sha256
        && counter_child["source_sha256_after"] == source_sha256;
    let cleanup_gate_passed = ordinary_output_removed
        && positive_cleanup_passed
        && counter_child_result_removed
        && no_counter_metadata;
    let observations = json!({
        "schema":"ami-rust-linux-pinned-rustc-null-stderr-observations-v1",
        "status":"OBSERVATIONS_RECORDED",
        "positive_gate_passed":positive_gate_passed,
        "counter_gate_passed":counter_gate_passed,
        "ordinary_metadata_equal":ordinary_metadata_equal,
        "source_bindings_unchanged":unchanged,
        "cleanup_gate_passed":cleanup_gate_passed,
        "bindings":spec.bindings,
        "component":component,
        "adapter":adapter,
        "policy_delta":policy_delta,
        "runtime_discovery":runtime.evidence,
        "ordinary_command":ordinary,
        "ordinary_metadata":{"path":artifacts.join("ordinary-unconfined.rmeta"),"bytes":ordinary_raw.len(),"sha256":sha256_bytes(&ordinary_raw)},
        "positive_adapter_case":positive_case,
        "positive_adapter_report":positive_report,
        "positive_child_result":positive_child,
        "positive_metadata":{"path":artifacts.join("positive.rmeta"),"bytes":positive_raw.len(),"sha256":sha256_bytes(&positive_raw)},
        "counter_adapter_case":counter_case,
        "counter_adapter_report":counter_report,
        "counter_child_result":counter_child,
        "counter_output":counter_output,
        "same_rustc_arguments_for_all_invocations":true,
        "claim":"Cause-specific null-stderr admission probe for pinned Linux rustc; no full host build or RC1 acceptance claim."
    });
    write_diagnostic_json(&artifacts.join("probe-observations.json"), &observations)?;
    if !positive_gate_passed
        || !counter_gate_passed
        || !ordinary_metadata_equal
        || !unchanged
        || !cleanup_gate_passed
    {
        return Err(format!(
            "null-probe gates failed; inspect {}",
            artifacts.join("probe-observations.json").display()
        ));
    }
    Ok(json!({
        "schema":"ami-rust-linux-pinned-rustc-null-stderr-probe-v1",
        "host":"linux-x86_64",
        "positive_gate_passed":positive_gate_passed,
        "counter_gate_passed":counter_gate_passed,
        "ordinary_metadata_equal":ordinary_metadata_equal,
        "source_bindings_unchanged":unchanged,
        "cleanup_gate_passed":cleanup_gate_passed,
        "evidence_path":artifacts.join("probe-observations.json"),
        "claim":"Pinned Linux rustc accepted metadata output only with the exact build write-null rule; no full host build or RC1 acceptance claim."
    }))
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
fn null_probe_copy_policy_without_write_null(
    policy: &Path,
    counter: &Path,
) -> std::result::Result<Value, String> {
    let original = read_regular_bounded(policy, 1024 * 1024).map_err(|error| error.to_string())?;
    let text = std::str::from_utf8(&original).map_err(|error| error.to_string())?;
    let matching = text
        .split_inclusive('\n')
        .filter(|line| line.strip_suffix('\n').unwrap_or(line) == "write-null /dev/null")
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(format!(
            "production policy has {} exact write-null rules",
            matching.len()
        ));
    }
    let removed = matching[0];
    let counter_text = text
        .split_inclusive('\n')
        .filter(|line| *line != removed)
        .collect::<String>();
    if counter_text.len() + removed.len() != original.len() {
        return Err("counterpolicy changed bytes beyond the exact write-null rule".to_owned());
    }
    write_new(counter, counter_text.as_bytes()).map_err(|error| error.to_string())?;
    Ok(json!({
        "positive_policy":policy,
        "positive_policy_sha256":sha256_file(policy).map_err(|error| error.to_string())?,
        "counter_policy":counter,
        "counter_policy_sha256":sha256_file(counter).map_err(|error| error.to_string())?,
        "omitted_rule":"write-null /dev/null",
        "omitted_rule_count":1,
        "all_other_policy_bytes_identical":true
    }))
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
fn null_probe_file_summary(path: &Path) -> Value {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            match read_regular_bounded(path, 4 * 1024 * 1024) {
                Ok(raw) => {
                    json!({"path":path,"exists":true,"regular":true,"bytes":raw.len(),"sha256":sha256_bytes(&raw)})
                }
                Err(error) => {
                    json!({"path":path,"exists":true,"regular":true,"inspection_error":error.to_string()})
                }
            }
        }
        Ok(metadata) => {
            json!({"path":path,"exists":true,"regular":false,"kind":format!("{:?}", metadata.file_type())})
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            json!({"path":path,"exists":false,"regular":false})
        }
        Err(error) => json!({"path":path,"exists":null,"inspection_error":error.to_string()}),
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
fn null_probe_remove_owned_file(path: &Path) -> std::result::Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path)
                .map_err(|error| format!("remove owned probe file {}: {error}", path.display()))?;
            Ok(true)
        }
        Ok(_) => Err(format!(
            "refusing to remove non-regular probe path {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "inspect owned probe file {}: {error}",
            path.display()
        )),
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "child fixture for the pinned Linux rustc null-stderr regression"]
fn linux_pinned_rustc_null_stderr_child() {
    use std::process::{Command, Stdio};

    let input_path = PathBuf::from(
        std::env::var_os("AMI_RUST_NULL_PROBE_INPUT")
            .expect("adapter command supplies the bound null-probe child input"),
    );
    let raw = read_regular_bounded(&input_path, 64 * 1024).expect("read child input");
    let input: Value = serde_json::from_slice(&raw).expect("parse child input");
    assert_eq!(input["schema"], "ami-rust-linux-null-probe-child-input-v1");
    let compiler = PathBuf::from(input["compiler"].as_str().expect("compiler path"));
    let source = PathBuf::from(input["source"].as_str().expect("source path"));
    let cwd = PathBuf::from(input["cwd"].as_str().expect("working directory"));
    let output = PathBuf::from(input["output"].as_str().expect("metadata output"));
    let result_path = PathBuf::from(input["child_result"].as_str().expect("child result path"));
    let arguments = input["rustc_args"]
        .as_array()
        .expect("rustc arguments")
        .iter()
        .map(|value| value.as_str().expect("string rustc argument"))
        .collect::<Vec<_>>();
    assert!(
        result_path.starts_with(
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .expect("private HOME")
        )
    );
    assert!(output.starts_with(&cwd));
    let compiler_before = sha256_file(&compiler).expect("hash pinned compiler before invocation");
    let source_before = sha256_file(&source).expect("hash source before invocation");
    let invocation = Command::new(&compiler)
        .args(&arguments)
        .current_dir(&cwd)
        .stderr(Stdio::null())
        .status();
    let actual = match invocation {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt;
            json!({"kind":"exit","code":status.code(),"signal":status.signal()})
        }
        Err(error) => json!({
            "kind":"spawn_error",
            "error_kind":format!("{:?}", error.kind()),
            "raw_os_error":error.raw_os_error(),
            "message":error.to_string()
        }),
    };
    let output_summary = null_probe_file_summary(&output);
    let result = json!({
        "schema":"ami-rust-linux-null-probe-child-result-v1",
        "compiler":compiler,
        "source":source,
        "cwd":cwd,
        "rustc_args":arguments,
        "stderr_stdio":"Stdio::null()",
        "invocation":actual,
        "output":output_summary,
        "compiler_sha256_before":compiler_before,
        "compiler_sha256_after":sha256_file(&compiler).ok(),
        "source_sha256_before":source_before,
        "source_sha256_after":sha256_file(&source).ok(),
        "expected_outcomes":input["expected_outcomes"],
        "claim":"Raw nested Rust Command::status result recorded before the parent evaluates the adapter case."
    });
    write_diagnostic_json(&result_path, &result).expect("preserve actual nested rustc outcome");
}

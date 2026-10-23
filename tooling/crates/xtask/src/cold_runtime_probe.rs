const COLD_RUNTIME_ARCHIVE_BYTES: u64 = 85_397_620;
const COLD_RUNTIME_ARCHIVE_SHA256: &str =
    "a0f5685f293fb6fc2c3b0ba1e67f24a38c688259ad1b4f04596ec4c86ec5a435";
const COLD_RUNTIME_ARCHIVE_URL: &str =
    "https://static.rust-lang.org/dist/2026-09-18/rustc-nightly-x86_64-unknown-linux-gnu.tar.xz";
const COLD_RUNTIME_INPUTS_SHA256: &str =
    "70ea2900ba0e61213c6636fe1ee1c9bb0666e975847aee5ee5dc52797b437162";

#[test]
fn cold_runtime_input_digest_matches_current_sdk_manifest() {
    let inputs = include_bytes!("../../../../release/ci-sdk-inputs.json");
    assert_eq!(inputs.len(), 6451);
    assert_eq!(sha256_bytes(inputs), COLD_RUNTIME_INPUTS_SHA256);
}
const COLD_RUNTIME_RUST_COMMIT: &str = "330d317121e16b5db8e5adc63595910528ff2ee7";
const COLD_RUNTIME_LLVM_VERSION: &str = "23.1.1";
const COLD_RUNTIME_TARGET: &str = "x86_64-unknown-linux-gnu";

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cold_runtime_path_text(path: &Path) -> std::result::Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cold_runtime_child_environment(work: &Path) -> BTreeMap<OsString, OsString> {
    BTreeMap::from([
        (
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
        ),
        (OsString::from("HOME"), work.join("home").into_os_string()),
        (OsString::from("TMPDIR"), work.join("tmp").into_os_string()),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("TZ"), OsString::from("UTC")),
    ])
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_cold_runtime_native_command(
    label: &str,
    program: &Path,
    arguments: &[String],
    cwd: &Path,
    work: &Path,
    output: &Path,
    timeout: Duration,
) -> std::result::Result<Value, String> {
    create_private_directory(output)?;
    let canonical_program = fs::canonicalize(program)
        .map_err(|error| format!("resolve {label} executable: {error}"))?;
    let program_sha256 = sha256_file(&canonical_program)
        .map_err(|error| format!("hash {label} executable: {error}"))?;
    let command = CommandSpec::new(
        canonical_program.as_os_str(),
        arguments.iter().map(OsString::from),
        cwd,
        cold_runtime_child_environment(work),
    );
    let captured = capture(
        &command,
        CaptureLimits {
            timeout,
            stdout_bytes: 1024 * 1024,
            stderr_bytes: 1024 * 1024,
            termination_grace: Duration::from_secs(2),
        },
        || false,
    );
    let (exit_code, signal, stdout, stderr, elapsed_millis, capture_error) = match captured {
        Ok(captured) => (
            captured.exit_code(),
            captured.signal(),
            captured.stdout,
            captured.stderr,
            captured.elapsed.as_millis(),
            Value::Null,
        ),
        Err(error) => {
            let message = error.to_string();
            (
                error.status.as_ref().and_then(|status| status.code()),
                error
                    .status
                    .as_ref()
                    .and_then(std::os::unix::process::ExitStatusExt::signal),
                error.stdout,
                error.stderr,
                0_u128,
                json!(message),
            )
        }
    };
    let stdout_path = output.join("stdout.raw");
    let stderr_path = output.join("stderr.raw");
    write_new(&stdout_path, &stdout).map_err(|error| error.to_string())?;
    write_new(&stderr_path, &stderr).map_err(|error| error.to_string())?;
    let argv = std::iter::once(cold_runtime_path_text(&canonical_program)?)
        .chain(arguments.iter().cloned())
        .collect::<Vec<_>>();
    let summary = json!({
        "label":label,
        "program":canonical_program,
        "program_sha256":program_sha256,
        "argv":argv,
        "exit_code":exit_code,
        "signal":signal,
        "elapsed_millis":elapsed_millis,
        "capture_error":capture_error,
        "stdout_path":stdout_path,
        "stdout_bytes":stdout.len(),
        "stdout_sha256":sha256_bytes(&stdout),
        "stderr_path":stderr_path,
        "stderr_bytes":stderr.len(),
        "stderr_sha256":sha256_bytes(&stderr),
        "limits":{"timeout_millis":timeout.as_millis(),"stdout_bytes":1048576,"stderr_bytes":1048576},
    });
    write_diagnostic_json(&output.join("command.json"), &summary)?;
    let command_failed = !capture_error.is_null() || exit_code != Some(0) || signal.is_some();
    if command_failed {
        return Err(format!(
            "{label} did not complete successfully; inspect {}",
            output.display()
        ));
    }
    Ok(summary)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cold_runtime_verify_pinned_inputs(
    source_root: &Path,
    artifact_root: &Path,
) -> std::result::Result<(PathBuf, Value, String), String> {
    let inputs = source_root.join("release/ci-sdk-inputs.json");
    let raw = read_regular_bounded(
        &inputs,
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )
    .map_err(|error| format!("read pinned SDK inputs: {error}"))?;
    let inputs_sha256 = sha256_bytes(&raw);
    if inputs_sha256 != COLD_RUNTIME_INPUTS_SHA256 {
        return Err(format!(
            "tracked SDK inputs digest changed: expected {COLD_RUNTIME_INPUTS_SHA256}, got {inputs_sha256}"
        ));
    }
    let value = parse_json_value(&raw, JsonProfile::PackageMetadataStateSelection)
        .map_err(|error| format!("parse pinned SDK inputs: {error}"))?;
    let archives = value["hosts"]["linux-x86_64"]["rust"]["archives"]
        .as_array()
        .ok_or_else(|| "pinned Linux Rust archive list is missing".to_owned())?;
    let selected = archives
        .iter()
        .filter(|row| row["component"] == "rustc")
        .collect::<Vec<_>>();
    let row = selected
        .first()
        .ok_or_else(|| "pinned Linux rustc archive is missing".to_owned())?;
    if selected.len() != 1
        || value["schema"] != "ami-rust-ci-sdk-inputs-v1"
        || value["rust_channel"] != "nightly-2026-09-18"
        || value["rust_commit"] != COLD_RUNTIME_RUST_COMMIT
        || value["rust_llvm"] != COLD_RUNTIME_LLVM_VERSION
        || row["url"] != COLD_RUNTIME_ARCHIVE_URL
        || row["sha256"] != COLD_RUNTIME_ARCHIVE_SHA256
        || row["bytes"].as_u64() != Some(COLD_RUNTIME_ARCHIVE_BYTES)
    {
        return Err(
            "pinned Linux rustc archive identity differs from the frozen baseline".to_owned(),
        );
    }
    let pin = json!({
        "schema":"ami-rust-linux-cold-runtime-rustc-pin-v1",
        "inputs_path":inputs,
        "inputs_sha256":inputs_sha256,
        "rust_channel":value["rust_channel"],
        "rust_commit":value["rust_commit"],
        "rust_llvm":value["rust_llvm"],
        "target":COLD_RUNTIME_TARGET,
        "archive_url":COLD_RUNTIME_ARCHIVE_URL,
        "archive_bytes":COLD_RUNTIME_ARCHIVE_BYTES,
        "archive_sha256":COLD_RUNTIME_ARCHIVE_SHA256,
        "status":"PINNED_INPUTS_MATCH",
    });
    write_diagnostic_json(&artifact_root.join("rustc-pin.json"), &pin)?;
    Ok((inputs, pin, inputs_sha256))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cold_runtime_copy_policy_without_libdl(
    policy_path: &Path,
    counter_path: &Path,
) -> std::result::Result<Value, String> {
    let original = read_regular_bounded(policy_path, 1024 * 1024)
        .map_err(|error| format!("read positive adapter policy: {error}"))?;
    let text = std::str::from_utf8(&original)
        .map_err(|error| format!("positive adapter policy is not UTF-8: {error}"))?;
    let matching = text
        .split_inclusive('\n')
        .filter(|line| {
            let body = line.strip_suffix('\n').unwrap_or(line);
            let Some(rest) = body.strip_prefix("read-library ") else {
                return false;
            };
            let Some((path, _digest)) = rest.split_once(' ') else {
                return false;
            };
            Path::new(path).file_name().and_then(|name| name.to_str()) == Some("libdl.so.2")
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(format!(
            "expected exactly one file-specific libdl.so.2 policy rule, found {}",
            matching.len()
        ));
    }
    let omitted = matching[0].strip_suffix('\n').unwrap_or(matching[0]);
    let counter = text
        .split_inclusive('\n')
        .filter(|line| line.strip_suffix('\n').unwrap_or(line) != omitted)
        .collect::<String>();
    if counter.len() + matching[0].len() != original.len() {
        return Err("libdl counterpolicy changed bytes beyond the single omitted rule".to_owned());
    }
    write_new(counter_path, counter.as_bytes()).map_err(|error| error.to_string())?;
    let summary = json!({
        "positive_policy":policy_path,
        "positive_policy_sha256":sha256_file(policy_path).map_err(|error| error.to_string())?,
        "counter_policy":counter_path,
        "counter_policy_sha256":sha256_file(counter_path).map_err(|error| error.to_string())?,
        "omitted_rule":omitted,
        "omitted_rule_count":1,
        "bytes_removed":matching[0].len(),
        "all_other_policy_bytes_identical":true,
    });
    write_diagnostic_json(&counter_path.with_extension("json"), &summary)?;
    Ok(summary)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cold_runtime_case_stdout(case: &Value) -> std::result::Result<Vec<u8>, String> {
    let path = case["stdout_path"]
        .as_str()
        .ok_or_else(|| "adapter case omitted raw stdout path".to_owned())?;
    read_regular_bounded(Path::new(path), 1024 * 1024)
        .map_err(|error| format!("read adapter child stdout: {error}"))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cold_runtime_derived_identity(path: &Path) -> std::result::Result<Value, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect derived parent: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err("derived parent lost its real-directory 0700 identity".to_owned());
    }
    Ok(
        json!({"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.permissions().mode() & 0o7777}),
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cold_runtime_remove_counter_stage(
    derived: &Path,
    staged_component: &Path,
) -> std::result::Result<Value, String> {
    if staged_component.parent() != Some(derived)
        || fs::canonicalize(derived).map_err(|error| error.to_string())? != derived
    {
        return Err(
            "counter stage is not a direct child of the retained derived parent".to_owned(),
        );
    }
    let entries = fs::read_dir(derived)
        .map_err(|error| format!("list derived parent before cleanup: {error}"))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if entries.len() == 1 && entries[0] == staged_component {
        let metadata = fs::symlink_metadata(staged_component)
            .map_err(|error| format!("inspect copied counter component: {error}"))?;
        if !metadata.file_type().is_dir()
            || fs::canonicalize(staged_component).map_err(|error| error.to_string())?
                != staged_component
        {
            return Err("counter stage is not the expected real copied directory".to_owned());
        }
        fs::remove_dir_all(staged_component)
            .map_err(|error| format!("remove only the owned counter stage: {error}"))?;
    } else if !entries.is_empty() {
        return Err(format!(
            "derived parent has unexpected entries after counter; refusing cleanup: {}",
            entries
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let remaining = fs::read_dir(derived)
        .map_err(|error| format!("recheck derived parent after cleanup: {error}"))?
        .next()
        .is_some();
    if remaining {
        return Err("derived parent is not empty after counter cleanup".to_owned());
    }
    Ok(
        json!({"removed_only_staged_component":entries.len() == 1,"empty_after_cleanup":true,"remaining_entries":0}),
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_linux_cold_rustc_runtime_probe() -> std::result::Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let artifact_root = required_diagnostic_path("AMI_RUST_COLD_RUNTIME_ARTIFACT_ROOT")?;
    create_private_directory(&artifact_root)?;
    let work_root = required_diagnostic_path("AMI_RUST_COLD_RUNTIME_WORK_ROOT")?;
    create_private_directory(&work_root)?;
    if overlaps(&artifact_root, &work_root) {
        return Err("cold runtime work and evidence roots overlap".to_owned());
    }
    let source_root = fs::canonicalize(required_diagnostic_path(
        "AMI_RUST_COLD_RUNTIME_SOURCE_ROOT",
    )?)
    .map_err(|error| format!("resolve source root: {error}"))?;
    let adapter = fs::canonicalize(required_diagnostic_path("AMI_RUST_COLD_RUNTIME_ADAPTER")?)
        .map_err(|error| format!("resolve enforcement adapter: {error}"))?;
    if !fs::metadata(&adapter)
        .map_err(|error| format!("inspect enforcement adapter: {error}"))?
        .is_file()
    {
        return Err("configured enforcement adapter is not a regular file".to_owned());
    }
    let (inputs_path, pin, inputs_sha256) =
        cold_runtime_verify_pinned_inputs(&source_root, &artifact_root)?;

    let inputs_root = work_root.join("inputs");
    let extraction_root = work_root.join("extracted");
    let home = work_root.join("home");
    let tmp = work_root.join("tmp");
    let state_writes = work_root.join("state-writes");
    let derived = state_writes.join("derived");
    for path in [
        &inputs_root,
        &extraction_root,
        &home,
        &tmp,
        &state_writes,
        &derived,
    ] {
        create_private_directory(path)?;
    }
    if fs::read_dir(&derived)
        .map_err(|error| format!("inspect initially empty derived parent: {error}"))?
        .next()
        .is_some()
    {
        return Err("derived parent is not initially empty".to_owned());
    }
    let derived_before = cold_runtime_derived_identity(&derived)?;

    let archive = inputs_root.join("rustc-nightly-x86_64-unknown-linux-gnu.tar.xz");
    let curl = Path::new("/usr/bin/curl");
    let curl_args = vec![
        "--fail".to_owned(),
        "--location".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--connect-timeout".to_owned(),
        "20".to_owned(),
        "--max-time".to_owned(),
        "300".to_owned(),
        "--max-filesize".to_owned(),
        COLD_RUNTIME_ARCHIVE_BYTES.to_string(),
        "--output".to_owned(),
        cold_runtime_path_text(&archive)?,
        COLD_RUNTIME_ARCHIVE_URL.to_owned(),
    ];
    let curl_result = run_cold_runtime_native_command(
        "download-pinned-rustc-archive",
        curl,
        &curl_args,
        &work_root,
        &work_root,
        &artifact_root.join("download"),
        Duration::from_secs(300),
    )?;
    let archive_metadata = fs::symlink_metadata(&archive)
        .map_err(|error| format!("inspect downloaded rustc archive: {error}"))?;
    let archive_bytes = archive_metadata.len();
    let archive_sha256 =
        sha256_file(&archive).map_err(|error| format!("hash downloaded rustc archive: {error}"))?;
    let archive_valid = archive_metadata.file_type().is_file()
        && archive_bytes == COLD_RUNTIME_ARCHIVE_BYTES
        && archive_sha256 == COLD_RUNTIME_ARCHIVE_SHA256;
    let archive_verification = json!({
        "path":archive,
        "regular_file":archive_metadata.file_type().is_file(),
        "bytes":archive_bytes,
        "sha256":archive_sha256,
        "expected_bytes":COLD_RUNTIME_ARCHIVE_BYTES,
        "expected_sha256":COLD_RUNTIME_ARCHIVE_SHA256,
        "pin_verified":archive_valid,
        "download":curl_result,
    });
    write_diagnostic_json(
        &artifact_root.join("archive-verification.json"),
        &archive_verification,
    )?;
    if !archive_valid {
        return Err(
            "downloaded rustc archive did not match its exact byte and SHA-256 pin".to_owned(),
        );
    }

    let tar = Path::new("/usr/bin/tar");
    let tar_args = vec![
        "--extract".to_owned(),
        "--xz".to_owned(),
        "--file".to_owned(),
        cold_runtime_path_text(&archive)?,
        "--directory".to_owned(),
        cold_runtime_path_text(&extraction_root)?,
        "--no-same-owner".to_owned(),
        "--no-same-permissions".to_owned(),
    ];
    let tar_result = run_cold_runtime_native_command(
        "extract-pinned-rustc-archive",
        tar,
        &tar_args,
        &work_root,
        &work_root,
        &artifact_root.join("extract"),
        Duration::from_secs(300),
    )?;
    let package_root = extraction_root.join("rustc-nightly-x86_64-unknown-linux-gnu");
    let source_component = package_root.join("rustc");
    let reference_rustc = source_component.join("bin/rustc");
    let canonical_extraction_root = fs::canonicalize(&extraction_root)
        .map_err(|error| format!("resolve extracted root: {error}"))?;
    if fs::canonicalize(&source_component)
        .map_err(|error| format!("resolve extracted rustc component: {error}"))?
        != source_component
        || !source_component.starts_with(&canonical_extraction_root)
        || fs::canonicalize(&reference_rustc)
            .map_err(|error| format!("resolve extracted rustc executable: {error}"))?
            != reference_rustc
    {
        return Err(
            "pinned archive did not produce the expected canonical rustc component layout"
                .to_owned(),
        );
    }
    let reference_metadata = fs::symlink_metadata(&reference_rustc)
        .map_err(|error| format!("inspect extracted rustc: {error}"))?;
    if !reference_metadata.file_type().is_file()
        || reference_metadata.permissions().mode() & 0o111 == 0
    {
        return Err("extracted pinned rustc is not a regular executable".to_owned());
    }
    let reference_rustc_sha256 =
        sha256_file(&reference_rustc).map_err(|error| format!("hash extracted rustc: {error}"))?;
    write_diagnostic_json(
        &artifact_root.join("reference-rustc.json"),
        &json!({
            "archive_sha256":archive_sha256,
            "extraction":tar_result,
            "package_root":package_root,
            "component_root":source_component,
            "rustc":reference_rustc,
            "rustc_sha256":reference_rustc_sha256,
            "rustc_mode":reference_metadata.permissions().mode() & 0o7777,
            "source":"verified pinned rustc installer archive",
        }),
    )?;

    let mut fixture = Fixture::at(artifact_root.join("fixture"), true);
    for path in [&home, &tmp, &state_writes, &derived] {
        if !path.is_dir() || fs::canonicalize(path).map_err(|error| error.to_string())? != *path {
            return Err(format!(
                "fixture path is not a canonical directory: {}",
                path.display()
            ));
        }
    }
    let test_binary = fs::canonicalize(
        std::env::current_exe().map_err(|error| format!("resolve test binary: {error}"))?,
    )
    .map_err(|error| format!("canonicalize test binary: {error}"))?;
    let env_path = fs::canonicalize("/usr/bin/env")
        .map_err(|error| format!("resolve /usr/bin/env: {error}"))?;
    let cp_path =
        fs::canonicalize("/usr/bin/cp").map_err(|error| format!("resolve /usr/bin/cp: {error}"))?;
    let rustc_stage = derived.join("rustc");
    let staged_rustc = rustc_stage.join("bin/rustc");
    let marker_path = home.join("cold-runtime-child-input.json");
    let marker = json!({
        "schema":"ami-rust-linux-cold-runtime-child-input-v1",
        "source_component":source_component,
        "source_rustc":reference_rustc,
        "source_rustc_sha256":reference_rustc_sha256,
        "derived_parent":derived,
        "staged_component":rustc_stage,
        "staged_rustc":staged_rustc,
        "rust_commit":COLD_RUNTIME_RUST_COMMIT,
        "llvm_version":COLD_RUNTIME_LLVM_VERSION,
        "target":COLD_RUNTIME_TARGET,
    });
    write_diagnostic_json(&marker_path, &marker)?;
    let marker_sha256 =
        sha256_file(&marker_path).map_err(|error| format!("hash child input marker: {error}"))?;
    let marker_binding = json!({"path":marker_path,"sha256":marker_sha256});
    configure_cold_runtime_fixture_roots(&mut fixture, &work_root, &source_component);
    fixture.value["command"] = json!([
        env_path,
        "AMI_RUST_COLD_RUNTIME_CHILD=positive",
        test_binary,
        "--ignored",
        "--exact",
        "consumer_observe::tests::linux_cold_rustc_runtime_child",
        "--test-threads=1",
        "--quiet",
    ]);
    fixture.value["expected_exit"] = json!(0);
    let selected_rust_tools = rust_component_executables(COLD_RUNTIME_TARGET)
        .into_iter()
        .map(|relative| source_component.join(relative))
        .collect::<Vec<_>>();
    let mut declared_executables = selected_rust_tools.clone();
    declared_executables.extend([cp_path.clone(), env_path.clone(), test_binary.clone()]);
    fixture.value["executables"] = json!(declared_executables);
    fixture.value["bindings"]
        .as_array_mut()
        .ok_or_else(|| "fixture omitted bindings array".to_owned())?
        .push(marker_binding);
    fixture.value["bindings"]
        .as_array_mut()
        .ok_or_else(|| "fixture omitted bindings array".to_owned())?
        .push(json!({"path":inputs_path,"sha256":inputs_sha256}));
    fixture.value["bindings"]
        .as_array_mut()
        .ok_or_else(|| "fixture omitted bindings array".to_owned())?
        .push(json!({"path":archive,"sha256":archive_sha256}));
    let raw_spec = serde_json::to_vec_pretty(&fixture.value)
        .map_err(|error| format!("encode observation spec: {error}"))?;
    write_new(&artifact_root.join("spec.json"), &raw_spec).map_err(|error| error.to_string())?;
    let spec = fixture.parse().map_err(|error| error.to_string())?;

    let mut executables = spec.executables.clone();
    executables.insert(fs::canonicalize(&spec.command[0]).map_err(|error| error.to_string())?);
    let mut invalid_executables = executables.clone();
    let unused_objcopy = source_component.join(format!(
        "lib/rustlib/{COLD_RUNTIME_TARGET}/bin/rust-objcopy"
    ));
    invalid_executables.insert(unused_objcopy.clone());
    let error = match consumer_runtime::discover(
        invalid_executables,
        spec.libraries.clone(),
        false,
        true,
        &work_root,
    ) {
        Err(error) => error.to_string(),
        Ok(_) => {
            return Err(
                "unused pinned rust-objcopy unexpectedly resolved its LLVM runtime".to_owned(),
            );
        }
    };
    if !error.contains(&cold_runtime_path_text(&unused_objcopy)?)
        || !error.contains("libLLVM.so.23.1-rust-1.100.0-nightly => not found")
    {
        return Err(format!(
            "unused Rust tool counter failed for the wrong reason: {error}"
        ));
    }
    write_diagnostic_json(
        &artifact_root.join("unused-rust-objcopy-counter.json"),
        &json!({
            "schema":"ami-rust-unused-rust-tool-runtime-counter-v1",
            "path":unused_objcopy,
            "sha256":sha256_file(&unused_objcopy).map_err(|error| error.to_string())?,
            "error":error,
            "status":"REFUSED_UNRESOLVED_LLVM_FOR_UNUSED_PINNED_TOOL",
            "claim":"Strict dependency refusal remains enabled; the frozen recipe uses toolchain llvm-objcopy instead.",
        }),
    )?;
    let runtime =
        consumer_runtime::discover(executables, spec.libraries.clone(), false, true, &work_root)
            .map_err(|error| {
                format!("discover selected Rust component runtime closure: {error}")
            })?;
    write_diagnostic_json(
        &artifact_root.join("runtime-discovery.json"),
        &runtime.evidence,
    )?;
    let libdl_paths = runtime
        .libraries
        .iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("libdl.so.2"))
        .collect::<Vec<_>>();
    if libdl_paths.len() != 1 {
        return Err(format!(
            "runtime discovery must identify one exact libdl.so.2 lookup path; found {}",
            libdl_paths.len()
        ));
    }
    let runtime_executables = runtime
        .executables
        .iter()
        .map(|path| cold_runtime_path_text(path))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    for expected in selected_rust_tools
        .iter()
        .chain([&cp_path, &env_path, &test_binary])
    {
        let canonical = fs::canonicalize(expected).map_err(|error| error.to_string())?;
        if !runtime_executables.contains(&cold_runtime_path_text(&canonical)?) {
            return Err(format!(
                "runtime discovery omitted required declared executable {}",
                canonical.display()
            ));
        }
    }

    let observer_sha256 =
        sha256_file(&test_binary).map_err(|error| format!("hash observer test binary: {error}"))?;
    let adapter_sha256 =
        sha256_file(&adapter).map_err(|error| format!("hash enforcement adapter: {error}"))?;
    verify_bindings(&spec.bindings).map_err(|error| error.to_string())?;
    let closure = json!({
        "schema":"ami-rust-consumer-reviewed-input-closure-v1",
        "spec_sha256":sha256_bytes(&raw_spec),
        "observer_sha256":observer_sha256,
        "adapter_sha256":adapter_sha256,
        "bindings":spec.bindings,
        "components":Value::Null,
        "runtime":runtime.evidence,
        "scope":"Pinned target-rustc staging and loader inputs for this cause-specific observation only; not a complete or independent runtime inventory.",
    });
    let closure_raw = serde_json::to_vec_pretty(&closure)
        .map_err(|error| format!("encode input closure: {error}"))?;
    let closure_sha256 = sha256_bytes(&closure_raw);
    write_new(&artifact_root.join("closure.json"), &closure_raw)
        .map_err(|error| error.to_string())?;
    let mut reads = spec
        .read_trees
        .iter()
        .map(|tree| tree.path.clone())
        .collect::<BTreeSet<_>>();
    reads.extend(runtime.read_trees.iter().cloned());
    let policy = render_policy(&spec, &runtime, reads, &closure_sha256)
        .map_err(|error| format!("render cold-stage observation policy: {error}"))?;
    let policy_path = artifact_root.join("positive-policy.txt");
    write_new(&policy_path, policy.as_bytes()).map_err(|error| error.to_string())?;
    let counter_policy_path = artifact_root.join("counter-policy-libdl-omitted.txt");
    let counter_policy =
        cold_runtime_copy_policy_without_libdl(&policy_path, &counter_policy_path)?;
    if !counter_policy["all_other_policy_bytes_identical"]
        .as_bool()
        .unwrap_or(false)
    {
        return Err("counterpolicy does not preserve every other policy byte".to_owned());
    }
    write_diagnostic_json(
        &artifact_root.join("policy-summary.json"),
        &json!({
            "phase":spec.phase,
            "positive_policy":policy_path,
            "positive_policy_sha256":sha256_file(&policy_path).map_err(|error| error.to_string())?,
            "counter_policy":counter_policy,
            "network_policy":"outbound permission is inherited from the existing cold-prepare phase; the observed child performs only component copy and rustc -vV",
            "python":"No Python executable or libpython was added to the observed executable/runtime closure; all unlisted execution and file access remains default-denied by the adapter.",
            "derived_parent":derived,
            "derived_parent_initial_identity":derived_before,
        }),
    )?;

    let child_test_binary = cold_runtime_path_text(&test_binary)?;
    let child_test_name = "consumer_observe::tests::linux_cold_rustc_runtime_child";
    let env_text = cold_runtime_path_text(&env_path)?;
    let make_child_command = |mode: &str| {
        vec![
            env_text.clone(),
            format!("AMI_RUST_COLD_RUNTIME_CHILD={mode}"),
            child_test_binary.clone(),
            "--ignored".to_owned(),
            "--exact".to_owned(),
            child_test_name.to_owned(),
            "--test-threads=1".to_owned(),
            "--quiet".to_owned(),
        ]
    };
    let counter_case = run_raw_adapter_case(
        "staged-target-rustc-with-only-libdl-read-rule-omitted",
        &artifact_root.join("counter"),
        &adapter,
        &counter_policy_path,
        &spec,
        &make_child_command("counter"),
    )?;
    let counter_report = diagnostic_json_file(Path::new(
        counter_case["report_path"].as_str().unwrap_or_default(),
    ));
    let counter_stderr = read_raw_stderr(&counter_case)?;
    let expected_loader_diagnostic = format!(
        "{}: error while loading shared libraries: libdl.so.2: cannot open shared object file: No such file or directory",
        staged_rustc.display()
    );
    let counter_loader_diagnostic = counter_stderr
        .lines()
        .any(|line| line == expected_loader_diagnostic);
    let counter_staged_rustc_sha256 = sha256_file(&staged_rustc).ok();
    let counter_staged_identity_matches =
        counter_staged_rustc_sha256.as_deref() == Some(reference_rustc_sha256.as_str());
    let counter_gate = counter_case["outer_exit_code"].as_i64() == Some(127)
        && counter_case["child_exit_code"].as_i64() == Some(127)
        && successful_linux_adapter_report(&counter_report, 127)
        && counter_case["capture_error"].is_null()
        && counter_loader_diagnostic
        && counter_staged_identity_matches;
    let counter_gate_report = json!({
        "gate_passed":counter_gate,
        "adapter_case":counter_case,
        "raw_stderr_contains_expected_loader_failure":counter_loader_diagnostic,
        "expected_loader_diagnostic":expected_loader_diagnostic,
        "staged_rustc_sha256":counter_staged_rustc_sha256,
        "staged_binary_matches_pinned_reference":counter_staged_identity_matches,
        "expected_status":127,
        "actual_stderr":counter_stderr,
        "counter_policy":counter_policy,
        "claim":"Only the exact discovered libdl.so.2 read-library rule was removed. The staged pinned rustc must itself reach the dynamic loader and fail because that system library is unavailable under this policy.",
    });
    write_diagnostic_json(
        &artifact_root.join("counter-gate.json"),
        &counter_gate_report,
    )?;

    let before_cleanup_identity = cold_runtime_derived_identity(&derived)?;
    let cleanup = cold_runtime_remove_counter_stage(&derived, &rustc_stage);
    let after_cleanup_identity = cold_runtime_derived_identity(&derived)?;
    let cleanup_value = cleanup.as_ref().ok().cloned();
    let cleanup_error = cleanup.as_ref().err().cloned();
    let cleanup_gate = cleanup.is_ok()
        && cleanup_value
            .as_ref()
            .is_some_and(|value| value["removed_only_staged_component"] == true)
        && before_cleanup_identity == derived_before
        && before_cleanup_identity["device"] == after_cleanup_identity["device"]
        && before_cleanup_identity["inode"] == after_cleanup_identity["inode"]
        && before_cleanup_identity["uid"] == derived_before["uid"]
        && before_cleanup_identity["mode"] == derived_before["mode"];
    let cleanup_report = json!({
        "gate_passed":cleanup_gate,
        "cleanup":cleanup_value,
        "cleanup_error":cleanup_error,
        "before_cleanup_identity":before_cleanup_identity,
        "after_cleanup_identity":after_cleanup_identity,
        "same_initial_parent_inode":before_cleanup_identity["device"] == derived_before["device"]
            && before_cleanup_identity["inode"] == derived_before["inode"],
        "same_parent_after_cleanup":before_cleanup_identity["device"] == after_cleanup_identity["device"]
            && before_cleanup_identity["inode"] == after_cleanup_identity["inode"],
    });
    write_diagnostic_json(&artifact_root.join("counter-cleanup.json"), &cleanup_report)?;
    if !cleanup_gate {
        let result = json!({
            "schema":"ami-rust-linux-cold-rustc-runtime-probe-v1",
            "status":"FAIL",
            "counter_gate_passed":counter_gate,
            "positive_gate_passed":false,
            "source_bindings_unchanged":false,
            "cleanup_gate_passed":cleanup_gate,
            "scope":"Cause-specific staged target-rustc runtime admission only; full cold preparation, native build and RC1 qualification are not established.",
            "claim":"No cause-specific runtime probe pass is established.",
        });
        write_diagnostic_json(&artifact_root.join("probe-result.json"), &result)?;
        return Err(
            "counter stage cleanup did not preserve the same empty private derived parent"
                .to_owned(),
        );
    }

    let positive_case = run_raw_adapter_case(
        "staged-target-rustc-with-pinned-runtime-closure",
        &artifact_root.join("positive"),
        &adapter,
        &policy_path,
        &spec,
        &make_child_command("positive"),
    )?;
    let positive_report = diagnostic_json_file(Path::new(
        positive_case["report_path"].as_str().unwrap_or_default(),
    ));
    let positive_stdout = cold_runtime_case_stdout(&positive_case)?;
    let positive_stdout_text = String::from_utf8_lossy(&positive_stdout).into_owned();
    let staged_rustc_sha256 = sha256_file(&staged_rustc)
        .map_err(|error| format!("hash staged positive rustc: {error}"))?;
    let positive_identity_matches = staged_rustc_sha256 == reference_rustc_sha256;
    let positive_identity = positive_stdout_text
        .contains(&format!("commit-hash: {COLD_RUNTIME_RUST_COMMIT}"))
        && positive_stdout_text.contains(&format!("host: {COLD_RUNTIME_TARGET}"))
        && positive_stdout_text.contains(&format!("LLVM version: {COLD_RUNTIME_LLVM_VERSION}"));
    let positive_gate = positive_case["outer_exit_code"].as_i64() == Some(0)
        && positive_case["child_exit_code"].as_i64() == Some(0)
        && successful_linux_adapter_report(&positive_report, 0)
        && positive_case["capture_error"].is_null()
        && positive_identity_matches
        && positive_identity;
    let positive_gate_report = json!({
        "gate_passed":positive_gate,
        "adapter_case":positive_case,
        "reference_rustc_sha256":reference_rustc_sha256,
        "staged_rustc_sha256":staged_rustc_sha256,
        "staged_binary_matches_pinned_reference":positive_identity_matches,
        "stdout_reports_pinned_rust_commit_target_and_llvm":positive_identity,
        "stdout_path":positive_case["stdout_path"],
        "stdout_sha256":sha256_bytes(&positive_stdout),
        "stdout_bytes":positive_stdout.len(),
        "claim":"The byte-identical staged rustc executed -vV under the positive exact runtime policy and reported the pinned host, commit and LLVM version.",
    });
    write_diagnostic_json(
        &artifact_root.join("positive-gate.json"),
        &positive_gate_report,
    )?;

    let final_parent_identity = cold_runtime_derived_identity(&derived)?;
    let source_unchanged = sha256_file(&inputs_path).map_err(|error| error.to_string())?
        == COLD_RUNTIME_INPUTS_SHA256
        && sha256_file(&archive).map_err(|error| error.to_string())? == COLD_RUNTIME_ARCHIVE_SHA256;
    verify_bindings(&spec.bindings).map_err(|error| error.to_string())?;
    verify_driver(&test_binary, &observer_sha256).map_err(|error| error.to_string())?;
    verify_driver(&adapter, &adapter_sha256).map_err(|error| error.to_string())?;
    let pass = counter_gate && cleanup_gate && positive_gate && source_unchanged;
    let cargo_fork = if pass {
        run_pinned_cargo_fork_probe(&work_root, &artifact_root, &adapter, &source_component)?
    } else {
        Value::Null
    };
    let result = json!({
        "schema":"ami-rust-linux-cold-rustc-runtime-probe-v1",
        "status":if pass { "PASS" } else { "FAIL" },
        "scope":"Cause-specific staged target-rustc loader and pinned Cargo subprocess checks; full cold preparation, native AROS build and RC1 qualification are not established.",
        "host":COLD_RUNTIME_TARGET,
        "source_root":source_root,
        "sdk_inputs_sha256":inputs_sha256,
        "spec_path":artifact_root.join("spec.json"),
        "spec_sha256":sha256_bytes(&raw_spec),
        "pinned_input":pin,
        "archive_verification":archive_verification,
        "reference_rustc_sha256":reference_rustc_sha256,
        "runtime_discovery":artifact_root.join("runtime-discovery.json"),
        "runtime_discovery_sha256":sha256_file(&artifact_root.join("runtime-discovery.json")).map_err(|error| error.to_string())?,
        "closure":artifact_root.join("closure.json"),
        "closure_sha256":closure_sha256,
        "positive_policy":policy_path,
        "positive_policy_sha256":sha256_file(&policy_path).map_err(|error| error.to_string())?,
        "counter_policy":counter_policy,
        "counter_gate_passed":counter_gate,
        "counter_cleanup":cleanup_report,
        "positive_gate_passed":positive_gate,
        "source_bindings_unchanged":source_unchanged,
        "pinned_cargo_fork":cargo_fork,
        "derived_parent_initial_identity":derived_before,
        "derived_parent_before_positive_identity":after_cleanup_identity,
        "derived_parent_final_identity":final_parent_identity,
        "cases":{"counter":counter_gate_report,"positive":positive_gate_report},
        "limits":{"curl_seconds":300,"tar_seconds":300,"runtime_discovery_each_query_seconds":30,"adapter_case_seconds":90,"per_stream_capture_bytes":1048576},
        "limitations":[
            "The staged rustc -vV loader and separate empty host-library Cargo build are cause-specific probes; they do not run the full native CLI cold preparation or an AROS application build.",
            "The existing cold-prepare policy grants outbound network permission, but the observed child performs only a local component copy and rustc -vV.",
            "Host shared-library bytes are those discovered on this Linux runner; the pinned rustc archive does not pin the host operating-system runtime.",
            "No Python executable or libpython is granted; default-deny policy remains in force for unlisted execution and file access.",
        ],
        "claim":"Scoped Linux cause-specific proof only. Full authenticated cold preparation, an AROS application build and protected both-host SDK qualification remain required.",
    });
    write_diagnostic_json(&artifact_root.join("probe-result.json"), &result)?;
    if !pass {
        return Err(format!(
            "cause-specific staged rustc runtime regression did not pass; inspect {}",
            artifact_root.display()
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "PR-only Linux staged target-rustc runtime regression; not cold-prepare or RC1 acceptance"]
fn linux_cold_rustc_runtime_dependency_regression() {
    let artifact = std::env::var_os("AMI_RUST_COLD_RUNTIME_ARTIFACT_ROOT").map(PathBuf::from);
    if let Err(error) = run_linux_cold_rustc_runtime_probe() {
        if let Some(artifact) = artifact.filter(|path| path.is_dir()) {
            let _ = write_diagnostic_json(
                &artifact.join("probe-failure.json"),
                &json!({
                    "schema":"ami-rust-linux-cold-rustc-runtime-failure-v1",
                    "status":"DIAGNOSTIC_INCOMPLETE",
                    "error":error,
                    "claim":"No cause-specific runtime probe pass is established.",
                }),
            );
        }
        panic!(
            "Linux staged target-rustc runtime regression failed; inspect retained evidence: {error}"
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "child fixture for the PR-only staged target-rustc runtime regression"]
fn linux_cold_rustc_runtime_child() {
    use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
    use std::process::Command;

    let mode = std::env::var("AMI_RUST_COLD_RUNTIME_CHILD")
        .expect("adapter command must set the isolated cold-runtime child marker");
    assert!(matches!(mode.as_str(), "counter" | "positive"));
    let home = PathBuf::from(std::env::var_os("HOME").expect("adapter provides private HOME"));
    let marker_path = home.join("cold-runtime-child-input.json");
    let marker_raw = read_regular_bounded(&marker_path, 64 * 1024)
        .expect("read input-bound child fixture marker");
    let marker: Value = serde_json::from_slice(&marker_raw).expect("parse child fixture marker");
    assert_eq!(
        marker["schema"],
        "ami-rust-linux-cold-runtime-child-input-v1"
    );
    let source_component = PathBuf::from(
        marker["source_component"]
            .as_str()
            .expect("source component"),
    );
    let source_rustc = PathBuf::from(marker["source_rustc"].as_str().expect("source rustc"));
    let expected_sha = marker["source_rustc_sha256"]
        .as_str()
        .expect("source rustc digest");
    let derived = PathBuf::from(marker["derived_parent"].as_str().expect("derived parent"));
    let staged_component = PathBuf::from(
        marker["staged_component"]
            .as_str()
            .expect("staged component"),
    );
    let staged_rustc = PathBuf::from(marker["staged_rustc"].as_str().expect("staged rustc"));
    assert!(source_component.is_absolute() && derived.is_absolute());
    assert_eq!(source_rustc, source_component.join("bin/rustc"));
    assert_eq!(staged_component, derived.join("rustc"));
    assert_eq!(staged_rustc, staged_component.join("bin/rustc"));
    assert!(is_sha256_digest(expected_sha));
    assert_eq!(
        sha256_file(&source_rustc).expect("hash pinned source rustc"),
        expected_sha
    );
    let derived_metadata = fs::symlink_metadata(&derived).expect("inspect private derived parent");
    assert!(derived_metadata.file_type().is_dir());
    assert_eq!(derived_metadata.permissions().mode() & 0o7777, 0o700);
    assert!(
        fs::read_dir(&derived)
            .expect("read private derived parent")
            .next()
            .is_none(),
        "adapter must start this fixture with an empty derived parent"
    );
    assert!(
        fs::symlink_metadata(&staged_component).is_err(),
        "stage destination must be new"
    );

    let copy = Command::new("/usr/bin/cp")
        .args(["-a", "--"])
        .arg(&source_component)
        .arg(&staged_component)
        .status()
        .expect("run declared native cp to stage the verified rustc component");
    assert!(copy.success(), "native component staging failed: {copy}");
    assert!(
        fs::symlink_metadata(&staged_rustc)
            .expect("inspect staged rustc")
            .file_type()
            .is_file()
    );
    assert_eq!(
        sha256_file(&staged_rustc).expect("hash staged rustc"),
        expected_sha,
        "staged rustc bytes must equal the archive-authenticated reference binary"
    );

    let status = Command::new(&staged_rustc)
        .arg("-vV")
        .status()
        .expect("execute staged pinned rustc directly");
    match status.code() {
        Some(code) => std::process::exit(code),
        None => panic!(
            "staged rustc terminated by signal {}",
            status.signal().unwrap_or(-1)
        ),
    }
}

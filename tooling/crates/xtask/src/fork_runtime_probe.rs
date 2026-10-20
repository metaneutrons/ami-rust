const CARGO_FORK_ARCHIVE_URL: &str = "https://github.com/metaneutrons/ami-rust/releases/download/v0.1.0/ami-rust-0.1.0-release.tar.xz";
const CARGO_FORK_ARCHIVE_BYTES: u64 = 25_902_508;
const CARGO_FORK_ARCHIVE_SHA256: &str =
    "f4a8cbc562d3c43c573a5a34ddfa99d74928ded94c47df45f4182fde71567d5c";
const CARGO_FORK_BINARY_BYTES: u64 = 48_110_632;
const CARGO_FORK_BINARY_SHA256: &str =
    "938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db";

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cargo_fork_probe_path(path: &Path) -> std::result::Result<String, String> {
    path.to_str()
        .filter(|text| !text.contains(['\n', '\r', '\0']))
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "path cannot be represented in probe policy: {}",
                path.display()
            )
        })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cargo_fork_probe_hash(path: &Path) -> std::result::Result<String, String> {
    sha256_file(path).map_err(|error| format!("hash {}: {error}", path.display()))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cargo_fork_probe_regular_executable(path: &Path) -> std::result::Result<(u64, String), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect executable {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "expected a regular executable file: {}",
            path.display()
        ));
    }
    if fs::canonicalize(path).map_err(|error| error.to_string())? != path {
        return Err(format!(
            "executable path is not canonical: {}",
            path.display()
        ));
    }
    Ok((metadata.len(), cargo_fork_probe_hash(path)?))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cargo_fork_probe_stdout(summary: &Value) -> std::result::Result<Vec<u8>, String> {
    let path = summary["stdout_path"]
        .as_str()
        .ok_or_else(|| "native command summary omitted stdout path".to_owned())?;
    read_regular_bounded(Path::new(path), 1024 * 1024)
        .map_err(|error| format!("read bounded native command stdout: {error}"))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cargo_fork_probe_list_members(
    summary: &Value,
    label: &str,
) -> std::result::Result<Vec<String>, String> {
    let raw = cargo_fork_probe_stdout(summary)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|error| format!("{label} member listing is not UTF-8: {error}"))?;
    if text.is_empty() || !text.ends_with('\n') || text.contains('\r') {
        return Err(format!("{label} member listing is incomplete or malformed"));
    }
    let members = text
        .split_terminator('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if members.is_empty() || members.len() > 4096 {
        return Err(format!("{label} member listing is outside its bound"));
    }
    Ok(members)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cargo_fork_probe_add_policy_environment(
    policy: &str,
    cwd: &Path,
    rustc: &Path,
    rustdoc: &Path,
    cargo_home: &Path,
    target_dir: &Path,
) -> std::result::Result<String, String> {
    let values = [
        ("RUSTC", cargo_fork_probe_path(rustc)?),
        ("RUSTDOC", cargo_fork_probe_path(rustdoc)?),
        ("CARGO_HOME", cargo_fork_probe_path(cargo_home)?),
        ("CARGO_TARGET_DIR", cargo_fork_probe_path(target_dir)?),
        ("RUSTC_BOOTSTRAP", "1".to_owned()),
        ("CARGO_BUILD_JOBS", "2".to_owned()),
    ];
    for (key, value) in &values {
        if value.contains(['\n', '\r', '\0'])
            || policy
                .lines()
                .any(|line| line.starts_with(&format!("env {key}=")))
        {
            return Err(format!(
                "invalid or duplicate generated environment value for {key}"
            ));
        }
    }
    let suffix = format!(
        "cwd {}\nnetwork deny\n",
        printable(cwd).map_err(|error| error.to_string())?
    );
    let body = policy.strip_suffix(&suffix).ok_or_else(|| {
        "generated policy does not end in the expected offline cwd suffix".to_owned()
    })?;
    if policy.matches("network deny\n").count() != 1 || policy.contains("write-null ") {
        return Err(
            "generated build policy has an unexpected network or device-write rule".to_owned(),
        );
    }
    let mut result = String::with_capacity(policy.len() + 512);
    result.push_str(body);
    for (key, value) in values {
        result.push_str("env ");
        result.push_str(key);
        result.push('=');
        result.push_str(&value);
        result.push('\n');
    }
    result.push_str(&suffix);
    Ok(result)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cargo_fork_probe_adapter_capture(
    report: &Value,
    stream: &str,
) -> std::result::Result<(Vec<u8>, String), String> {
    let evidence = report
        .get(stream)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("adapter report omitted {stream} capture evidence"))?;
    if evidence.get("truncated").and_then(Value::as_bool) != Some(false)
        || !evidence.get("write_error").is_some_and(Value::is_null)
    {
        return Err(format!("adapter reported incomplete {stream} output"));
    }
    let path = evidence
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("adapter report omitted {stream} capture path"))?;
    let bytes = read_regular_bounded(Path::new(path), 1024 * 1024)
        .map_err(|error| format!("read raw {stream} capture: {error}"))?;
    let length = u64::try_from(bytes.len()).map_err(|error| error.to_string())?;
    if evidence.get("bytes_captured").and_then(Value::as_u64) != Some(length)
        || evidence.get("bytes_total").and_then(Value::as_u64) != Some(length)
    {
        return Err(format!(
            "raw {stream} capture length differs from adapter evidence"
        ));
    }
    let digest = sha256_bytes(&bytes);
    Ok((bytes, digest))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_pinned_cargo_fork_probe_inner(
    work: &Path,
    artifacts: &Path,
    adapter: &Path,
    rust_component: &Path,
) -> std::result::Result<Value, String> {
    use std::os::unix::fs::PermissionsExt;

    for (label, root) in [("work", work), ("artifacts", artifacts)] {
        if !root.is_absolute()
            || fs::canonicalize(root).map_err(|error| format!("resolve {label} root: {error}"))?
                != root
            || !fs::symlink_metadata(root)
                .map_err(|error| format!("inspect {label} root: {error}"))?
                .file_type()
                .is_dir()
        {
            return Err(format!(
                "{label} root must be an existing canonical directory"
            ));
        }
    }
    let adapter = fs::canonicalize(adapter)
        .map_err(|error| format!("resolve enforcement adapter: {error}"))?;
    let adapter_metadata = fs::symlink_metadata(&adapter)
        .map_err(|error| format!("inspect enforcement adapter: {error}"))?;
    if !adapter_metadata.file_type().is_file() || adapter_metadata.permissions().mode() & 0o111 == 0
    {
        return Err("configured enforcement adapter is not a regular executable".to_owned());
    }
    let adapter_sha256 = cargo_fork_probe_hash(&adapter)?;
    let rust_component = fs::canonicalize(rust_component)
        .map_err(|error| format!("resolve pinned Rust component: {error}"))?;
    if !fs::symlink_metadata(&rust_component)
        .map_err(|error| format!("inspect pinned Rust component: {error}"))?
        .file_type()
        .is_dir()
    {
        return Err("pinned Rust component is not a real directory".to_owned());
    }
    let rustc = rust_component.join("bin/rustc");
    let rustdoc = rust_component.join("bin/rustdoc");
    let (rustc_bytes, rustc_sha256) = cargo_fork_probe_regular_executable(&rustc)?;
    let (rustdoc_bytes, rustdoc_sha256) = cargo_fork_probe_regular_executable(&rustdoc)?;

    let work_root = work.join("cargo-fork-probe");
    create_private_directory(&work_root)?;
    let inputs = work_root.join("inputs");
    let home = work_root.join("home");
    let tmp = work_root.join("tmp");
    let cargo_home = work_root.join("cargo-cache");
    let project = work_root.join("project");
    let project_src = project.join("src");
    let build_work = work_root.join("cargo-build");
    let derived = build_work.join("derived");
    let target_dir = derived.join("target");
    let cargo_root = work_root.join("cargo-component");
    for path in [
        &inputs,
        &home,
        &tmp,
        &cargo_home,
        &project,
        &project_src,
        &build_work,
        &derived,
        &cargo_root,
    ] {
        create_private_directory(path)?;
    }

    let archive = inputs.join("ami-rust-0.1.0-release.tar.xz");
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
        CARGO_FORK_ARCHIVE_BYTES.to_string(),
        "--output".to_owned(),
        cargo_fork_probe_path(&archive)?,
        CARGO_FORK_ARCHIVE_URL.to_owned(),
    ];
    let download = run_cold_runtime_native_command(
        "download-pinned-cargo-release-bundle",
        curl,
        &curl_args,
        &work_root,
        &work_root,
        &artifacts.join("cargo-download"),
        Duration::from_secs(300),
    )?;
    let archive_metadata = fs::symlink_metadata(&archive)
        .map_err(|error| format!("inspect downloaded Cargo release bundle: {error}"))?;
    let archive_sha256 = cargo_fork_probe_hash(&archive)?;
    let archive_verified = archive_metadata.file_type().is_file()
        && archive_metadata.len() == CARGO_FORK_ARCHIVE_BYTES
        && archive_sha256 == CARGO_FORK_ARCHIVE_SHA256;
    let archive_record = json!({
        "url":CARGO_FORK_ARCHIVE_URL,
        "path":archive,
        "bytes":archive_metadata.len(),
        "sha256":archive_sha256,
        "expected_bytes":CARGO_FORK_ARCHIVE_BYTES,
        "expected_sha256":CARGO_FORK_ARCHIVE_SHA256,
        "verified_before_extraction":archive_verified,
        "download_command":download,
    });
    write_diagnostic_json(
        &artifacts.join("cargo-archive-verification.json"),
        &archive_record,
    )?;
    if !archive_verified {
        return Err(
            "downloaded Cargo release bundle did not match its exact size and SHA-256 pin"
                .to_owned(),
        );
    }

    let tar = Path::new("/usr/bin/tar");
    let list_bundle_args = vec![
        "--list".to_owned(),
        "--xz".to_owned(),
        "--file".to_owned(),
        cargo_fork_probe_path(&archive)?,
    ];
    let bundle_listing = run_cold_runtime_native_command(
        "list-pinned-cargo-release-bundle",
        tar,
        &list_bundle_args,
        &work_root,
        &work_root,
        &artifacts.join("cargo-bundle-list"),
        Duration::from_secs(90),
    )?;
    let bundle_members = cargo_fork_probe_list_members(&bundle_listing, "release bundle")?;
    let cargo_archive_member = "cargo-linux-x86_64.tar.xz";
    if bundle_members
        .iter()
        .filter(|member| member.as_str() == cargo_archive_member)
        .count()
        != 1
    {
        return Err(
            "pinned release bundle must contain exactly one cargo-linux-x86_64.tar.xz member"
                .to_owned(),
        );
    }
    let extract_bundle_args = vec![
        "--extract".to_owned(),
        "--xz".to_owned(),
        "--file".to_owned(),
        cargo_fork_probe_path(&archive)?,
        "--directory".to_owned(),
        cargo_fork_probe_path(&inputs)?,
        "--no-same-owner".to_owned(),
        "--no-same-permissions".to_owned(),
        "--".to_owned(),
        cargo_archive_member.to_owned(),
    ];
    let bundle_extract = run_cold_runtime_native_command(
        "extract-only-pinned-linux-cargo-component-archive",
        tar,
        &extract_bundle_args,
        &work_root,
        &work_root,
        &artifacts.join("cargo-bundle-extract"),
        Duration::from_secs(90),
    )?;
    let cargo_component_archive = inputs.join(cargo_archive_member);
    let component_archive_metadata = fs::symlink_metadata(&cargo_component_archive)
        .map_err(|error| format!("inspect extracted Cargo component archive: {error}"))?;
    if !component_archive_metadata.file_type().is_file() {
        return Err("selected Cargo component archive is not a regular file".to_owned());
    }
    let component_archive_sha256 = cargo_fork_probe_hash(&cargo_component_archive)?;

    let list_component_args = vec![
        "--list".to_owned(),
        "--xz".to_owned(),
        "--file".to_owned(),
        cargo_fork_probe_path(&cargo_component_archive)?,
    ];
    let component_listing = run_cold_runtime_native_command(
        "list-pinned-linux-cargo-component-archive",
        tar,
        &list_component_args,
        &work_root,
        &work_root,
        &artifacts.join("cargo-component-list"),
        Duration::from_secs(90),
    )?;
    let component_members = cargo_fork_probe_list_members(&component_listing, "Cargo component")?;
    if component_members != ["bin/cargo", "producer.json"] {
        return Err(format!(
            "pinned Cargo component archive has unexpected members: {}",
            component_members.join(", ")
        ));
    }
    let extract_component_args = vec![
        "--extract".to_owned(),
        "--xz".to_owned(),
        "--file".to_owned(),
        cargo_fork_probe_path(&cargo_component_archive)?,
        "--directory".to_owned(),
        cargo_fork_probe_path(&cargo_root)?,
        "--no-same-owner".to_owned(),
        "--no-same-permissions".to_owned(),
    ];
    let component_extract = run_cold_runtime_native_command(
        "extract-pinned-linux-cargo-component",
        tar,
        &extract_component_args,
        &work_root,
        &work_root,
        &artifacts.join("cargo-component-extract"),
        Duration::from_secs(90),
    )?;
    let cargo = cargo_root.join("bin/cargo");
    let (cargo_bytes, cargo_sha256) = cargo_fork_probe_regular_executable(&cargo)?;
    if cargo_bytes != CARGO_FORK_BINARY_BYTES || cargo_sha256 != CARGO_FORK_BINARY_SHA256 {
        return Err(format!(
            "extracted Cargo binary differs from its exact producer pin: bytes={cargo_bytes}, sha256={cargo_sha256}"
        ));
    }
    let producer_record = cargo_root.join("producer.json");
    let producer_bytes = read_regular_bounded(&producer_record, 1024 * 1024)
        .map_err(|error| format!("read Cargo producer record: {error}"))?;

    let manifest_path = project.join("Cargo.toml");
    let lock_path = project.join("Cargo.lock");
    let source_path = project_src.join("lib.rs");
    let manifest = b"[package]\nname = \"ami-rust-fork-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\nname = \"ami_rust_fork_probe\"\npath = \"src/lib.rs\"\n";
    let lock = b"version = 4\n\n[[package]]\nname = \"ami-rust-fork-probe\"\nversion = \"0.1.0\"\n";
    let source = b"#![feature(no_core)]\n#![no_core]\n";
    write_new(&manifest_path, manifest).map_err(|error| error.to_string())?;
    write_new(&lock_path, lock).map_err(|error| error.to_string())?;
    write_new(&source_path, source).map_err(|error| error.to_string())?;

    let mut fixture = Fixture::at(artifacts.join("cargo-fixture"), true);
    fixture.value["phase"] = json!("build");
    fixture.value["command"] = json!([
        cargo,
        "build",
        "--release",
        "--locked",
        "--offline",
        "-j2",
        "-vv",
    ]);
    fixture.value["expected_exit"] = json!(0);
    fixture.value["cwd"] = json!(project);
    fixture.value["home"] = json!(home);
    fixture.value["tmp"] = json!(tmp);
    fixture.value["read_trees"] = json!([
        {"role":"toolchain", "path":cargo_root},
        {"role":"toolchain", "path":rust_component},
        {"role":"source", "path":project},
    ]);
    fixture.value["write_trees"] = json!([
        {"role":"home", "path":home},
        {"role":"tmp", "path":tmp},
        {"role":"cargo-home", "path":cargo_home},
        {"role":"work", "path":build_work},
    ]);
    fixture.value["executables"] = json!([cargo, rustc]);
    fixture.value["libraries"] = json!([]);
    fixture.value["read_files"] = json!([]);
    fixture.value["read_directories"] = json!([]);
    fixture.value["deny_exec"] = json!([]);
    fixture.value["deny_library"] = json!([]);
    fixture.value["component_record"] = Value::Null;
    fixture.value["derived"] = json!({"role":"consumer-build-parent", "path":derived});
    fixture.value["bindings"]
        .as_array_mut()
        .ok_or_else(|| "fixture omitted bindings array".to_owned())?
        .extend([
            json!({"path":cargo_component_archive, "sha256":component_archive_sha256}),
            json!({"path":cargo, "sha256":cargo_sha256}),
            json!({"path":producer_record, "sha256":sha256_bytes(&producer_bytes)}),
            json!({"path":rustc, "sha256":rustc_sha256}),
            json!({"path":rustdoc, "sha256":rustdoc_sha256}),
            json!({"path":manifest_path, "sha256":sha256_bytes(manifest)}),
            json!({"path":lock_path, "sha256":sha256_bytes(lock)}),
            json!({"path":source_path, "sha256":sha256_bytes(source)}),
        ]);
    let raw_spec = serde_json::to_vec_pretty(&fixture.value)
        .map_err(|error| format!("encode pinned Cargo observation spec: {error}"))?;
    write_new(&artifacts.join("cargo-spec.json"), &raw_spec).map_err(|error| error.to_string())?;
    let spec = fixture.parse().map_err(|error| error.to_string())?;
    if spec.phase != "build"
        || spec.derived.as_ref().map(|tree| tree.path.as_path()) != Some(derived.as_path())
        || spec
            .read_trees
            .iter()
            .map(|tree| tree.path.as_path())
            .collect::<BTreeSet<_>>()
            != BTreeSet::from([
                cargo_root.as_path(),
                rust_component.as_path(),
                project.as_path(),
            ])
        || spec.executables != BTreeSet::from([cargo.clone(), rustc.clone()])
        || spec
            .write_trees
            .iter()
            .map(|tree| tree.path.as_path())
            .collect::<BTreeSet<_>>()
            != BTreeSet::from([
                home.as_path(),
                tmp.as_path(),
                cargo_home.as_path(),
                build_work.as_path(),
            ])
    {
        return Err("parsed Cargo probe spec differs from its exact reviewed roots".to_owned());
    }
    verify_bindings(&spec.bindings).map_err(|error| error.to_string())?;

    let mut declared_executables = spec.executables.clone();
    declared_executables.insert(
        fs::canonicalize(&spec.command[0])
            .map_err(|error| format!("resolve Cargo command: {error}"))?,
    );
    let runtime = consumer_runtime::discover(
        declared_executables,
        spec.libraries.clone(),
        false,
        false,
        &work_root,
    )
    .map_err(|error| format!("discover Cargo and rustc native runtime: {error}"))?;
    write_diagnostic_json(
        &artifacts.join("cargo-runtime-discovery.json"),
        &runtime.evidence,
    )?;

    let closure = json!({
        "schema":"ami-rust-linux-pinned-cargo-fork-runtime-closure-v1",
        "spec_sha256":sha256_bytes(&raw_spec),
        "adapter_sha256":adapter_sha256,
        "cargo_sha256":cargo_sha256,
        "rustc_sha256":rustc_sha256,
        "rustdoc_sha256":rustdoc_sha256,
        "bindings":spec.bindings,
        "runtime":runtime.evidence,
        "scope":"Actual pinned Cargo 1.99 plus its paired pinned rustc compiling one dependency-free no_core rlib under offline and network-deny policy; no SDK, AROS target, linker, or acceptance claim.",
    });
    let closure_raw = serde_json::to_vec_pretty(&closure)
        .map_err(|error| format!("encode runtime closure: {error}"))?;
    let closure_sha256 = sha256_bytes(&closure_raw);
    write_new(&artifacts.join("cargo-runtime-closure.json"), &closure_raw)
        .map_err(|error| error.to_string())?;
    let base_policy = render_policy(
        &spec,
        &runtime,
        spec.read_trees
            .iter()
            .map(|tree| tree.path.clone())
            .collect(),
        &closure_sha256,
    )
    .map_err(|error| format!("render Cargo runtime policy: {error}"))?;
    let policy = cargo_fork_probe_add_policy_environment(
        &base_policy,
        &spec.cwd,
        &rustc,
        &rustdoc,
        &cargo_home,
        &target_dir,
    )?;
    let policy_path = artifacts.join("cargo-policy.txt");
    write_new(&policy_path, policy.as_bytes()).map_err(|error| error.to_string())?;
    let policy_sha256 = sha256_bytes(policy.as_bytes());
    if !policy.contains("network deny\n")
        || policy.contains("network outbound\n")
        || policy.contains("write-null ")
        || !policy.contains(&format!("env RUSTC={}\n", cargo_fork_probe_path(&rustc)?))
        || !policy.contains(&format!(
            "env RUSTDOC={}\n",
            cargo_fork_probe_path(&rustdoc)?
        ))
        || !policy.contains(&format!(
            "env CARGO_HOME={}\n",
            cargo_fork_probe_path(&cargo_home)?
        ))
        || !policy.contains(&format!(
            "env CARGO_TARGET_DIR={}\n",
            cargo_fork_probe_path(&target_dir)?
        ))
        || !policy.contains("env RUSTC_BOOTSTRAP=1\n")
        || !policy.contains("env CARGO_BUILD_JOBS=2\n")
    {
        return Err(
            "final Cargo policy does not enforce the exact offline compiler environment".to_owned(),
        );
    }
    write_diagnostic_json(
        &artifacts.join("cargo-policy.json"),
        &json!({
            "path":policy_path,
            "sha256":policy_sha256,
            "network":"deny",
            "write_roots":spec.write_trees.iter().map(|tree| json!({"role":tree.role,"path":tree.path})).collect::<Vec<_>>(),
            "read_trees":spec.read_trees.iter().map(|tree| tree.path.clone()).collect::<Vec<_>>(),
            "executables":spec.executables,
            "derived_execution_parent":derived,
        }),
    )?;

    let cargo_sha256_before = cargo_fork_probe_hash(&cargo)?;
    let rustc_sha256_before = cargo_fork_probe_hash(&rustc)?;
    if cargo_sha256_before != CARGO_FORK_BINARY_SHA256 || rustc_sha256_before != rustc_sha256 {
        return Err("pinned Cargo or paired rustc changed before the adapter launch".to_owned());
    }
    let target_rlib = target_dir.join("release/libami_rust_fork_probe.rlib");
    if target_rlib.symlink_metadata().is_ok() {
        return Err("Cargo probe started with an existing output artifact".to_owned());
    }
    // The adapter admits this exact private parent only while it is empty.
    // Cargo, rather than the harness, must create the target tree inside it.
    let derived_before = cold_runtime_derived_identity(&derived)?;
    if fs::read_dir(&derived)
        .map_err(|error| format!("inspect Cargo derived parent: {error}"))?
        .next()
        .is_some()
    {
        return Err("Cargo probe derived parent is not empty before its counter".to_owned());
    }
    let counter_policy_path = artifacts.join("cargo-counter-rustc-exec-omitted.txt");
    let counter_policy =
        copy_policy_omitting_one_exec_hash(&policy_path, &counter_policy_path, &rustc)?;
    let counter_case = run_raw_adapter_case(
        "pinned-cargo-with-only-rustc-exec-rule-omitted",
        &artifacts.join("cargo-counter-case"),
        &adapter,
        &counter_policy_path,
        &spec,
        &spec.command,
    )?;
    let counter_report = diagnostic_json_file(Path::new(
        counter_case["report_path"].as_str().unwrap_or_default(),
    ));
    if !successful_linux_adapter_report(&counter_report, 101) {
        let adapter_stderr = read_regular_bounded(
            Path::new(
                counter_case["adapter_stderr_path"]
                    .as_str()
                    .unwrap_or_default(),
            ),
            1024 * 1024,
        )
        .map_err(|error| format!("read failed Cargo counter adapter diagnostic: {error}"))?;
        return Err(format!(
            "Cargo counter did not reach the expected child refusal (outer exit {}): {}",
            counter_case["outer_exit_code"],
            String::from_utf8_lossy(&adapter_stderr)
        ));
    }
    let counter_stderr = read_raw_stderr(&counter_case)?;
    let counter_gate = counter_case["outer_exit_code"].as_i64() == Some(101)
        && counter_case["outer_signal"].is_null()
        && counter_case["capture_error"].is_null()
        && successful_linux_adapter_report(&counter_report, 101)
        && counter_report["network_outbound_allowed"] == false
        && counter_stderr.contains(&cargo_fork_probe_path(&rustc)?)
        && counter_stderr.contains("Permission denied (os error 13)")
        && target_rlib.symlink_metadata().is_err();
    let counter = json!({
        "gate_passed":counter_gate,
        "policy":counter_policy,
        "case":counter_case,
        "expected_cargo_exit":101,
        "artifact_absent":target_rlib.symlink_metadata().is_err(),
        "claim":"Removing only the selected rustc exec-hash rule must prevent this same pinned Cargo from starting its compiler. All other policy bytes and compiler inputs remain unchanged.",
    });
    write_diagnostic_json(&artifacts.join("cargo-counter-gate.json"), &counter)?;
    if !counter_gate {
        return Err(
            "pinned Cargo missing-compiler-execution counter did not refuse as expected".to_owned(),
        );
    }
    // A refused compiler must leave no reusable build output. Remove only the
    // known probe-owned target child, retaining the same private parent inode.
    let cleanup = cold_runtime_remove_counter_stage(&derived, &target_dir)?;
    let derived_after_counter = cold_runtime_derived_identity(&derived)?;
    if derived_after_counter != derived_before {
        return Err("Cargo counter changed its private derived parent identity".to_owned());
    }
    let counter_cleanup = json!({
        "cleanup":cleanup,
        "before":derived_before,
        "after":derived_after_counter,
        "same_parent_identity":true,
    });
    write_diagnostic_json(
        &artifacts.join("cargo-counter-cleanup.json"),
        &counter_cleanup,
    )?;
    let adapter_case = run_raw_adapter_case(
        "pinned-linux-cargo-1.99-starts-paired-rustc-offline",
        &artifacts.join("cargo-build-case"),
        &adapter,
        &policy_path,
        &spec,
        &spec.command,
    )?;
    let report_path = adapter_case["report_path"]
        .as_str()
        .ok_or_else(|| "adapter case omitted report path".to_owned())?;
    let report_raw = read_regular_bounded(Path::new(report_path), 2 * 1024 * 1024)
        .map_err(|error| format!("read pinned Cargo adapter report: {error}"))?;
    let report = parse_json_value(&report_raw, JsonProfile::VerifierOutput)
        .map_err(|error| format!("parse pinned Cargo adapter report: {error}"))?;
    let child_stdout = cargo_fork_probe_adapter_capture(&report, "stdout")?;
    let child_stderr = cargo_fork_probe_adapter_capture(&report, "stderr")?;
    let rustc_command_observed = [
        String::from_utf8_lossy(&child_stdout.0),
        String::from_utf8_lossy(&child_stderr.0),
    ]
    .iter()
    .any(|output| output.contains(&cargo_fork_probe_path(&rustc).unwrap_or_default()));
    let adapter_output_complete = adapter_case["outer_exit_code"].as_i64() == Some(0)
        && adapter_case["outer_signal"].is_null()
        && adapter_case["child_exit_code"].as_i64() == Some(0)
        && adapter_case["child_signal"].is_null()
        && adapter_case["capture_error"].is_null()
        && successful_linux_adapter_report(&report, 0)
        && report["network_outbound_allowed"].as_bool() == Some(false)
        && report["seccomp"]["network_denied"].as_bool() == Some(true)
        && rustc_command_observed;

    let rlib_metadata = fs::symlink_metadata(&target_rlib)
        .map_err(|error| format!("inspect expected Cargo rlib: {error}"))?;
    if !rlib_metadata.file_type().is_file() || rlib_metadata.len() <= 8 {
        return Err("Cargo did not produce a nonempty regular rlib artifact".to_owned());
    }
    let rlib_bytes = read_regular_bounded(&target_rlib, 64 * 1024 * 1024)
        .map_err(|error| format!("read Cargo rlib archive header: {error}"))?;
    let rlib_magic_valid = rlib_bytes.starts_with(b"!<arch>\n");
    let rlib_sha256 = sha256_bytes(&rlib_bytes);
    let cargo_sha256_after = cargo_fork_probe_hash(&cargo)?;
    let rustc_sha256_after = cargo_fork_probe_hash(&rustc)?;
    verify_bindings(&spec.bindings).map_err(|error| error.to_string())?;
    verify_driver(&adapter, &adapter_sha256).map_err(|error| error.to_string())?;
    let source_bindings_unchanged = cargo_sha256_before == cargo_sha256_after
        && rustc_sha256_before == rustc_sha256_after
        && cargo_sha256_after == CARGO_FORK_BINARY_SHA256;
    let pass =
        counter_gate && adapter_output_complete && rlib_magic_valid && source_bindings_unchanged;
    let result = json!({
        "schema":"ami-rust-linux-pinned-cargo-fork-runtime-probe-v1",
        "status":if pass {"PASS"} else {"FAIL"},
        "host":"linux-x86_64",
        "scope":"Cause-specific proof that the exact pinned Linux Cargo 1.99 binary starts its paired pinned rustc under offline and network-deny policy to compile one dependency-free no_core rlib. It is not a full SDK build, AROS target build, linker test, or SDK/RC1 acceptance.",
        "claim":"The pinned Cargo binary and source-provided rustc completed an actual locked offline Cargo build under the Linux enforcement adapter; the expected rlib passed regular-file and ar-magic checks.",
        "archive":archive_record,
        "cargo_component":{
            "archive_path":cargo_component_archive,
            "archive_sha256":component_archive_sha256,
            "archive_bytes":component_archive_metadata.len(),
            "archive_members":component_members,
            "bundle_members":bundle_members,
            "bundle_extract_command":bundle_extract,
            "component_extract_command":component_extract,
            "cargo_path":cargo,
            "cargo_bytes":cargo_bytes,
            "cargo_sha256":cargo_sha256,
            "expected_cargo_bytes":CARGO_FORK_BINARY_BYTES,
            "expected_cargo_sha256":CARGO_FORK_BINARY_SHA256,
            "producer_record_sha256":sha256_bytes(&producer_bytes),
        },
        "paired_rustc":{
            "component_root":rust_component,
            "rustc_path":rustc,
            "rustc_bytes":rustc_bytes,
            "rustc_sha256_before":rustc_sha256_before,
            "rustc_sha256_after":rustc_sha256_after,
            "rustdoc_path":rustdoc,
            "rustdoc_bytes":rustdoc_bytes,
            "rustdoc_sha256":rustdoc_sha256,
        },
        "project":{
            "manifest_path":manifest_path,
            "manifest_sha256":sha256_bytes(manifest),
            "lock_path":lock_path,
            "lock_sha256":sha256_bytes(lock),
            "source_path":source_path,
            "source_sha256":sha256_bytes(source),
            "source":"#![feature(no_core)]\\n#![no_core]\\n",
        },
        "runtime_discovery":artifacts.join("cargo-runtime-discovery.json"),
        "runtime_closure":artifacts.join("cargo-runtime-closure.json"),
        "runtime_closure_sha256":closure_sha256,
        "spec_path":artifacts.join("cargo-spec.json"),
        "spec_sha256":sha256_bytes(&raw_spec),
        "policy_path":policy_path,
        "policy_sha256":policy_sha256,
        "network_denied":report["seccomp"]["network_denied"].as_bool() == Some(true),
        "adapter_report":report_path,
        "adapter_report_sha256":sha256_bytes(&report_raw),
        "adapter_case":adapter_case,
        "compiler_execution_counter":counter,
        "counter_cleanup":counter_cleanup,
        "child_output":{
            "stdout_path":report["stdout"]["path"],
            "stdout_bytes":child_stdout.0.len(),
            "stdout_sha256":child_stdout.1,
            "stdout_truncated":report["stdout"]["truncated"],
            "stderr_path":report["stderr"]["path"],
            "stderr_bytes":child_stderr.0.len(),
            "stderr_sha256":child_stderr.1,
            "stderr_truncated":report["stderr"]["truncated"],
            "rustc_command_observed":rustc_command_observed,
            "capture_limit_bytes_per_stream":1048576,
        },
        "artifact":{
            "path":target_rlib,
            "regular_file":rlib_metadata.file_type().is_file(),
            "bytes":rlib_bytes.len(),
            "sha256":rlib_sha256,
            "ar_magic_valid":rlib_magic_valid,
        },
        "cargo_sha256_before":cargo_sha256_before,
        "cargo_sha256_after":cargo_sha256_after,
        "source_bindings_unchanged":source_bindings_unchanged,
        "limits":{"download_seconds":300,"native_setup_command_seconds":90,"adapter_seconds":90,"capture_bytes_per_stream":1048576},
        "limitations":[
            "The probe verifies Cargo-to-rustc startup and a dependency-free host rlib only; it does not invoke the native linker, cross-compile for AROS, or build the full SDK.",
            "Cargo's required derived-build execution parent is a fresh private work directory. The tiny no_core library has no build script or generated executable.",
            "The historical public release bundle is bound by its exact size and SHA-256; only cargo-linux-x86_64.tar.xz is extracted from that bundle.",
        ],
    });
    if !pass {
        return Err(format!(
            "pinned Cargo fork runtime probe did not satisfy all gates; inspect {}",
            artifacts.display()
        ));
    }
    Ok(result)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_pinned_cargo_fork_probe(
    work: &Path,
    artifacts: &Path,
    adapter: &Path,
    rust_component: &Path,
) -> std::result::Result<Value, String> {
    let final_path = artifacts.join("cargo-fork-probe-result.json");
    let result = run_pinned_cargo_fork_probe_inner(work, artifacts, adapter, rust_component);
    match result {
        Ok(value) => {
            write_diagnostic_json(&final_path, &value)?;
            Ok(value)
        }
        Err(error) => {
            let failure = json!({
                "schema":"ami-rust-linux-pinned-cargo-fork-runtime-probe-v1",
                "status":"FAIL",
                "error":error,
                "evidence_root":artifacts,
                "claim":"No Cargo fork runtime pass is established.",
            });
            if artifacts.is_dir() && final_path.symlink_metadata().is_err() {
                let _ = write_diagnostic_json(&final_path, &failure);
            }
            Err(error)
        }
    }
}

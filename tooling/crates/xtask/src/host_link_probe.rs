#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOST_LINK_WRAPPER_BYTES: u64 = 371_792;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOST_LINK_WRAPPER_SHA256: &str =
    "7f70580541f73167127f22c9e04b6b038af4febf06471dfb574f639830bf828a";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOST_LINK_RUST_LLD_BYTES: u64 = 11_879_600;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOST_LINK_RUST_LLD_SHA256: &str =
    "1cdd049960f8fb07aba44b9582d33c35e3e3913e14f754ba0ceade3cc2619bd8";

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "requires the previously extracted pinned Linux rustc component and host adapter"]
fn linux_pinned_host_linker_regression() {
    if let Err(error) = run_linux_pinned_host_linker_probe() {
        panic!("pinned Linux host-link regression failed: {error}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_linux_pinned_host_linker_probe() -> std::result::Result<(), String> {
    let artifacts = required_diagnostic_path("AMI_RUST_HOST_LINK_ARTIFACT_ROOT")?;
    create_private_directory(&artifacts)?;
    let result_path = artifacts.join("probe-result.json");
    let result = run_linux_pinned_host_linker_probe_inner(&artifacts);
    match result {
        Ok(mut value) => {
            value["status"] = json!("PASS");
            write_diagnostic_json(&result_path, &value)?;
            Ok(())
        }
        Err(error) => {
            write_diagnostic_json(
                &result_path,
                &json!({
                    "schema":"ami-rust-linux-pinned-host-linker-probe-v1",
                    "status":"FAIL",
                    "host":"linux-x86_64",
                    "scope":"Cause-specific pinned Linux host-linker route check; it does not establish a Rust host build, full SDK build, or RC1 acceptance.",
                    "positive_gate_passed":false,
                    "counter_gate_passed":false,
                    "system_link_input_gate_passed":false,
                    "source_bindings_unchanged":false,
                    "cleanup_gate_passed":false,
                    "error":error,
                    "evidence_root":artifacts,
                    "claim":"No pinned Linux host-linker regression pass is established."
                }),
            )?;
            Err(error)
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_linux_pinned_host_linker_probe_inner(
    artifacts: &Path,
) -> std::result::Result<Value, String> {
    use std::os::unix::fs::PermissionsExt;

    let work = required_diagnostic_path("AMI_RUST_HOST_LINK_WORK_ROOT")?;
    create_private_directory(&work)?;
    if overlaps(artifacts, &work) {
        return Err("host-link work and evidence roots overlap".to_owned());
    }
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
    if !fs::symlink_metadata(&adapter)
        .map_err(|error| format!("inspect host enforcement adapter: {error}"))?
        .file_type()
        .is_file()
    {
        return Err("configured host enforcement adapter is not a regular file".to_owned());
    }

    let home = work.join("home");
    let tmp = work.join("tmp");
    let build_work = work.join("build");
    let derived = build_work.join("derived");
    for path in [&home, &tmp, &build_work, &derived] {
        create_private_directory(path)?;
    }
    if fs::read_dir(&derived)
        .map_err(|error| format!("inspect initially empty linker output root: {error}"))?
        .next()
        .is_some()
    {
        return Err("linker output root is not initially empty".to_owned());
    }

    let cc = fs::canonicalize("/usr/bin/cc")
        .map_err(|error| format!("resolve pinned-host GCC driver /usr/bin/cc: {error}"))?;
    let rust_tools = rust_component_executables(COLD_RUNTIME_TARGET)
        .into_iter()
        .map(|relative| component.join(relative))
        .collect::<Vec<_>>();
    let wrapper_declared = component.join(format!(
        "lib/rustlib/{COLD_RUNTIME_TARGET}/bin/gcc-ld/ld.lld"
    ));
    if !rust_tools.contains(&wrapper_declared) {
        return Err(format!(
            "production Rust executable closure omits the pinned GCC linker wrapper: {}",
            wrapper_declared.display()
        ));
    }
    let wrapper = fs::canonicalize(&wrapper_declared)
        .map_err(|error| format!("resolve pinned GCC linker wrapper: {error}"))?;
    let wrapper_metadata = fs::symlink_metadata(&wrapper)
        .map_err(|error| format!("inspect pinned GCC linker wrapper: {error}"))?;
    if !wrapper_metadata.file_type().is_file() || wrapper_metadata.permissions().mode() & 0o111 == 0
    {
        return Err("pinned GCC linker wrapper is not a regular executable".to_owned());
    }
    let wrapper_sha256 = sha256_file(&wrapper).map_err(|error| error.to_string())?;
    if wrapper_metadata.len() != HOST_LINK_WRAPPER_BYTES
        || wrapper_sha256 != HOST_LINK_WRAPPER_SHA256
    {
        return Err(
            "pinned GCC linker wrapper differs from the verified archive identity".to_owned(),
        );
    }
    let rust_lld =
        fs::canonicalize(component.join(format!("lib/rustlib/{COLD_RUNTIME_TARGET}/bin/rust-lld")))
            .map_err(|error| format!("resolve pinned rust-lld: {error}"))?;
    let rust_lld_sha256 = sha256_file(&rust_lld).map_err(|error| error.to_string())?;
    let rust_lld_bytes = fs::metadata(&rust_lld)
        .map_err(|error| format!("inspect pinned rust-lld: {error}"))?
        .len();
    if rust_lld_bytes != HOST_LINK_RUST_LLD_BYTES || rust_lld_sha256 != HOST_LINK_RUST_LLD_SHA256 {
        return Err("pinned rust-lld differs from the verified archive identity".to_owned());
    }
    let source = artifacts.join("link-probe.c");
    let source_bytes =
        b"#include <stdio.h>\nint main(void) { puts(\"ami-rust-host-link-ok\"); return 0; }\n";
    write_new(&source, source_bytes).map_err(|error| error.to_string())?;
    let positive_output = derived.join("host-link-positive");
    let counter_output = derived.join("host-link-counter");
    let system_link_output = derived.join("host-link-system-input-counter");
    let wrapper_dir = wrapper_declared
        .parent()
        .ok_or_else(|| "pinned GCC linker wrapper has no parent directory".to_owned())?;
    let cc_text = cold_runtime_path_text(&cc)?;
    let wrapper_dir_text = cold_runtime_path_text(wrapper_dir)?;
    let source_text = cold_runtime_path_text(&source)?;
    let positive_output_text = cold_runtime_path_text(&positive_output)?;
    let counter_output_text = cold_runtime_path_text(&counter_output)?;
    let system_link_output_text = cold_runtime_path_text(&system_link_output)?;
    let route = format!("-B{wrapper_dir_text}");
    let rust_host_library_sequence = [
        "-Wl,-Bdynamic",
        "-lgcc_s",
        "-lutil",
        "-lrt",
        "-lpthread",
        "-lm",
        "-ldl",
        "-lc",
    ];
    let query_command = vec![
        cc_text.clone(),
        route.clone(),
        "-fuse-ld=lld".to_owned(),
        "-print-prog-name=ld.lld".to_owned(),
    ];
    let make_link_command = |output: &str| {
        vec![
            cc_text.clone(),
            route.clone(),
            "-fuse-ld=lld".to_owned(),
            "-x".to_owned(),
            "c".to_owned(),
            source_text.clone(),
            "-o".to_owned(),
            output.to_owned(),
        ]
        .into_iter()
        .chain(
            rust_host_library_sequence
                .iter()
                .map(|argument| (*argument).to_owned()),
        )
        .collect::<Vec<_>>()
    };
    let positive_command = make_link_command(&positive_output_text);
    let counter_command = make_link_command(&counter_output_text);
    let system_link_command = make_link_command(&system_link_output_text);

    let attempt = (|| -> std::result::Result<Value, String> {
        let mut fixture = Fixture::at(artifacts.join("fixture"), true);
        fixture.value["phase"] = json!("build");
        fixture.value["command"] = json!(positive_command);
        fixture.value["expected_exit"] = json!(0);
        fixture.value["cwd"] = json!(build_work);
        fixture.value["home"] = json!(home);
        fixture.value["tmp"] = json!(tmp);
        fixture.value["read_trees"] = json!([{"role":"toolchain", "path":component}]);
        fixture.value["write_trees"] = json!([
            {"role":"home", "path":home},
            {"role":"tmp", "path":tmp},
            {"role":"work", "path":build_work},
        ]);
        fixture.value["read_files"] = json!([source.clone()]);
        fixture.value["executables"] = json!(
            [cc.clone()]
                .into_iter()
                .chain(rust_tools.iter().cloned())
                .collect::<Vec<_>>()
        );
        fixture.value["libraries"] = json!([]);
        fixture.value["read_directories"] = json!([]);
        fixture.value["deny_exec"] = json!([]);
        fixture.value["deny_library"] = json!([]);
        fixture.value["component_record"] = Value::Null;
        fixture.value["derived"] = json!({"role":"consumer-build-parent", "path":derived});
        fixture.value["bindings"] = json!([]);
        let bindings = rust_tools
        .iter()
        .chain([&cc, &source])
        .map(|path| {
            Ok(json!({
                "path":path,
                "sha256":sha256_file(path).map_err(|error| format!("hash {}: {error}", path.display()))?,
            }))
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
        fixture.value["bindings"] = json!(bindings);
        let raw_spec = serde_json::to_vec_pretty(&fixture.value)
            .map_err(|error| format!("encode pinned host-link observation spec: {error}"))?;
        write_new(&artifacts.join("host-link-spec.json"), &raw_spec)
            .map_err(|error| error.to_string())?;
        let spec = fixture.parse().map_err(|error| error.to_string())?;
        if spec.phase != "build"
            || spec.derived.as_ref().map(|tree| tree.path.as_path()) != Some(derived.as_path())
            || !spec.executables.contains(&cc)
            || !spec.read_files.contains(&source)
            || spec.write_trees.len() != 3
        {
            return Err(
                "parsed host-link observation spec differs from its declared roots".to_owned(),
            );
        }
        verify_bindings(&spec.bindings).map_err(|error| error.to_string())?;

        let mut executables = spec.executables.clone();
        executables.insert(fs::canonicalize(&spec.command[0]).map_err(|error| error.to_string())?);
        let runtime =
            consumer_runtime::discover(executables, spec.libraries.clone(), true, false, &work)
                .map_err(|error| {
                    format!("discover pinned GCC and Rust component runtime: {error}")
                })?;
        if !runtime.executables.contains(&wrapper) || !runtime.executables.contains(&rust_lld) {
            return Err("runtime discovery omitted the wrapper or rust-lld executable".to_owned());
        }
        let system_link_inputs = host_link_probe_gcc_link_inputs(&runtime)?;
        write_diagnostic_json(
            &artifacts.join("system-link-inputs.json"),
            &json!({
                "inputs":system_link_inputs,
                "source":"runtime discovery build_inputs rows with kind gcc_link_input, independently checked as canonical regular files and admitted exact read_files",
                "claim":"Four GCC-resolved host-link archives and one GCC-resolved shared ELF input are individually identified by canonical path, byte length, and SHA-256.",
            }),
        )?;
        write_diagnostic_json(&artifacts.join("runtime-discovery.json"), &runtime.evidence)?;
        let closure = json!({
            "schema":"ami-rust-linux-pinned-host-link-closure-v1",
            "spec_sha256":sha256_bytes(&raw_spec),
            "bindings":spec.bindings,
            "runtime":runtime.evidence,
            "system_link_inputs":system_link_inputs,
            "gcc_linker_wrapper":{"declared_path":wrapper_declared,"canonical_path":wrapper,"sha256":wrapper_sha256},
            "rust_lld":{"canonical_path":rust_lld,"sha256":rust_lld_sha256},
            "scope":"Pinned Linux Rust component plus discovered GCC build inputs for the exact GCC -B/-fuse-ld=lld C-link route. This does not prove a rustc build script or full SDK build.",
        });
        let closure_raw = serde_json::to_vec_pretty(&closure)
            .map_err(|error| format!("encode pinned host-link input closure: {error}"))?;
        let closure_sha256 = sha256_bytes(&closure_raw);
        write_new(&artifacts.join("runtime-closure.json"), &closure_raw)
            .map_err(|error| error.to_string())?;
        let reads = spec
            .read_trees
            .iter()
            .map(|tree| tree.path.clone())
            .collect::<BTreeSet<_>>();
        let policy = render_policy(&spec, &runtime, reads, &closure_sha256)
            .map_err(|error| format!("render pinned host-link policy: {error}"))?;
        let policy_path = artifacts.join("positive-policy.txt");
        write_new(&policy_path, policy.as_bytes()).map_err(|error| error.to_string())?;
        let wrapper_rule = format!(
            "exec-hash {} {}",
            printable(&wrapper).map_err(|error| error.to_string())?,
            wrapper_sha256
        );
        let wrapper_rule_count = policy
            .lines()
            .filter(|line| *line == wrapper_rule.as_str())
            .count();
        if wrapper_rule_count != 1 {
            return Err(format!(
                "positive policy must contain one exact linker-wrapper exec rule; found {wrapper_rule_count}"
            ));
        }
        verify_host_link_probe_system_input_policy(&policy, &system_link_inputs)?;
        write_diagnostic_json(
            &artifacts.join("commands.json"),
            &json!({
                "query":{"argv":query_command,"purpose":"GCC selection under the same -B and -fuse-ld=lld options"},
                "explicit_rust_host_library_sequence":rust_host_library_sequence,
                "positive_link":{"argv":positive_command,"purpose":"C-source link through the pinned GCC linker wrapper with the explicit Rust host-library sequence; this is not a Rust build"},
                "counter_link":{"argv":counter_command,"purpose":"same C link route with only the wrapper exec-hash rule omitted"},
                "system_link_input_controls":{"argv":system_link_command,"purpose":"same C link route with one exact GCC-resolved system link input read-file rule omitted per control"},
            }),
        )?;

        let query_case = run_raw_adapter_case(
            "pinned-gcc-resolves-the-exact-rust-ld-lld-wrapper",
            &artifacts.join("query-case"),
            &adapter,
            &policy_path,
            &spec,
            &query_command,
        )?;
        let query_report = diagnostic_json_file(Path::new(
            query_case["report_path"].as_str().unwrap_or_default(),
        ));
        let query_stdout = read_regular_bounded(
            Path::new(query_case["stdout_path"].as_str().unwrap_or_default()),
            1024 * 1024,
        )
        .map_err(|error| format!("read GCC linker-selection output: {error}"))?;
        let query_text = std::str::from_utf8(&query_stdout)
            .map_err(|error| format!("GCC linker-selection output is not UTF-8: {error}"))?
            .trim();
        let query_path = PathBuf::from(query_text);
        let query_canonical = fs::canonicalize(&query_path)
            .map_err(|error| format!("resolve GCC-selected ld.lld {query_text:?}: {error}"))?;
        let selection_gate = query_path.is_absolute()
            && query_canonical == wrapper
            && query_case["outer_exit_code"].as_i64() == Some(0)
            && query_case["outer_signal"].is_null()
            && query_case["capture_error"].is_null()
            && successful_linux_adapter_report(&query_report, 0);
        write_diagnostic_json(
            &artifacts.join("linker-selection.json"),
            &json!({
                "gate_passed":selection_gate,
                "query_argv":query_command,
                "stdout_path":query_case["stdout_path"],
                "stdout_sha256":sha256_bytes(&query_stdout),
                "selected_program_stdout":query_text,
                "resolved_path":query_canonical,
                "expected_wrapper_path":wrapper,
                "wrapper_sha256":wrapper_sha256,
                "adapter_case":query_case,
                "claim":"GCC's own -print-prog-name query, under the exact route options, resolves ld.lld to the pinned component wrapper.",
            }),
        )?;
        if !selection_gate {
            return Err(
                "GCC did not select the exact pinned ld.lld wrapper under the adapter".to_owned(),
            );
        }

        let positive_case = run_raw_adapter_case(
            "pinned-gcc-links-c-program-through-rust-ld-lld",
            &artifacts.join("positive-link-case"),
            &adapter,
            &policy_path,
            &spec,
            &positive_command,
        )?;
        let positive_report = diagnostic_json_file(Path::new(
            positive_case["report_path"].as_str().unwrap_or_default(),
        ));
        let positive_metadata = fs::symlink_metadata(&positive_output)
            .map_err(|error| format!("inspect positive host-link output: {error}"))?;
        let positive_bytes = read_regular_bounded(&positive_output, 64 * 1024 * 1024)
            .map_err(|error| format!("read positive host-link output: {error}"))?;
        let positive_elf = positive_metadata.file_type().is_file()
            && positive_metadata.permissions().mode() & 0o111 != 0
            && positive_bytes.starts_with(b"\x7fELF");
        let positive_link_gate = positive_case["outer_exit_code"].as_i64() == Some(0)
            && positive_case["outer_signal"].is_null()
            && positive_case["capture_error"].is_null()
            && successful_linux_adapter_report(&positive_report, 0)
            && positive_elf;
        write_diagnostic_json(
            &artifacts.join("positive-link-gate.json"),
            &json!({
                "gate_passed":positive_link_gate,
                "adapter_case":positive_case,
                "artifact_path":positive_output,
                "artifact_bytes":positive_bytes.len(),
                "artifact_sha256":sha256_bytes(&positive_bytes),
                "regular_executable_elf":positive_elf,
            }),
        )?;
        if !positive_link_gate {
            return Err(
                "positive GCC link did not produce a valid executable ELF under the adapter"
                    .to_owned(),
            );
        }

        let mut run_fixture = Fixture::at(artifacts.join("run-fixture"), true);
        run_fixture.value["phase"] = json!("verify");
        run_fixture.value["command"] = json!([positive_output.clone()]);
        run_fixture.value["expected_exit"] = json!(0);
        run_fixture.value["cwd"] = json!(build_work);
        run_fixture.value["home"] = json!(home);
        run_fixture.value["tmp"] = json!(tmp);
        run_fixture.value["read_trees"] = json!([]);
        run_fixture.value["write_trees"] = json!([]);
        run_fixture.value["read_files"] = json!([]);
        run_fixture.value["executables"] = json!([positive_output.clone()]);
        run_fixture.value["libraries"] = json!([]);
        run_fixture.value["read_directories"] = json!([]);
        run_fixture.value["deny_exec"] = json!([]);
        run_fixture.value["deny_library"] = json!([]);
        run_fixture.value["component_record"] = Value::Null;
        run_fixture.value["derived"] = Value::Null;
        run_fixture.value["bindings"] = json!([{
            "path":source,
            "sha256":sha256_bytes(source_bytes),
        }]);
        let run_spec_raw = serde_json::to_vec_pretty(&run_fixture.value)
            .map_err(|error| format!("encode exact executable observation spec: {error}"))?;
        write_new(&artifacts.join("run-spec.json"), &run_spec_raw)
            .map_err(|error| error.to_string())?;
        let run_spec = run_fixture.parse().map_err(|error| error.to_string())?;
        let run_executables = run_spec.executables.clone();
        let run_runtime = consumer_runtime::discover(
            run_executables,
            run_spec.libraries.clone(),
            false,
            false,
            &build_work,
        )
        .map_err(|error| format!("discover generated executable runtime: {error}"))?;
        write_diagnostic_json(
            &artifacts.join("run-runtime-discovery.json"),
            &run_runtime.evidence,
        )?;
        let run_closure = json!({
            "schema":"ami-rust-linux-pinned-host-link-execution-closure-v1",
            "spec_sha256":sha256_bytes(&run_spec_raw),
            "bindings":run_spec.bindings,
            "runtime":run_runtime.evidence,
            "generated_executable_sha256":sha256_file(&positive_output).map_err(|error| error.to_string())?,
            "scope":"Exact generated C executable and its discovered Linux runtime for the marker run.",
        });
        let run_closure_raw = serde_json::to_vec_pretty(&run_closure)
            .map_err(|error| format!("encode exact executable closure: {error}"))?;
        let run_closure_sha256 = sha256_bytes(&run_closure_raw);
        write_new(
            &artifacts.join("run-runtime-closure.json"),
            &run_closure_raw,
        )
        .map_err(|error| error.to_string())?;
        let run_policy = render_policy(
            &run_spec,
            &run_runtime,
            BTreeSet::new(),
            &run_closure_sha256,
        )
        .map_err(|error| format!("render exact executable run policy: {error}"))?;
        let run_policy_path = artifacts.join("run-policy.txt");
        write_new(&run_policy_path, run_policy.as_bytes()).map_err(|error| error.to_string())?;
        let run_command = run_spec.command.clone();
        write_diagnostic_json(
            &artifacts.join("run-command.json"),
            &json!({"argv":run_command,"purpose":"run the exact generated executable under its derived policy"}),
        )?;
        let run_case = run_raw_adapter_case(
            "run-the-exact-generated-host-link-executable",
            &artifacts.join("positive-run-case"),
            &adapter,
            &run_policy_path,
            &run_spec,
            &run_command,
        )?;
        let run_report = diagnostic_json_file(Path::new(
            run_case["report_path"].as_str().unwrap_or_default(),
        ));
        let run_stdout = read_regular_bounded(
            Path::new(run_case["stdout_path"].as_str().unwrap_or_default()),
            1024 * 1024,
        )
        .map_err(|error| format!("read generated executable marker: {error}"))?;
        let run_gate = run_case["outer_exit_code"].as_i64() == Some(0)
            && run_case["outer_signal"].is_null()
            && run_case["capture_error"].is_null()
            && successful_linux_adapter_report(&run_report, 0)
            && run_stdout == b"ami-rust-host-link-ok\n";
        write_diagnostic_json(
            &artifacts.join("positive-run-gate.json"),
            &json!({"gate_passed":run_gate,"adapter_case":run_case,"marker":"ami-rust-host-link-ok","stdout_sha256":sha256_bytes(&run_stdout)}),
        )?;
        if !run_gate {
            return Err(
                "generated host-link executable did not run and emit its marker under the adapter"
                    .to_owned(),
            );
        }

        // Each policy load requires an initially empty derived-execution parent.
        // Retain the exact positive ELF as evidence, then remove only that known
        // output before loading the one-rule counterpolicy against the same root.
        let retained_positive = artifacts.join("positive-linked.elf");
        write_new(&retained_positive, &positive_bytes).map_err(|error| error.to_string())?;
        let positive_cleanup = host_link_probe_cleanup(&derived, &[&positive_output])?;
        write_diagnostic_json(
            &artifacts.join("positive-output-cleanup.json"),
            &positive_cleanup,
        )?;
        if positive_cleanup["empty_after_cleanup"].as_bool() != Some(true) {
            return Err(
                "positive linker output was not removed before counterpolicy load".to_owned(),
            );
        }

        let counter_policy_path = artifacts.join("counter-policy-wrapper-exec-omitted.txt");
        let counter_policy =
            copy_policy_omitting_one_exec_hash(&policy_path, &counter_policy_path, &wrapper)?;
        if counter_policy["all_other_policy_bytes_identical"].as_bool() != Some(true) {
            return Err(
                "counterpolicy changed bytes beyond the exact wrapper exec-hash rule".to_owned(),
            );
        }
        let counter_case = run_raw_adapter_case(
            "same-gcc-link-with-only-pinned-wrapper-exec-rule-omitted",
            &artifacts.join("counter-link-case"),
            &adapter,
            &counter_policy_path,
            &spec,
            &counter_command,
        )?;
        let counter_report = diagnostic_json_file(Path::new(
            counter_case["report_path"].as_str().unwrap_or_default(),
        ));
        let counter_stderr = read_raw_stderr(&counter_case)?;
        let counter_exit = counter_report["child_exit_code"].as_i64();
        let counter_has_no_elf = !host_link_probe_has_elf(&counter_output)?;
        let counter_gate = counter_exit.is_some_and(|code| code != 0)
            && counter_case["outer_exit_code"].as_i64() == counter_exit
            && counter_case["outer_signal"].is_null()
            && counter_case["capture_error"].is_null()
            && counter_report["child_signal"].is_null()
            && counter_report["launch_error"].is_null()
            && successful_linux_adapter_report(&counter_report, counter_exit.unwrap_or_default())
            && counter_stderr.contains("collect2: fatal error: execvp: Permission denied")
            && counter_stderr.contains("Permission denied")
            && counter_has_no_elf
            && counter_policy["all_other_policy_bytes_identical"] == true;
        write_diagnostic_json(
            &artifacts.join("counter-gate.json"),
            &json!({
                "gate_passed":counter_gate,
                "adapter_case":counter_case,
                "expected_denial_path":wrapper,
                "stderr":counter_stderr,
                "collect2_execvp_permission_denied":counter_stderr.contains("collect2: fatal error: execvp: Permission denied"),
                "permission_denied_observed":counter_stderr.contains("Permission denied"),
                "no_elf_output":counter_has_no_elf,
                "counter_policy":counter_policy,
                "claim":"With only the exact pinned linker-wrapper exec rule omitted, the identical GCC link route fails at that wrapper and produces no ELF output.",
            }),
        )?;
        if !counter_gate {
            return Err("wrapper-execution counter did not produce the expected adapter-backed EACCES failure".to_owned());
        }

        let wrapper_counter_cleanup = host_link_probe_cleanup(&derived, &[&counter_output])?;
        write_diagnostic_json(
            &artifacts.join("wrapper-counter-output-cleanup.json"),
            &wrapper_counter_cleanup,
        )?;
        if wrapper_counter_cleanup["empty_after_cleanup"].as_bool() != Some(true) {
            return Err(
                "wrapper counter left an entry before system-library policy loads".to_owned(),
            );
        }

        let mut system_link_input_controls = Vec::new();
        for input in &system_link_inputs {
            let empty_before = host_link_probe_cleanup(&derived, &[])?;
            if empty_before["empty_after_cleanup"].as_bool() != Some(true) {
                return Err(
                    "derived linker output root is not empty before a system-library control"
                        .to_owned(),
                );
            }
            let name = input["name"]
                .as_str()
                .ok_or_else(|| "system-link input omitted its name".to_owned())?;
            let input_path = PathBuf::from(
                input["canonical_path"]
                    .as_str()
                    .ok_or_else(|| "system-link input omitted its canonical path".to_owned())?,
            );
            let counter_policy_path = artifacts.join(format!("counter-policy-{name}-omitted.txt"));
            let policy_omission = copy_policy_omitting_one_read_file(
                &policy_path,
                &counter_policy_path,
                &input_path,
            )?;
            let case_dir = artifacts.join(format!("system-link-{name}-counter-case"));
            let case = run_raw_adapter_case(
                &format!("same-gcc-link-with-only-{name}-read-rule-omitted"),
                &case_dir,
                &adapter,
                &counter_policy_path,
                &spec,
                &system_link_command,
            )?;
            let report =
                diagnostic_json_file(Path::new(case["report_path"].as_str().unwrap_or_default()));
            let stderr = read_raw_stderr(&case)?;
            let child_exit = report["child_exit_code"].as_i64();
            let denial_diagnostic =
                host_link_probe_specific_link_input_denial(&stderr, &input_path);
            let specific_eacces = denial_diagnostic.is_some();
            let adapter_evidence_valid =
                child_exit.is_some_and(|code| successful_linux_adapter_report(&report, code));
            let no_elf_output = !host_link_probe_has_elf(&system_link_output)?;
            let cleanup = host_link_probe_cleanup(&derived, &[&system_link_output])?;
            let gate = child_exit.is_some_and(|code| code != 0)
                && case["outer_exit_code"].as_i64() == child_exit
                && case["outer_signal"].is_null()
                && case["capture_error"].is_null()
                && report["child_signal"].is_null()
                && report["launch_error"].is_null()
                && adapter_evidence_valid
                && specific_eacces
                && no_elf_output
                && cleanup["empty_after_cleanup"].as_bool() == Some(true)
                && policy_omission["all_other_policy_bytes_identical"] == true;
            let record = json!({
                "name":name,
                "expected_denial_path":input_path,
                "expected_denial_sha256":input["sha256"],
                "expected_denial_bytes":input["bytes"],
                "policy_omission":policy_omission,
                "adapter_case":case,
                "child_report":report,
                "stderr":stderr,
                "specific_denial_diagnostic":denial_diagnostic,
                "specific_system_link_input_path_and_eacces_observed":specific_eacces,
                "adapter_evidence_valid":adapter_evidence_valid,
                "no_elf_output":no_elf_output,
                "cleanup":cleanup,
                "gate_passed":gate,
                "claim":"The same C-source host link fails on this exact GCC-resolved system link input after only its read-file rule is removed; adapter evidence is valid, the diagnostic names this path with Permission denied, and no ELF remains.",
            });
            write_diagnostic_json(
                &artifacts.join(format!("system-link-{name}-counter.json")),
                &record,
            )?;
            system_link_input_controls.push(record);
            if !gate {
                return Err(format!(
                    "system-link input control for {name} did not produce the expected adapter-backed EACCES failure"
                ));
            }
            if cleanup["empty_after_cleanup"].as_bool() != Some(true) {
                return Err(format!(
                    "system-link input control for {name} left an entry in the derived output root"
                ));
            }
        }

        verify_host_link_probe_system_input_hashes(&system_link_inputs)?;

        verify_bindings(&spec.bindings).map_err(|error| error.to_string())?;
        verify_bindings(&run_spec.bindings).map_err(|error| error.to_string())?;
        write_diagnostic_json(
            &artifacts.join("source-bindings.json"),
            &json!({"unchanged":true,"positive_spec_bindings":spec.bindings,"run_spec_bindings":run_spec.bindings}),
        )?;
        Ok(json!({
            "schema":"ami-rust-linux-pinned-host-linker-probe-v1",
            "host":"linux-x86_64",
            "scope":"Cause-specific proof that GCC's exact -B<rust-component>/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld -fuse-ld=lld route selects, executes, and links through the pinned ld.lld wrapper under the Linux enforcement adapter. The wrapper-only counter proves the missing exec-hash admission causes Permission denied. This is not a Rust host build, SDK build, or RC1 acceptance.",
            "positive_gate_passed":true,
            "counter_gate_passed":true,
            "system_link_input_gate_passed":true,
            "source_bindings_unchanged":true,
            "cleanup_gate_passed":false,
            "component_root":component,
            "adapter":adapter,
            "wrapper":{"declared_path":wrapper_declared,"canonical_path":wrapper,"sha256":wrapper_sha256,"bytes":wrapper_metadata.len()},
            "rust_lld":{"canonical_path":rust_lld,"sha256":rust_lld_sha256},
            "linker_selection":artifacts.join("linker-selection.json"),
            "runtime_discovery":artifacts.join("runtime-discovery.json"),
            "positive_policy":policy_path,
            "counter_policy":counter_policy_path,
            "system_link_inputs":artifacts.join("system-link-inputs.json"),
            "system_link_input_controls":system_link_input_controls,
            "positive_link_gate":artifacts.join("positive-link-gate.json"),
            "retained_positive_elf":retained_positive,
            "positive_output_cleanup":positive_cleanup,
            "positive_run_gate":artifacts.join("positive-run-gate.json"),
            "counter_gate":artifacts.join("counter-gate.json"),
            "claim":"The pinned Rust component's GCC linker wrapper passed the exact host link route and marker execution; removing only its exec rule reproduced Permission denied with valid adapter evidence.",
        }))
    })();

    let cleanup = host_link_probe_cleanup(
        &derived,
        &[
            positive_output.as_path(),
            counter_output.as_path(),
            system_link_output.as_path(),
        ],
    );
    match &cleanup {
        Ok(value) => write_diagnostic_json(&artifacts.join("cleanup.json"), value)?,
        Err(error) => write_diagnostic_json(
            &artifacts.join("cleanup.json"),
            &json!({"empty_after_cleanup":false,"error":error}),
        )?,
    }
    match (attempt, cleanup) {
        (Ok(mut value), Ok(cleanup)) => {
            let clean = cleanup["empty_after_cleanup"].as_bool() == Some(true);
            value["cleanup_gate_passed"] = json!(clean);
            value["cleanup"] = cleanup;
            value["cleanup_evidence"] = json!(artifacts.join("cleanup.json"));
            if !clean {
                return Err(
                    "linker output cleanup left unexpected entries in its private derived root"
                        .to_owned(),
                );
            }
            Ok(value)
        }
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(format!(
            "host-link probe passed but output cleanup failed: {cleanup_error}"
        )),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; host-link output cleanup also failed: {cleanup_error}"
        )),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn host_link_probe_cleanup(
    derived: &Path,
    outputs: &[&Path],
) -> std::result::Result<Value, String> {
    let mut removed = Vec::new();
    for path in outputs {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let record = json!({
                    "path":path,
                    "bytes":metadata.len(),
                    "sha256":sha256_file(path).map_err(|error| error.to_string())?,
                });
                fs::remove_file(path).map_err(|error| {
                    format!("remove probe-owned output {}: {error}", path.display())
                })?;
                removed.push(record);
            }
            Ok(_) => {
                return Err(format!(
                    "probe-owned output is not a regular file: {}",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                removed.push(json!({"path":path,"absent":true}));
            }
            Err(error) => {
                return Err(format!("inspect probe output {}: {error}", path.display()));
            }
        }
    }
    let remaining = fs::read_dir(derived)
        .map_err(|error| format!("inspect derived root after cleanup: {error}"))?
        .count();
    Ok(json!({
        "removed_or_absent_outputs":removed,
        "remaining_entries":remaining,
        "empty_after_cleanup":remaining == 0,
    }))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn host_link_probe_gcc_link_inputs(
    runtime: &consumer_runtime::RuntimeInputs,
) -> std::result::Result<Vec<Value>, String> {
    let expected_names = [
        "libutil.a",
        "librt.a",
        "libpthread.a",
        "libdl.a",
        "libmvec.so.1",
    ];
    let rows = runtime.evidence["build_inputs"]
        .as_array()
        .ok_or_else(|| "runtime evidence omitted GCC build-input rows".to_owned())?;
    let mut paths = BTreeSet::new();
    let mut inputs = Vec::with_capacity(expected_names.len());
    for name in expected_names {
        let matches = rows
            .iter()
            .filter(|row| row["kind"] == "gcc_link_input" && row["name"] == name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "runtime evidence must resolve exactly one GCC link input for {name}; found {}",
                matches.len()
            ));
        }
        let row = matches[0];
        let raw_path = row["canonical_path"]
            .as_str()
            .ok_or_else(|| format!("GCC link-input row for {name} omitted canonical_path"))?;
        let path = PathBuf::from(raw_path);
        if !path.is_absolute() || !paths.insert(path.clone()) {
            return Err(format!(
                "GCC link-input path for {name} is nonabsolute or duplicated: {raw_path}"
            ));
        }
        if fs::canonicalize(&path)
            .map_err(|error| format!("resolve GCC link input {raw_path}: {error}"))?
            != path
        {
            return Err(format!(
                "GCC link input for {name} is not recorded by its canonical path"
            ));
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect GCC link input {}: {error}", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "GCC link input for {name} is not a regular non-symlink file: {}",
                path.display()
            ));
        }
        if !runtime.read_files.contains(&path) {
            return Err(format!(
                "runtime discovery did not admit GCC link input for {name}: {}",
                path.display()
            ));
        }
        let sha256 = sha256_file(&path)
            .map_err(|error| format!("hash GCC link input {}: {error}", path.display()))?;
        inputs.push(json!({
            "name":name,
            "canonical_path":path,
            "bytes":metadata.len(),
            "sha256":sha256,
            "runtime_build_input_row":row,
        }));
    }
    if inputs.len() != expected_names.len() {
        return Err("GCC system-link input inventory is incomplete".to_owned());
    }
    Ok(inputs)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn verify_host_link_probe_system_input_policy(
    policy: &str,
    inputs: &[Value],
) -> std::result::Result<(), String> {
    for input in inputs {
        let raw_path = input["canonical_path"]
            .as_str()
            .ok_or_else(|| "system-link input omitted canonical_path".to_owned())?;
        let path = PathBuf::from(raw_path);
        let rule = format!(
            "read-file {}",
            printable(&path).map_err(|error| error.to_string())?
        );
        let count = policy.lines().filter(|line| *line == rule.as_str()).count();
        if count != 1 {
            return Err(format!(
                "positive policy must contain one exact read-file rule for {}; found {count}",
                path.display()
            ));
        }
        let library_rule_prefix = format!(
            "read-library {} ",
            printable(&path).map_err(|error| error.to_string())?
        );
        if policy
            .lines()
            .any(|line| line.starts_with(&library_rule_prefix))
        {
            return Err(format!(
                "system-link input also has an alternate read-library grant: {}",
                path.display()
            ));
        }
        for line in policy.lines().filter(|line| line.starts_with("read-tree ")) {
            let rest = &line["read-tree ".len()..];
            let (_, raw_root) = rest
                .split_once(' ')
                .ok_or_else(|| format!("malformed read-tree rule in rendered policy: {line}"))?;
            let root = PathBuf::from(raw_root);
            if !root.is_absolute() || fs::canonicalize(&root).ok().as_ref() != Some(&root) {
                return Err(format!(
                    "read-tree root in rendered policy is not a canonical absolute path: {}",
                    root.display()
                ));
            }
            if path.starts_with(&root) {
                return Err(format!(
                    "system-link input {} is also granted by read-tree {}",
                    path.display(),
                    root.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn host_link_probe_specific_link_input_denial(stderr: &str, expected: &Path) -> Option<Value> {
    let prefix = "rust-lld: error: cannot open ";
    let candidates = stderr
        .lines()
        .filter(|line| line.starts_with(prefix) && line.contains(": Permission denied"))
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return None;
    }
    let diagnostic = candidates[0];
    let (_, remainder) = diagnostic.split_once("error: cannot open ")?;
    let (raw_path, trailing) = remainder.split_once(": Permission denied")?;
    if !trailing.trim().is_empty() {
        return None;
    }
    let raw_path = raw_path.trim();
    let denied_path = PathBuf::from(raw_path);
    if !denied_path.is_absolute() {
        return None;
    }
    let canonical_path = fs::canonicalize(&denied_path).ok()?;
    if canonical_path != expected {
        return None;
    }
    Some(json!({
        "raw_diagnostic":diagnostic,
        "reported_path":raw_path,
        "canonical_path":canonical_path,
        "expected_canonical_path":expected,
        "errno":13,
        "error":"Permission denied",
    }))
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod host_link_probe_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch_root() -> Scratch {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ami-rust-host-link-denial-parser-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create denial parser scratch root");
        Scratch(root)
    }

    #[test]
    fn rust_lld_denial_parser_canonicalizes_gcc_operand_and_rejects_other_paths_or_errors() {
        let scratch = scratch_root();
        let gcc = scratch.0.join("gcc");
        let library = scratch.0.join("x86_64-linux-gnu");
        let other = scratch.0.join("other");
        fs::create_dir(&gcc).expect("create gcc operand directory");
        fs::create_dir(&library).expect("create canonical library directory");
        fs::create_dir(&other).expect("create second library directory");
        let expected = library.join("libutil.a");
        let other_file = other.join("libutil.a");
        fs::write(&expected, b"fixture input").expect("write expected input fixture");
        fs::write(&other_file, b"different input").expect("write other input fixture");
        let expected = fs::canonicalize(expected).expect("canonicalize expected fixture");
        let noncanonical_operand = gcc.join("../x86_64-linux-gnu/libutil.a");
        assert_ne!(noncanonical_operand, expected);

        let valid = format!(
            "rust-lld: error: cannot open {}: Permission denied\n",
            noncanonical_operand.display()
        );
        let parsed = host_link_probe_specific_link_input_denial(&valid, &expected)
            .expect("accept exact denial after canonicalizing GCC's operand");
        assert_eq!(parsed["canonical_path"], expected.display().to_string());
        assert_eq!(parsed["errno"], 13);

        let wrong_file = format!(
            "rust-lld: error: cannot open {}: Permission denied\n",
            other_file.display()
        );
        assert!(host_link_probe_specific_link_input_denial(&wrong_file, &expected).is_none());

        let wrong_error = format!(
            "rust-lld: error: cannot open {}: No such file or directory\n",
            noncanonical_operand.display()
        );
        assert!(host_link_probe_specific_link_input_denial(&wrong_error, &expected).is_none());

        let wrong_program = format!(
            "collect2: error: cannot open {}: Permission denied\n",
            noncanonical_operand.display()
        );
        assert!(host_link_probe_specific_link_input_denial(&wrong_program, &expected).is_none());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn copy_policy_omitting_one_read_file(
    policy: &Path,
    counter_policy: &Path,
    file: &Path,
) -> std::result::Result<Value, String> {
    let original = read_regular_bounded(policy, 1024 * 1024)
        .map_err(|error| format!("read positive policy: {error}"))?;
    let original_text = std::str::from_utf8(&original)
        .map_err(|error| format!("positive policy is not UTF-8: {error}"))?;
    let rule = format!(
        "read-file {}",
        printable(file).map_err(|error| error.to_string())?
    );
    let rule_count = original_text
        .lines()
        .filter(|line| *line == rule.as_str())
        .count();
    if rule_count != 1 {
        return Err(format!(
            "positive policy must contain exactly one selected read-file rule for {}; found {rule_count}",
            file.display()
        ));
    }
    let removed_line_bytes = original_text
        .split_inclusive('\n')
        .find(|line| line.strip_suffix('\n').unwrap_or(line) == rule.as_str())
        .ok_or_else(|| "selected system-link read-file rule is absent".to_owned())?
        .len();
    let counter_text = original_text
        .split_inclusive('\n')
        .filter(|line| line.strip_suffix('\n').unwrap_or(line) != rule.as_str())
        .collect::<String>();
    if counter_text.len() + removed_line_bytes != original.len()
        || counter_text.lines().any(|line| line == rule.as_str())
    {
        return Err("system-link counterpolicy differs beyond the exact omitted rule".to_owned());
    }
    write_new(counter_policy, counter_text.as_bytes()).map_err(|error| error.to_string())?;
    Ok(json!({
        "original_policy":policy,
        "original_policy_sha256":sha256_file(policy).map_err(|error| error.to_string())?,
        "counter_policy":counter_policy,
        "counter_policy_sha256":sha256_file(counter_policy).map_err(|error| error.to_string())?,
        "omitted_rule":rule,
        "omitted_rule_count":rule_count,
        "bytes_removed":removed_line_bytes,
        "all_other_policy_bytes_identical":true,
    }))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn verify_host_link_probe_system_input_hashes(inputs: &[Value]) -> std::result::Result<(), String> {
    for input in inputs {
        let path = PathBuf::from(
            input["canonical_path"]
                .as_str()
                .ok_or_else(|| "system-link input omitted canonical_path".to_owned())?,
        );
        let expected_bytes = input["bytes"]
            .as_u64()
            .ok_or_else(|| "system-link input omitted byte length".to_owned())?;
        let expected_sha256 = input["sha256"]
            .as_str()
            .ok_or_else(|| "system-link input omitted SHA-256".to_owned())?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("reinspect system-link input {}: {error}", path.display()))?;
        if !metadata.file_type().is_file()
            || metadata.len() != expected_bytes
            || sha256_file(&path).map_err(|error| error.to_string())? != expected_sha256
        {
            return Err(format!(
                "system-link input changed during controls: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn host_link_probe_has_elf(path: &Path) -> std::result::Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            read_regular_bounded(path, 64 * 1024 * 1024)
                .map(|bytes| bytes.starts_with(b"\x7fELF"))
                .map_err(|error| format!("inspect counter output {}: {error}", path.display()))
        }
        Ok(_) => Err(format!(
            "counter output is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "inspect counter output {}: {error}",
            path.display()
        )),
    }
}

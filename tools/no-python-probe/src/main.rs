// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const TRUE: &str = "/usr/bin/true";
const OTOOL: &str = "/usr/bin/otool";
const CLANG: &str = "/usr/bin/clang";
const SYSTEM_PROFILE: &str = "/System/Library/Sandbox/Profiles/system.sb";
const DYLD_PROFILE: &str = "/System/Library/Sandbox/Profiles/dyld-support.sb";
const REFUSED_EXIT: i32 = 77;
const OBSERVER_CLOCK_UNCERTAINTY_MICROS: u128 = 10_000;
const DIRECT_MARKER: &str = "RC0_NO_PYTHON_PROBE_DIRECT_EXECUTION_MARKER";
const SHEBANG_MARKER: &str = "RC0_NO_PYTHON_PROBE_SHEBANG_EXECUTION_MARKER";
const EMBEDDED_MARKER: &str = "RC0_NO_PYTHON_PROBE_EMBEDDED_EXECUTION_MARKER";

#[derive(Clone)]
struct Component {
    path: String,
    sha256: String,
    role: String,
    process_exec_allowed: bool,
}

struct CaseResult {
    name: String,
    started_unix_micros: u128,
    finished_unix_micros: u128,
    status: String,
    exit_code: Option<i32>,
    passed: bool,
    stdout: String,
    stderr: String,
    command: Vec<String>,
}

struct DependencyEdge {
    source: String,
    requested_path: String,
    resolved_path: Option<String>,
    resolution: String,
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = if args.first().map(String::as_str) == Some("--control") {
        run_control(&args[1..])
    } else {
        run_probe(&args)
    };

    if let Err(error) = result {
        eprintln!("no-python-probe: {error}");
        process::exit(2);
    }
}

fn run_probe(args: &[String]) -> Result<(), String> {
    if env::consts::OS != "macos" {
        return Err(format!(
            "macOS implementation only; host is {}-{}",
            env::consts::OS,
            env::consts::ARCH
        ));
    }

    let python_arg = option_value(args, "--python").ok_or_else(|| {
        "usage: no-python-probe --python /absolute/path/to/python3 [--report path]".to_owned()
    })?;
    let python = canonical_absolute(python_arg)?;
    let report_path = option_value(args, "--report")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir().join("artifacts/report.json"));
    let artifact_dir = report_path
        .parent()
        .ok_or_else(|| "report path must have a parent directory".to_owned())?;
    fs::create_dir_all(artifact_dir)
        .map_err(|error| format!("create artifact directory: {error}"))?;
    let mut observer = if args.iter().any(|arg| arg == "--observe") {
        let stdout = fs::File::create(artifact_dir.join("exec-observer.raw.log"))
            .map_err(|e| e.to_string())?;
        let stderr = fs::File::create(artifact_dir.join("exec-observer.stderr.log"))
            .map_err(|e| e.to_string())?;
        let child = Command::new("/usr/bin/sudo")
            .args([
                "-n",
                "/usr/bin/env",
                "TZ=UTC",
                "/usr/bin/fs_usage",
                "-w",
                "-f",
                "exec",
                "-t",
                "30",
            ])
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| e.to_string())?;
        // This bounded startup delay is never evidence of readiness. The
        // unconfined controls must subsequently appear in the kernel trace.
        std::thread::sleep(std::time::Duration::from_millis(500));
        Some(child)
    } else {
        None
    };

    let executable =
        env::current_exe().map_err(|error| format!("resolve running probe executable: {error}"))?;
    let executable = fs::canonicalize(executable)
        .map_err(|error| format!("canonicalize running probe executable: {error}"))?;
    let true_path = PathBuf::from(TRUE);
    let sandbox_path = PathBuf::from(SANDBOX_EXEC);
    let otool_path = PathBuf::from(OTOOL);
    let clang_path = PathBuf::from(CLANG);

    let shebang_path = artifact_dir.join("python-shebang-control");
    let shebang = format!("#!{} -I\nprint('{}')\n", python.display(), SHEBANG_MARKER);
    fs::write(&shebang_path, shebang.as_bytes())
        .map_err(|error| format!("write shebang countercontrol: {error}"))?;
    set_executable(&shebang_path)?;

    let embedded_source = artifact_dir.join("embedded-python-control.c");
    let embedded_binary = artifact_dir.join("embedded-python-control");
    fs::write(
        &embedded_source,
        format!(
            "#include <Python.h>\nint main(void) {{ Py_Initialize(); PyRun_SimpleString(\"print('{}')\"); return Py_FinalizeEx(); }}\n",
            EMBEDDED_MARKER
        )
        .as_bytes(),
    )
    .map_err(|error| format!("write embedded-runtime countercontrol source: {error}"))?;
    let embedded_build = build_embedded_control(&python, &embedded_source, &embedded_binary);

    let profile_path = artifact_dir.join("macos-exec-allowlist.sb");
    let profile = sandbox_profile(&executable, &shebang_path, &embedded_binary);
    fs::write(&profile_path, profile.as_bytes())
        .map_err(|error| format!("write sandbox profile: {error}"))?;

    let mut components = BTreeMap::<String, Component>::new();
    if observer.is_some() {
        for path in ["/usr/bin/fs_usage", "/usr/bin/sudo", "/usr/bin/env"] {
            add_component(
                &mut components,
                Path::new(path),
                "OS kernel-observer launch chain",
                false,
            )?;
        }
    }
    add_component(&mut components, &executable, "probe executable", true)?;
    add_component(&mut components, &true_path, "positive native command", true)?;
    add_component(
        &mut components,
        &sandbox_path,
        "macOS sandbox launcher",
        false,
    )?;
    add_component(
        &mut components,
        &otool_path,
        "Mach-O dependency inspector",
        false,
    )?;
    add_component(
        &mut components,
        &clang_path,
        "native C compiler for owned countercontrol",
        false,
    )?;
    add_component(
        &mut components,
        &python,
        "declared positive/detector-control interpreter; denied in sandbox cases",
        false,
    )?;
    add_component(
        &mut components,
        &shebang_path,
        "declared shebang countercontrol; interpreter denied",
        true,
    )?;
    add_component(
        &mut components,
        &profile_path,
        "generated sandbox policy",
        false,
    )?;
    add_component(
        &mut components,
        &PathBuf::from(SYSTEM_PROFILE),
        "macOS imported system sandbox rules",
        false,
    )?;
    add_component(
        &mut components,
        &PathBuf::from(DYLD_PROFILE),
        "macOS imported dyld sandbox rules",
        false,
    )?;
    if embedded_build.is_ok() {
        add_component(
            &mut components,
            &embedded_source,
            "owned embedded-runtime countercontrol source",
            false,
        )?;
        add_component(
            &mut components,
            &embedded_binary,
            "owned embedded-runtime countercontrol; absent from exec allowlist",
            false,
        )?;
    }
    let mut roots = vec![
        (executable.as_path(), "probe executable"),
        (true_path.as_path(), "positive native command"),
        (sandbox_path.as_path(), "macOS sandbox launcher"),
        (otool_path.as_path(), "Mach-O dependency inspector"),
        (clang_path.as_path(), "native C compiler"),
        (python.as_path(), "countercontrol interpreter"),
    ];
    if embedded_build.is_ok() {
        roots.push((embedded_binary.as_path(), "embedded countercontrol"));
    }
    let dependency_edges = collect_dependency_closure(&mut components, &roots)?;

    // Separate execution permission from loader permission: allow the embedding
    // fixture to execute, but explicitly refuse its resolved libpython mapping.
    // This does not try to infer interpreter semantics from an opaque binary.
    let embedded_dependency = dependency_edges.iter().find(|edge| {
        edge.source == embedded_binary.display().to_string()
            && edge
                .requested_path
                .to_ascii_lowercase()
                .contains("libpython")
    });
    let embedded_loader_profile = artifact_dir.join("macos-embedded-loader.sb");
    if let Some(library) = embedded_dependency.and_then(|edge| edge.resolved_path.as_ref()) {
        let profile = format!(
            "{}\n(allow process-exec (literal \"{}\"))\n(deny file-read-data file-map-executable (literal \"{}\"))\n",
            sandbox_profile(&executable, &shebang_path, &embedded_binary),
            scheme_escape(&embedded_binary.display().to_string()),
            scheme_escape(library)
        );
        fs::write(&embedded_loader_profile, profile).map_err(|error| error.to_string())?;
        add_component(
            &mut components,
            &embedded_loader_profile,
            "owned dynamic-loader refusal policy",
            false,
        )?;
    }

    let before_hashes = component_hashes(&components)?;
    let mut cases = Vec::new();

    // These unsandboxed, owned positive controls show each negative control
    // reaches the intended interpreter path when enforcement is absent.
    verify_hashes(
        &components,
        &before_hashes,
        "before direct positive control",
    )?;
    cases.push(run_command_case(
        "positive_control_direct_absolute_python",
        &python,
        &[
            "-I",
            "-S",
            "-c",
            "import sys; print('RC0_NO_PYTHON_PROBE_DIRECT_EXECUTION_MARKER'); print('PYTHON_VERSION=' + sys.version.split()[0])",
        ],
        |output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains(DIRECT_MARKER)
                && String::from_utf8_lossy(&output.stdout).contains("PYTHON_VERSION=3.12.15")
        },
    ));

    verify_hashes(
        &components,
        &before_hashes,
        "before descendant positive control",
    )?;
    cases.push(run_native_control_case(
        "positive_control_descendant_absolute_python",
        &executable,
        &[
            "descendant",
            "--python",
            python.to_str().unwrap_or_default(),
        ],
        |output| {
            output.status.code() == Some(92)
                && String::from_utf8_lossy(&output.stdout).contains("DESCENDANT_ESCAPE")
                && String::from_utf8_lossy(&output.stdout).contains(DIRECT_MARKER)
        },
    ));

    verify_hashes(
        &components,
        &before_hashes,
        "before shebang positive control",
    )?;
    cases.push(run_command_case(
        "positive_control_absolute_python_shebang",
        &shebang_path,
        &[],
        |output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains(SHEBANG_MARKER)
        },
    ));

    if embedded_build.is_ok() {
        verify_hashes(
            &components,
            &before_hashes,
            "before embedded-runtime positive control",
        )?;
        cases.push(run_command_case(
            "positive_control_embedded_python_binary",
            &embedded_binary,
            &[],
            |output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains(EMBEDDED_MARKER)
            },
        ));
    } else {
        cases.push(CaseResult {
            name: "positive_control_embedded_python_binary".to_owned(),
            started_unix_micros: 0,
            finished_unix_micros: 0,
            status: "not-run".to_owned(),
            exit_code: None,
            passed: false,
            stdout: String::new(),
            stderr: "embedded fixture was not built".to_owned(),
            command: vec![embedded_binary.display().to_string()],
        });
    }

    verify_hashes(
        &components,
        &before_hashes,
        "before positive native command",
    )?;
    cases.push(run_case(
        "positive_native_true",
        &profile_path,
        &true_path,
        &[],
        |output| output.status.success(),
    ));

    verify_hashes(
        &components,
        &before_hashes,
        "before direct absolute-path control",
    )?;
    cases.push(run_control_case(
        "direct_absolute_python",
        &profile_path,
        &executable,
        &["direct", "--python", python.to_str().unwrap_or_default()],
        |output| {
            output.status.code() == Some(REFUSED_EXIT)
                && String::from_utf8_lossy(&output.stdout).contains("REFUSED_EXEC path=")
                && !String::from_utf8_lossy(&output.stdout).contains(DIRECT_MARKER)
        },
    ));

    verify_hashes(&components, &before_hashes, "before descendant control")?;
    cases.push(run_control_case(
        "transitive_descendant_absolute_python",
        &profile_path,
        &executable,
        &[
            "descendant",
            "--python",
            python.to_str().unwrap_or_default(),
        ],
        |output| {
            output.status.code() == Some(78)
                && String::from_utf8_lossy(&output.stdout).contains("DESCENDANT_REFUSED")
                && String::from_utf8_lossy(&output.stdout).contains("REFUSED_EXEC path=")
                && !String::from_utf8_lossy(&output.stdout).contains(DIRECT_MARKER)
        },
    ));

    verify_hashes(&components, &before_hashes, "before shebang control")?;
    cases.push(run_control_case(
        "absolute_python_shebang",
        &profile_path,
        &executable,
        &[
            "shebang",
            "--script",
            shebang_path.to_str().unwrap_or_default(),
        ],
        |output| {
            output.status.code() == Some(REFUSED_EXIT)
                && String::from_utf8_lossy(&output.stdout).contains("SHEBANG_REFUSED path=")
                && !String::from_utf8_lossy(&output.stdout).contains(SHEBANG_MARKER)
        },
    ));

    let embedded_case = match &embedded_build {
        Ok(()) => {
            verify_hashes(
                &components,
                &before_hashes,
                "before embedded-runtime control",
            )?;
            run_control_case(
                "unlisted_embedded_python_binary",
                &profile_path,
                &executable,
                &[
                    "embedded",
                    "--binary",
                    embedded_binary.to_str().unwrap_or_default(),
                ],
                |output| {
                    output.status.code() == Some(REFUSED_EXIT)
                        && String::from_utf8_lossy(&output.stdout)
                            .contains("EMBEDDED_BINARY_REFUSED path=")
                        && !String::from_utf8_lossy(&output.stdout).contains(EMBEDDED_MARKER)
                },
            )
        }
        Err(error) => CaseResult {
            name: "unlisted_embedded_python_binary".to_owned(),
            started_unix_micros: 0,
            finished_unix_micros: 0,
            status: "not-run".to_owned(),
            exit_code: None,
            passed: false,
            stdout: String::new(),
            stderr: error.to_owned(),
            command: vec![
                CLANG.to_owned(),
                "compile embedded Python control".to_owned(),
            ],
        },
    };
    cases.push(embedded_case);
    if embedded_loader_profile.is_file() {
        verify_hashes(
            &components,
            &before_hashes,
            "before allowlisted embedding loader control",
        )?;
        cases.push(run_case(
            "allowlisted_embedding_library_refused",
            &embedded_loader_profile,
            &embedded_binary,
            &[],
            |output| {
                !output.status.success()
                    && !String::from_utf8_lossy(&output.stdout).contains(EMBEDDED_MARKER)
                    && String::from_utf8_lossy(&output.stderr)
                        .to_ascii_lowercase()
                        .contains("libpython")
            },
        ));
    }
    verify_hashes(&components, &before_hashes, "after all controls")?;
    let mut observed_python_controls = 0;
    let mut observed_case_routes = 0;
    let mut observed_refusals = 0;
    let observer_result = if let Some(child) = observer.as_mut() {
        let status = child.wait().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("independent fs_usage observer failed; retain stderr".into());
        }
        let trace_path = artifact_dir.join("exec-observer.raw.log");
        if fs::metadata(&trace_path).map_err(|e| e.to_string())?.len() > 16 * 1024 * 1024 {
            return Err("kernel execution trace exceeds its bounded proof size".into());
        }
        let trace = fs::read_to_string(trace_path).map_err(|e| e.to_string())?;
        for pair in cases.windows(2) {
            if pair[0].finished_unix_micros != 0
                && pair[1].started_unix_micros
                    < pair[0].finished_unix_micros + 2 * OBSERVER_CLOCK_UNCERTAINTY_MICROS
            {
                return Err("kernel trace correlation windows overlap".into());
            }
        }
        let mut relevant = Vec::new();
        for case in &cases {
            if case.started_unix_micros == 0 {
                continue;
            }
            let rows: Vec<_> = trace
                .lines()
                .filter(|line| {
                    trace_in_window(
                        line,
                        case.started_unix_micros
                            .saturating_sub(OBSERVER_CLOCK_UNCERTAINTY_MICROS),
                        case.finished_unix_micros + OBSERVER_CLOCK_UNCERTAINTY_MICROS,
                    ) && (line.contains(&python.display().to_string())
                        || line.contains(&artifact_dir.display().to_string())
                        || line.contains(&executable.display().to_string())
                        || line.contains("/usr/bin/true"))
                })
                .collect();
            let expected_target = match case.name.as_str() {
                "positive_control_direct_absolute_python"
                | "positive_control_descendant_absolute_python"
                | "direct_absolute_python"
                | "transitive_descendant_absolute_python" => python.as_path(),
                "positive_control_absolute_python_shebang" | "absolute_python_shebang" => {
                    shebang_path.as_path()
                }
                "positive_native_true" => Path::new(TRUE),
                _ => embedded_binary.as_path(),
            };
            let expected_target = expected_target.display().to_string();
            let expected_rows: Vec<_> = rows
                .iter()
                .filter(|line| trace_targets(line, &expected_target))
                .collect();
            let python_rows = rows
                .iter()
                .filter(|line| trace_targets(line, &python.display().to_string()))
                .count();
            if !expected_rows.is_empty() {
                observed_case_routes += 1;
            }
            if case.name.starts_with("positive_control_") && !expected_rows.is_empty() {
                observed_python_controls += 1;
            }
            if matches!(
                case.name.as_str(),
                "direct_absolute_python"
                    | "transitive_descendant_absolute_python"
                    | "absolute_python_shebang"
                    | "unlisted_embedded_python_binary"
            ) && expected_rows
                .iter()
                .any(|line| trace_refuses_target(line, &expected_target))
            {
                observed_refusals += 1;
            }
            relevant.push(format!(
                "{{\"case\":{},\"expected_target\":{},\"kernel_events\":[{}],\"python_path_events\":{}}}",
                json_string(&case.name),
                json_string(&expected_target),
                rows.iter()
                    .map(|line| json_string(line))
                    .collect::<Vec<_>>()
                    .join(","),
                python_rows
            ));
        }
        format!("{{\"mechanism\":\"Apple fs_usage kernel exec/spawn trace, UTC\",\"exit_code\":{},\"positive_interpreter_route_controls_observed\":{},\"all_case_routes_observed\":{},\"kernel_eperm_refusals_observed\":{},\"cases\":[{}],\"clock_uncertainty_micros\":10000,\"minimum_case_separation_millis\":25,\"scope\":\"named owned controls and disjoint measured time windows; not universal interpreter-semantic detection\"}}",
            status.code().unwrap_or(-1), observed_python_controls, observed_case_routes, observed_refusals, relevant.join(","))
    } else {
        "null".to_owned()
    };

    let closure_json = components
        .values()
        .map(component_json)
        .collect::<Vec<_>>()
        .join(",\n    ");
    let dependency_edges_json = dependency_edges
        .iter()
        .map(dependency_edge_json)
        .collect::<Vec<_>>()
        .join(",\n    ");
    let cases_json = cases
        .iter()
        .map(case_json)
        .collect::<Vec<_>>()
        .join(",\n    ");
    let required_cases_passed = cases
        .iter()
        .filter(|case| case.name != "unlisted_embedded_python_binary")
        .all(|case| case.passed);
    let embedded_was_built = cases
        .iter()
        .any(|case| case.name == "unlisted_embedded_python_binary" && case.passed);
    let embedded_fixture_available = cases
        .iter()
        .any(|case| case.name == "unlisted_embedded_python_binary" && case.status != "not-run");
    let embedded_source_path = embedded_binary.display().to_string();
    let embedded_python_dependency = dependency_edges.iter().find(|edge| {
        edge.source == embedded_source_path
            && (edge.requested_path.contains("Python.framework")
                || edge
                    .requested_path
                    .to_ascii_lowercase()
                    .contains("libpython"))
    });
    let embedded_python_dependency_detected = embedded_python_dependency.is_some();
    let sandbox_markers_absent = cases
        .iter()
        .filter(|case| {
            matches!(
                case.name.as_str(),
                "direct_absolute_python"
                    | "transitive_descendant_absolute_python"
                    | "absolute_python_shebang"
                    | "unlisted_embedded_python_binary"
            )
        })
        .all(|case| {
            let output = format!("{}\n{}", case.stdout, case.stderr);
            !output.contains(DIRECT_MARKER)
                && !output.contains(SHEBANG_MARKER)
                && !output.contains(EMBEDDED_MARKER)
        });
    let embedded_positive_control_passed = cases
        .iter()
        .any(|case| case.name == "positive_control_embedded_python_binary" && case.passed);
    let overall = if required_cases_passed
        && (!embedded_fixture_available || embedded_was_built)
        && (!embedded_fixture_available || embedded_python_dependency_detected)
    {
        "PARTIAL"
    } else {
        "FAIL"
    };
    let embedded_build_summary = match &embedded_build {
        Ok(()) if embedded_positive_control_passed => {
            "built; unconfined positive control and sandboxed loader control executed".to_owned()
        }
        Ok(()) => "built; positive control did not pass, no execution claim".to_owned(),
        Err(error) => format!("unavailable: {error}"),
    };
    let report = format!(
        "{{\n  \"schema\": \"ami-rust-no-python-probe-v4\",\n  \"overall\": {},\n  \"host\": {{\"os\": {}, \"arch\": {}}},\n  \"policy\": {{\"mechanism\": \"/usr/bin/sandbox-exec with deny-default process-exec allowlist\", \"allowed_exec_paths\": [{}, {}, {}], \"python_path_is_allowed\": false, \"network_and_file_writes_denied\": true, \"hashes_rechecked_before_each_case_and_after\": true, \"hash_root_is_runtime_observation_not_committed_trust_pin\": true}},\n  \"python_countercontrol\": {{\"path\": {}, \"role\": \"test-only pinned CPython positive and detector control; sandbox cases must refuse it\"}},\n  \"positive_control_execution\": \"owned interpreter/script/embedding controls ran outside the sandbox and emitted their distinct markers; the same markers are required absent from sandbox refusal outputs\",\n  \"embedded_fixture_build\": {},\n  \"embedded_runtime_preflight\": {{\"fixture\": {}, \"python_dependency_detected\": {}, \"matched_dependency\": {}, \"test_policy\": \"exclude from process-exec allowlist; dependency inspection does not automatically construct or enforce the allowlist\", \"fixture_executed_unconfined_control_only\": {}, \"sandbox_refusal_marker_absent\": {}}},\n  \"component_closure_status\": \"recursive Mach-O load-reference inspection; absolute LC_RPATH and @loader_path dependencies are resolved, LC_ID_DYLIB self-names are excluded, and unresolved dyld shared-cache or loader-relative dependencies prevent a complete closure claim\",\n  \"declared_hash_verified_components\": [\n    {}\n  ],\n  \"dependency_edges\": [\n    {}\n  ],\n  \"cases\": [\n    {}\n  ],\n  \"qualification_limits\": [\"The original unlisted-embedding case refuses process execution; the separate allowlisted-embedding case denies its resolved libpython mapping. Neither identifies Python semantics inside an opaque allowed binary.\", \"Static or otherwise opaque embedded runtimes cannot be excluded by exec observation. A reviewed source/build/dependency closure and reproducible component identity are required; arbitrary-language detection is not claimed.\", \"The test harness can read the caller-visible EPERM in these controls; this run does not qualify an independent per-exec audit stream for arbitrary commands.\", \"The OS shared-cache dependency edges recorded below have no ordinary file bytes to hash in this user process; this limits the local hash closure.\", \"This run qualifies the macOS host only. No Linux runner was available in this task.\", \"sandbox-exec is deprecated Apple tooling; the probe records its observed behavior on this host, not a supported long-term Apple sandbox API contract.\", \"Per-run path hashing is evidence and drift detection, not protection from a same-user time-of-check/time-of-use replacement race.\"]\n}}\n",
        json_string(overall),
        json_string(env::consts::OS),
        json_string(env::consts::ARCH),
        json_string(&executable.display().to_string()),
        json_string(TRUE),
        json_string(&shebang_path.display().to_string()),
        json_string(&python.display().to_string()),
        json_string(&embedded_build_summary),
        json_string(&embedded_binary.display().to_string()),
        embedded_python_dependency_detected,
        embedded_python_dependency
            .map(|edge| json_string(edge.resolved_path.as_deref().unwrap_or(&edge.requested_path)))
            .unwrap_or_else(|| "null".to_owned()),
        embedded_positive_control_passed,
        sandbox_markers_absent,
        closure_json,
        dependency_edges_json,
        cases_json,
    );
    let mut report = report;
    let closing = report.rfind('}').ok_or("missing report terminator")?;
    let os_version = Command::new("/usr/bin/sw_vers")
        .output()
        .map_err(|e| e.to_string())?;
    if !os_version.status.success() {
        return Err("cannot identify the OS runtime boundary".into());
    }
    report.insert_str(closing, &format!(
        ",\n  \"os_runtime_identity\": {},\n  \"independent_observer\": {},\n  \"allowlisted_dynamic_embedding_control\": {{\"executed_under_policy\": true, \"library_mapping_denied\": {}, \"requires_reviewed_source_for_static_embedding\": true}}\n",
        json_string(&String::from_utf8_lossy(&os_version.stdout)), observer_result, cases.iter().any(|case| case.name == "allowlisted_embedding_library_refused" && case.passed)
    ));
    fs::write(&report_path, report.as_bytes())
        .map_err(|error| format!("write report {}: {error}", report_path.display()))?;

    println!("RESULT={overall}");
    for case in &cases {
        println!(
            "CASE={} {} exit={:?}",
            case.name,
            if case.passed { "PASS" } else { "FAIL" },
            case.exit_code
        );
    }
    println!("REPORT={}", report_path.display());
    if observer.is_some()
        && (observed_python_controls != 4
            || observed_case_routes != cases.len()
            || observed_refusals != 4)
    {
        return Err(
            "kernel observer did not observe all ten control routes and four kernel EPERM refusals"
                .into(),
        );
    }
    if overall == "FAIL"
        || !cases
            .iter()
            .any(|case| case.name == "allowlisted_embedding_library_refused" && case.passed)
    {
        return Err("one or more required no-Python control cases failed".into());
    }
    Ok(())
}

fn run_control(args: &[String]) -> Result<(), String> {
    let mode = args.first().map(String::as_str).unwrap_or_default();
    match mode {
        "direct" => attempt_python(required_option(args, "--python")?, "DIRECT"),
        "descendant" => {
            let python = required_option(args, "--python")?;
            let self_path = env::current_exe().map_err(|error| error.to_string())?;
            let output = Command::new(self_path)
                .arg("--control")
                .arg("direct")
                .arg("--python")
                .arg(python)
                .output()
                .map_err(|error| format!("spawn native descendant: {error}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            if output.status.code() == Some(REFUSED_EXIT) && stdout.contains("REFUSED_EXEC path=") {
                println!(
                    "DESCENDANT_REFUSED child_status={:?} child_stdout={}",
                    output.status.code(),
                    stdout.trim()
                );
                process::exit(78);
            }
            println!(
                "DESCENDANT_ESCAPE child_status={:?} child_stdout={}",
                output.status.code(),
                stdout.trim()
            );
            process::exit(92);
        }
        "shebang" => {
            let script = required_option(args, "--script")?;
            match Command::new(script).output() {
                Err(error) => {
                    println!(
                        "SHEBANG_REFUSED path={} raw_os_error={:?} error={error}",
                        script,
                        error.raw_os_error()
                    );
                    process::exit(REFUSED_EXIT);
                }
                Ok(output) => {
                    println!(
                        "SHEBANG_ESCAPE status={:?} stdout={}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stdout).trim()
                    );
                    process::exit(93);
                }
            }
        }
        "embedded" => {
            let binary = required_option(args, "--binary")?;
            match Command::new(binary).output() {
                Err(error) => {
                    println!(
                        "EMBEDDED_BINARY_REFUSED path={} raw_os_error={:?} error={error}",
                        binary,
                        error.raw_os_error()
                    );
                    process::exit(REFUSED_EXIT);
                }
                Ok(output) => {
                    println!(
                        "EMBEDDED_BINARY_ESCAPE status={:?} stdout={}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stdout).trim()
                    );
                    process::exit(94);
                }
            }
        }
        _ => Err(format!("unknown control mode {mode:?}")),
    }
}

fn attempt_python(python: &str, label: &str) -> Result<(), String> {
    match Command::new(python)
        .arg("-I")
        .arg("-S")
        .arg("-c")
        .arg(format!("print('{DIRECT_MARKER}')"))
        .output()
    {
        Err(error) => {
            println!(
                "REFUSED_EXEC path={python} raw_os_error={:?} error={error}",
                error.raw_os_error()
            );
            process::exit(REFUSED_EXIT);
        }
        Ok(output) => {
            println!(
                "{label}_ESCAPE status={:?} stdout={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).trim()
            );
            process::exit(91);
        }
    }
}

fn run_command_case(
    name: &str,
    command: &Path,
    args: &[&str],
    expected: impl FnOnce(&Output) -> bool,
) -> CaseResult {
    // Keep trace-correlation windows disjoint despite the fs_usage wall/monotonic clock calibration.
    std::thread::sleep(std::time::Duration::from_millis(25));
    let started = epoch_micros();
    let mut child = Command::new(command);
    child.env_clear().args(args);
    let mut result = match child.output() {
        Ok(output) => case_from_output(
            name,
            std::iter::once(command.display().to_string())
                .chain(args.iter().map(|arg| (*arg).to_owned()))
                .collect(),
            output,
            expected,
        ),
        Err(error) => CaseResult {
            name: name.to_owned(),
            started_unix_micros: 0,
            finished_unix_micros: 0,
            status: "launch-error".to_owned(),
            exit_code: None,
            passed: false,
            stdout: String::new(),
            stderr: error.to_string(),
            command: std::iter::once(command.display().to_string())
                .chain(args.iter().map(|arg| (*arg).to_owned()))
                .collect(),
        },
    };
    result.started_unix_micros = started;
    result.finished_unix_micros = epoch_micros();
    result
}

fn run_native_control_case(
    name: &str,
    executable: &Path,
    control_args: &[&str],
    expected: impl FnOnce(&Output) -> bool,
) -> CaseResult {
    let args = std::iter::once("--control")
        .chain(control_args.iter().copied())
        .collect::<Vec<_>>();
    run_command_case(name, executable, &args, expected)
}

fn run_case(
    name: &str,
    profile: &Path,
    command: &Path,
    args: &[&str],
    expected: impl FnOnce(&Output) -> bool,
) -> CaseResult {
    // Keep trace-correlation windows disjoint despite the fs_usage wall/monotonic clock calibration.
    std::thread::sleep(std::time::Duration::from_millis(25));
    let started = epoch_micros();
    let mut command_args = vec!["-f".to_owned(), profile.display().to_string()];
    command_args.push(command.display().to_string());
    command_args.extend(args.iter().map(|arg| (*arg).to_owned()));
    let output = Command::new(SANDBOX_EXEC).args(&command_args).output();
    let mut result = match output {
        Ok(output) => case_from_output(name, invocation_vector(&command_args), output, expected),
        Err(error) => CaseResult {
            name: name.to_owned(),
            started_unix_micros: 0,
            finished_unix_micros: 0,
            status: "launcher-error".to_owned(),
            exit_code: None,
            passed: false,
            stdout: String::new(),
            stderr: error.to_string(),
            command: invocation_vector(&command_args),
        },
    };
    result.started_unix_micros = started;
    result.finished_unix_micros = epoch_micros();
    result
}

fn run_control_case(
    name: &str,
    profile: &Path,
    executable: &Path,
    control_args: &[&str],
    expected: impl FnOnce(&Output) -> bool,
) -> CaseResult {
    // Keep trace-correlation windows disjoint despite the fs_usage wall/monotonic clock calibration.
    std::thread::sleep(std::time::Duration::from_millis(25));
    let started = epoch_micros();
    let mut command_args = vec!["-f".to_owned(), profile.display().to_string()];
    command_args.push(executable.display().to_string());
    command_args.push("--control".to_owned());
    command_args.extend(control_args.iter().map(|arg| (*arg).to_owned()));
    let mut result = match Command::new(SANDBOX_EXEC).args(&command_args).output() {
        Ok(output) => case_from_output(name, invocation_vector(&command_args), output, expected),
        Err(error) => CaseResult {
            name: name.to_owned(),
            started_unix_micros: 0,
            finished_unix_micros: 0,
            status: "launcher-error".to_owned(),
            exit_code: None,
            passed: false,
            stdout: String::new(),
            stderr: error.to_string(),
            command: invocation_vector(&command_args),
        },
    };
    result.started_unix_micros = started;
    result.finished_unix_micros = epoch_micros();
    result
}

fn epoch_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_micros()
}

fn trace_targets(line: &str, target: &str) -> bool {
    if !(line.contains("posix_spawn") || line.contains("execve")) {
        return false;
    }
    let Some(at) = line.find(target) else {
        return false;
    };
    at > 0
        && line.as_bytes()[at - 1].is_ascii_whitespace()
        && line
            .as_bytes()
            .get(at + target.len())
            .is_some_and(u8::is_ascii_whitespace)
}

fn trace_refuses_target(line: &str, target: &str) -> bool {
    if !trace_targets(line, target) {
        return false;
    }
    let before = &line[..line.find(target).expect("matched target")];
    before
        .split('[')
        .nth(1)
        .and_then(|tail| tail.split(']').next())
        .is_some_and(|code| code.trim() == "1")
}

fn trace_in_window(line: &str, start: u128, finish: u128) -> bool {
    let Some(clock) = line.split_whitespace().next() else {
        return false;
    };
    let mut parts = clock.split([':', '.']);
    let parsed: Option<Vec<u128>> = parts.by_ref().map(|s| s.parse().ok()).collect();
    let Some(parts) = parsed else {
        return false;
    };
    if parts.len() != 4 || parts[0] > 23 || parts[1] > 59 || parts[2] > 59 || parts[3] > 999999 {
        return false;
    }
    let day = 86_400_000_000u128;
    let relative = ((parts[0] * 60 + parts[1]) * 60 + parts[2]) * 1_000_000 + parts[3];
    let base = start / day * day + relative;
    [Some(base), base.checked_add(day), base.checked_sub(day)]
        .into_iter()
        .flatten()
        .any(|at| start <= at && at <= finish)
}

fn invocation_vector(arguments: &[String]) -> Vec<String> {
    let mut result = vec![SANDBOX_EXEC.to_owned()];
    result.extend(arguments.iter().cloned());
    result
}

fn case_from_output(
    name: &str,
    command: Vec<String>,
    output: Output,
    expected: impl FnOnce(&Output) -> bool,
) -> CaseResult {
    let passed = expected(&output);
    CaseResult {
        name: name.to_owned(),
        started_unix_micros: 0,
        finished_unix_micros: 0,
        status: if output.status.success() {
            "success".to_owned()
        } else {
            "nonzero".to_owned()
        },
        exit_code: output.status.code(),
        passed,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        command,
    }
}

fn sandbox_profile(executable: &Path, shebang: &Path, embedded: &Path) -> String {
    let execs = [executable, Path::new(TRUE), shebang]
        .into_iter()
        .map(|path| {
            format!(
                "(literal \"{}\")",
                scheme_escape(&path.display().to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n       ");
    let readable = [executable, shebang, embedded]
        .into_iter()
        .map(|path| {
            format!(
                "(literal \"{}\")",
                scheme_escape(&path.display().to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n       ");
    format!(
        "(version 1)\n(deny default)\n(import \"system.sb\")\n(deny network*)\n(deny file-write*)\n(allow process-fork)\n(allow signal)\n(allow file-read* file-map-executable\n       {readable})\n(allow process-exec\n       {execs})\n"
    )
}

fn build_embedded_control(python: &Path, source: &Path, output: &Path) -> Result<(), String> {
    let python_bin_dir = python
        .parent()
        .ok_or_else(|| "Python binary has no parent directory".to_owned())?;
    let version_root = python_bin_dir
        .parent()
        .ok_or_else(|| "Python binary path lacks a version directory".to_owned())?;
    let include_root = version_root.join("include");
    let include_dir = fs::read_dir(&include_root)
        .map_err(|error| format!("find Python.h under {}: {error}", include_root.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("Python.h").is_file())
        .ok_or_else(|| format!("no Python.h under {}", include_root.display()))?;
    let lib_dir = version_root.join("lib");
    let lib_name = fs::read_dir(&lib_dir)
        .map_err(|error| format!("find libpython under {}: {error}", lib_dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("libpython") && name.ends_with(".dylib"))
        .ok_or_else(|| format!("no libpython dylib under {}", lib_dir.display()))?;
    let link_name = lib_name
        .strip_prefix("lib")
        .and_then(|name| name.strip_suffix(".dylib"))
        .ok_or_else(|| format!("unexpected Python library name {lib_name}"))?;

    let output_result = Command::new(CLANG)
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-I")
        .arg(include_dir)
        .arg(source)
        .arg("-L")
        .arg(&lib_dir)
        .arg(format!("-Wl,-rpath,{}", lib_dir.display()))
        .arg(format!("-l{link_name}"))
        .arg("-o")
        .arg(output)
        .output()
        .map_err(|error| format!("launch system clang for owned countercontrol: {error}"))?;
    if !output_result.status.success() {
        return Err(format!(
            "system clang could not build the embedded-runtime countercontrol (status {:?}): {}{}",
            output_result.status.code(),
            String::from_utf8_lossy(&output_result.stdout),
            String::from_utf8_lossy(&output_result.stderr)
        ));
    }
    Ok(())
}

fn macho_rpaths(binary: &Path) -> Result<Vec<String>, String> {
    let output = Command::new(OTOOL)
        .arg("-l")
        .arg(binary)
        .output()
        .map_err(|error| format!("inspect LC_RPATH entries for {}: {error}", binary.display()))?;
    if !output.status.success() {
        return Err(format!(
            "otool -l failed for {} with status {:?}: {}",
            binary.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            line.trim().strip_prefix("path ").and_then(|value| {
                value
                    .split_once(" (offset")
                    .map(|(path, _)| path.to_owned())
            })
        })
        .collect())
}

fn macho_install_name(binary: &Path) -> Option<String> {
    if binary.extension().and_then(|extension| extension.to_str()) != Some("dylib") {
        return None;
    }
    let output = Command::new(OTOOL).arg("-D").arg(binary).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn resolve_loader_relative_dependency(
    binary: &Path,
    dependency: &str,
    rpaths: &[String],
) -> Option<PathBuf> {
    let binary_dir = binary.parent()?;
    if let Some(suffix) = dependency.strip_prefix("@loader_path/") {
        return Some(binary_dir.join(suffix));
    }
    let suffix = dependency.strip_prefix("@rpath/")?;
    for rpath in rpaths {
        let base = if rpath == "@loader_path" {
            binary_dir.to_path_buf()
        } else if let Some(suffix) = rpath.strip_prefix("@loader_path/") {
            binary_dir.join(suffix)
        } else {
            let path = PathBuf::from(rpath);
            if !path.is_absolute() {
                continue;
            }
            path
        };
        let candidate = base.join(suffix);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn collect_dependency_closure(
    components: &mut BTreeMap<String, Component>,
    roots: &[(&Path, &str)],
) -> Result<Vec<DependencyEdge>, String> {
    let mut queue = roots
        .iter()
        .map(|(path, role)| (path.to_path_buf(), (*role).to_owned()))
        .collect::<Vec<_>>();
    let mut scanned = BTreeSet::new();
    let mut edges = Vec::new();
    while let Some((binary, role)) = queue.pop() {
        let canonical_binary = fs::canonicalize(&binary)
            .map_err(|error| format!("resolve dependency root {}: {error}", binary.display()))?;
        let source = canonical_binary.display().to_string();
        if !scanned.insert(source.clone()) {
            continue;
        }
        let output = Command::new(OTOOL)
            .arg("-L")
            .arg(&canonical_binary)
            .output()
            .map_err(|error| {
                format!(
                    "inspect dependencies of {}: {error}",
                    canonical_binary.display()
                )
            })?;
        if !output.status.success() {
            return Err(format!(
                "otool -L failed for {} with status {:?}: {}",
                canonical_binary.display(),
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let rpaths = macho_rpaths(&canonical_binary)?;
        let install_name = macho_install_name(&canonical_binary);
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let dependency = line
                .trim()
                .split(" (compatibility version")
                .next()
                .unwrap_or_default();
            if dependency.is_empty() {
                continue;
            }
            if install_name.as_deref() == Some(dependency) {
                continue;
            }
            let requested = PathBuf::from(dependency);
            let candidate = if requested.is_absolute() {
                Some(requested.clone())
            } else {
                resolve_loader_relative_dependency(&canonical_binary, dependency, &rpaths)
            };
            let Some(candidate) = candidate else {
                edges.push(DependencyEdge {
                    source: source.clone(),
                    requested_path: dependency.to_owned(),
                    resolved_path: None,
                    resolution: if dependency.starts_with("@rpath/") {
                        "unresolved-rpath-loader-path".to_owned()
                    } else {
                        "unresolved-loader-relative-path".to_owned()
                    },
                });
                continue;
            };
            match fs::canonicalize(&candidate) {
                Ok(resolved) if resolved.is_file() => {
                    let resolved_string = resolved.display().to_string();
                    add_component(
                        components,
                        &resolved,
                        &format!("recursive dynamic dependency of {role}"),
                        false,
                    )?;
                    edges.push(DependencyEdge {
                        source: source.clone(),
                        requested_path: dependency.to_owned(),
                        resolved_path: Some(resolved_string.clone()),
                        resolution: if dependency.starts_with('@') {
                            "resolved-loader-relative-and-hashed".to_owned()
                        } else {
                            "resolved-and-hashed".to_owned()
                        },
                    });
                    queue.push((resolved, format!("dependency of {role}")));
                }
                Ok(resolved) => edges.push(DependencyEdge {
                    source: source.clone(),
                    requested_path: dependency.to_owned(),
                    resolved_path: Some(resolved.display().to_string()),
                    resolution: "resolved-path-not-regular-file".to_owned(),
                }),
                Err(_) => edges.push(DependencyEdge {
                    source: source.clone(),
                    requested_path: dependency.to_owned(),
                    resolved_path: None,
                    resolution: if dependency.starts_with("/usr/lib/")
                        || dependency.starts_with("/System/")
                    {
                        "unresolved-system-shared-cache-path".to_owned()
                    } else if dependency.starts_with('@') {
                        "unresolved-loader-relative-path".to_owned()
                    } else {
                        "unresolved".to_owned()
                    },
                }),
            }
        }
    }
    Ok(edges)
}

fn add_component(
    components: &mut BTreeMap<String, Component>,
    path: &Path,
    role: &str,
    process_exec_allowed: bool,
) -> Result<(), String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("canonicalize component {}: {error}", path.display()))?;
    let key = canonical.display().to_string();
    let digest = sha256_file(&canonical)?;
    components
        .entry(key.clone())
        .and_modify(|component| {
            if process_exec_allowed {
                component.process_exec_allowed = true;
            }
            if !component.role.contains(role) {
                component.role.push_str("; ");
                component.role.push_str(role);
            }
        })
        .or_insert(Component {
            path: key,
            sha256: digest,
            role: role.to_owned(),
            process_exec_allowed,
        });
    Ok(())
}

fn component_hashes(
    components: &BTreeMap<String, Component>,
) -> Result<BTreeMap<String, String>, String> {
    components
        .values()
        .map(|component| {
            Ok((
                component.path.clone(),
                sha256_file(Path::new(&component.path))?,
            ))
        })
        .collect()
}

fn verify_hashes(
    components: &BTreeMap<String, Component>,
    expected: &BTreeMap<String, String>,
    phase: &str,
) -> Result<(), String> {
    for component in components.values() {
        let current = sha256_file(Path::new(&component.path))?;
        let pinned = expected
            .get(&component.path)
            .ok_or_else(|| format!("missing expected hash for {}", component.path))?;
        if &current != pinned || current != component.sha256 {
            return Err(format!(
                "component hash changed {phase}: {} expected {pinned}, initial {} current {current}",
                component.path,
                component.sha256
            ));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied
                && path == Path::new("/usr/bin/sudo") =>
        {
            // Some standard macOS runners make this setuid OS binary unreadable
            // to the runner account. Hash that exact immutable system path via
            // its existing privileged OS helper, without elevating the probe.
            let result = Command::new("/usr/bin/sudo")
                .args(["-n", "/usr/bin/shasum", "-a", "256", "/usr/bin/sudo"])
                .output()
                .map_err(|e| e.to_string())?;
            let text = String::from_utf8(result.stdout).map_err(|e| e.to_string())?;
            let hash = text
                .split_whitespace()
                .next()
                .ok_or("empty privileged OS hash")?;
            if !result.status.success()
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || !text.ends_with("  /usr/bin/sudo\n")
            {
                return Err("cannot identify the unreadable OS sudo helper".into());
            }
            return Ok(hash.to_owned());
        }
        Err(error) => return Err(format!("read {} for SHA-256: {error}", path.display())),
    };
    Ok(hex(&sha256(&bytes)))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut words = [0u32; 64];
        for (index, chunk) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut working = state;
        for index in 0..64 {
            let sum1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choice = (working[4] & working[5]) ^ (!working[4] & working[6]);
            let temp1 = working[7]
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = sum0.wrapping_add(majority);
            working = [
                temp1.wrapping_add(temp2),
                working[0],
                working[1],
                working[2],
                working[3].wrapping_add(temp1),
                working[4],
                working[5],
                working[6],
            ];
        }
        for index in 0..8 {
            state[index] = state[index].wrapping_add(working[index]);
        }
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn component_json(component: &Component) -> String {
    format!(
        "{{\"path\":{},\"sha256\":{},\"role\":{},\"process_exec_allowed\":{}}}",
        json_string(&component.path),
        json_string(&component.sha256),
        json_string(&component.role),
        component.process_exec_allowed
    )
}

fn dependency_edge_json(edge: &DependencyEdge) -> String {
    format!(
        "{{\"source\":{},\"requested_path\":{},\"resolved_path\":{},\"resolution\":{}}}",
        json_string(&edge.source),
        json_string(&edge.requested_path),
        edge.resolved_path
            .as_ref()
            .map(|path| json_string(path))
            .unwrap_or_else(|| "null".to_owned()),
        json_string(&edge.resolution)
    )
}

fn case_json(case: &CaseResult) -> String {
    let command = case
        .command
        .iter()
        .map(|argument| json_string(argument))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"name\":{},\"status\":{},\"exit_code\":{},\"passed\":{},\"started_unix_micros\":{},\"finished_unix_micros\":{},\"command\":[{}],\"stdout\":{},\"stderr\":{}}}",
        json_string(&case.name),
        json_string(&case.status),
        case.exit_code.map(|code| code.to_string()).unwrap_or_else(|| "null".to_owned()),
        case.passed,
        case.started_unix_micros,
        case.finished_unix_micros,
        command,
        json_string(&case.stdout),
        json_string(&case.stderr)
    )
}

fn json_string(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            control if control <= '\u{1f}' => {
                result.push_str(&format!("\\u{:04x}", control as u32));
            }
            ordinary => result.push(ordinary),
        }
    }
    result.push('"');
    result
}

fn option_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn required_option<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    option_value(args, name).ok_or_else(|| format!("missing required argument {name}"))
}

fn canonical_absolute(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(format!(
            "countercontrol path must be absolute: {}",
            path.display()
        ));
    }
    fs::canonicalize(path)
        .map_err(|error| format!("resolve countercontrol {}: {error}", path.display()))
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|error| format!("read fixture permissions: {error}"))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("make shebang fixture executable: {error}"))
}

fn scheme_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{hex, sha256, trace_in_window, trace_refuses_target, trace_targets};

    #[test]
    fn kernel_refusal_requires_exact_target_and_errno() {
        let line = "00:00:00.000123 posix_spawn [  1] /owned/python  0.000010 probe.12";
        assert!(trace_refuses_target(line, "/owned/python"));
        assert!(!trace_refuses_target(line, "/owned/py"));
        assert!(!trace_refuses_target(line, "/other/python"));
        assert!(!trace_refuses_target(
            &line.replace("[  1]", "[  2]"),
            "/owned/python"
        ));
        assert!(!trace_refuses_target(
            &line.replace("[  1]", ""),
            "/owned/python"
        ));
        assert!(!trace_targets(
            &line.replace("python ", "python-old "),
            "/owned/python"
        ));
    }

    #[test]
    fn kernel_trace_window_matches_utc_and_midnight_but_not_neighbours() {
        let day = 86_400_000_000u128;
        assert!(trace_in_window(
            "00:00:00.000123 execve /owned",
            day - 5,
            day + 200
        ));
        assert!(!trace_in_window(
            "00:00:00.000201 execve /owned",
            day - 5,
            day + 200
        ));
        assert!(!trace_in_window(
            "23:59:59.999000 execve /owned",
            day - 5,
            day + 200
        ));
        assert!(!trace_in_window("invalid header", 0, day));
        assert!(!trace_in_window("00:00:99.000001 execve /owned", 0, day));
    }

    #[test]
    fn sha256_matches_standard_abc_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

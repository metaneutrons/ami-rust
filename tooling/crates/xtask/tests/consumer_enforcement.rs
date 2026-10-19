//! Explicit maintainer-only replay of the consumer adapter's interpreter controls.
//!
//! Run only with a prebuilt native adapter and the pinned host Python runtime:
//! `cargo test -p ami-rust-xtask --test consumer_enforcement -- --ignored --nocapture`
//! Set AMI_RUST_CONSUMER_ENFORCEMENT_ADAPTER, _PYTHON_ROOT, _WORK and _OUTPUT.
//! The test retains its private inputs, reports, and result JSON on success or
//! failure. It qualifies only these narrow host controls, not a consumer build.

use ami_rust_core::{
    digest::{is_sha256_digest, sha256_file},
    process_capture::{CaptureLimits, CapturedProcess, CommandSpec},
    resource_capture::{ResourceLimits, SampleLimits, capture_with_resources},
    workspace_accounting::ScanLimits,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::Duration,
};

const CAPTURE_TIMEOUT: Duration = Duration::from_secs(60);
const RESOURCE_LIMITS: ResourceLimits = ResourceLimits {
    max_visible_rss_bytes: 4 * 1024 * 1024 * 1024,
    max_workspace_bytes: 12 * 1024 * 1024 * 1024,
    max_log_bytes: 16 * 1024 * 1024,
};
const SAMPLE_LIMITS: SampleLimits = SampleLimits {
    max_ps_bytes: 2 * 1024 * 1024,
    max_ps_rows: 32_768,
    max_history_entries: 131_072,
    max_roots: 2,
    scan: ScanLimits {
        max_entries: 100_000,
        max_work_units: 200_001,
    },
};
const EMBEDDED_MARKER: &str = "ADAPTER_EMBEDDED_PYTHON_MARKER";
const SHEBANG_MARKER: &str = "ADAPTER_SHEBANG_PYTHON_MARKER";

#[test]
#[ignore = "maintainer qualification only; requires a prebuilt adapter and pinned Python runtime"]
fn native_interpreter_controls_are_refused_under_the_adapter_policy() -> Result<(), String> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .map_err(display_error)?;
    let pin_path = repo.join("release/ci-python-inputs.json");
    let pin_bytes = fs::read(&pin_path).map_err(display_error)?;
    let pin: Value = serde_json::from_slice(&pin_bytes).map_err(display_error)?;
    if pin.get("schema").and_then(Value::as_str) != Some("ami-rust-ci-python-inputs-v1") {
        return Err("unexpected pinned Python input schema".to_owned());
    }
    let (host_id, platform) = selected_host()?;
    let host_pin = pin
        .get("hosts")
        .and_then(|hosts| hosts.get(host_id))
        .ok_or_else(|| format!("ci-python-inputs.json has no {host_id} host pin"))?;
    let runtime_relative = required_string(host_pin, "runtime_relative_path")?;
    let expected_runtime_sha = required_string(host_pin, "runtime_sha256")?;
    let expected_runtime_bytes = required_u64(host_pin, "runtime_bytes")?;
    if !is_sha256_digest(expected_runtime_sha) {
        return Err("pinned Python runtime SHA-256 is malformed".to_owned());
    }

    let adapter = required_env_path("AMI_RUST_CONSUMER_ENFORCEMENT_ADAPTER")?;
    let python_root = required_env_path("AMI_RUST_CONSUMER_ENFORCEMENT_PYTHON_ROOT")?;
    let work = create_fresh_private_root("AMI_RUST_CONSUMER_ENFORCEMENT_WORK")?;
    let output = create_fresh_private_root("AMI_RUST_CONSUMER_ENFORCEMENT_OUTPUT")?;
    if paths_overlap(&work, &output) {
        return Err("private work and output roots must be disjoint".to_owned());
    }
    let adapter = canonical_executable(&adapter, "adapter")?;
    let python_root = python_root
        .canonicalize()
        .map_err(|error| format!("resolve pinned Python root: {error}"))?;
    if !python_root.is_dir() {
        return Err("pinned Python root is not a directory".to_owned());
    }
    let python = python_root.join(runtime_relative);
    let python = canonical_executable(&python, "pinned Python interpreter")?;
    let python_metadata = fs::metadata(&python).map_err(display_error)?;
    let python_sha = sha256_file(&python).map_err(|error| error.to_string())?;
    if python_metadata.len() != expected_runtime_bytes || python_sha != expected_runtime_sha {
        return Err(format!(
            "Python executable does not match {host_id} pin: bytes={} sha256={python_sha}",
            python_metadata.len()
        ));
    }

    let input_dir = create_private_dir(&work.join("inputs"))?;
    let child = create_private_dir(&work.join("child"))?;
    let home = create_private_dir(&child.join("home"))?;
    let tmp = create_private_dir(&child.join("tmp"))?;
    let markers = create_private_dir(&child.join("markers"))?;
    let reports = create_private_dir(&output.join("reports"))?;
    let runner = RunContext {
        work: &work,
        output: &output,
        home: &home,
        tmp: &tmp,
    };
    let result_path = output.join("consumer-enforcement-controls.json");
    let result_source = repo.join("tooling/crates/xtask/tests/consumer_enforcement.rs");
    let result_source_sha = sha256_file(&result_source).map_err(|error| error.to_string())?;

    let python_library = find_pinned_python_library(&python_root, platform)?;
    let compiler = host_compiler(platform)?;
    let compiler = canonical_executable(compiler, "native C compiler")?;
    let fixture = input_dir.join("embedded-python-control");
    let fixture_source = input_dir.join("embedded-python-control.c");
    let embedded_marker = markers.join("embedded-python-ran");
    let fixture_text = embedded_fixture_source(&embedded_marker)?;
    write_new_private(&fixture_source, fixture_text.as_bytes())?;
    let compile_args = compile_arguments(platform, &fixture_source, &fixture);
    let build = runner.run(&compiler, compile_args)?;
    require_status(&build, 0, "compile embedded Python control")?;
    set_executable(&fixture)?;
    let fixture = canonical_executable(&fixture, "embedded Python control")?;
    let fixture_sha = sha256_file(&fixture).map_err(|error| error.to_string())?;

    let shebang_script = input_dir.join("python-shebang-control");
    let shebang_interpreter = input_dir.join("python3.12");
    symlink(&python, &shebang_interpreter).map_err(display_error)?;
    let shebang_interpreter_text = shebang_interpreter
        .to_str()
        .ok_or_else(|| "shebang interpreter alias must be UTF-8".to_owned())?;
    if shebang_interpreter_text.chars().any(char::is_whitespace) {
        return Err("absolute shebang interpreter alias must contain no whitespace".to_owned());
    }
    // The unconfined execution below must actually run this exact script on
    // the selected host; an unsupported shebang cannot count as a refusal.
    let shebang_marker = markers.join("shebang-python-ran");
    let shebang_marker_text =
        serde_json::to_string(&shebang_marker.to_string_lossy()).map_err(display_error)?;
    let shebang_source = format!(
        "#!{}\nopen({}, 'w').write('shebang-python-wrote\\n')\nprint('{SHEBANG_MARKER}', flush=True)\n",
        shebang_interpreter.display(),
        shebang_marker_text,
    );
    write_new_private(&shebang_script, shebang_source.as_bytes())?;
    set_executable(&shebang_script)?;
    let shebang_script = canonical_executable(&shebang_script, "absolute Python shebang script")?;
    let shebang_sha = sha256_file(&shebang_script).map_err(|error| error.to_string())?;

    let adapter_sha = sha256_file(&adapter).map_err(|error| error.to_string())?;
    let python_library_sha = sha256_file(&python_library).map_err(|error| error.to_string())?;
    let mut inputs = json!({
        "host": host_id,
        "ci_python_inputs_json": {
            "path": pin_path.display().to_string(),
            "sha256": ami_rust_core::digest::sha256_bytes(&pin_bytes),
        },
        "adapter": {"path": adapter.display().to_string(), "sha256": adapter_sha},
        "python_root": python_root.display().to_string(),
        "python_executable": {
            "path": python.display().to_string(),
            "sha256": python_sha,
            "bytes": python_metadata.len(),
            "pinned_sha256": expected_runtime_sha,
            "pinned_bytes": expected_runtime_bytes,
        },
        "python_library": {"path": python_library.display().to_string(), "sha256": python_library_sha},
        "compiler": {"path": compiler.display().to_string(), "sha256": sha256_file(&compiler).map_err(|error| error.to_string())?},
        "fixture_source": {"path": fixture_source.display().to_string(), "sha256": ami_rust_core::digest::sha256_bytes(fixture_text.as_bytes())},
        "fixture": {"path": fixture.display().to_string(), "sha256": fixture_sha},
        "shebang_script": {"path": shebang_script.display().to_string(), "sha256": shebang_sha},
        "shebang_interpreter_alias": {
            "path": shebang_interpreter.display().to_string(),
            "target": python.display().to_string(),
        },
        "native_runtime_boundary": if platform == Platform::Macos {
            "macOS system shared cache under imported system profile; no file-backed system-library grants"
        } else {
            "exact file-backed Linux ldd closure, with each ELF PT_INTERP excluded from read-file grants and granted as an exact hashed executable"
        },
        "test_source": {"path": result_source.display().to_string(), "sha256": result_source_sha},
    });
    let mut cases = Vec::<Value>::new();
    let mut result = json!({
        "schema": "ami-rust-native-interpreter-control-replay-v1",
        "status": "RUNNING",
        "scope": "adapter controls only; not RC1-A2 acceptance and not a full-consumer claim",
        "host": host_id,
        "work_root": work.display().to_string(),
        "output_root": output.display().to_string(),
        "inputs": inputs,
        "cases": cases,
    });
    persist_result(&result_path, &result)?;

    // macOS system libraries live in the shared cache under the imported
    // system profile. Linux grants the exact file-backed ldd closure, with
    // each binary's exact ELF interpreter separated as a hashed executable.
    let runtime_binaries = [adapter.clone(), fixture.clone()];
    let (runtime_libraries, runtime_interpreters) = if platform == Platform::Linux {
        let interpreters = linux_runtime_interpreters(&runtime_binaries)?;
        let mut libraries = linux_runtime_libraries(&runtime_binaries, &runner)?;
        for interpreter in &interpreters {
            if !libraries
                .iter()
                .any(|library| library == &interpreter.canonical_path)
            {
                return Err(format!(
                    "ELF PT_INTERP {} for {} is absent from the ldd runtime closure",
                    interpreter.canonical_path.display(),
                    interpreter.binary.display()
                ));
            }
        }
        let interpreter_paths = interpreters
            .iter()
            .map(|interpreter| interpreter.canonical_path.clone())
            .collect::<BTreeSet<_>>();
        libraries.retain(|library| !interpreter_paths.contains(library));
        (libraries, interpreters)
    } else {
        (Vec::new(), Vec::new())
    };
    if runtime_libraries.iter().any(|path| path == &python_library) {
        return Err("Python library unexpectedly appears in the native runtime closure".to_owned());
    }
    if runtime_interpreters
        .iter()
        .any(|interpreter| interpreter.canonical_path == python_library)
    {
        return Err("Python library unexpectedly appears as an ELF interpreter".to_owned());
    }
    let runtime_library_identities = runtime_libraries
        .iter()
        .map(|path| {
            Ok(json!({
                "path": path.display().to_string(),
                "sha256": sha256_file(path).map_err(|error| error.to_string())?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    inputs["native_runtime_libraries"] = json!(runtime_library_identities);
    let runtime_interpreter_identities = runtime_interpreters
        .iter()
        .map(|interpreter| {
            Ok(json!({
                "binary": interpreter.binary.display().to_string(),
                "binary_sha256": sha256_file(&interpreter.binary).map_err(|error| error.to_string())?,
                "elf_pt_interp": interpreter.declared_path.display().to_string(),
                "canonical_path": interpreter.canonical_path.display().to_string(),
                "sha256": sha256_file(&interpreter.canonical_path).map_err(|error| error.to_string())?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    inputs["native_runtime_interpreters"] = json!(runtime_interpreter_identities);
    result["inputs"] = inputs.clone();
    persist_result(&result_path, &result)?;
    let context = ReplayContext {
        adapter: &adapter,
        python: &python,
        python_library: &python_library,
        runtime_libraries: &runtime_libraries,
        runtime_interpreters: &runtime_interpreters,
        input_dir: &input_dir,
        reports: &reports,
        child: &child,
        home: &home,
        tmp: &tmp,
        markers: &markers,
        runner: &runner,
        platform,
    };

    for (name, mode, option, argument, status, marker, marker_file) in [
        (
            "unconfined_direct",
            "direct",
            "--python",
            &python,
            91,
            "ADAPTER_DIRECT_PYTHON_MARKER",
            None,
        ),
        (
            "unconfined_transitive",
            "transitive",
            "--python",
            &python,
            92,
            "ADAPTER_DIRECT_PYTHON_MARKER",
            None,
        ),
        (
            "unconfined_shebang",
            "shebang",
            "--script",
            &shebang_script,
            93,
            SHEBANG_MARKER,
            Some(&shebang_marker),
        ),
    ] {
        let process = runner.run(
            &adapter,
            strings(["--control", mode, option])
                .into_iter()
                .chain([argument.as_os_str().to_os_string()])
                .collect(),
        )?;
        require_status(&process, status, name)?;
        require_text(&process.stdout, marker, name)?;
        if marker_file.is_some_and(|path| !path.is_file()) {
            return Err(format!("{name} did not create its marker file"));
        }
        cases.push(unconfined_case(name, &process));
        save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;
    }

    let unconfined_embedded =
        runner.run(&fixture, vec![python_library.as_os_str().to_os_string()])?;
    require_status(
        &unconfined_embedded,
        0,
        "unconfined embedded Python fixture",
    )?;
    require_text(
        &unconfined_embedded.stdout,
        EMBEDDED_MARKER,
        "unconfined embedded marker",
    )?;
    if !embedded_marker.is_file() {
        return Err("unconfined embedded fixture did not create its marker file".to_owned());
    }
    cases.push(unconfined_case("unconfined_embedded", &unconfined_embedded));
    save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;
    fs::remove_file(&embedded_marker).map_err(display_error)?;
    fs::remove_file(&shebang_marker).map_err(display_error)?;

    let positive_marker = markers.join("native-positive");
    let positive_mode = if platform == Platform::Macos {
        "positive-write"
    } else {
        "positive-spawn"
    };
    let positive_args: Vec<OsString> = strings(["--control", positive_mode, "--path"])
        .into_iter()
        .chain([positive_marker.as_os_str().to_os_string()])
        .collect();
    let positive_execs = if platform == Platform::Macos {
        vec![
            adapter.clone(),
            canonical_executable(Path::new("/usr/bin/touch"), "touch")?,
        ]
    } else {
        vec![adapter.clone()]
    };
    if platform == Platform::Linux {
        // Without this one runtime input Command::output fails while opening
        // stdin, before it can attempt an exec. Such a failure cannot prove
        // that Python itself was refused. Preserve an isolated counterprobe.
        let complete = policy_text(&positive_execs, &context)?;
        let missing_stdin = complete.replace("read-file /dev/null\n", "");
        if missing_stdin == complete {
            return Err("Linux policy omitted the exact native stdin allowance".to_owned());
        }
        let refused = run_restricted(
            "native_descendant_missing_stdin",
            &context,
            &adapter,
            &positive_args,
            &policy_path(
                &input_dir,
                "native-descendant-missing-stdin",
                &missing_stdin,
            )?,
            2,
        )?;
        require_text(
            refused.stderr.as_bytes(),
            "launch native positive descendant: Permission denied (os error 13)",
            "native descendant missing stdin counterprobe",
        )?;
        if positive_marker.exists()
            || fs::read_dir(&markers)
                .map_err(display_error)?
                .next()
                .is_some()
        {
            return Err("missing-stdin counterprobe unexpectedly ran the descendant".to_owned());
        }
        cases.push(refused.case);
        save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;
    }
    let positive = run_restricted(
        "native_positive",
        &context,
        &adapter,
        &positive_args,
        &policy_path(
            &input_dir,
            "native-positive",
            &policy_text(&positive_execs, &context)?,
        )?,
        0,
    )?;
    if platform == Platform::Macos {
        require_text(
            positive.stdout.as_bytes(),
            "NATIVE_WRITE_OK",
            "macOS native positive marker",
        )?;
    } else {
        require_text(
            positive.stdout.as_bytes(),
            "ADAPTER_NATIVE_DESCENDANT_POSITIVE",
            "Linux native positive marker",
        )?;
    }
    if !positive_marker.is_file() {
        return Err("native positive control did not create its declared marker file".to_owned());
    }
    let positive_contents = fs::read(&positive_marker).map_err(display_error)?;
    let expected_positive_contents: &[u8] = if platform == Platform::Macos {
        b""
    } else {
        b"adapter-positive\n"
    };
    if positive_contents != expected_positive_contents {
        return Err(format!(
            "native positive marker contents differ: {:?}",
            positive_contents
        ));
    }
    ensure_only_marker(&markers, "native-positive")?;
    cases.push(positive.case);
    save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;

    let null_probe_args = strings(["--control", "write-null-probe"]);
    let null_probe_execs = vec![adapter.clone()];
    let no_null_write_policy = policy_text(&null_probe_execs, &context)?;
    let with_null_write_policy =
        no_null_write_policy.replace("network deny\n", "write-null /dev/null\nnetwork deny\n");
    if with_null_write_policy == no_null_write_policy
        || with_null_write_policy.replace("write-null /dev/null\n", "") != no_null_write_policy
    {
        return Err("could not construct the isolated write-null policy pair".to_owned());
    }
    let refused_null_write = run_restricted(
        "null_write_omitted",
        &context,
        &adapter,
        &null_probe_args,
        &policy_path(&input_dir, "null-write-omitted", &no_null_write_policy)?,
        0,
    )?;
    // Imported macOS system.sb already allows null writes. Record that OS
    // allowance honestly; Linux requires the explicit Landlock write rule.
    let omitted_result = if platform == Platform::Macos {
        "WRITE_NULL_ALLOWED"
    } else {
        "WRITE_NULL_REFUSED errno=13"
    };
    require_text(
        refused_null_write.stdout.as_bytes(),
        omitted_result,
        "native /dev/null write omission counterprobe",
    )?;
    cases.push(refused_null_write.case);
    save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;

    let allowed_null_write = run_restricted(
        "null_write_allowed",
        &context,
        &adapter,
        &null_probe_args,
        &policy_path(&input_dir, "null-write-allowed", &with_null_write_policy)?,
        0,
    )?;
    require_text(
        allowed_null_write.stdout.as_bytes(),
        "WRITE_NULL_ALLOWED",
        "native /dev/null write positive control",
    )?;
    let null_report_path = context.reports.join("null_write_allowed/report.json");
    let null_report: Value =
        serde_json::from_slice(&fs::read(&null_report_path).map_err(display_error)?)
            .map_err(display_error)?;
    let null_evidence = null_report
        .get("write_null")
        .ok_or_else(|| "write-null report evidence is missing".to_owned())?;
    if null_evidence.get("path").and_then(Value::as_str) != Some("/dev/null")
        || null_evidence.get("device_type").and_then(Value::as_str) != Some("character-device")
        || null_evidence
            .get("post_run_identity_matches")
            .and_then(Value::as_bool)
            != Some(true)
        || null_evidence.get("pre_run_identity") != null_evidence.get("post_run_identity")
        || !null_evidence
            .get("content_sha256")
            .is_some_and(Value::is_null)
    {
        return Err(
            "write-null report did not preserve exact character-device identity evidence"
                .to_owned(),
        );
    }
    cases.push(allowed_null_write.case);
    save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;

    let invalid_null_policy =
        with_null_write_policy.replace("write-null /dev/null", "write-null /dev/zero");
    let invalid_null_path = policy_path(&input_dir, "null-write-invalid", &invalid_null_policy)?;
    let invalid_null_report = context.reports.join("null_write_invalid");
    let invalid = runner.run(
        &adapter,
        vec![
            "--policy".into(),
            invalid_null_path.into_os_string(),
            "--report-dir".into(),
            invalid_null_report.clone().into_os_string(),
            "--run".into(),
            "--".into(),
            adapter.clone().into_os_string(),
            "--control".into(),
            "write-null-probe".into(),
        ],
    )?;
    require_status(&invalid, 2, "invalid write-null directive setup refusal")?;
    require_text(
        &invalid.stderr,
        "write-null only accepts the exact path /dev/null",
        "invalid write-null diagnostic",
    )?;
    require_no_text(
        &invalid.stdout,
        "WRITE_NULL_",
        "invalid write-null must not execute the child",
    )?;
    if invalid_null_report.join("report.json").exists() {
        return Err("invalid write-null directive unexpectedly ran a child".to_owned());
    }
    let mut invalid_case = unconfined_case("invalid_null_write_directive", &invalid);
    invalid_case["scope"] =
        json!("Adapter setup refusal before child launch; not an interpreter refusal");
    cases.push(invalid_case);
    save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;

    for (name, mode, option, argument, refusal, marker, stale_marker) in [
        (
            "restricted_direct",
            "direct",
            "--python",
            &python,
            "DIRECT_REFUSED",
            "ADAPTER_DIRECT_PYTHON_MARKER",
            None,
        ),
        (
            "restricted_transitive",
            "transitive",
            "--python",
            &python,
            "TRANSITIVE_REFUSED",
            "ADAPTER_DIRECT_PYTHON_MARKER",
            None,
        ),
        (
            "restricted_shebang",
            "shebang",
            "--script",
            &shebang_script,
            "SHEBANG_REFUSED",
            SHEBANG_MARKER,
            Some(&shebang_marker),
        ),
    ] {
        if stale_marker.is_some_and(|path| path.exists()) {
            return Err(format!("{name} started with a stale Python marker"));
        }
        let control = run_adapter_control(&context, name, mode, option, argument, refusal)?;
        require_no_text(control.stdout.as_bytes(), marker, name)?;
        if stale_marker.is_some_and(|path| path.exists()) {
            return Err(format!("{name} created its Python marker file"));
        }
        ensure_only_marker(&markers, "native-positive")?;
        cases.push(control.case);
        save_progress(&result_path, &mut result, &inputs, &cases, "RUNNING")?;
    }

    let embedded_args = vec![python_library.as_os_str().to_os_string()];
    let embedded_execs = vec![fixture.clone()];
    let embedded_policy = policy_text(&embedded_execs, &context)?;
    let embedded_policy_path = policy_path(&input_dir, "restricted-embedded", &embedded_policy)?;
    let embedded = run_restricted(
        "restricted_embedded",
        &context,
        &fixture,
        &embedded_args,
        &embedded_policy_path,
        77,
    )?;
    require_text(
        embedded.stderr.as_bytes(),
        "DLOPEN_DENIED",
        "restricted embedded fixture denial",
    )?;
    require_text(
        embedded.stderr.as_bytes(),
        &python_library.display().to_string(),
        "restricted embedded denied library path",
    )?;
    // POSIX reports dlopen failures through dlerror; it defines no errno
    // value. Keep errno as raw diagnostic data, and require the actual loader
    // permission-denial reason in addition to exit 77, path and no marker.
    let expected_denial = if platform == Platform::Linux {
        "cannot open shared object file: Permission denied"
    } else {
        "(blocked by sandbox)"
    };
    require_text(
        embedded.stderr.as_bytes(),
        expected_denial,
        "restricted embedded loader permission denial",
    )?;
    require_no_text(
        embedded.stdout.as_bytes(),
        EMBEDDED_MARKER,
        "restricted embedded control",
    )?;
    if embedded_marker.exists() {
        return Err("restricted embedded fixture created the Python marker file".to_owned());
    }
    ensure_only_marker(&markers, "native-positive")?;
    cases.push(embedded.case);
    save_progress(
        &result_path,
        &mut result,
        &inputs,
        &cases,
        "PASS_NARROW_NATIVE_INTERPRETER_CONTROLS",
    )?;

    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Platform {
    Macos,
    Linux,
}

struct RunContext<'a> {
    work: &'a Path,
    output: &'a Path,
    home: &'a Path,
    tmp: &'a Path,
}

impl RunContext<'_> {
    fn run(&self, program: &Path, args: Vec<OsString>) -> Result<CapturedProcess, String> {
        let env = [
            ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            ("HOME", self.home.to_str().ok_or("HOME path is not UTF-8")?),
            (
                "TMPDIR",
                self.tmp.to_str().ok_or("TMPDIR path is not UTF-8")?,
            ),
            ("LC_ALL", "C"),
            ("TZ", "UTC"),
        ]
        .into_iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
        let spec = CommandSpec::new(program.as_os_str(), args, self.work, env);
        let captured = capture_with_resources(
            &spec,
            CaptureLimits {
                timeout: CAPTURE_TIMEOUT,
                stdout_bytes: 16 * 1024 * 1024,
                stderr_bytes: 16 * 1024 * 1024,
                termination_grace: Duration::from_secs(2),
            },
            RESOURCE_LIMITS,
            SAMPLE_LIMITS,
            &[self.work.to_path_buf(), self.output.to_path_buf()],
            || false,
        )
        .map_err(|error| error.to_string())?;
        if !captured.report.last_sample_complete {
            return Err(
                "bounded command ended without a complete final resource sample".to_owned(),
            );
        }
        Ok(captured.process)
    }
}

struct ReplayContext<'a> {
    adapter: &'a Path,
    python: &'a Path,
    python_library: &'a Path,
    runtime_libraries: &'a [PathBuf],
    runtime_interpreters: &'a [RuntimeInterpreter],
    input_dir: &'a Path,
    reports: &'a Path,
    child: &'a Path,
    home: &'a Path,
    tmp: &'a Path,
    markers: &'a Path,
    runner: &'a RunContext<'a>,
    platform: Platform,
}

#[derive(Clone, Debug)]
struct RuntimeInterpreter {
    binary: PathBuf,
    declared_path: PathBuf,
    canonical_path: PathBuf,
}

fn selected_host() -> Result<(&'static str, Platform), String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok(("macos-aarch64", Platform::Macos)),
        ("linux", "x86_64") => Ok(("linux-x86_64", Platform::Linux)),
        host => Err(format!("unsupported native qualification host: {host:?}")),
    }
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("pin field {key:?} is missing or not a string"))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("pin field {key:?} is missing or not an unsigned integer"))
}

fn required_env_path(name: &str) -> Result<PathBuf, String> {
    let path =
        std::env::var_os(name).ok_or_else(|| format!("required environment {name} is unset"))?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(path)
}

fn create_fresh_private_root(name: &str) -> Result<PathBuf, String> {
    let requested = required_env_path(name)?;
    if requested.exists() || fs::symlink_metadata(&requested).is_ok() {
        return Err(format!("{name} must name a fresh, absent directory"));
    }
    let parent = requested
        .parent()
        .ok_or_else(|| format!("{name} has no parent"))?
        .canonicalize()
        .map_err(|error| format!("resolve {name} parent: {error}"))?;
    let leaf = requested
        .file_name()
        .ok_or_else(|| format!("{name} must name a directory"))?;
    let path = parent.join(leaf);
    create_private_dir(&path)
}

fn create_private_dir(path: &Path) -> Result<PathBuf, String> {
    DirBuilder::new()
        .recursive(false)
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("create private directory {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(display_error)?;
    let canonical = path.canonicalize().map_err(display_error)?;
    let metadata = fs::metadata(&canonical).map_err(display_error)?;
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(format!(
            "private directory has unexpected type or mode: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn canonical_executable(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("resolve {label} {}: {error}", path.display()))?;
    let metadata = fs::metadata(&canonical).map_err(display_error)?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(format!(
            "{label} is not a regular executable: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn find_pinned_python_library(root: &Path, platform: Platform) -> Result<PathBuf, String> {
    let names: &[&str] = if platform == Platform::Macos {
        &["libpython3.12.dylib"]
    } else {
        &["libpython3.12.so.1.0", "libpython3.12.so"]
    };
    let library_root = root.join("python/lib");
    for name in names {
        let path = library_root.join(name);
        if path.exists() {
            let canonical = path.canonicalize().map_err(display_error)?;
            if !fs::metadata(&canonical).map_err(display_error)?.is_file() {
                return Err(format!(
                    "pinned Python library is not a regular file: {}",
                    path.display()
                ));
            }
            return Ok(canonical);
        }
    }
    Err(format!(
        "pinned Python library is missing below {}",
        library_root.display()
    ))
}

fn host_compiler(platform: Platform) -> Result<&'static Path, String> {
    match platform {
        Platform::Macos => Ok(Path::new("/usr/bin/clang")),
        Platform::Linux => Ok(Path::new("/usr/bin/cc")),
    }
}

fn compile_arguments(platform: Platform, source: &Path, output: &Path) -> Vec<OsString> {
    let mut arguments = strings(["-O2", "-Wall", "-Wextra", "-Werror", "-o"]);
    arguments.push(output.as_os_str().to_os_string());
    arguments.push(source.as_os_str().to_os_string());
    if platform == Platform::Linux {
        arguments.push(OsString::from("-ldl"));
    }
    arguments
}

fn embedded_fixture_source(marker: &Path) -> Result<String, String> {
    let marker = marker
        .to_str()
        .ok_or_else(|| "embedded marker path must be UTF-8".to_owned())?;
    let python_path_literal = serde_json::to_string(marker).map_err(display_error)?;
    let marker = c_string_literal(&python_path_literal);
    let source = r#"#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>

#define MARKER_PATH __EMBEDDED_MARKER_PATH__

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: embedded-python-control ABSOLUTE-LIBPYTHON-PATH\n");
        return 2;
    }
    errno = 0;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        int saved_errno = errno;
        fprintf(stderr, "DLOPEN_DENIED errno=%d path=%s message=%s\n", saved_errno, argv[1], dlerror());
        return 77;
    }
    void (*initialize)(void) = (void (*)(void))dlsym(library, "Py_Initialize");
    int (*run_string)(const char *) = (int (*)(const char *))dlsym(library, "PyRun_SimpleString");
    int (*finalize)(void) = (int (*)(void))dlsym(library, "Py_FinalizeEx");
    if (initialize == NULL || run_string == NULL || finalize == NULL) {
        fprintf(stderr, "embedded Python API is incomplete\n");
        dlclose(library);
        return 3;
    }
    initialize();
    const char *source = "open(" MARKER_PATH ", 'w').write('embedded-python-wrote\\n'); "
                         "print('ADAPTER_EMBEDDED_PYTHON_MARKER', flush=True)";
    int result = run_string(source);
    int finalization = finalize();
    dlclose(library);
    return result == 0 && finalization == 0 ? 0 : 4;
}
"#;
    Ok(source.replace("__EMBEDDED_MARKER_PATH__", &marker))
}

fn c_string_literal(value: &str) -> String {
    let mut literal = String::from("\"");
    for byte in value.bytes() {
        match byte {
            b'\\' => literal.push_str("\\\\"),
            b'"' => literal.push_str("\\\""),
            b'\n' => literal.push_str("\\n"),
            b'\r' => literal.push_str("\\r"),
            _ => literal.push(char::from(byte)),
        }
    }
    literal.push('"');
    literal
}

fn require_status(process: &CapturedProcess, expected: i32, label: &str) -> Result<(), String> {
    if process.exit_code() != Some(expected) || process.signal().is_some() {
        return Err(format!(
            "{label}: expected exit {expected}, got exit {:?} signal {:?}; stdout={} stderr={}",
            process.exit_code(),
            process.signal(),
            String::from_utf8_lossy(&process.stdout),
            String::from_utf8_lossy(&process.stderr)
        ));
    }
    Ok(())
}

fn require_text(bytes: &[u8], needle: &str, label: &str) -> Result<(), String> {
    let text = String::from_utf8_lossy(bytes);
    if !text.contains(needle) {
        return Err(format!("{label}: expected {needle:?} in {text:?}"));
    }
    Ok(())
}

fn require_no_text(bytes: &[u8], needle: &str, label: &str) -> Result<(), String> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains(needle) {
        return Err(format!("{label}: unexpected {needle:?} in {text:?}"));
    }
    Ok(())
}

fn ensure_only_marker(directory: &Path, expected: &str) -> Result<(), String> {
    let mut names = fs::read_dir(directory)
        .map_err(display_error)?
        .map(|entry| {
            entry
                .map_err(display_error)?
                .file_name()
                .into_string()
                .map_err(|_| "marker filename is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    names.sort();
    if names.len() != 1 || names.first().map(String::as_str) != Some(expected) {
        return Err(format!("unexpected restricted marker files: {names:?}"));
    }
    Ok(())
}

fn unconfined_case(name: &str, process: &CapturedProcess) -> Value {
    json!({
        "name": name,
        "adapter_report": false,
        "exit_code": process.exit_code(),
        "signal": process.signal(),
        "stdout": String::from_utf8_lossy(&process.stdout),
        "stderr": String::from_utf8_lossy(&process.stderr),
    })
}

struct RestrictedCase {
    case: Value,
    stdout: String,
    stderr: String,
}

fn run_adapter_control(
    context: &ReplayContext<'_>,
    name: &str,
    mode: &str,
    option: &str,
    argument: &Path,
    marker: &str,
) -> Result<RestrictedCase, String> {
    let args = strings(["--control", mode, option])
        .into_iter()
        .chain([argument.as_os_str().to_os_string()])
        .collect::<Vec<_>>();
    let execs = if mode == "shebang" {
        vec![context.adapter.to_path_buf(), argument.to_path_buf()]
    } else {
        vec![context.adapter.to_path_buf()]
    };
    let text = policy_text(&execs, context)?;
    let policy = policy_path(context.input_dir, name, &text)?;
    let outcome = run_restricted(name, context, context.adapter, &args, &policy, 0)?;
    require_text(outcome.stdout.as_bytes(), marker, name)?;
    Ok(outcome)
}

fn run_restricted(
    name: &str,
    context: &ReplayContext<'_>,
    command: &Path,
    args: &[OsString],
    policy: &Path,
    expected_status: i32,
) -> Result<RestrictedCase, String> {
    let report_dir = context.reports.join(name);
    if report_dir.exists() {
        return Err(format!(
            "adapter report directory already exists: {}",
            report_dir.display()
        ));
    }
    let mut adapter_args = strings(["--policy"]);
    adapter_args.push(policy.as_os_str().to_os_string());
    adapter_args.extend(strings(["--report-dir"]));
    adapter_args.push(report_dir.as_os_str().to_os_string());
    adapter_args.extend(strings(["--run", "--"]));
    adapter_args.push(command.as_os_str().to_os_string());
    adapter_args.extend(args.iter().cloned());
    let process = context.runner.run(context.adapter, adapter_args)?;
    require_status(&process, expected_status, name)?;
    let report_path = report_dir.join("report.json");
    let report_bytes = fs::read(&report_path)
        .map_err(|error| format!("read adapter report for {name}: {error}"))?;
    let report: Value = serde_json::from_slice(&report_bytes)
        .map_err(|error| format!("parse adapter report for {name}: {error}"))?;
    if report.get("schema").and_then(Value::as_str) != Some("consumer-enforcement-adapter-a1")
        || report
            .get("qualification_evidence_valid")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(format!(
            "{name}: adapter report did not validate its evidence"
        ));
    }
    let child_status = report
        .get("exit_code")
        .or_else(|| report.get("child_exit_code"))
        .and_then(Value::as_i64);
    if child_status != Some(i64::from(expected_status)) {
        return Err(format!(
            "{name}: report child exit status is {child_status:?}"
        ));
    }
    if report
        .get("network_outbound_allowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(format!("{name}: report did not record network denial"));
    }
    if !report_path.is_file() {
        return Err(format!("{name}: durable adapter report is missing"));
    }
    let stdout_path = report_dir.join("stdout.raw");
    let stderr_path = report_dir.join("stderr.raw");
    let stdout_bytes = fs::read(&stdout_path).map_err(display_error)?;
    let stderr_bytes = fs::read(&stderr_path).map_err(display_error)?;
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    let case = json!({
        "name": name,
        "adapter_report": {
            "path": report_path.display().to_string(),
            "sha256": ami_rust_core::digest::sha256_bytes(&report_bytes),
            "qualification_evidence_valid": true,
            "child_exit_code": expected_status,
            "network_outbound_allowed": false,
        },
        "outer_exit_code": process.exit_code(),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": ami_rust_core::digest::sha256_bytes(&stdout_bytes),
        "stderr_sha256": ami_rust_core::digest::sha256_bytes(&stderr_bytes),
        "policy_path": policy.display().to_string(),
        "policy_sha256": sha256_file(policy).map_err(|error| error.to_string())?,
    });
    Ok(RestrictedCase {
        case,
        stdout,
        stderr,
    })
}

fn policy_text(execs: &[PathBuf], context: &ReplayContext<'_>) -> Result<String, String> {
    let mut text = String::from("consumer-policy-v1\n");
    if context.platform == Platform::Linux {
        // Exact read access for std::process::Command's null stdin. This
        // neither grants execution nor opens the rest of /dev for reads.
        text.push_str("read-file /dev/null\n");
    }
    let mut seen_execs = BTreeSet::<PathBuf>::new();
    for executable in execs.iter().chain(
        context
            .runtime_interpreters
            .iter()
            .map(|interpreter| &interpreter.canonical_path),
    ) {
        let executable = executable.canonicalize().map_err(display_error)?;
        if seen_execs.insert(executable.clone()) {
            text.push_str(&format!(
                "exec-hash {} {}\n",
                executable.display(),
                sha256_file(&executable).map_err(|error| error.to_string())?
            ));
        }
    }
    for library in context.runtime_libraries {
        let library = library.canonicalize().map_err(display_error)?;
        if library != context.python_library {
            text.push_str(&format!("read-file {}\n", library.display()));
        }
    }
    text.push_str(&format!("deny-exec {}\n", context.python.display()));
    text.push_str(&format!(
        "deny-library {}\n",
        context.python_library.display()
    ));
    if context.platform == Platform::Macos {
        let mut directories = BTreeSet::new();
        for path in execs
            .iter()
            .chain(context.runtime_libraries)
            .map(PathBuf::as_path)
            .chain([
                context.python,
                context.python_library,
                context.child,
                context.home,
                context.tmp,
                context.markers,
            ])
        {
            let canonical = path.canonicalize().map_err(display_error)?;
            for ancestor in canonical.ancestors().skip(1) {
                if ancestor == context.child || ancestor.starts_with(context.child) {
                    continue;
                }
                if ancestor.is_dir() {
                    directories.insert(ancestor.to_path_buf());
                }
            }
        }
        directories.insert(context.child.to_path_buf());
        directories.insert(context.home.to_path_buf());
        directories.insert(context.tmp.to_path_buf());
        directories.insert(context.markers.to_path_buf());
        for directory in directories {
            text.push_str(&format!("read-directory {}\n", directory.display()));
        }
    }
    text.push_str(&format!(
        "read-tree work {}\nwrite-tree work {}\n",
        context.child.display(),
        context.child.display()
    ));
    for (key, value) in [
        ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin".to_owned()),
        ("HOME", context.home.display().to_string()),
        ("TMPDIR", context.tmp.display().to_string()),
        ("LC_ALL", "C".to_owned()),
        ("TZ", "UTC".to_owned()),
    ] {
        text.push_str(&format!("env {key}={value}\n"));
    }
    text.push_str(&format!("cwd {}\nnetwork deny\n", context.child.display()));
    Ok(text)
}

fn linux_runtime_interpreters(binaries: &[PathBuf]) -> Result<Vec<RuntimeInterpreter>, String> {
    let mut interpreters = Vec::with_capacity(binaries.len());
    for binary in binaries {
        let bytes = fs::read(binary)
            .map_err(|error| format!("read native ELF {}: {error}", binary.display()))?;
        let declared_path = parse_elf_pt_interp(&bytes)
            .map_err(|error| format!("inspect native ELF {}: {error}", binary.display()))?;
        let canonical_path = canonical_executable(&declared_path, "ELF PT_INTERP")?;
        interpreters.push(RuntimeInterpreter {
            binary: binary.clone(),
            declared_path,
            canonical_path,
        });
    }
    if interpreters.is_empty() {
        return Err("no native ELF binaries were supplied for PT_INTERP inspection".to_owned());
    }
    Ok(interpreters)
}

fn parse_elf_pt_interp(bytes: &[u8]) -> Result<PathBuf, String> {
    const ELF_HEADER_SIZE: usize = 64;
    const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
    const PT_INTERP: u32 = 3;

    if bytes.len() < ELF_HEADER_SIZE || bytes.get(..4) != Some(&b"\x7fELF"[..]) {
        return Err("missing or truncated ELF64 header".to_owned());
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err("expected ELF64 little-endian current-version input".to_owned());
    }

    let object_type = read_elf_u16(bytes, 16, "e_type")?;
    if !matches!(object_type, 2 | 3) {
        return Err(format!("unsupported ELF object type {object_type}"));
    }
    let machine = read_elf_u16(bytes, 18, "e_machine")?;
    if machine != 62 {
        return Err(format!("expected x86-64 ELF machine 62, got {machine}"));
    }
    if read_elf_u32(bytes, 20, "e_version")? != 1 {
        return Err("ELF header has an unsupported version".to_owned());
    }
    if usize::from(read_elf_u16(bytes, 52, "e_ehsize")?) != ELF_HEADER_SIZE {
        return Err("ELF header has an unexpected size".to_owned());
    }

    let program_header_offset = usize::try_from(read_elf_u64(bytes, 32, "e_phoff")?)
        .map_err(|_| "ELF program-header offset is not representable".to_owned())?;
    let program_header_size = usize::from(read_elf_u16(bytes, 54, "e_phentsize")?);
    if program_header_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "ELF program-header size is {program_header_size}, expected {ELF64_PROGRAM_HEADER_SIZE}"
        ));
    }
    let program_header_count = usize::from(read_elf_u16(bytes, 56, "e_phnum")?);
    if program_header_count == 0 || program_header_count == usize::from(u16::MAX) {
        return Err(
            "ELF program-header count is missing or uses unsupported extended numbering".to_owned(),
        );
    }
    let program_header_bytes = program_header_count
        .checked_mul(program_header_size)
        .ok_or_else(|| "ELF program-header table size overflows".to_owned())?;
    let program_header_end = program_header_offset
        .checked_add(program_header_bytes)
        .ok_or_else(|| "ELF program-header table end overflows".to_owned())?;
    if program_header_end > bytes.len() {
        return Err("ELF program-header table is truncated".to_owned());
    }

    let mut interpreter = None;
    for index in 0..program_header_count {
        let entry_offset = program_header_offset
            .checked_add(
                index
                    .checked_mul(program_header_size)
                    .ok_or_else(|| "ELF program-header offset overflows".to_owned())?,
            )
            .ok_or_else(|| "ELF program-header offset overflows".to_owned())?;
        if read_elf_u32(bytes, entry_offset, "p_type")? != PT_INTERP {
            continue;
        }
        if interpreter.is_some() {
            return Err("ELF contains more than one PT_INTERP segment".to_owned());
        }

        let path_offset = usize::try_from(read_elf_u64(bytes, entry_offset + 8, "p_offset")?)
            .map_err(|_| "ELF PT_INTERP offset is not representable".to_owned())?;
        let path_size = usize::try_from(read_elf_u64(bytes, entry_offset + 32, "p_filesz")?)
            .map_err(|_| "ELF PT_INTERP size is not representable".to_owned())?;
        if path_size < 2 {
            return Err("ELF PT_INTERP path is empty or lacks a terminator".to_owned());
        }
        let path_end = path_offset
            .checked_add(path_size)
            .ok_or_else(|| "ELF PT_INTERP end overflows".to_owned())?;
        let path_bytes = bytes
            .get(path_offset..path_end)
            .ok_or_else(|| "ELF PT_INTERP segment is truncated".to_owned())?;
        if path_bytes.last() != Some(&0) || path_bytes[..path_bytes.len() - 1].contains(&0) {
            return Err("ELF PT_INTERP path is not a single NUL-terminated string".to_owned());
        }
        let path_text = std::str::from_utf8(&path_bytes[..path_bytes.len() - 1])
            .map_err(|error| format!("ELF PT_INTERP path is not UTF-8: {error}"))?;
        if path_text.chars().any(char::is_control) {
            return Err("ELF PT_INTERP path contains unsupported control characters".to_owned());
        }
        let path = PathBuf::from(path_text);
        if !path.is_absolute() {
            return Err("ELF PT_INTERP path is not absolute".to_owned());
        }
        interpreter = Some(path);
    }

    interpreter.ok_or_else(|| "ELF has no PT_INTERP segment".to_owned())
}

fn read_elf_u16(bytes: &[u8], offset: usize, field: &str) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| format!("ELF {field} offset overflows"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| format!("ELF {field} is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_elf_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format!("ELF {field} offset overflows"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| format!("ELF {field} is truncated"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_elf_u64(bytes: &[u8], offset: usize, field: &str) -> Result<u64, String> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| format!("ELF {field} offset overflows"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| format!("ELF {field} is truncated"))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn linux_runtime_libraries(
    binaries: &[PathBuf],
    runner: &RunContext<'_>,
) -> Result<Vec<PathBuf>, String> {
    let mut libraries = BTreeSet::new();
    for binary in binaries {
        let output = runner.run(
            Path::new("/usr/bin/ldd"),
            vec![binary.as_os_str().to_os_string()],
        )?;
        require_status(&output, 0, "inspect Linux runtime dependencies")?;
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|error| format!("ldd output is not UTF-8: {error}"))?;
        for line in text.lines() {
            let line = line.trim();
            let token = line.split_once("=>").map_or_else(
                || line.split_whitespace().next().unwrap_or_default(),
                |(_, right)| right.split_whitespace().next().unwrap_or_default(),
            );
            if token == "not" {
                return Err(format!("unresolved Linux runtime dependency: {line}"));
            }
            if token.starts_with('/') {
                let path = PathBuf::from(token)
                    .canonicalize()
                    .map_err(|error| format!("resolve Linux runtime library {token}: {error}"))?;
                if !fs::metadata(&path).map_err(display_error)?.is_file() {
                    return Err(format!(
                        "Linux runtime dependency is not a file: {}",
                        path.display()
                    ));
                }
                libraries.insert(path);
            }
        }
    }
    if libraries.is_empty() {
        return Err("ldd found no file-backed dependencies for the native controls".to_owned());
    }
    Ok(libraries.into_iter().collect())
}

fn policy_path(input_dir: &Path, name: &str, text: &str) -> Result<PathBuf, String> {
    let path = input_dir.join(format!("{name}.policy"));
    write_new_private(&path, text.as_bytes())?;
    Ok(path)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("create private file {}: {error}", path.display()))?;
    file.write_all(bytes).map_err(display_error)?;
    file.sync_all().map_err(display_error)
}

fn set_executable(path: &Path) -> Result<(), String> {
    let mut permissions = fs::metadata(path).map_err(display_error)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).map_err(display_error)
}

fn save_progress(
    path: &Path,
    result: &mut Value,
    inputs: &Value,
    cases: &[Value],
    status: &str,
) -> Result<(), String> {
    result["status"] = json!(status);
    result["inputs"] = inputs.clone();
    result["cases"] = json!(cases);
    persist_result(path, result)
}

fn persist_result(path: &Path, result: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(result).map_err(display_error)?;
    fs::write(path, bytes).map_err(display_error)
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod elf_pt_interp_tests {
    use super::parse_elf_pt_interp;
    use std::path::PathBuf;

    #[test]
    fn reads_the_single_absolute_elf_interpreter() {
        let bytes = elf_with_interpreters(&["/lib64/ld-linux-x86-64.so.2"]);
        assert_eq!(
            parse_elf_pt_interp(&bytes).expect("valid ELF PT_INTERP"),
            PathBuf::from("/lib64/ld-linux-x86-64.so.2")
        );
    }

    #[test]
    fn rejects_missing_duplicate_truncated_and_relative_interpreters() {
        let mut missing = elf_with_interpreters(&["/lib64/ld-linux-x86-64.so.2"]);
        missing[64..68].copy_from_slice(&1_u32.to_le_bytes());
        assert!(
            parse_elf_pt_interp(&missing)
                .expect_err("missing PT_INTERP must fail")
                .contains("no PT_INTERP")
        );

        let duplicate =
            elf_with_interpreters(&["/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"]);
        assert!(
            parse_elf_pt_interp(&duplicate)
                .expect_err("duplicate PT_INTERP must fail")
                .contains("more than one PT_INTERP")
        );

        let mut truncated = elf_with_interpreters(&["/lib64/ld-linux-x86-64.so.2"]);
        truncated.pop();
        assert!(
            parse_elf_pt_interp(&truncated)
                .expect_err("truncated PT_INTERP must fail")
                .contains("segment is truncated")
        );

        let mut missing_terminator = elf_with_interpreters(&["/lib64/ld-linux-x86-64.so.2"]);
        *missing_terminator
            .last_mut()
            .expect("path has a terminator") = b'x';
        assert!(
            parse_elf_pt_interp(&missing_terminator)
                .expect_err("unterminated PT_INTERP must fail")
                .contains("NUL-terminated")
        );

        let relative = elf_with_interpreters(&["ld-linux-x86-64.so.2"]);
        assert!(
            parse_elf_pt_interp(&relative)
                .expect_err("relative PT_INTERP must fail")
                .contains("not absolute")
        );
    }

    fn elf_with_interpreters(paths: &[&str]) -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 64;
        const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
        let table_end = ELF_HEADER_SIZE + paths.len() * ELF64_PROGRAM_HEADER_SIZE;
        let mut bytes = vec![0_u8; table_end];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(paths.len() as u16).to_le_bytes());

        let mut path_offset = table_end;
        for (index, path) in paths.iter().enumerate() {
            let header_offset = ELF_HEADER_SIZE + index * ELF64_PROGRAM_HEADER_SIZE;
            bytes[header_offset..header_offset + 4].copy_from_slice(&3_u32.to_le_bytes());
            let path_size = path.len() + 1;
            bytes[header_offset + 8..header_offset + 16]
                .copy_from_slice(&(path_offset as u64).to_le_bytes());
            bytes[header_offset + 32..header_offset + 40]
                .copy_from_slice(&(path_size as u64).to_le_bytes());
            bytes.extend_from_slice(path.as_bytes());
            bytes.push(0);
            path_offset += path_size;
        }
        bytes
    }
}

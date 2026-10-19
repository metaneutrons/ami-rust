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
            "exact file-backed Linux ldd closure for adapter and fixture"
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
    // system profile. Linux grants the exact file-backed ldd closure.
    let runtime_binaries = [adapter.clone(), fixture.clone()];
    let runtime_libraries = if platform == Platform::Linux {
        linux_runtime_libraries(&runtime_binaries, &runner)?
    } else {
        Vec::new()
    };
    if runtime_libraries.iter().any(|path| path == &python_library) {
        return Err("Python library unexpectedly appears in the native runtime closure".to_owned());
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
    result["inputs"] = inputs.clone();
    persist_result(&result_path, &result)?;
    let context = ReplayContext {
        adapter: &adapter,
        python: &python,
        python_library: &python_library,
        runtime_libraries: &runtime_libraries,
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
        "positive"
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
            "ADAPTER_NATIVE_POSITIVE",
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
    let expected_denial = if platform == Platform::Linux {
        "DLOPEN_DENIED errno=13"
    } else {
        "DLOPEN_DENIED errno=1"
    };
    require_text(
        embedded.stderr.as_bytes(),
        expected_denial,
        "restricted embedded denial errno",
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
    input_dir: &'a Path,
    reports: &'a Path,
    child: &'a Path,
    home: &'a Path,
    tmp: &'a Path,
    markers: &'a Path,
    runner: &'a RunContext<'a>,
    platform: Platform,
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
    let mut seen_execs = BTreeSet::<PathBuf>::new();
    for executable in execs {
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

//! Internal host-local ordinary-Cargo qualification for the fixed AROS target.
//!
//! A protected workflow authenticates the retained prerequisite ZIPs before
//! placing their profile roots in the request. This command checks the roots
//! against the candidate profiles embedded in the compiled xtask, builds the
//! current source's host linker with the pinned host bootstrap, composes the
//! prefix, and runs ordinary Cargo against local workspace/path packages
//! through an isolated rustup registration. It does not qualify application
//! of a versioned or published crate. It is not a downloader, SDK manager, or
//! publisher.

use crate::native_prefix_compose;
use ami_rust_core::{
    Refusal, Result,
    component_archive::{self, ArchiveFormat, ArchiveLimits, ComponentArchiveSpec},
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    directory::Directory,
    files::read_regular_bounded,
    json::{JsonProfile, parse_json_value},
    ownership,
    qualification_command::{self as core_qualification_command, CommandBudgets, CommandRequest},
    workspace_accounting::{self, ScanLimits},
};
use aros_native_build::Toolchain;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Instant,
};

const REQUEST_SCHEMA: &str = "ami-rust-native-cargo-qualification-request-v1";
const RESULT_SCHEMA: &str = "ami-rust-native-cargo-qualification-result-v1";
const PREREQUISITES: &[u8] =
    include_bytes!("../../../../release/native-cargo-qualification-prerequisites.json");
const PREREQUISITES_SHA256: &str =
    "31487c9232b9ec7383d33f5ff3b2798a21b28ce85af68c9ebb8b565df041ccf6";
const VENDOR_BYTES: u64 = 2_331_800;
const VENDOR_SHA256: &str = "dea3c4d945f31406cdfe824581592a9253f1afcffe8423e8a1bc9f528b2267b0";
const VENDOR_SOURCE_LOCKS: [(&str, &str); 2] = [
    (
        "Cargo.lock",
        "02f61cc56fb56caf1b03c2e900f14e829e938fd2e365c747203a7b664152fffd",
    ),
    (
        "tooling/Cargo.lock",
        "d129ef969b4a8b926e9c7e8403472dfa56337da2ff841b7098b2f47793c79efe",
    ),
];
const HOST_BOOTSTRAP_COMMIT: &str = "48a229ceaefd4985c50990b14116b6d856af0985";
const HOST_BOOTSTRAP_CARGO_COMMIT: &str = "797e8a9bca276c1c9f9f738d2a20f484fa4eea9d";
const NATIVE_CARGO_COMMIT: &str = "3efb1f477e99b42974b982d939fd100303cdf7db";
const TOOLCHAIN_NAME: &str = "aros-0.2.0-dev";
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_COMMAND_SECONDS: u64 = 1_200;
const MAX_ACTIVE_SECONDS: u64 = 5_100;
const MAX_RSS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_WORKSPACE_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONSUMER_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ELF_BYTES: u64 = 4 * 1024 * 1024;
const MAX_NATIVE_OBJECT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
struct Request {
    host_key: String,
    rust_host_triple: String,
    source_root: PathBuf,
    managed_root: PathBuf,
    work_root: PathBuf,
    output_root: PathBuf,
    component_roots: [PathBuf; 6],
    bootstrap_cargo: PathBuf,
    bootstrap_rustc: PathBuf,
    rustup: PathBuf,
}

#[derive(Clone, Debug)]
struct CommandOutcome {
    label: String,
    request: CommandRequest,
    request_path: PathBuf,
    request_sha256: String,
    result_sha256: String,
    result_path: PathBuf,
    binding: core_qualification_command::CommandBinding,
    passed: bool,
    refusal: Option<String>,
    capture_complete: bool,
    capture_error: Option<String>,
    child_exit_code: Option<i32>,
    child_signal: Option<i32>,
    stdout: String,
    stdout_bytes: u64,
    stdout_sha256: String,
    stderr_bytes: u64,
    stderr_sha256: String,
    aggregate_peak_rss_bytes: u64,
    peak_workspace_bytes: u64,
    peak_log_bytes: u64,
    sample_count: u64,
    last_sample_complete: bool,
    incomplete_cleanup: bool,
}

#[derive(Clone)]
struct ExpectedCargoFailure {
    label: &'static str,
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    environment: BTreeMap<String, String>,
    required_roots: Vec<String>,
    diagnostic_fragments: &'static [&'static str],
}

struct RunState {
    request: Request,
    started: Instant,
    commands: Vec<Value>,
    total_log_bytes: u64,
    consumer_artifact_bytes: u64,
}

#[derive(Clone, Copy)]
struct Variant {
    key: &'static str,
    package: &'static str,
    binary: &'static str,
    feature: Option<&'static str>,
    testing: bool,
    elf_variant: &'static str,
}

struct CargoEnvironmentInputs<'a> {
    state: &'a RunState,
    source_root: &'a Path,
    variant_root: &'a Path,
    cargo_home: &'a Path,
    rustup_home: &'a Path,
    target_root: &'a Path,
    vendor_root: &'a Path,
    prefix: &'a Path,
    overrides: Option<&'a BTreeMap<String, String>>,
}

const VARIANTS: [Variant; 5] = [
    Variant {
        key: "core",
        package: "ami-rust-minimal",
        binary: "ami-rust-minimal",
        feature: None,
        testing: false,
        elf_variant: "core",
    },
    Variant {
        key: "alloc",
        package: "ami-rust-minimal",
        binary: "ami-rust-minimal",
        feature: Some("alloc"),
        testing: false,
        elf_variant: "core",
    },
    Variant {
        key: "qualification",
        package: "ami-rust-qualification",
        binary: "ami-rust-qualification",
        feature: None,
        testing: true,
        elf_variant: "default",
    },
    Variant {
        key: "dependencies",
        package: "ami-rust-dependencies",
        binary: "ami-rust-dependencies",
        feature: None,
        testing: true,
        elf_variant: "deps",
    },
    Variant {
        key: "sha256sum",
        package: "ami-rust-sha256sum",
        binary: "ami-rust-sha256sum",
        feature: None,
        testing: false,
        elf_variant: "default",
    },
];

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    if arguments.next().as_deref() != Some(OsStr::new("--request")) {
        return Err(usage());
    }
    let request_path = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| Refusal::new("native Cargo request path is missing"))?,
    );
    if arguments.next().is_some() {
        return Err(usage());
    }
    let raw = read_regular_bounded(&request_path, MAX_REQUEST_BYTES)?;
    let value = parse_json_value(&raw, JsonProfile::PackageMetadataStateSelection)?;
    let request = parse_request(&value)?;
    let started = Instant::now();
    validate_inputs(&request)?;
    create_run_directories(&request)?;

    let mut state = RunState {
        request,
        started,
        commands: Vec::new(),
        total_log_bytes: 0,
        consumer_artifact_bytes: 0,
    };
    let result = run_campaign(&mut state, &raw);
    match result {
        Ok(value) => {
            let output_path = state.request.output_root.join("result.json");
            write_new_json(&output_path, &value)?;
            println!("{}", serde_json::to_string(&value).map_err(json_error)?);
            Ok(())
        }
        Err(error) => {
            let failure = json!({
                "schema": RESULT_SCHEMA,
                "status": "FAILED",
                "request_sha256": sha256_bytes(&raw),
                "error": error.to_string(),
                "commands": state.commands,
                "log_bytes": state.total_log_bytes,
                "consumer_artifact_bytes": state.consumer_artifact_bytes,
                "active_seconds": state.started.elapsed().as_secs(),
                "claim": "Failure receipt only. A missing result.json or status other than PASS is never qualification evidence."
            });
            let failure_path = state.request.output_root.join("failure.json");
            if !failure_path.exists() {
                let _ = write_new_json(&failure_path, &failure);
            }
            Err(error)
        }
    }
}

fn parse_request(value: &Value) -> Result<Request> {
    require_keys(
        value,
        &[
            "schema",
            "host_key",
            "rust_host_triple",
            "source_root",
            "managed_root",
            "work_root",
            "output_root",
            "component_roots",
            "bootstrap",
        ],
        "native Cargo request",
    )?;
    if text(value, "schema")? != REQUEST_SCHEMA {
        return Err(Refusal::new("native Cargo request schema is unsupported"));
    }
    let roots = get(value, "component_roots")?;
    require_keys(
        roots,
        &[
            "rust",
            "cargo",
            "llvm",
            "csdk",
            "collector",
            "target_libraries",
        ],
        "native Cargo component roots",
    )?;
    let bootstrap = get(value, "bootstrap")?;
    require_keys(
        bootstrap,
        &["cargo", "rustc", "rustup"],
        "native Cargo bootstrap tools",
    )?;
    Ok(Request {
        host_key: text(value, "host_key")?.to_owned(),
        rust_host_triple: text(value, "rust_host_triple")?.to_owned(),
        source_root: PathBuf::from(text(value, "source_root")?),
        managed_root: PathBuf::from(text(value, "managed_root")?),
        work_root: PathBuf::from(text(value, "work_root")?),
        output_root: PathBuf::from(text(value, "output_root")?),
        component_roots: [
            PathBuf::from(text(roots, "rust")?),
            PathBuf::from(text(roots, "cargo")?),
            PathBuf::from(text(roots, "llvm")?),
            PathBuf::from(text(roots, "csdk")?),
            PathBuf::from(text(roots, "collector")?),
            PathBuf::from(text(roots, "target_libraries")?),
        ],
        bootstrap_cargo: PathBuf::from(text(bootstrap, "cargo")?),
        bootstrap_rustc: PathBuf::from(text(bootstrap, "rustc")?),
        rustup: PathBuf::from(text(bootstrap, "rustup")?),
    })
}

fn validate_inputs(request: &Request) -> Result<()> {
    if sha256_bytes(PREREQUISITES) != PREREQUISITES_SHA256 {
        return Err(Refusal::new(
            "compiled prerequisite manifest differs from its reviewed identity",
        ));
    }
    let manifest = parse_json_value(PREREQUISITES, JsonProfile::PackageMetadataStateSelection)?;
    if text(&manifest, "schema")? != "ami-rust-native-cargo-qualification-prerequisites-v1" {
        return Err(Refusal::new(
            "embedded prerequisite manifest schema is invalid",
        ));
    }
    let source_root = existing_directory(&request.source_root, "candidate source root")?;
    let managed_root = existing_directory(&request.managed_root, "managed root")?;
    if source_root != request.source_root || managed_root != request.managed_root {
        return Err(Refusal::new(
            "source and managed roots must use canonical directory paths",
        ));
    }
    ownership::require_disjoint(
        &managed_root,
        &source_root,
        "managed root overlaps the read-only source checkout",
    )?;
    let _host = native_prefix_compose::verify_candidate_source(
        &request.host_key,
        &request.rust_host_triple,
        &source_root,
    )?;
    let mut canonical_components = Vec::with_capacity(request.component_roots.len());
    for root in &request.component_roots {
        let canonical = existing_directory(root, "authenticated component profile root")?;
        if canonical != *root {
            return Err(Refusal::new(
                "component roots must use canonical directory paths",
            ));
        }
        if !canonical.starts_with(&managed_root) {
            return Err(Refusal::new(
                "managed root must include every extracted prerequisite component",
            ));
        }
        canonical_components.push(canonical);
    }
    for left in 0..canonical_components.len() {
        for right in left + 1..canonical_components.len() {
            ownership::require_disjoint(
                &canonical_components[left],
                &canonical_components[right],
                "authenticated component roots overlap",
            )?;
        }
    }
    let bootstrap_cargo = executable_file(&request.bootstrap_cargo, "host bootstrap Cargo")?;
    let bootstrap_rustc = executable_file(&request.bootstrap_rustc, "host bootstrap rustc")?;
    let rustup = executable_file(&request.rustup, "rustup executable")?;
    if bootstrap_cargo != request.bootstrap_cargo
        || bootstrap_rustc != request.bootstrap_rustc
        || rustup != request.rustup
    {
        return Err(Refusal::new(
            "bootstrap executable paths must be canonical regular-file paths",
        ));
    }
    if bootstrap_cargo == bootstrap_rustc || bootstrap_cargo == rustup || bootstrap_rustc == rustup
    {
        return Err(Refusal::new(
            "host bootstrap Cargo, rustc and rustup must be distinct executables",
        ));
    }
    let work = fresh_path(&request.work_root, "work root")?;
    let output = fresh_path(&request.output_root, "output root")?;
    if work != request.work_root || output != request.output_root {
        return Err(Refusal::new(
            "work and output paths must use canonical existing parents",
        ));
    }
    if !work.starts_with(&managed_root) || !output.starts_with(&managed_root) {
        return Err(Refusal::new(
            "managed root must include both work and output roots",
        ));
    }
    ownership::require_disjoint(&work, &output, "work and output roots overlap")?;
    ownership::require_disjoint(&work, &source_root, "work root overlaps source")?;
    ownership::require_disjoint(&output, &source_root, "output root overlaps source")?;
    for root in &request.component_roots {
        ownership::require_disjoint(&work, root, "work root overlaps a component")?;
        ownership::require_disjoint(&output, root, "output root overlaps a component")?;
        ownership::require_disjoint(&source_root, root, "source overlaps a component")?;
    }
    let source_lock = existing_regular(&source_root.join("Cargo.lock"), "workspace Cargo.lock")?;
    let tooling_lock = existing_regular(
        &source_root.join("tooling/Cargo.lock"),
        "tooling Cargo.lock",
    )?;
    if source_lock == tooling_lock {
        return Err(Refusal::new("workspace locks must be distinct files"));
    }
    Ok(())
}

fn create_run_directories(request: &Request) -> Result<()> {
    create_private_dir(&request.work_root)?;
    create_private_dir(&request.output_root)?;
    for name in ["requests", "records", "artifacts", "native-objects"] {
        create_private_dir(&request.output_root.join(name))?;
    }
    for name in ["home", "tmp", "linker-cargo-home", "linker-target"] {
        create_private_dir(&request.work_root.join(name))?;
    }
    Ok(())
}

fn source_copy_destinations(work_root: &Path) -> [PathBuf; 2] {
    [
        work_root.join("root a/source"),
        work_root.join("root b/source"),
    ]
}

fn prepare_source_copy(source: &Path, destination: &Path) -> Result<Vec<String>> {
    let parent = destination
        .parent()
        .ok_or_else(|| Refusal::new("fresh source-copy path has no parent"))?;
    create_private_dir(parent)?;
    copy_arguments(source, destination)
}

fn run_campaign(state: &mut RunState, raw_request: &[u8]) -> Result<Value> {
    let source = state.request.source_root.clone();
    let work = state.request.work_root.clone();
    let managed = state.request.managed_root.clone();
    let bootstrap_cargo = state.request.bootstrap_cargo.clone();
    let rustup = state.request.rustup.clone();
    let host_key = state.request.host_key.clone();
    let rust_host_triple = state.request.rust_host_triple.clone();
    let input_lock_sha = sha256_file(&source.join("Cargo.lock"))?;
    let input_tooling_lock_sha = sha256_file(&source.join("tooling/Cargo.lock"))?;

    verify_host_bootstrap(state)?;
    let vendor_root = extract_vendor(state)?;
    let linker_cargo_home = work.join("linker-cargo-home");
    write_cargo_vendor_config(&linker_cargo_home, &vendor_root, None)?;
    let linker_target = work.join("linker-target");
    let h_env = bootstrap_environment(state, &linker_cargo_home, &linker_target)?;
    let source_tooling = source.join("tooling");
    let linker_args = vec![
        "build".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
        "--release".to_owned(),
        "--target".to_owned(),
        rust_host_triple.clone(),
        "-p".to_owned(),
        "aros-native-build".to_owned(),
        "--bin".to_owned(),
        "aros-link".to_owned(),
        "-j".to_owned(),
        "2".to_owned(),
    ];
    let linker_outcome = execute(
        state,
        "source-linker-build",
        &bootstrap_cargo,
        &linker_args,
        &source_tooling,
        h_env,
    )?;
    require_pass(&linker_outcome)?;
    let linker_release = linker_target.join(&rust_host_triple).join("release");
    let linker_path = linker_release.join("aros-link");
    // Cargo inherits the private harness umask; the component contract is 0755.
    Directory::open(&linker_release)?
        .regular(OsStr::new("aros-link"))?
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    let (linker_bytes, linker_sha256) = executable_identity(&linker_path, "built aros-link")?;
    let linker_record_sha = linker_outcome.result_sha256.clone();

    let prefix_path = work.join("composed-prefix");
    let composition = native_prefix_compose::compose_candidate(
        &host_key,
        &rust_host_triple,
        &source,
        &prefix_path,
        state.request.component_roots.clone(),
        native_prefix_compose::LinkerIdentity {
            root: linker_target.join(&rust_host_triple).join("release"),
            bytes: linker_bytes,
            sha256: linker_sha256.clone(),
            build_request_sha256: linker_outcome.request_sha256.clone(),
            build_record_sha256: linker_record_sha.clone(),
        },
    )?;
    let toolchain = Toolchain::open(&prefix_path)?;
    toolchain.recheck()?;
    if toolchain.root() != fs::canonicalize(&prefix_path)? {
        return Err(Refusal::new("Toolchain::open selected another prefix"));
    }

    let source_copies = source_copy_destinations(&work);
    let copy_program = fs::canonicalize("/bin/cp")?;
    for (index, destination) in source_copies.iter().enumerate() {
        let args = prepare_source_copy(&source, destination)?;
        let copy = execute(
            state,
            if index == 0 {
                "source-copy-a"
            } else {
                "source-copy-b"
            },
            &copy_program,
            &args,
            &managed,
            minimal_environment(&work),
        )?;
        require_pass(&copy)?;
        existing_directory(destination, "fresh Cargo source root")?;
        if sha256_file(&destination.join("Cargo.lock"))? != input_lock_sha
            || sha256_file(&destination.join("tooling/Cargo.lock"))? != input_tooling_lock_sha
        {
            return Err(Refusal::new("fresh source copy changed a Cargo lock"));
        }
    }

    let mut variant_rows = Vec::new();
    let mut roots = Vec::new();
    for (root_index, source_copy) in source_copies.iter().enumerate() {
        let root_key = if root_index == 0 { "a" } else { "b" };
        let mut root_rows = BTreeMap::new();
        for variant in VARIANTS {
            let label = format!("root-{root_key}-{}", variant.key);
            let variant_root = work.join(format!("root {root_key}/{}", variant.key));
            create_private_dir(&variant_root)?;
            for child in ["home", "tmp", "cargo-home", "rustup-home", "target"] {
                create_private_dir(&variant_root.join(child))?;
            }
            let cargo_home = variant_root.join("cargo-home");
            let target_root = variant_root.join("target");
            write_cargo_vendor_config(&cargo_home, &vendor_root, Some(&prefix_path))?;
            let rustup_home = variant_root.join("rustup-home");
            register_toolchain(state, root_key, variant, &rustup_home, &prefix_path)?;
            let environment = cargo_environment(CargoEnvironmentInputs {
                state,
                source_root: source_copy,
                variant_root: &variant_root,
                cargo_home: &cargo_home,
                rustup_home: &rustup_home,
                target_root: &target_root,
                vendor_root: &vendor_root,
                prefix: &prefix_path,
                overrides: None,
            })?;
            if variant.key == "core" {
                verify_registered_toolchain(
                    state,
                    root_key,
                    source_copy,
                    &environment,
                    &prefix_path,
                )?;
            }
            let args = cargo_build_args(source_copy, variant)?;
            let cargo = execute(state, &label, &rustup, &args, source_copy, environment)?;
            require_pass(&cargo)?;
            let elf_path = target_root.join("x86_64-aros/release").join(variant.binary);
            let elf = retain_elf(state, &label, &elf_path, variant.elf_variant)?;
            let objects = retain_native_objects(
                state,
                &label,
                &target_root,
                &prefix_path,
                toolchain.identity(),
                variant.testing,
            )?;
            root_rows.insert(
                variant.key,
                json!({"elf":elf,"native_objects":objects,"command":command_summary(&cargo)}),
            );
        }
        roots.push(root_rows);
    }
    if roots.len() != 2 {
        return Err(Refusal::new("the two-root Cargo matrix is incomplete"));
    }
    for variant in VARIANTS {
        let left = roots[0]
            .get(variant.key)
            .ok_or_else(|| Refusal::new("first Cargo root is incomplete"))?;
        let right = roots[1]
            .get(variant.key)
            .ok_or_else(|| Refusal::new("second Cargo root is incomplete"))?;
        if left["elf"]["bytes"] != right["elf"]["bytes"]
            || left["elf"]["sha256"] != right["elf"]["sha256"]
            || left["native_objects"] != right["native_objects"]
        {
            return Err(Refusal::new(format!(
                "Cargo variant {} differs between fresh source roots",
                variant.key
            )));
        }
        variant_rows.push(json!({
            "variant":variant.key,
            "package":variant.package,
            "binary":variant.binary,
            "elf_audit":left["elf"]["audit"],
            "elf":left["elf"],
            "native_objects":left["native_objects"]
        }));
    }

    let controls = run_cargo_refusal_controls(
        state,
        &source_copies[0],
        &vendor_root,
        &prefix_path,
        &input_lock_sha,
        &input_tooling_lock_sha,
    )?;
    native_prefix_compose::verify_candidate_source(&host_key, &rust_host_triple, &source)?;
    if sha256_file(&source.join("Cargo.lock"))? != input_lock_sha
        || sha256_file(&source.join("tooling/Cargo.lock"))? != input_tooling_lock_sha
    {
        return Err(Refusal::new(
            "candidate checkout Cargo lock changed during proof",
        ));
    }
    if state.started.elapsed().as_secs() > MAX_ACTIVE_SECONDS {
        return Err(Refusal::new(
            "native Cargo qualification exceeded the 5,100-second active window",
        ));
    }
    if state.total_log_bytes > MAX_LOG_BYTES {
        return Err(Refusal::new("campaign raw logs exceed the 16 MiB cap"));
    }
    if state.consumer_artifact_bytes > MAX_CONSUMER_ARTIFACT_BYTES {
        return Err(Refusal::new(
            "retained consumer artifacts exceed the 64 MiB cap",
        ));
    }

    Ok(json!({
        "schema":RESULT_SCHEMA,
        "status":"PASS_LOCAL_NATIVE_CARGO_QUALIFICATION",
        "request_sha256":sha256_bytes(raw_request),
        "host_key":host_key,
        "rust_host_triple":rust_host_triple,
        "source_root":source,
        "prerequisites_manifest_sha256":PREREQUISITES_SHA256,
        "offline_vendor":{
            "path":"release/inputs/native-cargo-vendor.tar.xz",
            "bytes":VENDOR_BYTES,
            "sha256":VENDOR_SHA256,
            "scope":"Exact 51-package registry union of the pinned application and tooling locks"
        },
        "trust_boundary":"The protected workflow authenticates run metadata, artifact identities and ZIP bytes before staging prerequisite roots. This local record verifies staged profile bytes; the embedded manifest is not GitHub authentication.",
        "source_candidate":{
            "inputs_rs_sha256":sha256_file(&source.join("tooling/crates/aros-native-build/src/inputs.rs"))?,
            "public_view_source_sha256":sha256_file(&source.join("tooling/crates/aros-native-build/src/public_view.rs"))?,
            "public_view_policy_sha256":sha256_file(&source.join("tooling/crates/aros-native-build/pins/public-view-v1.json"))?,
            "portable_view_source_sha256":sha256_file(&source.join("tooling/crates/aros-native-build/src/portable_view.rs"))?,
            "portable_view_policy_sha256":sha256_file(&source.join("tooling/crates/aros-native-build/pins/portable-view-v2.json"))?,
            "target_libraries_sha256":sha256_file(&source.join("tooling/crates/aros-native-build/pins/target-libraries.json"))?,
            "target_spec_sha256":"de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71",
            "workspace_cargo_lock_sha256":input_lock_sha,
            "tooling_cargo_lock_sha256":input_tooling_lock_sha
        },
        "host_bootstrap":{
            "cargo_path":state.request.bootstrap_cargo,
            "rustc_path":state.request.bootstrap_rustc,
            "rustup_path":state.request.rustup,
            "cargo_commit":HOST_BOOTSTRAP_CARGO_COMMIT,
            "rustc_commit":HOST_BOOTSTRAP_COMMIT,
            "hosted_authentication":"The calling workflow supplies and retains the pinned bootstrap archives; command records bind the executables actually used."
        },
        "source_built_linker":{"path":linker_path,"bytes":linker_bytes,"sha256":linker_sha256,"request_sha256":linker_outcome.request_sha256,"record_sha256":linker_record_sha},
        "composed_prefix":{
            "root":toolchain.root(),
            "identity":toolchain.identity(),
            "replaced_official_cargo":composition.receipt.replaced_official_cargo,
            "unmapped_cargo_rows":composition.receipt.unmapped_cargo_rows,
            "unmapped_collector_rows":composition.receipt.unmapped_collector_rows,
            "public_view_policy_sha256":composition.receipt.public_view_policy_sha256,
            "excluded_public_files":composition.receipt.excluded_public_files,
            "portable_view_policy_sha256":composition.receipt.portable_view_policy_sha256,
            "materialized_links":composition.receipt.materialized_links,
            "omitted_generated_aliases":composition.receipt.omitted_generated_aliases,
            "relocated_files":composition.receipt.relocated_files,
            "omitted_installer_files":composition.receipt.omitted_installer_files,
            "permission_changes":composition.receipt.permission_changes,
            "measurement":{
                "files":composition.receipt.measurement.files,
                "symlinks":composition.receipt.measurement.symlinks,
                "directories":composition.receipt.measurement.directories,
                "file_bytes":composition.receipt.measurement.file_bytes
            }
        },
        "matrix":variant_rows,
        "controls":controls,
        "commands":state.commands,
        "limits":{
            "per_command_seconds":MAX_COMMAND_SECONDS,
            "rss_bytes":MAX_RSS_BYTES,
            "workspace_bytes":MAX_WORKSPACE_BYTES,
            "log_bytes":MAX_LOG_BYTES,
            "active_seconds":MAX_ACTIVE_SECONDS,
            "campaign_seconds":5400,
            "finalization_reserve_seconds":300,
            "consumer_artifact_bytes":MAX_CONSUMER_ARTIFACT_BYTES
        },
        "measurement":{
            "active_seconds":state.started.elapsed().as_secs(),
            "qualification_log_bytes":state.total_log_bytes,
            "consumer_artifact_bytes":state.consumer_artifact_bytes,
            "aggregate_campaign_rss":"The protected outer monitor must enforce the 4 GiB campaign aggregate across this driver and all command children; the inner command records retain each observed process-group peak."
        },
        "claim":"One host-local current-source linker build, fixed-prefix composition, Toolchain::open/recheck, and ordinary locked/offline Cargo builds of local workspace/path packages for five variants in two isolated source roots, plus actual Cargo refusals for a missing rustc and wrong linker. This does not qualify a versioned or published crate, cross-host admission, runtime/SDK acceptance, publication, or RC4."
    }))
}

fn verify_host_bootstrap(state: &mut RunState) -> Result<()> {
    let work = state.request.work_root.clone();
    let source = state.request.source_root.clone();
    let cargo_program = state.request.bootstrap_cargo.clone();
    let rustc_program = state.request.bootstrap_rustc.clone();
    let rustup_program = state.request.rustup.clone();
    let cargo_home = work.join("linker-cargo-home");
    let target_root = work.join("linker-target");
    let environment = bootstrap_environment(state, &cargo_home, &target_root)?;
    let cargo_args = vec!["--version".to_owned(), "--verbose".to_owned()];
    let cargo = execute(
        state,
        "bootstrap-cargo-version",
        &cargo_program,
        &cargo_args,
        &source,
        environment.clone(),
    )?;
    require_pass(&cargo)?;
    require_output_contains(
        &cargo.stdout,
        "release: 1.98.1",
        "host bootstrap Cargo release",
    )?;
    require_output_contains(
        &cargo.stdout,
        &format!("commit-hash: {HOST_BOOTSTRAP_CARGO_COMMIT}"),
        "host bootstrap Cargo commit",
    )?;
    require_output_contains(
        &cargo.stdout,
        &format!("host: {}", state.request.rust_host_triple),
        "host bootstrap Cargo triple",
    )?;

    let rustc_args = vec!["-Vv".to_owned()];
    let rustc = execute(
        state,
        "bootstrap-rustc-version",
        &rustc_program,
        &rustc_args,
        &source,
        environment.clone(),
    )?;
    require_pass(&rustc)?;
    require_output_contains(
        &rustc.stdout,
        "release: 1.98.1",
        "host bootstrap rustc release",
    )?;
    require_output_contains(
        &rustc.stdout,
        &format!("commit-hash: {HOST_BOOTSTRAP_COMMIT}"),
        "host bootstrap rustc commit",
    )?;
    require_output_contains(
        &rustc.stdout,
        &format!("host: {}", state.request.rust_host_triple),
        "host bootstrap rustc triple",
    )?;

    let rustup_args = vec!["--version".to_owned()];
    let rustup = execute(
        state,
        "rustup-version",
        &rustup_program,
        &rustup_args,
        &source,
        environment,
    )?;
    require_pass(&rustup)?;
    Ok(())
}

fn extract_vendor(state: &mut RunState) -> Result<PathBuf> {
    for (path, expected) in VENDOR_SOURCE_LOCKS {
        if sha256_file(&state.request.source_root.join(path))? != expected {
            return Err(Refusal::new(format!(
                "native Cargo vendor archive does not match source lock {path}"
            )));
        }
    }
    let archive_path = state
        .request
        .source_root
        .join("release/inputs/native-cargo-vendor.tar.xz");
    let archive = ownership::protected_regular_file(&archive_path, false)?;
    let metadata = archive.metadata()?;
    if metadata.len() != VENDOR_BYTES || sha256_file(&archive_path)? != VENDOR_SHA256 {
        return Err(Refusal::new(
            "tracked Cargo vendor archive differs from its pinned identity",
        ));
    }
    let work = state.request.work_root.clone();
    let managed = Directory::open(&state.request.managed_root)?;
    let measured = workspace_accounting::scan_directory(
        &managed,
        ScanLimits {
            max_entries: 1_000_000,
            max_work_units: 2_000_001,
        },
    )
    .map_err(|error| Refusal::new(format!("managed workspace accounting failed: {error}")))?;
    let limits = ArchiveLimits {
        max_compressed_bytes: VENDOR_BYTES,
        max_decoded_tar_bytes: 512 * 1024 * 1024,
        max_expanded_bytes: 256 * 1024 * 1024,
        max_file_bytes: 64 * 1024 * 1024,
        max_members: 50_000,
        max_index_bytes: 64 * 1024 * 1024,
        max_path_bytes: 4_096,
        max_path_components: 64,
        max_extension_bytes: 1024 * 1024,
        current_workspace_bytes: measured.regular_file_bytes,
        max_workspace_bytes: MAX_WORKSPACE_BYTES,
        xz_memory_limit_kib: 64 * 1024,
    };
    let parent = Directory::open(&work)?;
    let receipt = component_archive::extract_component_archive(
        archive,
        &parent,
        ComponentArchiveSpec {
            destination_name: OsStr::new("vendor-extract"),
            compressed_bytes: VENDOR_BYTES,
            compressed_sha256: VENDOR_SHA256,
            format: ArchiveFormat::TarXz,
            limits,
        },
        || Ok(()),
    )
    .map_err(|error| {
        Refusal::new(format!(
            "could not extract pinned Cargo vendor archive: {error}"
        ))
    })?;
    if receipt.component_root != "vendor" {
        return Err(Refusal::new(
            "pinned Cargo vendor archive has an unexpected component root",
        ));
    }
    let root = work.join("vendor-extract/vendor");
    existing_directory(&root, "extracted Cargo vendor tree")
}

fn bootstrap_environment(
    state: &RunState,
    cargo_home: &Path,
    target_root: &Path,
) -> Result<BTreeMap<String, String>> {
    let work = &state.request.work_root;
    let mut environment = BTreeMap::new();
    environment.insert(
        "PATH".to_owned(),
        format!(
            "{}:/usr/bin:/bin",
            path_text(
                state
                    .request
                    .bootstrap_cargo
                    .parent()
                    .ok_or_else(|| Refusal::new("bootstrap Cargo has no parent"))?
            )?
        ),
    );
    environment.insert("HOME".to_owned(), path_text(&work.join("home"))?);
    environment.insert("TMPDIR".to_owned(), path_text(&work.join("tmp"))?);
    environment.insert("CARGO_HOME".to_owned(), path_text(cargo_home)?);
    environment.insert("CARGO_TARGET_DIR".to_owned(), path_text(target_root)?);
    environment.insert(
        "RUSTC".to_owned(),
        path_text(&state.request.bootstrap_rustc)?,
    );
    environment.insert("CARGO_BUILD_JOBS".to_owned(), "2".to_owned());
    environment.insert("CARGO_INCREMENTAL".to_owned(), "0".to_owned());
    environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    environment.insert("RUSTUP_AUTO_INSTALL".to_owned(), "0".to_owned());
    environment.insert("CARGO_CACHE_RUSTC_INFO".to_owned(), "0".to_owned());
    environment.insert("SOURCE_DATE_EPOCH".to_owned(), "1791936000".to_owned());
    environment.insert("LC_ALL".to_owned(), "C".to_owned());
    environment.insert("TZ".to_owned(), "UTC".to_owned());
    environment.insert("RUSTC_WRAPPER".to_owned(), String::new());
    environment.insert("RUSTC_WORKSPACE_WRAPPER".to_owned(), String::new());
    Ok(environment)
}

fn write_cargo_vendor_config(
    cargo_home: &Path,
    vendor_root: &Path,
    prefix: Option<&Path>,
) -> Result<()> {
    let vendor = toml_string(&path_text(vendor_root)?);
    let mut config = format!(
        "[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"ami-rust-qualification-vendor\"\n\n[source.ami-rust-qualification-vendor]\ndirectory = {vendor}\n"
    );
    if let Some(prefix) = prefix {
        let linker = toml_string(&path_text(&prefix.join("bin/aros-link"))?);
        // The pinned Cargo producer exposes this opt-in mode for fresh private
        // cross-build caches. Keep ordinary Cargo commands while excluding
        // host build-script identities from target crate disambiguators.
        config.push_str(&format!(
            "\n[unstable]\nami-rust-reproducible-cross = true\n\n[target.x86_64-aros]\nlinker = {linker}\n"
        ));
    }
    write_new(&cargo_home.join("config.toml"), config.as_bytes())
}

fn register_toolchain(
    state: &mut RunState,
    root_key: &str,
    variant: Variant,
    rustup_home: &Path,
    prefix: &Path,
) -> Result<()> {
    let source = state.request.source_root.clone();
    let rustup = state.request.rustup.clone();
    let mut environment = minimal_environment(&state.request.work_root);
    environment.insert("RUSTUP_HOME".to_owned(), path_text(rustup_home)?);
    environment.insert(
        "CARGO_HOME".to_owned(),
        path_text(
            &rustup_home
                .parent()
                .ok_or_else(|| Refusal::new("variant root has no parent"))?
                .join("cargo-home"),
        )?,
    );
    environment.insert(
        "PATH".to_owned(),
        format!("{}:/usr/bin:/bin", path_text(&prefix.join("bin"))?),
    );
    let args = vec![
        "toolchain".to_owned(),
        "link".to_owned(),
        TOOLCHAIN_NAME.to_owned(),
        path_text(prefix)?,
    ];
    let outcome = execute(
        state,
        &format!("toolchain-link-{root_key}-{}", variant.key),
        &rustup,
        &args,
        &source,
        environment,
    )?;
    require_pass(&outcome)
}

fn verify_registered_toolchain(
    state: &mut RunState,
    root_key: &str,
    source_root: &Path,
    environment: &BTreeMap<String, String>,
    prefix: &Path,
) -> Result<()> {
    let rustup = state.request.rustup.clone();
    let rustc_args = vec![
        "run".to_owned(),
        TOOLCHAIN_NAME.to_owned(),
        "rustc".to_owned(),
        "-Vv".to_owned(),
    ];
    let rustc = execute(
        state,
        &format!("candidate-rustc-version-{root_key}"),
        &rustup,
        &rustc_args,
        source_root,
        environment.clone(),
    )?;
    require_pass(&rustc)?;
    require_output_contains(
        &rustc.stdout,
        &format!("host: {}", state.request.rust_host_triple),
        "candidate rustc host triple",
    )?;
    let sysroot_args = vec![
        "run".to_owned(),
        TOOLCHAIN_NAME.to_owned(),
        "rustc".to_owned(),
        "--print".to_owned(),
        "sysroot".to_owned(),
    ];
    let sysroot = execute(
        state,
        &format!("candidate-rustc-sysroot-{root_key}"),
        &rustup,
        &sysroot_args,
        source_root,
        environment.clone(),
    )?;
    require_pass(&sysroot)?;
    if sysroot.stdout.trim() != path_text(&fs::canonicalize(prefix)?)? {
        return Err(Refusal::new(
            "rustup selected a sysroot outside the composed native prefix",
        ));
    }
    let cargo_args = vec![
        "run".to_owned(),
        TOOLCHAIN_NAME.to_owned(),
        "cargo".to_owned(),
        "-Vv".to_owned(),
    ];
    let cargo = execute(
        state,
        &format!("candidate-cargo-version-{root_key}"),
        &rustup,
        &cargo_args,
        source_root,
        environment.clone(),
    )?;
    require_pass(&cargo)?;
    require_output_contains(
        &cargo.stdout,
        &format!("commit-hash: {NATIVE_CARGO_COMMIT}"),
        "candidate paired Cargo commit",
    )?;
    require_output_contains(
        &cargo.stdout,
        &format!("host: {}", state.request.rust_host_triple),
        "candidate paired Cargo host triple",
    )?;
    Ok(())
}

fn cargo_environment(inputs: CargoEnvironmentInputs<'_>) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    environment.insert(
        "PATH".to_owned(),
        format!("{}:/usr/bin:/bin", path_text(&inputs.prefix.join("bin"))?),
    );
    environment.insert(
        "HOME".to_owned(),
        path_text(&inputs.variant_root.join("home"))?,
    );
    environment.insert(
        "TMPDIR".to_owned(),
        path_text(&inputs.variant_root.join("tmp"))?,
    );
    environment.insert("CARGO_HOME".to_owned(), path_text(inputs.cargo_home)?);
    environment.insert("RUSTUP_HOME".to_owned(), path_text(inputs.rustup_home)?);
    environment.insert(
        "CARGO_TARGET_DIR".to_owned(),
        path_text(inputs.target_root)?,
    );
    environment.insert(
        "RUSTC".to_owned(),
        path_text(&inputs.prefix.join("bin/rustc"))?,
    );
    environment.insert(
        "RUSTDOC".to_owned(),
        path_text(&inputs.prefix.join("bin/rustdoc"))?,
    );
    environment.insert("CARGO_BUILD_JOBS".to_owned(), "2".to_owned());
    environment.insert("CARGO_INCREMENTAL".to_owned(), "0".to_owned());
    environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    environment.insert("RUSTUP_AUTO_INSTALL".to_owned(), "0".to_owned());
    environment.insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());
    environment.insert("CARGO_TERM_PROGRESS_WHEN".to_owned(), "never".to_owned());
    environment.insert("SOURCE_DATE_EPOCH".to_owned(), "1791936000".to_owned());
    environment.insert("LC_ALL".to_owned(), "C".to_owned());
    environment.insert("TZ".to_owned(), "UTC".to_owned());
    environment.insert("RUSTC_WRAPPER".to_owned(), String::new());
    environment.insert("RUSTC_WORKSPACE_WRAPPER".to_owned(), String::new());
    // Rust uses the last matching prefix. Keep the broad managed-work map
    // before the more specific source/vendor maps so relocated inputs retain
    // their intended canonical paths even when nested below work_root.
    let remaps = [
        "-Zunstable-options".to_owned(),
        format!(
            "--remap-path-prefix={}=/build",
            path_text(&inputs.state.request.work_root)?
        ),
        format!(
            "--remap-path-prefix={}=/ami-rust-source",
            path_text(inputs.source_root)?
        ),
        format!(
            "--remap-path-prefix={}=/cargo-registry",
            path_text(inputs.vendor_root)?
        ),
    ];
    environment.insert("CARGO_ENCODED_RUSTFLAGS".to_owned(), remaps.join("\u{1f}"));
    if let Some(overrides) = inputs.overrides {
        environment.extend(overrides.clone());
    }
    Ok(environment)
}

fn cargo_build_args(source_root: &Path, variant: Variant) -> Result<Vec<String>> {
    let mut args = vec![
        "run".to_owned(),
        TOOLCHAIN_NAME.to_owned(),
        "cargo".to_owned(),
        "build".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
        "--release".to_owned(),
        "--target".to_owned(),
        "x86_64-aros".to_owned(),
        "--manifest-path".to_owned(),
        path_text(&source_root.join("Cargo.toml"))?,
        "--package".to_owned(),
        variant.package.to_owned(),
        "--bin".to_owned(),
        variant.binary.to_owned(),
    ];
    if let Some(feature) = variant.feature {
        args.push("--features".to_owned());
        args.push(feature.to_owned());
    }
    Ok(args)
}

fn run_cargo_refusal_controls(
    state: &mut RunState,
    source_copy: &Path,
    vendor_root: &Path,
    prefix: &Path,
    original_lock_sha: &str,
    original_tooling_lock_sha: &str,
) -> Result<Value> {
    let control_root = state.request.work_root.join("cargo-controls");
    create_private_dir(&control_root)?;
    let cargo_home = control_root.join("cargo-home");
    let rustup_home = control_root.join("rustup-home");
    let home = control_root.join("home");
    let tmp = control_root.join("tmp");
    create_private_dir(&cargo_home)?;
    create_private_dir(&rustup_home)?;
    create_private_dir(&home)?;
    create_private_dir(&tmp)?;
    write_cargo_vendor_config(&cargo_home, vendor_root, Some(prefix))?;
    let mut register_env = minimal_environment(&state.request.work_root);
    register_env.insert("RUSTUP_HOME".to_owned(), path_text(&rustup_home)?);
    register_env.insert("CARGO_HOME".to_owned(), path_text(&cargo_home)?);
    register_env.insert(
        "PATH".to_owned(),
        format!("{}:/usr/bin:/bin", path_text(&prefix.join("bin"))?),
    );
    let rustup = state.request.rustup.clone();
    let registration = execute(
        state,
        "toolchain-link-controls",
        &rustup,
        &[
            "toolchain".to_owned(),
            "link".to_owned(),
            TOOLCHAIN_NAME.to_owned(),
            path_text(prefix)?,
        ],
        source_copy,
        register_env,
    )?;
    require_pass(&registration)?;

    let missing_root = control_root.join("missing-rustc");
    create_private_dir(&missing_root)?;
    let missing_target = missing_root.join("target");
    let missing_overrides = BTreeMap::from([(
        "RUSTC".to_owned(),
        "/ami-rust-controlled-missing-rustc".to_owned(),
    )]);
    let missing_env = cargo_environment(CargoEnvironmentInputs {
        state,
        source_root: source_copy,
        variant_root: &control_root,
        cargo_home: &cargo_home,
        rustup_home: &rustup_home,
        target_root: &missing_target,
        vendor_root,
        prefix,
        overrides: Some(&missing_overrides),
    })?;
    let core = VARIANTS[0];
    let missing_args = cargo_build_args(source_copy, core)?;
    let missing_expectation = ExpectedCargoFailure {
        label: "cargo-missing-rustc-control",
        program: rustup.clone(),
        args: missing_args.clone(),
        cwd: source_copy.to_path_buf(),
        environment: missing_env.clone(),
        required_roots: vec![path_text(&state.request.managed_root)?],
        diagnostic_fragments: &[
            "could not execute process",
            "/ami-rust-controlled-missing-rustc",
            "No such file or directory",
        ],
    };
    let missing = execute(
        state,
        missing_expectation.label,
        &rustup,
        &missing_args,
        source_copy,
        missing_env,
    )?;
    require_expected_failure(&missing, &missing_target, core.binary, &missing_expectation)?;

    let linker_root = control_root.join("wrong-linker");
    create_private_dir(&linker_root)?;
    let wrong_target = linker_root.join("target");
    let wrong_overrides = BTreeMap::from([(
        "CARGO_TARGET_X86_64_AROS_LINKER".to_owned(),
        "/usr/bin/false".to_owned(),
    )]);
    let wrong_env = cargo_environment(CargoEnvironmentInputs {
        state,
        source_root: source_copy,
        variant_root: &control_root,
        cargo_home: &cargo_home,
        rustup_home: &rustup_home,
        target_root: &wrong_target,
        vendor_root,
        prefix,
        overrides: Some(&wrong_overrides),
    })?;
    let wrong_args = cargo_build_args(source_copy, core)?;
    let wrong_expectation = ExpectedCargoFailure {
        label: "cargo-wrong-linker-control",
        program: rustup.clone(),
        args: wrong_args.clone(),
        cwd: source_copy.to_path_buf(),
        environment: wrong_env.clone(),
        required_roots: vec![path_text(&state.request.managed_root)?],
        diagnostic_fragments: &[
            "failed to run custom build command",
            "AROS native bridge",
            "Cargo selected a different target linker",
        ],
    };
    let wrong = execute(
        state,
        wrong_expectation.label,
        &rustup,
        &wrong_args,
        source_copy,
        wrong_env,
    )?;
    require_expected_failure(&wrong, &wrong_target, core.binary, &wrong_expectation)?;
    if sha256_file(&source_copy.join("Cargo.lock"))? != original_lock_sha
        || sha256_file(&source_copy.join("tooling/Cargo.lock"))? != original_tooling_lock_sha
    {
        return Err(Refusal::new("Cargo refusal controls changed a source lock"));
    }
    Ok(json!([
        {"case":"missing RUSTC override","status":"REFUSED_BY_ORDINARY_CARGO","command":command_summary(&missing)},
        {"case":"wrong target linker override","status":"REFUSED_BY_ORDINARY_CARGO","command":command_summary(&wrong)}
    ]))
}

fn require_expected_failure(
    outcome: &CommandOutcome,
    target_root: &Path,
    binary: &str,
    expected: &ExpectedCargoFailure,
) -> Result<()> {
    if outcome.label != expected.label {
        return Err(Refusal::new(format!(
            "negative Cargo control label differs from the expected {}",
            expected.label
        )));
    }
    if outcome.passed || outcome.child_exit_code.unwrap_or(0) == 0 {
        return Err(Refusal::new(format!(
            "negative Cargo control {} unexpectedly succeeded",
            outcome.label
        )));
    }
    let request_bytes = read_regular_bounded(&outcome.request_path, MAX_REQUEST_BYTES)?;
    let expected_request_bytes = serde_json::to_vec(&outcome.request).map_err(json_error)?;
    let expected_program = path_text(&expected.program)?;
    let expected_cwd = path_text(&expected.cwd)?;
    let expected_args_sha256 =
        sha256_bytes(&serde_json::to_vec(&expected.args).map_err(json_error)?);
    let expected_environment_sha256 =
        sha256_bytes(&serde_json::to_vec(&expected.environment).map_err(json_error)?);
    let expected_program_sha256 = sha256_file(&expected.program)?;
    let expected_environment_keys = expected.environment.keys().cloned().collect::<Vec<_>>();
    if request_bytes != expected_request_bytes
        || outcome.request_sha256 != sha256_bytes(&request_bytes)
        || outcome.request.program != expected_program
        || outcome.request.args != expected.args
        || outcome.request.cwd != expected_cwd
        || outcome.request.environment != expected.environment
        || outcome.request.required_roots != expected.required_roots
        || outcome.request.schema != core_qualification_command::REQUEST_SCHEMA
        || outcome.request.limits.seconds == 0
        || outcome.request.limits.seconds > MAX_COMMAND_SECONDS
        || outcome.request.limits.rss_bytes != MAX_RSS_BYTES
        || outcome.request.limits.workspace_bytes != MAX_WORKSPACE_BYTES
        || outcome.request.limits.log_bytes == 0
        || outcome.request.limits.log_bytes > MAX_LOG_BYTES
        || outcome.binding.program != expected_program
        || outcome.binding.program_sha256 != expected_program_sha256
        || outcome.binding.cwd != expected_cwd
        || outcome.binding.args_sha256 != expected_args_sha256
        || outcome.binding.environment_keys != expected_environment_keys
        || outcome.binding.environment_sha256 != expected_environment_sha256
        || !is_sha256_digest(&outcome.binding.helper_sha256)
    {
        return Err(Refusal::new(format!(
            "negative Cargo control {} does not match its pinned command request",
            outcome.label
        )));
    }
    let result_bytes = read_regular_bounded(&outcome.result_path, MAX_REQUEST_BYTES)?;
    let record_directory = outcome
        .result_path
        .parent()
        .ok_or_else(|| Refusal::new("qualified command result has no parent directory"))?;
    let stdout_bytes =
        read_regular_bounded(&record_directory.join("stdout.log"), MAX_LOG_BYTES as usize)?;
    let stderr_bytes =
        read_regular_bounded(&record_directory.join("stderr.log"), MAX_LOG_BYTES as usize)?;
    if sha256_bytes(&result_bytes) != outcome.result_sha256
        || outcome.capture_complete != outcome.capture_error.is_none()
        || !outcome.capture_complete
        || outcome.child_signal.is_some()
        || outcome.refusal.as_deref()
            != outcome
                .child_exit_code
                .map(|code| format!("child exited with status {code}"))
                .as_deref()
        || outcome.sample_count == 0
        || !outcome.last_sample_complete
        || outcome.incomplete_cleanup
        || outcome.aggregate_peak_rss_bytes > MAX_RSS_BYTES
        || outcome.peak_workspace_bytes > MAX_WORKSPACE_BYTES
        || outcome.peak_log_bytes > outcome.request.limits.log_bytes
        || outcome.peak_log_bytes < outcome.stdout_bytes.saturating_add(outcome.stderr_bytes)
        || outcome.stdout_bytes.saturating_add(outcome.stderr_bytes)
            > outcome.request.limits.log_bytes
        || stdout_bytes.len() as u64 != outcome.stdout_bytes
        || sha256_bytes(&stdout_bytes) != outcome.stdout_sha256
        || stderr_bytes.len() as u64 != outcome.stderr_bytes
        || sha256_bytes(&stderr_bytes) != outcome.stderr_sha256
    {
        return Err(Refusal::new(format!(
            "negative Cargo control {} has incomplete capture or failed observer/resource checks",
            outcome.label
        )));
    }
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    if expected
        .diagnostic_fragments
        .iter()
        .any(|fragment| !stderr.contains(fragment))
    {
        return Err(Refusal::new(format!(
            "negative Cargo control {} lacks its expected diagnostic",
            outcome.label
        )));
    }
    let output = target_root.join("x86_64-aros/release").join(binary);
    match fs::symlink_metadata(&output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Refusal::new(format!(
            "failed Cargo control {} left an accepted ELF output",
            outcome.label
        ))),
        Err(error) => Err(error.into()),
    }
}

fn retain_elf(
    state: &mut RunState,
    label: &str,
    source: &Path,
    audit_variant: &str,
) -> Result<Value> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_ELF_BYTES {
        return Err(Refusal::new(format!(
            "Cargo output {label} is not a bounded regular ELF",
        )));
    }
    let bytes = read_regular_bounded(source, MAX_ELF_BYTES as usize)?;
    let audit = aros_elf::elf::audit(&bytes, audit_variant, label)?;
    if audit["result"] != "PASS" || audit["reference_status"]["within_reference_limits"] != true {
        return Err(Refusal::new(format!(
            "Cargo output {label} failed the retained ELF audit",
        )));
    }
    let filename = format!("{label}.elf");
    let destination = state.request.output_root.join("artifacts").join(&filename);
    retain_bytes(state, &destination, &bytes)?;
    Ok(json!({
        "path":filename,
        "bytes":bytes.len(),
        "sha256":sha256_bytes(&bytes),
        "audit":audit
    }))
}

fn retain_native_objects(
    state: &mut RunState,
    label: &str,
    target_root: &Path,
    prefix: &Path,
    toolchain_identity: &str,
    testing: bool,
) -> Result<Value> {
    let build_root = target_root.join("x86_64-aros/release/build");
    let mut metadata_paths = Vec::new();
    let mut remaining_entries = 100_000;
    find_native_metadata(&build_root, 0, &mut metadata_paths, &mut remaining_entries)?;
    if metadata_paths.len() != 1 {
        return Err(Refusal::new(format!(
            "Cargo variant {label} produced {} native object manifests; expected exactly one",
            metadata_paths.len()
        )));
    }
    let manifest_path = metadata_paths
        .pop()
        .ok_or_else(|| Refusal::new("native object manifest disappeared"))?;
    let raw = read_regular_bounded(&manifest_path, 64 * 1024)?;
    let value = parse_json_value(&raw, JsonProfile::PackageMetadataStateSelection)?;
    require_keys(
        &value,
        &[
            "schema",
            "toolchain_root",
            "toolchain_identity",
            "testing",
            "linker",
            "objects",
        ],
        "native object manifest",
    )?;
    if text(&value, "schema")? != "aros-cargo-native-objects-v1"
        || text(&value, "toolchain_root")? != path_text(&fs::canonicalize(prefix)?)?
        || text(&value, "toolchain_identity")? != toolchain_identity
        || value.get("testing").and_then(Value::as_bool) != Some(testing)
    {
        return Err(Refusal::new(format!(
            "Cargo variant {label} native object manifest does not bind the selected prefix",
        )));
    }
    let linker = get(&value, "linker")?;
    require_keys(linker, &["path", "bytes", "sha256"], "native linker row")?;
    let linker_path = prefix.join("bin/aros-link");
    if text(linker, "path")? != "bin/aros-link"
        || integer(linker, "bytes")? != fs::metadata(&linker_path)?.len()
        || text(linker, "sha256")? != sha256_file(&linker_path)?
    {
        return Err(Refusal::new(format!(
            "Cargo variant {label} native objects name another linker",
        )));
    }
    let expected_names: BTreeSet<&str> = if testing {
        ["startup.o", "entry.o", "sdk.o", "layout.o", "bind.o"]
            .into_iter()
            .collect()
    } else {
        ["startup.o", "entry.o", "sdk.o", "layout.o"]
            .into_iter()
            .collect()
    };
    let rows = get(&value, "objects")?
        .as_array()
        .ok_or_else(|| Refusal::new("native object rows are not an array"))?;
    if rows.len() != expected_names.len() {
        return Err(Refusal::new(format!(
            "Cargo variant {label} native object row count is wrong",
        )));
    }
    let native_dir = manifest_path
        .parent()
        .ok_or_else(|| Refusal::new("native object manifest has no parent"))?;
    let retained_dir = state.request.output_root.join("native-objects").join(label);
    create_private_dir(&retained_dir)?;
    let mut seen = BTreeSet::new();
    let mut retained = Vec::new();
    for row in rows {
        require_keys(row, &["path", "bytes", "sha256"], "native object row")?;
        let name = text(row, "path")?;
        let expected_bytes = integer(row, "bytes")?;
        let expected_sha = text(row, "sha256")?;
        if !expected_names.contains(name)
            || !seen.insert(name)
            || !is_sha256_digest(expected_sha)
            || expected_bytes == 0
            || expected_bytes > MAX_NATIVE_OBJECT_BYTES
        {
            return Err(Refusal::new(format!(
                "Cargo variant {label} has an invalid native object identity",
            )));
        }
        let source = native_dir.join(name);
        let metadata = fs::symlink_metadata(&source)?;
        if !metadata.file_type().is_file() || metadata.len() != expected_bytes {
            return Err(Refusal::new(format!(
                "Cargo variant {label} native object size or type changed",
            )));
        }
        let bytes = read_regular_bounded(&source, MAX_NATIVE_OBJECT_BYTES as usize)?;
        if sha256_bytes(&bytes) != expected_sha {
            return Err(Refusal::new(format!(
                "Cargo variant {label} native object digest changed",
            )));
        }
        let destination = retained_dir.join(name);
        retain_bytes(state, &destination, &bytes)?;
        retained.push(json!({"path":name,"bytes":expected_bytes,"sha256":expected_sha}));
    }
    if seen != expected_names {
        return Err(Refusal::new(format!(
            "Cargo variant {label} native object set is incomplete",
        )));
    }
    retained.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    Ok(Value::Array(retained))
}

fn find_native_metadata(
    directory: &Path,
    depth: usize,
    output: &mut Vec<PathBuf>,
    remaining_entries: &mut usize,
) -> Result<()> {
    if depth > 12 || output.len() > 1 {
        return Ok(());
    }
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => metadata,
        Ok(_) => {
            return Err(Refusal::new(
                "Cargo build directory contains a non-directory",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let _ = metadata;
    for entry in fs::read_dir(directory)? {
        if *remaining_entries == 0 {
            return Err(Refusal::new(
                "native object traversal exceeds its entry bound",
            ));
        }
        *remaining_entries -= 1;
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if entry.file_name() == OsStr::new("ami-native") {
                let candidate = path.join("native.json");
                if fs::symlink_metadata(&candidate)
                    .is_ok_and(|metadata| metadata.file_type().is_file())
                {
                    output.push(candidate);
                    if output.len() > 1 {
                        return Ok(());
                    }
                }
            }
            find_native_metadata(&path, depth + 1, output, remaining_entries)?;
        }
    }
    Ok(())
}

fn retain_bytes(state: &mut RunState, destination: &Path, bytes: &[u8]) -> Result<()> {
    let next = state
        .consumer_artifact_bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| Refusal::new("retained artifact byte count overflow"))?;
    if next > MAX_CONSUMER_ARTIFACT_BYTES {
        return Err(Refusal::new(
            "retained consumer artifacts exceed the 64 MiB cap",
        ));
    }
    write_new(destination, bytes)?;
    if sha256_file(destination)? != sha256_bytes(bytes) {
        return Err(Refusal::new(
            "retained consumer artifact changed during write",
        ));
    }
    state.consumer_artifact_bytes = next;
    Ok(())
}

fn execute(
    state: &mut RunState,
    label: &str,
    program: &Path,
    args: &[String],
    cwd: &Path,
    environment: BTreeMap<String, String>,
) -> Result<CommandOutcome> {
    let elapsed = state.started.elapsed().as_secs();
    let remaining_active = MAX_ACTIVE_SECONDS.saturating_sub(elapsed);
    if remaining_active == 0 {
        return Err(Refusal::new(
            "active qualification window ended before the next command",
        ));
    }
    let remaining_logs = MAX_LOG_BYTES.saturating_sub(state.total_log_bytes);
    if remaining_logs == 0 {
        return Err(Refusal::new("campaign raw-log budget is exhausted"));
    }
    let args = args.to_vec();
    let request = CommandRequest {
        schema: core_qualification_command::REQUEST_SCHEMA.to_owned(),
        program: path_text(program)?,
        args,
        cwd: path_text(cwd)?,
        environment,
        required_roots: vec![path_text(&state.request.managed_root)?],
        limits: CommandBudgets {
            seconds: MAX_COMMAND_SECONDS.min(remaining_active),
            rss_bytes: MAX_RSS_BYTES,
            workspace_bytes: MAX_WORKSPACE_BYTES,
            log_bytes: remaining_logs,
        },
    };
    let request_bytes = serde_json::to_vec(&request).map_err(json_error)?;
    let request_path = state
        .request
        .output_root
        .join("requests")
        .join(format!("{label}.json"));
    write_new(&request_path, &request_bytes)?;
    let record_path = state.request.output_root.join("records").join(label);
    let record =
        core_qualification_command::run_and_record(&request, &request_bytes, &record_path)?;
    if !record.result_published {
        return Err(Refusal::new(format!(
            "qualified command {label} did not publish its final record; inspect retained command directory",
        )));
    }
    let log_bytes = record
        .stdout
        .bytes
        .checked_add(record.stderr.bytes)
        .ok_or_else(|| Refusal::new("command log-byte count overflow"))?;
    state.total_log_bytes = state
        .total_log_bytes
        .checked_add(log_bytes)
        .ok_or_else(|| Refusal::new("campaign log-byte count overflow"))?;
    if state.total_log_bytes > MAX_LOG_BYTES {
        return Err(Refusal::new("campaign raw logs exceed the 16 MiB cap"));
    }
    let aggregate_peak = record
        .aggregate_peak_rss_bytes
        .ok_or_else(|| Refusal::new(format!("qualified command {label} omitted aggregate RSS")))?;
    let peak_workspace = record.resource_report.peak_workspace_bytes;
    let peak_log = record.resource_report.peak_log_bytes;
    let result_path = record_path.join("result.json");
    let result_sha256 = sha256_file(&result_path)?;
    let stdout_raw = read_regular_bounded(&record_path.join("stdout.log"), MAX_LOG_BYTES as usize)?;
    let stderr_raw = read_regular_bounded(&record_path.join("stderr.log"), MAX_LOG_BYTES as usize)?;
    if stdout_raw.len() as u64 != record.stdout.bytes
        || sha256_bytes(&stdout_raw) != record.stdout.sha256
        || stderr_raw.len() as u64 != record.stderr.bytes
        || sha256_bytes(&stderr_raw) != record.stderr.sha256
    {
        return Err(Refusal::new(format!(
            "qualified command {label} retained streams differ from the measured record",
        )));
    }
    let stdout = String::from_utf8_lossy(&stdout_raw).into_owned();
    let outcome = CommandOutcome {
        label: label.to_owned(),
        request: request.clone(),
        request_path,
        request_sha256: record.request_sha256.clone(),
        result_sha256,
        result_path,
        binding: record.command.clone(),
        passed: record.passed,
        refusal: record.refusal.clone(),
        capture_complete: record.capture_complete,
        capture_error: record.capture_error.clone(),
        child_exit_code: record.child_exit_code,
        child_signal: record.child_signal,
        stdout,
        stdout_bytes: record.stdout.bytes,
        stdout_sha256: record.stdout.sha256,
        stderr_bytes: record.stderr.bytes,
        stderr_sha256: record.stderr.sha256,
        aggregate_peak_rss_bytes: aggregate_peak,
        peak_workspace_bytes: peak_workspace,
        peak_log_bytes: peak_log,
        sample_count: record.resource_report.sample_count,
        last_sample_complete: record.resource_report.last_sample_complete,
        incomplete_cleanup: record.resource_report.incomplete_cleanup,
    };
    state.commands.push(command_summary(&outcome));
    Ok(outcome)
}

fn require_pass(outcome: &CommandOutcome) -> Result<()> {
    if !outcome.passed || outcome.child_exit_code != Some(0) {
        return Err(Refusal::new(format!(
            "qualified command {} failed; result retained at {}",
            outcome.label,
            outcome.result_path.display()
        )));
    }
    Ok(())
}

fn command_summary(outcome: &CommandOutcome) -> Value {
    json!({
        "label":outcome.label,
        "request_sha256":outcome.request_sha256,
        "result_path":outcome.result_path,
        "result_sha256":outcome.result_sha256,
        "command_binding":{
            "program":outcome.binding.program,
            "program_sha256":outcome.binding.program_sha256,
            "cwd":outcome.binding.cwd,
            "args_sha256":outcome.binding.args_sha256,
            "environment_keys":outcome.binding.environment_keys,
            "environment_sha256":outcome.binding.environment_sha256,
            "helper_sha256":outcome.binding.helper_sha256
        },
        "passed":outcome.passed,
        "refusal":outcome.refusal,
        "capture_complete":outcome.capture_complete,
        "capture_error":outcome.capture_error,
        "child_exit_code":outcome.child_exit_code,
        "child_signal":outcome.child_signal,
        "stdout_bytes":outcome.stdout_bytes,
        "stdout_sha256":outcome.stdout_sha256,
        "stderr_bytes":outcome.stderr_bytes,
        "stderr_sha256":outcome.stderr_sha256,
        "aggregate_peak_rss_bytes":outcome.aggregate_peak_rss_bytes,
        "peak_workspace_bytes":outcome.peak_workspace_bytes,
        "peak_log_bytes":outcome.peak_log_bytes,
        "sample_count":outcome.sample_count,
        "last_sample_complete":outcome.last_sample_complete,
        "incomplete_cleanup":outcome.incomplete_cleanup
    })
}

fn require_output_contains(output: &str, expected: &str, label: &str) -> Result<()> {
    if !output.contains(expected) {
        return Err(Refusal::new(format!(
            "command output does not identify the pinned {label}",
        )));
    }
    Ok(())
}

fn copy_arguments(source: &Path, destination: &Path) -> Result<Vec<String>> {
    let mut args = Vec::new();
    #[cfg(target_os = "macos")]
    args.extend(["-cR".to_owned()]);
    #[cfg(target_os = "linux")]
    args.extend(["-a".to_owned(), "--reflink=auto".to_owned()]);
    args.push(path_text(source)?);
    args.push(path_text(destination)?);
    Ok(args)
}

fn minimal_environment(work: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        (
            "HOME".to_owned(),
            work.join("home").to_string_lossy().into_owned(),
        ),
        (
            "TMPDIR".to_owned(),
            work.join("tmp").to_string_lossy().into_owned(),
        ),
        ("LC_ALL".to_owned(), "C".to_owned()),
        ("TZ".to_owned(), "UTC".to_owned()),
    ])
}

fn existing_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Refusal::new(format!(
            "could not inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Refusal::new(format!(
            "{label} is not a real directory: {}",
            path.display()
        )));
    }
    fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))
}

fn existing_regular(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Refusal::new(format!(
            "could not inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::new(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))
}

fn executable_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = existing_regular(path, label)?;
    let metadata = fs::metadata(&canonical)?;
    if metadata.len() == 0 || metadata.permissions().mode() & 0o111 == 0 {
        return Err(Refusal::new(format!("{label} is not an executable file")));
    }
    Ok(canonical)
}

fn executable_identity(path: &Path, label: &str) -> Result<(u64, String)> {
    let canonical = executable_file(path, label)?;
    let metadata = fs::metadata(&canonical)?;
    Ok((metadata.len(), sha256_file(&canonical)?))
}

fn fresh_path(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(Refusal::new(format!(
            "{label} must be absolute and normalized",
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Refusal::new(format!("{label} has no parent")))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Refusal::new(format!("could not resolve {label} parent: {error}")))?;
    let name = path
        .file_name()
        .ok_or_else(|| Refusal::new(format!("{label} must name a new leaf")))?;
    let normalized = parent.join(name);
    match fs::symlink_metadata(&normalized) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(normalized),
        Ok(_) => Err(Refusal::new(format!("{label} already exists"))),
        Err(error) => Err(error.into()),
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_new_json(path: &Path, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(json_error)?;
    write_new(path, &bytes)
}

fn require_keys(value: &Value, keys: &[&str], label: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new(format!("{label} must be an object")))?;
    let expected = keys.iter().copied().collect::<BTreeSet<_>>();
    if object.len() != expected.len()
        || object.keys().any(|key| !expected.contains(key.as_str()))
        || expected.iter().any(|key| !object.contains_key(*key))
    {
        return Err(Refusal::new(format!(
            "{label} has missing or unknown fields"
        )));
    }
    Ok(())
}

fn get<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| Refusal::new(format!("required field {key} is missing")))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let text = get(value, key)?
        .as_str()
        .ok_or_else(|| Refusal::new(format!("field {key} must be a string")))?;
    if text.is_empty() || text.contains(['\0', '\r', '\n']) {
        return Err(Refusal::new(format!(
            "field {key} is empty or contains a line break"
        )));
    }
    Ok(text)
}

fn integer(value: &Value, key: &str) -> Result<u64> {
    get(value, key)?
        .as_u64()
        .ok_or_else(|| Refusal::new(format!("field {key} must be a nonnegative integer")))
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new("qualified command path is not UTF-8"))
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

fn json_error(error: serde_json::Error) -> Refusal {
    Refusal::new(format!("could not encode qualification JSON: {error}"))
}

fn usage() -> Refusal {
    Refusal::new("usage: ami-rust-xtask native-cargo-qualification --request JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn request_value() -> Value {
        json!({
            "schema": REQUEST_SCHEMA,
            "host_key": "macos-aarch64",
            "rust_host_triple": "aarch64-apple-darwin",
            "source_root": "/managed/source",
            "managed_root": "/managed",
            "work_root": "/managed/work",
            "output_root": "/managed/output",
            "component_roots": {
                "rust": "/managed/components/rust",
                "cargo": "/managed/components/cargo",
                "llvm": "/managed/components/llvm",
                "csdk": "/managed/components/csdk",
                "collector": "/managed/components/collector",
                "target_libraries": "/managed/components/target-libraries"
            },
            "bootstrap": {
                "cargo": "/bootstrap/bin/cargo",
                "rustc": "/bootstrap/bin/rustc",
                "rustup": "/bootstrap/bin/rustup"
            }
        })
    }

    fn temporary_root(label: &str) -> PathBuf {
        crate::test_support::temporary_root(&format!("native-cargo-{label}"))
    }

    #[test]
    fn vendor_archive_is_data_and_corrupt_bytes_are_refused() {
        let root = temporary_root("vendor-data");
        fs::create_dir(&root).expect("private test root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private root permissions");
        let root = fs::canonicalize(&root).expect("canonical private root");
        let source = root.join("source");
        let inputs = source.join("release/inputs");
        fs::create_dir_all(&inputs).expect("isolated archive directory");
        let original_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let profile: Value = serde_json::from_slice(
            &fs::read(original_root.join("release/native-cargo-vendor-inputs.json"))
                .expect("native vendor material profile"),
        )
        .expect("valid vendor material profile");
        assert_eq!(profile["bytes"], VENDOR_BYTES);
        assert_eq!(profile["sha256"], VENDOR_SHA256);
        assert_eq!(
            profile["packages"].as_array().expect("package rows").len(),
            51
        );
        fs::create_dir(source.join("tooling")).expect("isolated tooling lock parent");
        for (path, digest) in VENDOR_SOURCE_LOCKS {
            assert_eq!(profile["source_locks"][path], digest);
            fs::copy(original_root.join(path), source.join(path)).expect("copy pinned source lock");
        }
        let original = original_root.join("release/inputs/native-cargo-vendor.tar.xz");
        let archive = inputs.join("native-cargo-vendor.tar.xz");
        fs::copy(&original, &archive).expect("copy pinned real vendor archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o644))
            .expect("archive is non-executable data");
        let work = root.join("work");
        create_private_dir(&work).expect("private extraction work");
        let mut value = request_value();
        value["source_root"] = json!(source);
        value["managed_root"] = json!(root);
        value["work_root"] = json!(work);
        let mut state = RunState {
            request: parse_request(&value).expect("archive test request"),
            started: Instant::now(),
            commands: Vec::new(),
            total_log_bytes: 0,
            consumer_artifact_bytes: 0,
        };
        let extracted = extract_vendor(&mut state)
            .expect("the real pinned archive must extract without executable permission");
        assert!(extracted.is_dir());
        assert!(
            fs::read_dir(&extracted)
                .expect("vendor entries")
                .next()
                .is_some()
        );
        let mut changed = fs::read(&archive).expect("isolated archive bytes");
        changed[0] ^= 1;
        fs::write(&archive, changed).expect("corrupt only isolated archive");
        let refusal = extract_vendor(&mut state).expect_err("changed archive must be refused");
        assert!(
            refusal
                .to_string()
                .contains("differs from its pinned identity")
        );
        fs::write(source.join("tooling/Cargo.lock"), b"different lock")
            .expect("change only isolated lock");
        let refusal = extract_vendor(&mut state).expect_err("changed source lock must be refused");
        assert!(refusal.to_string().contains("does not match source lock"));
        fs::remove_dir_all(&root).expect("retire isolated fixture");
    }

    fn expected_control(
        root: &Path,
        label: &'static str,
        environment: BTreeMap<String, String>,
        diagnostic_fragments: &'static [&'static str],
    ) -> ExpectedCargoFailure {
        let args = vec![
            "run".to_owned(),
            TOOLCHAIN_NAME.to_owned(),
            "cargo".to_owned(),
            "build".to_owned(),
            "--locked".to_owned(),
            "--offline".to_owned(),
            "--release".to_owned(),
            "--target".to_owned(),
            "x86_64-aros".to_owned(),
            "--manifest-path".to_owned(),
            root.join("Cargo.toml").to_string_lossy().into_owned(),
            "--package".to_owned(),
            "ami-rust-minimal".to_owned(),
            "--bin".to_owned(),
            "ami-rust-minimal".to_owned(),
        ];
        ExpectedCargoFailure {
            label,
            program: std::env::current_exe().expect("test executable path"),
            args,
            cwd: root.to_path_buf(),
            environment,
            required_roots: vec![root.to_string_lossy().into_owned()],
            diagnostic_fragments,
        }
    }

    fn synthetic_failure(
        root: &Path,
        expected: &ExpectedCargoFailure,
        stderr: &[u8],
    ) -> CommandOutcome {
        fs::create_dir_all(root.join("requests")).expect("request fixture directory");
        let record_directory = root.join("records").join(expected.label);
        fs::create_dir_all(&record_directory).expect("record fixture directory");
        let request = CommandRequest {
            schema: core_qualification_command::REQUEST_SCHEMA.to_owned(),
            program: path_text(&expected.program).expect("program path"),
            args: expected.args.clone(),
            cwd: path_text(&expected.cwd).expect("cwd path"),
            environment: expected.environment.clone(),
            required_roots: expected.required_roots.clone(),
            limits: CommandBudgets {
                seconds: MAX_COMMAND_SECONDS,
                rss_bytes: MAX_RSS_BYTES,
                workspace_bytes: MAX_WORKSPACE_BYTES,
                log_bytes: MAX_LOG_BYTES,
            },
        };
        let request_bytes = serde_json::to_vec(&request).expect("serialize request");
        let request_path = root
            .join("requests")
            .join(format!("{}.json", expected.label));
        fs::write(&request_path, &request_bytes).expect("write request fixture");
        let stdout_path = record_directory.join("stdout.log");
        let stderr_path = record_directory.join("stderr.log");
        fs::write(&stdout_path, b"").expect("write stdout fixture");
        fs::write(&stderr_path, stderr).expect("write stderr fixture");
        let result_path = record_directory.join("result.json");
        let result_bytes = b"{\"fixture\":\"UNIT_FIXTURE only\"}\n";
        fs::write(&result_path, result_bytes).expect("write result fixture");
        let binding = core_qualification_command::CommandBinding {
            program: request.program.clone(),
            program_sha256: sha256_file(&expected.program).expect("program digest"),
            cwd: request.cwd.clone(),
            args_sha256: sha256_bytes(
                &serde_json::to_vec(&request.args).expect("serialize command arguments"),
            ),
            environment_keys: request.environment.keys().cloned().collect(),
            environment_sha256: sha256_bytes(
                &serde_json::to_vec(&request.environment).expect("serialize command environment"),
            ),
            helper_sha256: "a".repeat(64),
        };
        CommandOutcome {
            label: expected.label.to_owned(),
            request_sha256: sha256_bytes(&request_bytes),
            request,
            request_path,
            result_sha256: sha256_bytes(result_bytes),
            result_path,
            binding,
            passed: false,
            refusal: Some("child exited with status 101".to_owned()),
            capture_complete: true,
            capture_error: None,
            child_exit_code: Some(101),
            child_signal: None,
            stdout: String::new(),
            stdout_bytes: 0,
            stdout_sha256: sha256_bytes(b""),
            stderr_bytes: stderr.len() as u64,
            stderr_sha256: sha256_bytes(stderr),
            aggregate_peak_rss_bytes: 128 * 1024 * 1024,
            peak_workspace_bytes: 1024 * 1024,
            peak_log_bytes: stderr.len() as u64,
            sample_count: 1,
            last_sample_complete: true,
            incomplete_cleanup: false,
        }
    }

    #[test]
    fn request_requires_exact_fields_and_preserves_host_identity() {
        let request = parse_request(&request_value()).expect("valid request");
        assert_eq!(request.host_key, "macos-aarch64");
        assert_eq!(request.rust_host_triple, "aarch64-apple-darwin");
        assert_eq!(request.component_roots.len(), 6);

        let mut with_unknown = request_value();
        with_unknown["authenticated"] = Value::Bool(true);
        assert!(parse_request(&with_unknown).is_err());

        let mut missing = request_value();
        missing
            .as_object_mut()
            .expect("request object")
            .remove("bootstrap");
        assert!(parse_request(&missing).is_err());
    }

    #[test]
    fn strict_json_parser_refuses_duplicate_request_keys() {
        let raw = br#"{"schema":"ami-rust-native-cargo-qualification-request-v1","schema":"ami-rust-native-cargo-qualification-request-v1"}"#;
        assert!(parse_json_value(raw, JsonProfile::PackageMetadataStateSelection).is_err());
    }

    #[test]
    fn cargo_matrix_uses_locked_offline_workspace_source_toolchain_commands() {
        let args = cargo_build_args(Path::new("/checkout with spaces"), VARIANTS[3])
            .expect("dependency variant arguments");
        assert_eq!(
            args.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "run",
                TOOLCHAIN_NAME,
                "cargo",
                "build",
                "--locked",
                "--offline",
                "--release",
                "--target",
                "x86_64-aros",
                "--manifest-path",
                "/checkout with spaces/Cargo.toml",
                "--package",
                "ami-rust-dependencies",
                "--bin",
                "ami-rust-dependencies"
            ]
        );
        assert_eq!(
            VARIANTS.map(|variant| variant.key),
            [
                "core",
                "alloc",
                "qualification",
                "dependencies",
                "sha256sum"
            ]
        );
    }

    #[test]
    fn source_copy_preparation_creates_two_spaced_roots_and_copies_source() {
        let root = temporary_root("source-copy-spaces");
        fs::create_dir_all(&root).expect("fixture root");
        let managed = root.join("managed workspace");
        fs::create_dir(&managed).expect("managed fixture directory");
        let source = root.join("source checkout with spaces");
        fs::create_dir_all(source.join("tooling")).expect("source fixture directories");
        fs::write(source.join("Cargo.lock"), b"workspace-lock fixture\n")
            .expect("workspace lock fixture");
        fs::write(source.join("tooling/Cargo.lock"), b"tooling-lock fixture\n")
            .expect("tooling lock fixture");
        fs::write(source.join("README.md"), b"UNIT_FIXTURE source tree\n")
            .expect("source marker fixture");

        let work = managed.join("work area");
        let output = managed.join("output area");
        let request = Request {
            host_key: "macos-aarch64".to_owned(),
            rust_host_triple: "aarch64-apple-darwin".to_owned(),
            source_root: source.clone(),
            managed_root: managed,
            work_root: work.clone(),
            output_root: output,
            component_roots: [
                root.join("components/rust"),
                root.join("components/cargo"),
                root.join("components/llvm"),
                root.join("components/csdk"),
                root.join("components/collector"),
                root.join("components/target-libraries"),
            ],
            bootstrap_cargo: root.join("bootstrap/cargo"),
            bootstrap_rustc: root.join("bootstrap/rustc"),
            rustup: root.join("bootstrap/rustup"),
        };
        create_run_directories(&request).expect("initial run directories");

        let destinations = source_copy_destinations(&work);
        assert!(
            destinations
                .iter()
                .all(|destination| destination.to_string_lossy().contains(" "))
        );
        for (index, destination) in destinations.iter().enumerate() {
            let parent = destination.parent().expect("source-copy parent");
            assert!(!parent.exists(), "source-copy parent must be fresh");
            let args = prepare_source_copy(&source, destination)
                .expect("prepare source-copy parent and arguments");
            assert!(parent.is_dir(), "spaced source-copy parent was created");
            let status = Command::new("/bin/cp")
                .args(&args)
                .status()
                .expect("run the production source-copy program");
            assert!(status.success(), "source copy {index} must succeed");
            assert_eq!(
                fs::read(destination.join("README.md")).expect("copied source marker"),
                b"UNIT_FIXTURE source tree\n"
            );
            assert_eq!(
                sha256_file(&destination.join("Cargo.lock")).expect("copied workspace lock"),
                sha256_file(&source.join("Cargo.lock")).expect("source workspace lock")
            );
            assert_eq!(
                sha256_file(&destination.join("tooling/Cargo.lock")).expect("copied tooling lock"),
                sha256_file(&source.join("tooling/Cargo.lock")).expect("source tooling lock")
            );
        }
        fs::remove_dir_all(&root).expect("remove source-copy fixtures");
    }

    #[test]
    fn named_cargo_refusals_require_the_expected_command_and_diagnostic() {
        let root = temporary_root("named-refusal");
        fs::create_dir_all(&root).expect("fixture root");
        let missing_target = root.join("missing-rustc-target");
        let missing_expected = expected_control(
            &root,
            "cargo-missing-rustc-control",
            BTreeMap::from([(
                "RUSTC".to_owned(),
                "/ami-rust-controlled-missing-rustc".to_owned(),
            )]),
            &[
                "could not execute process",
                "/ami-rust-controlled-missing-rustc",
                "No such file or directory",
            ],
        );
        let missing_diagnostic = b"error: could not execute process `/ami-rust-controlled-missing-rustc --crate-name fixture` (never executed)\n\nCaused by:\n  No such file or directory (os error 2)\n";
        let missing = synthetic_failure(
            &root.join("missing-positive"),
            &missing_expected,
            missing_diagnostic,
        );
        require_expected_failure(
            &missing,
            &missing_target,
            "ami-rust-minimal",
            &missing_expected,
        )
        .expect("the named missing-rustc refusal is accepted");

        let unrelated_missing = synthetic_failure(
            &root.join("missing-unrelated"),
            &missing_expected,
            b"error: invalid Cargo configuration; no compiler was invoked\n",
        );
        assert!(
            require_expected_failure(
                &unrelated_missing,
                &root.join("missing-unrelated-target"),
                "ami-rust-minimal",
                &missing_expected,
            )
            .is_err()
        );

        let wrong_expected = expected_control(
            &root,
            "cargo-wrong-linker-control",
            BTreeMap::from([(
                "CARGO_TARGET_X86_64_AROS_LINKER".to_owned(),
                "/usr/bin/false".to_owned(),
            )]),
            &[
                "failed to run custom build command",
                "AROS native bridge",
                "Cargo selected a different target linker",
            ],
        );
        let wrong_diagnostic = b"error: failed to run custom build command for `ami-rust-minimal v0.2.0-dev`\n\nCaused by:\n  process didn't exit successfully: `/UNIT_FIXTURE/cargo build-script-build` (exit status: 101)\n  --- stderr\n\n  thread 'main' panicked at examples/minimal/build.rs:3:10:\n  AROS native bridge: Cargo selected a different target linker\n";
        let wrong = synthetic_failure(
            &root.join("linker-positive"),
            &wrong_expected,
            wrong_diagnostic,
        );
        require_expected_failure(
            &wrong,
            &root.join("linker-target"),
            "ami-rust-minimal",
            &wrong_expected,
        )
        .expect("the named wrong-linker refusal is accepted");

        let unrelated_linker = synthetic_failure(
            &root.join("linker-unrelated"),
            &wrong_expected,
            b"error: failed to parse workspace metadata before linking\n",
        );
        assert!(
            require_expected_failure(
                &unrelated_linker,
                &root.join("linker-unrelated-target"),
                "ami-rust-minimal",
                &wrong_expected,
            )
            .is_err()
        );

        let mut wrong_binding = synthetic_failure(
            &root.join("wrong-binding"),
            &wrong_expected,
            wrong_diagnostic,
        );
        wrong_binding.binding.args_sha256 = sha256_bytes(b"wrong argv");
        assert!(
            require_expected_failure(
                &wrong_binding,
                &root.join("wrong-binding-target"),
                "ami-rust-minimal",
                &wrong_expected,
            )
            .is_err()
        );

        fs::remove_dir_all(&root).expect("remove refusal fixtures");
    }

    #[test]
    fn native_manifest_search_uses_one_cumulative_entry_budget_and_skips_symlinks() {
        let root = temporary_root("metadata-search");
        let outside = temporary_root("metadata-outside");
        let manifest_dir = root.join("build-hash/out/ami-native");
        fs::create_dir_all(&manifest_dir).expect("manifest directories");
        fs::write(manifest_dir.join("native.json"), b"{}\n").expect("manifest fixture");
        let outside_manifest = outside.join("ami-native/native.json");
        fs::create_dir_all(outside_manifest.parent().expect("outside parent"))
            .expect("outside directories");
        fs::write(&outside_manifest, b"{}\n").expect("outside manifest");
        std::os::unix::fs::symlink(&outside, root.join("linked-build")).expect("symlink fixture");

        let mut found = Vec::new();
        let mut remaining = 8;
        find_native_metadata(&root, 0, &mut found, &mut remaining)
            .expect("bounded manifest search");
        assert_eq!(found, vec![manifest_dir.join("native.json")]);
        assert_eq!(remaining, 3);

        let mut too_small = 2;
        let mut ignored = Vec::new();
        assert!(find_native_metadata(&root, 0, &mut ignored, &mut too_small).is_err());

        fs::remove_dir_all(&root).expect("remove search fixture");
        fs::remove_dir_all(&outside).expect("remove outside fixture");
    }
}

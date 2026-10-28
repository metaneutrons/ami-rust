//! Derive the pinned portable C-SDK candidate from its original archives.
//!
//! This is a maintainer producer. It describes the files derived on one native
//! host and does not accept a release, publish an artifact, or replace the
//! outer workflow observer. Direct commands use the shared bounded process
//! capture API; Nouveau workers use the shared per-compiler resource sampler.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("the portable C-SDK producer is supported on macOS and Linux only");

use ami_rust_core::{
    Refusal, Result,
    component_archive::ArchiveLimits,
    csdk_headers::{CsdkHeadersRequest, generate_public_headers},
    csdk_metadata::{
        CsdkMetadataRequest, CsdkMetadataRunOutput, CsdkMetadataTool, CsdkMetadataTools,
        generate_aom_metadata,
    },
    csdk_nouveau::{NouveauCompileRequest, compile_nouveau_with_prefix, plan_nouveau},
    csdk_pack::{CsdkPackLimits, CsdkPackReceipt, CsdkPackRequest, pack_csdk_tar},
    csdk_patches::apply_csdk_source_patches,
    csdk_prefix_map::probe_prefix_mapping,
    csdk_recipes::{classic_generator_recipe, nouveau_compile_recipes, public_header_recipes},
    csdk_source::{
        CsdkSourceFilePin, CsdkSourceMaterializationRequest, CsdkSourceRoots,
        materialize_csdk_source,
    },
    csdk_staging::{CsdkStagingRequest, stage_original_csdk},
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    files::{read_regular_bounded, validate_relative_inventory_path},
    inventory::{FileIdentity, InventoryLimits, LinkIdentity, verify_complete},
    json::{JsonProfile, parse_json_value},
    process_capture::{self, CaptureLimits, CommandSpec},
    resource_capture::{ResourceLimits, SampleLimits},
    signals::SigtermGuard,
    workspace_accounting::{self, ScanLimits},
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Component, Path, PathBuf},
    time::Duration,
};

const RESOURCE_POLICY_PATH: &str = "release/ci-resources.json";
const SOURCE_CAPSULE_DEFAULT: &str = "release/portable-csdk/spec.json";
const SOURCE_SCHEMA: &str = "ami-rust-portable-csdk-v1";
const SOURCE_STATUS: &str = "PINNED_CANDIDATE_THREE_HOST_QUALIFICATION_REQUIRED";
const PRODUCER_SCHEMA: &str = "ami-rust-portable-csdk-producer-v1";
const PRODUCER_STATUS: &str = "PRODUCED_CSDK_COMPONENT_CANDIDATE_NOT_R1_ACCEPTED";
const ARM_TOOLCHAIN_URL: &str = "https://github.com/metaneutrons/aros-toolchains/releases/download/v0.1.4/aros-toolchain-v1-llvm11.0.0-linux-aarch64-pc-x86_64.tar.xz";
const NEXT_GENMODULE_SERIES_BYTES: u64 = 1_332;
const NEXT_GENMODULE_SERIES_SHA256: &str =
    "88cd83ca5136e9b5698e3cfe05b4ce0eb35573deefbda1fdb77c362b6b61c8b2";
const HISTORICAL_PREFIX: &str = "/Volumes/Dev/Source/AROS-NX";
const MESA_PATCH_PATH: &str = "workbench/libs/mesa/mesa-20.0.8-aros.diff";
const MESA_PATCH_SHA256: &str = "16e6df68b64996d880b4fb1eb9275851ee2ab70badff731e2610bd7edca548b6";
const NOUVEAU_OBJECTS: u64 = 825;
const NOUVEAU_SYMBOLS: u64 = 4_515;
const ORIGINAL_FILE_COUNT: usize = 2_835;
const CHANGED_FILE_COUNT: usize = 532;
const PUBLIC_HEADER_COUNT: usize = 530;
const COMMAND_TERMINATION_GRACE: Duration = Duration::from_secs(2);
const MAX_POLICY_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SPEC_BYTES: usize = 2 * 1024 * 1024;
const MAX_AR_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 1_000_000;
const MAX_WORK_UNITS: usize = 2_000_001;
const RESOURCE_JOBS: u64 = 2;
const RESOURCE_RSS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const RESOURCE_WORKSPACE_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const RESOURCE_LOG_BYTES: u64 = 16 * 1024 * 1024;
const RESOURCE_SECONDS: u64 = 1_200;
const MINIMUM_RAM_BYTES: u64 = 6 * 1024 * 1024 * 1024;
const MINIMUM_FREE_DISK_BYTES: u64 = 24 * 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
struct PinnedFile {
    path: String,
    identity: CsdkSourceFilePin,
    sha256: String,
}

#[derive(Clone, Debug)]
struct Profile {
    files: Vec<FileIdentity>,
    symlinks: Vec<LinkIdentity>,
}

struct LoadedInputs {
    spec: Value,
    spec_sha256: String,
    original_profile: Profile,
    candidate_profile: Profile,
    candidate_profile_sha256: String,
    original_archive: PinnedFile,
    candidate_archive_sha256: String,
    source_capsule: PinnedFile,
    source_manifest_pin: PinnedFile,
    patch_series: PinnedFile,
    selected_toolchain_profile: Profile,
    selected_compiler: PinnedFile,
    nested_archive: CsdkSourceFilePin,
    nested_generator_sha256: [u8; 32],
    mesa_patch_sha256: [u8; 32],
    prospective_series: PinnedFile,
}

#[derive(Clone)]
struct ResourcePolicy {
    sha256: String,
    limits: ResourceLimits,
    sample_limits: SampleLimits,
    timeout: Duration,
    workspace_bytes: u64,
}

struct ResolvedTools {
    metadata: CsdkMetadataTools,
    xz: CsdkMetadataTool,
}

struct RunOutput {
    stdout: Vec<u8>,
    record: Value,
}

struct ProducerRunner<'a> {
    work: PathBuf,
    env: BTreeMap<OsString, OsString>,
    signal: &'a SigtermGuard,
    max_log_bytes: usize,
    saved_log_bytes: usize,
    commands: Vec<Value>,
}

pub(super) fn run(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let arguments = ProducerArguments::parse(arguments)?;
    let signal = SigtermGuard::acquire()?;
    let result = produce(arguments, &signal);
    let interrupted = signal.finish_requested()?;
    if interrupted {
        return Err(
            Refusal::new("portable C-SDK production cancelled by SIGTERM").with_exit_code(143),
        );
    }
    result.map(|record| {
        println!("{}", record["status"].as_str().unwrap_or(PRODUCER_STATUS));
    })
}

struct ProducerArguments {
    source_root: PathBuf,
    spec: Option<PathBuf>,
    original_archive: PathBuf,
    toolchain: PathBuf,
    native_compiler: PathBuf,
    work: PathBuf,
    output: PathBuf,
    cmake: Option<PathBuf>,
    pkg_config: Option<PathBuf>,
    perl: Option<PathBuf>,
    git: Option<PathBuf>,
}

impl ProducerArguments {
    fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Self> {
        let mut options = BTreeMap::<OsString, OsString>::new();
        while let Some(key) = arguments.next() {
            if ![
                "--source-root",
                "--spec",
                "--original-archive",
                "--toolchain",
                "--native-compiler",
                "--work",
                "--output",
                "--cmake",
                "--pkg-config",
                "--perl",
                "--git",
            ]
            .iter()
            .any(|candidate| key == *candidate)
            {
                return Err(usage());
            }
            let value = arguments.next().ok_or_else(usage)?;
            if options.insert(key, value).is_some() {
                return Err(Refusal::new(
                    "portable C-SDK producer options may occur only once",
                ));
            }
        }
        let required = |name: &str| {
            options
                .get(OsStr::new(name))
                .cloned()
                .map(PathBuf::from)
                .ok_or_else(usage)
        };
        let optional = |name: &str| options.get(OsStr::new(name)).cloned().map(PathBuf::from);
        Ok(Self {
            source_root: required("--source-root")?,
            spec: optional("--spec"),
            original_archive: required("--original-archive")?,
            toolchain: required("--toolchain")?,
            native_compiler: required("--native-compiler")?,
            work: required("--work")?,
            output: required("--output")?,
            cmake: optional("--cmake"),
            pkg_config: optional("--pkg-config"),
            perl: optional("--perl"),
            git: optional("--git"),
        })
    }
}

fn produce(arguments: ProducerArguments, signal: &SigtermGuard) -> Result<Value> {
    let source_root = existing_directory(arguments.source_root, "C-SDK source root")?;
    let host = actual_host()?;
    let original_archive_arg =
        existing_regular(arguments.original_archive, "original C-SDK archive")?;
    let toolchain = existing_directory(arguments.toolchain, "portable C-SDK toolchain")?;
    let native_compiler = existing_regular(arguments.native_compiler, "native host C compiler")?;
    let spec_path = resolve_spec_path(&source_root, arguments.spec)?;
    let loaded = load_inputs(&source_root, &spec_path, &original_archive_arg, host)?;
    let toolchain_compiler = verify_toolchain(&toolchain, &loaded, host)?;
    let native_compiler_pin = executable_pin(&native_compiler, "native host C compiler")?;
    let tools = resolve_tools(
        arguments.cmake,
        arguments.pkg_config,
        arguments.perl,
        arguments.git,
    )?;
    let resource = read_resource_policy(&source_root)?;
    let capacity_policy = parse_json_value(
        &read_regular_bounded(&source_root.join(RESOURCE_POLICY_PATH), MAX_POLICY_BYTES)?,
        JsonProfile::SdkComponentManifest,
    )?;
    for destination in [&arguments.work, &arguments.output] {
        let parent = destination.parent().ok_or_else(usage)?;
        let (ram, free) = ami_rust_core::cargo_producer::host_capacity(parent)?;
        if ram
            < capacity_policy["host_capacity"]["ram_minimum_bytes"]
                .as_u64()
                .ok_or_else(usage)?
            || free
                < capacity_policy["host_capacity"]["disk_free_minimum_bytes"]
                    .as_u64()
                    .ok_or_else(usage)?
        {
            return Err(Refusal::new(
                "host RAM or destination filesystem capacity is below the C-SDK policy",
            ));
        }
    }

    let work = create_fresh_root(arguments.work, "portable C-SDK work")?;
    let output = create_fresh_root(arguments.output, "portable C-SDK output")?;
    require_disjoint(&work, &output, "C-SDK work and output roots overlap")?;
    create_private_dir(&work.join("home"))?;
    create_private_dir(&work.join("tmp"))?;
    create_private_dir(&work.join("command-logs"))?;
    for input in [
        source_root.as_path(),
        toolchain.as_path(),
        original_archive_arg.as_path(),
        native_compiler.as_path(),
    ] {
        require_disjoint(&work, input, "C-SDK work root overlaps an input")?;
        require_disjoint(&output, input, "C-SDK output root overlaps an input")?;
    }
    let mut runner = ProducerRunner::new(&work, signal, resource.limits.max_log_bytes, host)?;
    runner.checkpoint("beginning portable C-SDK production")?;

    let result = produce_inner(
        &source_root,
        &toolchain,
        &toolchain_compiler,
        &native_compiler,
        native_compiler_pin,
        &original_archive_arg,
        &loaded,
        &tools,
        &resource,
        &work,
        &output,
        host,
        &mut runner,
    );
    match result {
        Ok(record) => Ok(record),
        Err(error) => Err(Refusal::new(format!(
            "{error}; partial C-SDK work retained at {}; partial output retained at {}",
            work.display(),
            output.display()
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn produce_inner(
    source_root: &Path,
    toolchain: &Path,
    toolchain_compiler: &Path,
    native_compiler: &Path,
    native_compiler_pin: CsdkSourceFilePin,
    original_archive: &Path,
    loaded: &LoadedInputs,
    tools: &ResolvedTools,
    resource: &ResourcePolicy,
    work: &Path,
    output: &Path,
    host: &str,
    runner: &mut ProducerRunner<'_>,
) -> Result<Value> {
    let source_request = CsdkSourceMaterializationRequest {
        capsule: source_root.join(&loaded.source_capsule.path),
        manifest: source_root.join(&loaded.source_manifest_pin.path),
        destination: work.join("capsule"),
        capsule_pin: loaded.source_capsule.identity,
        manifest_pin: loaded.source_manifest_pin.identity,
        nested_archive_sha256: loaded.nested_archive.sha256,
        nested_generator_path: "build/cmake/pkg_config.cmake".to_owned(),
        nested_generator_sha256: loaded.nested_generator_sha256,
    };
    let material = materialize_csdk_source(source_request, |label| runner.checkpoint(label))?;
    let original_patch_series = apply_patch_series(
        &material.roots,
        source_root.join(&loaded.patch_series.path),
        loaded.patch_series.identity,
        runner,
        "sealed-source-patches",
    )?;
    let prospective_patch_series = apply_patch_series(
        &material.roots,
        source_root.join(&loaded.prospective_series.path),
        loaded.prospective_series.identity,
        runner,
        "prospective-genmodule-patches",
    )?;

    let capsule = &material.roots.destination;
    let ninja_path = capsule.join("recipes/build.ninja");
    let ninja_bytes = read_regular_bounded(&ninja_path, 128 * 1024 * 1024)?;
    let ninja = std::str::from_utf8(&ninja_bytes)
        .map_err(|_| Refusal::new("pinned C-SDK Ninja recipe must be UTF-8"))?;
    let header_recipes = public_header_recipes(ninja)?;
    let generator_recipe = classic_generator_recipe(ninja)?;
    let header_runner = RefCell::new(&mut *runner);
    let headers = generate_public_headers(
        CsdkHeadersRequest {
            source: material.roots.aros_nx.clone(),
            frozen_include: capsule.join("generated/sdk-include"),
            header_recipes: header_recipes.clone(),
            generator_recipe,
            destination: work.join("headers"),
            compiler: native_compiler.to_path_buf(),
            compiler_pin: native_compiler_pin,
            mesa_patch_sha256: loaded.mesa_patch_sha256,
            forbidden_path_prefixes: forbidden_prefixes(work),
        },
        |argv, cwd, label, timeout| {
            header_runner
                .borrow_mut()
                .run_argv(argv, cwd, label, timeout)
                .map(|output| output.record)
        },
        |label| header_runner.borrow().checkpoint(label),
    )?;
    let prefix_probe = probe_prefix_mapping(
        toolchain_compiler,
        &work.join("prefix-probe"),
        |argv, cwd, label| {
            runner
                .run_argv(argv, cwd, label, Duration::from_secs(60))
                .map(|output| output.record)
        },
    )?;

    let stage = work.join("build");
    create_private_dir(&stage)?;
    let current_workspace_bytes = measure_workspace(work, output)?;
    ensure_workspace_room(current_workspace_bytes, 1, resource.workspace_bytes)?;
    let staged = stage_original_csdk(
        CsdkStagingRequest {
            archive: original_archive.to_path_buf(),
            archive_pin: loaded.original_archive.identity,
            profile: loaded.original_profile.files.clone(),
            destination: stage.join("SYS"),
            limits: original_archive_limits(
                loaded.original_archive.identity.bytes,
                &loaded.original_profile,
                current_workspace_bytes,
                resource.workspace_bytes,
            )?,
        },
        |label| runner.checkpoint(label),
    )?;
    let developer = relocate_staged_developer(&staged.developer, &stage.join("SYS"))?;
    create_private_dir(&stage.join("SDK"))?;
    copy_regular_tree(
        &capsule.join("generated/sdk-include"),
        &stage.join("SDK/include"),
    )?;
    copy_regular_tree(
        &capsule.join("generated/sdk-include"),
        &stage.join("GENINCDIR"),
    )?;
    install_regenerated_headers(
        &work.join("headers"),
        &developer,
        &stage.join("SDK/include"),
        &stage.join("GENINCDIR"),
        &header_recipes,
        &headers,
    )?;
    create_empty_directory(&material.roots.aros_nx.join("arch/all-native/include"))?;
    create_directory_chain(&stage.join("gen/workbench/hidds/nouveau"))?;

    let original_pc_path = developer.join("lib/pkgconfig/aom.pc");
    let original_pc = read_regular_bounded(&original_pc_path, 1024 * 1024)?;
    let metadata_env = runner.env.clone();
    let metadata_runner = RefCell::new(&mut *runner);
    let aom = generate_aom_metadata(
        CsdkMetadataRequest {
            source: material.roots.libaom.clone(),
            original_archive: capsule.join("vendor/libaom/original/libaom-3.12.1.tar.gz"),
            destination: work.join("aom-metadata"),
            archive_pin: loaded.nested_archive,
            original_pc,
            tools: tools.metadata.clone(),
            base_env: metadata_env,
            label_prefix: "csdk-aom".to_owned(),
        },
        |spec, label, timeout| {
            let output = metadata_runner
                .borrow_mut()
                .run_spec(spec, label, timeout)?;
            Ok(CsdkMetadataRunOutput {
                stdout: output.stdout,
                process_record: output.record,
            })
        },
        |label| metadata_runner.borrow().checkpoint(label),
    )?;
    let generated_pc_path = value_path(&aom, "generated_pc_path")?;
    overwrite_regular(&generated_pc_path, &original_pc_path)?;

    let compile_database_path = capsule.join("recipes/compile_commands.json");
    let compile_database_bytes = read_regular_bounded(
        &compile_database_path,
        JsonProfile::CsdkCompilationDatabase.max_bytes(),
    )?;
    let compile_database = std::str::from_utf8(&compile_database_bytes)
        .map_err(|_| Refusal::new("Nouveau compilation database must be UTF-8"))?;
    let compile_records =
        nouveau_compile_recipes(compile_database, JsonProfile::CsdkCompilationDatabase)?;
    let nouveau_plan = plan_nouveau(
        &compile_records,
        ninja,
        &material.roots.aros_nx,
        &stage,
        toolchain,
    )?;
    if nouveau_plan["object_count"].as_u64() != Some(NOUVEAU_OBJECTS) {
        return Err(Refusal::new(
            "Nouveau plan does not contain exactly 825 objects",
        ));
    }
    let original_native_bytes = read_regular_bounded(
        &developer.join(
            loaded.spec["nouveau"]["archive_path"]
                .as_str()
                .ok_or_else(usage)?,
        ),
        MAX_AR_BYTES,
    )?;
    let original_native = ami_rust_core::csdk_ar::read_archive(&original_native_bytes)?;
    verify_original_native_archive(&original_native, loaded)?;

    verify_toolchain(toolchain, loaded, host)?;
    let native_work = work.join("nouveau-compile");
    create_private_dir(&native_work)?;
    let compile_request = nouveau_compile_request(
        &compile_records,
        ninja.to_owned(),
        material.roots.aros_nx.clone(),
        stage.clone(),
        toolchain.to_path_buf(),
        loaded.selected_compiler.sha256.clone(),
        native_work,
        resource,
    );
    let native_plan = compile_nouveau_with_prefix(compile_request, None, || runner.cancelled())?;
    let native_compile = require_complete_compile(&native_plan, "normal")?;
    verify_toolchain(toolchain, loaded, host)?;
    let native_members =
        compare_derived_objects(&original_native, &native_plan, &loaded.spec["nouveau"])?;

    let counter_work = work.join("counter");
    create_private_dir(&counter_work)?;
    let counter_request = nouveau_compile_request(
        &compile_records,
        ninja.to_owned(),
        material.roots.aros_nx.clone(),
        stage.clone(),
        toolchain.to_path_buf(),
        loaded.selected_compiler.sha256.clone(),
        counter_work.clone(),
        resource,
    );
    let counter_plan =
        compile_nouveau_with_prefix(counter_request, Some(HISTORICAL_PREFIX), || {
            runner.cancelled()
        })?;
    let counter_compile = require_complete_compile(&counter_plan, "historical-prefix")?;
    let original_prefix_counter = validate_original_prefix_counter(
        &original_native,
        &counter_plan,
        counter_compile,
        HISTORICAL_PREFIX,
    )?;
    write_new_json(
        &work.join("original-prefix-counter.json"),
        &original_prefix_counter,
    )?;

    let ar_path = toolchain.join("bin/llvm-ar");
    let ranlib_path = toolchain.join("bin/llvm-ranlib");
    let object_paths = plan_paths(&native_plan, "ordered_object_paths")?;
    let mut deterministic_archive = None;
    for index in 0..2 {
        runner.checkpoint("before deterministic Nouveau archive creation")?;
        let archive_path = work.join(format!("nouveau-{index}.a"));
        let mut ar_argv = vec![
            ar_path.as_os_str().to_os_string(),
            OsString::from("--format=gnu"),
            OsString::from("qcD"),
            archive_path.as_os_str().to_os_string(),
        ];
        ar_argv.extend(
            object_paths
                .iter()
                .map(|path| path.as_os_str().to_os_string()),
        );
        runner.run_argv(
            &ar_argv,
            &stage,
            &format!("native-archive-{index}"),
            Duration::from_secs(120),
        )?;
        runner.run_argv(
            &[
                ranlib_path.as_os_str().to_os_string(),
                OsString::from("-D"),
                archive_path.as_os_str().to_os_string(),
            ],
            &stage,
            &format!("native-ranlib-{index}"),
            Duration::from_secs(120),
        )?;
        let raw = read_regular_bounded(&archive_path, MAX_AR_BYTES)?;
        let archive = ami_rust_core::csdk_ar::read_archive(&raw)?;
        verify_derived_archive(&archive, &original_native, &native_members, loaded)?;
        if let Some(previous) = &deterministic_archive
            && previous != &archive.sha256
        {
            return Err(Refusal::new(
                "deterministic Nouveau archives differ between two runs",
            ));
        }
        deterministic_archive = Some(archive.sha256.clone());
        if index == 0 {
            overwrite_regular(&archive_path, &developer.join("lib/libdrm_nouveau.a"))?;
        }
    }

    verify_toolchain(toolchain, loaded, host)?;
    validate_component_tree(&developer, &loaded.candidate_profile)?;
    scan_for_local_prefixes(&developer, &loaded.candidate_profile, work)?;
    let profile_value = profile_value(&loaded.candidate_profile);
    let profile_path = output.join("csdk-profile.json");
    let profile_sha256 = write_new_json(&profile_path, &profile_value)?;
    if profile_sha256 != loaded.candidate_profile_sha256 {
        return Err(Refusal::new(
            "written C-SDK profile differs from its separate immutable identity",
        ));
    }

    let current_workspace_bytes = measure_workspace(work, output)?;
    let mut pack_limits = candidate_pack_limits(loaded)?;
    let archive_reservation = pack_limits
        .max_tar_bytes
        .checked_add(loaded_candidate_archive_bytes(loaded)?)
        .ok_or_else(|| Refusal::new("C-SDK packaging reservation overflow"))?;
    ensure_workspace_room(
        current_workspace_bytes,
        archive_reservation,
        resource.workspace_bytes,
    )?;
    let candidate_archive_name = candidate_archive_name(loaded)?;
    let archive_path = output.join(&candidate_archive_name);
    let tar_path = archive_path.with_extension("");
    // Preserve the existing liblzma encoding with the standard xz tool. Rust
    // owns canonical TAR generation and complete input/output validation.
    pack_limits.max_archive_bytes = pack_limits.max_tar_bytes;
    let tar_receipt = pack_csdk_tar(
        CsdkPackRequest {
            developer: developer.clone(),
            destination: tar_path.clone(),
            profile: loaded.candidate_profile.files.clone(),
            modes: staged.modes,
            limits: pack_limits,
        },
        |label| runner.checkpoint(label),
    )?;
    if executable_pin(&tools.xz.path, "C-SDK XZ compressor")? != tools.xz.pin {
        return Err(Refusal::new("C-SDK XZ compressor changed before packaging"));
    }
    let xz_version = runner
        .run_argv(
            &[
                tools.xz.path.as_os_str().to_owned(),
                OsString::from("--version"),
            ],
            output,
            "csdk-xz-version",
            Duration::from_secs(30),
        )?
        .record;
    runner.run_argv(
        &[
            tools.xz.path.as_os_str().to_owned(),
            OsString::from("--compress"),
            OsString::from("--format=xz"),
            OsString::from("--check=crc64"),
            OsString::from("--threads=1"),
            OsString::from("-6"),
            OsString::from("--keep"),
            OsString::from("--"),
            tar_path.as_os_str().to_owned(),
        ],
        output,
        "csdk-xz-canonical-archive",
        Duration::from_secs(120),
    )?;
    if executable_pin(&tools.xz.path, "C-SDK XZ compressor")? != tools.xz.pin {
        return Err(Refusal::new("C-SDK XZ compressor changed during packaging"));
    }
    let archive_bytes = read_regular_bounded(&archive_path, MAX_AR_BYTES)?;
    let pack_receipt = CsdkPackReceipt {
        archive: CsdkSourceFilePin {
            bytes: archive_bytes.len() as u64,
            sha256: decode_digest(&sha256_bytes(&archive_bytes))?,
        },
        decoded_tar: tar_receipt.decoded_tar,
        files: tar_receipt.files,
        file_bytes: tar_receipt.file_bytes,
    };
    if pack_receipt.archive.bytes != loaded_candidate_archive_bytes(loaded)?
        || hex_digest(&pack_receipt.archive.sha256) != loaded.candidate_archive_sha256
    {
        return Err(Refusal::new(
            "canonical candidate archive identity differs from its separate immutable pin",
        ));
    }
    let profile_readback = read_regular_bounded(&profile_path, MAX_PROFILE_BYTES)?;
    if sha256_bytes(&profile_readback) != profile_sha256 {
        return Err(Refusal::new(
            "written C-SDK profile changed during readback",
        ));
    }
    let archive_readback = read_regular_bounded(&archive_path, MAX_AR_BYTES)?;
    if archive_readback.len() as u64 != pack_receipt.archive.bytes
        || sha256_bytes(&archive_readback) != hex_digest(&pack_receipt.archive.sha256)
    {
        return Err(Refusal::new(
            "canonical C-SDK archive changed during readback",
        ));
    }
    let final_workspace_bytes = measure_workspace(work, output)?;
    ensure_workspace_room(final_workspace_bytes, 0, resource.workspace_bytes)?;
    runner.checkpoint("before writing portable C-SDK producer receipt")?;

    let record = json!({
        "schema": PRODUCER_SCHEMA,
        "host": host,
        "status": PRODUCER_STATUS,
        "spec_sha256": loaded.spec_sha256,
        "patches": original_patch_series,
        "prospective_genmodule_patches": prospective_patch_series,
        "source_capsule_sha256": loaded.source_capsule.sha256,
        "public_headers": headers,
        "prefix_probe": prefix_probe,
        "aom": aom,
        "native_compile": native_compile,
        "native_compile_plan": plan_evidence(&native_plan, &work.join("nouveau-compile"))?,
        "native_members": native_members,
        "original_prefix_counter": original_prefix_counter,
        "original_prefix_counter_plan": plan_evidence(&counter_plan, &counter_work)?,
        "native_symbol_entries": NOUVEAU_SYMBOLS,
        "candidate_archive": {
            "path": candidate_archive_name,
            "bytes": pack_receipt.archive.bytes,
            "sha256": hex_digest(&pack_receipt.archive.sha256),
        },
        "canonical_tar": {"bytes": pack_receipt.decoded_tar.bytes,
                          "sha256": hex_digest(&pack_receipt.decoded_tar.sha256)},
        "xz_compressor": {"path": tools.xz.path, "bytes": tools.xz.pin.bytes,
                          "sha256": hex_digest(&tools.xz.pin.sha256), "version": xz_version},
        "profile_sha256": profile_sha256,
        "resource_policy_sha256": resource.sha256,
        "commands": runner.commands,
        "capture_boundaries": {
            "direct_commands": "Bounded process_capture, per-command logs and timeouts; no aggregate process-tree resource observer is owned by this producer.",
            "nouveau": "Per-compiler process-tree and shared-root samples from the existing core executor; coordinator and concurrent sibling compiler are excluded.",
            "workflow": "Aggregate workflow observation remains the outer workflow's responsibility.",
        },
        "baseline_changed": false,
        "R1_accepted": false,
    });
    write_new_json(&output.join("csdk-producer.json"), &record)?;
    Ok(record)
}

fn load_inputs(
    source_root: &Path,
    spec_path: &Path,
    original_archive_path: &Path,
    host: &str,
) -> Result<LoadedInputs> {
    let spec_bytes = read_regular_bounded(spec_path, MAX_SPEC_BYTES)?;
    let spec_sha256 = sha256_bytes(&spec_bytes);
    let spec = parse_json_value(&spec_bytes, JsonProfile::SdkComponentManifest)?;
    if spec["schema"].as_str() != Some(SOURCE_SCHEMA)
        || spec["status"].as_str() != Some(SOURCE_STATUS)
        || spec["required_counts"]
            != json!({
                "regular_files": ORIGINAL_FILE_COUNT,
                "changed_files": CHANGED_FILE_COUNT,
                "public_headers": PUBLIC_HEADER_COUNT,
            })
    {
        return Err(Refusal::new(
            "unrecognized portable C-SDK candidate contract",
        ));
    }
    validate_native_counts(&spec["nouveau"])?;
    let original_archive = pin_from_object(&spec["original"]["archive"], "original archive")?;
    verify_path_pin(
        original_archive_path,
        &original_archive,
        "original C-SDK archive",
    )?;
    let original_profile_pin = pin_from_object(&spec["original"]["profile"], "original profile")?;
    let candidate_profile_pin =
        pin_from_object(&spec["candidate"]["profile"], "candidate profile")?;
    let original_profile_path = pinned_path(source_root, &original_profile_pin)?;
    let candidate_profile_path = pinned_path(source_root, &candidate_profile_pin)?;
    let original_profile = parse_profile(
        &parse_json_file(&original_profile_path, MAX_PROFILE_BYTES)?,
        "original C-SDK profile",
        true,
    )?;
    let candidate_profile = parse_profile(
        &parse_json_file(&candidate_profile_path, MAX_PROFILE_BYTES)?,
        "candidate C-SDK profile",
        true,
    )?;
    validate_profiles(&original_profile, &candidate_profile)?;
    let candidate_profile_sha256 = candidate_profile_pin.sha256.clone();

    let source_capsule = pin_from_object(&spec["source_capsule"], "source capsule")?;
    let source_manifest_pin = pin_from_object(&spec["source_manifest"], "source manifest")?;
    let patch_series = pin_from_object(&spec["patch_series"], "source patch series")?;
    for pin in [&source_capsule, &source_manifest_pin, &patch_series] {
        let _ = pinned_path(source_root, pin)?;
    }
    let source_manifest_path = pinned_path(source_root, &source_manifest_pin)?;
    let source_manifest = parse_json_file(&source_manifest_path, MAX_PROFILE_BYTES)?;
    validate_source_manifest(&source_manifest, &source_capsule, &original_archive)?;
    let nested_archive = nested_archive_pin(&source_manifest)?;
    let patch_series_path = pinned_path(source_root, &patch_series)?;
    let patch_series_value = parse_json_file(&patch_series_path, MAX_PROFILE_BYTES)?;
    let nested_generator_sha256 = series_preimage_sha(
        &patch_series_value,
        "libaom",
        "build/cmake/pkg_config.cmake",
    )?;
    let mesa_patch_sha256 = manifest_file_sha(&source_manifest, MESA_PATCH_PATH)?;
    if encode_hex(&mesa_patch_sha256) != MESA_PATCH_SHA256 {
        return Err(Refusal::new(
            "pinned Mesa source patch differs from its reviewed identity",
        ));
    }
    let prospective_series_path =
        source_root.join("release/portable-csdk/next-genmodule/series.json");
    let prospective_series = PinnedFile {
        path: "release/portable-csdk/next-genmodule/series.json".to_owned(),
        identity: CsdkSourceFilePin {
            bytes: NEXT_GENMODULE_SERIES_BYTES,
            sha256: decode_digest(NEXT_GENMODULE_SERIES_SHA256)?,
        },
        sha256: NEXT_GENMODULE_SERIES_SHA256.to_owned(),
    };
    verify_path_pin(
        &prospective_series_path,
        &prospective_series,
        "prospective genmodule patch series",
    )?;
    let prospective_value = parse_json_file(&prospective_series_path, MAX_PROFILE_BYTES)?;
    if prospective_value["schema"].as_str() != Some("ami-rust-portable-csdk-patches-v1") {
        return Err(Refusal::new(
            "prospective genmodule patch series schema is unsupported",
        ));
    }
    validate_toolchain_hosts(source_root, &spec, host)?;
    let selected_toolchain = &spec["toolchains"][host];
    let selected_toolchain_profile =
        pin_from_object(&selected_toolchain["profile"], "toolchain profile")?;
    let selected_compiler = pin_from_object(&selected_toolchain["compiler"], "toolchain compiler")?;
    if selected_compiler.path != "bin/clang-11" {
        return Err(Refusal::new(
            "portable C-SDK toolchain compiler must be bin/clang-11",
        ));
    }
    let candidate_archive = pin_from_object(&spec["candidate"]["archive"], "candidate archive")?;
    if spec["candidate"]["archive"]["name"].as_str() != Some("csdk-component.tar.xz") {
        return Err(Refusal::new(
            "candidate archive name differs from its producer output contract",
        ));
    }
    let candidate_archive_sha256 = candidate_archive.sha256;

    Ok(LoadedInputs {
        spec,
        spec_sha256,
        original_profile,
        candidate_profile,
        candidate_profile_sha256,
        original_archive,
        candidate_archive_sha256,
        source_capsule,
        source_manifest_pin,
        patch_series,
        selected_toolchain_profile: parse_profile(
            &parse_json_file(
                &pinned_path(source_root, &selected_toolchain_profile)?,
                MAX_PROFILE_BYTES,
            )?,
            "selected C-SDK toolchain profile",
            false,
        )?,
        selected_compiler,
        nested_archive,
        nested_generator_sha256,
        mesa_patch_sha256,
        prospective_series,
    })
}

fn validate_toolchain_hosts(source_root: &Path, spec: &Value, actual_host: &str) -> Result<()> {
    let toolchains = spec["toolchains"]
        .as_object()
        .ok_or_else(|| Refusal::new("portable C-SDK toolchain pins must be an object"))?;
    let expected = BTreeSet::from(["linux-aarch64", "linux-x86_64", "macos-aarch64"]);
    if toolchains
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(Refusal::new(
            "portable C-SDK toolchain pins must cover exactly the admitted hosts",
        ));
    }
    for host in expected {
        let row = &spec["toolchains"][host];
        let profile = pin_from_object(&row["profile"], "toolchain profile")?;
        let _ = parse_profile(
            &parse_json_file(&pinned_path(source_root, &profile)?, MAX_PROFILE_BYTES)?,
            "C-SDK toolchain profile",
            false,
        )?;
        let compiler = pin_from_object(&row["compiler"], "toolchain compiler")?;
        if compiler.path != "bin/clang-11" {
            return Err(Refusal::new(
                "portable C-SDK toolchain compiler path is malformed",
            ));
        }
        if host == "linux-aarch64" {
            let archive = &row["archive"];
            if archive["kind"].as_str() != Some("tar")
                || archive["url"].as_str() != Some(ARM_TOOLCHAIN_URL)
                || archive["archive_root"].as_str() != Some("toolchain")
                || archive["bytes"].as_u64().is_none_or(|value| value == 0)
                || archive["sha256"]
                    .as_str()
                    .is_none_or(|value| !is_sha256_digest(value))
            {
                return Err(Refusal::new(
                    "portable C-SDK Linux/AArch64 archive pin is malformed",
                ));
            }
            let keys = archive
                .as_object()
                .map(|value| value.keys().map(String::as_str).collect::<BTreeSet<_>>())
                .ok_or_else(|| {
                    Refusal::new("portable C-SDK Linux/AArch64 archive pin is malformed")
                })?;
            if keys != BTreeSet::from(["kind", "url", "bytes", "sha256", "archive_root"]) {
                return Err(Refusal::new(
                    "portable C-SDK Linux/AArch64 archive pin has unknown fields",
                ));
            }
        } else if row.get("archive").is_some() {
            return Err(Refusal::new(
                "unexpected archive pin for a native-host toolchain",
            ));
        }
    }
    if !matches!(
        actual_host,
        "linux-x86_64" | "linux-aarch64" | "macos-aarch64"
    ) {
        return Err(Refusal::new(
            "actual native host is not admitted for C-SDK production",
        ));
    }
    Ok(())
}

fn validate_source_manifest(
    manifest: &Value,
    capsule: &PinnedFile,
    original: &PinnedFile,
) -> Result<()> {
    let capsule_pin = &manifest["capsule"];
    if capsule_pin["path"].as_str() != Some("csdk-corresponding-source.tar.xz")
        || capsule_pin["bytes"].as_u64() != Some(capsule.identity.bytes)
        || capsule_pin["sha256"].as_str() != Some(capsule.sha256.as_str())
        || manifest["sdk_input"]["bytes"].as_u64() != Some(original.identity.bytes)
        || manifest["sdk_input"]["sha256"].as_str() != Some(original.sha256.as_str())
    {
        return Err(Refusal::new(
            "portable C-SDK source manifest differs from its pinned identities",
        ));
    }
    let inventory = manifest["inventory"]
        .as_array()
        .ok_or_else(|| Refusal::new("portable C-SDK source manifest has no inventory"))?;
    if inventory.iter().any(|row| {
        row["path"]
            .as_str()
            .is_some_and(|path| path.starts_with("sources/AROS-NX/arch/all-native/include/"))
    }) {
        return Err(Refusal::new(
            "declared empty source include unexpectedly has frozen entries",
        ));
    }
    Ok(())
}

fn validate_native_counts(nouveau: &Value) -> Result<()> {
    for (key, expected) in [
        ("objects", NOUVEAU_OBJECTS),
        ("unchanged_members", 616),
        ("path_changed_members", 209),
        ("symbols", NOUVEAU_SYMBOLS),
    ] {
        if nouveau[key].as_u64() != Some(expected) {
            return Err(Refusal::new(
                "portable C-SDK native counts differ from the frozen contract",
            ));
        }
    }
    if nouveau["archive_path"].as_str() != Some("lib/libdrm_nouveau.a")
        || nouveau["original_bytes"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || nouveau["derived_bytes"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || nouveau["original_sha256"]
            .as_str()
            .is_none_or(|value| !is_sha256_digest(value))
        || nouveau["derived_sha256"]
            .as_str()
            .is_none_or(|value| !is_sha256_digest(value))
    {
        return Err(Refusal::new(
            "portable C-SDK Nouveau archive pins are malformed",
        ));
    }
    Ok(())
}

fn validate_profiles(original: &Profile, candidate: &Profile) -> Result<Vec<String>> {
    if !original.symlinks.is_empty() || !candidate.symlinks.is_empty() {
        return Err(Refusal::new(
            "C-SDK profiles require regular files and no symlinks",
        ));
    }
    let before = profile_rows(original)?;
    let after = profile_rows(candidate)?;
    if before.len() != ORIGINAL_FILE_COUNT || before.keys().ne(after.keys()) {
        return Err(Refusal::new(
            "portable C-SDK must preserve the original 2835-file set",
        ));
    }
    let changed = before
        .iter()
        .filter_map(|(path, identity)| (after.get(path) != Some(identity)).then_some(path.clone()))
        .collect::<Vec<_>>();
    let headers = changed
        .iter()
        .filter(|path| path.starts_with("include/") && path.ends_with(".h"))
        .count();
    let non_headers = changed
        .iter()
        .filter(|path| !path.starts_with("include/") || !path.ends_with(".h"))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if changed.len() != CHANGED_FILE_COUNT
        || headers != PUBLIC_HEADER_COUNT
        || non_headers != BTreeSet::from(["lib/libdrm_nouveau.a", "lib/pkgconfig/aom.pc"])
    {
        return Err(Refusal::new(
            "portable C-SDK change set is not exactly 530 headers, Nouveau and aom.pc",
        ));
    }
    Ok(changed)
}

fn profile_rows(profile: &Profile) -> Result<BTreeMap<String, (u64, String)>> {
    let mut rows = BTreeMap::new();
    for identity in &profile.files {
        validate_relative_inventory_path(&identity.path)?;
        if identity.path.is_empty()
            || !identity.path.is_ascii()
            || !is_sha256_digest(&identity.sha256)
            || rows
                .insert(
                    identity.path.clone(),
                    (identity.bytes, identity.sha256.clone()),
                )
                .is_some()
        {
            return Err(Refusal::new("duplicate or malformed C-SDK profile file"));
        }
    }
    Ok(rows)
}

fn parse_profile(value: &Value, label: &str, require_no_links: bool) -> Result<Profile> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new(format!("{label} must be an object")))?;
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if keys != BTreeSet::from(["files", "symlinks"]) {
        return Err(Refusal::new(format!(
            "{label} has missing or unknown fields"
        )));
    }
    let files: Vec<FileIdentity> = serde_json::from_value(value["files"].clone())
        .map_err(|error| Refusal::new(format!("{label} file rows are malformed: {error}")))?;
    let symlinks: Vec<LinkIdentity> = serde_json::from_value(value["symlinks"].clone())
        .map_err(|error| Refusal::new(format!("{label} symlink rows are malformed: {error}")))?;
    if require_no_links && !symlinks.is_empty() {
        return Err(Refusal::new(format!("{label} must not contain symlinks")));
    }
    let profile = Profile { files, symlinks };
    let _ = profile_rows(&profile)?;
    Ok(profile)
}

fn verify_toolchain(toolchain: &Path, loaded: &LoadedInputs, host: &str) -> Result<PathBuf> {
    validate_component_tree(toolchain, &loaded.selected_toolchain_profile)?;
    let compiler = pinned_path(toolchain, &loaded.selected_compiler)?;
    let pin = &loaded.selected_compiler;
    verify_path_pin(&compiler, pin, "portable C-SDK target compiler")?;
    let metadata = fs::symlink_metadata(&compiler)?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(Refusal::new(
            "portable C-SDK target compiler is not executable",
        ));
    }
    if host.is_empty() {
        return Err(Refusal::new("native host identity is empty"));
    }
    Ok(compiler)
}

fn validate_component_tree(root: &Path, profile: &Profile) -> Result<()> {
    verify_complete(
        root,
        &profile.files,
        &profile.symlinks,
        InventoryLimits {
            max_tree_entries: profile
                .files
                .len()
                .saturating_add(profile.symlinks.len())
                .saturating_mul(8)
                .max(1_000),
            max_link_resolution_steps: profile.symlinks.len().saturating_mul(256).max(1_000),
        },
    )?;
    Ok(())
}

fn original_archive_limits(
    compressed_bytes: u64,
    profile: &Profile,
    current_workspace_bytes: u64,
    max_workspace_bytes: u64,
) -> Result<ArchiveLimits> {
    let expanded = profile.files.iter().try_fold(0_u64, |sum, file| {
        sum.checked_add(file.bytes)
            .ok_or_else(|| Refusal::new("original C-SDK profile byte count overflow"))
    })?;
    let max_file = profile
        .files
        .iter()
        .map(|file| file.bytes)
        .max()
        .unwrap_or(0);
    Ok(ArchiveLimits {
        max_compressed_bytes: compressed_bytes,
        max_decoded_tar_bytes: 1024 * 1024 * 1024,
        max_expanded_bytes: expanded.max(1),
        max_file_bytes: max_file.max(1),
        max_members: profile.files.len().saturating_mul(8).max(10_000),
        max_index_bytes: 64 * 1024 * 1024,
        max_path_bytes: 4_096,
        max_path_components: 128,
        max_extension_bytes: 1024 * 1024,
        current_workspace_bytes,
        max_workspace_bytes,
        xz_memory_limit_kib: 64 * 1024,
    })
}

fn candidate_pack_limits(loaded: &LoadedInputs) -> Result<CsdkPackLimits> {
    let payload = loaded
        .candidate_profile
        .files
        .iter()
        .try_fold(0_u64, |sum, file| {
            sum.checked_add(file.bytes)
                .ok_or_else(|| Refusal::new("candidate C-SDK profile byte count overflow"))
        })?;
    Ok(CsdkPackLimits {
        max_files: ORIGINAL_FILE_COUNT,
        max_file_bytes: 512 * 1024 * 1024,
        max_payload_bytes: payload.max(1),
        max_tar_bytes: payload
            .saturating_add((ORIGINAL_FILE_COUNT as u64).saturating_mul(2_048))
            .saturating_add(10_240),
        max_archive_bytes: loaded_candidate_archive_bytes(loaded)?,
    })
}

fn install_regenerated_headers(
    headers_root: &Path,
    developer: &Path,
    sdk_include: &Path,
    genincludir: &Path,
    recipes: &[Value],
    header_record: &Value,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (index, recipe) in recipes.iter().enumerate() {
        let outputs = recipe["outputs"]
            .as_array()
            .ok_or_else(|| Refusal::new("public-header recipe has no outputs"))?;
        for output in outputs {
            let name = output
                .as_str()
                .ok_or_else(|| Refusal::new("public-header recipe output must be text"))?;
            validate_relative_inventory_path(name)?;
            if !seen.insert(name.to_owned()) {
                return Err(Refusal::new("public-header recipe output is duplicated"));
            }
            let expected = header_record
                .get("headers")
                .and_then(|rows| rows.get(name))
                .and_then(|row| row.get("sha256"))
                .and_then(Value::as_str)
                .ok_or_else(|| Refusal::new("public-header receipt lacks an output identity"))?;
            let generated = headers_root
                .join("headers-0")
                .join(index.to_string())
                .join(name);
            let bytes = read_regular_bounded(&generated, 64 * 1024 * 1024)?;
            if sha256_bytes(&bytes) != expected {
                return Err(Refusal::new(
                    "regenerated public header differs from its receipt",
                ));
            }
            for root in [
                developer.join("include"),
                sdk_include.to_path_buf(),
                genincludir.to_path_buf(),
            ] {
                let target = root.join(name);
                let metadata = fs::symlink_metadata(&target)?;
                if !metadata.file_type().is_file() {
                    return Err(Refusal::new(
                        "original public-header staging target is not a regular file",
                    ));
                }
                overwrite_regular(&generated, &target)?;
            }
        }
    }
    if seen.len() != PUBLIC_HEADER_COUNT {
        return Err(Refusal::new(
            "regenerated public-header set is not exactly 530 files",
        ));
    }
    Ok(())
}

fn apply_patch_series(
    roots: &CsdkSourceRoots,
    series_path: PathBuf,
    series_pin: CsdkSourceFilePin,
    runner: &mut ProducerRunner<'_>,
    series_label: &str,
) -> Result<Vec<Value>> {
    let parent = series_path
        .parent()
        .ok_or_else(|| Refusal::new("C-SDK patch series has no parent directory"))?;
    let patch_runner = RefCell::new(runner);
    let receipts = apply_csdk_source_patches(
        roots,
        parent,
        series_pin,
        |argv, cwd, label, timeout| {
            let qualified = format!("{series_label}-{label}");
            patch_runner
                .borrow_mut()
                .run_argv(argv, cwd, &qualified, timeout)
                .map(|_| ())
        },
        |label| patch_runner.borrow().checkpoint(label),
    )?;
    Ok(receipts)
}

#[allow(clippy::too_many_arguments)]
fn nouveau_compile_request(
    records: &[Value],
    ninja_text: String,
    source_root: PathBuf,
    build_root: PathBuf,
    toolchain_root: PathBuf,
    compiler_sha256: String,
    work_dir: PathBuf,
    resource: &ResourcePolicy,
) -> NouveauCompileRequest {
    NouveauCompileRequest {
        records: records.to_vec(),
        ninja_text,
        source_root,
        build_root,
        toolchain_root,
        compiler_sha256,
        work_dir,
        jobs: 2,
        timeout: resource.timeout,
        resource_limits: resource.limits,
        sample_limits: resource.sample_limits,
    }
}

fn require_complete_compile<'a>(plan: &'a Value, label: &str) -> Result<&'a Value> {
    if plan["status"].as_str() != Some("NOUVEAU_825_COMPILE_COMMANDS_COMPLETE")
        || plan["object_count"].as_u64() != Some(NOUVEAU_OBJECTS)
    {
        return Err(Refusal::new(format!(
            "{label} Nouveau compilation did not complete all 825 commands"
        )));
    }
    let compile = plan
        .get("compile")
        .ok_or_else(|| Refusal::new(format!("{label} Nouveau plan has no compile summary")))?;
    if compile["completed"].as_u64() != Some(NOUVEAU_OBJECTS) || !compile["failure"].is_null() {
        return Err(Refusal::new(format!(
            "{label} Nouveau compile summary is incomplete"
        )));
    }
    Ok(compile)
}

fn compare_derived_objects(
    original: &ami_rust_core::csdk_ar::Archive<'_>,
    plan: &Value,
    nouveau_pin: &Value,
) -> Result<Vec<Value>> {
    let paths = plan_paths(plan, "ordered_object_paths")?;
    if paths.len() != NOUVEAU_OBJECTS as usize || original.members.len() != paths.len() {
        return Err(Refusal::new(
            "Nouveau object-order comparison requires 825 members",
        ));
    }
    let planned_names = plan
        .get("member_basenames")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("Nouveau plan has no archive member order"))?;
    if planned_names.len() != original.members.len()
        || original
            .members
            .iter()
            .zip(planned_names)
            .any(|(member, planned)| planned.as_str() != Some(member.name.as_str()))
    {
        return Err(Refusal::new(
            "original Nouveau archive member order differs from the build plan",
        ));
    }
    let historical_prefix = nouveau_pin["historical_source_prefix"]
        .as_str()
        .ok_or_else(|| Refusal::new("historical Nouveau source prefix is missing"))?;
    if historical_prefix != HISTORICAL_PREFIX {
        return Err(Refusal::new(
            "historical Nouveau source prefix differs from its frozen value",
        ));
    }
    let old_prefix = format!("{historical_prefix}/").into_bytes();
    let mut compared = Vec::with_capacity(paths.len());
    for (index, (old, path)) in original.members.iter().zip(paths).enumerate() {
        let raw = read_regular_bounded(&path, MAX_OBJECT_BYTES)?;
        let changed = raw.as_slice() != old.data;
        let path_bearing = old
            .data
            .windows(old_prefix.len())
            .any(|window| window == old_prefix);
        if changed != path_bearing {
            return Err(Refusal::new(format!(
                "unexplained Nouveau object change at index {index}"
            )));
        }
        reject_local_prefixes(&raw, &path)?;
        compared.push(json!({
            "index": index,
            "name": old.name,
            "original_sha256": old.sha256,
            "derived_sha256": sha256_bytes(&raw),
            "derived_bytes": raw.len(),
            "changed": changed,
        }));
    }
    if compared
        .iter()
        .filter(|row| row["changed"].as_bool() == Some(true))
        .count()
        != 209
    {
        return Err(Refusal::new(
            "Nouveau path-change coverage differs from 209 objects",
        ));
    }
    Ok(compared)
}

fn validate_original_prefix_counter(
    original: &ami_rust_core::csdk_ar::Archive<'_>,
    plan: &Value,
    compile: &Value,
    replacement: &str,
) -> Result<Value> {
    let paths = plan_paths(plan, "ordered_object_paths")?;
    if paths.len() != original.members.len() || paths.len() != NOUVEAU_OBJECTS as usize {
        return Err(Refusal::new(
            "historical-prefix counter must contain 825 objects",
        ));
    }
    if plan["prefix_map_replacement"].as_str() != Some(replacement) {
        return Err(Refusal::new(
            "historical-prefix counter did not use its declared prefix",
        ));
    }
    let mut members = Vec::with_capacity(paths.len());
    for (index, (old, path)) in original.members.iter().zip(paths).enumerate() {
        let raw = read_regular_bounded(&path, MAX_OBJECT_BYTES)?;
        if raw.as_slice() != old.data {
            return Err(Refusal::new(format!(
                "historical-prefix counter did not reproduce original object {index}"
            )));
        }
        members.push(json!({"index": index, "sha256": old.sha256}));
        fs::remove_file(path)?;
    }
    let mut compile_summary = compile.clone();
    if let Some(object) = compile_summary.as_object_mut() {
        object.remove("compiler_runs");
    }
    Ok(json!({
        "status": "PASS_ALL_825_ORIGINAL_OBJECTS_REPRODUCED",
        "members": members,
        "prefix_replacement": replacement,
        "compile": compile_summary,
    }))
}

fn verify_original_native_archive(
    original: &ami_rust_core::csdk_ar::Archive<'_>,
    loaded: &LoadedInputs,
) -> Result<()> {
    let pin = &loaded.spec["nouveau"];
    if original.sha256 != pin["original_sha256"].as_str().unwrap_or_default()
        || original.bytes as u64 != pin["original_bytes"].as_u64().unwrap_or_default()
        || original.members.len() != NOUVEAU_OBJECTS as usize
        || original.symbols.len() != NOUVEAU_SYMBOLS as usize
    {
        return Err(Refusal::new(
            "original Nouveau archive identity, member count or symbol count differs",
        ));
    }
    Ok(())
}

fn verify_derived_archive(
    archive: &ami_rust_core::csdk_ar::Archive<'_>,
    original: &ami_rust_core::csdk_ar::Archive<'_>,
    compared: &[Value],
    loaded: &LoadedInputs,
) -> Result<()> {
    let pin = &loaded.spec["nouveau"];
    if archive.symbols != original.symbols
        || archive.members.len() != NOUVEAU_OBJECTS as usize
        || archive.sha256 != pin["derived_sha256"].as_str().unwrap_or_default()
        || archive.bytes as u64 != pin["derived_bytes"].as_u64().unwrap_or_default()
        || archive.members.len() != compared.len()
    {
        return Err(Refusal::new(
            "derived native archive or symbol-to-member index differs",
        ));
    }
    for (member, row) in archive.members.iter().zip(compared) {
        if member.name != row["name"].as_str().unwrap_or_default()
            || member.sha256 != row["derived_sha256"].as_str().unwrap_or_default()
            || member.bytes as u64 != row["derived_bytes"].as_u64().unwrap_or_default()
        {
            return Err(Refusal::new(
                "native archive does not contain every exact compiled object",
            ));
        }
    }
    Ok(())
}

fn plan_paths(plan: &Value, key: &str) -> Result<Vec<PathBuf>> {
    plan.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new(format!("Nouveau plan has no {key} array")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(PathBuf::from)
                .ok_or_else(|| Refusal::new(format!("Nouveau plan {key} contains a non-path")))
        })
        .collect()
}

fn plan_evidence(plan: &Value, work_dir: &Path) -> Result<Value> {
    let path = work_dir.join("nouveau-compile-plan.json");
    Ok(json!({
        "path": path.to_string_lossy(),
        "sha256": sha256_file(&path)?,
        "status": plan["status"],
        "object_count": plan["object_count"],
    }))
}

fn scan_for_local_prefixes(developer: &Path, profile: &Profile, work: &Path) -> Result<()> {
    let mut prefixes = vec![
        b"/Volumes/Dev/Source/".to_vec(),
        b"/Users/fabian/".to_vec(),
        b"/home/runner/".to_vec(),
        b"/Users/runner/".to_vec(),
        work.as_os_str().as_bytes().to_vec(),
    ];
    prefixes.retain(|prefix| !prefix.is_empty());
    for identity in &profile.files {
        let path = developer.join(&identity.path);
        let bytes = read_regular_bounded(&path, 512 * 1024 * 1024)?;
        reject_local_prefixes_from(&bytes, &prefixes, &path)?;
    }
    Ok(())
}

fn reject_local_prefixes(bytes: &[u8], path: &Path) -> Result<()> {
    let prefixes = [
        b"/Volumes/".as_slice(),
        b"/Users/fabian/".as_slice(),
        b"/home/runner/".as_slice(),
        b"/Users/runner/".as_slice(),
    ];
    if prefixes.iter().any(|prefix| contains_bytes(bytes, prefix)) {
        return Err(Refusal::new(format!(
            "local build prefix remains in Nouveau object: {}",
            path.display()
        )));
    }
    Ok(())
}

fn reject_local_prefixes_from(bytes: &[u8], prefixes: &[Vec<u8>], path: &Path) -> Result<()> {
    if prefixes.iter().any(|prefix| contains_bytes(bytes, prefix)) {
        return Err(Refusal::new(format!(
            "local build prefix remains in derived C-SDK: {}",
            path.display()
        )));
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn forbidden_prefixes(work: &Path) -> Vec<Vec<u8>> {
    vec![
        b"/Volumes/Dev/Source/".to_vec(),
        b"/Users/fabian/".to_vec(),
        b"/home/runner/".to_vec(),
        b"/Users/runner/".to_vec(),
        work.as_os_str().as_bytes().to_vec(),
    ]
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn create_directory_chain(path: &Path) -> Result<()> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => cursor.push(component.as_os_str()),
            Component::Normal(name) => {
                cursor.push(name);
                match fs::symlink_metadata(&cursor) {
                    Ok(metadata) if metadata.file_type().is_dir() => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        create_private_dir(&cursor)?;
                    }
                    _ => {
                        return Err(Refusal::new(
                            "staging directory chain contains an unsafe entry",
                        ));
                    }
                }
            }
            _ => return Err(Refusal::new("staging directory path is not normalized")),
        }
    }
    Ok(())
}

fn create_empty_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(path),
        _ => Err(Refusal::new(
            "expected empty C-SDK source include directory is not fresh",
        )),
    }
}

fn relocate_staged_developer(staged: &Path, sys_root: &Path) -> Result<PathBuf> {
    let destination = sys_root.join("Developer");
    if destination.exists() || destination.is_symlink() {
        return Err(Refusal::new(
            "original C-SDK staging destination is not fresh",
        ));
    }
    fs::rename(staged, &destination)?;
    let archive_root = sys_root.join("archive");
    let entries = fs::read_dir(&archive_root)?.collect::<std::io::Result<Vec<_>>>()?;
    if !entries.is_empty() {
        return Err(Refusal::new(
            "original C-SDK staging container contains unexpected entries",
        ));
    }
    fs::remove_dir(archive_root)?;
    Ok(destination)
}

fn copy_regular_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_dir() {
        return Err(Refusal::new(
            "C-SDK generated include source is not a real directory",
        ));
    }
    create_private_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_dir() {
            copy_regular_tree(&source_path, &target_path)?;
        } else if metadata.file_type().is_file() {
            fs::copy(&source_path, &target_path)?;
            fs::set_permissions(
                &target_path,
                fs::Permissions::from_mode(metadata.permissions().mode() & 0o777),
            )?;
        } else {
            return Err(Refusal::new(
                "generated C-SDK include tree contains a non-regular entry",
            ));
        }
    }
    Ok(())
}

fn overwrite_regular(source: &Path, destination: &Path) -> Result<()> {
    let source_metadata = fs::symlink_metadata(source)?;
    let destination_metadata = fs::symlink_metadata(destination)?;
    if !source_metadata.file_type().is_file() || !destination_metadata.file_type().is_file() {
        return Err(Refusal::new("C-SDK replacement requires two regular files"));
    }
    let bytes = read_regular_bounded(source, 512 * 1024 * 1024)?;
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(destination)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

fn read_resource_policy(source_root: &Path) -> Result<ResourcePolicy> {
    let path = source_root.join(RESOURCE_POLICY_PATH);
    let raw = read_regular_bounded(&path, MAX_POLICY_BYTES)?;
    let sha256 = sha256_bytes(&raw);
    let value = parse_json_value(&raw, JsonProfile::SdkComponentManifest)?;
    if value["schema"].as_str() != Some("ami-rust-hosted-resources-v1") {
        return Err(Refusal::new("unsupported portable C-SDK resource policy"));
    }
    let build = &value["build"];
    if build
        != &json!({
            "jobs": RESOURCE_JOBS,
            "rss_bytes": RESOURCE_RSS_BYTES,
            "seconds": RESOURCE_SECONDS,
            "workspace_bytes": RESOURCE_WORKSPACE_BYTES,
            "log_bytes": RESOURCE_LOG_BYTES,
        })
    {
        return Err(Refusal::new(
            "portable C-SDK build ceilings differ from the admitted resource profile",
        ));
    }
    let capacity = &value["host_capacity"];
    if capacity["schema"].as_str() != Some("ami-rust-host-capacity-v1")
        || capacity["ram_minimum_bytes"]
            .as_u64()
            .is_none_or(|number| number < MINIMUM_RAM_BYTES)
        || capacity["disk_free_minimum_bytes"]
            .as_u64()
            .is_none_or(|number| number < MINIMUM_FREE_DISK_BYTES)
    {
        return Err(Refusal::new(
            "portable C-SDK host capacity policy is malformed",
        ));
    }
    let positive = |key: &str| -> Result<u64> {
        build[key]
            .as_u64()
            .filter(|number| *number > 0)
            .ok_or_else(|| Refusal::new(format!("resource policy build.{key} must be positive")))
    };
    let seconds = positive("seconds")?;
    Ok(ResourcePolicy {
        sha256,
        limits: ResourceLimits {
            max_visible_rss_bytes: positive("rss_bytes")?,
            max_workspace_bytes: positive("workspace_bytes")?,
            max_log_bytes: positive("log_bytes")?,
        },
        sample_limits: SampleLimits {
            max_ps_bytes: 2 * 1024 * 1024,
            max_ps_rows: 32_768,
            max_history_entries: 131_072,
            max_roots: 4,
            scan: ScanLimits {
                max_entries: MAX_TREE_ENTRIES as u64,
                max_work_units: MAX_WORK_UNITS as u64,
            },
        },
        timeout: Duration::from_secs(seconds),
        workspace_bytes: positive("workspace_bytes")?,
    })
}

fn measure_workspace(work: &Path, output: &Path) -> Result<u64> {
    let limits = ScanLimits {
        max_entries: MAX_TREE_ENTRIES as u64,
        max_work_units: MAX_WORK_UNITS as u64,
    };
    let work_size = workspace_accounting::scan(work, limits)
        .map_err(|error| Refusal::new(format!("C-SDK work accounting failed: {error}")))?
        .regular_file_bytes;
    let output_size = workspace_accounting::scan(output, limits)
        .map_err(|error| Refusal::new(format!("C-SDK output accounting failed: {error}")))?
        .regular_file_bytes;
    work_size
        .checked_add(output_size)
        .ok_or_else(|| Refusal::new("C-SDK workspace byte count overflow"))
}

fn ensure_workspace_room(current: u64, additional: u64, maximum: u64) -> Result<()> {
    if current
        .checked_add(additional)
        .is_none_or(|value| value > maximum)
    {
        return Err(Refusal::new(
            "portable C-SDK workspace exceeds the selected resource policy",
        ));
    }
    Ok(())
}

fn loaded_candidate_archive_bytes(loaded: &LoadedInputs) -> Result<u64> {
    loaded.spec["candidate"]["archive"]["bytes"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| Refusal::new("candidate archive byte pin is malformed"))
}

fn candidate_archive_name(loaded: &LoadedInputs) -> Result<String> {
    let name = loaded.spec["candidate"]["archive"]["name"]
        .as_str()
        .ok_or_else(|| Refusal::new("candidate archive name is missing"))?;
    validate_relative_inventory_path(name)?;
    if name.contains('/') || name.contains('\\') {
        return Err(Refusal::new(
            "candidate archive name must be a single path component",
        ));
    }
    Ok(name.to_owned())
}

fn profile_value(profile: &Profile) -> Value {
    json!({"files":profile.files,"symlinks":profile.symlinks})
}

fn parse_json_file(path: &Path, maximum: usize) -> Result<Value> {
    let raw = read_regular_bounded(path, maximum)?;
    parse_json_value(&raw, JsonProfile::SdkComponentManifest)
}

fn pin_from_object(value: &Value, label: &str) -> Result<PinnedFile> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new(format!("{label} pin must be an object")))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("{label} pin path is missing")))?;
    validate_relative_inventory_path(path)?;
    let bytes = object
        .get("bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| Refusal::new(format!("{label} pin byte count is malformed")))?;
    let sha256 = object
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| is_sha256_digest(value))
        .ok_or_else(|| Refusal::new(format!("{label} pin digest is malformed")))?
        .to_owned();
    Ok(PinnedFile {
        path: path.to_owned(),
        identity: CsdkSourceFilePin {
            bytes,
            sha256: decode_digest(&sha256)?,
        },
        sha256,
    })
}

fn nested_archive_pin(manifest: &Value) -> Result<CsdkSourceFilePin> {
    let row = &manifest["vendor_sources"]["libaom"];
    let bytes = row["archive_bytes"]
        .as_u64()
        .ok_or_else(|| Refusal::new("libaom source archive byte pin is missing"))?;
    let sha256 = row["archive_sha256"]
        .as_str()
        .filter(|value| is_sha256_digest(value))
        .ok_or_else(|| Refusal::new("libaom source archive SHA-256 pin is missing"))?;
    Ok(CsdkSourceFilePin {
        bytes,
        sha256: decode_digest(sha256)?,
    })
}

fn series_preimage_sha(series: &Value, component: &str, path: &str) -> Result<[u8; 32]> {
    let rows = series["patches"]
        .as_array()
        .ok_or_else(|| Refusal::new("source patch series has no patch list"))?;
    let matches = rows
        .iter()
        .filter(|row| {
            row["component"].as_str() == Some(component) && row["path"].as_str() == Some(path)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Refusal::new(
            "source patch series lacks the unique libaom generator preimage",
        ));
    }
    let digest = matches[0]["before_sha256"]
        .as_str()
        .filter(|value| is_sha256_digest(value))
        .ok_or_else(|| Refusal::new("libaom generator preimage SHA-256 is malformed"))?;
    decode_digest(digest)
}

fn manifest_file_sha(manifest: &Value, path: &str) -> Result<[u8; 32]> {
    let full_path = format!("sources/AROS-NX/{path}");
    let rows = manifest["inventory"]
        .as_array()
        .ok_or_else(|| Refusal::new("source manifest has no inventory"))?;
    let matches = rows
        .iter()
        .filter(|row| row["path"].as_str() == Some(full_path.as_str()))
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0]["type"].as_str() != Some("file") {
        return Err(Refusal::new(
            "source manifest lacks the unique pinned Mesa patch",
        ));
    }
    let digest = matches[0]["sha256"]
        .as_str()
        .filter(|value| is_sha256_digest(value))
        .ok_or_else(|| Refusal::new("Mesa patch SHA-256 is malformed"))?;
    decode_digest(digest)
}

fn pinned_path(root: &Path, pin: &PinnedFile) -> Result<PathBuf> {
    let relative = Path::new(&pin.path);
    validate_relative_inventory_path(&pin.path)?;
    let components = relative.components().collect::<Vec<_>>();
    let mut path = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(Refusal::new(
                "pinned input path is not a safe relative path",
            ));
        };
        path.push(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Refusal::new(format!(
                "could not inspect pinned input {}: {error}",
                pin.path
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Refusal::new(format!(
                "pinned input traverses a symlink: {}",
                pin.path
            )));
        }
        if index + 1 < components.len() && !metadata.file_type().is_dir() {
            return Err(Refusal::new(format!(
                "pinned input parent is not a directory: {}",
                pin.path
            )));
        }
    }
    verify_path_pin(&path, pin, &pin.path)?;
    Ok(path)
}

fn verify_path_pin(path: &Path, pin: &PinnedFile, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("could not inspect {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.len() != pin.identity.bytes
        || sha256_file(path)? != pin.sha256
    {
        return Err(Refusal::new(format!(
            "{label} differs from its immutable pin"
        )));
    }
    Ok(())
}

fn decode_digest(value: &str) -> Result<[u8; 32]> {
    if !is_sha256_digest(value) {
        return Err(Refusal::new(
            "SHA-256 digest must be 64 lowercase hexadecimal characters",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| Refusal::new("could not decode SHA-256 digest"))?;
    }
    Ok(digest)
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    encode_hex(bytes)
}

fn resolve_spec_path(source_root: &Path, spec: Option<PathBuf>) -> Result<PathBuf> {
    let path = match spec {
        Some(path) if path.is_absolute() => path,
        Some(path) => source_root.join(path),
        None => source_root.join(SOURCE_CAPSULE_DEFAULT),
    };
    existing_regular(path, "portable C-SDK specification")
}

fn actual_host() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        ("macos", "aarch64") => Ok("macos-aarch64"),
        _ => Err(Refusal::new(
            "portable C-SDK producer requires Linux/x86-64, Linux/ARM64 or macOS/ARM64",
        )),
    }
}

fn existing_directory(path: PathBuf, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(&path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if !metadata.file_type().is_dir() {
        return Err(Refusal::new(format!("{label} must be a real directory")));
    }
    Ok(canonical)
}

fn existing_regular(path: PathBuf, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(&path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::new(format!("{label} must be a regular file")));
    }
    Ok(canonical)
}

fn executable_pin(path: &Path, label: &str) -> Result<CsdkSourceFilePin> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(Refusal::new(format!(
            "{label} must be an executable regular file"
        )));
    }
    Ok(CsdkSourceFilePin {
        bytes: metadata.len(),
        sha256: decode_digest(&sha256_file(path)?)?,
    })
}

fn resolve_tools(
    cmake: Option<PathBuf>,
    pkg_config: Option<PathBuf>,
    perl: Option<PathBuf>,
    git: Option<PathBuf>,
) -> Result<ResolvedTools> {
    let explicit = [cmake, pkg_config, perl, git];
    let any = explicit.iter().any(Option::is_some);
    let paths = if any {
        if explicit.iter().any(Option::is_none) {
            return Err(Refusal::new(
                "explicit C-SDK host tools must include cmake, pkg-config, perl and git",
            ));
        }
        explicit
            .into_iter()
            .map(|path| path.expect("all explicit tools were checked"))
            .collect::<Vec<_>>()
    } else {
        ["cmake", "pkg-config", "perl", "git"]
            .into_iter()
            .map(find_in_path)
            .collect::<Result<Vec<_>>>()?
    };
    let paths = paths
        .into_iter()
        .map(|path| existing_regular(path, "C-SDK host tool"))
        .collect::<Result<Vec<_>>>()?;
    let tool = |index: usize| -> Result<CsdkMetadataTool> {
        Ok(CsdkMetadataTool {
            pin: executable_pin(&paths[index], "C-SDK host tool")?,
            path: paths[index].clone(),
        })
    };
    let xz = existing_regular(find_in_path("xz")?, "C-SDK XZ compressor")?;
    let xz = CsdkMetadataTool {
        pin: executable_pin(&xz, "C-SDK XZ compressor")?,
        path: xz,
    };
    Ok(ResolvedTools {
        xz,
        metadata: CsdkMetadataTools {
            cmake: tool(0)?,
            pkg_config: tool(1)?,
            perl: tool(2)?,
            git: tool(3)?,
        },
    })
}

fn find_in_path(program: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(program);
        if let Ok(metadata) = fs::metadata(&candidate)
            && metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
        {
            return Ok(candidate);
        }
    }
    Err(Refusal::new(format!(
        "required C-SDK host tool was not found in PATH: {program}"
    )))
}

fn create_fresh_root(path: PathBuf, label: &str) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(Refusal::new(format!(
            "{label} must be an absolute normalized path"
        )));
    }
    let leaf = path
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| Refusal::new(format!("{label} must name a fresh directory")))?;
    let parent = path
        .parent()
        .ok_or_else(|| Refusal::new(format!("{label} must have a parent directory")))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Refusal::new(format!("could not resolve {label} parent: {error}")))?;
    let destination = parent.join(leaf);
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(Refusal::new(format!("fresh {label} directory required"))),
    }
    create_private_dir(&destination)?;
    Ok(destination)
}

fn require_disjoint(left: &Path, right: &Path, message: &str) -> Result<()> {
    if left.starts_with(right) || right.starts_with(left) {
        return Err(Refusal::new(message));
    }
    Ok(())
}

fn write_new_json(path: &Path, value: &Value) -> Result<String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        Refusal::new(format!("could not serialize C-SDK producer JSON: {error}"))
    })?;
    bytes.push(b'\n');
    let digest = sha256_bytes(&bytes);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(digest)
}

fn value_path(value: &Value, key: &str) -> Result<PathBuf> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| Refusal::new(format!("C-SDK metadata result lacks {key}")))
}

impl<'a> ProducerRunner<'a> {
    fn new(work: &Path, signal: &'a SigtermGuard, max_log_bytes: u64, host: &str) -> Result<Self> {
        let mut env = BTreeMap::new();
        for key in ["PATH", "DEVELOPER_DIR", "SDKROOT"] {
            if (key == "PATH" || host == "macos-aarch64")
                && let Some(value) = std::env::var_os(key)
            {
                env.insert(OsString::from(key), value);
            }
        }
        env.insert(OsString::from("LC_ALL"), OsString::from("C"));
        env.insert(OsString::from("LANG"), OsString::from("C"));
        env.insert(OsString::from("TZ"), OsString::from("UTC"));
        env.insert(OsString::from("HOME"), work.join("home").into_os_string());
        env.insert(OsString::from("TMPDIR"), work.join("tmp").into_os_string());
        env.insert(OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0"));
        env.insert(OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1"));
        env.insert(
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        );
        env.insert(OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0"));
        env.insert(
            OsString::from("SOURCE_DATE_EPOCH"),
            OsString::from("1791936000"),
        );
        let max_log_bytes = usize::try_from(max_log_bytes)
            .map_err(|_| Refusal::new("C-SDK log budget is not representable on this host"))?;
        if max_log_bytes == 0 {
            return Err(Refusal::new("C-SDK log budget must be positive"));
        }
        Ok(Self {
            work: work.to_path_buf(),
            env,
            signal,
            max_log_bytes,
            saved_log_bytes: 0,
            commands: Vec::new(),
        })
    }

    fn cancelled(&self) -> bool {
        self.signal.requested()
    }

    fn checkpoint(&self, label: &str) -> Result<()> {
        self.signal
            .check()
            .map_err(|error| Refusal::new(format!("C-SDK production interrupted {label}: {error}")))
    }

    fn run_argv(
        &mut self,
        argv: &[OsString],
        cwd: &Path,
        label: &str,
        timeout: Duration,
    ) -> Result<RunOutput> {
        let program = argv
            .first()
            .ok_or_else(|| Refusal::new("C-SDK command argv must not be empty"))?;
        let spec = CommandSpec::new(
            program.clone(),
            argv.iter().skip(1).cloned(),
            cwd,
            self.env.clone(),
        );
        self.run_spec(&spec, label, timeout)
    }

    fn run_spec(
        &mut self,
        spec: &CommandSpec,
        label: &str,
        timeout: Duration,
    ) -> Result<RunOutput> {
        self.checkpoint("before command")?;
        let remaining = self.max_log_bytes.saturating_sub(self.saved_log_bytes);
        if remaining < 2 {
            return Err(Refusal::new(
                "portable C-SDK command log budget is exhausted",
            ));
        }
        let stdout_limit = remaining / 2;
        let stderr_limit = remaining - stdout_limit;
        let capture = process_capture::capture(
            spec,
            CaptureLimits {
                timeout,
                stdout_bytes: stdout_limit,
                stderr_bytes: stderr_limit,
                termination_grace: COMMAND_TERMINATION_GRACE,
            },
            || self.signal.requested(),
        );
        match capture {
            Ok(process) => {
                let status = process.status.code();
                let stdout = process.stdout;
                let stderr = process.stderr;
                let record = self.save_process(
                    spec,
                    label,
                    timeout,
                    &stdout,
                    &stderr,
                    process.elapsed,
                    status,
                    process.status.signal(),
                    process.status.success(),
                    None,
                )?;
                if status != Some(0) {
                    return Err(Refusal::new(format!(
                        "C-SDK command {label} exited with {}",
                        status.map_or_else(|| "a signal".to_owned(), |code| code.to_string())
                    )));
                }
                Ok(RunOutput { stdout, record })
            }
            Err(error) => {
                let detail = error.to_string();
                let stdout = error.stdout;
                let stderr = error.stderr;
                let status = error.status.as_ref().and_then(|status| status.code());
                let signal = error.status.as_ref().and_then(ExitStatusExt::signal);
                let _record = self.save_process(
                    spec,
                    label,
                    timeout,
                    &stdout,
                    &stderr,
                    error.elapsed,
                    status,
                    signal,
                    false,
                    Some(detail.clone()),
                )?;
                Err(Refusal::new(format!(
                    "C-SDK command {label} failed: {detail}"
                )))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn save_process(
        &mut self,
        spec: &CommandSpec,
        label: &str,
        timeout: Duration,
        stdout: &[u8],
        stderr: &[u8],
        elapsed: Duration,
        status: Option<i32>,
        signal: Option<i32>,
        success: bool,
        failure: Option<String>,
    ) -> Result<Value> {
        let amount = stdout
            .len()
            .checked_add(stderr.len())
            .ok_or_else(|| Refusal::new("C-SDK command log byte count overflow"))?;
        self.saved_log_bytes = self
            .saved_log_bytes
            .checked_add(amount)
            .ok_or_else(|| Refusal::new("C-SDK command log byte count overflow"))?;
        if self.saved_log_bytes > self.max_log_bytes {
            return Err(Refusal::new(
                "portable C-SDK command logs exceed the selected budget",
            ));
        }
        let index = self.commands.len();
        let slug = safe_label(label);
        let stem = format!("command-{index:04}-{slug}");
        let stdout_path = self
            .work
            .join("command-logs")
            .join(format!("{stem}.stdout.log"));
        let stderr_path = self
            .work
            .join("command-logs")
            .join(format!("{stem}.stderr.log"));
        write_new(&stdout_path, stdout)?;
        write_new(&stderr_path, stderr)?;
        let argv = std::iter::once(spec.program.clone())
            .chain(spec.args.iter().cloned())
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let record = json!({
            "index": index,
            "label": label,
            "argv": argv,
            "cwd": spec.cwd,
            "timeout_seconds": timeout.as_secs_f64(),
            "elapsed_milliseconds": elapsed.as_millis(),
            "exit_code": status,
            "signal": signal,
            "success": success,
            "failure": failure,
            "stdout": std::str::from_utf8(stdout).ok(),
            "stdout_log": {"path": format!("command-logs/{stem}.stdout.log"), "bytes": stdout.len(), "sha256": sha256_bytes(stdout)},
            "stderr": std::str::from_utf8(stderr).ok(),
            "stderr_log": {"path": format!("command-logs/{stem}.stderr.log"), "bytes": stderr.len(), "sha256": sha256_bytes(stderr)},
        });
        self.commands.push(record.clone());
        Ok(record)
    }
}

fn safe_label(value: &str) -> String {
    let label = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .take(80)
        .collect::<String>();
    if label.is_empty() {
        "command".to_owned()
    } else {
        label
    }
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

fn usage() -> Refusal {
    Refusal::new(
        "usage: ami-rust-xtask csdk-producer --source-root DIR --work DIR --output DIR --toolchain DIR --native-compiler FILE --original-archive FILE [--spec FILE] [--cmake FILE --pkg-config FILE --perl FILE --git FILE]",
    )
}

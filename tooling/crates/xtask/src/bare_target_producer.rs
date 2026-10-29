//! Internal maintainer producer for bare AROS Rust libraries.
//!
//! This stages only the exact pinned rustc, native host std, and rust-src
//! components. Official Cargo and the composed SDK's host-bin/aros-link alias
//! are separate components. The target spec is an explicit producer input;
//! its relative target.json alias is created only inside the fresh subset.
//! This does not admit a host or qualify an SDK.

use ami_rust_core::{
    Refusal, Result,
    bare_target_record_validation::{self, InnerCommandSummary},
    component_install::{self, ComponentInstallLimits, ComponentInstallSpec},
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    files::{read_regular_bounded, validate_relative_inventory_path},
    inventory::{FileIdentity, InventoryLimits, LinkIdentity, verify_complete},
    json::{JsonProfile, parse_json, parse_json_value},
    ownership,
    qualification_command::{self, CommandBudgets, CommandRequest},
    workspace_accounting::{self, ScanLimits},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{fs::PermissionsExt, fs::symlink},
    path::{Path, PathBuf},
    time::Instant,
};

const SOURCE_PROFILE_TARGET: &str = "x86_64-aros";
const RUST_COMMIT: &str = "330d317121e16b5db8e5adc63595910528ff2ee7";
const LIBRARY_LOCK_PATH: &str = "lib/rustlib/src/rust/library/Cargo.lock";
const LIBRARY_LOCK_BYTES: u64 = 10_042;
const LIBRARY_LOCK_SHA256: &str =
    "75848db58a70444bfb62c649b103d19c5d92fede325eb0c8c0e5442848448669";
const SOURCE_PROFILE_TARGET_SPEC_BYTES: u64 = 955;
const SOURCE_PROFILE_TARGET_SPEC_SHA256: &str =
    "de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71";
const SOURCE_PROFILE_TARGET_ALIAS_PATH: &str = "lib/rustlib/x86_64-aros/target.json";
const SOURCE_PROFILE_TARGET_ALIAS: &str = "x86_64-aros.json";
const SOURCE_PROFILE_TARGET_SPEC_PATH: &str = "lib/rustlib/x86_64-aros/x86_64-aros.json";
const MACOS_LLVM_SOURCE_PATH: &str = "lib/libLLVM.dylib";
const MACOS_LLVM_SOURCE_BYTES: u64 = 143_609_472;
const MACOS_LLVM_SOURCE_SHA256: &str =
    "f875883949c8ff96b94faca6a295f66302ae305ce897165fc8765d5ba2d73573";
const MACOS_LLVM_ALIAS_PATH: &str = "lib/rustlib/aarch64-apple-darwin/lib/libLLVM.dylib";
const MACOS_LLVM_ALIAS_TARGET: &str = "../../../libLLVM.dylib";
const LINUX_LLVM_SOURCE_PATH: &str = "lib/libLLVM.so.23.1-rust-1.100.0-nightly";
const LINUX_LLVM_SOURCE_PATH_NAME: &str = "libLLVM.so.23.1-rust-1.100.0-nightly";
const LINUX_LLVM_ALIAS_TARGET: &str = "../../../libLLVM.so.23.1-rust-1.100.0-nightly";
const LINUX_X86_64_LLVM_SOURCE_BYTES: u64 = 208_323_328;
const LINUX_X86_64_LLVM_SOURCE_SHA256: &str =
    "eba1c74fa09e3e4704b331e92cd166fc398cbf73becf3f6e49e83087e15be257";
const LINUX_AARCH64_LLVM_SOURCE_BYTES: u64 = 164_461_896;
const LINUX_AARCH64_LLVM_SOURCE_SHA256: &str =
    "6be3e489d3ffa25dfbaeb2ea815ecf1a7d9b3737c189e4d352382a6c88d29de7";
const LLVM_OBJCOPY_VERSION: &str = "LLVM version 23.1.1";
const CARGO_LOCK_BYTES: &[u8] =
    b"version = 4\n\n[[package]]\nname = \"bare-target-library-probe\"\nversion = \"0.1.0\"\n";
const CARGO_LOCK_SHA256: &str = "969184047306a3a38adfd54e6f4bc77afa3de91713ffd3b3e407789ea69d3708";
const COMMAND_SECONDS: u64 = 1_200;
const RSS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const EMBEDDED_PARENT_RSS_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const WORKSPACE_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const LOG_BYTES: u64 = 16 * 1024 * 1024;
const CAMPAIGN_SECONDS: u64 = 5_400;
const FINALIZATION_RESERVE_SECONDS: u64 = 300;
const CAMPAIGN_WORK_SECONDS: u64 = CAMPAIGN_SECONDS - FINALIZATION_RESERVE_SECONDS;
const HOSTS: [HostPins; 3] = [
    HostPins {
        name: "macos-aarch64",
        triple: "aarch64-apple-darwin",
        profile_sha256: "9acf02ab3d4a22137b6c5f82294e35c518ff1ffdbad5a701d5f3cdb0910668ea",
        profile_file_rows: 3_882,
        rustc_payload_rows: 45,
        installer_admin_rows: 3,
        std_rows: 59,
        src_rows: 3_731,
        target_spec_rows: 0,
        cargo_rows: 44,
        historical_cargo_bytes: 32_170_408,
        historical_cargo_sha256: "37e07284393e4c979d0cf8d0efc62e4c29b64424a0d10123a616aec790056333",
    },
    HostPins {
        name: "linux-x86_64",
        triple: "x86_64-unknown-linux-gnu",
        profile_sha256: "7a88373f28d19d6d61494587240681999adfb2bec964b4c3d74fae9718f097e8",
        profile_file_rows: 3_883,
        rustc_payload_rows: 42,
        installer_admin_rows: 3,
        std_rows: 63,
        src_rows: 3_731,
        target_spec_rows: 0,
        cargo_rows: 44,
        historical_cargo_bytes: 36_137_048,
        historical_cargo_sha256: "21c38ae0b341e88245fc0cd7afc0a28ff51183d3459f05a4c41aec254b06cb45",
    },
    HostPins {
        name: "linux-aarch64",
        triple: "aarch64-unknown-linux-gnu",
        profile_sha256: "862be6c4c1d29c59fc774e2d38f046672fcd0aa0978a869be9af2752fb4f76ee",
        profile_file_rows: 3_882,
        rustc_payload_rows: 42,
        installer_admin_rows: 3,
        std_rows: 62,
        src_rows: 3_731,
        target_spec_rows: 0,
        cargo_rows: 44,
        historical_cargo_bytes: 35_521_536,
        historical_cargo_sha256: "44a4f14309e8d807e9e514f2c3b95be5ec0717887b5e6edadf112b8f7235c371",
    },
];

#[derive(Clone, Copy)]
struct HostPins {
    name: &'static str,
    triple: &'static str,
    profile_sha256: &'static str,
    profile_file_rows: usize,
    rustc_payload_rows: usize,
    installer_admin_rows: usize,
    std_rows: usize,
    src_rows: usize,
    target_spec_rows: usize,
    cargo_rows: usize,
    historical_cargo_bytes: u64,
    historical_cargo_sha256: &'static str,
}

struct ProfileRows {
    files: Vec<FileIdentity>,
    symlinks: Vec<LinkIdentity>,
}

struct ScopedInventory {
    files: Vec<FileIdentity>,
    installer_admin_files: Vec<FileIdentity>,
    cargo_files: Vec<FileIdentity>,
    host_linker_alias: LinkIdentity,
    macos_llvm_runtime_alias: Option<MacosLlvmRuntimeAlias>,
    linux_llvm_runtime_alias: Option<LinuxLlvmRuntimeAlias>,
    rustc_payload_rows: usize,
    std_rows: usize,
    src_rows: usize,
    target_spec_rows: usize,
    historical_cargo: FileIdentity,
}

struct MacosLlvmRuntimeAlias {
    link: LinkIdentity,
    source_file: FileIdentity,
}

struct LinuxLlvmRuntimeAlias {
    link: LinkIdentity,
    source_file: FileIdentity,
}

struct Inputs {
    host: HostPins,
    profile_path: PathBuf,
    profile_bytes: u64,
    profile_sha256: String,
    source_root: PathBuf,
    cargo_path: PathBuf,
    cargo_identity: FileIdentity,
    target_pin_path: PathBuf,
    target_spec_path: PathBuf,
    target: TargetDefinition,
    scoped: ScopedInventory,
    target_spec_identity: FileIdentity,
}

#[derive(Clone, Debug)]
struct TargetDefinition {
    name: String,
    source_date_epoch: u64,
    pin_bytes: u64,
    pin_sha256: String,
    spec_bytes: u64,
    spec_sha256: String,
    alias_path: String,
    alias: String,
    spec_profile_path: String,
}

impl TargetDefinition {
    fn library_root(&self) -> String {
        format!("lib/rustlib/{}/lib", self.name)
    }
}

/// Typed in-process boundary used by the cohesive toolchain producer. The
/// retained maintainer command below parses the same closed fields.
pub(super) struct BareTargetRequest {
    pub(super) host: String,
    pub(super) rust_profile: PathBuf,
    pub(super) host_rust: PathBuf,
    pub(super) native_cargo: PathBuf,
    pub(super) target_pin: PathBuf,
    pub(super) target_spec: PathBuf,
    pub(super) work: PathBuf,
    pub(super) output: PathBuf,
}

pub(super) fn produce(request: BareTargetRequest) -> Result<()> {
    let arguments = [
        OsString::from("--host"),
        request.host.into(),
        OsString::from("--rust-profile"),
        request.rust_profile.into_os_string(),
        OsString::from("--host-rust"),
        request.host_rust.into_os_string(),
        OsString::from("--native-cargo"),
        request.native_cargo.into_os_string(),
        OsString::from("--target-pin"),
        request.target_pin.into_os_string(),
        OsString::from("--target-spec"),
        request.target_spec.into_os_string(),
        OsString::from("--work"),
        request.work.into_os_string(),
        OsString::from("--output"),
        request.output.into_os_string(),
    ];
    run_with_parent_rss_limit(arguments.into_iter(), EMBEDDED_PARENT_RSS_BYTES)
}

pub(super) fn profile_relative_path(host: &str) -> Result<&'static Path> {
    match host {
        "macos-aarch64" => Ok(Path::new(
            "tooling/crates/aros-native-build/pins/macos-aarch64/rust.json",
        )),
        "linux-x86_64" => Ok(Path::new(
            "tooling/crates/aros-native-build/pins/linux-x86_64/rust.json",
        )),
        "linux-aarch64" => Ok(Path::new(
            "release/bare-target-libraries/linux-aarch64-rust.json",
        )),
        _ => Err(Refusal::new("bare-target host has no admitted profile")),
    }
}

pub(super) fn run(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    run_with_parent_rss_limit(
        arguments,
        bare_target_record_validation::MAX_PARENT_RSS_BYTES,
    )
}

fn run_with_parent_rss_limit(
    mut arguments: impl Iterator<Item = OsString>,
    parent_rss_limit_bytes: u64,
) -> Result<()> {
    let started = Instant::now();
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if ![
            "--host",
            "--rust-profile",
            "--host-rust",
            "--native-cargo",
            "--target-pin",
            "--target-spec",
            "--work",
            "--output",
        ]
        .iter()
        .any(|candidate| key == *candidate)
        {
            return Err(usage());
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("bare-target producer option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new(
                "bare-target producer options may occur only once",
            ));
        }
    }
    if options.len() != 8 {
        return Err(usage());
    }
    let host_name = take(&mut options, "--host")?
        .into_string()
        .map_err(|_| Refusal::new("bare-target host must be UTF-8"))?;
    let host = host_pins(&host_name).ok_or_else(usage)?;
    verify_running_host(host)?;

    let profile_path = existing_regular(PathBuf::from(take(&mut options, "--rust-profile")?))?;
    let source_root = existing_directory(PathBuf::from(take(&mut options, "--host-rust")?))?;
    let cargo_path = existing_regular(PathBuf::from(take(&mut options, "--native-cargo")?))?;
    let target_pin_path = existing_regular(PathBuf::from(take(&mut options, "--target-pin")?))?;
    let target_spec_path = existing_regular(PathBuf::from(take(&mut options, "--target-spec")?))?;
    let work = fresh_directory_path(PathBuf::from(take(&mut options, "--work")?))?;
    let output = fresh_directory_path(PathBuf::from(take(&mut options, "--output")?))?;
    if !options.is_empty() {
        return Err(usage());
    }
    ownership::require_disjoint(&work, &output, "producer work and output must be disjoint")?;

    // All pinned inputs are authenticated before either caller output path is created.
    let inputs = preflight(
        host,
        profile_path,
        source_root,
        cargo_path,
        target_pin_path,
        target_spec_path,
    )?;
    ownership::require_disjoint(
        &work,
        &inputs.source_root,
        "producer work must be outside the immutable Rust source root",
    )?;
    ownership::require_disjoint(
        &output,
        &inputs.source_root,
        "producer output must be outside the immutable Rust source root",
    )?;
    fs::create_dir(&work)?;
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    for name in ["inputs", "requests", "records", "libraries"] {
        create_private_dir(&output.join(name))?;
    }
    for name in ["home", "tmp", "cargo-home", "fixture", "target"] {
        create_private_dir(&work.join(name))?;
    }
    copy_input(
        &inputs.profile_path,
        &output.join("inputs/rust-profile.json"),
        inputs.profile_bytes,
        &inputs.profile_sha256,
    )?;
    copy_input(
        &inputs.target_pin_path,
        &output.join("inputs/target-pin.json"),
        inputs.target.pin_bytes,
        &inputs.target.pin_sha256,
    )?;
    copy_input(
        &inputs.target_spec_path,
        &output.join("inputs").join(&inputs.target.alias),
        inputs.target.spec_bytes,
        &inputs.target.spec_sha256,
    )?;
    write_json_new(
        &output.join("inputs.json"),
        &json!({
            "schema": "ami-rust-bare-target-producer-inputs-v1",
            "host": inputs.host.name,
            "rust_profile": {
                "source_path": utf8(&inputs.profile_path)?,
                "retained_path": "inputs/rust-profile.json",
                "bytes": inputs.profile_bytes,
                "sha256": inputs.profile_sha256
            },
            "host_rust_sysroot": utf8(&inputs.source_root)?,
            "native_cargo": {
                "source_path": utf8(&inputs.cargo_path)?,
                "bytes": inputs.cargo_identity.bytes,
                "sha256": inputs.cargo_identity.sha256,
                "origin": "official Cargo component from the pinned Rust distribution"
            },
            "target_pin": {
                "source_path": utf8(&inputs.target_pin_path)?,
                "retained_path": "inputs/target-pin.json",
                "bytes": inputs.target.pin_bytes,
                "sha256": inputs.target.pin_sha256,
                "source_date_epoch": inputs.target.source_date_epoch
            },
            "target_spec": {
                "source_path": utf8(&inputs.target_spec_path)?,
                "retained_path": format!("inputs/{}", inputs.target.alias),
                "bytes": inputs.target.spec_bytes,
                "sha256": inputs.target.spec_sha256
            },
            "component_install_scope": "authenticated rustc/native-host-std/rust-src payload subset; installer administration rows, official Cargo, and composed host linker alias excluded; target spec added explicitly"
        }),
    )?;

    let stage = work.join("toolchain");
    install_rust_components(&inputs, &work, &output, &stage)?;
    copy_input(
        &inputs.cargo_path,
        &stage.join("bin/cargo"),
        inputs.cargo_identity.bytes,
        &inputs.cargo_identity.sha256,
    )?;
    let target_spec_path = stage.join(&inputs.target.spec_profile_path);
    create_private_dir(target_spec_path.parent().expect("target spec parent"))?;
    copy_input(
        &inputs.target_spec_path,
        &target_spec_path,
        inputs.target_spec_identity.bytes,
        &inputs.target_spec_identity.sha256,
    )?;
    symlink(&inputs.target.alias, stage.join(&inputs.target.alias_path))?;
    if let Some(alias) = &inputs.scoped.macos_llvm_runtime_alias {
        create_macos_llvm_runtime_alias(&stage, alias)?;
    }
    if let Some(alias) = &inputs.scoped.linux_llvm_runtime_alias {
        create_linux_llvm_runtime_alias(inputs.host, &stage, alias)?;
    }

    let mut final_files = inputs.scoped.files.clone();
    final_files.push(inputs.cargo_identity.clone());
    final_files.push(inputs.target_spec_identity.clone());
    let mut final_links = vec![LinkIdentity {
        path: inputs.target.alias_path.clone(),
        target: inputs.target.alias.clone(),
    }];
    if let Some(alias) = &inputs.scoped.macos_llvm_runtime_alias {
        final_links.push(alias.link.clone());
    }
    if let Some(alias) = &inputs.scoped.linux_llvm_runtime_alias {
        final_links.push(alias.link.clone());
    }
    let component_inventory = json!({
        "schema": "ami-rust-bare-target-scoped-component-inventory-v2",
        "input_profile_sha256": inputs.profile_sha256,
        "selected_rust_component_files": &inputs.scoped.files,
        "excluded_installer_admin_rows": &inputs.scoped.installer_admin_files,
        "excluded_official_cargo_rows": &inputs.scoped.cargo_files,
        "excluded_composed_host_linker_alias": &inputs.scoped.host_linker_alias,
        "macos_rust_objcopy_llvm_runtime_alias": inputs.scoped.macos_llvm_runtime_alias.as_ref().map(|alias| json!({
            "link": &alias.link,
            "authenticated_source_file": &alias.source_file,
            "purpose": "resolve the pinned macOS rust-objcopy @rpath/libLLVM.dylib from the authenticated root Rust component file"
        })),
        "linux_rust_objcopy_llvm_runtime_alias": inputs.scoped.linux_llvm_runtime_alias.as_ref().map(|alias| json!({
            "link": &alias.link,
            "authenticated_source_file": &alias.source_file,
            "purpose": "resolve the pinned Linux rust-objcopy libLLVM.so.23.1-rust-1.100.0-nightly dependency from the authenticated root Rust component file"
        })),
        "target_spec_profile_rows_readded_as_explicit_input": inputs.scoped.target_spec_rows,
        "materialized_files": &final_files,
        "materialized_symlinks": &final_links,
        "cargo_component": {
            "path": "bin/cargo",
            "bytes": inputs.cargo_identity.bytes,
            "sha256": inputs.cargo_identity.sha256,
            "origin": "official Cargo component from the pinned Rust distribution"
        },
        "scope": "Rust producer component subset only; not the composed SDK profile"
    });
    let component_inventory_sha256 = write_json_new(
        &output.join("component-inventory.json"),
        &component_inventory,
    )?;
    verify_complete(
        &stage,
        &final_files,
        &final_links,
        InventoryLimits {
            max_tree_entries: 10_000,
            max_link_resolution_steps: 256,
        },
    )?;
    if stage.join(inputs.target.library_root()).exists() {
        return Err(Refusal::new(
            "bare-target stage unexpectedly contains pre-existing target libraries",
        ));
    }

    let lock_path = stage.join(LIBRARY_LOCK_PATH);
    let manifest = work.join("fixture/Cargo.toml");
    write_new(
        &manifest,
        b"[workspace]\n\n[package]\nname = \"bare-target-library-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\npath = \"src/lib.rs\"\ncrate-type = [\"rlib\"]\n\n[profile.release]\nopt-level = 2\npanic = \"abort\"\ncodegen-units = 1\nincremental = false\n",
    )?;
    let fixture_lock = work.join("fixture/Cargo.lock");
    write_new(&fixture_lock, CARGO_LOCK_BYTES)?;
    create_private_dir(&work.join("fixture/src"))?;
    write_new(
        &work.join("fixture/src/lib.rs"),
        b"#![no_std]\nextern crate alloc;\n\npub fn make_probe_vec() -> alloc::vec::Vec<u8> {\n    alloc::vec![1, 2, 3]\n}\n",
    )?;
    let vendor = stage.join("lib/rustlib/src/rust/library/vendor");
    if !vendor.is_dir() || vendor.is_symlink() {
        return Err(Refusal::new(
            "pinned Rust library vendor tree is missing or not a directory",
        ));
    }
    let vendor_toml = serde_json::to_string(&utf8(&vendor)?)
        .map_err(|error| Refusal::new(format!("could not encode local vendor path: {error}")))?;
    write_new(
        &work.join("cargo-home/config.toml"),
        format!(
            "[source.crates-io]\nreplace-with=\"ami-rust-local-vendor\"\n[source.ami-rust-local-vendor]\ndirectory={vendor_toml}\n"
        )
        .as_bytes(),
    )?;

    let mut records = Vec::new();
    let mut expected_requests =
        Vec::with_capacity(bare_target_record_validation::INNER_COMMAND_LABELS.len());
    let mut parent_peak_rss_bytes = 0_u64;
    let mut environment = BTreeMap::new();
    environment.insert(
        "PATH".to_owned(),
        format!("{}:/usr/bin:/bin", utf8(&stage.join("bin"))?),
    );
    environment.insert("HOME".to_owned(), utf8(&work.join("home"))?);
    environment.insert("TMPDIR".to_owned(), utf8(&work.join("tmp"))?);
    environment.insert("CARGO_HOME".to_owned(), utf8(&work.join("cargo-home"))?);
    environment.insert("CARGO_TARGET_DIR".to_owned(), utf8(&work.join("target"))?);
    environment.insert("RUSTC".to_owned(), utf8(&stage.join("bin/rustc"))?);
    environment.insert("RUSTDOC".to_owned(), utf8(&stage.join("bin/rustdoc"))?);
    environment.insert("CARGO_BUILD_JOBS".to_owned(), "2".to_owned());
    environment.insert("CARGO_INCREMENTAL".to_owned(), "0".to_owned());
    environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    environment.insert("LC_ALL".to_owned(), "C".to_owned());
    environment.insert("TZ".to_owned(), "UTC".to_owned());
    environment.insert(
        "SOURCE_DATE_EPOCH".to_owned(),
        inputs.target.source_date_epoch.to_string(),
    );
    environment.insert("RUSTC_WRAPPER".to_owned(), String::new());
    environment.insert("RUSTC_WORKSPACE_WRAPPER".to_owned(), String::new());

    let command_context = CommandContext {
        work: &work,
        output: &output,
        started: &started,
    };
    let version = run_command(
        &command_context,
        "rustc-version",
        &stage.join("bin/rustc"),
        &[OsString::from("-Vv")],
        &work.join("fixture"),
        &environment,
    )?;
    require_output_contains(
        &version.stdout,
        &format!("commit-hash: {RUST_COMMIT}"),
        "pinned rustc commit",
    )?;
    retain_command_outcome(
        version,
        &mut expected_requests,
        &mut records,
        &mut parent_peak_rss_bytes,
    );

    let selected_sysroot = run_command(
        &command_context,
        "rustc-sysroot",
        &stage.join("bin/rustc"),
        &[OsString::from("--print"), OsString::from("sysroot")],
        &work.join("fixture"),
        &environment,
    )?;
    require_output_contains(
        &selected_sysroot.stdout,
        &utf8(&stage)?,
        "selected private Rust sysroot",
    )?;
    retain_command_outcome(
        selected_sysroot,
        &mut expected_requests,
        &mut records,
        &mut parent_peak_rss_bytes,
    );

    let cargo_version = run_command(
        &command_context,
        "cargo-version",
        &stage.join("bin/cargo"),
        &[OsString::from("--version"), OsString::from("--verbose")],
        &work.join("fixture"),
        &environment,
    )?;
    require_output_contains(
        &cargo_version.stdout,
        "commit-hash: 495c385d0875c4ba51eb72ea0448a2d4c018b8d4",
        "pinned native Cargo commit",
    )?;
    require_output_contains(
        &cargo_version.stdout,
        host.triple,
        "native Cargo host triple",
    )?;
    retain_command_outcome(
        cargo_version,
        &mut expected_requests,
        &mut records,
        &mut parent_peak_rss_bytes,
    );

    let objcopy_version = run_command(
        &command_context,
        "rust-objcopy-version",
        &stage.join(format!("lib/rustlib/{}/bin/rust-objcopy", host.triple)),
        &[OsString::from("--version")],
        &work.join("fixture"),
        &environment,
    )?;
    require_output_contains(
        &objcopy_version.stdout,
        LLVM_OBJCOPY_VERSION,
        "pinned LLVM objcopy runtime version",
    )?;
    retain_command_outcome(
        objcopy_version,
        &mut expected_requests,
        &mut records,
        &mut parent_peak_rss_bytes,
    );

    let flags = [
        "-Zunstable-options".to_owned(),
        "-Copt-level=2".to_owned(),
        "-Cpanic=abort".to_owned(),
        "-Ccodegen-units=1".to_owned(),
        "-Cembed-bitcode=no".to_owned(),
        "-Clto=off".to_owned(),
        format!("--remap-path-prefix={}=/build", utf8(&work)?),
        format!("--remap-path-prefix={}=/rust-toolchain", utf8(&stage)?),
        format!("--remap-path-prefix={}=/output", utf8(&output)?),
    ];
    environment.insert("CARGO_ENCODED_RUSTFLAGS".to_owned(), flags.join("\u{1f}"));
    let build = run_command(
        &command_context,
        "source-production",
        &stage.join("bin/cargo"),
        &[
            OsString::from("-Zjson-target-spec"),
            OsString::from("-Zbuild-std=core,alloc"),
            OsString::from("-Zbuild-std-features=compiler-builtins-mem"),
            OsString::from("build"),
            OsString::from("--manifest-path"),
            manifest.clone().into_os_string(),
            OsString::from("--target"),
            OsString::from(&inputs.target.name),
            OsString::from("--release"),
            OsString::from("--locked"),
            OsString::from("--offline"),
            OsString::from("--lib"),
            OsString::from("-j"),
            OsString::from("2"),
            OsString::from("-vv"),
            OsString::from("--message-format=json-render-diagnostics"),
        ],
        &work.join("fixture"),
        &environment,
    )?;
    let build_stdout = build.stdout.clone();
    retain_command_outcome(
        build,
        &mut expected_requests,
        &mut records,
        &mut parent_peak_rss_bytes,
    );

    if sha256_file(&lock_path)? != LIBRARY_LOCK_SHA256
        || sha256_file(&fixture_lock)? != CARGO_LOCK_SHA256
    {
        return Err(Refusal::new(
            "locked Rust library or probe lock changed during the build",
        ));
    }
    verify_stable_inputs(&inputs)?;
    verify_complete(
        &stage,
        &final_files,
        &final_links,
        InventoryLimits {
            max_tree_entries: 10_000,
            max_link_resolution_steps: 256,
        },
    )?;
    if stage.join(inputs.target.library_root()).exists() {
        return Err(Refusal::new(
            "source-library build modified the private Rust component stage",
        ));
    }

    // The same process sampled its RUSAGE_SELF high-water in every final
    // command record. The outer trusted supervisor remains responsible for
    // observing the complete producer invocation, including finalization.
    let helper_sha256 = sha256_file(&std::env::current_exe()?)?;
    let program_sha256_by_label = pinned_program_digests(&work, host)?;
    let binding_context = InnerCommandBindingContext {
        host,
        work_root: &work,
        output_root: &output,
        helper_sha256: &helper_sha256,
        program_sha256_by_label: &program_sha256_by_label,
    };
    let inner_validation = validate_caller_bound_inner_commands(
        &output,
        &expected_requests,
        &records,
        &binding_context,
        parent_peak_rss_bytes,
        parent_rss_limit_bytes,
    )?;

    let libraries = collect_libraries(
        &work,
        &output,
        &inputs.target,
        &build_stdout,
        &output.join("libraries"),
    )?;
    let elapsed = started.elapsed().as_secs();
    if elapsed > CAMPAIGN_SECONDS {
        return Err(Refusal::new(
            "bare-target producer exceeded its 5,400-second campaign bound",
        ));
    }
    let workspace = managed_workspace_bytes(&work, &output)?;
    if workspace > WORKSPACE_BYTES {
        return Err(Refusal::new(
            "bare-target producer exceeded its 12-GiB workspace bound",
        ));
    }

    let report = json!({
        "schema": "ami-rust-bare-target-library-producer-v1",
        "status": "PRODUCED_BARE_TARGET_LIBRARIES_NOT_L1_OR_RC_QUALIFICATION",
        "scope": format!("source-built {} core, alloc, and compiler_builtins rlibs from pinned rustc/rust-std/rust-src components", inputs.target.name),
        "host": host.name,
        "rustc_commit": RUST_COMMIT,
        "target": inputs.target.name,
        "input_profile_sha256": inputs.profile_sha256,
        "input_component_counts": {
            "rustc_payload": inputs.scoped.rustc_payload_rows,
            "installer_admin_excluded": inputs.scoped.installer_admin_files.len(),
            "native_host_std": inputs.scoped.std_rows,
            "rust_src": inputs.scoped.src_rows,
            "official_cargo_excluded": inputs.scoped.cargo_files.len(),
            "cross_component_aros_link_alias_excluded": 1,
            "macos_llvm_runtime_alias_added": inputs.scoped.macos_llvm_runtime_alias.is_some(),
            "linux_llvm_runtime_alias_added": inputs.scoped.linux_llvm_runtime_alias.is_some(),
            "target_spec_row_explicitly_readded": inputs.scoped.target_spec_rows,
            "installer_admin_paths_allowlist": [
                "lib/rustlib/components",
                "lib/rustlib/install.log",
                "lib/rustlib/manifest-cargo",
                "lib/rustlib/manifest-rustc",
                "lib/rustlib/manifest-rust-src",
                format!("lib/rustlib/manifest-rust-std-{}", host.triple),
                "lib/rustlib/rust-installer-version",
                "lib/rustlib/uninstall.sh"
            ]
        },
        "scoped_component_inventory_sha256": component_inventory_sha256,
        "component_inventory_path": "component-inventory.json",
        "cargo_component": {
            "bytes": inputs.cargo_identity.bytes,
            "sha256": inputs.cargo_identity.sha256,
            "replaces_official_cargo_component": false,
            "historical_official_cargo": {
                "path": inputs.scoped.historical_cargo.path,
                "bytes": inputs.scoped.historical_cargo.bytes,
                "sha256": inputs.scoped.historical_cargo.sha256
            }
        },
        "rust_source_library_lock": {"path": LIBRARY_LOCK_PATH, "bytes": LIBRARY_LOCK_BYTES, "sha256": LIBRARY_LOCK_SHA256},
        "target_pin": {"sha256": inputs.target.pin_sha256, "epoch": inputs.target.source_date_epoch},
        "target_spec": {"bytes": inputs.target.spec_bytes, "sha256": inputs.target.spec_sha256, "alias": {"path": inputs.target.alias_path, "target": inputs.target.alias}},
        "macos_rust_objcopy_llvm_runtime_alias": inputs.scoped.macos_llvm_runtime_alias.as_ref().map(|alias| json!({
            "link": &alias.link,
            "authenticated_source_file": &alias.source_file,
            "purpose": "resolve the pinned macOS rust-objcopy @rpath/libLLVM.dylib from the authenticated root Rust component file"
        })),
        "linux_rust_objcopy_llvm_runtime_alias": inputs.scoped.linux_llvm_runtime_alias.as_ref().map(|alias| json!({
            "link": &alias.link,
            "authenticated_source_file": &alias.source_file,
            "purpose": "resolve the pinned Linux rust-objcopy libLLVM.so.23.1-rust-1.100.0-nightly dependency from the authenticated root Rust component file"
        })),
        "recipe": {
            "target": inputs.target.name,
            "build_flags": ["-Zjson-target-spec", "-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem", "build", format!("--target={}", inputs.target.name), "--release", "--locked", "--offline", "--lib", "-j2", "-vv", "--message-format=json-render-diagnostics"],
            "rustflags": flags,
            "source_date_epoch": inputs.target.source_date_epoch,
            "network": "offline",
            "stale_target_libraries_loaded": false
        },
        "qualification_commands": records,
        "inner_record_validation": {
            "status": "ALL_FIVE_CALLER_BOUND_RECORDS_AND_RAW_STREAMS_VALIDATED",
            "command_count": inner_validation.commands.len(),
            "parent_peak_rss_bytes": parent_peak_rss_bytes,
            "parent_rss_limit_bytes": parent_rss_limit_bytes,
            "inner_conservative_rss_envelope_bytes": inner_validation.inner_rss_envelope_bytes,
            "combined_conservative_rss_envelope_bytes": inner_validation.combined_rss_envelope_bytes,
            "raw_log_bytes": inner_validation.total_log_bytes,
            "command_elapsed_nanos": inner_validation.total_elapsed_nanos,
            "parent_peak_source": "maximum RUSAGE_SELF high-water sampled by the five completed qualification-command records",
            "interpretation": "conservative resource envelope; trusted outer supervisor observes the complete producer invocation"
        },
        "libraries": libraries,
        "budgets": {
            "per_command_seconds": COMMAND_SECONDS,
            "per_command_aggregate_rss_bytes": RSS_BYTES,
            "full_campaign_aggregate_rss_claimed": false,
            "full_campaign_rss_owner": "trusted outer sealed-X supervisor",
            "workspace_bytes": WORKSPACE_BYTES,
            "aggregate_log_bytes_per_command": LOG_BYTES,
            "campaign_seconds": CAMPAIGN_SECONDS,
            "finalization_reserve_seconds": FINALIZATION_RESERVE_SECONDS,
            "measured_work_window_seconds": CAMPAIGN_WORK_SECONDS,
            "elapsed_seconds_before_final_receipt": elapsed,
            "workspace_bytes_before_final_receipt": workspace,
            "pending_receipt_included_in_final_workspace_bound_check": true,
            "success_receipt_rename_is_last_fallible_operation": true
        },
        "source_and_output_postchecks": {
            "selected_rust_component_files_unchanged": true,
            "rust_library_lock_unchanged": true,
            "native_cargo_unchanged": true,
            "target_pin_and_spec_unchanged": true,
            "probe_cargo_lock_unchanged": true,
            "private_component_stage_unchanged_after_build": true
        },
        "limitations": [
            "The Rust component subset is not a complete SDK or composed host toolchain.",
            "This producer does not qualify a C SDK, linker runtime, AROS execution, L1, or RC acceptance.",
            "The per-command records do not establish full-invocation aggregate RSS; the trusted outer supervisor owns that measurement.",
            "The Linux AArch64 candidate remains prospective data and does not admit that host."
        ]
    });
    let report_path = output.join("producer.json");
    let pending_path = output.join("producer.pending.json");
    match fs::symlink_metadata(&report_path) {
        Ok(_) => {
            return Err(Refusal::new(
                "producer success receipt destination already exists",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    write_json_new(&pending_path, &report)?;
    if managed_workspace_bytes(&work, &output)? > WORKSPACE_BYTES {
        return Err(Refusal::new(
            "producer output and pending receipt exceeded the 12-GiB workspace bound",
        ));
    }
    if started.elapsed().as_secs() > CAMPAIGN_SECONDS {
        return Err(Refusal::new(
            "producer receipt finalization exceeded the campaign bound",
        ));
    }
    fs::rename(&pending_path, &report_path)?;
    Ok(())
}

fn preflight(
    host: HostPins,
    profile_path: PathBuf,
    source_root: PathBuf,
    cargo_path: PathBuf,
    target_pin_path: PathBuf,
    target_spec_path: PathBuf,
) -> Result<Inputs> {
    let target_spec_bytes = read_bounded_regular(&target_spec_path, 16 * 1024)?;
    let target_pin_bytes = read_bounded_regular(&target_pin_path, 16 * 1024)?;
    let target = parse_target_definition(&target_pin_bytes, &target_spec_bytes)?;
    let profile_bytes = read_bounded_regular(
        &profile_path,
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let profile_bytes_len = profile_bytes.len() as u64;
    let profile_sha256 = sha256_bytes(&profile_bytes);
    require_digest(&profile_sha256, host.profile_sha256, "host Rust profile")?;
    let profile = parse_profile(&profile_bytes)?;
    let scoped = select_component_inventory(&profile, host)?;
    verify_source_files(&source_root, &scoped.files)?;
    verify_profile_target_spec_row(&source_root, scoped.target_spec_rows)?;

    let cargo_metadata = fs::symlink_metadata(&cargo_path)?;
    if !cargo_metadata.file_type().is_file()
        || cargo_metadata.len() == 0
        || cargo_metadata.len() > 128 * 1024 * 1024
    {
        return Err(Refusal::new(
            "native Cargo is not a bounded regular executable",
        ));
    }
    let cargo_identity = FileIdentity {
        path: "bin/cargo".to_owned(),
        bytes: cargo_metadata.len(),
        sha256: sha256_file(&cargo_path)?,
        mode: None,
    };
    verify_file_identity(
        &target_spec_path,
        target.spec_bytes,
        &target.spec_sha256,
        "target spec",
    )?;
    let lock = source_root.join(LIBRARY_LOCK_PATH);
    verify_file_identity(
        &lock,
        LIBRARY_LOCK_BYTES,
        LIBRARY_LOCK_SHA256,
        "Rust source library lock",
    )?;
    let target_spec_identity = FileIdentity {
        path: target.spec_profile_path.clone(),
        bytes: target.spec_bytes,
        sha256: target.spec_sha256.clone(),
        mode: None,
    };
    Ok(Inputs {
        host,
        profile_path,
        profile_bytes: profile_bytes_len,
        profile_sha256,
        source_root,
        cargo_path,
        cargo_identity,
        target_pin_path,
        target_spec_path,
        target,
        scoped,
        target_spec_identity,
    })
}

fn parse_profile(raw: &[u8]) -> Result<ProfileRows> {
    let value: Value = parse_json(raw, JsonProfile::PackageMetadataStateSelection)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("Rust component profile must be an object"))?;
    if object.len() != 2 || !object.contains_key("files") || !object.contains_key("symlinks") {
        return Err(Refusal::new(
            "Rust component profile has an unexpected schema",
        ));
    }
    let files = serde_json::from_value::<Vec<FileIdentity>>(object["files"].clone())
        .map_err(|error| Refusal::new(format!("Rust profile files are malformed: {error}")))?;
    let symlinks = serde_json::from_value::<Vec<LinkIdentity>>(object["symlinks"].clone())
        .map_err(|error| Refusal::new(format!("Rust profile symlinks are malformed: {error}")))?;
    Ok(ProfileRows { files, symlinks })
}

fn select_component_inventory(profile: &ProfileRows, host: HostPins) -> Result<ScopedInventory> {
    if profile.files.len() != host.profile_file_rows || profile.symlinks.len() != 2 {
        return Err(Refusal::new(
            "host Rust profile row counts differ from the pinned component profile",
        ));
    }
    let macos_llvm_runtime_alias =
        select_macos_llvm_runtime_alias(host, &profile.files, &profile.symlinks)?;
    let linux_llvm_runtime_alias =
        select_linux_llvm_runtime_alias(host, &profile.files, &profile.symlinks)?;
    let target_link = LinkIdentity {
        path: SOURCE_PROFILE_TARGET_ALIAS_PATH.to_owned(),
        target: SOURCE_PROFILE_TARGET_ALIAS.to_owned(),
    };
    let linker_link = LinkIdentity {
        path: format!("lib/rustlib/{}/bin/aros-link", host.triple),
        target: "../../../../bin/aros-link".to_owned(),
    };
    let links = profile
        .symlinks
        .iter()
        .map(|row| (row.path.as_str(), row.target.as_str()))
        .collect::<BTreeSet<_>>();
    let expected_links = [
        (target_link.path.as_str(), target_link.target.as_str()),
        (linker_link.path.as_str(), linker_link.target.as_str()),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if links != expected_links {
        return Err(Refusal::new(
            "Rust profile symlink rows differ from the target alias and composed host linker alias",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    let mut installer_admin_files = Vec::new();
    let mut cargo_files = Vec::new();
    let mut rustc_payload_rows = 0usize;
    let mut std_rows = 0usize;
    let mut src_rows = 0usize;
    let mut target_spec_rows = 0usize;
    let mut historical_cargo = None;
    for row in &profile.files {
        validate_relative_inventory_path(&row.path)?;
        if !seen.insert(row.path.as_str()) {
            return Err(Refusal::new("Rust profile contains duplicate file paths"));
        }
        if row.path == SOURCE_PROFILE_TARGET_SPEC_PATH {
            target_spec_rows += 1;
            if row.bytes != SOURCE_PROFILE_TARGET_SPEC_BYTES
                || row.sha256 != SOURCE_PROFILE_TARGET_SPEC_SHA256
            {
                return Err(Refusal::new(
                    "profile target spec row differs from the explicit target spec pin",
                ));
            }
            continue;
        }
        if row
            .path
            .starts_with(&format!("lib/rustlib/{SOURCE_PROFILE_TARGET}/"))
        {
            return Err(Refusal::new(
                "Rust profile unexpectedly contains prebuilt x86_64-aros files",
            ));
        }
        if is_installer_admin_path(&row.path, host.triple) {
            installer_admin_files.push(row.clone());
            continue;
        }
        if is_official_cargo_path(&row.path) {
            if row.path == "bin/cargo" {
                historical_cargo = Some(row.clone());
            }
            cargo_files.push(row.clone());
            continue;
        }
        if row.path.starts_with("lib/rustlib/src/") {
            src_rows += 1;
        } else if row
            .path
            .starts_with(&format!("lib/rustlib/{}/lib/", host.triple))
        {
            std_rows += 1;
        } else {
            rustc_payload_rows += 1;
        }
        selected.push(row.clone());
    }
    let historical_cargo =
        historical_cargo.ok_or_else(|| Refusal::new("official Cargo inventory row is missing"))?;
    if historical_cargo.bytes != host.historical_cargo_bytes
        || historical_cargo.sha256 != host.historical_cargo_sha256
    {
        return Err(Refusal::new(
            "official Cargo row differs from the frozen source profile",
        ));
    }
    if cargo_files.len() != host.cargo_rows
        || rustc_payload_rows != host.rustc_payload_rows
        || installer_admin_files.len() != host.installer_admin_rows
        || std_rows != host.std_rows
        || src_rows != host.src_rows
        || target_spec_rows != host.target_spec_rows
        || selected.len() + installer_admin_files.len() + cargo_files.len() + target_spec_rows
            != profile.files.len()
    {
        return Err(Refusal::new(
            "Rust component path partition differs from the frozen source profile",
        ));
    }
    let lock = selected
        .iter()
        .find(|row| row.path == LIBRARY_LOCK_PATH)
        .ok_or_else(|| {
            Refusal::new("pinned Rust source library lock is missing from selected components")
        })?;
    if lock.bytes != LIBRARY_LOCK_BYTES || lock.sha256 != LIBRARY_LOCK_SHA256 {
        return Err(Refusal::new(
            "Rust source library lock differs from its exact pin",
        ));
    }
    if !selected.iter().any(|row| row.path == "bin/rustc")
        || !selected.iter().any(|row| row.path == "bin/rustdoc")
        || !selected
            .iter()
            .any(|row| row.path.starts_with("lib/rustlib/src/rust/library/vendor/"))
    {
        return Err(Refusal::new(
            "selected Rust components lack required compiler, rustdoc, or local vendor files",
        ));
    }
    Ok(ScopedInventory {
        files: selected,
        installer_admin_files,
        cargo_files,
        host_linker_alias: linker_link,
        macos_llvm_runtime_alias,
        linux_llvm_runtime_alias,
        rustc_payload_rows,
        std_rows,
        src_rows,
        target_spec_rows,
        historical_cargo,
    })
}

fn select_macos_llvm_runtime_alias(
    host: HostPins,
    files: &[FileIdentity],
    symlinks: &[LinkIdentity],
) -> Result<Option<MacosLlvmRuntimeAlias>> {
    if host.name != "macos-aarch64" {
        return Ok(None);
    }
    if host.triple != "aarch64-apple-darwin" {
        return Err(Refusal::new(
            "macOS LLVM runtime alias is only valid for the pinned Apple host triple",
        ));
    }
    if files.iter().any(|row| row.path == MACOS_LLVM_ALIAS_PATH)
        || symlinks.iter().any(|row| row.path == MACOS_LLVM_ALIAS_PATH)
    {
        return Err(Refusal::new(
            "macOS LLVM runtime alias destination collides with a profile row",
        ));
    }
    let source_file = files
        .iter()
        .find(|row| row.path == MACOS_LLVM_SOURCE_PATH)
        .cloned()
        .ok_or_else(|| Refusal::new("authenticated macOS root libLLVM.dylib row is missing"))?;
    let link = LinkIdentity {
        path: MACOS_LLVM_ALIAS_PATH.to_owned(),
        target: MACOS_LLVM_ALIAS_TARGET.to_owned(),
    };
    validate_macos_llvm_runtime_alias(&link, &source_file)?;
    Ok(Some(MacosLlvmRuntimeAlias { link, source_file }))
}

fn validate_macos_llvm_runtime_alias(
    link: &LinkIdentity,
    source_file: &FileIdentity,
) -> Result<()> {
    validate_relative_inventory_path(&link.path)?;
    if link.path != MACOS_LLVM_ALIAS_PATH || link.target != MACOS_LLVM_ALIAS_TARGET {
        return Err(Refusal::new(
            "macOS LLVM runtime alias path or relative target differs from its fixed scope",
        ));
    }
    if source_file.path != MACOS_LLVM_SOURCE_PATH
        || source_file.bytes != MACOS_LLVM_SOURCE_BYTES
        || source_file.sha256 != MACOS_LLVM_SOURCE_SHA256
    {
        return Err(Refusal::new(
            "macOS LLVM runtime alias source differs from its authenticated profile row",
        ));
    }
    Ok(())
}

fn create_macos_llvm_runtime_alias(stage: &Path, alias: &MacosLlvmRuntimeAlias) -> Result<()> {
    validate_macos_llvm_runtime_alias(&alias.link, &alias.source_file)?;
    let path = stage.join(&alias.link.path);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            return Err(Refusal::new(
                "macOS LLVM runtime alias destination already exists in the staged profile",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    symlink(&alias.link.target, path)?;
    Ok(())
}

fn select_linux_llvm_runtime_alias(
    host: HostPins,
    files: &[FileIdentity],
    symlinks: &[LinkIdentity],
) -> Result<Option<LinuxLlvmRuntimeAlias>> {
    if host.name == "macos-aarch64" {
        return Ok(None);
    }
    let (expected_triple, source_bytes, source_sha256) = match host.name {
        "linux-x86_64" => (
            "x86_64-unknown-linux-gnu",
            LINUX_X86_64_LLVM_SOURCE_BYTES,
            LINUX_X86_64_LLVM_SOURCE_SHA256,
        ),
        "linux-aarch64" => (
            "aarch64-unknown-linux-gnu",
            LINUX_AARCH64_LLVM_SOURCE_BYTES,
            LINUX_AARCH64_LLVM_SOURCE_SHA256,
        ),
        _ => {
            return Err(Refusal::new(
                "Linux LLVM runtime alias host is not a pinned Linux profile",
            ));
        }
    };
    if host.triple != expected_triple {
        return Err(Refusal::new(
            "Linux LLVM runtime alias host triple differs from its pinned host",
        ));
    }
    let alias_path = format!("lib/rustlib/{expected_triple}/lib/{LINUX_LLVM_SOURCE_PATH_NAME}");
    if files.iter().any(|row| row.path == alias_path)
        || symlinks.iter().any(|row| row.path == alias_path)
    {
        return Err(Refusal::new(
            "Linux LLVM runtime alias destination collides with a profile row",
        ));
    }
    let source_file = files
        .iter()
        .find(|row| row.path == LINUX_LLVM_SOURCE_PATH)
        .cloned()
        .ok_or_else(|| Refusal::new("authenticated Linux root libLLVM.so row is missing"))?;
    let link = LinkIdentity {
        path: alias_path,
        target: LINUX_LLVM_ALIAS_TARGET.to_owned(),
    };
    validate_linux_llvm_runtime_alias(host, &link, &source_file)?;
    if source_file.bytes != source_bytes || source_file.sha256 != source_sha256 {
        return Err(Refusal::new(
            "Linux root libLLVM.so identity differs from its pinned host profile",
        ));
    }
    Ok(Some(LinuxLlvmRuntimeAlias { link, source_file }))
}

fn validate_linux_llvm_runtime_alias(
    host: HostPins,
    link: &LinkIdentity,
    source_file: &FileIdentity,
) -> Result<()> {
    let (expected_triple, source_bytes, source_sha256) = match host.name {
        "linux-x86_64" => (
            "x86_64-unknown-linux-gnu",
            LINUX_X86_64_LLVM_SOURCE_BYTES,
            LINUX_X86_64_LLVM_SOURCE_SHA256,
        ),
        "linux-aarch64" => (
            "aarch64-unknown-linux-gnu",
            LINUX_AARCH64_LLVM_SOURCE_BYTES,
            LINUX_AARCH64_LLVM_SOURCE_SHA256,
        ),
        _ => {
            return Err(Refusal::new(
                "Linux LLVM runtime alias host is not a pinned Linux profile",
            ));
        }
    };
    if host.triple != expected_triple {
        return Err(Refusal::new(
            "Linux LLVM runtime alias host triple differs from its pinned host",
        ));
    }
    let expected_path = format!("lib/rustlib/{expected_triple}/lib/{LINUX_LLVM_SOURCE_PATH_NAME}");
    validate_relative_inventory_path(&link.path)?;
    if link.path != expected_path || link.target != LINUX_LLVM_ALIAS_TARGET {
        return Err(Refusal::new(
            "Linux LLVM runtime alias path or relative target differs from its fixed host scope",
        ));
    }
    if source_file.path != LINUX_LLVM_SOURCE_PATH
        || source_file.bytes != source_bytes
        || source_file.sha256 != source_sha256
    {
        return Err(Refusal::new(
            "Linux LLVM runtime alias source differs from its authenticated host profile row",
        ));
    }
    Ok(())
}

fn create_linux_llvm_runtime_alias(
    host: HostPins,
    stage: &Path,
    alias: &LinuxLlvmRuntimeAlias,
) -> Result<()> {
    validate_linux_llvm_runtime_alias(host, &alias.link, &alias.source_file)?;
    let path = stage.join(&alias.link.path);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            return Err(Refusal::new(
                "Linux LLVM runtime alias destination already exists in the staged profile",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    symlink(&alias.link.target, path)?;
    Ok(())
}

fn is_installer_admin_path(path: &str, triple: &str) -> bool {
    matches!(
        path,
        "lib/rustlib/components"
            | "lib/rustlib/install.log"
            | "lib/rustlib/manifest-cargo"
            | "lib/rustlib/manifest-rustc"
            | "lib/rustlib/manifest-rust-src"
            | "lib/rustlib/rust-installer-version"
            | "lib/rustlib/uninstall.sh"
    ) || path.strip_prefix("lib/rustlib/manifest-rust-std-") == Some(triple)
}

fn is_official_cargo_path(path: &str) -> bool {
    path == "bin/cargo"
        || path == "etc/bash_completion.d/cargo"
        || path.starts_with("share/doc/cargo/")
        || path.starts_with("share/man/man1/cargo-")
        || path == "share/man/man1/cargo.1"
        || path == "share/zsh/site-functions/_cargo"
}

fn verify_source_files(root: &Path, files: &[FileIdentity]) -> Result<()> {
    for row in files {
        verify_file_identity(
            &root.join(&row.path),
            row.bytes,
            &row.sha256,
            "selected Rust component file",
        )?;
    }
    Ok(())
}

fn verify_profile_target_spec_row(root: &Path, rows: usize) -> Result<()> {
    if rows == 1 {
        verify_file_identity(
            &root.join(SOURCE_PROFILE_TARGET_SPEC_PATH),
            SOURCE_PROFILE_TARGET_SPEC_BYTES,
            SOURCE_PROFILE_TARGET_SPEC_SHA256,
            "pinned profile target-spec row",
        )?;
    }
    Ok(())
}

fn verify_stable_inputs(inputs: &Inputs) -> Result<()> {
    verify_file_identity(
        &inputs.profile_path,
        inputs.profile_bytes,
        inputs.host.profile_sha256,
        "Rust profile input",
    )?;
    verify_source_files(&inputs.source_root, &inputs.scoped.files)?;
    verify_profile_target_spec_row(&inputs.source_root, inputs.scoped.target_spec_rows)?;
    verify_file_identity(
        &inputs.source_root.join(LIBRARY_LOCK_PATH),
        LIBRARY_LOCK_BYTES,
        LIBRARY_LOCK_SHA256,
        "Rust source library lock",
    )?;
    verify_file_identity(
        &inputs.cargo_path,
        inputs.cargo_identity.bytes,
        &inputs.cargo_identity.sha256,
        "native Cargo",
    )?;
    verify_file_identity(
        &inputs.target_spec_path,
        inputs.target.spec_bytes,
        &inputs.target.spec_sha256,
        "target spec",
    )?;
    verify_file_identity(
        &inputs.target_pin_path,
        inputs.target.pin_bytes,
        &inputs.target.pin_sha256,
        "target pin",
    )?;
    let target_pin = read_bounded_regular(&inputs.target_pin_path, 16 * 1024)?;
    let target_spec = read_bounded_regular(&inputs.target_spec_path, 16 * 1024)?;
    let target = parse_target_definition(&target_pin, &target_spec)?;
    if target.name != inputs.target.name
        || target.source_date_epoch != inputs.target.source_date_epoch
    {
        return Err(Refusal::new("target pin epoch changed during producer run"));
    }
    Ok(())
}

fn parse_target_definition(pin_raw: &[u8], spec_raw: &[u8]) -> Result<TargetDefinition> {
    let value: Value = parse_json(pin_raw, JsonProfile::PackageMetadataStateSelection)?;
    let target = value
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("target pin target is malformed"))?;
    let (pin_bytes, pin_sha256, spec_bytes, spec_sha256) = match target {
        "x86_64-unknown-aros-abi1" => (
            253,
            "5840e8bc7cb7b810a6948d8f9042a992a18ec000351d21e697538489c146367f",
            972,
            "0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807",
        ),
        "x86_64-unknown-aros-abi11" => (
            254,
            "382d0ad643fb659fe14a5074cc709be15f6a53524baf406fbf6563c68914dfe7",
            980,
            "5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9",
        ),
        _ => {
            return Err(Refusal::new(
                "target pin is not an admitted AROS release target",
            ));
        }
    };
    let source_date_epoch = value
        .get("source_date_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new("target pin source-date epoch is malformed"))?;
    if value.get("schema").and_then(Value::as_str) != Some("aros-native-build-target-v1")
        || value.get("spec_sha256").and_then(Value::as_str) != Some(spec_sha256)
        || value.get("status").and_then(Value::as_str) != Some("RELEASE_CANDIDATE_NOT_PUBLISHED")
        || source_date_epoch != 1_791_936_000
        || pin_raw.len() as u64 != pin_bytes
        || sha256_bytes(pin_raw) != pin_sha256
        || spec_raw.len() as u64 != spec_bytes
        || sha256_bytes(spec_raw) != spec_sha256
    {
        return Err(Refusal::new(
            "target pin or specification differs from the admitted release candidate",
        ));
    }
    let alias = format!("{target}.json");
    Ok(TargetDefinition {
        name: target.to_owned(),
        source_date_epoch,
        pin_bytes,
        pin_sha256: pin_sha256.to_owned(),
        spec_bytes,
        spec_sha256: spec_sha256.to_owned(),
        alias_path: format!("lib/rustlib/{target}/target.json"),
        alias: alias.clone(),
        spec_profile_path: format!("lib/rustlib/{target}/{alias}"),
    })
}

fn install_rust_components(
    inputs: &Inputs,
    work: &Path,
    output: &Path,
    stage: &Path,
) -> Result<()> {
    let source = ami_rust_core::directory::Directory::open(&inputs.source_root)?;
    let parent = ami_rust_core::directory::Directory::open(work)?;
    let current = managed_workspace_bytes(work, output)?;
    let spec = ComponentInstallSpec {
        destination_name: OsStr::new("toolchain"),
        files: &inputs.scoped.files,
        symlinks: &[],
        limits: ComponentInstallLimits {
            max_tree_entries: 10_000,
            max_path_bytes: 4_096,
            max_path_components: 32,
            max_file_bytes: 512 * 1024 * 1024,
            max_expanded_bytes: 1024 * 1024 * 1024,
            current_workspace_bytes: current,
            max_workspace_bytes: WORKSPACE_BYTES,
            max_link_target_bytes: 4_096,
            max_link_resolution_steps: 256,
        },
    };
    component_install::install_component_profile(&source, &parent, spec, || Ok(())).map_err(
        |error| {
            Refusal::new(format!(
                "could not install pinned Rust component subset: {error}"
            ))
        },
    )?;
    if !stage.is_dir() || stage.is_symlink() {
        return Err(Refusal::new(
            "Rust component installer did not publish the private sysroot",
        ));
    }
    Ok(())
}

struct CommandOutcome {
    summary: Value,
    stdout: String,
    request: CommandRequest,
    own_peak_rss_bytes: u64,
}

struct CommandContext<'a> {
    work: &'a Path,
    output: &'a Path,
    started: &'a Instant,
}

struct InnerCommandBindingContext<'a> {
    host: HostPins,
    work_root: &'a Path,
    output_root: &'a Path,
    helper_sha256: &'a str,
    program_sha256_by_label: &'a BTreeMap<&'static str, String>,
}

fn run_command(
    context: &CommandContext<'_>,
    label: &str,
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<CommandOutcome> {
    if context
        .started
        .elapsed()
        .as_secs()
        .saturating_add(COMMAND_SECONDS)
        > CAMPAIGN_WORK_SECONDS
    {
        return Err(Refusal::new(
            "bare-target campaign reserve prevents starting another 1,200-second command",
        ));
    }
    let record_path = context.output.join("records").join(label);
    let request_path = context
        .output
        .join("requests")
        .join(format!("{label}.json"));
    let request = CommandRequest {
        schema: qualification_command::REQUEST_SCHEMA.to_owned(),
        program: utf8(program)?,
        args: args
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Refusal::new("qualified command argument is not UTF-8"))
            })
            .collect::<Result<Vec<_>>>()?,
        cwd: utf8(cwd)?,
        environment: environment.clone(),
        required_roots: vec![utf8(context.work)?, utf8(context.output)?],
        limits: CommandBudgets {
            seconds: COMMAND_SECONDS,
            rss_bytes: RSS_BYTES,
            workspace_bytes: WORKSPACE_BYTES,
            log_bytes: LOG_BYTES,
        },
    };
    let raw = serde_json::to_vec(&request).map_err(|error| {
        Refusal::new(format!(
            "could not serialize qualified command request: {error}"
        ))
    })?;
    write_new(&request_path, &raw)?;
    let record = qualification_command::run_and_record(&request, &raw, &record_path)?;
    if !record.passed || !record.result_published || record.cli_exit_code() != 0 {
        return Err(Refusal::new(format!(
            "qualified command {label} did not pass"
        )));
    }
    let result_path = record_path.join("result.json");
    let own_peak_rss_bytes = record.own_peak_rss_bytes.ok_or_else(|| {
        Refusal::new(format!(
            "qualified command {label} omitted producer RUSAGE_SELF peak"
        ))
    })?;
    let stdout = fs::read_to_string(record_path.join("stdout.log")).map_err(|error| {
        Refusal::new(format!(
            "could not read qualified command output {label}: {error}"
        ))
    })?;
    let summary = json!({
        "label": label,
        "request_sha256": record.request_sha256,
        "result_sha256": sha256_file(&result_path)?,
        "passed": record.passed,
        "child_exit_code": record.child_exit_code,
        "aggregate_peak_rss_bytes": record.aggregate_peak_rss_bytes,
        "peak_workspace_bytes": record.resource_report.peak_workspace_bytes,
        "peak_log_bytes": record.resource_report.peak_log_bytes,
        "record_path": utf8(&result_path)?,
        "request_path": utf8(&request_path)?
    });
    Ok(CommandOutcome {
        summary,
        stdout,
        request,
        own_peak_rss_bytes,
    })
}

fn retain_command_outcome(
    outcome: CommandOutcome,
    expected_requests: &mut Vec<CommandRequest>,
    summaries: &mut Vec<Value>,
    parent_peak_rss_bytes: &mut u64,
) {
    *parent_peak_rss_bytes = (*parent_peak_rss_bytes).max(outcome.own_peak_rss_bytes);
    expected_requests.push(outcome.request);
    summaries.push(outcome.summary);
}

fn expected_program_path(label: &str, work_root: &Path, host: HostPins) -> Result<PathBuf> {
    let stage = work_root.join("toolchain");
    match label {
        "rustc-version" | "rustc-sysroot" => Ok(stage.join("bin/rustc")),
        "cargo-version" | "source-production" => Ok(stage.join("bin/cargo")),
        "rust-objcopy-version" => {
            Ok(stage.join(format!("lib/rustlib/{}/bin/rust-objcopy", host.triple)))
        }
        _ => Err(Refusal::new("unknown bare-target command binding label")),
    }
}

fn pinned_program_digests(
    work_root: &Path,
    host: HostPins,
) -> Result<BTreeMap<&'static str, String>> {
    bare_target_record_validation::INNER_COMMAND_LABELS
        .iter()
        .map(|label| {
            let path = expected_program_path(label, work_root, host)?;
            Ok((*label, sha256_file(&path)?))
        })
        .collect()
}

fn expected_command_binding(
    request: &CommandRequest,
    program_sha256: &str,
    helper_sha256: &str,
) -> Result<Value> {
    if !is_sha256_digest(program_sha256) || !is_sha256_digest(helper_sha256) {
        return Err(Refusal::new(
            "qualified command executable identity is not SHA-256",
        ));
    }
    let args_raw = serde_json::to_vec(&request.args)
        .map_err(|error| Refusal::new(format!("could not encode command arguments: {error}")))?;
    let environment_raw = serde_json::to_vec(&request.environment)
        .map_err(|error| Refusal::new(format!("could not encode command environment: {error}")))?;
    Ok(json!({
        "program": request.program,
        "program_sha256": program_sha256,
        "cwd": request.cwd,
        "args_sha256": sha256_bytes(&args_raw),
        "environment_keys": request.environment.keys().cloned().collect::<Vec<_>>(),
        "environment_sha256": sha256_bytes(&environment_raw),
        "helper_sha256": helper_sha256
    }))
}

fn validate_bound_command_record(
    label: &str,
    expected: &CommandRequest,
    request_bytes: &[u8],
    summary: &InnerCommandSummary,
    record: &Value,
    context: &InnerCommandBindingContext<'_>,
) -> Result<()> {
    let parsed = qualification_command::parse_request(request_bytes)?;
    let canonical = serde_json::to_vec(expected).map_err(|error| {
        Refusal::new(format!("could not encode planned command request: {error}"))
    })?;
    let expected_roots = vec![utf8(context.work_root)?, utf8(context.output_root)?];
    let expected_program = utf8(&expected_program_path(
        label,
        context.work_root,
        context.host,
    )?)?;
    if parsed != *expected
        || request_bytes != canonical
        || sha256_bytes(request_bytes) != summary.request_sha256
        || record.get("request_sha256").and_then(Value::as_str)
            != Some(summary.request_sha256.as_str())
        || expected.schema != qualification_command::REQUEST_SCHEMA
        || expected.limits != bare_target_record_validation::INNER_LIMITS
        || expected.program != expected_program
        || expected.cwd != utf8(&context.work_root.join("fixture"))?
        || expected.required_roots != expected_roots
    {
        return Err(Refusal::new(format!(
            "qualified command request differs from the producer's host-pinned plan: {label}"
        )));
    }
    let program_sha256 = context
        .program_sha256_by_label
        .get(label)
        .ok_or_else(|| Refusal::new("pinned command program digest is missing"))?;
    let command = expected_command_binding(expected, program_sha256, context.helper_sha256)?;
    if record.get("command") != Some(&command) {
        return Err(Refusal::new(format!(
            "qualified command record binding differs from the producer's host-pinned plan: {label}"
        )));
    }
    Ok(())
}

fn validate_caller_bound_inner_commands(
    storage_output_root: &Path,
    expected_requests: &[CommandRequest],
    summary_values: &[Value],
    context: &InnerCommandBindingContext<'_>,
    parent_peak_rss_bytes: u64,
    parent_rss_limit_bytes: u64,
) -> Result<bare_target_record_validation::InnerValidationSummary> {
    let labels = bare_target_record_validation::INNER_COMMAND_LABELS;
    if expected_requests.len() != labels.len() || summary_values.len() != labels.len() {
        return Err(Refusal::new(
            "producer did not retain exactly five command requests",
        ));
    }
    let summaries: Vec<InnerCommandSummary> =
        serde_json::from_value(Value::Array(summary_values.to_vec())).map_err(|error| {
            Refusal::new(format!("producer command summary is malformed: {error}"))
        })?;
    for ((label, expected), summary) in labels.iter().zip(expected_requests).zip(&summaries) {
        if summary.label != *label {
            return Err(Refusal::new(
                "producer command request labels are out of order",
            ));
        }
        let request_path = storage_output_root
            .join("requests")
            .join(format!("{label}.json"));
        let request_bytes = read_regular_bounded(
            &request_path,
            JsonProfile::PackageMetadataStateSelection.max_bytes(),
        )?;
        let result_path = storage_output_root
            .join("records")
            .join(label)
            .join("result.json");
        let result_bytes = read_regular_bounded(
            &result_path,
            JsonProfile::PackageMetadataStateSelection.max_bytes(),
        )?;
        if sha256_bytes(&result_bytes) != summary.result_sha256 {
            return Err(Refusal::new(format!(
                "qualified command result digest differs from its retained summary: {label}"
            )));
        }
        let record = parse_json_value(&result_bytes, JsonProfile::PackageMetadataStateSelection)?;
        validate_bound_command_record(label, expected, &request_bytes, summary, &record, context)?;
    }
    bare_target_record_validation::validate_inner_commands_with_parent_limit(
        storage_output_root,
        &utf8(context.output_root)?,
        &summaries,
        parent_peak_rss_bytes,
        parent_rss_limit_bytes,
    )
}

fn require_output_contains(output: &str, expected: &str, label: &str) -> Result<()> {
    if output.lines().any(|line| line.trim() == expected) || output.contains(expected) {
        Ok(())
    } else {
        Err(Refusal::new(format!(
            "qualified command output did not prove {label}"
        )))
    }
}

fn collect_libraries(
    work: &Path,
    output_root: &Path,
    target: &TargetDefinition,
    cargo_stdout: &str,
    output: &Path,
) -> Result<Vec<Value>> {
    let crates = ["core", "alloc", "compiler_builtins"];
    let target_release = fs::canonicalize(work.join("target").join(&target.name).join("release"))?;
    let mut artifacts: BTreeMap<&str, Vec<PathBuf>> =
        crates.iter().map(|name| (*name, Vec::new())).collect();

    for line in cargo_stdout.lines() {
        if !line.starts_with('{') || !line.contains("\"reason\"") {
            continue;
        }
        let message =
            parse_json_value(line.as_bytes(), JsonProfile::PackageMetadataStateSelection)?;
        if message.get("reason").and_then(Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(crate_name) = message
            .get("target")
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(matches) = artifacts.get_mut(crate_name) else {
            continue;
        };
        let Some(filenames) = message.get("filenames").and_then(Value::as_array) else {
            return Err(Refusal::new(format!(
                "Cargo artifact for {crate_name} omitted filenames"
            )));
        };
        let prefix = format!("lib{crate_name}-");
        for filename in filenames {
            let path = filename.as_str().ok_or_else(|| {
                Refusal::new(format!(
                    "Cargo artifact filename for {crate_name} is not a string"
                ))
            })?;
            let candidate = PathBuf::from(path);
            let Some(name) = candidate.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if name.starts_with(&prefix) && (name.ends_with(".rlib") || name.ends_with(".rmeta")) {
                matches.push(candidate);
            }
        }
    }

    let mut results = Vec::new();
    for crate_name in crates {
        let matches = artifacts
            .remove(crate_name)
            .ok_or_else(|| Refusal::new("internal Cargo artifact selection is incomplete"))?;
        if matches.len() != 2
            || !matches
                .iter()
                .any(|path| path.extension() == Some(OsStr::new("rlib")))
            || !matches
                .iter()
                .any(|path| path.extension() == Some(OsStr::new("rmeta")))
        {
            return Err(Refusal::new(format!(
                "expected one Cargo-reported {crate_name} rlib/rmeta pair, found {} files",
                matches.len()
            )));
        }
        for source in matches {
            let metadata = fs::symlink_metadata(&source)?;
            if !metadata.file_type().is_file() {
                return Err(Refusal::new(format!(
                    "new {crate_name} target artifact is not a regular file"
                )));
            }
            let canonical_source = fs::canonicalize(&source)?;
            if !canonical_source.starts_with(&target_release) {
                return Err(Refusal::new(format!(
                    "Cargo-reported {crate_name} target artifact is outside the controlled target output"
                )));
            }
            let current = managed_workspace_bytes(work, output_root)?;
            if metadata.len() == 0 || metadata.len() > WORKSPACE_BYTES.saturating_sub(current) {
                return Err(Refusal::new(format!(
                    "retaining the new {crate_name} target artifact would exceed the workspace bound"
                )));
            }
            let filename = source
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| Refusal::new("new target artifact filename is not UTF-8"))?
                .to_owned();
            let kind = source
                .extension()
                .and_then(OsStr::to_str)
                .ok_or_else(|| Refusal::new("new target artifact extension is not UTF-8"))?;
            let destination = output.join(&filename);
            fs::copy(&source, &destination)?;
            let bytes = fs::metadata(&destination)?.len();
            let sha256 = sha256_file(&destination)?;
            if bytes == 0 || sha256 != sha256_file(&source)? {
                return Err(Refusal::new(format!(
                    "new {crate_name} {kind} changed while being retained"
                )));
            }
            results.push(json!({
                "crate": crate_name,
                "kind": kind,
                "path": filename,
                "source_filename": source.file_name().and_then(OsStr::to_str),
                "bytes": bytes,
                "sha256": sha256
            }));
        }
    }
    Ok(results)
}

fn managed_workspace_bytes(work: &Path, output: &Path) -> Result<u64> {
    let limits = ScanLimits {
        max_entries: 250_000,
        max_work_units: 500_001,
    };
    let first = workspace_accounting::scan(work, limits)
        .map_err(|error| Refusal::new(format!("could not account producer work: {error}")))?;
    let second = if work == output {
        Default::default()
    } else {
        workspace_accounting::scan(output, limits)
            .map_err(|error| Refusal::new(format!("could not account producer output: {error}")))?
    };
    first
        .regular_file_bytes
        .checked_add(second.regular_file_bytes)
        .ok_or_else(|| Refusal::new("producer workspace byte count overflow"))
}

fn verify_file_identity(path: &Path, bytes: u64, sha256: &str, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("could not inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() != bytes || sha256_file(path)? != sha256 {
        return Err(Refusal::new(format!(
            "{label} differs from its pinned size or digest"
        )));
    }
    Ok(())
}

fn read_bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("could not inspect input file: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(Refusal::new(
            "pinned input is not regular or exceeds its byte bound",
        ));
    }
    Ok(fs::read(path)?)
}

fn require_digest(actual: &str, expected: &str, label: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(Refusal::new(format!(
            "{label} digest differs from its frozen pin"
        )))
    }
}

fn copy_input(source: &Path, destination: &Path, bytes: u64, sha256: &str) -> Result<()> {
    verify_file_identity(source, bytes, sha256, "producer input")?;
    if destination.exists() || destination.is_symlink() {
        return Err(Refusal::new(
            "private staged input destination already exists",
        ));
    }
    fs::copy(source, destination)?;
    verify_file_identity(destination, bytes, sha256, "private staged input")
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_json_new(path: &Path, value: &Value) -> Result<String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| Refusal::new(format!("could not serialize producer JSON: {error}")))?;
    bytes.push(b'\n');
    let sha256 = sha256_bytes(&bytes);
    write_new(path, &bytes)?;
    Ok(sha256)
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn existing_regular(path: PathBuf) -> Result<PathBuf> {
    let path = absolute_existing(path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::new("producer input must be a regular file"));
    }
    Ok(path)
}

fn existing_directory(path: PathBuf) -> Result<PathBuf> {
    let path = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_dir() {
        return Err(Refusal::new("host Rust input must be a real directory"));
    }
    Ok(path)
}

fn absolute_existing(path: PathBuf) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| Refusal::new("input path has no parent"))?;
    let parent = fs::canonicalize(parent)?;
    Ok(parent.join(
        absolute
            .file_name()
            .ok_or_else(|| Refusal::new("input path has no leaf"))?,
    ))
}

fn fresh_directory_path(path: PathBuf) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| Refusal::new("fresh directory path has no parent"))?;
    let parent = fs::canonicalize(parent)?;
    let leaf = absolute
        .file_name()
        .ok_or_else(|| Refusal::new("fresh directory path has no leaf"))?;
    let normalized = parent.join(leaf);
    ownership::fresh_output(&normalized)?;
    Ok(normalized)
}

fn verify_running_host(host: HostPins) -> Result<()> {
    let actual = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macos-aarch64",
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        _ => {
            return Err(Refusal::new(
                "bare-target producer supports only macOS ARM64 and Linux x86_64/ARM64",
            ));
        }
    };
    if actual == host.name {
        Ok(())
    } else {
        Err(Refusal::new(
            "selected host profile does not match the running host",
        ))
    }
}

fn host_pins(name: &str) -> Option<HostPins> {
    HOSTS.iter().copied().find(|host| host.name == name)
}

fn utf8(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new("producer path must be UTF-8"))
}

fn take(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<OsString> {
    options.remove(OsStr::new(name)).ok_or_else(usage)
}

fn usage() -> Refusal {
    Refusal::new(
        "usage: ami-rust-xtask bare-target-libraries --host {macos-aarch64|linux-x86_64|linux-aarch64} --rust-profile JSON --host-rust SYSROOT --native-cargo FILE --target-pin JSON --target-spec JSON --work FRESH_DIR --output FRESH_DIR",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        HostPins, InnerCommandBindingContext, LIBRARY_LOCK_BYTES, LIBRARY_LOCK_PATH,
        LIBRARY_LOCK_SHA256, LINUX_AARCH64_LLVM_SOURCE_BYTES, LINUX_AARCH64_LLVM_SOURCE_SHA256,
        LINUX_LLVM_ALIAS_TARGET, LINUX_LLVM_SOURCE_PATH, LINUX_LLVM_SOURCE_PATH_NAME,
        LINUX_X86_64_LLVM_SOURCE_BYTES, LINUX_X86_64_LLVM_SOURCE_SHA256, MACOS_LLVM_ALIAS_PATH,
        MACOS_LLVM_ALIAS_TARGET, MACOS_LLVM_SOURCE_BYTES, MACOS_LLVM_SOURCE_PATH,
        MACOS_LLVM_SOURCE_SHA256, ProfileRows, SOURCE_PROFILE_TARGET_ALIAS,
        SOURCE_PROFILE_TARGET_ALIAS_PATH, SOURCE_PROFILE_TARGET_SPEC_BYTES,
        SOURCE_PROFILE_TARGET_SPEC_PATH, SOURCE_PROFILE_TARGET_SPEC_SHA256, TargetDefinition,
        collect_libraries, create_linux_llvm_runtime_alias, is_installer_admin_path,
        is_official_cargo_path, pinned_program_digests, require_digest, select_component_inventory,
        select_linux_llvm_runtime_alias, select_macos_llvm_runtime_alias,
        validate_bound_command_record, validate_caller_bound_inner_commands,
        validate_linux_llvm_runtime_alias, validate_macos_llvm_runtime_alias,
    };
    use ami_rust_core::{
        bare_target_record_validation::{self, InnerCommandSummary},
        inventory::{FileIdentity, LinkIdentity},
        qualification_command::{self, CommandRequest},
    };
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = crate::test_support::temporary_root("bare-target-producer-test");
            fs::create_dir(&root).expect("create test fixture");
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn pins() -> HostPins {
        HostPins {
            name: "macos-aarch64",
            triple: "aarch64-apple-darwin",
            profile_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            profile_file_rows: 12,
            rustc_payload_rows: 3,
            installer_admin_rows: 3,
            std_rows: 1,
            src_rows: 2,
            target_spec_rows: 0,
            cargo_rows: 3,
            historical_cargo_bytes: 1,
            historical_cargo_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
        }
    }

    fn file(path: &str) -> FileIdentity {
        FileIdentity {
            path: path.to_owned(),
            bytes: 1,
            sha256: "3".repeat(64),
            mode: None,
        }
    }

    fn profile(host: HostPins) -> ProfileRows {
        let mut lock = file(LIBRARY_LOCK_PATH);
        lock.bytes = LIBRARY_LOCK_BYTES;
        lock.sha256 = LIBRARY_LOCK_SHA256.to_owned();
        let mut llvm = file(MACOS_LLVM_SOURCE_PATH);
        llvm.bytes = MACOS_LLVM_SOURCE_BYTES;
        llvm.sha256 = MACOS_LLVM_SOURCE_SHA256.to_owned();
        let mut cargo = file("bin/cargo");
        cargo.bytes = host.historical_cargo_bytes;
        cargo.sha256 = host.historical_cargo_sha256.to_owned();
        ProfileRows {
            files: vec![
                file("bin/rustc"),
                file("bin/rustdoc"),
                llvm,
                file("lib/rustlib/aarch64-apple-darwin/lib/libstd.rlib"),
                lock,
                file("lib/rustlib/src/rust/library/vendor/bitflags/Cargo.toml"),
                cargo,
                file("share/doc/cargo/README.md"),
                file("share/man/man1/cargo-build.1"),
                file("lib/rustlib/components"),
                file("lib/rustlib/rust-installer-version"),
                file("lib/rustlib/uninstall.sh"),
            ],
            symlinks: vec![
                LinkIdentity {
                    path: SOURCE_PROFILE_TARGET_ALIAS_PATH.to_owned(),
                    target: SOURCE_PROFILE_TARGET_ALIAS.to_owned(),
                },
                LinkIdentity {
                    path: "lib/rustlib/aarch64-apple-darwin/bin/aros-link".to_owned(),
                    target: "../../../../bin/aros-link".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn retained_target_artifact_pairs_keep_cargo_generated_filenames() {
        let fixture = Fixture::new();
        let work = fixture.0.join("work");
        let output_root = fixture.0.join("output");
        let target_name = "x86_64-unknown-aros-abi1";
        let deps = work
            .join("target")
            .join(target_name)
            .join("release/build/library/out");
        let libraries = output_root.join("libraries");
        fs::create_dir_all(&deps).expect("create deps fixture");
        fs::create_dir_all(&libraries).expect("create library output");
        let pairs = [
            (
                "core",
                [
                    "libcore-0123456789abcdef.rlib",
                    "libcore-0123456789abcdef.rmeta",
                ],
            ),
            (
                "alloc",
                [
                    "liballoc-1123456789abcdef.rlib",
                    "liballoc-1123456789abcdef.rmeta",
                ],
            ),
            (
                "compiler_builtins",
                [
                    "libcompiler_builtins-2123456789abcdef.rlib",
                    "libcompiler_builtins-2123456789abcdef.rmeta",
                ],
            ),
        ];
        for (_, names) in pairs {
            for name in names {
                fs::write(deps.join(name), b"target artifact fixture")
                    .expect("write target artifact fixture");
            }
        }
        let stdout = pairs
            .iter()
            .map(|(crate_name, names)| {
                serde_json::to_string(&json!({
                    "reason": "compiler-artifact",
                    "target": {"name": crate_name},
                    "filenames": names.map(|name| deps.join(name))
                }))
                .expect("serialize Cargo artifact fixture")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let target = TargetDefinition {
            name: target_name.to_owned(),
            source_date_epoch: 1_791_936_000,
            pin_bytes: 0,
            pin_sha256: String::new(),
            spec_bytes: 0,
            spec_sha256: String::new(),
            alias_path: String::new(),
            alias: String::new(),
            spec_profile_path: String::new(),
        };
        let rows = collect_libraries(&work, &output_root, &target, &stdout, &libraries)
            .expect("retain exactly three rlib/rmeta pairs");
        let names = pairs
            .into_iter()
            .flat_map(|(_, names)| names)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 6);
        for (row, name) in rows.iter().zip(names) {
            assert_eq!(row["path"].as_str(), Some(name));
            assert_eq!(row["source_filename"].as_str(), Some(name));
            assert!(libraries.join(name).is_file());
        }
    }

    #[test]
    fn selected_inventory_is_unique_and_keeps_only_the_rust_components() {
        let host = pins();
        let profile = profile(host);
        let selected =
            select_component_inventory(&profile, host).expect("partition fixture profile");
        assert_eq!(selected.files.len(), 6);
        assert_eq!(selected.cargo_files.len(), 3);
        assert_eq!(selected.rustc_payload_rows, 3);
        assert_eq!(selected.installer_admin_files.len(), 3);
        assert_eq!(selected.std_rows, 1);
        assert_eq!(selected.src_rows, 2);
        assert_eq!(selected.target_spec_rows, 0);
        assert_eq!(selected.historical_cargo.path, "bin/cargo");
        assert_eq!(
            selected.host_linker_alias.path,
            "lib/rustlib/aarch64-apple-darwin/bin/aros-link"
        );
        let llvm_alias = selected
            .macos_llvm_runtime_alias
            .expect("Mac Rust objcopy runtime alias");
        assert_eq!(llvm_alias.link.path, MACOS_LLVM_ALIAS_PATH);
        assert_eq!(llvm_alias.link.target, MACOS_LLVM_ALIAS_TARGET);
        assert_eq!(llvm_alias.source_file.path, MACOS_LLVM_SOURCE_PATH);
        assert_eq!(llvm_alias.source_file.bytes, MACOS_LLVM_SOURCE_BYTES);
        assert_eq!(llvm_alias.source_file.sha256, MACOS_LLVM_SOURCE_SHA256);
        assert!(
            select_linux_llvm_runtime_alias(host, &profile.files, &profile.symlinks)
                .expect("Mac profile has no Linux alias")
                .is_none()
        );
        assert!(
            !selected
                .files
                .iter()
                .any(|row| is_official_cargo_path(&row.path))
        );
        assert!(
            !selected
                .files
                .iter()
                .any(|row| row.path.starts_with("lib/rustlib/x86_64-aros/lib/"))
        );
    }

    #[test]
    fn macos_llvm_runtime_alias_refuses_profile_collisions_and_escaping_targets() {
        let host = pins();
        let profile = profile(host);
        let source = profile
            .files
            .iter()
            .find(|row| row.path == MACOS_LLVM_SOURCE_PATH)
            .expect("profile has authenticated root LLVM runtime row")
            .clone();
        let mut colliding_files = profile.files.clone();
        colliding_files.push(file(MACOS_LLVM_ALIAS_PATH));
        assert!(
            select_macos_llvm_runtime_alias(host, &colliding_files, &profile.symlinks).is_err()
        );
        let mut colliding_links = profile.symlinks.clone();
        colliding_links.push(LinkIdentity {
            path: MACOS_LLVM_ALIAS_PATH.to_owned(),
            target: MACOS_LLVM_ALIAS_TARGET.to_owned(),
        });
        assert!(select_macos_llvm_runtime_alias(host, &profile.files, &colliding_links).is_err());
        let escaping = LinkIdentity {
            path: MACOS_LLVM_ALIAS_PATH.to_owned(),
            target: "../../../../libLLVM.dylib".to_owned(),
        };
        assert!(validate_macos_llvm_runtime_alias(&escaping, &source).is_err());
        let mut wrong_source = source.clone();
        wrong_source.sha256 = "0".repeat(64);
        let fixed_link = LinkIdentity {
            path: MACOS_LLVM_ALIAS_PATH.to_owned(),
            target: MACOS_LLVM_ALIAS_TARGET.to_owned(),
        };
        assert!(validate_macos_llvm_runtime_alias(&fixed_link, &wrong_source).is_err());
    }

    #[test]
    fn linux_profiles_receive_authenticated_host_scoped_llvm_aliases() {
        for (name, triple, bytes, sha256) in [
            (
                "linux-x86_64",
                "x86_64-unknown-linux-gnu",
                LINUX_X86_64_LLVM_SOURCE_BYTES,
                LINUX_X86_64_LLVM_SOURCE_SHA256,
            ),
            (
                "linux-aarch64",
                "aarch64-unknown-linux-gnu",
                LINUX_AARCH64_LLVM_SOURCE_BYTES,
                LINUX_AARCH64_LLVM_SOURCE_SHA256,
            ),
        ] {
            let mut host = pins();
            host.name = name;
            host.triple = triple;
            let mut source = file(LINUX_LLVM_SOURCE_PATH);
            source.bytes = bytes;
            source.sha256 = sha256.to_owned();
            let mut profile = profile(host);
            let root = profile
                .files
                .iter_mut()
                .find(|row| row.path == MACOS_LLVM_SOURCE_PATH)
                .expect("fixture root LLVM row");
            *root = source.clone();
            let std = profile
                .files
                .iter_mut()
                .find(|row| row.path.ends_with("/libstd.rlib"))
                .expect("fixture native std row");
            std.path = format!("lib/rustlib/{triple}/lib/libstd.rlib");
            let host_link = profile
                .symlinks
                .iter_mut()
                .find(|row| row.path.ends_with("/bin/aros-link"))
                .expect("fixture host linker alias");
            host_link.path = format!("lib/rustlib/{triple}/bin/aros-link");

            let selected =
                select_component_inventory(&profile, host).expect("complete pinned Linux profile");
            let alias = selected
                .linux_llvm_runtime_alias
                .expect("Linux runtime alias");
            assert_eq!(
                alias.link.path,
                format!("lib/rustlib/{triple}/lib/{LINUX_LLVM_SOURCE_PATH_NAME}")
            );
            assert_eq!(alias.link.target, LINUX_LLVM_ALIAS_TARGET);
            assert_eq!(alias.source_file.path, LINUX_LLVM_SOURCE_PATH);
            validate_linux_llvm_runtime_alias(host, &alias.link, &alias.source_file)
                .expect("exact host runtime alias");

            let fixture = Fixture::new();
            let stage = fixture.0.join("stage");
            let root_file = stage.join(LINUX_LLVM_SOURCE_PATH);
            fs::create_dir_all(root_file.parent().expect("root lib directory"))
                .expect("create root lib directory");
            fs::write(&root_file, b"small loader path fixture")
                .expect("write root library fixture");
            let alias_path = stage.join(&alias.link.path);
            fs::create_dir_all(alias_path.parent().expect("nested host lib directory"))
                .expect("create nested host lib directory");
            create_linux_llvm_runtime_alias(host, &stage, &alias)
                .expect("create nested Linux loader alias");
            assert_eq!(
                fs::read_link(&alias_path)
                    .expect("read alias")
                    .to_str()
                    .expect("UTF-8 symlink target"),
                LINUX_LLVM_ALIAS_TARGET
            );
            assert_eq!(
                alias_path.canonicalize().expect("resolve alias"),
                root_file.canonicalize().expect("resolve root file")
            );
            assert!(create_linux_llvm_runtime_alias(host, &stage, &alias).is_err());
        }
    }

    #[test]
    fn linux_llvm_alias_refuses_missing_wrong_host_collision_escape_and_wrong_source() {
        let mut host = pins();
        host.name = "linux-x86_64";
        host.triple = "x86_64-unknown-linux-gnu";
        let mut source = file(LINUX_LLVM_SOURCE_PATH);
        source.bytes = LINUX_X86_64_LLVM_SOURCE_BYTES;
        source.sha256 = LINUX_X86_64_LLVM_SOURCE_SHA256.to_owned();
        assert!(select_linux_llvm_runtime_alias(host, &[], &[]).is_err());

        let mut wrong_host = host;
        wrong_host.triple = "aarch64-unknown-linux-gnu";
        assert!(select_linux_llvm_runtime_alias(wrong_host, &[source.clone()], &[]).is_err());
        let mut arm_host_with_x86_profile = host;
        arm_host_with_x86_profile.name = "linux-aarch64";
        arm_host_with_x86_profile.triple = "aarch64-unknown-linux-gnu";
        assert!(
            select_linux_llvm_runtime_alias(arm_host_with_x86_profile, &[source.clone()], &[])
                .is_err()
        );

        let alias_path = format!(
            "lib/rustlib/{}/lib/{LINUX_LLVM_SOURCE_PATH_NAME}",
            host.triple
        );
        let mut colliding_file = source.clone();
        colliding_file.path = alias_path.clone();
        assert!(
            select_linux_llvm_runtime_alias(host, &[source.clone(), colliding_file], &[]).is_err()
        );
        assert!(
            select_linux_llvm_runtime_alias(
                host,
                &[source.clone()],
                &[LinkIdentity {
                    path: alias_path.clone(),
                    target: LINUX_LLVM_ALIAS_TARGET.to_owned(),
                }]
            )
            .is_err()
        );

        let link = LinkIdentity {
            path: alias_path.clone(),
            target: LINUX_LLVM_ALIAS_TARGET.to_owned(),
        };
        let escaping = LinkIdentity {
            path: alias_path,
            target: "../../../../libLLVM.so.23.1-rust-1.100.0-nightly".to_owned(),
        };
        assert!(validate_linux_llvm_runtime_alias(host, &escaping, &source).is_err());
        let mut wrong_source = source;
        wrong_source.sha256 = "0".repeat(64);
        assert!(validate_linux_llvm_runtime_alias(host, &link, &wrong_source).is_err());
    }

    #[test]
    fn macos_linux_runtime_alias_selection_remains_disabled() {
        let host = pins();
        let profile = profile(host);
        assert!(
            select_linux_llvm_runtime_alias(host, &profile.files, &profile.symlinks)
                .expect("Mac profile")
                .is_none()
        );
        assert!(
            select_macos_llvm_runtime_alias(host, &profile.files, &profile.symlinks)
                .expect("Mac profile")
                .is_some()
        );
    }

    #[test]
    fn installer_administration_is_authenticated_but_not_component_payload() {
        let host = pins();
        let selected =
            select_component_inventory(&profile(host), host).expect("partition fixture profile");
        let admin_paths = selected
            .installer_admin_files
            .iter()
            .map(|row| row.path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            admin_paths,
            [
                "lib/rustlib/components",
                "lib/rustlib/rust-installer-version",
                "lib/rustlib/uninstall.sh"
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(selected.files.len(), 6);
        assert_eq!(selected.cargo_files.len(), 3);
        for path in [
            "lib/rustlib/components",
            "lib/rustlib/install.log",
            "lib/rustlib/manifest-cargo",
            "lib/rustlib/manifest-rustc",
            "lib/rustlib/manifest-rust-src",
            "lib/rustlib/manifest-rust-std-aarch64-apple-darwin",
            "lib/rustlib/rust-installer-version",
            "lib/rustlib/uninstall.sh",
        ] {
            assert!(is_installer_admin_path(path, host.triple), "{path}");
        }
        assert!(!is_official_cargo_path("lib/rustlib/manifest-cargo"));
        assert!(!is_installer_admin_path(
            "lib/rustlib/manifest-rust-std-x86_64-unknown-linux-gnu",
            host.triple
        ));
        assert!(!is_installer_admin_path(
            "lib/rustlib/components-extra",
            host.triple
        ));
    }

    #[test]
    fn regular_profile_target_spec_is_an_explicit_addition_not_a_rustc_file() {
        let mut host = pins();
        host.profile_file_rows += 1;
        host.target_spec_rows = 1;
        let mut profile = profile(host);
        profile.files.push(FileIdentity {
            path: SOURCE_PROFILE_TARGET_SPEC_PATH.to_owned(),
            bytes: SOURCE_PROFILE_TARGET_SPEC_BYTES,
            sha256: SOURCE_PROFILE_TARGET_SPEC_SHA256.to_owned(),
            mode: None,
        });
        let selected =
            select_component_inventory(&profile, host).expect("target spec partition fixture");
        assert_eq!(selected.target_spec_rows, 1);
        assert!(
            !selected
                .files
                .iter()
                .any(|row| row.path == SOURCE_PROFILE_TARGET_SPEC_PATH)
        );
    }

    #[test]
    fn duplicate_profile_paths_refuse_before_any_fresh_output_is_created() {
        let fixture = Fixture::new();
        let work = fixture.0.join("work");
        let output = fixture.0.join("output");
        let mut host = pins();
        host.profile_file_rows += 1;
        let mut profile = profile(host);
        profile.files.push(file("bin/rustc"));
        assert!(select_component_inventory(&profile, host).is_err());
        assert!(!work.exists());
        assert!(!output.exists());
    }

    #[test]
    fn work_and_output_must_not_be_nested_in_or_enclose_the_source_root() {
        let fixture = Fixture::new();
        let shared = fixture.0.join("shared");
        fs::create_dir(&shared).expect("create shared parent");
        let source = shared.join("rust-source");
        fs::create_dir(&source).expect("create source root");
        let nested_work = source.join("work");
        let nested_output = source.join("output");
        assert!(
            ami_rust_core::ownership::require_disjoint(
                &nested_work,
                &source,
                "work must be disjoint",
            )
            .is_err()
        );
        assert!(
            ami_rust_core::ownership::require_disjoint(
                &source,
                &nested_output,
                "output nested in source must be refused",
            )
            .is_err()
        );
        let enclosing_work = shared.clone();
        let enclosing_output = fixture.0.clone();
        assert!(
            ami_rust_core::ownership::require_disjoint(
                &enclosing_work,
                &source,
                "work enclosing source must be refused",
            )
            .is_err()
        );
        assert!(
            ami_rust_core::ownership::require_disjoint(
                &enclosing_output,
                &source,
                "output enclosing source must be refused",
            )
            .is_err()
        );
        assert!(
            ami_rust_core::ownership::require_disjoint(
                &fixture.0.join("sibling-output"),
                &source,
                "disjoint output accepted",
            )
            .is_ok()
        );
        assert!(!nested_work.exists());
        assert!(!nested_output.exists());
    }

    const ACTUAL_MACOS_COMMAND_FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../core/tests/fixtures/bare-target-records/actual-macos/producer"
    );
    const ACTUAL_MACOS_HELPER_SHA256: &str =
        "23e9ff9cc248ab43a54de757700ac5b62f1528f83c2f43f3bdb4c9b137303a73";

    fn fixture_command_digests() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "rustc-version",
                "5bb7cf7ca89e240c2f97c00c94b5aa3576a84798def7d329b72cb12a20e6e6d0".to_owned(),
            ),
            (
                "rustc-sysroot",
                "5bb7cf7ca89e240c2f97c00c94b5aa3576a84798def7d329b72cb12a20e6e6d0".to_owned(),
            ),
            (
                "cargo-version",
                "4b9264c8796bc594fb0b04fcd023020173f456fde355634760d429765b89486d".to_owned(),
            ),
            (
                "rust-objcopy-version",
                "41f770659a8429c0d1239b103da688041df424998529775bfa9b6d97a0011e95".to_owned(),
            ),
            (
                "source-production",
                "4b9264c8796bc594fb0b04fcd023020173f456fde355634760d429765b89486d".to_owned(),
            ),
        ])
    }

    fn actual_macos_fixture() -> (
        PathBuf,
        PathBuf,
        Vec<CommandRequest>,
        Vec<Value>,
        Vec<InnerCommandSummary>,
        u64,
    ) {
        let fixture = PathBuf::from(ACTUAL_MACOS_COMMAND_FIXTURE)
            .canonicalize()
            .expect("resolve retained fixture without parent traversal");
        let producer: Value = serde_json::from_slice(
            &fs::read(fixture.join("producer.json")).expect("read retained producer record"),
        )
        .expect("parse retained producer record");
        let summary_values = producer["qualification_commands"]
            .as_array()
            .expect("producer retains command summaries")
            .clone();
        let summaries: Vec<InnerCommandSummary> =
            serde_json::from_value(Value::Array(summary_values.clone()))
                .expect("parse retained command summaries");
        let expected_requests = bare_target_record_validation::INNER_COMMAND_LABELS
            .iter()
            .map(|label| {
                let bytes = fs::read(fixture.join("requests").join(format!("{label}.json")))
                    .expect("read retained command request");
                qualification_command::parse_request(&bytes).expect("parse retained request")
            })
            .collect::<Vec<_>>();
        let work_root = PathBuf::from(&expected_requests[0].required_roots[0]);
        let parent_peak = bare_target_record_validation::INNER_COMMAND_LABELS
            .iter()
            .map(|label| {
                let record: Value = serde_json::from_slice(
                    &fs::read(fixture.join("records").join(label).join("result.json"))
                        .expect("read retained command record"),
                )
                .expect("parse retained command record");
                record["own_peak_rss_bytes"]
                    .as_u64()
                    .expect("retained producer RSS high-water")
            })
            .max()
            .expect("five retained records");
        (
            fixture,
            work_root,
            expected_requests,
            summary_values,
            summaries,
            parent_peak,
        )
    }

    #[test]
    fn caller_binding_maps_staged_programs_from_work_root_and_rejects_doubled_toolchain() {
        let fixture = Fixture::new();
        let work = fixture.0.join("work");
        let stage = work.join("toolchain");
        let host = super::host_pins("macos-aarch64").expect("pinned Mac host");
        let rustc = b"fixture staged rustc";
        let cargo = b"fixture staged cargo";
        let objcopy = b"fixture staged rust-objcopy";

        let rustc_path = stage.join("bin/rustc");
        let cargo_path = stage.join("bin/cargo");
        let objcopy_path = stage.join(format!("lib/rustlib/{}/bin/rust-objcopy", host.triple));
        for path in [&rustc_path, &cargo_path, &objcopy_path] {
            fs::create_dir_all(path.parent().expect("staged program parent"))
                .expect("create staged program parent");
        }
        fs::write(&rustc_path, rustc).expect("write staged rustc fixture");
        fs::write(&cargo_path, cargo).expect("write staged Cargo fixture");
        fs::write(&objcopy_path, objcopy).expect("write staged rust-objcopy fixture");
        for path in [&rustc_path, &cargo_path, &objcopy_path] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .expect("make staged program fixture executable");
        }

        let digests = pinned_program_digests(&work, host)
            .expect("production work root resolves the staged toolchain");
        assert_eq!(digests.len(), 5);
        assert_eq!(
            digests["rustc-version"],
            ami_rust_core::digest::sha256_bytes(rustc)
        );
        assert_eq!(
            digests["rustc-sysroot"],
            ami_rust_core::digest::sha256_bytes(rustc)
        );
        assert_eq!(
            digests["cargo-version"],
            ami_rust_core::digest::sha256_bytes(cargo)
        );
        assert_eq!(
            digests["source-production"],
            ami_rust_core::digest::sha256_bytes(cargo)
        );
        assert_eq!(
            digests["rust-objcopy-version"],
            ami_rust_core::digest::sha256_bytes(objcopy)
        );

        assert!(pinned_program_digests(&stage, host).is_err());
    }

    #[test]
    fn retained_actual_macos_five_command_records_pass_caller_binding() {
        let (fixture, work_root, requests, rows, summaries, parent_peak) = actual_macos_fixture();
        let output_root = PathBuf::from(&requests[0].required_roots[1]);
        let host = super::host_pins("macos-aarch64").expect("pinned Mac host");
        let program_sha256_by_label = fixture_command_digests();
        let context = InnerCommandBindingContext {
            host,
            work_root: &work_root,
            output_root: &output_root,
            helper_sha256: ACTUAL_MACOS_HELPER_SHA256,
            program_sha256_by_label: &program_sha256_by_label,
        };
        let validation = validate_caller_bound_inner_commands(
            &fixture,
            &requests,
            &rows,
            &context,
            parent_peak,
            bare_target_record_validation::MAX_PARENT_RSS_BYTES,
        )
        .expect("actual five-command Mac fixture matches the producer plan");
        assert_eq!(validation.commands.len(), 5);
        assert_eq!(validation.total_log_bytes, 52_706);
        assert!(validation.combined_rss_envelope_bytes <= 4 * 1024 * 1024 * 1024);
        assert_eq!(summaries.len(), 5);
    }

    #[test]
    fn caller_binding_refuses_program_argv_cwd_environment_roots_and_digest_changes() {
        let (fixture, work_root, requests, _rows, summaries, _parent_peak) = actual_macos_fixture();
        let output_root = PathBuf::from(&requests[0].required_roots[1]);
        let host = super::host_pins("macos-aarch64").expect("pinned Mac host");
        let program_sha256_by_label = fixture_command_digests();
        let context = InnerCommandBindingContext {
            host,
            work_root: &work_root,
            output_root: &output_root,
            helper_sha256: ACTUAL_MACOS_HELPER_SHA256,
            program_sha256_by_label: &program_sha256_by_label,
        };
        let label = "rustc-version";
        let request_bytes = fs::read(fixture.join("requests/rustc-version.json"))
            .expect("read retained request bytes");
        let record: Value = serde_json::from_slice(
            &fs::read(fixture.join("records/rustc-version/result.json"))
                .expect("read retained command result"),
        )
        .expect("parse retained command result");
        let summary = &summaries[0];
        let original = &requests[0];

        let mut changed = original.clone();
        changed.program.push_str(".unexpected");
        assert!(
            validate_bound_command_record(
                label,
                &changed,
                &request_bytes,
                summary,
                &record,
                &context
            )
            .is_err()
        );

        let mut changed = original.clone();
        changed.args.push("--unexpected".to_owned());
        assert!(
            validate_bound_command_record(
                label,
                &changed,
                &request_bytes,
                summary,
                &record,
                &context
            )
            .is_err()
        );

        let mut changed = original.clone();
        changed.cwd.push_str("/unexpected");
        assert!(
            validate_bound_command_record(
                label,
                &changed,
                &request_bytes,
                summary,
                &record,
                &context
            )
            .is_err()
        );

        let mut changed = original.clone();
        changed
            .environment
            .insert("PATH".to_owned(), "/unexpected".to_owned());
        assert!(
            validate_bound_command_record(
                label,
                &changed,
                &request_bytes,
                summary,
                &record,
                &context
            )
            .is_err()
        );

        let mut changed = original.clone();
        changed.required_roots[0].push_str("/unexpected");
        assert!(
            validate_bound_command_record(
                label,
                &changed,
                &request_bytes,
                summary,
                &record,
                &context
            )
            .is_err()
        );

        let mut changed_summary = summary.clone();
        changed_summary.request_sha256.replace_range(..1, "0");
        assert!(
            validate_bound_command_record(
                label,
                original,
                &request_bytes,
                &changed_summary,
                &record,
                &context
            )
            .is_err()
        );

        let mut changed_record = record.clone();
        changed_record["request_sha256"] = Value::String("0".repeat(64));
        assert!(
            validate_bound_command_record(
                label,
                original,
                &request_bytes,
                summary,
                &changed_record,
                &context,
            )
            .is_err()
        );

        for (field, replacement) in [
            ("program", Value::String("/tmp/unpinned".to_owned())),
            ("program_sha256", Value::String("0".repeat(64))),
            ("args_sha256", Value::String("0".repeat(64))),
            ("cwd", Value::String("/tmp/unpinned".to_owned())),
            ("environment_keys", Value::Array(Vec::new())),
            ("environment_sha256", Value::String("0".repeat(64))),
            ("helper_sha256", Value::String("0".repeat(64))),
        ] {
            let mut changed_record = record.clone();
            changed_record["command"][field] = replacement;
            assert!(
                validate_bound_command_record(
                    label,
                    original,
                    &request_bytes,
                    summary,
                    &changed_record,
                    &context
                )
                .is_err()
            );
        }
    }

    #[test]
    fn wrong_cargo_source_lock_and_stale_profile_digest_refuse_before_output_mutation() {
        let fixture = Fixture::new();
        let work = fixture.0.join("work");
        let output = fixture.0.join("output");
        let host = pins();
        let mut wrong_cargo = profile(host);
        wrong_cargo
            .files
            .iter_mut()
            .find(|row| row.path == "bin/cargo")
            .unwrap()
            .sha256 = "4".repeat(64);
        assert!(select_component_inventory(&wrong_cargo, host).is_err());
        let mut wrong_lock = profile(host);
        wrong_lock
            .files
            .iter_mut()
            .find(|row| row.path == LIBRARY_LOCK_PATH)
            .unwrap()
            .bytes += 1;
        assert!(select_component_inventory(&wrong_lock, host).is_err());
        let mut expanded_host = host;
        expanded_host.profile_file_rows += 1;
        let mut stale_target = profile(expanded_host);
        stale_target
            .files
            .push(file("lib/rustlib/x86_64-aros/lib/libcore-stale.rlib"));
        assert!(select_component_inventory(&stale_target, expanded_host).is_err());
        let fixture = profile(host);
        let raw = serde_json::to_vec(
            &serde_json::json!({"files": fixture.files, "symlinks": fixture.symlinks}),
        )
        .expect("serialize stale profile fixture");
        let actual = ami_rust_core::digest::sha256_bytes(&raw);
        require_digest(&actual, &actual, "exact Rust profile").expect("matching profile digest");
        assert!(require_digest(&actual, host.profile_sha256, "stale Rust profile").is_err());
        assert!(!work.exists());
        assert!(!output.exists());
    }
}

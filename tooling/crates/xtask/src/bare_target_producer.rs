//! Internal maintainer producer for bare x86_64-aros Rust libraries.
//!
//! This stages only the exact pinned rustc, native host std, and rust-src
//! components. Official Cargo and the composed SDK's host-bin/aros-link alias
//! are separate components. The target spec is an explicit producer input;
//! its relative target.json alias is created only inside the fresh subset.
//! This does not admit a host or qualify an SDK.

use ami_rust_core::{
    Refusal, Result,
    component_install::{self, ComponentInstallLimits, ComponentInstallSpec},
    digest::{sha256_bytes, sha256_file},
    files::validate_relative_inventory_path,
    inventory::{FileIdentity, InventoryLimits, LinkIdentity, verify_complete},
    json::{JsonProfile, parse_json},
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

const TARGET: &str = "x86_64-aros";
const RUST_COMMIT: &str = "330d317121e16b5db8e5adc63595910528ff2ee7";
const LIBRARY_LOCK_PATH: &str = "lib/rustlib/src/rust/library/Cargo.lock";
const LIBRARY_LOCK_BYTES: u64 = 10_042;
const LIBRARY_LOCK_SHA256: &str =
    "75848db58a70444bfb62c649b103d19c5d92fede325eb0c8c0e5442848448669";
const TARGET_PIN_BYTES: u64 = 256;
const TARGET_PIN_SHA256: &str = "33fdd3d97053370eb3db9e05ea75721dafcfc7f4b5f8c218acaab1911984c341";
const TARGET_SPEC_BYTES: u64 = 955;
const TARGET_SPEC_SHA256: &str = "de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71";
const TARGET_ALIAS_PATH: &str = "lib/rustlib/x86_64-aros/target.json";
const TARGET_ALIAS: &str = "x86_64-aros.json";
const TARGET_SPEC_PROFILE_PATH: &str = "lib/rustlib/x86_64-aros/x86_64-aros.json";
const MACOS_LLVM_SOURCE_PATH: &str = "lib/libLLVM.dylib";
const MACOS_LLVM_SOURCE_BYTES: u64 = 143_609_472;
const MACOS_LLVM_SOURCE_SHA256: &str =
    "f875883949c8ff96b94faca6a295f66302ae305ce897165fc8765d5ba2d73573";
const MACOS_LLVM_ALIAS_PATH: &str = "lib/rustlib/aarch64-apple-darwin/lib/libLLVM.dylib";
const MACOS_LLVM_ALIAS_TARGET: &str = "../../../libLLVM.dylib";
const LLVM_OBJCOPY_VERSION: &str = "LLVM version 23.1.1";
const CARGO_LOCK_BYTES: &[u8] =
    b"version = 4\n\n[[package]]\nname = \"bare-target-library-probe\"\nversion = \"0.1.0\"\n";
const CARGO_LOCK_SHA256: &str = "969184047306a3a38adfd54e6f4bc77afa3de91713ffd3b3e407789ea69d3708";
const COMMAND_SECONDS: u64 = 1_200;
const RSS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
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
        native_cargo_bytes: 39_348_200,
        native_cargo_sha256: "4b9264c8796bc594fb0b04fcd023020173f456fde355634760d429765b89486d",
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
        native_cargo_bytes: 48_110_632,
        native_cargo_sha256: "938bc3ee1f60b5f239d369a9f3b6bf1a6e004aecdb6ef65fb7fe901745b011db",
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
        native_cargo_bytes: 45_863_336,
        native_cargo_sha256: "2f8a507ec5bef7fe41a04c18aee06e359ff7f3b70d17d98007c9014114e17d9b",
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
    native_cargo_bytes: u64,
    native_cargo_sha256: &'static str,
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

struct Inputs {
    host: HostPins,
    profile_path: PathBuf,
    profile_bytes: u64,
    profile_sha256: String,
    source_root: PathBuf,
    cargo_path: PathBuf,
    target_pin_path: PathBuf,
    target_spec_path: PathBuf,
    target_epoch: u64,
    scoped: ScopedInventory,
    target_spec_identity: FileIdentity,
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
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
        TARGET_PIN_BYTES,
        TARGET_PIN_SHA256,
    )?;
    copy_input(
        &inputs.target_spec_path,
        &output.join("inputs/x86_64-aros.json"),
        TARGET_SPEC_BYTES,
        TARGET_SPEC_SHA256,
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
                "bytes": inputs.host.native_cargo_bytes,
                "sha256": inputs.host.native_cargo_sha256,
                "commit": "3efb1f477e99b42974b982d939fd100303cdf7db"
            },
            "target_pin": {
                "source_path": utf8(&inputs.target_pin_path)?,
                "retained_path": "inputs/target-pin.json",
                "bytes": TARGET_PIN_BYTES,
                "sha256": TARGET_PIN_SHA256,
                "source_date_epoch": inputs.target_epoch
            },
            "target_spec": {
                "source_path": utf8(&inputs.target_spec_path)?,
                "retained_path": "inputs/x86_64-aros.json",
                "bytes": TARGET_SPEC_BYTES,
                "sha256": TARGET_SPEC_SHA256
            },
            "component_install_scope": "authenticated rustc/native-host-std/rust-src payload subset; installer administration rows, official Cargo, and composed host linker alias excluded; target spec added explicitly"
        }),
    )?;

    let stage = work.join("toolchain");
    install_rust_components(&inputs, &work, &output, &stage)?;
    copy_input(
        &inputs.cargo_path,
        &stage.join("bin/cargo"),
        inputs.host.native_cargo_bytes,
        inputs.host.native_cargo_sha256,
    )?;
    let target_spec_path = stage.join(TARGET_SPEC_PROFILE_PATH);
    create_private_dir(target_spec_path.parent().expect("target spec parent"))?;
    copy_input(
        &inputs.target_spec_path,
        &target_spec_path,
        inputs.target_spec_identity.bytes,
        &inputs.target_spec_identity.sha256,
    )?;
    symlink(TARGET_ALIAS, stage.join(TARGET_ALIAS_PATH))?;
    if let Some(alias) = &inputs.scoped.macos_llvm_runtime_alias {
        create_macos_llvm_runtime_alias(&stage, alias)?;
    }

    let mut final_files = inputs.scoped.files.clone();
    final_files.push(FileIdentity {
        path: "bin/cargo".to_owned(),
        bytes: inputs.host.native_cargo_bytes,
        sha256: inputs.host.native_cargo_sha256.to_owned(),
        mode: None,
    });
    final_files.push(inputs.target_spec_identity.clone());
    let mut final_links = vec![LinkIdentity {
        path: TARGET_ALIAS_PATH.to_owned(),
        target: TARGET_ALIAS.to_owned(),
    }];
    if let Some(alias) = &inputs.scoped.macos_llvm_runtime_alias {
        final_links.push(alias.link.clone());
    }
    let component_inventory = json!({
        "schema": "ami-rust-bare-target-scoped-component-inventory-v1",
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
        "target_spec_profile_rows_readded_as_explicit_input": inputs.scoped.target_spec_rows,
        "materialized_files": &final_files,
        "materialized_symlinks": &final_links,
        "cargo_override": {
            "path": "bin/cargo",
            "bytes": inputs.host.native_cargo_bytes,
            "sha256": inputs.host.native_cargo_sha256,
            "commit": "3efb1f477e99b42974b982d939fd100303cdf7db"
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
    if stage.join("lib/rustlib/x86_64-aros/lib").exists() {
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
        inputs.target_epoch.to_string(),
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
    records.push(version.summary);

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
    records.push(selected_sysroot.summary);

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
        "commit-hash: 3efb1f477e99b42974b982d939fd100303cdf7db",
        "pinned native Cargo commit",
    )?;
    require_output_contains(
        &cargo_version.stdout,
        host.triple,
        "native Cargo host triple",
    )?;
    records.push(cargo_version.summary);

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
    records.push(objcopy_version.summary);

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
            OsString::from("-Zami-rust-reproducible-cross"),
            OsString::from("-Zbuild-std=core,alloc"),
            OsString::from("-Zbuild-std-features=compiler-builtins-mem"),
            OsString::from("build"),
            OsString::from("--manifest-path"),
            manifest.clone().into_os_string(),
            OsString::from("--target"),
            OsString::from(TARGET),
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
    records.push(build.summary);

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
    if stage.join("lib/rustlib/x86_64-aros/lib").exists() {
        return Err(Refusal::new(
            "source-library build modified the private Rust component stage",
        ));
    }

    let libraries = collect_libraries(
        &work,
        &output,
        &work.join("target/x86_64-aros/release/deps"),
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
        "scope": "source-built x86_64-aros core, alloc, and compiler_builtins rlibs from pinned rustc/rust-std/rust-src components",
        "host": host.name,
        "rustc_commit": RUST_COMMIT,
        "target": TARGET,
        "input_profile_sha256": inputs.profile_sha256,
        "input_component_counts": {
            "rustc_payload": inputs.scoped.rustc_payload_rows,
            "installer_admin_excluded": inputs.scoped.installer_admin_files.len(),
            "native_host_std": inputs.scoped.std_rows,
            "rust_src": inputs.scoped.src_rows,
            "official_cargo_excluded": inputs.scoped.cargo_files.len(),
            "cross_component_aros_link_alias_excluded": 1,
            "macos_llvm_runtime_alias_added": inputs.scoped.macos_llvm_runtime_alias.is_some(),
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
        "native_cargo_override": {
            "bytes": host.native_cargo_bytes,
            "sha256": host.native_cargo_sha256,
            "replaces_official_cargo_component": true,
            "historical_official_cargo": {
                "path": inputs.scoped.historical_cargo.path,
                "bytes": inputs.scoped.historical_cargo.bytes,
                "sha256": inputs.scoped.historical_cargo.sha256
            }
        },
        "rust_source_library_lock": {"path": LIBRARY_LOCK_PATH, "bytes": LIBRARY_LOCK_BYTES, "sha256": LIBRARY_LOCK_SHA256},
        "target_pin": {"sha256": TARGET_PIN_SHA256, "epoch": inputs.target_epoch},
        "target_spec": {"bytes": TARGET_SPEC_BYTES, "sha256": TARGET_SPEC_SHA256, "alias": {"path": TARGET_ALIAS_PATH, "target": TARGET_ALIAS}},
        "macos_rust_objcopy_llvm_runtime_alias": inputs.scoped.macos_llvm_runtime_alias.as_ref().map(|alias| json!({
            "link": &alias.link,
            "authenticated_source_file": &alias.source_file,
            "purpose": "resolve the pinned macOS rust-objcopy @rpath/libLLVM.dylib from the authenticated root Rust component file"
        })),
        "recipe": {
            "target": TARGET,
            "build_flags": ["-Zjson-target-spec", "-Zami-rust-reproducible-cross", "-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem", "build", "--target=x86_64-aros", "--release", "--locked", "--offline", "--lib", "-j2", "-vv", "--message-format=json-render-diagnostics"],
            "rustflags": flags,
            "source_date_epoch": inputs.target_epoch,
            "network": "offline",
            "stale_target_libraries_loaded": false
        },
        "qualification_commands": records,
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

    verify_file_identity(
        &cargo_path,
        host.native_cargo_bytes,
        host.native_cargo_sha256,
        "native Cargo",
    )?;
    verify_file_identity(
        &target_spec_path,
        TARGET_SPEC_BYTES,
        TARGET_SPEC_SHA256,
        "target spec",
    )?;
    let target_pin_bytes = read_bounded_regular(&target_pin_path, 16 * 1024)?;
    if target_pin_bytes.len() as u64 != TARGET_PIN_BYTES {
        return Err(Refusal::new(
            "target pin differs from its pinned byte length",
        ));
    }
    require_digest(
        &sha256_bytes(&target_pin_bytes),
        TARGET_PIN_SHA256,
        "target pin",
    )?;
    let target_epoch = validate_target_pin(&target_pin_bytes)?;
    let lock = source_root.join(LIBRARY_LOCK_PATH);
    verify_file_identity(
        &lock,
        LIBRARY_LOCK_BYTES,
        LIBRARY_LOCK_SHA256,
        "Rust source library lock",
    )?;
    let target_spec_identity = FileIdentity {
        path: TARGET_SPEC_PROFILE_PATH.to_owned(),
        bytes: TARGET_SPEC_BYTES,
        sha256: TARGET_SPEC_SHA256.to_owned(),
        mode: None,
    };
    Ok(Inputs {
        host,
        profile_path,
        profile_bytes: profile_bytes_len,
        profile_sha256,
        source_root,
        cargo_path,
        target_pin_path,
        target_spec_path,
        target_epoch,
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
    let target_link = LinkIdentity {
        path: TARGET_ALIAS_PATH.to_owned(),
        target: TARGET_ALIAS.to_owned(),
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
        if row.path == TARGET_SPEC_PROFILE_PATH {
            target_spec_rows += 1;
            if row.bytes != TARGET_SPEC_BYTES || row.sha256 != TARGET_SPEC_SHA256 {
                return Err(Refusal::new(
                    "profile target spec row differs from the explicit target spec pin",
                ));
            }
            continue;
        }
        if row.path.starts_with("lib/rustlib/x86_64-aros/") {
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
            &root.join(TARGET_SPEC_PROFILE_PATH),
            TARGET_SPEC_BYTES,
            TARGET_SPEC_SHA256,
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
        inputs.host.native_cargo_bytes,
        inputs.host.native_cargo_sha256,
        "native Cargo",
    )?;
    verify_file_identity(
        &inputs.target_spec_path,
        TARGET_SPEC_BYTES,
        TARGET_SPEC_SHA256,
        "target spec",
    )?;
    verify_file_identity(
        &inputs.target_pin_path,
        TARGET_PIN_BYTES,
        TARGET_PIN_SHA256,
        "target pin",
    )?;
    let target_pin = read_bounded_regular(&inputs.target_pin_path, 16 * 1024)?;
    if validate_target_pin(&target_pin)? != inputs.target_epoch {
        return Err(Refusal::new("target pin epoch changed during producer run"));
    }
    Ok(())
}

fn validate_target_pin(raw: &[u8]) -> Result<u64> {
    let value: Value = parse_json(raw, JsonProfile::PackageMetadataStateSelection)?;
    if value.get("schema").and_then(Value::as_str) != Some("aros-native-build-target-v1")
        || value.get("target").and_then(Value::as_str) != Some(TARGET)
        || value.get("spec_sha256").and_then(Value::as_str) != Some(TARGET_SPEC_SHA256)
        || value.get("status").and_then(Value::as_str)
            != Some("DEVELOPMENT_CANDIDATE_NOT_RELEASE_QUALIFICATION")
    {
        return Err(Refusal::new(
            "target pin does not identify the fixed development candidate",
        ));
    }
    value
        .get("source_date_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new("target pin source-date epoch is malformed"))
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
}

struct CommandContext<'a> {
    work: &'a Path,
    output: &'a Path,
    started: &'a Instant,
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
    Ok(CommandOutcome { summary, stdout })
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
    deps: &Path,
    output: &Path,
) -> Result<Vec<Value>> {
    let crates = ["core", "alloc", "compiler_builtins"];
    let mut results = Vec::new();
    for crate_name in crates {
        let prefix = format!("lib{crate_name}-");
        let mut matches = Vec::new();
        for entry in fs::read_dir(deps)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(&prefix) && name.ends_with(".rlib") {
                matches.push(entry.path());
            }
        }
        if matches.len() != 1 {
            return Err(Refusal::new(format!(
                "expected one new {crate_name} rlib, found {}",
                matches.len()
            )));
        }
        let source = &matches[0];
        let metadata = fs::symlink_metadata(source)?;
        if !metadata.file_type().is_file() {
            return Err(Refusal::new(format!(
                "new {crate_name} rlib is not a regular file"
            )));
        }
        let current = managed_workspace_bytes(work, output_root)?;
        if metadata.len() == 0 || metadata.len() > WORKSPACE_BYTES.saturating_sub(current) {
            return Err(Refusal::new(format!(
                "retaining the new {crate_name} rlib would exceed the workspace bound"
            )));
        }
        let filename = source
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| Refusal::new("new rlib filename is not UTF-8"))?
            .to_owned();
        let destination = output.join(&filename);
        fs::copy(source, &destination)?;
        let bytes = fs::metadata(&destination)?.len();
        let sha256 = sha256_file(&destination)?;
        if bytes == 0 || sha256 != sha256_file(source)? {
            return Err(Refusal::new(format!(
                "new {crate_name} rlib changed while being retained"
            )));
        }
        results.push(json!({
            "crate": crate_name,
            "path": filename,
            "source_filename": source.file_name().and_then(OsStr::to_str),
            "bytes": bytes,
            "sha256": sha256
        }));
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
        HostPins, LIBRARY_LOCK_BYTES, LIBRARY_LOCK_PATH, LIBRARY_LOCK_SHA256,
        MACOS_LLVM_ALIAS_PATH, MACOS_LLVM_ALIAS_TARGET, MACOS_LLVM_SOURCE_BYTES,
        MACOS_LLVM_SOURCE_PATH, MACOS_LLVM_SOURCE_SHA256, ProfileRows, TARGET_ALIAS,
        TARGET_ALIAS_PATH, TARGET_SPEC_BYTES, TARGET_SPEC_PROFILE_PATH, TARGET_SPEC_SHA256,
        collect_libraries, is_installer_admin_path, is_official_cargo_path, require_digest,
        select_component_inventory, select_macos_llvm_runtime_alias,
        validate_macos_llvm_runtime_alias,
    };
    use ami_rust_core::inventory::{FileIdentity, LinkIdentity};
    use std::{
        collections::BTreeSet,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "ami-rust-bare-target-producer-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
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
            native_cargo_bytes: 1,
            native_cargo_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
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
                    path: TARGET_ALIAS_PATH.to_owned(),
                    target: TARGET_ALIAS.to_owned(),
                },
                LinkIdentity {
                    path: "lib/rustlib/aarch64-apple-darwin/bin/aros-link".to_owned(),
                    target: "../../../../bin/aros-link".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn retained_rlibs_keep_cargo_generated_filenames() {
        let fixture = Fixture::new();
        let work = fixture.0.join("work");
        let output_root = fixture.0.join("output");
        let deps = work.join("deps");
        let libraries = output_root.join("libraries");
        fs::create_dir_all(&deps).expect("create deps fixture");
        fs::create_dir_all(&libraries).expect("create library output");
        let names = [
            "libcore-0123456789abcdef.rlib",
            "liballoc-1123456789abcdef.rlib",
            "libcompiler_builtins-2123456789abcdef.rlib",
        ];
        for name in names {
            fs::write(deps.join(name), b"rlib fixture").expect("write rlib fixture");
        }
        let rows = collect_libraries(&work, &output_root, &deps, &libraries)
            .expect("retain exactly the three matching rlibs");
        assert_eq!(rows.len(), 3);
        for (row, name) in rows.iter().zip(names) {
            assert_eq!(row["path"].as_str(), Some(name));
            assert_eq!(row["source_filename"].as_str(), Some(name));
            assert!(libraries.join(name).is_file());
        }
    }

    #[test]
    fn selected_inventory_is_unique_and_keeps_only_the_rust_components() {
        let host = pins();
        let selected =
            select_component_inventory(&profile(host), host).expect("partition fixture profile");
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
    fn linux_profiles_do_not_receive_a_macos_llvm_runtime_alias() {
        let mut host = pins();
        host.name = "linux-x86_64";
        host.triple = "x86_64-unknown-linux-gnu";
        let files = [file("lib/libLLVM.so.23.1-rust-1.100.0-nightly")];
        assert!(
            select_macos_llvm_runtime_alias(host, &files, &[])
                .expect("Linux profile")
                .is_none()
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
            path: TARGET_SPEC_PROFILE_PATH.to_owned(),
            bytes: TARGET_SPEC_BYTES,
            sha256: TARGET_SPEC_SHA256.to_owned(),
            mode: None,
        });
        let selected =
            select_component_inventory(&profile, host).expect("target spec partition fixture");
        assert_eq!(selected.target_spec_rows, 1);
        assert!(
            !selected
                .files
                .iter()
                .any(|row| row.path == TARGET_SPEC_PROFILE_PATH)
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

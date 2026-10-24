//! Internal maintainer caller for the fixed native-prefix assembler.
//!
//! Source-built linker provenance is verified by the outer workflow and attached
//! to this composition receipt; this command checks the artifact identity only.

use ami_rust_core::{
    Refusal, Result,
    component_install::ComponentInstallLimits,
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    files::read_regular_bounded,
    inventory::{FileIdentity, LinkIdentity},
    json::{JsonProfile, parse_json_value},
    native_prefix::{
        NativePrefixFile, NativePrefixProfile, NativePrefixReceipt, NativePrefixSpec,
        assemble_native_prefix,
    },
    ownership::require_disjoint,
    signals::SigtermGuard,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const REQUEST_SCHEMA: &str = "ami-rust-native-prefix-compose-request-v1";
const EXPECTED_INPUTS_RS_SHA256: &str =
    "7d589d181de3b10e9b70c79be5156140403185d4f85eb01917c5dc78c8f392d4";
const EXPECTED_TARGET_LIBRARIES_SHA256: &str =
    "4759fc1a0f2f74e1a624a6c7b62b5d9949d873f1ce05a61ba9825891bf327183";
const EXPECTED_TARGET_PIN_SHA256: &str =
    "33fdd3d97053370eb3db9e05ea75721dafcfc7f4b5f8c218acaab1911984c341";
const EXPECTED_TARGET_SPEC_SHA256: &str =
    "de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71";
const TARGET_SPEC_PATH: &str = "x86_64-aros.json";
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_SOURCE_PIN_BYTES: usize = 2 * 1024 * 1024;
const MAX_LINKER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PREFIX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PREFIX_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const MAX_PREFIX_ENTRIES: usize = 20_000;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_PATH_COMPONENTS: usize = 128;
const MAX_LINK_TARGET_BYTES: usize = 4_096;
const MAX_LINK_RESOLUTION_STEPS: usize = 256;

const MAC_RUST: &str =
    include_str!("../../aros-native-build/pins/macos-aarch64/rust-runtime-v2.json");
const EXPECTED_MAC_RUST_SHA256: &str =
    "02eecb396c56bd134cb4dc732d30898b03ab9a84ad1143f5d09c0a6b25fc466e";
const MAC_CARGO: &str = include_str!("../../aros-native-build/pins/macos-aarch64/cargo.json");
const MAC_LLVM: &str = include_str!("../../aros-native-build/pins/macos-aarch64/toolchain.json");
const MAC_CSDK: &str = include_str!("../../aros-native-build/pins/macos-aarch64/csdk.json");
const MAC_COLLECTOR: &str =
    include_str!("../../aros-native-build/pins/macos-aarch64/collector.json");
const ARM_RUST: &str = include_str!("../../aros-native-build/pins/linux-aarch64/rust.json");
const ARM_CARGO: &str = include_str!("../../aros-native-build/pins/linux-aarch64/cargo.json");
const ARM_LLVM: &str = include_str!("../../aros-native-build/pins/linux-aarch64/toolchain.json");
const ARM_CSDK: &str = include_str!("../../aros-native-build/pins/linux-aarch64/csdk.json");
const ARM_COLLECTOR: &str =
    include_str!("../../aros-native-build/pins/linux-aarch64/collector.json");
const LINUX_X64_RUST: &str = include_str!("../../aros-native-build/pins/linux-x86_64/rust.json");
const LINUX_X64_CARGO: &str = include_str!("../../aros-native-build/pins/linux-x86_64/cargo.json");
const LINUX_X64_LLVM: &str =
    include_str!("../../aros-native-build/pins/linux-x86_64/toolchain.json");
const LINUX_X64_CSDK: &str = include_str!("../../aros-native-build/pins/linux-x86_64/csdk.json");
const LINUX_X64_COLLECTOR: &str =
    include_str!("../../aros-native-build/pins/linux-x86_64/collector.json");
const TARGET_PIN: &str = include_str!("../../aros-native-build/pins/target.json");
const TARGET_LIBRARIES: &str = include_str!("../../aros-native-build/pins/target-libraries.json");
const TARGET_SPEC: &[u8] = include_bytes!("../../../../targets/x86_64-aros.json");
const INPUTS_RS: &[u8] = include_bytes!("../../aros-native-build/src/inputs.rs");

pub(super) struct ProfileRows {
    pub(super) files: Vec<FileIdentity>,
    pub(super) symlinks: Vec<LinkIdentity>,
}

pub(super) struct HostProfiles {
    pub(super) key: &'static str,
    pub(super) triple: &'static str,
    pub(super) os: &'static str,
    pub(super) arch: &'static str,
    pub(super) rust: &'static str,
    pub(super) cargo: &'static str,
    pub(super) llvm: &'static str,
    pub(super) csdk: &'static str,
    pub(super) collector: &'static str,
}

pub(super) struct LinkerIdentity {
    pub(super) root: PathBuf,
    pub(super) bytes: u64,
    pub(super) sha256: String,
    pub(super) build_request_sha256: String,
    pub(super) build_record_sha256: String,
}

pub(super) struct CandidateComposition {
    pub(super) host: HostProfiles,
    pub(super) linker: FileIdentity,
    pub(super) linker_build_request_sha256: String,
    pub(super) linker_build_record_sha256: String,
    pub(super) receipt: NativePrefixReceipt,
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    if arguments.next().as_deref() != Some(OsStr::new("--request")) {
        return Err(usage());
    }
    let request_path = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| Refusal::new("native-prefix request path is missing"))?,
    );
    if arguments.next().is_some() {
        return Err(usage());
    }
    let raw_request = read_regular_bounded(&request_path, MAX_REQUEST_BYTES)?;
    let request_sha256 = sha256_bytes(&raw_request);
    let request = parse_json_value(&raw_request, JsonProfile::PackageMetadataStateSelection)?;
    check_keys(
        &request,
        &[
            "schema",
            "host_key",
            "rust_host_triple",
            "source_root",
            "destination",
            "roots",
            "linker",
        ],
    )?;
    if text(&request, "schema")? != REQUEST_SCHEMA {
        return Err(Refusal::new("native-prefix request schema is unsupported"));
    }
    require_candidate_profile_sources()?;

    let host_key = text(&request, "host_key")?;
    let rust_host_triple = text(&request, "rust_host_triple")?;
    let source_root = existing_directory(text(&request, "source_root")?)?;
    let destination = PathBuf::from(text(&request, "destination")?);

    let roots_value = request
        .get("roots")
        .ok_or_else(|| Refusal::new("native-prefix roots are missing"))?;
    check_keys(
        roots_value,
        &[
            "rust",
            "cargo",
            "llvm",
            "csdk",
            "collector",
            "target_libraries",
        ],
    )?;
    let roots = [
        existing_directory(text(roots_value, "rust")?)?,
        existing_directory(text(roots_value, "cargo")?)?,
        existing_directory(text(roots_value, "llvm")?)?,
        existing_directory(text(roots_value, "csdk")?)?,
        existing_directory(text(roots_value, "collector")?)?,
        existing_directory(text(roots_value, "target_libraries")?)?,
    ];
    let linker = request
        .get("linker")
        .ok_or_else(|| Refusal::new("source-built linker identity is missing"))?;
    check_keys(
        linker,
        &[
            "root",
            "path",
            "bytes",
            "sha256",
            "build_request_sha256",
            "build_record_sha256",
        ],
    )?;
    let linker_root = existing_directory(text(linker, "root")?)?;
    let linker_path = text(linker, "path")?;
    let linker_bytes = integer(linker, "bytes")?;
    let linker_sha256 = text(linker, "sha256")?;
    let linker_build_request_sha256 = text(linker, "build_request_sha256")?;
    let linker_build_record_sha256 = text(linker, "build_record_sha256")?;
    if linker_path != "aros-link"
        || linker_bytes == 0
        || linker_bytes > MAX_LINKER_BYTES
        || !is_sha256_digest(linker_sha256)
        || !is_sha256_digest(linker_build_request_sha256)
        || !is_sha256_digest(linker_build_record_sha256)
    {
        return Err(Refusal::new(
            "source-built linker identity or provenance references are invalid",
        ));
    }
    let linker_file = linker_root.join(linker_path);
    let linker_metadata = std::fs::symlink_metadata(&linker_file)?;
    if !linker_metadata.file_type().is_file()
        || linker_metadata.len() != linker_bytes
        || linker_metadata.permissions().mode() & 0o111 == 0
        || sha256_file(&linker_file)? != linker_sha256
    {
        return Err(Refusal::new(
            "source-built linker does not match the caller-authenticated executable identity",
        ));
    }
    let linker = LinkerIdentity {
        root: linker_root,
        bytes: linker_bytes,
        sha256: linker_sha256.to_owned(),
        build_request_sha256: linker_build_request_sha256.to_owned(),
        build_record_sha256: linker_build_record_sha256.to_owned(),
    };
    let composition = compose_candidate(
        host_key,
        rust_host_triple,
        &source_root,
        &destination,
        roots,
        linker,
    )?;
    let host = composition.host;
    let linker_identity = composition.linker;
    let linker_build_request_sha256 = composition.linker_build_request_sha256;
    let linker_build_record_sha256 = composition.linker_build_record_sha256;
    let receipt = composition.receipt;
    println!(
        "{}",
        serde_json::json!({
            "schema":"ami-rust-native-prefix-compose-result-v1",
            "status":"LOCAL_COMPOSED_CANDIDATE_ONLY",
            "request_sha256":request_sha256,
            "source_root":source_root,
            "host_key":receipt.host_key,
            "rust_host_triple":host.triple,
            "source_inputs_rs_sha256":EXPECTED_INPUTS_RS_SHA256,
            "target_library_profile_sha256":EXPECTED_TARGET_LIBRARIES_SHA256,
            "target_spec_sha256":EXPECTED_TARGET_SPEC_SHA256,
            "linker_artifact":{"path":linker_identity.path,"bytes":linker_identity.bytes,"sha256":linker_identity.sha256},
            "linker_build_request_sha256":linker_build_request_sha256,
            "linker_build_record_sha256":linker_build_record_sha256,
            "replaced_official_cargo":receipt.replaced_official_cargo,
            "unmapped_cargo_rows":receipt.unmapped_cargo_rows,
            "unmapped_collector_rows":receipt.unmapped_collector_rows,
            "measurement":{
                "files":receipt.measurement.files,
                "symlinks":receipt.measurement.symlinks,
                "directories":receipt.measurement.directories,
                "file_bytes":receipt.measurement.file_bytes
            },
            "files":receipt.files,
            "symlinks":receipt.symlinks,
            "claim":"Local fixed-layout composition and checked linker artifact identity only. Build provenance is supplied by the outer workflow. Toolchain::open, ordinary Cargo application proof, SDK publication, host admission and RC4 acceptance remain separate."
        })
    );
    Ok(())
}

/// Compose the fixed prefix from profiles embedded in this compiled source.
/// The caller supplies component roots produced by its already authenticated
/// acquisition flow. This API does not admit a new host or authenticate an
/// artifact source; it applies the same source/profile/host checks as the
/// retained maintainer command.
pub(super) fn compose_candidate(
    host_key: &str,
    rust_host_triple: &str,
    source_root: &Path,
    destination: &Path,
    roots: [PathBuf; 6],
    linker: LinkerIdentity,
) -> Result<CandidateComposition> {
    let host = verify_candidate_source(host_key, rust_host_triple, source_root)?;
    let source_root = existing_directory(&source_root.to_string_lossy())?;
    let target_spec_root = existing_directory(&source_root.join("targets").to_string_lossy())?;
    let roots = roots
        .into_iter()
        .map(|root| existing_directory(&root.to_string_lossy()))
        .collect::<Result<Vec<_>>>()?;
    let linker_root = existing_directory(&linker.root.to_string_lossy())?;
    if linker.bytes == 0
        || linker.bytes > MAX_LINKER_BYTES
        || !is_sha256_digest(&linker.sha256)
        || !is_sha256_digest(&linker.build_request_sha256)
        || !is_sha256_digest(&linker.build_record_sha256)
    {
        return Err(Refusal::new(
            "source-built linker identity or provenance references are invalid",
        ));
    }
    let linker_file = linker_root.join("aros-link");
    let linker_metadata = std::fs::symlink_metadata(&linker_file)?;
    if !linker_metadata.file_type().is_file()
        || linker_metadata.len() != linker.bytes
        || linker_metadata.permissions().mode() & 0o111 == 0
        || sha256_file(&linker_file)? != linker.sha256
    {
        return Err(Refusal::new(
            "source-built linker does not match the caller-authenticated executable identity",
        ));
    }
    let linker_identity = FileIdentity {
        path: "aros-link".to_owned(),
        bytes: linker.bytes,
        sha256: linker.sha256,
        mode: Some(0o755),
    };

    require_disjoint(
        &source_root,
        destination,
        "native prefix output overlaps candidate source",
    )?;
    for left in 0..roots.len() {
        require_disjoint(
            &source_root,
            &roots[left],
            "native prefix component overlaps candidate source",
        )?;
        require_disjoint(
            &roots[left],
            destination,
            "native prefix output overlaps a component root",
        )?;
        require_disjoint(
            &linker_root,
            &roots[left],
            "source-built linker overlaps a component root",
        )?;
        for right in left + 1..roots.len() {
            require_disjoint(
                &roots[left],
                &roots[right],
                "native prefix component roots overlap",
            )?;
        }
    }
    require_disjoint(
        &linker_root,
        &source_root,
        "source-built linker overlaps candidate source",
    )?;
    require_disjoint(
        &linker_root,
        destination,
        "native prefix output overlaps source-built linker",
    )?;

    let rust = profile(host.rust, "Rust")?;
    let cargo = profile(host.cargo, "Cargo")?;
    let llvm = profile(host.llvm, "LLVM")?;
    let csdk = profile(host.csdk, "C SDK")?;
    let collector = profile(host.collector, "collector")?;
    let target_libraries = profile(TARGET_LIBRARIES, "target libraries")?;
    let target_library_pin: Value = serde_json::from_str(TARGET_LIBRARIES).map_err(|error| {
        Refusal::new(format!("embedded target-library pin is invalid: {error}"))
    })?;
    if text(&target_library_pin, "schema")? != "aros-target-library-candidate-v1"
        || text(&target_library_pin, "target")? != "x86_64-aros"
        || target_libraries.files.len() != 3
    {
        return Err(Refusal::new(
            "target-library candidate must contain exactly the three reviewed x86_64-aros libraries",
        ));
    }
    let target_pin: Value = serde_json::from_str(TARGET_PIN)
        .map_err(|error| Refusal::new(format!("embedded target pin is invalid: {error}")))?;
    if text(&target_pin, "schema")? != "aros-native-build-target-v1"
        || text(&target_pin, "target")? != "x86_64-aros"
        || text(&target_pin, "status")? != "DEVELOPMENT_CANDIDATE_NOT_RELEASE_QUALIFICATION"
        || text(&target_pin, "spec_sha256")? != EXPECTED_TARGET_SPEC_SHA256
        || sha256_bytes(TARGET_SPEC) != EXPECTED_TARGET_SPEC_SHA256
    {
        return Err(Refusal::new(
            "target specification does not match the pinned development candidate",
        ));
    }
    let target_spec = FileIdentity {
        path: TARGET_SPEC_PATH.to_owned(),
        bytes: TARGET_SPEC.len() as u64,
        sha256: EXPECTED_TARGET_SPEC_SHA256.to_owned(),
        mode: None,
    };
    let guard = SigtermGuard::acquire()?;
    let receipt = assemble_native_prefix(
        NativePrefixSpec {
            destination,
            host_key: host.key,
            rust_host_triple: host.triple,
            rust: NativePrefixProfile {
                root: &roots[0],
                files: &rust.files,
                symlinks: &rust.symlinks,
            },
            cargo: NativePrefixProfile {
                root: &roots[1],
                files: &cargo.files,
                symlinks: &cargo.symlinks,
            },
            llvm: NativePrefixProfile {
                root: &roots[2],
                files: &llvm.files,
                symlinks: &llvm.symlinks,
            },
            csdk: NativePrefixProfile {
                root: &roots[3],
                files: &csdk.files,
                symlinks: &csdk.symlinks,
            },
            collector: NativePrefixProfile {
                root: &roots[4],
                files: &collector.files,
                symlinks: &collector.symlinks,
            },
            target_libraries: NativePrefixProfile {
                root: &roots[5],
                files: &target_libraries.files,
                symlinks: &target_libraries.symlinks,
            },
            target_spec: NativePrefixFile {
                root: &target_spec_root,
                identity: &target_spec,
            },
            aros_link: NativePrefixFile {
                root: &linker_root,
                identity: &linker_identity,
            },
            limits: ComponentInstallLimits {
                max_tree_entries: MAX_PREFIX_ENTRIES,
                max_path_bytes: MAX_PATH_BYTES,
                max_path_components: MAX_PATH_COMPONENTS,
                max_file_bytes: MAX_PREFIX_FILE_BYTES,
                max_expanded_bytes: MAX_PREFIX_BYTES,
                current_workspace_bytes: 0,
                max_workspace_bytes: MAX_PREFIX_BYTES,
                max_link_target_bytes: MAX_LINK_TARGET_BYTES,
                max_link_resolution_steps: MAX_LINK_RESOLUTION_STEPS,
            },
        },
        || guard.check(),
    )
    .map_err(|failure| {
        Refusal::new(format!(
            "{failure}; recovery entry: {:?}",
            failure.recovery_entry
        ))
    })?;
    Ok(CandidateComposition {
        host,
        linker: linker_identity,
        linker_build_request_sha256: linker.build_request_sha256,
        linker_build_record_sha256: linker.build_record_sha256,
        receipt,
    })
}

pub(super) fn verify_candidate_source(
    key: &str,
    triple: &str,
    source_root: &Path,
) -> Result<HostProfiles> {
    require_candidate_profile_sources()?;
    let host = host_profiles(key, triple)?;
    if std::env::consts::OS != host.os || std::env::consts::ARCH != host.arch {
        return Err(Refusal::new(
            "native-prefix host profile must match the running native host",
        ));
    }
    let source_root = existing_directory(&source_root.to_string_lossy())?;
    verify_source_profile_files(&source_root)?;
    Ok(host)
}

fn host_profiles(key: &str, triple: &str) -> Result<HostProfiles> {
    let host = match key {
        "macos-aarch64" => HostProfiles {
            key: "macos-aarch64",
            triple: "aarch64-apple-darwin",
            os: "macos",
            arch: "aarch64",
            rust: MAC_RUST,
            cargo: MAC_CARGO,
            llvm: MAC_LLVM,
            csdk: MAC_CSDK,
            collector: MAC_COLLECTOR,
        },
        "linux-x86_64" => HostProfiles {
            key: "linux-x86_64",
            triple: "x86_64-unknown-linux-gnu",
            os: "linux",
            arch: "x86_64",
            rust: LINUX_X64_RUST,
            cargo: LINUX_X64_CARGO,
            llvm: LINUX_X64_LLVM,
            csdk: LINUX_X64_CSDK,
            collector: LINUX_X64_COLLECTOR,
        },
        "linux-aarch64" => HostProfiles {
            key: "linux-aarch64",
            triple: "aarch64-unknown-linux-gnu",
            os: "linux",
            arch: "aarch64",
            rust: ARM_RUST,
            cargo: ARM_CARGO,
            llvm: ARM_LLVM,
            csdk: ARM_CSDK,
            collector: ARM_COLLECTOR,
        },
        _ => {
            return Err(Refusal::new(
                "native-prefix host is not an explicitly pinned candidate",
            ));
        }
    };
    if triple != host.triple {
        return Err(Refusal::new(
            "native-prefix host key and Rust triple disagree",
        ));
    }
    Ok(host)
}

fn verify_source_profile_files(source_root: &Path) -> Result<()> {
    for (relative, expected_bytes, expected_sha256) in [
        (
            "tooling/crates/aros-native-build/src/inputs.rs",
            INPUTS_RS,
            EXPECTED_INPUTS_RS_SHA256,
        ),
        (
            "tooling/crates/aros-native-build/pins/macos-aarch64/rust-runtime-v2.json",
            MAC_RUST.as_bytes(),
            EXPECTED_MAC_RUST_SHA256,
        ),
        (
            "tooling/crates/aros-native-build/pins/target.json",
            TARGET_PIN.as_bytes(),
            EXPECTED_TARGET_PIN_SHA256,
        ),
        (
            "tooling/crates/aros-native-build/pins/target-libraries.json",
            TARGET_LIBRARIES.as_bytes(),
            EXPECTED_TARGET_LIBRARIES_SHA256,
        ),
        (
            "targets/x86_64-aros.json",
            TARGET_SPEC,
            EXPECTED_TARGET_SPEC_SHA256,
        ),
    ] {
        let path = source_root.join(relative);
        let actual = read_regular_bounded(&path, MAX_SOURCE_PIN_BYTES)?;
        if sha256_bytes(&actual) != expected_sha256 || actual.as_slice() != expected_bytes {
            return Err(Refusal::new(format!(
                "native-prefix candidate source pin differs from the compiled profile: {relative}"
            )));
        }
    }
    Ok(())
}

fn require_candidate_profile_sources() -> Result<()> {
    if sha256_bytes(INPUTS_RS) != EXPECTED_INPUTS_RS_SHA256
        || sha256_bytes(TARGET_LIBRARIES.as_bytes()) != EXPECTED_TARGET_LIBRARIES_SHA256
        || sha256_bytes(TARGET_PIN.as_bytes()) != EXPECTED_TARGET_PIN_SHA256
    {
        return Err(Refusal::new(
            "compiled native-build source is not the reviewed combined candidate profile",
        ));
    }
    for (raw, expected) in [
        (MAC_RUST, EXPECTED_MAC_RUST_SHA256),
        (
            MAC_CARGO,
            "2f081118d19e93b95304c95440d82d1f3d022fb063e4ae7ad1b89285ceddbe39",
        ),
        (
            MAC_LLVM,
            "28237af9576e852451fcdf0470a904edb34a70232feb41d0c56be246313baadf",
        ),
        (
            MAC_CSDK,
            "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
        ),
        (
            MAC_COLLECTOR,
            "34e7e069a72ac84d980f15c797b4250f324eee19088f55d135c9e4eafa0d88de",
        ),
        (
            LINUX_X64_RUST,
            "7a88373f28d19d6d61494587240681999adfb2bec964b4c3d74fae9718f097e8",
        ),
        (
            LINUX_X64_CARGO,
            "85f5bb754c7f11429dc1a58a2adc1256b9ad4da1f7a47926629e1f94dd92ead8",
        ),
        (
            LINUX_X64_LLVM,
            "a68f0d3d6b6d9e9678dca0af25b083d6b00f67fd4f806adcb6a2e16af1a19a6d",
        ),
        (
            LINUX_X64_CSDK,
            "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
        ),
        (
            LINUX_X64_COLLECTOR,
            "0e97967a63d6ec868edcf26e2b2c08a9c36a292416aa0f7ae016564369551caa",
        ),
        (
            ARM_RUST,
            "862be6c4c1d29c59fc774e2d38f046672fcd0aa0978a869be9af2752fb4f76ee",
        ),
        (
            ARM_CARGO,
            "857d1fa31e24d23c6792f79471a454dcdd644e01f18e3dec9b2cb78314e1da87",
        ),
        (
            ARM_LLVM,
            "be3dc1a696882367f4ff39ad393bf3ae66d6ee25fd73f8042eccfcb738defd68",
        ),
        (
            ARM_CSDK,
            "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
        ),
        (
            ARM_COLLECTOR,
            "52ea287e4fdf80eaa58a6d459828f1cb0d778b7201affe0dfde65f5ffec29e55",
        ),
    ] {
        if sha256_bytes(raw.as_bytes()) != expected {
            return Err(Refusal::new(
                "embedded host component profile differs from the reviewed candidate source pins",
            ));
        }
    }
    if sha256_bytes(TARGET_PIN.as_bytes()) != EXPECTED_TARGET_PIN_SHA256
        || sha256_bytes(TARGET_SPEC) != EXPECTED_TARGET_SPEC_SHA256
    {
        return Err(Refusal::new(
            "embedded target profile differs from its reviewed candidate pin",
        ));
    }
    Ok(())
}

fn profile(raw: &str, name: &str) -> Result<ProfileRows> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|error| Refusal::new(format!("embedded {name} profile is invalid: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new(format!("embedded {name} profile is not an object")))?;
    let files = serde_json::from_value::<Vec<FileIdentity>>(
        object
            .get("files")
            .cloned()
            .ok_or_else(|| Refusal::new(format!("embedded {name} profile lacks files")))?,
    )
    .map_err(|error| Refusal::new(format!("embedded {name} file profile is invalid: {error}")))?;
    let symlinks = serde_json::from_value::<Vec<LinkIdentity>>(
        object
            .get("symlinks")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
    )
    .map_err(|error| {
        Refusal::new(format!(
            "embedded {name} symlink profile is invalid: {error}"
        ))
    })?;
    Ok(ProfileRows { files, symlinks })
}

fn existing_directory(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(Refusal::new("native-prefix input paths must be absolute"));
    }
    let canonical = path.canonicalize()?;
    if !canonical.is_dir() {
        return Err(Refusal::new("native-prefix input root is not a directory"));
    }
    Ok(canonical)
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("native-prefix field {name} is not a string")))
}

fn integer(value: &Value, name: &str) -> Result<u64> {
    value.get(name).and_then(Value::as_u64).ok_or_else(|| {
        Refusal::new(format!(
            "native-prefix field {name} is not an unsigned integer"
        ))
    })
}

fn check_keys(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("native-prefix object is invalid"))?;
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Refusal::new(
            "native-prefix request has missing or unknown fields",
        ));
    }
    Ok(())
}

fn usage() -> Refusal {
    Refusal::new("usage: ami-rust-xtask native-prefix-compose --request JSON")
}

//! Assemble the fixed local native-build prefix from caller-authenticated component profiles.
//!
//! This verifies inventory consistency and safely composes local inputs. It
//! does not authenticate a publisher, download inputs, or admit a host profile.

use crate::{
    Refusal, Result,
    component_install::{
        ComponentInstallLimits, create_symlink, random_stage_name, validate_link_target,
    },
    digest::{encode_hex, is_sha256_digest},
    directory::Directory,
    files::validate_relative_inventory_path,
    inventory::{
        FileIdentity, InventoryLimits, LinkIdentity, Measurement, verify_complete_directory_checked,
    },
    ownership::{entry_exists_at, require_disjoint},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{OsStr, OsString},
    fs::{Metadata, Permissions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const RUST_CARGO_ROW: &str = "bin/cargo";
const CARGO_PATH: &str = "bin/cargo";
const COLLECTOR_SOURCE_PATH: &str = "bin/aros-collect";
const COLLECTOR_DESTINATION_PATH: &str = "bin/collect-aros";
const TARGET_SPEC_PATH: &str = "lib/rustlib/x86_64-aros/x86_64-aros.json";
const TARGET_ALIAS_PATH: &str = "lib/rustlib/x86_64-aros/target.json";
const TARGET_ALIAS: &str = "x86_64-aros.json";
const MACOS_AARCH64_RUST_HOST_TRIPLE: &str = "aarch64-apple-darwin";
const RUST_HOST_LINKER_ALIAS_SUFFIX: &str = "/bin/aros-link";
const RUST_HOST_LINKER_ALIAS_TARGET: &str = "../../../../bin/aros-link";
const RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX: &str = "/lib/libLLVM.dylib";
const RUST_HOST_LLVM_RUNTIME_ALIAS_TARGET: &str = "../../../libLLVM.dylib";
const TARGET_LIBRARIES_PREFIX: &str = "lib/rustlib/x86_64-aros/lib";
const LLVM_PREFIX: &str = "libexec/aros/llvm";
const CSDK_PREFIX: &str = "lib/aros/c-sdk";
const LLVM_ROOT_TOOLS: [&str; 5] = ["llvm-objdump", "llvm-nm", "llvm-ar", "llvm-strip", "ld.lld"];
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Caller-authenticated rows for one already-present component root.
///
/// The caller remains responsible for authenticating the profile and selecting
/// the correct host. This function verifies the named bytes and links before
/// publishing the composed prefix.
#[derive(Clone, Copy)]
pub struct NativePrefixProfile<'a> {
    pub root: &'a Path,
    pub files: &'a [FileIdentity],
    pub symlinks: &'a [LinkIdentity],
}

/// One explicitly selected regular file outside a component profile.
#[derive(Clone, Copy)]
pub struct NativePrefixFile<'a> {
    pub root: &'a Path,
    pub identity: &'a FileIdentity,
}

/// Inputs for the one supported fixed native-build prefix layout.
///
/// The host key and Rust host triple are data supplied by the caller's already
/// admitted host profile. Supplying a new key here does not admit that host in
/// a consumer or change any embedded native-build pins.
pub struct NativePrefixSpec<'a> {
    pub destination: &'a Path,
    pub host_key: &'a str,
    pub rust_host_triple: &'a str,
    pub rust: NativePrefixProfile<'a>,
    pub cargo: NativePrefixProfile<'a>,
    pub llvm: NativePrefixProfile<'a>,
    pub csdk: NativePrefixProfile<'a>,
    pub collector: NativePrefixProfile<'a>,
    pub target_libraries: NativePrefixProfile<'a>,
    pub target_spec: NativePrefixFile<'a>,
    pub aros_link: NativePrefixFile<'a>,
    pub limits: ComponentInstallLimits,
}

/// Complete output inventory and measurements for a published prefix.
#[derive(Debug)]
pub struct NativePrefixReceipt {
    pub destination: PathBuf,
    pub host_key: String,
    pub files: Vec<FileIdentity>,
    pub symlinks: Vec<LinkIdentity>,
    /// Cargo-profile files outside the selected `bin/cargo` mapping.
    /// Callers retain these rows for provenance and notice handling.
    pub unmapped_cargo_rows: Vec<FileIdentity>,
    /// Collector-profile files outside the selected `bin/aros-collect` mapping.
    /// Callers retain these rows for provenance and notice handling.
    pub unmapped_collector_rows: Vec<FileIdentity>,
    pub replaced_official_cargo: FileIdentity,
    pub measurement: Measurement,
}

/// Failure preserves the primary cause and a bounded recovery name if cleanup
/// of the private stage also fails.
#[derive(Debug)]
pub struct NativePrefixFailure {
    pub reason: Refusal,
    pub recovery_entry: Option<OsString>,
}

impl std::fmt::Display for NativePrefixFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, formatter)
    }
}

impl Error for NativePrefixFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.reason)
    }
}

pub type NativePrefixResult<T> = std::result::Result<T, NativePrefixFailure>;

#[derive(Clone, Copy)]
struct SourceRoot {
    root: usize,
}

struct OpenInputs {
    roots: Vec<Directory>,
    profiles: [SourceRoot; 6],
    target_spec: SourceRoot,
    aros_link: SourceRoot,
}

#[derive(Clone)]
struct MappedFile {
    source_root: usize,
    source_path: String,
    output: FileIdentity,
}

#[derive(Clone)]
struct MappedLink {
    source_root: Option<usize>,
    source_path: String,
    output: LinkIdentity,
}

struct PrefixPlan {
    files: Vec<MappedFile>,
    symlinks: Vec<MappedLink>,
    output_files: Vec<FileIdentity>,
    output_symlinks: Vec<LinkIdentity>,
    directories: BTreeSet<String>,
    tree_entries: usize,
    unmapped_cargo_rows: Vec<FileIdentity>,
    unmapped_collector_rows: Vec<FileIdentity>,
    replaced_official_cargo: FileIdentity,
}

fn is_generated_rust_alias_path(path: &str, rust_host_triple: &str) -> bool {
    path == TARGET_ALIAS_PATH
        || path == format!("lib/rustlib/{rust_host_triple}{RUST_HOST_LINKER_ALIAS_SUFFIX}")
        || (rust_host_triple == MACOS_AARCH64_RUST_HOST_TRIPLE
            && path
                == format!("lib/rustlib/{rust_host_triple}{RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX}"))
}

fn validate_generated_rust_aliases(
    rust: NativePrefixProfile<'_>,
    rust_host_triple: &str,
) -> Result<()> {
    let target_alias_count = rust
        .symlinks
        .iter()
        .filter(|link| link.path == TARGET_ALIAS_PATH)
        .count();
    if target_alias_count != 1
        || !rust
            .symlinks
            .iter()
            .any(|link| link.path == TARGET_ALIAS_PATH && link.target == TARGET_ALIAS)
    {
        return Err(Refusal::new(
            "Rust profile lacks the required relative target.json alias",
        ));
    }

    let expected_linker_path =
        format!("lib/rustlib/{rust_host_triple}{RUST_HOST_LINKER_ALIAS_SUFFIX}");
    let linker_aliases = rust
        .symlinks
        .iter()
        .filter(|link| link.path.ends_with(RUST_HOST_LINKER_ALIAS_SUFFIX))
        .collect::<Vec<_>>();
    if linker_aliases.len() != 1
        || linker_aliases[0].path != expected_linker_path
        || linker_aliases[0].target != RUST_HOST_LINKER_ALIAS_TARGET
    {
        return Err(Refusal::new(
            "Rust profile host aros-link alias does not match the selected host",
        ));
    }

    let llvm_runtime_aliases = rust
        .symlinks
        .iter()
        .filter(|link| link.path.ends_with(RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX))
        .collect::<Vec<_>>();
    if rust_host_triple == MACOS_AARCH64_RUST_HOST_TRIPLE {
        let expected_path =
            format!("lib/rustlib/{rust_host_triple}{RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX}");
        if llvm_runtime_aliases.len() != 1
            || llvm_runtime_aliases[0].path != expected_path
            || llvm_runtime_aliases[0].target != RUST_HOST_LLVM_RUNTIME_ALIAS_TARGET
        {
            return Err(Refusal::new(
                "Rust profile macOS LLVM runtime alias does not match the selected host",
            ));
        }
    } else if !llvm_runtime_aliases.is_empty() {
        return Err(Refusal::new(
            "Rust profile contains an unsupported LLVM runtime alias",
        ));
    }
    Ok(())
}

pub fn assemble_native_prefix(
    spec: NativePrefixSpec<'_>,
    mut cancellation_check: impl FnMut() -> Result<()>,
) -> NativePrefixResult<NativePrefixReceipt> {
    cancellation_check().map_err(failure)?;
    let (destination_parent_path, destination_name) =
        validate_destination(spec.destination).map_err(failure)?;
    validate_host_identity(spec.host_key, spec.rust_host_triple).map_err(failure)?;
    validate_limits(spec.limits).map_err(failure)?;

    for source in [
        spec.rust.root,
        spec.cargo.root,
        spec.llvm.root,
        spec.csdk.root,
        spec.collector.root,
        spec.target_libraries.root,
        spec.target_spec.root,
        spec.aros_link.root,
    ] {
        require_disjoint(
            source,
            spec.destination,
            "native prefix output overlaps an input component root",
        )
        .map_err(failure)?;
    }

    let destination_parent = Directory::open(destination_parent_path).map_err(failure)?;
    require_destination_absent(&destination_parent, destination_name).map_err(failure)?;
    let inputs = open_inputs(&spec).map_err(failure)?;
    let plan = preflight(&spec, &inputs, &mut cancellation_check).map_err(failure)?;
    let cleanup_bound = plan
        .tree_entries
        .checked_add(1)
        .ok_or_else(|| failure(Refusal::new("native prefix cleanup bound overflow")))?;

    let stage_name = random_stage_name().map_err(failure)?;
    let mut stage_created = false;
    let stage = match destination_parent.mkdir_new_tracked(&stage_name, 0o700, || {
        stage_created = true;
    }) {
        Ok(stage) => stage,
        Err(reason) if stage_created => {
            return Err(cleanup_failure(
                &destination_parent,
                &stage_name,
                cleanup_bound,
                reason,
            ));
        }
        Err(reason) => return Err(failure(reason)),
    };

    let built = build_stage(&stage, &inputs, &plan, spec.limits, &mut cancellation_check);
    let measurement = match built {
        Ok(measurement) => measurement,
        Err(reason) => {
            return Err(cleanup_failure(
                &destination_parent,
                &stage_name,
                cleanup_bound,
                reason,
            ));
        }
    };

    if let Err(reason) = cancellation_check() {
        return Err(cleanup_failure(
            &destination_parent,
            &stage_name,
            cleanup_bound,
            reason,
        ));
    }
    if let Err(reason) =
        destination_parent.rename_no_replace(&stage_name, &destination_parent, destination_name)
    {
        return Err(cleanup_failure(
            &destination_parent,
            &stage_name,
            cleanup_bound,
            reason,
        ));
    }
    destination_parent.sync_best_effort();

    Ok(NativePrefixReceipt {
        destination: spec.destination.to_path_buf(),
        host_key: spec.host_key.to_owned(),
        files: plan.output_files,
        symlinks: plan.output_symlinks,
        unmapped_cargo_rows: plan.unmapped_cargo_rows,
        unmapped_collector_rows: plan.unmapped_collector_rows,
        replaced_official_cargo: plan.replaced_official_cargo,
        measurement,
    })
}

fn require_destination_absent(parent: &Directory, destination_name: &OsStr) -> Result<()> {
    if entry_exists_at(parent, destination_name)? {
        return Err(Refusal::new("native prefix destination already exists"));
    }
    Ok(())
}

fn validate_destination(destination: &Path) -> Result<(&Path, &OsStr)> {
    if !destination.is_absolute() {
        return Err(Refusal::new("native prefix destination must be absolute"));
    }
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty() && *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| Refusal::new("native prefix destination must name one new directory"))?;
    let parent = destination
        .parent()
        .ok_or_else(|| Refusal::new("native prefix destination has no parent"))?;
    if parent.as_os_str().as_bytes().contains(&0) || name.as_bytes().contains(&0) {
        return Err(Refusal::new(
            "native prefix destination contains a NUL byte",
        ));
    }
    Ok((parent, name))
}

fn validate_host_identity(host_key: &str, rust_host_triple: &str) -> Result<()> {
    for (value, label) in [
        (host_key, "host key"),
        (rust_host_triple, "Rust host triple"),
    ] {
        if value.is_empty()
            || value.contains('/')
            || value.contains('\\')
            || value.contains(':')
            || value.bytes().any(|byte| byte < 0x21 || byte == 0x7f)
        {
            return Err(Refusal::new(format!("native prefix {label} is invalid")));
        }
    }
    let expected_triple = match host_key {
        "macos-aarch64" => "aarch64-apple-darwin",
        "linux-x86_64" => "x86_64-unknown-linux-gnu",
        "linux-aarch64" => "aarch64-unknown-linux-gnu",
        _ => {
            return Err(Refusal::new(
                "native prefix host key is not a supported host identity",
            ));
        }
    };
    if rust_host_triple != expected_triple {
        return Err(Refusal::new(
            "native prefix host key and Rust host triple disagree",
        ));
    }
    Ok(())
}

fn open_inputs(spec: &NativePrefixSpec<'_>) -> Result<OpenInputs> {
    let paths = [
        spec.rust.root,
        spec.cargo.root,
        spec.llvm.root,
        spec.csdk.root,
        spec.collector.root,
        spec.target_libraries.root,
        spec.target_spec.root,
        spec.aros_link.root,
    ];
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(paths.len())
        .map_err(|_| Refusal::new("could not allocate native prefix source roots"))?;
    for path in paths {
        roots.push(Directory::open(path)?);
    }
    Ok(OpenInputs {
        roots,
        profiles: [
            SourceRoot { root: 0 },
            SourceRoot { root: 1 },
            SourceRoot { root: 2 },
            SourceRoot { root: 3 },
            SourceRoot { root: 4 },
            SourceRoot { root: 5 },
        ],
        target_spec: SourceRoot { root: 6 },
        aros_link: SourceRoot { root: 7 },
    })
}

fn preflight(
    spec: &NativePrefixSpec<'_>,
    inputs: &OpenInputs,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<PrefixPlan> {
    let profiles = [
        spec.rust,
        spec.cargo,
        spec.llvm,
        spec.csdk,
        spec.collector,
        spec.target_libraries,
    ];
    for profile in &profiles {
        cancellation_check()?;
        validate_profile_rows(*profile, spec.limits)?;
    }
    validate_generated_rust_aliases(spec.rust, spec.rust_host_triple)?;

    for (index, profile) in profiles.iter().enumerate() {
        cancellation_check()?;
        let root = &inputs.roots[inputs.profiles[index].root];
        for file in profile.files {
            cancellation_check()?;
            verify_source_file(root, file, spec.limits, cancellation_check)?;
        }
        for link in profile.symlinks {
            cancellation_check()?;
            let (parent, leaf) = split_inventory_path(&link.path)?;
            validate_link_target(&link.target, spec.limits.max_link_target_bytes)?;
            if index == 0 && is_generated_rust_alias_path(&link.path, spec.rust_host_triple) {
                continue;
            }
            let source_parent = root.relative_directory(parent)?;
            let target =
                source_parent.link_target(OsStr::new(leaf), spec.limits.max_link_target_bytes)?;
            if target.as_bytes() != link.target.as_bytes() {
                return Err(Refusal::new(
                    "native prefix source symlink differs from profile",
                ));
            }
        }
    }
    validate_external_file(spec.target_spec.identity, spec.limits)?;
    verify_source_file(
        &inputs.roots[inputs.target_spec.root],
        spec.target_spec.identity,
        spec.limits,
        cancellation_check,
    )?;
    validate_external_file(spec.aros_link.identity, spec.limits)?;
    verify_source_file(
        &inputs.roots[inputs.aros_link.root],
        spec.aros_link.identity,
        spec.limits,
        cancellation_check,
    )?;

    let rust = spec.rust;
    let mut official_cargo = None;
    for row in rust.files {
        if row.path == RUST_CARGO_ROW && official_cargo.replace(row.clone()).is_some() {
            return Err(Refusal::new("Rust profile repeats its official Cargo row"));
        }
    }
    let replaced_official_cargo =
        official_cargo.ok_or_else(|| Refusal::new("Rust profile lacks its official Cargo row"))?;
    let unmapped_cargo_rows = spec
        .cargo
        .files
        .iter()
        .filter(|row| row.path != CARGO_PATH)
        .cloned()
        .collect::<Vec<_>>();
    let unmapped_collector_rows = spec
        .collector
        .files
        .iter()
        .filter(|row| row.path != COLLECTOR_SOURCE_PATH)
        .cloned()
        .collect::<Vec<_>>();

    for tool in LLVM_ROOT_TOOLS {
        let path = format!("bin/{tool}");
        let file_count = spec
            .llvm
            .files
            .iter()
            .filter(|row| row.path == path)
            .count();
        let link_count = spec
            .llvm
            .symlinks
            .iter()
            .filter(|row| row.path == path)
            .count();
        if file_count + link_count != 1 {
            return Err(Refusal::new(format!(
                "LLVM profile must contain exactly one {path} entry"
            )));
        }
    }
    require_profile_file(spec.cargo, CARGO_PATH)?;
    if !spec.cargo.symlinks.is_empty() {
        return Err(Refusal::new(
            "paired Cargo profile must contain regular-file rows only",
        ));
    }
    require_profile_file(spec.collector, COLLECTOR_SOURCE_PATH)?;
    if !spec.collector.symlinks.is_empty() {
        return Err(Refusal::new(
            "collector profile must contain regular-file rows only",
        ));
    }
    if !spec.target_libraries.symlinks.is_empty() || spec.target_libraries.files.len() != 3 {
        return Err(Refusal::new(
            "target-library profile must contain the three selected rlibs",
        ));
    }
    validate_target_library_names(spec.target_libraries.files)?;
    if spec.target_spec.identity.bytes == 0 {
        return Err(Refusal::new("target specification input is empty"));
    }
    if spec.aros_link.identity.bytes == 0 {
        return Err(Refusal::new("source-built aros-link input is empty"));
    }

    let mut files = Vec::new();
    let mut symlinks = Vec::new();
    files
        .try_reserve_exact(
            rust.files
                .len()
                .checked_add(
                    spec.cargo.files.len()
                        + spec.llvm.files.len()
                        + spec.csdk.files.len()
                        + spec.collector.files.len()
                        + spec.target_libraries.files.len()
                        + 2,
                )
                .ok_or_else(|| Refusal::new("native prefix output row count overflow"))?,
        )
        .map_err(|_| Refusal::new("could not allocate native prefix file plan"))?;
    symlinks
        .try_reserve_exact(
            rust.symlinks
                .len()
                .checked_add(spec.llvm.symlinks.len())
                .and_then(|count| count.checked_add(spec.csdk.symlinks.len()))
                .and_then(|count| count.checked_add(LLVM_ROOT_TOOLS.len()))
                .ok_or_else(|| Refusal::new("native prefix symlink row count overflow"))?,
        )
        .map_err(|_| Refusal::new("could not allocate native prefix symlink plan"))?;

    let mut add_profile_files = |slot: usize,
                                 profile: NativePrefixProfile<'_>,
                                 prefix: &str,
                                 excluded: &[&str],
                                 selected_only: Option<&str>|
     -> Result<()> {
        for row in profile.files {
            if excluded.contains(&row.path.as_str())
                || selected_only.is_some_and(|selected| row.path != selected)
            {
                continue;
            }
            let destination = join_inventory_prefix(prefix, &row.path)?;
            files.push(MappedFile {
                source_root: slot,
                source_path: row.path.clone(),
                output: FileIdentity {
                    path: destination,
                    bytes: row.bytes,
                    sha256: row.sha256.clone(),
                    mode: row.mode,
                },
            });
        }
        Ok(())
    };
    add_profile_files(0, spec.rust, "", &[RUST_CARGO_ROW], None)?;
    add_profile_files(1, spec.cargo, "", &[], Some(CARGO_PATH))?;
    add_profile_files(2, spec.llvm, LLVM_PREFIX, &[], None)?;
    add_profile_files(3, spec.csdk, CSDK_PREFIX, &[], None)?;
    for row in spec
        .collector
        .files
        .iter()
        .filter(|row| row.path == COLLECTOR_SOURCE_PATH)
    {
        files.push(MappedFile {
            source_root: 4,
            source_path: row.path.clone(),
            output: FileIdentity {
                path: COLLECTOR_DESTINATION_PATH.to_owned(),
                bytes: row.bytes,
                sha256: row.sha256.clone(),
                mode: row.mode,
            },
        });
    }
    for row in spec.target_libraries.files {
        files.push(MappedFile {
            source_root: 5,
            source_path: row.path.clone(),
            output: FileIdentity {
                path: format!("{TARGET_LIBRARIES_PREFIX}/{}", row.path),
                bytes: row.bytes,
                sha256: row.sha256.clone(),
                mode: row.mode,
            },
        });
    }
    files.push(MappedFile {
        source_root: inputs.target_spec.root,
        source_path: spec.target_spec.identity.path.clone(),
        output: FileIdentity {
            path: TARGET_SPEC_PATH.to_owned(),
            bytes: spec.target_spec.identity.bytes,
            sha256: spec.target_spec.identity.sha256.clone(),
            mode: spec.target_spec.identity.mode,
        },
    });
    files.push(MappedFile {
        source_root: inputs.aros_link.root,
        source_path: spec.aros_link.identity.path.clone(),
        output: FileIdentity {
            path: "bin/aros-link".to_owned(),
            bytes: spec.aros_link.identity.bytes,
            sha256: spec.aros_link.identity.sha256.clone(),
            mode: spec.aros_link.identity.mode,
        },
    });

    for (slot, profile, prefix) in [
        (0, spec.rust, ""),
        (2, spec.llvm, LLVM_PREFIX),
        (3, spec.csdk, CSDK_PREFIX),
    ] {
        for row in profile.symlinks {
            let generated =
                slot == 0 && is_generated_rust_alias_path(&row.path, spec.rust_host_triple);
            symlinks.push(MappedLink {
                source_root: (!generated).then_some(slot),
                source_path: if generated {
                    String::new()
                } else {
                    row.path.clone()
                },
                output: LinkIdentity {
                    path: join_inventory_prefix(prefix, &row.path)?,
                    target: row.target.clone(),
                },
            });
        }
    }
    for tool in LLVM_ROOT_TOOLS {
        symlinks.push(MappedLink {
            source_root: None,
            source_path: String::new(),
            output: LinkIdentity {
                path: format!("bin/{tool}"),
                target: format!("../{LLVM_PREFIX}/bin/{tool}"),
            },
        });
    }

    let mut output_files = files
        .iter()
        .map(|row| row.output.clone())
        .collect::<Vec<_>>();
    let mut output_symlinks = symlinks
        .iter()
        .map(|row| row.output.clone())
        .collect::<Vec<_>>();
    output_files.sort_by(|left, right| left.path.cmp(&right.path));
    output_symlinks.sort_by(|left, right| left.path.cmp(&right.path));
    let (directories, tree_entries, expanded_bytes) =
        validate_output_inventory(&output_files, &output_symlinks, spec.limits)?;
    if spec
        .limits
        .current_workspace_bytes
        .checked_add(expanded_bytes)
        .is_none_or(|total| total > spec.limits.max_workspace_bytes)
    {
        return Err(Refusal::new("composed prefix exceeds workspace byte bound"));
    }
    Ok(PrefixPlan {
        files,
        symlinks,
        output_files,
        output_symlinks,
        directories,
        tree_entries,
        unmapped_cargo_rows,
        unmapped_collector_rows,
        replaced_official_cargo,
    })
}

fn validate_profile_rows(
    profile: NativePrefixProfile<'_>,
    limits: ComponentInstallLimits,
) -> Result<()> {
    let rows = profile
        .files
        .len()
        .checked_add(profile.symlinks.len())
        .ok_or_else(|| Refusal::new("native prefix source row count overflow"))?;
    if rows > limits.max_tree_entries {
        return Err(Refusal::new(
            "native prefix source profile exceeds entry bound",
        ));
    }
    let mut paths = BTreeSet::new();
    for file in profile.files {
        validate_input_path(&file.path, limits)?;
        if !is_sha256_digest(&file.sha256)
            || file.mode.is_some_and(|mode| mode & !0o7777 != 0)
            || file.bytes > limits.max_file_bytes
        {
            return Err(Refusal::new(
                "native prefix source file row is invalid or over limit",
            ));
        }
        if !paths.insert(file.path.as_str()) {
            return Err(Refusal::new(
                "native prefix source profile contains duplicate paths",
            ));
        }
    }
    for link in profile.symlinks {
        validate_input_path(&link.path, limits)?;
        validate_link_target(&link.target, limits.max_link_target_bytes)?;
        if !paths.insert(link.path.as_str()) {
            return Err(Refusal::new(
                "native prefix source profile contains duplicate paths",
            ));
        }
    }
    for path in &paths {
        for (offset, _) in path.match_indices('/') {
            if paths.contains(&path[..offset]) {
                return Err(Refusal::new(
                    "native prefix source leaf is a directory ancestor",
                ));
            }
        }
    }
    Ok(())
}

fn validate_input_path(path: &str, limits: ComponentInstallLimits) -> Result<()> {
    validate_relative_inventory_path(path)?;
    if path.len() > limits.max_path_bytes || path.split('/').count() > limits.max_path_components {
        return Err(Refusal::new(
            "native prefix inventory path exceeds path bound",
        ));
    }
    Ok(())
}

fn validate_external_file(identity: &FileIdentity, limits: ComponentInstallLimits) -> Result<()> {
    validate_input_path(&identity.path, limits)?;
    if !is_sha256_digest(&identity.sha256)
        || identity.mode.is_some_and(|mode| mode & !0o7777 != 0)
        || identity.bytes > limits.max_file_bytes
    {
        return Err(Refusal::new(
            "native prefix standalone file identity is invalid",
        ));
    }
    Ok(())
}

fn validate_limits(limits: ComponentInstallLimits) -> Result<()> {
    if limits.max_tree_entries == 0
        || limits.max_path_bytes == 0
        || limits.max_path_components == 0
        || limits.max_file_bytes == 0
        || limits.max_expanded_bytes == 0
        || limits.max_workspace_bytes == 0
        || limits.max_link_target_bytes == 0
        || limits.max_link_resolution_steps == 0
        || limits.current_workspace_bytes > limits.max_workspace_bytes
    {
        return Err(Refusal::new("native prefix limits are invalid"));
    }
    Ok(())
}

fn require_profile_file(profile: NativePrefixProfile<'_>, path: &str) -> Result<()> {
    if profile.files.iter().filter(|row| row.path == path).count() != 1 {
        return Err(Refusal::new(format!(
            "component profile must contain exactly {path}"
        )));
    }
    Ok(())
}

fn validate_target_library_names(files: &[FileIdentity]) -> Result<()> {
    let mut crates = BTreeSet::new();
    for row in files {
        if row.path.contains('/') || !row.path.ends_with(".rlib") {
            return Err(Refusal::new(
                "target library path must be one hash-named rlib",
            ));
        }
        let crate_name = ["libcore-", "liballoc-", "libcompiler_builtins-"]
            .into_iter()
            .find(|prefix| row.path.starts_with(prefix))
            .ok_or_else(|| Refusal::new("target library profile has an unexpected crate"))?;
        let hash = row
            .path
            .strip_prefix(crate_name)
            .and_then(|value| value.strip_suffix(".rlib"))
            .ok_or_else(|| Refusal::new("target library filename is invalid"))?;
        if hash.is_empty()
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !crates.insert(crate_name)
        {
            return Err(Refusal::new(
                "target library hash name is invalid or duplicated",
            ));
        }
    }
    if crates.len() != 3 {
        return Err(Refusal::new(
            "target library profile must contain core, alloc, and compiler_builtins",
        ));
    }
    Ok(())
}

fn verify_source_file(
    root: &Directory,
    expected: &FileIdentity,
    limits: ComponentInstallLimits,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (parent_path, leaf) = split_inventory_path(&expected.path)?;
    let parent = root.relative_directory(parent_path)?;
    let mut input = parent.regular(OsStr::new(leaf))?;
    let before = input.metadata()?;
    if !before.file_type().is_file()
        || before.len() != expected.bytes
        || expected
            .mode
            .is_some_and(|mode| before.permissions().mode() & 0o7777 != mode)
    {
        return Err(Refusal::new(
            "native prefix source file metadata differs from its inventory",
        ));
    }
    let bound = expected
        .bytes
        .checked_add(1)
        .ok_or_else(|| Refusal::new("native prefix source file size cannot be bounded"))?;
    let mut total = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        cancellation_check()?;
        let amount = usize::try_from((bound - total).min(buffer.len() as u64))
            .map_err(|_| Refusal::new("native prefix read bound is not representable"))?;
        match input.read(&mut buffer[..amount]) {
            Ok(0) => break,
            Ok(count) => {
                total = total
                    .checked_add(count as u64)
                    .ok_or_else(|| Refusal::new("native prefix source byte count overflow"))?;
                if total > expected.bytes {
                    return Err(Refusal::new(
                        "native prefix source file grew beyond its inventory",
                    ));
                }
                digest.update(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read native prefix input: {error}"
                )));
            }
        }
    }
    if total != expected.bytes || encode_hex(&digest.finalize().into()) != expected.sha256 {
        return Err(Refusal::new(
            "native prefix source bytes differ from inventory",
        ));
    }
    let after = input.metadata()?;
    if !same_file_state(&before, &after) {
        return Err(Refusal::new(
            "native prefix source changed during preflight",
        ));
    }
    if total > limits.max_file_bytes {
        return Err(Refusal::new(
            "native prefix source file exceeds its size bound",
        ));
    }
    Ok(())
}

fn copy_file(
    source: &Directory,
    source_path: &str,
    destination_parent: &Directory,
    output: &FileIdentity,
    limits: ComponentInstallLimits,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (source_parent_path, source_leaf) = split_inventory_path(source_path)?;
    let source_parent = source.relative_directory(source_parent_path)?;
    let mut input = source_parent.regular(OsStr::new(source_leaf))?;
    let before = input.metadata()?;
    if !before.file_type().is_file()
        || before.len() != output.bytes
        || output
            .mode
            .is_some_and(|mode| before.permissions().mode() & 0o7777 != mode)
    {
        return Err(Refusal::new(
            "native prefix source file changed after preflight",
        ));
    }
    let mut destination = destination_parent.create_new_file(
        OsStr::new(
            output
                .path
                .rsplit('/')
                .next()
                .ok_or_else(|| Refusal::new("invalid output path"))?,
        ),
        0o600,
    )?;
    let bound = output
        .bytes
        .checked_add(1)
        .ok_or_else(|| Refusal::new("native prefix file size cannot be bounded"))?;
    let mut total = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        cancellation_check()?;
        let amount = usize::try_from((bound - total).min(buffer.len() as u64))
            .map_err(|_| Refusal::new("native prefix copy bound is not representable"))?;
        match input.read(&mut buffer[..amount]) {
            Ok(0) => break,
            Ok(count) => {
                total = total
                    .checked_add(count as u64)
                    .ok_or_else(|| Refusal::new("native prefix copied byte count overflow"))?;
                if total > output.bytes {
                    return Err(Refusal::new("native prefix source grew during copy"));
                }
                digest.update(&buffer[..count]);
                destination.write_all(&buffer[..count])?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not copy native prefix input: {error}"
                )));
            }
        }
    }
    if total != output.bytes || encode_hex(&digest.finalize().into()) != output.sha256 {
        return Err(Refusal::new(
            "native prefix copied bytes differ from inventory",
        ));
    }
    destination.flush()?;
    destination.set_permissions(Permissions::from_mode(before.permissions().mode() & 0o7777))?;
    if !same_file_state(&before, &input.metadata()?) {
        return Err(Refusal::new("native prefix source changed while copying"));
    }
    if total > limits.max_file_bytes {
        return Err(Refusal::new("native prefix copy exceeds file size bound"));
    }
    Ok(())
}

fn same_file_state(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn build_stage(
    stage: &Directory,
    inputs: &OpenInputs,
    plan: &PrefixPlan,
    limits: ComponentInstallLimits,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<Measurement> {
    let directories = create_output_directories(stage, &plan.directories, cancellation_check)?;
    for file in &plan.files {
        cancellation_check()?;
        let (parent_path, _) = split_inventory_path(&file.output.path)?;
        let parent = if parent_path.is_empty() {
            stage
        } else {
            directories
                .get(parent_path)
                .ok_or_else(|| Refusal::new("native prefix output parent was not created"))?
        };
        copy_file(
            &inputs.roots[file.source_root],
            &file.source_path,
            parent,
            &file.output,
            limits,
            cancellation_check,
        )?;
    }
    for link in &plan.symlinks {
        cancellation_check()?;
        let (parent_path, leaf) = split_inventory_path(&link.output.path)?;
        let parent = if parent_path.is_empty() {
            stage
        } else {
            directories
                .get(parent_path)
                .ok_or_else(|| Refusal::new("native prefix symlink parent was not created"))?
        };
        if let Some(source_root) = link.source_root {
            let source = &inputs.roots[source_root];
            let (source_parent_path, source_leaf) = split_inventory_path(&link.source_path)?;
            let source_parent = source.relative_directory(source_parent_path)?;
            let actual =
                source_parent.link_target(OsStr::new(source_leaf), limits.max_link_target_bytes)?;
            if actual.as_bytes() != link.output.target.as_bytes() {
                return Err(Refusal::new(
                    "native prefix source symlink changed after preflight",
                ));
            }
        }
        create_symlink(parent, leaf, &link.output.target)?;
    }
    let measurement = verify_complete_directory_checked(
        stage,
        &plan.output_files,
        &plan.output_symlinks,
        InventoryLimits {
            max_tree_entries: limits.max_tree_entries,
            max_link_resolution_steps: limits.max_link_resolution_steps,
        },
        &mut *cancellation_check,
    )?;
    stage.set_mode_exact(0o755 as libc::mode_t)?;
    cancellation_check()?;
    Ok(measurement)
}

fn create_output_directories(
    stage: &Directory,
    directories: &BTreeSet<String>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<BTreeMap<String, Directory>> {
    let mut paths = directories.iter().collect::<Vec<_>>();
    paths.sort_by(|left, right| {
        left.matches('/')
            .count()
            .cmp(&right.matches('/').count())
            .then_with(|| left.cmp(right))
    });
    let mut output = BTreeMap::new();
    for path in paths {
        cancellation_check()?;
        let (parent_path, leaf) = split_inventory_path(path)?;
        let parent = if parent_path.is_empty() {
            stage
        } else {
            output
                .get(parent_path)
                .ok_or_else(|| Refusal::new("native prefix directory parent was not created"))?
        };
        output.insert(path.clone(), parent.mkdir_new(OsStr::new(leaf), 0o755)?);
    }
    Ok(output)
}

fn validate_output_inventory(
    files: &[FileIdentity],
    symlinks: &[LinkIdentity],
    limits: ComponentInstallLimits,
) -> Result<(BTreeSet<String>, usize, u64)> {
    let mut leaves = BTreeSet::new();
    let mut folded = BTreeMap::<String, String>::new();
    let mut expanded_bytes = 0_u64;
    for file in files {
        validate_input_path(&file.path, limits)?;
        if !is_sha256_digest(&file.sha256) || file.bytes > limits.max_file_bytes {
            return Err(Refusal::new(
                "native prefix output file identity is invalid",
            ));
        }
        record_case_path(&file.path, &mut folded)?;
        if !leaves.insert(file.path.as_str()) {
            return Err(Refusal::new(
                "native prefix output contains duplicate paths",
            ));
        }
        expanded_bytes = expanded_bytes
            .checked_add(file.bytes)
            .ok_or_else(|| Refusal::new("native prefix output byte count overflow"))?;
    }
    for link in symlinks {
        validate_input_path(&link.path, limits)?;
        validate_link_target(&link.target, limits.max_link_target_bytes)?;
        record_case_path(&link.path, &mut folded)?;
        if !leaves.insert(link.path.as_str()) {
            return Err(Refusal::new(
                "native prefix output has conflicting file/link paths",
            ));
        }
    }
    let mut directories = BTreeSet::new();
    for path in &leaves {
        let mut prefix = String::new();
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if components.peek().is_some() {
                if leaves.contains(prefix.as_str()) {
                    return Err(Refusal::new(
                        "native prefix output leaf is a directory ancestor",
                    ));
                }
                directories.insert(prefix.clone());
            }
        }
    }
    let tree_entries = leaves
        .len()
        .checked_add(directories.len())
        .ok_or_else(|| Refusal::new("native prefix output tree entry count overflow"))?;
    if tree_entries > limits.max_tree_entries || expanded_bytes > limits.max_expanded_bytes {
        return Err(Refusal::new(
            "native prefix output exceeds tree or expanded-byte bound",
        ));
    }
    Ok((directories, tree_entries, expanded_bytes))
}

fn record_case_path(path: &str, folded: &mut BTreeMap<String, String>) -> Result<()> {
    let mut prefix = String::new();
    for component in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        let key = prefix.to_lowercase();
        if folded.get(&key).is_some_and(|previous| previous != &prefix) {
            return Err(Refusal::new("native prefix contains case-colliding paths"));
        }
        folded.entry(key).or_insert_with(|| prefix.clone());
    }
    Ok(())
}

fn join_inventory_prefix(prefix: &str, path: &str) -> Result<String> {
    validate_relative_inventory_path(path)?;
    if prefix.is_empty() {
        Ok(path.to_owned())
    } else {
        Ok(format!("{prefix}/{path}"))
    }
}

fn split_inventory_path(path: &str) -> Result<(&str, &str)> {
    validate_relative_inventory_path(path)?;
    Ok(path.rsplit_once('/').unwrap_or(("", path)))
}

fn failure(reason: Refusal) -> NativePrefixFailure {
    NativePrefixFailure {
        reason,
        recovery_entry: None,
    }
}

fn cleanup_failure(
    parent: &Directory,
    stage_name: &OsStr,
    maximum_entries: usize,
    reason: Refusal,
) -> NativePrefixFailure {
    match parent.remove_tree(stage_name, maximum_entries) {
        Ok(()) => NativePrefixFailure {
            reason,
            recovery_entry: None,
        },
        Err(cleanup) => NativePrefixFailure {
            reason: Refusal::new(format!(
                "{reason}; incomplete native prefix stage remains at {} because cleanup failed: {cleanup}",
                stage_name.to_string_lossy()
            )),
            recovery_entry: Some(stage_name.to_os_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{digest::sha256_bytes, inventory::verify_complete};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        rust: OwnedProfile,
        cargo: OwnedProfile,
        llvm: OwnedProfile,
        csdk: OwnedProfile,
        collector: OwnedProfile,
        target_libraries: OwnedProfile,
        target_spec_root: PathBuf,
        target_spec: FileIdentity,
        linker_root: PathBuf,
        aros_link: FileIdentity,
    }

    struct OwnedProfile {
        root: PathBuf,
        files: Vec<FileIdentity>,
        symlinks: Vec<LinkIdentity>,
    }

    impl OwnedProfile {
        fn borrowed(&self) -> NativePrefixProfile<'_> {
            NativePrefixProfile {
                root: &self.root,
                files: &self.files,
                symlinks: &self.symlinks,
            }
        }
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::current_dir().unwrap().join(format!(
                ".ami-native-prefix-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let rust = profile(
                &root.join("rust-source"),
                &[
                    ("bin/rustc", b"rustc"),
                    ("bin/rustdoc", b"rustdoc"),
                    ("bin/cargo", b"official cargo"),
                    ("lib/rustlib/components", b"rust components"),
                    ("lib/rustlib/rust-installer-version", b"version"),
                    ("lib/rustlib/uninstall.sh", b"installer"),
                ],
                &[
                    ("lib/rustlib/x86_64-aros/target.json", "x86_64-aros.json"),
                    (
                        "lib/rustlib/x86_64-unknown-linux-gnu/bin/aros-link",
                        "../../../../bin/aros-link",
                    ),
                ],
            );
            let cargo = profile(
                &root.join("cargo-source"),
                &[
                    ("bin/cargo", b"paired cargo"),
                    ("producer.json", b"paired Cargo provenance"),
                ],
                &[],
            );
            let llvm = profile(
                &root.join("llvm-source"),
                &[
                    ("bin/clang", b"clang"),
                    ("bin/llvm-objdump", b"objdump"),
                    ("bin/llvm-nm", b"nm"),
                    ("bin/llvm-ar", b"ar"),
                    ("bin/llvm-strip", b"strip"),
                    ("bin/ld.lld", b"lld"),
                ],
                &[],
            );
            let csdk = profile(
                &root.join("csdk-source"),
                &[("include/stdio.h", b"header")],
                &[],
            );
            let collector = profile(
                &root.join("collector-source"),
                &[
                    ("LICENSE", b"collector license"),
                    ("README.md", b"collector readme"),
                    ("bin/aros", b"aros"),
                    ("bin/aros-ahi-runner", b"ahi runner"),
                    ("bin/aros-collect", b"collector"),
                    ("bin/aros-fetch", b"fetch"),
                    ("bin/aros-genmodule", b"genmodule"),
                    ("bin/aros-romtool", b"romtool"),
                    ("bin/aros-transpiler", b"transpiler"),
                    ("bin/aros-verify", b"verify"),
                ],
                &[],
            );
            let target_libraries = profile(
                &root.join("target-libraries-source"),
                &[
                    ("libcore-1234567890abcdef.rlib", b"core"),
                    ("liballoc-2234567890abcdef.rlib", b"alloc"),
                    ("libcompiler_builtins-3234567890abcdef.rlib", b"builtins"),
                ],
                &[],
            );
            let target_spec_root = root.join("target-spec-source");
            fs::create_dir(&target_spec_root).unwrap();
            let target_spec = write_identity(&target_spec_root, "spec.json", b"target spec");
            let linker_root = root.join("linker-source");
            fs::create_dir(&linker_root).unwrap();
            let aros_link = write_identity(&linker_root, "aros-link", b"native linker");
            Self {
                root,
                rust,
                cargo,
                llvm,
                csdk,
                collector,
                target_libraries,
                target_spec_root,
                target_spec,
                linker_root,
                aros_link,
            }
        }

        fn spec<'a>(&'a self, destination: &'a Path) -> NativePrefixSpec<'a> {
            NativePrefixSpec {
                destination,
                host_key: "linux-x86_64",
                rust_host_triple: "x86_64-unknown-linux-gnu",
                rust: self.rust.borrowed(),
                cargo: self.cargo.borrowed(),
                llvm: self.llvm.borrowed(),
                csdk: self.csdk.borrowed(),
                collector: self.collector.borrowed(),
                target_libraries: self.target_libraries.borrowed(),
                target_spec: NativePrefixFile {
                    root: &self.target_spec_root,
                    identity: &self.target_spec,
                },
                aros_link: NativePrefixFile {
                    root: &self.linker_root,
                    identity: &self.aros_link,
                },
                limits: ComponentInstallLimits {
                    max_tree_entries: 4096,
                    max_path_bytes: 4096,
                    max_path_components: 32,
                    max_file_bytes: 1024 * 1024,
                    max_expanded_bytes: 4 * 1024 * 1024,
                    current_workspace_bytes: 0,
                    max_workspace_bytes: 8 * 1024 * 1024,
                    max_link_target_bytes: 1024,
                    max_link_resolution_steps: 64,
                },
            }
        }
    }

    fn configure_macos_runtime_alias(fixture: &mut Fixture) {
        let linux_linker_alias =
            format!("lib/rustlib/x86_64-unknown-linux-gnu{RUST_HOST_LINKER_ALIAS_SUFFIX}");
        fs::remove_file(fixture.rust.root.join(&linux_linker_alias)).unwrap();
        fixture
            .rust
            .symlinks
            .retain(|link| link.path != linux_linker_alias);

        fixture.rust.symlinks.push(LinkIdentity {
            path: format!(
                "lib/rustlib/{MACOS_AARCH64_RUST_HOST_TRIPLE}{RUST_HOST_LINKER_ALIAS_SUFFIX}"
            ),
            target: RUST_HOST_LINKER_ALIAS_TARGET.to_owned(),
        });
        fixture.rust.symlinks.push(LinkIdentity {
            path: format!(
                "lib/rustlib/{MACOS_AARCH64_RUST_HOST_TRIPLE}{RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX}"
            ),
            target: RUST_HOST_LLVM_RUNTIME_ALIAS_TARGET.to_owned(),
        });
        fixture.rust.files.push(write_identity(
            &fixture.rust.root,
            "lib/libLLVM.dylib",
            b"Mac LLVM runtime",
        ));
    }

    fn macos_spec<'a>(fixture: &'a Fixture, destination: &'a Path) -> NativePrefixSpec<'a> {
        let mut spec = fixture.spec(destination);
        spec.host_key = "macos-aarch64";
        spec.rust_host_triple = MACOS_AARCH64_RUST_HOST_TRIPLE;
        spec
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn profile(root: &Path, files: &[(&str, &[u8])], links: &[(&str, &str)]) -> OwnedProfile {
        fs::create_dir_all(root).unwrap();
        let identities = files
            .iter()
            .map(|(path, bytes)| write_identity(root, path, bytes))
            .collect();
        let link_rows = links
            .iter()
            .map(|(path, target)| {
                let destination = root.join(path);
                fs::create_dir_all(destination.parent().unwrap()).unwrap();
                symlink(target, destination).unwrap();
                LinkIdentity {
                    path: (*path).to_owned(),
                    target: (*target).to_owned(),
                }
            })
            .collect();
        OwnedProfile {
            root: root.to_path_buf(),
            files: identities,
            symlinks: link_rows,
        }
    }

    fn write_identity(root: &Path, path: &str, bytes: &[u8]) -> FileIdentity {
        let destination = root.join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, bytes).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
        FileIdentity {
            path: path.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(bytes),
            mode: Some(0o755),
        }
    }

    fn assert_no_stage(parent: &Path) {
        let names = fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(
            !names
                .iter()
                .any(|name| name.to_string_lossy().starts_with(".ami-rust-profile-"))
        );
    }

    #[test]
    fn accepts_only_the_three_declared_host_triple_pairs() {
        for (host, triple) in [
            ("macos-aarch64", "aarch64-apple-darwin"),
            ("linux-x86_64", "x86_64-unknown-linux-gnu"),
            ("linux-aarch64", "aarch64-unknown-linux-gnu"),
        ] {
            assert!(validate_host_identity(host, triple).is_ok());
        }
        assert!(validate_host_identity("linux-arm", "aarch64-unknown-linux-gnu").is_err());
        assert!(validate_host_identity("linux-aarch64", "x86_64-unknown-linux-gnu").is_err());
    }

    #[test]
    fn assembles_fixed_prefix_and_preserves_full_authenticated_source_profiles() {
        let fixture = Fixture::new();
        let parent = fixture.root.join("output parent with spaces");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("native prefix");
        let receipt = assemble_native_prefix(fixture.spec(&destination), || Ok(())).unwrap();
        assert_eq!(
            fs::read(destination.join("bin/cargo")).unwrap(),
            b"paired cargo"
        );
        assert_eq!(
            receipt.replaced_official_cargo.sha256,
            fixture
                .rust
                .files
                .iter()
                .find(|row| row.path == "bin/cargo")
                .unwrap()
                .sha256
        );
        assert!(
            receipt
                .unmapped_cargo_rows
                .iter()
                .any(|row| row.path == "producer.json")
        );
        assert_eq!(receipt.unmapped_collector_rows.len(), 9);
        for path in [
            "lib/rustlib/components",
            "lib/rustlib/rust-installer-version",
            "lib/rustlib/uninstall.sh",
        ] {
            assert!(receipt.files.iter().any(|row| row.path == path));
            assert!(destination.join(path).is_file());
        }
        assert!(!destination.join("producer.json").exists());
        assert!(!destination.join("bin/aros").exists());
        assert!(!destination.join("LICENSE").exists());
        assert_eq!(
            fs::read_link(destination.join(TARGET_ALIAS_PATH)).unwrap(),
            Path::new(TARGET_ALIAS)
        );
        assert_eq!(
            fs::read_link(destination.join("bin/llvm-ar")).unwrap(),
            Path::new("../libexec/aros/llvm/bin/llvm-ar")
        );
        verify_complete(
            &destination,
            &receipt.files,
            &receipt.symlinks,
            InventoryLimits {
                max_tree_entries: 4096,
                max_link_resolution_steps: 64,
            },
        )
        .unwrap();
    }

    #[test]
    fn generates_required_rust_aliases_when_pristine_component_omits_them() {
        let fixture = Fixture::new();
        let target_alias = fixture.rust.root.join(TARGET_ALIAS_PATH);
        fs::remove_file(&target_alias).unwrap();
        fs::remove_dir(target_alias.parent().unwrap()).unwrap();
        let linker_alias = fixture.rust.root.join(format!(
            "lib/rustlib/x86_64-unknown-linux-gnu{RUST_HOST_LINKER_ALIAS_SUFFIX}"
        ));
        fs::remove_file(&linker_alias).unwrap();

        let parent = fixture.root.join("generated aliases output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        let receipt = assemble_native_prefix(fixture.spec(&destination), || Ok(())).unwrap();

        let linker_path =
            format!("lib/rustlib/x86_64-unknown-linux-gnu{RUST_HOST_LINKER_ALIAS_SUFFIX}");
        assert!(
            receipt
                .symlinks
                .iter()
                .any(|link| { link.path == TARGET_ALIAS_PATH && link.target == TARGET_ALIAS })
        );
        assert!(receipt.symlinks.iter().any(|link| {
            link.path == linker_path && link.target == RUST_HOST_LINKER_ALIAS_TARGET
        }));
        assert_eq!(
            fs::read_link(destination.join(TARGET_ALIAS_PATH)).unwrap(),
            Path::new(TARGET_ALIAS)
        );
        assert_eq!(
            fs::read_link(destination.join(linker_path)).unwrap(),
            Path::new(RUST_HOST_LINKER_ALIAS_TARGET)
        );
        verify_complete(
            &destination,
            &receipt.files,
            &receipt.symlinks,
            InventoryLimits {
                max_tree_entries: 4096,
                max_link_resolution_steps: 64,
            },
        )
        .unwrap();
    }

    #[test]
    fn generates_exact_macos_llvm_runtime_alias_without_a_source_link() {
        let mut fixture = Fixture::new();
        configure_macos_runtime_alias(&mut fixture);
        let alias_path = format!(
            "lib/rustlib/{MACOS_AARCH64_RUST_HOST_TRIPLE}{RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX}"
        );
        assert!(!fixture.rust.root.join(&alias_path).exists());

        let parent = fixture.root.join("Mac runtime alias output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        let receipt =
            assemble_native_prefix(macos_spec(&fixture, &destination), || Ok(())).unwrap();

        assert!(receipt.symlinks.iter().any(|link| {
            link.path == alias_path && link.target == RUST_HOST_LLVM_RUNTIME_ALIAS_TARGET
        }));
        assert_eq!(
            fs::read_link(destination.join(alias_path)).unwrap(),
            Path::new(RUST_HOST_LLVM_RUNTIME_ALIAS_TARGET)
        );
        assert_eq!(
            fs::read(destination.join("lib/libLLVM.dylib")).unwrap(),
            b"Mac LLVM runtime"
        );
        verify_complete(
            &destination,
            &receipt.files,
            &receipt.symlinks,
            InventoryLimits {
                max_tree_entries: 4096,
                max_link_resolution_steps: 64,
            },
        )
        .unwrap();
    }

    #[test]
    fn refuses_wrong_macos_llvm_runtime_alias_target_before_opening_source_link() {
        let mut fixture = Fixture::new();
        configure_macos_runtime_alias(&mut fixture);
        let alias_path = format!(
            "lib/rustlib/{MACOS_AARCH64_RUST_HOST_TRIPLE}{RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX}"
        );
        fixture
            .rust
            .symlinks
            .iter_mut()
            .find(|link| link.path == alias_path)
            .unwrap()
            .target = "../../../other.dylib".to_owned();

        let parent = fixture.root.join("wrong Mac runtime alias output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        let error =
            assemble_native_prefix(macos_spec(&fixture, &destination), || Ok(())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Rust profile macOS LLVM runtime alias does not match the selected host")
        );
        assert!(!destination.exists());
        assert_no_stage(&parent);
    }

    #[test]
    fn refuses_conflicting_macos_llvm_runtime_alias_file_and_link_rows() {
        let mut fixture = Fixture::new();
        configure_macos_runtime_alias(&mut fixture);
        let alias_path = format!(
            "lib/rustlib/{MACOS_AARCH64_RUST_HOST_TRIPLE}{RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX}"
        );
        fixture.rust.files.push(FileIdentity {
            path: alias_path,
            bytes: 8,
            sha256: sha256_bytes(b"conflict"),
            mode: Some(0o755),
        });

        let parent = fixture.root.join("conflicting Mac runtime alias output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        let error =
            assemble_native_prefix(macos_spec(&fixture, &destination), || Ok(())).unwrap_err();
        assert!(error.to_string().contains("duplicate paths"));
        assert!(!destination.exists());
        assert_no_stage(&parent);
    }

    #[test]
    fn refuses_macos_llvm_runtime_alias_for_an_unsupported_host() {
        let mut fixture = Fixture::new();
        fixture.rust.symlinks.push(LinkIdentity {
            path: format!(
                "lib/rustlib/x86_64-unknown-linux-gnu{RUST_HOST_LLVM_RUNTIME_ALIAS_SUFFIX}"
            ),
            target: RUST_HOST_LLVM_RUNTIME_ALIAS_TARGET.to_owned(),
        });

        let parent = fixture.root.join("unsupported runtime alias output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        let error = assemble_native_prefix(fixture.spec(&destination), || Ok(())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Rust profile contains an unsupported LLVM runtime alias")
        );
        assert!(!destination.exists());
        assert_no_stage(&parent);
    }

    #[test]
    fn refuses_wrong_generated_rust_alias_targets_before_opening_input_links() {
        for (target_path, wrong_target, expected_message, remove_parent) in [
            (
                TARGET_ALIAS_PATH,
                "wrong-target.json",
                "Rust profile lacks the required relative target.json alias",
                true,
            ),
            (
                "lib/rustlib/x86_64-unknown-linux-gnu/bin/aros-link",
                "../../wrong/aros-link",
                "Rust profile host aros-link alias does not match the selected host",
                false,
            ),
        ] {
            let mut fixture = Fixture::new();
            let source_alias = fixture.rust.root.join(target_path);
            fs::remove_file(&source_alias).unwrap();
            if remove_parent {
                fs::remove_dir(source_alias.parent().unwrap()).unwrap();
            }
            fixture
                .rust
                .symlinks
                .iter_mut()
                .find(|link| link.path == target_path)
                .unwrap()
                .target = wrong_target.to_owned();

            let parent = fixture.root.join("wrong alias output");
            fs::create_dir(&parent).unwrap();
            let destination = parent.join("prefix");
            let error = assemble_native_prefix(fixture.spec(&destination), || Ok(())).unwrap_err();
            assert!(error.to_string().contains(expected_message));
            assert!(!destination.exists());
            assert_no_stage(&parent);
        }
    }

    #[test]
    fn refuses_corrupt_or_missing_input_without_publishing() {
        for missing in [false, true] {
            let mut fixture = Fixture::new();
            let parent = fixture.root.join("output");
            fs::create_dir(&parent).unwrap();
            let destination = parent.join("prefix");
            if missing {
                fs::remove_file(fixture.csdk.root.join("include/stdio.h")).unwrap();
            } else {
                let row = &mut fixture.csdk.files[0];
                row.sha256 = sha256_bytes(b"wrong bytes");
            }
            assert!(assemble_native_prefix(fixture.spec(&destination), || Ok(())).is_err());
            assert!(!destination.exists());
            assert_no_stage(&parent);
        }
    }

    #[test]
    fn accepts_output_parent_with_more_entries_than_composed_tree_limit() {
        let fixture = Fixture::new();
        let parent = fixture.root.join("output");
        fs::create_dir(&parent).unwrap();
        for index in 0..65 {
            fs::write(parent.join(format!("unrelated-{index}")), b"unrelated").unwrap();
        }
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 65);

        let destination = parent.join("prefix");
        let mut spec = fixture.spec(&destination);
        spec.limits.max_tree_entries = 64;
        let receipt = assemble_native_prefix(spec, || Ok(())).unwrap();
        assert_eq!(receipt.destination, destination);
        assert!(destination.is_dir());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 66);
    }

    #[test]
    fn refuses_corrupt_unmapped_cargo_or_collector_rows_without_publishing() {
        for cargo_row in [true, false] {
            let mut fixture = Fixture::new();
            let parent = fixture.root.join("output");
            fs::create_dir(&parent).unwrap();
            let destination = parent.join("prefix");
            let profile = if cargo_row {
                &mut fixture.cargo
            } else {
                &mut fixture.collector
            };
            let selected = if cargo_row {
                CARGO_PATH
            } else {
                COLLECTOR_SOURCE_PATH
            };
            let row = profile
                .files
                .iter_mut()
                .find(|row| row.path != selected)
                .unwrap();
            row.sha256 = sha256_bytes(b"altered unselected inventory row");
            assert!(assemble_native_prefix(fixture.spec(&destination), || Ok(())).is_err());
            assert!(!destination.exists());
            assert_no_stage(&parent);
        }
    }

    #[test]
    fn refuses_path_traversal_and_component_collision_before_stage_creation() {
        let mut fixture = Fixture::new();
        let parent = fixture.root.join("output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        fixture.csdk.files[0].path = "../escape".to_owned();
        assert!(assemble_native_prefix(fixture.spec(&destination), || Ok(())).is_err());
        assert_no_stage(&parent);

        let mut fixture = Fixture::new();
        let parent = fixture.root.join("output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        fixture.target_libraries.files[0].path = "libcore-bad.rlib".to_owned();
        assert!(assemble_native_prefix(fixture.spec(&destination), || Ok(())).is_err());
        assert_no_stage(&parent);

        let mut fixture = Fixture::new();
        let parent = fixture.root.join("output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        let collision = write_identity(&fixture.rust.root, "bin/collect-aros", b"collision");
        fixture.rust.files.push(collision);
        assert!(assemble_native_prefix(fixture.spec(&destination), || Ok(())).is_err());
        assert!(!destination.exists());
        assert_no_stage(&parent);
    }

    #[test]
    fn refuses_escaping_symlink_before_publish() {
        let mut fixture = Fixture::new();
        let outside = fixture.root.join("outside");
        fs::write(&outside, b"outside").unwrap();
        let link_path = fixture.csdk.root.join("include/escape");
        symlink("../../../../outside", &link_path).unwrap();
        fixture.csdk.symlinks.push(LinkIdentity {
            path: "include/escape".to_owned(),
            target: "../../../../outside".to_owned(),
        });
        let parent = fixture.root.join("output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        assert!(assemble_native_prefix(fixture.spec(&destination), || Ok(())).is_err());
        assert!(!destination.exists());
        assert_no_stage(&parent);
    }

    #[test]
    fn refuses_source_overlap_and_preserves_preexisting_destination() {
        let mut fixture = Fixture::new();
        let nested_destination = fixture.rust.root.join("composed");
        assert!(assemble_native_prefix(fixture.spec(&nested_destination), || Ok(())).is_err());

        let parent = fixture.root.join("output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        fs::write(&destination, b"preserve").unwrap();
        fixture.csdk.files[0].sha256 = sha256_bytes(b"wrong bytes");
        let error = assemble_native_prefix(fixture.spec(&destination), || Ok(())).unwrap_err();
        assert_eq!(
            error.to_string(),
            "native prefix destination already exists"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"preserve");
        assert_no_stage(&parent);
    }

    #[test]
    fn cancellation_after_stage_creation_cleans_owned_tree() {
        let fixture = Fixture::new();
        let parent = fixture.root.join("output");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("prefix");
        let saw_stage_file = std::cell::Cell::new(false);
        let result = assemble_native_prefix(fixture.spec(&destination), || {
            if saw_stage_file.get() {
                return Err(Refusal::new("fixture cancellation"));
            }
            for entry in fs::read_dir(&parent).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                if name.to_string_lossy().starts_with(".ami-rust-profile-")
                    && entry.path().is_dir()
                    && fs::read_dir(entry.path()).unwrap().next().is_some()
                {
                    saw_stage_file.set(true);
                }
            }
            Ok(())
        });
        assert!(saw_stage_file.get());
        assert!(result.is_err());
        assert!(!destination.exists());
        assert_no_stage(&parent);
    }
}

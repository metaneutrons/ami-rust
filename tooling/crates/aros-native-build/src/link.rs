//! Execute the fixed collector/strip stages for a Cargo-native link.
//!
//! The linker argument parser only extracts owned arguments. This module
//! verifies the associated object record and pinned toolchain, then publishes
//! an audited output atomically after the fixed recipe succeeds.

use super::link_args::parse;
use crate::{
    Refusal, Result,
    build::{load_native_objects, run_recipe, verify_native_objects},
    inputs::Toolchain,
    recipe::{NativeBuildRecipe, NativeRecipePaths},
};
use std::{
    ffi::OsString,
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Run the fixed native linker recipe and atomically publish its audited ELF.
pub fn link(arguments: &[OsString]) -> Result<()> {
    let parsed = parse(arguments)?;
    let (toolchain, objects) = load_native_objects(&parsed.native_objects)?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let executable_root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Refusal::new("target linker has no toolchain prefix"))?;
    if executable_root != toolchain.root() {
        return Err(Refusal::new(
            "native object record belongs to a different selected linker prefix; rebuild its Cargo build script",
        ));
    }
    verify_native_objects(&parsed.native_objects, &objects)?;
    check_object_toolchain(
        &toolchain,
        &objects.toolchain_root,
        &objects.toolchain_identity,
    )?;
    toolchain.recheck()?;

    let output_parent = parsed
        .output
        .parent()
        .ok_or_else(|| Refusal::new("Cargo linker output has no parent directory"))?;
    let output_name = parsed
        .output
        .file_name()
        .ok_or_else(|| Refusal::new("Cargo linker output has no file name"))?;
    let output_label = parsed
        .output
        .to_str()
        .ok_or_else(|| Refusal::new("Cargo linker output path is not valid UTF-8"))?;
    let output_parent = fs::canonicalize(output_parent)
        .map_err(|error| Refusal::new(format!("cannot resolve Cargo output parent: {error}")))?;
    if !fs::metadata(&output_parent)
        .map_err(|error| Refusal::new(format!("cannot inspect Cargo output parent: {error}")))?
        .is_dir()
    {
        return Err(Refusal::new(
            "Cargo linker output parent is not a directory",
        ));
    }
    let output = output_parent.join(output_name);
    check_output_slot(&output)?;

    let native_objects_root = fs::canonicalize(&parsed.native_objects).map_err(|error| {
        Refusal::new(format!("cannot resolve native-object directory: {error}"))
    })?;
    if output.starts_with(&native_objects_root) || output.starts_with(toolchain.root()) {
        return Err(Refusal::new(
            "Cargo linker output overlaps verified native inputs",
        ));
    }
    let mut staging = StagingDirectory::create(&output_parent)?;
    let raw = staging.path.join("linked.raw");
    let map = staging.path.join("linked.map");
    let stripped = staging.path.join("linked.stripped");

    let recipe = NativeBuildRecipe {
        paths: NativeRecipePaths {
            source_root: parsed.native_objects.join("source"),
            toolchain_root: toolchain.toolchain_root().to_path_buf(),
            sdk_root: toolchain.sdk_root().to_path_buf(),
            collector: toolchain.collector().to_path_buf(),
        },
        testing: objects.testing,
    };

    let collector = recipe.collector_spec_for_cargo(
        &parsed.native_objects,
        &parsed.rust_arguments,
        &raw,
        &map,
    )?;
    run_recipe(&collector, toolchain.source_date_epoch())?;
    require_regular_file(&raw, "collector output")?;

    let strip = recipe.strip_spec_for_paths(&raw, &stripped)?;
    run_recipe(&strip, toolchain.source_date_epoch())?;
    require_regular_file(&stripped, "stripped linker output")?;

    let stripped_bytes = fs::read(&stripped)
        .map_err(|error| Refusal::new(format!("cannot read stripped linker output: {error}")))?;
    let compacted = aros_elf::compact::compact_elf_sections_with_report(&stripped_bytes)
        .map_err(|error| Refusal::new(error.to_string()))?;
    aros_elf::elf::audit(&compacted.bytes, "core", output_label)
        .map_err(|error| Refusal::new(error.to_string()))?;

    let mut output_temp = OutputTemp::write(&output_parent, &compacted.bytes)?;

    // The output file is not touched until the private workspace is removed
    // and every immutable input is checked again.
    staging.cleanup()?;
    verify_native_objects(&parsed.native_objects, &objects)?;
    check_object_toolchain(
        &toolchain,
        &objects.toolchain_root,
        &objects.toolchain_identity,
    )?;
    toolchain.recheck()?;
    check_output_slot(&output)?;
    output_temp.publish(&output)?;
    Ok(())
}

fn check_object_toolchain(
    toolchain: &Toolchain,
    recorded_root: &Path,
    recorded_identity: &str,
) -> Result<()> {
    if recorded_root != toolchain.root() || recorded_identity != toolchain.identity() {
        return Err(Refusal::new(
            "native-object record belongs to a different pinned toolchain",
        ));
    }
    Ok(())
}

fn check_output_slot(output: &Path) -> Result<()> {
    match fs::symlink_metadata(output) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(Refusal::new("Cargo linker output is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Refusal::new(format!(
            "cannot inspect Cargo linker output: {error}"
        ))),
    }
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("cannot inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::new(format!("{label} is not a regular file")));
    }
    Ok(())
}

struct StagingDirectory {
    path: PathBuf,
    active: bool,
}

impl StagingDirectory {
    fn create(parent: &Path) -> Result<Self> {
        loop {
            let path = parent.join(format!(
                ".aros-native-link-{}-{}",
                std::process::id(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => {
                    let staging = Self { path, active: true };
                    fs::set_permissions(&staging.path, fs::Permissions::from_mode(0o700)).map_err(
                        |error| {
                            Refusal::new(format!("cannot secure linker staging directory: {error}"))
                        },
                    )?;
                    return Ok(staging);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Refusal::new(format!(
                        "cannot create linker staging directory: {error}"
                    )));
                }
            }
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.active {
            fs::remove_dir_all(&self.path)
                .map_err(|error| Refusal::new(format!("cannot clean linker staging: {error}")))?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct OutputTemp {
    path: PathBuf,
    active: bool,
}

impl OutputTemp {
    fn write(parent: &Path, bytes: &[u8]) -> Result<Self> {
        loop {
            let path = parent.join(format!(
                ".aros-native-link-{}-{}.tmp",
                std::process::id(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o755);
            match options.open(&path) {
                Ok(mut file) => {
                    let temp = Self { path, active: true };
                    file.set_permissions(fs::Permissions::from_mode(0o755))
                        .map_err(|error| {
                            Refusal::new(format!("cannot set linker output mode: {error}"))
                        })?;
                    file.write_all(bytes).map_err(|error| {
                        Refusal::new(format!("cannot write compacted linker output: {error}"))
                    })?;
                    file.sync_all().map_err(|error| {
                        Refusal::new(format!("cannot sync compacted linker output: {error}"))
                    })?;
                    drop(file);
                    return Ok(temp);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Refusal::new(format!(
                        "cannot create compacted linker output: {error}"
                    )));
                }
            }
        }
    }

    fn publish(&mut self, output: &Path) -> Result<()> {
        fs::rename(&self.path, output)
            .map_err(|error| Refusal::new(format!("cannot publish linker output: {error}")))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for OutputTemp {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

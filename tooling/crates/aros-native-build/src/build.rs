use crate::{
    Refusal, Result,
    inputs::Toolchain,
    recipe::{ArosAbi, CSourceUnit, CommandRecipe, NativeBuildRecipe, NativeRecipePaths},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};

const SCHEMA: &str = "aros-cargo-native-objects-v2";
const RECORD: &str = "native.json";
const OWNER: &str = ".ami-native-owner";
const SOURCES: &[(&str, &[u8])] = &[
    ("native/entry.c", include_bytes!("../native/entry.c")),
    ("native/sdk.c", include_bytes!("../native/sdk.c")),
    ("native/sdk.h", include_bytes!("../native/sdk.h")),
    ("native/layout.c", include_bytes!("../native/layout.c")),
    (
        "native/eh-frame-start.c",
        include_bytes!("../native/eh-frame-start.c"),
    ),
    (
        "native/compatibility-gates.h",
        include_bytes!("../native/compatibility-gates.h"),
    ),
    (
        "native/stack-probe.h",
        include_bytes!("../native/stack-probe.h"),
    ),
    (
        "native/test-controls.h",
        include_bytes!("../native/test-controls.h"),
    ),
    (
        "native/test-file-controls.h",
        include_bytes!("../native/test-file-controls.h"),
    ),
    (
        "native/test-stderr-controls.h",
        include_bytes!("../native/test-stderr-controls.h"),
    ),
    (
        "tests/measurement/ami_test_bind_diagnostics.c",
        include_bytes!("../tests/measurement/ami_test_bind_diagnostics.c"),
    ),
    (
        "scripts/measurement/m1_measurement.h",
        include_bytes!("../scripts/measurement/m1_measurement.h"),
    ),
];

/// Options for the retained qualification-only native C hooks.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuildOptions {
    pub testing: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeObjects {
    schema: String,
    pub abi: ArosAbi,
    pub toolchain_root: PathBuf,
    pub toolchain_identity: String,
    pub testing: bool,
    pub linker: FileIdentity,
    pub objects: Vec<FileIdentity>,
}

fn native_host_triple(host: &str) -> Result<&'static str> {
    match host {
        "macos-aarch64" => Ok("aarch64-apple-darwin"),
        "linux-x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "linux-aarch64" => Ok("aarch64-unknown-linux-gnu"),
        _ => Err(Refusal::new(
            "native-build host input admission is incomplete",
        )),
    }
}

/// Prepare the unchanged native bridge within Cargo's own OUT_DIR.
///
/// This function runs from the application's additive build script. It never
/// calls Cargo, resolves dependencies, downloads inputs or changes rustup state.
///
/// A refusal is also explained on standard error, with the usual remedy, so the
/// cause is readable in Cargo's build-script output.
pub fn prepare(options: BuildOptions) -> Result<()> {
    let result = prepare_checked(options);
    if let Err(refusal) = &result {
        eprintln!("aros-native-build: {refusal}");
        if let Some(help) = remedy(&refusal.to_string()) {
            eprintln!("aros-native-build: {help}");
        }
        eprintln!("aros-native-build: see https://ami-rust.metaneutrons.cc/troubleshooting/");
    }
    result
}

/// Compiler wrappers that only cache the output of the compiler Cargo selected.
///
/// `RUSTC` still names the pinned compiler when such a wrapper is configured, and
/// the compiler, Cargo and linker checks below still apply to it. Any other
/// wrapper could substitute the compiler and stays refused. A program is
/// recognised by the name of its executable.
const CACHING_WRAPPERS: &[&str] = &["sccache"];

fn is_caching_wrapper(program: &std::ffi::OsStr) -> bool {
    // `Path::file_name` ignores a trailing separator, but a directory is not a program.
    if program.as_bytes().ends_with(b"/") {
        return false;
    }
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| CACHING_WRAPPERS.contains(&name))
}

/// How to fix the refusals that users most often meet, keyed by the refusal text.
fn remedy(message: &str) -> Option<&'static str> {
    if message.starts_with("RUSTC_WRAPPER ") || message.starts_with("RUSTC_WORKSPACE_WRAPPER ") {
        Some(
            "a compiler wrapper is active and could replace the pinned compiler. Only the caching \
             wrapper sccache is accepted. Unset RUSTC_WRAPPER and RUSTC_WORKSPACE_WRAPPER in your \
             environment. If the wrapper comes from a Cargo configuration file, run this build with \
             CARGO_BUILD_RUSTC_WRAPPER= or set rustc-wrapper = \"\" under [build] in the project's \
             .cargo/config.toml.",
        )
    } else if message.starts_with("RUST_TARGET_PATH ") {
        Some("unset RUST_TARGET_PATH: the toolchain supplies its own target specification.")
    } else if message.starts_with("Cargo must explicitly select this toolchain's aros-link") {
        Some(
            "add the AROS target sections to .cargo/config.toml: linker = \"aros-link\" and \
             rustflags = [\"-Zunstable-options\"] for x86_64-unknown-aros-abi1 and \
             x86_64-unknown-aros-abi11.",
        )
    } else if message.starts_with("native bridge requires a supported AROS target") {
        Some("build with --target x86_64-unknown-aros-abi1 or --target x86_64-unknown-aros-abi11.")
    } else if message.starts_with("AROS target flags must not override") {
        Some(
            "remove --sysroot, --target, -C linker and -C linker-flavor from RUSTFLAGS and from the rustflags in your Cargo configuration.",
        )
    } else {
        None
    }
}

fn prepare_checked(options: BuildOptions) -> Result<()> {
    verify_rust_target_path(env::var_os("RUST_TARGET_PATH").as_deref())?;
    let abi = match env::var("TARGET").ok().as_deref() {
        Some("x86_64-unknown-aros-abi1") => ArosAbi::Abi1,
        Some("x86_64-unknown-aros-abi11") => ArosAbi::Abi11,
        _ => {
            return Err(Refusal::new(
                "native bridge requires a supported AROS target",
            ));
        }
    };
    let host = native_host_triple(crate::inputs::current_host()?)?;
    if env::var("HOST").ok().as_deref() != Some(host) {
        return Err(Refusal::new(
            "Cargo host does not match the admitted native tools",
        ));
    }
    verify_target_rustflags(env::var_os("CARGO_ENCODED_RUSTFLAGS").as_deref())?;
    for name in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"] {
        if env::var_os(name).is_some_and(|value| !value.is_empty() && !is_caching_wrapper(&value)) {
            return Err(Refusal::new(format!(
                "{name} conflicts with the pinned compiler selection"
            )));
        }
    }
    let compiler =
        env::var_os("RUSTC").ok_or_else(|| Refusal::new("Cargo did not select RUSTC"))?;
    let default_proxy = compiler == "rustc";
    let compiler = resolve_program(Path::new(&compiler))?;
    let query = Command::new(&compiler)
        .args(["--print", "sysroot"])
        .output()?;
    if !query.status.success() {
        return Err(Refusal::new("selected compiler did not report its sysroot"));
    }
    let root = std::str::from_utf8(&query.stdout)
        .map_err(|_| Refusal::new("toolchain sysroot is not UTF-8"))?
        .trim_end();
    if root.is_empty() || root.contains(['\r', '\n']) {
        return Err(Refusal::new("invalid selected toolchain sysroot"));
    }
    let tc = Toolchain::open(Path::new(root))?;
    verify_selected_compiler(&compiler, &tc, default_proxy)?;
    let linker = env::var_os("RUSTC_LINKER")
        .ok_or_else(|| Refusal::new("Cargo must explicitly select this toolchain's aros-link"))?;
    tc.verify_selected_linker(Path::new(&linker))?;
    let cargo = env::var_os("CARGO")
        .ok_or_else(|| Refusal::new("Cargo did not identify its executable"))?;
    if fs::canonicalize(cargo)? != fs::canonicalize(tc.cargo())? {
        return Err(Refusal::new("build must use the toolchain's paired Cargo"));
    }
    // The selected compiler's own sysroot and target definition are checked
    // independently of Cargo's package resolution.
    if !tc.rustc().is_file() || !tc.target_spec(abi).is_file() {
        return Err(Refusal::new(
            "selected compiler or target specification is missing",
        ));
    }
    let source_linker_identity = tc.source_linker_identity();
    let linker_identity = FileIdentity {
        path: "bin/aros-link".to_owned(),
        bytes: source_linker_identity.bytes,
        sha256: source_linker_identity.sha256.clone(),
    };
    let out = fs::canonicalize(
        env::var_os("OUT_DIR").ok_or_else(|| Refusal::new("missing Cargo OUT_DIR"))?,
    )?;
    let objects = out.join("ami-native");
    prepare_directory(&objects)?;
    let source_root = objects.join("source");
    stage_sources(&source_root)?;
    let recipe = NativeBuildRecipe {
        paths: NativeRecipePaths {
            source_root,
            toolchain_root: tc.toolchain_root().to_owned(),
            sdk_root: tc.sdk_root(abi),
            collector: tc.collector().to_owned(),
        },
        abi,
        testing: options.testing,
    };
    run_recipe(&recipe.startup_spec_into(&objects)?, tc.source_date_epoch())?;
    let mut units = vec![
        CSourceUnit::Sdk,
        CSourceUnit::Layout,
        CSourceUnit::EhFrameStart,
    ];
    if abi == ArosAbi::Abi1 {
        units.insert(0, CSourceUnit::Entry);
    }
    for unit in units {
        run_recipe(
            &recipe.c_compile_spec_into(unit, &objects)?,
            tc.source_date_epoch(),
        )?;
    }
    if options.testing {
        run_recipe(
            &recipe.c_compile_spec_into(CSourceUnit::BindDiagnostics, &objects)?,
            tc.source_date_epoch(),
        )?;
    }
    let mut identities = Vec::new();
    for name in object_names(abi, options.testing) {
        let (bytes, sha256) = file_identity(&objects.join(name))?;
        identities.push(FileIdentity {
            path: name.to_owned(),
            bytes,
            sha256,
        });
    }
    let record = NativeObjects {
        schema: SCHEMA.to_owned(),
        abi,
        toolchain_root: tc.root().to_owned(),
        toolchain_identity: tc.identity().to_owned(),
        testing: options.testing,
        linker: linker_identity,
        objects: identities,
    };
    verify_native_objects(&objects, &record)?;
    tc.recheck()?;
    let bytes = serde_json::to_vec(&record).map_err(|e| Refusal::new(e.to_string()))?;
    write_new(&objects.join(RECORD), &bytes)?;
    for name in [
        "RUSTC",
        "CARGO",
        "RUSTUP_TOOLCHAIN",
        "RUSTC_LINKER",
        "CARGO_TARGET_X86_64_AROS_LINKER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_TARGET",
        "RUSTUP_HOME",
        "CARGO_HOME",
        "RUST_TARGET_PATH",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "PATH",
    ] {
        println!("cargo::rerun-if-env-changed={name}");
    }
    // Cargo watches the selected prefix; a replaced component must rerun the
    // script and its checks instead of silently using a stale bridge record.
    println!("cargo::rerun-if-changed={}", cargo_path(tc.root())?);
    println!("cargo::rerun-if-changed={}", cargo_path(Path::new(root))?);
    println!("cargo::rerun-if-changed={}", cargo_path(&compiler)?);
    println!("cargo::rustc-link-arg=--no-gc-sections");
    println!(
        "cargo::rustc-link-arg=--ami-native-objects={}",
        cargo_path(&objects)?
    );
    Ok(())
}

/// Cargo supplies the effective target flags as unit-separated arguments.
/// Tool selection belongs to the selected prefix and Cargo's linker setting.
fn verify_target_rustflags(flags: Option<&std::ffi::OsStr>) -> Result<()> {
    let Some(flags) = flags else {
        return Ok(());
    };
    let mut codegen_argument = false;
    for flag in flags.as_bytes().split(|byte| *byte == 0x1f) {
        if flag == b"--sysroot"
            || flag.starts_with(b"--sysroot=")
            || flag == b"--target"
            || flag.starts_with(b"--target=")
        {
            return Err(Refusal::new(
                "AROS target flags must not override the selected sysroot or target",
            ));
        }
        if flag == b"-C" || flag == b"--codegen" {
            codegen_argument = true;
            continue;
        }
        let value = if codegen_argument {
            Some(flag)
        } else {
            flag.strip_prefix(b"-C=")
                .or_else(|| flag.strip_prefix(b"-C"))
                .or_else(|| flag.strip_prefix(b"--codegen="))
        };
        codegen_argument = false;
        if value.is_some_and(|value| {
            matches!(
                value.split(|byte| *byte == b'=').next(),
                Some(b"linker" | b"linker-flavor")
            )
        }) {
            return Err(Refusal::new(
                "AROS target flags must not override Cargo's selected target linker",
            ));
        }
    }
    Ok(())
}

/// Refuse ambient target search paths before opening or preparing native inputs.
fn verify_rust_target_path(path: Option<&std::ffi::OsStr>) -> Result<()> {
    if path.is_some_and(|path| !path.is_empty()) {
        return Err(Refusal::new(
            "RUST_TARGET_PATH must be unset or empty for the selected toolchain",
        ));
    }
    Ok(())
}

fn resolve_program(program: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if program.components().count() > 1 {
        return Ok(if program.is_absolute() {
            program.to_owned()
        } else {
            env::current_dir()?.join(program)
        });
    }
    let path = env::var_os("PATH").ok_or_else(|| Refusal::new("missing compiler search path"))?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(program);
        if let Ok(metadata) = fs::metadata(&candidate)
            && metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
        {
            return Ok(candidate);
        }
    }
    Err(Refusal::new("selected compiler was not found on PATH"))
}

fn verify_selected_compiler(compiler: &Path, tc: &Toolchain, default_proxy: bool) -> Result<()> {
    if fs::canonicalize(compiler)? == fs::canonicalize(tc.rustc())? {
        return Ok(());
    }
    // The standard bare `rustc` entry point can be a packaged rustup launcher
    // (Homebrew uses shell launchers). Trust that installed prerequisite and
    // validate its selected compiler; do not parse or patch its launcher code.
    // Explicit RUSTC overrides must be the pinned compiler or an identical
    // binary proxy, not an arbitrary wrapper reporting the same sysroot.
    let rustup = compiler
        .parent()
        .ok_or_else(|| Refusal::new("compiler has no parent"))?
        .join("rustup");
    if !rustup.is_file()
        || (!default_proxy
            && file_identity(&fs::canonicalize(compiler)?)?
                != file_identity(&fs::canonicalize(&rustup)?)?)
    {
        return Err(Refusal::new(
            "selected RUSTC is neither the pinned compiler nor its rustup proxy",
        ));
    }
    let selected = Command::new(&rustup).args(["which", "rustc"]).output()?;
    if !selected.status.success() {
        return Err(Refusal::new(
            "rustup did not identify the selected compiler",
        ));
    }
    let path = std::str::from_utf8(&selected.stdout)
        .map_err(|_| Refusal::new("rustup compiler path is not UTF-8"))?
        .trim_end();
    if path.is_empty()
        || path.contains(['\r', '\n'])
        || fs::canonicalize(path)? != fs::canonicalize(tc.rustc())?
    {
        return Err(Refusal::new("rustup selected a different Rust compiler"));
    }
    Ok(())
}

fn cargo_path(path: &Path) -> Result<&str> {
    let value = path
        .to_str()
        .ok_or_else(|| Refusal::new("Cargo directive path must be UTF-8"))?;
    if value.contains(['\r', '\n']) {
        return Err(Refusal::new("Cargo directive path contains a line break"));
    }
    Ok(value)
}

fn object_names(abi: ArosAbi, testing: bool) -> Vec<&'static str> {
    let mut names = vec!["startup.o", "sdk.o", "layout.o", "eh-frame-start.o"];
    if abi == ArosAbi::Abi1 {
        names.insert(1, "entry.o");
    }
    if testing {
        names.push("bind.o");
    }
    names
}

fn ensure_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(path)?.file_type().is_dir() {
                Ok(())
            } else {
                Err(Refusal::new(
                    "native output directory is not a real directory",
                ))
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn prepare_directory(path: &Path) -> Result<()> {
    ensure_directory(path)?;
    let owner = path.join(OWNER);
    if fs::read_dir(path)?.next().is_none() {
        write_new(&owner, SCHEMA.as_bytes())?;
    } else if read_regular(&owner, 128)? != SCHEMA.as_bytes() {
        return Err(Refusal::new(
            "native output directory has no matching owner marker",
        ));
    }
    let allowed = [
        OWNER,
        RECORD,
        "startup.o",
        "entry.o",
        "sdk.o",
        "layout.o",
        "eh-frame-start.o",
        "bind.o",
        "source",
    ];
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(Refusal::new("unknown native output entry"));
        };
        if !allowed.contains(&name)
            || entry.file_type()?.is_symlink()
            || (name != "source" && !entry.file_type()?.is_file())
        {
            return Err(Refusal::new("unexpected entry in native output directory"));
        }
    }
    // Remove the success record before rebuilding so a failed compiler cannot
    // leave a new bridge associated with a stale successful generation.
    for name in [
        RECORD,
        "startup.o",
        "entry.o",
        "sdk.o",
        "layout.o",
        "eh-frame-start.o",
        "bind.o",
    ] {
        match fs::remove_file(path.join(name)) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn stage_sources(root: &Path) -> Result<()> {
    ensure_directory(root)?;
    ensure_directory(&root.join("native"))?;
    ensure_directory(&root.join("tests"))?;
    ensure_directory(&root.join("tests/measurement"))?;
    ensure_directory(&root.join("scripts"))?;
    ensure_directory(&root.join("scripts/measurement"))?;
    for &(name, bytes) in SOURCES {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if read_regular(&path, bytes.len() as u64 + 1)? != bytes {
                    return Err(Refusal::new(
                        "staged native source differs from packaged source",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => write_new(&path, bytes)?,
            Err(error) => return Err(error.into()),
        }
    }
    verify_sources(root)
}

fn verify_sources(root: &Path) -> Result<()> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        if !fs::symlink_metadata(&dir)?.file_type().is_dir() {
            return Err(Refusal::new("staged source directory was replaced"));
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| Refusal::new("native source escaped root"))?
                .to_owned();
            if entry.file_type()?.is_dir() {
                if ![
                    "native",
                    "tests",
                    "tests/measurement",
                    "scripts",
                    "scripts/measurement",
                ]
                .iter()
                .any(|name| relative == Path::new(name))
                {
                    return Err(Refusal::new("unexpected native source directory"));
                }
                pending.push(entry.path());
            } else if entry.file_type()?.is_file() {
                let Some((_, expected)) =
                    SOURCES.iter().find(|(name, _)| relative == Path::new(name))
                else {
                    return Err(Refusal::new("unexpected native source file"));
                };
                if read_regular(&entry.path(), expected.len() as u64 + 1)? != *expected {
                    return Err(Refusal::new("packaged native source was changed"));
                }
                entries.push(relative);
            } else {
                return Err(Refusal::new("native source is not a regular file"));
            }
        }
    }
    if entries.len() != SOURCES.len() {
        return Err(Refusal::new("incomplete native source tree"));
    }
    Ok(())
}

pub(crate) fn run_recipe(recipe: &CommandRecipe, epoch: u64) -> Result<()> {
    execute_recipe(recipe, epoch, false)
}

/// Select the collector's existing linker-alias mode independently of its
/// recorded placement name. The executable path and linker arguments stay exact.
pub(crate) fn run_collector_recipe(recipe: &CommandRecipe, epoch: u64) -> Result<()> {
    execute_recipe(recipe, epoch, true)
}

fn execute_recipe(recipe: &CommandRecipe, epoch: u64, collector_alias: bool) -> Result<()> {
    let mut command = Command::new(&recipe.program);
    if collector_alias {
        command.arg0("collect-aros");
    }
    command
        .args(&recipe.arguments)
        .env("SOURCE_DATE_EPOCH", epoch.to_string())
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
    for name in [
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "COMPILER_PATH",
        "LIBRARY_PATH",
        "CCC_OVERRIDE_OPTIONS",
        "CCC_ADD_ARGS",
        "CLANG_CONFIG_FILE_SYSTEM_DIR",
        "CLANG_CONFIG_FILE_USER_DIR",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
    ] {
        command.env_remove(name);
    }
    for (key, _) in env::vars_os() {
        let bytes = key.as_encoded_bytes();
        if bytes.starts_with(b"LD_") || bytes.starts_with(b"DYLD_") {
            command.env_remove(key);
        }
    }
    let status = command.status()?;
    if !status.success() {
        return Err(Refusal::new(format!(
            "native tool {} failed: {status}",
            recipe.program.display()
        ))
        .with_exit_code(u8::try_from(status.code().unwrap_or(1)).unwrap_or(1)));
    }
    Ok(())
}

pub(crate) fn verify_native_objects(dir: &Path, record: &NativeObjects) -> Result<()> {
    if record.schema != SCHEMA {
        return Err(Refusal::new("unsupported native object record"));
    }
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(Refusal::new("native object directory was replaced"));
    }
    if read_regular(&dir.join(OWNER), 128)? != SCHEMA.as_bytes() {
        return Err(Refusal::new("native object owner marker changed"));
    }
    if record.linker.path != "bin/aros-link" {
        return Err(Refusal::new("unexpected native linker identity path"));
    }
    let (linker_bytes, linker_sha256) =
        file_identity(&record.toolchain_root.join("bin/aros-link"))?;
    if linker_bytes != record.linker.bytes || linker_sha256 != record.linker.sha256 {
        return Err(Refusal::new(
            "selected target linker bytes changed after native preparation",
        ));
    }
    let names = object_names(record.abi, record.testing);
    if record.objects.len() != names.len() {
        return Err(Refusal::new("incomplete native object record"));
    }
    for (object, name) in record.objects.iter().zip(names) {
        if object.path != name {
            return Err(Refusal::new("unexpected native object record path"));
        }
        let (bytes, sha256) = file_identity(&dir.join(name))?;
        if bytes != object.bytes || sha256 != object.sha256 {
            return Err(Refusal::new("native object bytes were changed"));
        }
    }
    verify_sources(&dir.join("source"))
}

pub(crate) fn load_native_objects(dir: &Path) -> Result<(Toolchain, NativeObjects)> {
    let bytes = read_regular(&dir.join(RECORD), 65536)?;
    let record: NativeObjects = serde_json::from_slice(&bytes)
        .map_err(|e| Refusal::new(format!("invalid native object record: {e}")))?;
    verify_native_objects(dir, &record)?;
    let tc = Toolchain::open(&record.toolchain_root)?;
    if tc.identity() != record.toolchain_identity {
        return Err(Refusal::new(
            "native objects belong to a different toolchain",
        ));
    }
    Ok((tc, record))
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

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(Refusal::new("native metadata is not a regular file"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Refusal::new(
            "native metadata is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Refusal::new("native metadata exceeded its parser bound"));
    }
    Ok(bytes)
}

fn file_identity(path: &Path) -> Result<(u64, String)> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(Refusal::new("native object is not a regular file"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(Refusal::new("native object is not a regular file"));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
        count = count
            .checked_add(n as u64)
            .ok_or_else(|| Refusal::new("object size overflow"))?;
    }
    if count != before.len() || file.metadata()?.len() != count {
        return Err(Refusal::new("native object changed during hashing"));
    }
    Ok((
        count,
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn common_refusals_have_a_remedy_and_unknown_ones_do_not() {
        for message in [
            "RUSTC_WRAPPER conflicts with the pinned compiler selection",
            "RUSTC_WORKSPACE_WRAPPER conflicts with the pinned compiler selection",
            "RUST_TARGET_PATH must be unset or empty for the selected toolchain",
            "Cargo must explicitly select this toolchain's aros-link",
            "native bridge requires a supported AROS target",
            "AROS target flags must not override the selected sysroot or target",
        ] {
            assert!(super::remedy(message).is_some(), "{message}");
        }
        assert!(super::remedy("missing Cargo OUT_DIR").is_none());
        let help =
            super::remedy("RUSTC_WRAPPER conflicts with the pinned compiler selection").unwrap();
        assert!(help.contains("CARGO_BUILD_RUSTC_WRAPPER=") && help.contains("sccache"));
    }

    #[test]
    fn only_the_sccache_executable_is_a_caching_wrapper() {
        use std::ffi::OsStr;
        for accepted in ["sccache", "/opt/homebrew/bin/sccache", "./tools/sccache"] {
            assert!(
                super::is_caching_wrapper(OsStr::new(accepted)),
                "{accepted}"
            );
        }
        for refused in [
            "clippy-driver",
            "/usr/bin/env",
            "sccache-fork",
            "my-sccache",
            // A directory named sccache does not make its contents the cache.
            "/opt/sccache/rustc-wrapper",
            "/tmp/sccache/",
            "",
        ] {
            assert!(!super::is_caching_wrapper(OsStr::new(refused)), "{refused}");
        }
    }

    #[test]
    fn collector_invocation_selects_alias_without_changing_executable_or_link_arguments() {
        let recipe = crate::recipe::CommandRecipe {
            program: std::path::PathBuf::from("/bin/sh"),
            arguments: ["-c", "test \"$0\" = collect-aros"]
                .map(std::ffi::OsString::from)
                .to_vec(),
        };
        super::run_collector_recipe(&recipe, 0).unwrap();
        assert!(super::run_recipe(&recipe, 0).is_err());
    }

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let dir = env::temp_dir().join(format!(
                "aros-native-build-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn native_host_target_triple_selection_is_explicit_and_closed() {
        assert_eq!(
            native_host_triple("macos-aarch64").unwrap(),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            native_host_triple("linux-x86_64").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            native_host_triple("linux-aarch64").unwrap(),
            "aarch64-unknown-linux-gnu"
        );
        assert!(native_host_triple("linux-riscv64").is_err());
    }

    #[test]
    fn effective_target_flags_cannot_replace_tool_selection() {
        use std::ffi::OsStr;
        verify_target_rustflags(None).unwrap();
        verify_target_rustflags(Some(OsStr::new(
            "-Zunstable-options\x1f-Copt-level=2\x1f-C\x1fpanic=abort",
        )))
        .unwrap();
        for flags in [
            "-Clinker=other",
            "-C=linker=other",
            "-C\x1flinker=other",
            "--codegen=linker=other",
            "--codegen\x1flinker=other",
            "-Clinker-flavor=gcc",
            "--sysroot=/other",
            "--sysroot\x1f/other",
            "--target=other",
            "--target\x1fother",
        ] {
            assert!(
                verify_target_rustflags(Some(OsStr::new(flags))).is_err(),
                "{flags:?}"
            );
        }
        verify_target_rustflags(Some(OsStr::new("--cfg\x1ffeature=\"--sysroot\""))).unwrap();
    }

    #[test]
    fn rust_target_path_must_be_unset_or_empty() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

        verify_rust_target_path(None).unwrap();
        verify_rust_target_path(Some(OsStr::new(""))).unwrap();
        assert!(verify_rust_target_path(Some(OsStr::new("/other/targets"))).is_err());
        assert!(verify_rust_target_path(Some(OsStr::from_bytes(b"\xff"))).is_err());
    }

    #[test]
    fn quoted_c_includes_are_staged_and_missing_measurement_header_refuses() {
        let temp = Temp::new();
        let root = temp.0.join("source");
        stage_sources(&root).unwrap();
        let canonical_root = fs::canonicalize(&root).unwrap();
        for &(name, bytes) in SOURCES {
            let parent = root.join(name).parent().unwrap().to_owned();
            for line in std::str::from_utf8(bytes).unwrap().lines() {
                let Some(include) = line.trim_start().strip_prefix("#include \"") else {
                    continue;
                };
                let (include, _) = include.split_once('"').unwrap();
                let path = fs::canonicalize(parent.join(include)).unwrap_or_else(|error| {
                    panic!("missing include {include} from {name}: {error}")
                });
                assert!(path.starts_with(&canonical_root));
                assert!(path.is_file());
            }
        }
        let header = root.join("scripts/measurement/m1_measurement.h");
        fs::remove_file(&header).unwrap();
        assert!(verify_sources(&root).is_err());
        stage_sources(&root).unwrap();
        assert_eq!(
            fs::read(&header).unwrap(),
            include_bytes!("../scripts/measurement/m1_measurement.h")
        );
        verify_sources(&root).unwrap();
    }

    fn fixture(root: &Path) -> NativeObjects {
        prepare_directory(root).unwrap();
        stage_sources(&root.join("source")).unwrap();
        let objects = object_names(ArosAbi::Abi1, false)
            .into_iter()
            .map(|name| {
                fs::write(root.join(name), name.as_bytes()).unwrap();
                let (bytes, sha256) = file_identity(&root.join(name)).unwrap();
                FileIdentity {
                    path: name.to_owned(),
                    bytes,
                    sha256,
                }
            })
            .collect();
        let toolchain = root.parent().unwrap().join("toolchain");
        fs::create_dir_all(toolchain.join("bin")).unwrap();
        fs::write(toolchain.join("bin/aros-link"), b"linker fixture").unwrap();
        let (bytes, sha256) = file_identity(&toolchain.join("bin/aros-link")).unwrap();
        NativeObjects {
            schema: SCHEMA.to_owned(),
            abi: ArosAbi::Abi1,
            toolchain_root: toolchain,
            toolchain_identity: "fixture".to_owned(),
            testing: false,
            linker: FileIdentity {
                path: "bin/aros-link".to_owned(),
                bytes,
                sha256,
            },
            objects,
        }
    }

    #[test]
    fn changed_object_and_source_refuse_after_a_valid_control() {
        let temp = Temp::new();
        let root = temp.0.join("objects");
        let record = fixture(&root);
        verify_native_objects(&root, &record).unwrap();
        fs::write(
            record.toolchain_root.join("bin/aros-link"),
            b"changed linker",
        )
        .unwrap();
        assert!(verify_native_objects(&root, &record).is_err());
        fs::write(
            record.toolchain_root.join("bin/aros-link"),
            b"linker fixture",
        )
        .unwrap();
        verify_native_objects(&root, &record).unwrap();
        fs::write(root.join("sdk.o"), b"other").unwrap();
        assert!(verify_native_objects(&root, &record).is_err());
        fs::write(root.join("sdk.o"), b"sdk.o").unwrap();
        verify_native_objects(&root, &record).unwrap();
        fs::write(root.join("source/native/sdk.h"), b"changed source").unwrap();
        assert!(verify_native_objects(&root, &record).is_err());
    }

    #[test]
    fn rerun_invalidates_success_record_and_keeps_unrelated_files_safe() {
        let temp = Temp::new();
        let root = temp.0.join("objects");
        let record = fixture(&root);
        write_new(&root.join(RECORD), &serde_json::to_vec(&record).unwrap()).unwrap();
        prepare_directory(&root).unwrap();
        assert!(!root.join(RECORD).exists());
        assert!(!root.join("sdk.o").exists());
        assert!(root.join("source/native/sdk.h").is_file());
        fs::write(root.join("unrelated"), b"keep").unwrap();
        assert!(prepare_directory(&root).is_err());
        assert_eq!(fs::read(root.join("unrelated")).unwrap(), b"keep");
    }

    #[test]
    fn symlink_object_and_directive_injection_are_rejected() {
        let temp = Temp::new();
        let root = temp.0.join("objects");
        let record = fixture(&root);
        fs::rename(root.join("sdk.o"), temp.0.join("outside.o")).unwrap();
        std::os::unix::fs::symlink(temp.0.join("outside.o"), root.join("sdk.o")).unwrap();
        assert!(verify_native_objects(&root, &record).is_err());
        assert!(prepare_directory(&root).is_err());
        assert_eq!(fs::read(temp.0.join("outside.o")).unwrap(), b"sdk.o");
        assert!(cargo_path(Path::new("/a\ncargo::rustc-link-arg=bad")).is_err());
    }
}

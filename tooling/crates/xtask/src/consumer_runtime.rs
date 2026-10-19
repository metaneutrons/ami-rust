//! Bounded discovery of native runtime inputs for a consumer phase.
//!
//! This is an input inventory, not proof that a runtime is complete. Queries
//! run with a replacement environment and bounded output; no query writes files.

use ami_rust_core::{
    Refusal, Result,
    digest::sha256_file,
    process_capture::{CaptureLimits, CapturedProcess, CommandSpec, capture},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};

#[cfg(target_os = "macos")]
#[path = "../../../macos-host-selection.rs"]
mod macos_host_selection;

const PATH_VALUE: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
// The capture API bounds stdout and stderr independently. Keep each half at
// 1 MiB so one query retains at most 2 MiB in total.
const CAPTURE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_INTERPRETER_BYTES: u64 = 4096;
const INSTALLER_COMMANDS: &[&str] = &[
    "mkdir", "cut", "grep", "uname", "tr", "sed", "chmod", "rm", "touch", "dirname", "basename",
    "cat", "cp", "mv",
];

/// Exact runtime inputs discovered for one native consumer phase.
pub(super) struct RuntimeInputs {
    pub executables: BTreeSet<PathBuf>,
    pub libraries: BTreeSet<PathBuf>,
    pub read_files: BTreeSet<PathBuf>,
    pub read_trees: BTreeSet<PathBuf>,
    pub evidence: Value,
}

#[derive(Default)]
struct Discovery {
    executables: BTreeSet<PathBuf>,
    libraries: BTreeSet<PathBuf>,
    read_files: BTreeSet<PathBuf>,
    read_trees: BTreeSet<PathBuf>,
    executable_aliases: Vec<Value>,
    library_aliases: Vec<Value>,
    loader_rows: Vec<Value>,
    query_rows: Vec<Value>,
    runtime_rows: Vec<Value>,
    build_rows: Vec<Value>,
    cold_rows: Vec<Value>,
}

/// Resolve host runtime inputs from explicit tool and library paths.
///
/// The supported runtime hosts are macOS/aarch64 and Linux/x86_64. A bounded
/// discovery result does not establish complete runtime closure for arbitrary
/// programs, plugins, dynamic loads, or file/network access.
pub(super) fn discover(
    executables: BTreeSet<PathBuf>,
    libraries: BTreeSet<PathBuf>,
    build: bool,
    cold_prepare: bool,
    work: &Path,
) -> Result<RuntimeInputs> {
    if executables.is_empty() {
        return Err(Refusal::new(
            "native runtime discovery requires at least one declared executable",
        ));
    }
    let work = canonical_directory(work)?;
    let mut discovery = Discovery::default();

    for path in executables {
        let canonical = canonical_file(&path, true)?;
        discovery.executable_aliases.push(json!({
            "declared_path": path_text(&path)?,
            "canonical_path": path_text(&canonical)?,
        }));
        discovery.executables.insert(canonical);
    }
    for path in libraries {
        add_library(&mut discovery, &path, "declared")?;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        if build {
            discover_linux_build(&mut discovery, &work)?;
        }
        if cold_prepare {
            discover_linux_cold_prepare(&mut discovery, &work)?;
        }
        discover_linux_runtime(&mut discovery, &work)?;
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        // Every nested verifier/tool opens null stdin, including warm install
        // authentication before compiler or network preparation is needed.
        add_read_device(
            &mut discovery,
            Path::new("/dev/null"),
            "nested command stdin",
        )?;
        if build || cold_prepare {
            discover_macos_selection(&mut discovery, &work, build, cold_prepare)?;
        }
    }

    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (&mut discovery, &work, build, cold_prepare);
        return Err(Refusal::new(
            "native runtime discovery supports only macOS/aarch64 and Linux/x86_64",
        ));
    }

    exclude_executable_aliases(&mut discovery)?;
    let executable_hashes = hash_executables(&discovery.executables)?;
    let library_hashes = hash_libraries(&discovery.libraries)?;
    let evidence = json!({
        "schema": "ami-rust-consumer-native-runtime-inputs-v1",
        "status": "BOUNDED_DISCOVERY_ONLY",
        "host": host_name(),
        "declared_executables": discovery.executable_aliases,
        "declared_libraries": discovery.library_aliases,
        "executables": executable_hashes,
        "libraries": library_hashes,
        "loaders": discovery.loader_rows,
        "read_files": path_list(&discovery.read_files)?,
        "read_trees": path_list(&discovery.read_trees)?,
        "queries": discovery.query_rows,
        "runtime_closure": discovery.runtime_rows,
        "build_inputs": discovery.build_rows,
        "cold_prepare_inputs": discovery.cold_rows,
        "limitations": limitations(build, cold_prepare),
    });

    Ok(RuntimeInputs {
        executables: discovery.executables,
        libraries: discovery.libraries,
        read_files: discovery.read_files,
        read_trees: discovery.read_trees,
        evidence,
    })
}

fn host_name() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x86_64"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "macos-aarch64"
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        "unsupported"
    }
}

fn limitations(build: bool, cold_prepare: bool) -> Value {
    let mut rows = vec![
        "Static and bounded discovery does not prove complete runtime file, dynamic-load, or network access."
            .to_owned(),
        "Linux ldd reports the resolved ELF dependency closure for each discovered executable; it does not model later dlopen calls."
            .to_owned(),
        "Linux ELF executables without PT_INTERP are hashed and reported without invoking ldd; this does not independently prove static linkage or detect opaque runtime dependencies."
            .to_owned(),
    ];
    if build && cfg!(target_os = "linux") {
        rows.push(
            "Linux build discovery records GCC-selected programs, link inputs, and header roots, but does not prove every compiler data-file access, linker-script include, or later LTO plugin load."
                .to_owned(),
        );
    }
    if cold_prepare {
        rows.push(
            "Cold installers redirect output to /dev/null. RuntimeInputs has no exact device-write field, so this write allowance must be resolved by the policy caller."
                .to_owned(),
        );
    }
    json!(rows)
}

fn query_environment(work: &Path) -> BTreeMap<OsString, OsString> {
    BTreeMap::from([
        (OsString::from("PATH"), OsString::from(PATH_VALUE)),
        (OsString::from("HOME"), work.as_os_str().to_os_string()),
        (OsString::from("TMPDIR"), work.as_os_str().to_os_string()),
        (OsString::from("LC_ALL"), OsString::from("C")),
    ])
}

fn run_query(
    program: &Path,
    arguments: &[&str],
    work: &Path,
    label: &str,
) -> Result<CapturedProcess> {
    let canonical = canonical_file(program, true)?;
    let spec = CommandSpec::new(
        canonical.as_os_str(),
        arguments.iter().map(OsString::from),
        work,
        query_environment(work),
    );
    let captured = capture(
        &spec,
        CaptureLimits {
            timeout: Duration::from_secs(30),
            stdout_bytes: CAPTURE_BYTES,
            stderr_bytes: CAPTURE_BYTES,
            termination_grace: Duration::from_secs(1),
        },
        || false,
    )
    .map_err(|error| Refusal::new(format!("{label} query failed: {error}")))?;
    if !captured.status.success() {
        return Err(Refusal::new(format!(
            "{label} query exited with {}: {}",
            captured.exit_code().unwrap_or(-1),
            bounded_diagnostic(&captured.stderr)
        )));
    }
    Ok(captured)
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars().take(1024).collect()
}

fn one_line(bytes: &[u8], label: &str) -> Result<String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Refusal::new(format!("{label} output is not UTF-8")))?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        return Err(Refusal::new(format!(
            "{label} output must be exactly one nonempty line"
        )));
    }
    Ok(line.to_owned())
}

fn canonical_file(path: &Path, executable: bool) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Refusal::new(format!(
            "cannot resolve native input {}: {error}",
            path.display()
        ))
    })?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(Refusal::new(format!(
            "native input is not a regular file: {}",
            canonical.display()
        )));
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(Refusal::new(format!(
            "native executable has no execute permission: {}",
            canonical.display()
        )));
    }
    let _ = path_text(&canonical)?;
    Ok(canonical)
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Refusal::new(format!(
            "cannot resolve runtime work directory {}: {error}",
            path.display()
        ))
    })?;
    if !fs::metadata(&canonical)?.is_dir() {
        return Err(Refusal::new(format!(
            "runtime work path is not an existing directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

/// Normalize path syntax while retaining symlink components for lookup.
fn lookup_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!(
            "library lookup path must be absolute: {}",
            path.display()
        )));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push("/"),
            Component::Normal(name) => normalized.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(Refusal::new(format!(
                    "library lookup path contains unsupported parent syntax: {}",
                    path.display()
                )));
            }
        }
    }
    if !normalized.is_absolute() {
        return Err(Refusal::new(
            "library lookup path did not normalize to an absolute path",
        ));
    }
    let _ = path_text(&normalized)?;
    Ok(normalized)
}

fn add_executable(discovery: &mut Discovery, requested: &Path, label: &str) -> Result<PathBuf> {
    let canonical = canonical_file(requested, true)?;
    discovery.executables.insert(canonical.clone());
    discovery.query_rows.push(json!({
        "kind": "executable",
        "source": label,
        "declared_path": path_text(requested)?,
        "canonical_path": path_text(&canonical)?,
    }));
    Ok(canonical)
}

fn add_library(discovery: &mut Discovery, requested: &Path, label: &str) -> Result<()> {
    let lookup = lookup_path(requested)?;
    let canonical = canonical_file(&lookup, false)?;
    discovery.library_aliases.push(json!({
        "source": label,
        "lookup_path": path_text(&lookup)?,
        "canonical_path": path_text(&canonical)?,
    }));
    discovery.libraries.insert(lookup);
    Ok(())
}

fn add_read_file(discovery: &mut Discovery, path: &Path, label: &str) -> Result<()> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Refusal::new(format!(
            "cannot resolve required read file {}: {error}",
            path.display()
        ))
    })?;
    if !fs::metadata(&canonical)?.is_file() {
        return Err(Refusal::new(format!(
            "runtime read input is not a file: {}",
            canonical.display()
        )));
    }
    discovery.read_files.insert(canonical.clone());
    discovery.query_rows.push(json!({
        "kind": "read_file",
        "source": label,
        "path": path_text(&canonical)?,
    }));
    Ok(())
}

fn add_read_device(discovery: &mut Discovery, path: &Path, label: &str) -> Result<()> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Refusal::new(format!(
            "cannot resolve required read device {}: {error}",
            path.display()
        ))
    })?;
    if !fs::metadata(&canonical)?.file_type().is_char_device() {
        return Err(Refusal::new(format!(
            "runtime read device is not a character device: {}",
            canonical.display()
        )));
    }
    discovery.read_files.insert(canonical.clone());
    discovery.query_rows.push(json!({
        "kind": "read_file",
        "source": label,
        "device": "character",
        "path": path_text(&canonical)?,
    }));
    Ok(())
}

fn add_read_tree(discovery: &mut Discovery, path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = canonical_directory(path)?;
    discovery.read_trees.insert(canonical.clone());
    discovery.query_rows.push(json!({
        "kind": "read_tree",
        "source": label,
        "path": path_text(&canonical)?,
    }));
    Ok(canonical)
}

fn resolve_path_name(name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains('/') {
        return Err(Refusal::new(format!("invalid PATH command name: {name}")));
    }
    for directory in PATH_VALUE.split(':') {
        let candidate = Path::new(directory).join(name);
        if candidate.exists() {
            return canonical_file(&candidate, true);
        }
    }
    Err(Refusal::new(format!(
        "required command is absent from replacement PATH: {name}"
    )))
}

fn add_path_command(discovery: &mut Discovery, name: &str, label: &str) -> Result<PathBuf> {
    let requested = resolve_path_name(name)?;
    add_executable(discovery, &requested, label)
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new("native runtime path is not UTF-8"))
}

fn path_list(paths: &BTreeSet<PathBuf>) -> Result<Vec<String>> {
    paths.iter().map(|path| path_text(path)).collect()
}

fn read_hash(path: &Path) -> Result<String> {
    sha256_file(path)
}

fn hash_executables(paths: &BTreeSet<PathBuf>) -> Result<Vec<Value>> {
    paths
        .iter()
        .map(|path| {
            Ok(json!({
                "canonical_path": path_text(path)?,
                "sha256": read_hash(path)?,
            }))
        })
        .collect()
}

fn hash_libraries(paths: &BTreeSet<PathBuf>) -> Result<Vec<Value>> {
    paths
        .iter()
        .map(|lookup| {
            let canonical = canonical_file(lookup, false)?;
            Ok(json!({
                "lookup_path": path_text(lookup)?,
                "canonical_path": path_text(&canonical)?,
                "sha256": read_hash(&canonical)?,
            }))
        })
        .collect()
}

fn exclude_executable_aliases(discovery: &mut Discovery) -> Result<()> {
    let executable_ids: BTreeSet<PathBuf> = discovery
        .executables
        .iter()
        .map(|path| fs::canonicalize(path).map_err(Refusal::from))
        .collect::<Result<_>>()?;
    let mut retained = BTreeSet::new();
    for lookup in std::mem::take(&mut discovery.libraries) {
        let canonical = fs::canonicalize(&lookup).map_err(|error| {
            Refusal::new(format!(
                "cannot recheck library lookup identity {}: {error}",
                lookup.display()
            ))
        })?;
        if !executable_ids.contains(&canonical) {
            retained.insert(lookup);
        }
    }
    discovery.libraries = retained;
    Ok(())
}

fn bounded_single_query(
    discovery: &mut Discovery,
    program: &Path,
    arguments: &[&str],
    work: &Path,
    label: &str,
) -> Result<String> {
    let captured = run_query(program, arguments, work, label)?;
    let line = one_line(&captured.stdout, label)?;
    discovery.query_rows.push(json!({
        "kind": "command_query",
        "label": label,
        "program": path_text(program)?,
        "arguments": arguments,
        "stdout": line,
    }));
    Ok(line)
}

fn add_git_transport_helpers(
    discovery: &mut Discovery,
    git: &Path,
    work: &Path,
    label: &str,
) -> Result<()> {
    let raw = bounded_single_query(discovery, git, &["--exec-path"], work, label)?;
    let directory = Path::new(&raw);
    if !directory.is_absolute() {
        return Err(Refusal::new(format!(
            "{label} returned a nonabsolute git exec path"
        )));
    }
    let directory = canonical_directory(directory)?;
    #[cfg(target_os = "macos")]
    add_read_tree(
        discovery,
        &directory,
        "selected OS Git helper lookup, including HTTPS helper aliases; execution remains exact and hash-bound",
    )?;
    for helper in ["git-remote-http", "git-remote-https"] {
        let requested = directory.join(helper);
        add_executable(discovery, &requested, "git HTTPS transport helper")?;
    }
    Ok(())
}

fn add_cold_network_inputs(discovery: &mut Discovery) -> Result<()> {
    for path in [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/gai.conf",
        "/etc/services",
        "/etc/localtime",
        "/etc/ssl/openssl.cnf",
        "/etc/ssl/cert.pem",
    ] {
        let path = Path::new(path);
        if path.exists() {
            add_read_file(
                discovery,
                path,
                "cold network name service or TLS configuration",
            )?;
        }
    }
    let certificates = Path::new("/etc/ssl/certs");
    if certificates.exists() {
        add_read_tree(
            discovery,
            certificates,
            "cold TLS certificate bundle directory",
        )?;
    }
    Ok(())
}

fn discover_cold_commands(
    discovery: &mut Discovery,
    work: &Path,
    include_system_git: bool,
) -> Result<()> {
    let start = discovery.query_rows.len();
    if include_system_git {
        let git = add_executable(
            discovery,
            Path::new("/usr/bin/git"),
            "cold preparation system git",
        )?;
        add_git_transport_helpers(discovery, &git, work, "system git --exec-path")?;
    }
    for name in ["curl", "env", "bash"] {
        let path = add_path_command(discovery, name, "cold preparation command")?;
        if name == "bash" {
            discovery.cold_rows.push(json!({
                "kind": "installer_interpreter",
                "shebang": "#!/usr/bin/env bash",
                "canonical_path": path_text(&path)?,
            }));
        } else {
            discovery.cold_rows.push(json!({
                "kind": "cold_command",
                "name": name,
                "canonical_path": path_text(&path)?,
            }));
        }
    }
    for name in INSTALLER_COMMANDS {
        let path = add_path_command(discovery, name, "cold preparation installer command")?;
        discovery.cold_rows.push(json!({
            "kind": "installer_command",
            "name": name,
            "canonical_path": path_text(&path)?,
        }));
    }
    discovery.cold_rows.push(json!({
        "kind":"source_checkout_recipe",
        "git_templates":"disabled by the consumer's explicit init --template= argument",
        "hooks":"disabled by core.hooksPath=/dev/null",
    }));
    add_cold_network_inputs(discovery)?;
    if discovery.query_rows.len() == start {
        return Err(Refusal::new("cold preparation command closure was empty"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn discover_macos_cold_prepare(
    discovery: &mut Discovery,
    work: &Path,
    selection: &macos_host_selection::HostSelection,
) -> Result<()> {
    discover_cold_commands(discovery, work, false)?;
    let developer_git = selection
        .developer_directory
        .canonical_path
        .join("usr/bin/git");
    let developer_git = add_executable(discovery, &developer_git, "selected Developer git")?;
    add_git_transport_helpers(
        discovery,
        &developer_git,
        work,
        "selected Developer git --exec-path",
    )?;
    let root_keychain = Path::new("/System/Library/Keychains/SystemRootCertificates.keychain");
    if root_keychain.exists() {
        add_read_file(
            discovery,
            root_keychain,
            "cold TLS trust roots used by macOS Secure Transport",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn discover_linux_build(discovery: &mut Discovery, work: &Path) -> Result<()> {
    let cc = add_path_command(discovery, "cc", "Linux native compiler")?;
    let search = run_query(&cc, &["-print-search-dirs"], work, "GCC -print-search-dirs")?;
    let search_text = std::str::from_utf8(&search.stdout)
        .map_err(|_| Refusal::new("GCC -print-search-dirs output is not UTF-8"))?;
    let search_dirs = parse_gcc_search_dirs(search_text)?;
    discovery.build_rows.push(json!({
        "kind": "gcc_search_dirs",
        "programs": search_dirs.0.iter().map(|path| path_text(path)).collect::<Result<Vec<_>>>()?,
        "libraries": search_dirs.1.iter().map(|path| path_text(path)).collect::<Result<Vec<_>>>()?,
    }));

    let mut programs = BTreeMap::new();
    for name in ["cc1", "collect2", "as", "ld", "lto-wrapper"] {
        let argument = format!("-print-prog-name={name}");
        let captured = run_query(&cc, &[argument.as_str()], work, &format!("GCC {argument}"))?;
        let output = one_line(&captured.stdout, &format!("GCC {argument}"))?;
        let tool = resolve_gcc_program(&output, &search_dirs.0)?;
        add_executable(discovery, &tool, "GCC compiler program")?;
        programs.insert(name.to_owned(), tool.clone());
        discovery.build_rows.push(json!({
            "kind": "gcc_program",
            "name": name,
            "path": path_text(&tool)?,
        }));
    }

    let required_files = [
        "crt1.o",
        "Scrt1.o",
        "crti.o",
        "crtn.o",
        "crtbeginS.o",
        "crtendS.o",
        "libgcc.a",
        "libgcc_s.so",
        "libc.so",
        "libc_nonshared.a",
        "liblto_plugin.so",
    ];
    let optional_files = [
        "crtbegin.o",
        "crtend.o",
        "crtfastmath.o",
        "libgcc_eh.a",
        "libm.so",
        "libpthread.so",
        "libdl.so",
        "librt.so",
        "libutil.so",
        "libresolv.so",
        "libatomic.so",
        "libstdc++.so",
    ];
    let mut queried_files = BTreeMap::new();
    for name in required_files.iter().chain(optional_files.iter()) {
        let argument = format!("-print-file-name={name}");
        let captured = run_query(&cc, &[argument.as_str()], work, &format!("GCC {argument}"))?;
        let output = one_line(&captured.stdout, &format!("GCC {argument}"))?;
        if output == *name {
            if required_files.contains(name) {
                return Err(Refusal::new(format!(
                    "GCC did not resolve required native link input {name}"
                )));
            }
            discovery.build_rows.push(json!({
                "kind": "optional_gcc_link_input_unresolved",
                "name": name,
            }));
            continue;
        }
        let path = Path::new(&output);
        if !path.is_absolute() {
            return Err(Refusal::new(format!(
                "GCC returned a nonabsolute link input for {name}"
            )));
        }
        let canonical = canonical_file(path, false)?;
        if *name == "liblto_plugin.so" {
            add_library(discovery, path, "GCC LTO plugin")?;
        } else {
            add_read_file(discovery, &canonical, "GCC native link input")?;
        }
        queried_files.insert((*name).to_owned(), canonical.clone());
        discovery.build_rows.push(json!({
            "kind": if *name == "liblto_plugin.so" { "gcc_link_library" } else { "gcc_link_input" },
            "name": name,
            "canonical_path": path_text(&canonical)?,
        }));
    }

    let include = bounded_single_query(
        discovery,
        &cc,
        &["-print-file-name=include"],
        work,
        "GCC builtin include directory",
    )?;
    let include = canonical_directory(Path::new(&include))?;
    add_read_tree(discovery, &include, "GCC builtin headers")?;

    let specs_result = bounded_single_query(
        discovery,
        &cc,
        &["-print-file-name=specs"],
        work,
        "GCC specs path",
    )?;
    if specs_result != "specs" {
        let specs = canonical_file(Path::new(&specs_result), false)?;
        add_read_file(discovery, &specs, "GCC specs file")?;
        discovery.build_rows.push(json!({
            "kind": "gcc_specs",
            "canonical_path": path_text(&specs)?,
        }));
    } else {
        discovery.build_rows.push(json!({
            "kind": "gcc_specs",
            "embedded": true,
        }));
    }

    let headers = run_query(
        &cc,
        &["-E", "-v", "-x", "c", "-"],
        work,
        "GCC header search",
    )?;
    let stderr = std::str::from_utf8(&headers.stderr)
        .map_err(|_| Refusal::new("GCC header search output is not UTF-8"))?;
    let header_dirs = parse_header_dirs(stderr)?;
    for header in &header_dirs {
        add_read_tree(discovery, header, "GCC system header search directory")?;
    }
    discovery.build_rows.push(json!({
        "kind": "gcc_header_dirs",
        "paths": path_list(&header_dirs)?,
    }));

    if programs.len() != 5 || queried_files.len() < required_files.len() {
        return Err(Refusal::new(
            "GCC native build closure is incomplete; refusing a partial compiler pass",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_gcc_program(output: &str, gcc_program_dirs: &[PathBuf]) -> Result<PathBuf> {
    let reported = Path::new(output);
    if reported.is_absolute() {
        return canonical_file(reported, true);
    }
    if output.is_empty() || output.contains('/') {
        return Err(Refusal::new(format!(
            "GCC returned an invalid relative compiler program: {output}"
        )));
    }
    for directory in gcc_program_dirs {
        let candidate = directory.join(output);
        if candidate.exists() {
            return canonical_file(&candidate, true);
        }
    }
    resolve_path_name(output)
}

#[cfg(target_os = "linux")]
fn parse_gcc_search_dirs(text: &str) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut programs = None;
    let mut libraries = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("programs:") {
            programs = Some(parse_search_path_list(value, "GCC program search dirs")?);
        } else if let Some(value) = line.strip_prefix("libraries:") {
            libraries = Some(parse_search_path_list(value, "GCC library search dirs")?);
        }
    }
    let programs = programs.ok_or_else(|| Refusal::new("GCC omitted programs search dirs"))?;
    let libraries = libraries.ok_or_else(|| Refusal::new("GCC omitted libraries search dirs"))?;
    if programs.is_empty() || libraries.is_empty() {
        return Err(Refusal::new("GCC search directories are empty"));
    }
    Ok((programs, libraries))
}

#[cfg(target_os = "linux")]
fn parse_search_path_list(raw: &str, label: &str) -> Result<Vec<PathBuf>> {
    let raw = raw.trim().strip_prefix('=').unwrap_or(raw.trim());
    if raw.is_empty() {
        return Err(Refusal::new(format!("{label} are empty")));
    }
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();
    for token in raw.split(':') {
        if token.is_empty() {
            return Err(Refusal::new(format!("{label} contain an empty element")));
        }
        let path = Path::new(token);
        if !path.is_absolute() {
            return Err(Refusal::new(format!("{label} contain a nonabsolute path")));
        }
        let path = path.to_path_buf();
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn parse_header_dirs(text: &str) -> Result<BTreeSet<PathBuf>> {
    let start = text
        .find("#include <...> search starts here:")
        .ok_or_else(|| Refusal::new("GCC omitted system header search start"))?;
    let after_start = &text[start + "#include <...> search starts here:".len()..];
    let end = after_start
        .find("End of search list.")
        .ok_or_else(|| Refusal::new("GCC omitted system header search end"))?;
    let mut paths = BTreeSet::new();
    for line in after_start[..end].lines() {
        let token = line.trim();
        if token.is_empty() {
            continue;
        }
        if token.ends_with(" (framework directory)") {
            return Err(Refusal::new(
                "GCC emitted an unsupported framework header directory",
            ));
        }
        let path = Path::new(token);
        if !path.is_absolute() {
            return Err(Refusal::new(
                "GCC system header search contains a nonabsolute directory",
            ));
        }
        paths.insert(canonical_directory(path)?);
    }
    if paths.is_empty() {
        return Err(Refusal::new("GCC system header search is empty"));
    }
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn discover_linux_runtime(discovery: &mut Discovery, work: &Path) -> Result<()> {
    add_read_device(discovery, Path::new("/dev/null"), "nested command stdin")?;
    // Ownership guards use getpwuid_r rather than trusting HOME. Keep the
    // ordinary local account lookup available in warm as well as cold phases.
    for path in ["/etc/passwd", "/etc/nsswitch.conf"] {
        if Path::new(path).exists() {
            add_read_file(discovery, Path::new(path), "local account-home lookup")?;
        }
    }
    if Path::new("/etc/ld.so.cache").exists() {
        add_read_file(
            discovery,
            Path::new("/etc/ld.so.cache"),
            "Linux dynamic loader cache",
        )?;
    }
    add_read_tree(
        discovery,
        Path::new("/proc"),
        "Linux process resource sampling",
    )?;
    add_read_file(
        discovery,
        Path::new("/etc/os-release"),
        "supported Linux host profile",
    )?;
    if Path::new("/bin/ps").exists() {
        add_executable(discovery, Path::new("/bin/ps"), "Linux process sampling")?;
    }

    let mut loaders = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
    let mut executable_loader = BTreeMap::<PathBuf, PathBuf>::new();
    let mut dynamic_executables = BTreeSet::new();
    let mut no_interpreter_executables = Vec::new();
    let native_executables: Vec<PathBuf> = discovery.executables.iter().cloned().collect();
    for executable in &native_executables {
        let Some(declared) = elf_interpreter(executable)? else {
            no_interpreter_executables.push(json!({
                "canonical_path": path_text(executable)?,
                "sha256": read_hash(executable)?,
                "runtime_detection": "native_elf_without_pt_interp_static_linkage_not_proven",
            }));
            continue;
        };
        let loader = canonical_file(&declared, true)?;
        loaders
            .entry(loader.clone())
            .or_default()
            .insert(declared.clone());
        executable_loader.insert(executable.clone(), loader.clone());
        discovery.loader_rows.push(json!({
            "consumer": path_text(executable)?,
            "declared_path": path_text(&declared)?,
            "canonical_path": path_text(&loader)?,
            "sha256": read_hash(&loader)?,
            "source": "ELF PT_INTERP",
        }));
        discovery.executables.insert(loader);
        dynamic_executables.insert(executable.clone());
    }

    let mut ldd_rows = Vec::new();
    if !dynamic_executables.is_empty() {
        let ldd = canonical_file(Path::new("/usr/bin/ldd"), true)?;
        for executable in &dynamic_executables {
            let executable_loader_path = executable_loader
                .get(executable)
                .ok_or_else(|| Refusal::new("Linux executable has no recorded PT_INTERP loader"))?;
            let argument = path_text(executable)?;
            let captured = run_query(&ldd, &[argument.as_str()], work, "Linux ldd closure")?;
            let dependencies = parse_ldd_output(&captured.stdout)?;
            if dependencies.is_empty() {
                return Err(Refusal::new(format!(
                    "ldd returned no file-backed runtime inputs for {}",
                    executable.display()
                )));
            }
            let mut dependency_rows = Vec::new();
            for declared in dependencies {
                let lookup = lookup_path(&declared)?;
                let loader_spelling = is_loader_path(&lookup);
                let canonical = canonical_file(&lookup, loader_spelling)?;
                if canonical == *executable_loader_path
                    || loaders.contains_key(&canonical)
                    || loader_spelling
                {
                    loaders
                        .entry(canonical.clone())
                        .or_default()
                        .insert(lookup.clone());
                    discovery.executables.insert(canonical.clone());
                } else {
                    add_library(discovery, &lookup, "Linux ldd runtime dependency")?;
                }
                dependency_rows.push(json!({
                    "lookup_path": path_text(&lookup)?,
                    "canonical_path": path_text(&canonical)?,
                }));
            }
            ldd_rows.push(json!({
                "executable": path_text(executable)?,
                "dependencies": dependency_rows,
            }));
        }
    }
    if !no_interpreter_executables.is_empty() {
        discovery.runtime_rows.push(json!({
            "kind": "linux_elf_without_pt_interp",
            "executables": no_interpreter_executables,
        }));
    }
    if !ldd_rows.is_empty() {
        discovery.runtime_rows.push(json!({
            "kind": "linux_ldd_closure",
            "executables": ldd_rows,
        }));
    }
    for (canonical, declared_paths) in loaders {
        discovery.executables.insert(canonical.clone());
        let sha256 = read_hash(&canonical)?;
        for declared in declared_paths {
            discovery.loader_rows.push(json!({
                "declared_path": path_text(&declared)?,
                "canonical_path": path_text(&canonical)?,
                "sha256": sha256,
            }));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_loader_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("ld-linux") || name.starts_with("ld-"))
}

#[cfg(target_os = "linux")]
fn parse_ldd_output(bytes: &[u8]) -> Result<Vec<PathBuf>> {
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::new("ldd output is not UTF-8"))?;
    let mut paths = BTreeSet::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once("=>") {
            if name.trim().is_empty() || name.trim().chars().any(char::is_whitespace) {
                return Err(Refusal::new(format!("opaque ldd dependency row: {line}")));
            }
            let fields: Vec<&str> = value.split_whitespace().collect();
            if fields.len() == 2 && fields[0] == "not" && fields[1] == "found" {
                return Err(Refusal::new(format!(
                    "unresolved Linux runtime dependency: {line}"
                )));
            }
            if fields.len() != 2 || !valid_ldd_address(fields[1]) {
                return Err(Refusal::new(format!("opaque ldd dependency row: {line}")));
            }
            let path = Path::new(fields[0]);
            if !path.is_absolute() {
                return Err(Refusal::new(format!("opaque ldd dependency path: {line}")));
            }
            paths.insert(path.to_path_buf());
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() == 2 && fields[0] == "linux-vdso.so.1" && valid_ldd_address(fields[1]) {
            continue;
        }
        if fields.len() == 2 && fields[0].starts_with('/') && valid_ldd_address(fields[1]) {
            paths.insert(PathBuf::from(fields[0]));
            continue;
        }
        return Err(Refusal::new(format!("opaque ldd output row: {line}")));
    }
    Ok(paths.into_iter().collect())
}

#[cfg(target_os = "linux")]
fn valid_ldd_address(value: &str) -> bool {
    value
        .strip_prefix("(0x")
        .and_then(|hex| hex.strip_suffix(')'))
        .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(target_os = "linux")]
fn elf_interpreter(path: &Path) -> Result<Option<PathBuf>> {
    let file_len = fs::metadata(path)?.len();
    let mut file = fs::File::open(path)?;
    let mut bytes = [0_u8; 64];
    file.read_exact(&mut bytes)?;
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01".as_slice())
        || !matches!(le_u16(&bytes, 16)?, 2 | 3)
        || le_u16(&bytes, 18)? != 62
    {
        return Err(Refusal::new(format!(
            "runtime executable is not a native ELF64 little-endian x86_64 image: {}",
            path.display()
        )));
    }
    let program_offset = le_u64(&bytes, 32)?;
    let entry_size = le_u16(&bytes, 54)?;
    let count = le_u16(&bytes, 56)?;
    if entry_size != 56 || count == 0 {
        return Err(Refusal::new(
            "ELF program header table has an unsupported shape",
        ));
    }
    let table_bytes = u64::from(count)
        .checked_mul(u64::from(entry_size))
        .ok_or_else(|| Refusal::new("ELF program header table size overflow"))?;
    program_offset
        .checked_add(table_bytes)
        .filter(|end| *end <= file_len)
        .ok_or_else(|| Refusal::new("ELF program header table is out of file bounds"))?;
    let mut interpreter = None;
    for index in 0..count {
        let entry_offset = program_offset
            .checked_add(u64::from(index) * u64::from(entry_size))
            .ok_or_else(|| Refusal::new("ELF program header entry offset overflow"))?;
        file.seek(SeekFrom::Start(entry_offset))?;
        let mut program_header = [0_u8; 56];
        file.read_exact(&mut program_header)?;
        if le_u32(&program_header, 0)? != 3 {
            continue;
        }
        if interpreter.is_some() {
            return Err(Refusal::new(
                "ELF executable has multiple PT_INTERP entries",
            ));
        }
        let start = le_u64(&program_header, 8)?;
        let size = le_u64(&program_header, 32)?;
        start
            .checked_add(size)
            .filter(|limit| *limit <= file_len)
            .ok_or_else(|| Refusal::new("ELF interpreter bytes are out of file bounds"))?;
        if size > MAX_INTERPRETER_BYTES {
            return Err(Refusal::new(
                "ELF PT_INTERP path exceeds its bounded path size",
            ));
        }
        file.seek(SeekFrom::Start(start))?;
        let size = usize::try_from(size)
            .map_err(|_| Refusal::new("ELF PT_INTERP size exceeds host bounds"))?;
        let mut raw = vec![0_u8; size];
        file.read_exact(&mut raw)?;
        if raw.len() < 2 || raw.last() != Some(&0) || raw[..raw.len() - 1].contains(&0) {
            return Err(Refusal::new(
                "ELF PT_INTERP must contain one absolute NUL-terminated path",
            ));
        }
        let value = std::str::from_utf8(&raw[..raw.len() - 1])
            .map_err(|_| Refusal::new("ELF PT_INTERP path is not UTF-8"))?;
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(Refusal::new("ELF PT_INTERP path is not absolute"));
        }
        interpreter = Some(path);
    }
    Ok(interpreter)
}

#[cfg(target_os = "linux")]
fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| Refusal::new("truncated ELF integer"))?
        .try_into()
        .map_err(|_| Refusal::new("truncated ELF integer"))?;
    Ok(u16::from_le_bytes(raw))
}

#[cfg(target_os = "linux")]
fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| Refusal::new("truncated ELF integer"))?
        .try_into()
        .map_err(|_| Refusal::new("truncated ELF integer"))?;
    Ok(u32::from_le_bytes(raw))
}

#[cfg(target_os = "linux")]
fn le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| Refusal::new("truncated ELF integer"))?
        .try_into()
        .map_err(|_| Refusal::new("truncated ELF integer"))?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(target_os = "macos")]
fn discover_macos_selection(
    discovery: &mut Discovery,
    work: &Path,
    build: bool,
    cold_prepare: bool,
) -> Result<()> {
    let selector = canonical_file(Path::new("/usr/bin/xcode-select"), true)?;
    let selected_raw =
        bounded_single_query(discovery, &selector, &["-p"], work, "xcode-select -p")?;
    let selected = macos_host_selection::resolve_selected(Path::new(&selected_raw))
        .map_err(|error| Refusal::new(format!("selected Developer directory refused: {error}")))?;
    add_read_tree(
        discovery,
        Path::new("/private/var/select"),
        "selected Developer metadata read by host tools",
    )?;
    add_executable(discovery, &selector, "macOS developer selection query")?;
    if build {
        add_executable(
            discovery,
            &selected.clang.canonical_path,
            "selected Developer clang",
        )?;
        add_executable(
            discovery,
            &selected.linker.canonical_path,
            "selected Developer linker",
        )?;
        let resource = bounded_single_query(
            discovery,
            &selected.clang.canonical_path,
            &["-print-resource-dir"],
            work,
            "selected clang resource directory",
        )?;
        let resource = add_read_tree(
            discovery,
            Path::new(&resource),
            "selected clang resource headers and modules",
        )?;
        let sdk = add_read_tree(
            discovery,
            &selected.sdk.canonical_path,
            "selected macOS SDK",
        )?;
        for name in [
            "libtapi.dylib",
            "libcodedirectory.dylib",
            "libLTO.dylib",
            "libswiftDemangle.dylib",
        ] {
            let library = selected
                .linker
                .canonical_path
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| Refusal::new("selected linker has no usr directory"))?
                .join("lib")
                .join(name);
            add_library(discovery, &library, "selected Developer linker library")?;
        }
        if Path::new("/private/etc/ssl/openssl.cnf").is_file() {
            add_read_file(
                discovery,
                Path::new("/private/etc/ssl/openssl.cnf"),
                "macOS OpenSSL runtime configuration",
            )?;
        }
        discovery.build_rows.push(json!({
            "kind": "selected_macos_host",
            "layout": selected.layout.as_str(),
            "developer_directory": path_text(&selected.developer_directory.canonical_path)?,
            "sdk": path_text(&sdk)?,
            "clang_resource_directory": path_text(&resource)?,
            "clang": path_text(&selected.clang.canonical_path)?,
            "linker": path_text(&selected.linker.canonical_path)?,
        }));
    }
    if cold_prepare {
        discover_macos_cold_prepare(discovery, work, &selected)?;
    }
    let selected_raw_after_queries = bounded_single_query(
        discovery,
        &selector,
        &["-p"],
        work,
        "xcode-select -p recheck",
    )?;
    let selected_after_queries = macos_host_selection::resolve_selected(Path::new(
        &selected_raw_after_queries,
    ))
    .map_err(|error| Refusal::new(format!("selected Developer directory changed: {error}")))?;
    if selected_after_queries != selected {
        return Err(Refusal::new(
            "selected Developer directory changed during runtime discovery",
        ));
    }
    selected
        .recheck()
        .map_err(|error| Refusal::new(format!("selected Developer identities changed: {error}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn discover_linux_cold_prepare(discovery: &mut Discovery, work: &Path) -> Result<()> {
    discover_cold_commands(discovery, work, true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ami-rust-consumer-runtime-{}-{stamp}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temporary test directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn elf_image(interpreter: &[u8], interpreter_offset: u64) -> Vec<u8> {
        let mut bytes = vec![0_u8; 128 + interpreter.len()];
        bytes[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\0");
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&interpreter_offset.to_le_bytes());
        bytes[96..104].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
        let start = interpreter_offset as usize;
        let end = start.saturating_add(interpreter.len());
        if end <= bytes.len() {
            bytes[start..end].copy_from_slice(interpreter);
        }
        bytes
    }

    fn write_executable(path: &Path, contents: &[u8]) {
        fs::write(path, contents).expect("write test executable");
        let mut permissions = fs::metadata(path)
            .expect("read test executable metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).expect("set executable mode");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pt_interp_checks_absolute_path_nul_and_file_bounds() {
        let temp = Scratch::new();
        let expected = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
        let valid = elf_image(b"/lib64/ld-linux-x86-64.so.2\0", 128);
        let path = temp.0.join("valid-elf");
        write_executable(&path, &valid);
        assert_eq!(
            elf_interpreter(&path).expect("valid PT_INTERP"),
            Some(expected)
        );

        let mut no_interpreter = elf_image(b"/lib64/ld-linux-x86-64.so.2\0", 128);
        no_interpreter[64..68].copy_from_slice(&1_u32.to_le_bytes());
        let path = temp.0.join("no-interpreter");
        write_executable(&path, &no_interpreter);
        assert_eq!(
            elf_interpreter(&path).expect("native ELF without PT_INTERP"),
            None
        );

        let missing_nul = elf_image(b"/lib64/ld-linux-x86-64.so.2", 128);
        let path = temp.0.join("missing-nul");
        write_executable(&path, &missing_nul);
        assert!(elf_interpreter(&path).is_err());

        let embedded_nul = elf_image(b"/lib64\0/ld-linux.so.2\0", 128);
        let path = temp.0.join("embedded-nul");
        write_executable(&path, &embedded_nul);
        assert!(elf_interpreter(&path).is_err());

        let relative = elf_image(b"lib/ld-linux.so.2\0", 128);
        let path = temp.0.join("relative");
        write_executable(&path, &relative);
        assert!(elf_interpreter(&path).is_err());

        let out_of_bounds = elf_image(b"/lib64/ld-linux-x86-64.so.2\0", u64::MAX);
        let path = temp.0.join("out-of-bounds");
        write_executable(&path, &out_of_bounds);
        assert!(elf_interpreter(&path).is_err());

        let duplicate_interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
        let mut duplicate = elf_image(duplicate_interpreter, 176);
        duplicate.resize(176 + duplicate_interpreter.len(), 0);
        duplicate[56..58].copy_from_slice(&2_u16.to_le_bytes());
        duplicate[120..124].copy_from_slice(&3_u32.to_le_bytes());
        duplicate[128..136].copy_from_slice(&176_u64.to_le_bytes());
        duplicate[152..160].copy_from_slice(&(duplicate_interpreter.len() as u64).to_le_bytes());
        duplicate[176..].copy_from_slice(duplicate_interpreter);
        let path = temp.0.join("duplicate-interpreter");
        write_executable(&path, &duplicate);
        assert!(elf_interpreter(&path).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ldd_rows_resolve_paths_and_reject_missing_or_opaque_output() {
        let parsed = parse_ldd_output(
            b"linux-vdso.so.1 (0x00007fff0000)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f001234)\n/lib64/ld-linux-x86-64.so.2 (0x00007f009999)\n",
        )
        .expect("parse ldd closure");
        assert_eq!(
            parsed,
            vec![
                PathBuf::from("/lib/x86_64-linux-gnu/libc.so.6"),
                PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            ]
        );
        assert!(parse_ldd_output(b"libmissing.so => not found\n").is_err());
        assert!(parse_ldd_output(b"unexpected ldd output\n").is_err());
    }

    #[test]
    fn library_lookup_aliases_are_preserved_and_executable_aliases_excluded() {
        let temp = Scratch::new();
        let executable = temp.0.join("tool");
        write_executable(&executable, b"native tool");
        let executable_alias = temp.0.join("tool-as-library");
        symlink(&executable, &executable_alias).expect("create executable alias");

        let library = temp.0.join("libsample.dylib");
        fs::write(&library, b"runtime library").expect("write test library");
        let library_alias = temp.0.join("libsample-lookup.dylib");
        symlink(&library, &library_alias).expect("create library lookup alias");

        let mut discovery = Discovery::default();
        discovery
            .executables
            .insert(canonical_file(&executable, true).expect("canonical executable"));
        add_library(&mut discovery, &executable_alias, "test alias")
            .expect("register executable alias as a candidate library");
        add_library(&mut discovery, &library_alias, "test alias")
            .expect("register library lookup alias");
        exclude_executable_aliases(&mut discovery).expect("separate executable identities");

        assert_eq!(discovery.libraries, BTreeSet::from([library_alias.clone()]));
        assert_eq!(
            fs::canonicalize(discovery.libraries.iter().next().unwrap())
                .expect("canonical retained library"),
            library
        );
        assert!(
            discovery
                .library_aliases
                .iter()
                .any(|row| row["lookup_path"] == path_text(&library_alias).unwrap())
        );
    }
}

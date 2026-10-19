use std::{
    env,
    error::Error,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[allow(dead_code)]
#[path = "../../macos-host-selection.rs"]
mod macos_host_selection;

const CLEAN_PATH: &str = "/usr/bin:/bin";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "macos" {
        return;
    }

    println!("cargo:rerun-if-changed=src/macos_process_snapshot.c");

    if let Err(error) = build_macos_topology_shim() {
        panic!("could not build the bounded macOS process-topology shim: {error}");
    }
}

fn build_macos_topology_shim() -> Result<(), Box<dyn Error>> {
    let target = env::var("TARGET")?;
    let host = env::var("HOST")?;
    if target != "aarch64-apple-darwin" || host != target {
        return Err(format!(
            "the process-topology shim supports native aarch64-apple-darwin only (HOST={host}, TARGET={target})"
        )
        .into());
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or(
        "CARGO_MANIFEST_DIR is unavailable while compiling the macOS process-topology shim",
    )?);
    let selector_source = manifest_dir.join("../../macos-host-selection.rs");
    if !selector_source.is_file() {
        return Err(format!(
            "shared macOS host-selection source is missing: {}",
            selector_source.display()
        )
        .into());
    }
    println!("cargo:rerun-if-changed={}", selector_source.display());
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR")
            .ok_or("OUT_DIR is unavailable while compiling the macOS process-topology shim")?,
    );
    if !out_dir.is_dir() {
        return Err(format!(
            "Cargo output directory does not exist: {}",
            out_dir.display()
        )
        .into());
    }
    // Recheck the active Xcode/SDK on each source build, including when Cargo
    // reuses this output directory after an Xcode switch. A deliberately absent
    // input makes the selected Cargo rerun this small SDK-header compilation;
    // no global SDK setting or caller-provided identity is trusted as a cache key.
    println!(
        "cargo:rerun-if-changed={}",
        out_dir.join("recheck-active-macos-sdk").display()
    );

    let selected_path = query_selected_developer_directory(&manifest_dir, &out_dir)?;
    let selection = macos_host_selection::resolve_selected(&selected_path)?;
    selection.recheck()?;
    let sdk_path = selection.sdk.canonical_path.clone();
    let clang_path = selection.clang.canonical_path.clone();
    if !sdk_path.is_absolute() || !sdk_path.join("usr/include/sys/sysctl.h").is_file() {
        return Err(format!(
            "selected macOS SDK is missing sys/sysctl.h: {}",
            sdk_path.display()
        )
        .into());
    }

    let source = manifest_dir.join("src/macos_process_snapshot.c");
    if !source.is_file() {
        return Err(format!(
            "macOS process-topology source is missing: {}",
            source.display()
        )
        .into());
    }
    let object = out_dir.join("macos_process_snapshot.o");
    let archive = out_dir.join("libami_rust_macos_process_snapshot.a");
    let manifest_prefix = format!(
        "-ffile-prefix-map={}=/ami-rust-core",
        manifest_dir.display()
    );
    let debug_prefix = format!(
        "-fdebug-prefix-map={}=/ami-rust-core",
        manifest_dir.display()
    );
    let macro_prefix = format!(
        "-fmacro-prefix-map={}=/ami-rust-core",
        manifest_dir.display()
    );
    let object_args = [
        OsStr::new("-target"),
        OsStr::new("arm64-apple-macosx26.0"),
        OsStr::new("-mmacosx-version-min=26.0"),
        OsStr::new("-isysroot"),
        sdk_path.as_os_str(),
        OsStr::new("-std=c11"),
        OsStr::new("-O2"),
        OsStr::new("-g0"),
        OsStr::new("-fPIC"),
        OsStr::new("-fno-common"),
        OsStr::new("-fno-ident"),
        OsStr::new("-Wall"),
        OsStr::new("-Wextra"),
        OsStr::new("-Werror"),
        OsStr::new("-c"),
        source.as_os_str(),
        OsStr::new("-o"),
        object.as_os_str(),
        OsStr::new(&manifest_prefix),
        OsStr::new(&debug_prefix),
        OsStr::new(&macro_prefix),
    ];
    let clang_result = run_cleared(
        clang_path.as_os_str(),
        object_args,
        &manifest_dir,
        &out_dir,
        false,
    )?;
    require_success(
        "clang compiling the macOS process-topology shim",
        &clang_result,
    )?;

    if archive.exists() {
        fs::remove_file(&archive)?;
    }
    let archive_args = [OsStr::new("-crs"), archive.as_os_str(), object.as_os_str()];
    // /usr/bin/ar remains the fixed OS archive writer. The selected SDK
    // compiler and SDK are explicit above; ar receives only the new object.
    let ar_result = run_cleared("/usr/bin/ar", archive_args, &manifest_dir, &out_dir, true)?;
    require_success(
        "ar creating the process-topology static archive",
        &ar_result,
    )?;

    selection.recheck()?;
    let selected_after_commands = query_selected_developer_directory(&manifest_dir, &out_dir)?;
    if selected_after_commands != selected_path {
        return Err(format!(
            "selected macOS developer directory changed during shim build: {} -> {}",
            selected_path.display(),
            selected_after_commands.display()
        )
        .into());
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ami_rust_macos_process_snapshot");
    Ok(())
}

fn query_selected_developer_directory(
    manifest_dir: &Path,
    out_dir: &Path,
) -> Result<PathBuf, Box<dyn Error>> {
    let output = run_cleared(
        "/usr/bin/xcode-select",
        [OsStr::new("-p")],
        manifest_dir,
        out_dir,
        false,
    )?;
    require_success("/usr/bin/xcode-select -p", &output)?;
    let output = String::from_utf8(output.stdout)?;
    let selected = output
        .strip_suffix('\n')
        .ok_or("xcode-select output must end in exactly one newline")?;
    if selected.is_empty()
        || selected
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
        || !Path::new(selected).is_absolute()
    {
        return Err(
            "xcode-select output must contain one absolute developer-directory path".into(),
        );
    }
    Ok(PathBuf::from(selected))
}

fn run_cleared<P, I, S>(
    program: P,
    arguments: I,
    current_dir: &Path,
    temporary_dir: &Path,
    deterministic_archive: bool,
) -> Result<Output, Box<dyn Error>>
where
    P: AsRef<OsStr>,
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program.as_ref());
    command
        .args(arguments)
        .current_dir(current_dir)
        .env_clear()
        .env("PATH", CLEAN_PATH)
        .env("LC_ALL", "C")
        .env("TMPDIR", temporary_dir);
    if deterministic_archive {
        command.env("ZERO_AR_DATE", "1");
    }
    Ok(command.output()?)
}

fn require_success(label: &str, output: &Output) -> Result<(), Box<dyn Error>> {
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{label} exited with {}; stdout={:?}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

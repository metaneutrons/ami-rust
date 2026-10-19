use std::{
    env,
    error::Error,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

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
    // xcrun selects the active Xcode/SDK outside Cargo's source tree. Recheck
    // that selection on every source build, including when Cargo reuses this
    // output directory after an Xcode switch. A deliberately absent input
    // makes the selected Cargo rerun this small SDK-header compilation; no
    // global SDK setting or caller-provided identity is trusted as a cache key.
    println!(
        "cargo:rerun-if-changed={}",
        out_dir.join("recheck-active-macos-sdk").display()
    );

    let sdk_result = run_cleared(
        "/usr/bin/xcrun",
        [
            OsStr::new("--sdk"),
            OsStr::new("macosx"),
            OsStr::new("--show-sdk-path"),
        ],
        &manifest_dir,
        &out_dir,
        false,
    )?;
    require_success("xcrun --sdk macosx --show-sdk-path", &sdk_result)?;
    let sdk_path = PathBuf::from(String::from_utf8(sdk_result.stdout)?.trim());
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
        "/usr/bin/clang",
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
    let ar_result = run_cleared("/usr/bin/ar", archive_args, &manifest_dir, &out_dir, true)?;
    require_success(
        "ar creating the process-topology static archive",
        &ar_result,
    )?;

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ami_rust_macos_process_snapshot");
    Ok(())
}

fn run_cleared<I, S>(
    program: &str,
    arguments: I,
    current_dir: &Path,
    temporary_dir: &Path,
    deterministic_archive: bool,
) -> Result<Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
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

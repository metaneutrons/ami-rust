//! Maintainer operations. Producing a draft never authorizes signing/publication.
mod cargo_producer;
mod cargo_storage_probe;
mod cargo_vendor_overlay;
mod consumer_observe;
mod consumer_report;
mod consumer_runtime;
mod historical_prepare_sigterm;
mod legacy_migration_fixture;
mod prepare_sigterm;

use ami_rust_core::{
    Refusal, Result,
    digest::sha256_bytes,
    directory::Directory,
    package::{PackageRuntime, check_native_package_root},
    public_transport::unpack_native_transport,
    publisher::verify_publisher_bundle,
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("ami-rust maintainer task refused: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    match arguments.next().as_deref().and_then(|value| value.to_str()) {
        Some("--cargo-plugin") => cargo_storage_probe::credential_provider(arguments),
        Some("--rc2-git-credential") => cargo_storage_probe::git_credential_helper(arguments),
        Some("cargo-storage-registry-probe") => cargo_storage_probe::run_registry(arguments),
        Some("cargo-storage-probe") => cargo_storage_probe::run(arguments),
        Some("cargo-storage-lifecycle-probe") => cargo_storage_probe::run_lifecycle(arguments),
        Some("cargo-storage-nested-probe") => cargo_storage_probe::run_nested(arguments),
        Some("cargo-storage-git-helper-probe") => cargo_storage_probe::run_git_helper(arguments),
        Some("cargo-storage-concurrent-gc-probe") => {
            cargo_storage_probe::run_concurrent_gc(arguments)
        }
        Some("cargo-repro-producer") => cargo_producer::run(arguments),
        Some("cargo-vendor-overlay") => cargo_vendor_overlay::run(arguments),
        Some("native-package-verify") => run_native_package_verify(arguments),
        Some("native-consumer-observe") => consumer_observe::run(arguments),
        Some("native-prepare-interruption") => prepare_sigterm::run(arguments),
        Some("historical-prepare-interruption") => historical_prepare_sigterm::run(arguments),
        Some("native-legacy-migration-fixture") => legacy_migration_fixture::run(arguments),
        _ => Err(Refusal::new(
            "usage: ami-rust-xtask {--cargo-plugin|--rc2-git-credential|cargo-storage-probe|cargo-storage-lifecycle-probe|cargo-storage-registry-probe|cargo-storage-nested-probe|cargo-storage-concurrent-gc-probe|cargo-storage-git-helper-probe|native-package-verify|native-consumer-observe|native-prepare-interruption|historical-prepare-interruption|native-legacy-migration-fixture|cargo-repro-producer|cargo-vendor-overlay} OPTIONS; composition does not accept a release",
        )),
    }
}

fn run_native_package_verify(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !["--package", "--policy", "--inputs", "--work"]
            .iter()
            .any(|candidate| key == *candidate)
        {
            return Err(Refusal::new("unknown native-package-verify argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("package-verify option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("package-verify options may occur only once"));
        }
    }
    let root = fs::canonicalize(PathBuf::from(take(&mut options, "--package")?))?;
    let policy = PathBuf::from(take(&mut options, "--policy")?);
    let inputs = read_bounded(
        &PathBuf::from(take(&mut options, "--inputs")?),
        2 * 1024 * 1024,
    )?;
    let work = PathBuf::from(take(&mut options, "--work")?);
    let parent = fs::canonicalize(work.parent().unwrap_or(Path::new(".")))?;
    let work = parent.join(
        work.file_name()
            .ok_or_else(|| Refusal::new("verification work must name a fresh directory"))?,
    );
    if work.starts_with(&root) || root.starts_with(&work) {
        return Err(Refusal::new(
            "package verification work must be disjoint from its package",
        ));
    }
    let host = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => ami_rust_core::records::Host::LinuxX86_64,
        ("macos", "aarch64") => ami_rust_core::records::Host::MacosAarch64,
        _ => return Err(Refusal::new("unsupported native verification host")),
    };
    let package = check_native_package_root(
        &root,
        PackageRuntime {
            host,
            cli_version: env!("CARGO_PKG_VERSION"),
        },
    )?;
    let outer =
        ami_rust_core::publisher::outer::verify_outer_package(&package, &policy, &inputs, || {
            false
        })?;
    fs::DirBuilder::new().mode(0o700).create(&work)?;
    let verify = || -> Result<()> {
        let archive = work.join("authenticated-capsule.tar.xz");
        write_new(&archive, outer.archive())?;
        unpack_native_transport(
            fs::File::open(archive)?,
            &outer.record().archive.name,
            &Directory::open(&work)?,
            "inner",
            outer.record(),
            || false,
        )?;
        let inner = verify_publisher_bundle(&work.join("inner"), &policy, || false)?;
        let inner = outer.bind_inner(inner)?;
        println!(
            "{}",
            serde_json::json!({
                "schema":"ami-rust-native-package-publisher-verification-v1", "status":"OUTER_AND_INNER_AUTHENTICATED",
                "host":host, "sdk_version":inner.manifest().version,
                "manifest_sha256":sha256_bytes(inner.raw_manifest()),
                "claim":"Actual native package outer/inner authentication and identity binding only; preparation, no-Python and complete lifecycle acceptance remain separate"
            })
        );
        Ok(())
    };
    verify().map_err(|error| {
        Refusal::new(format!(
            "{error}; verification work retained at {}",
            work.display()
        ))
    })
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > limit {
        return Err(Refusal::new(format!(
            "maintainer input exceeds its format bound: {}",
            path.display()
        )));
    }
    Ok(raw)
}

fn take(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<OsString> {
    options
        .remove(std::ffi::OsStr::new(name))
        .ok_or_else(|| Refusal::new(format!("missing {name}")))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

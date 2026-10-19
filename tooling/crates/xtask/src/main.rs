//! Maintainer operations. Producing a draft never authorizes signing/publication.
mod consumer_observe;
mod consumer_report;
mod consumer_runtime;
mod native_notices;
mod native_outer;
mod native_package;
mod native_release;
mod sdk;

use ami_rust_core::{
    Refusal, Result,
    compression::{DecodeLimits, copy_xz},
    digest::sha256_bytes,
    directory::Directory,
    json::{JsonProfile, parse_json_value},
    package::{PackageRuntime, check_native_package_root},
    package_records::parse_native_package_pins,
    public_transport::{parse_native_transport_record, unpack_native_transport},
    publisher::verify_publisher_bundle,
    publisher_files::read_bundle_file,
    publisher_tar::{ExpectedFile, verify_publisher_sdk_tar},
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
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
        Some("native-sdk") => run_native_sdk(arguments),
        Some("native-release") => run_native_release(arguments),
        Some("native-package") => run_native_package(arguments),
        Some("native-outer") => run_native_outer(arguments),
        Some("native-outer-finalize") => run_native_outer_finalize(arguments),
        Some("native-package-verify") => run_native_package_verify(arguments),
        Some("native-consumer-observe") => consumer_observe::run(arguments),
        _ => Err(Refusal::new(
            "usage: ami-rust-xtask {native-sdk|native-release|native-package|native-outer|native-outer-finalize|native-package-verify|native-consumer-observe} OPTIONS; composition does not accept a release",
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

fn run_native_outer_finalize(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !["--output", "--sdk-version"]
            .iter()
            .any(|candidate| key == *candidate)
        {
            return Err(Refusal::new("unknown native-outer-finalize argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("outer-finalize option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("outer-finalize options may occur only once"));
        }
    }
    let root = fs::canonicalize(PathBuf::from(take(&mut options, "--output")?))?;
    let version = take(&mut options, "--sdk-version")?
        .into_string()
        .map_err(|_| Refusal::new("SDK version is not UTF-8"))?;
    let archive = format!("ami-rust-{version}-release.tar.xz");
    let transport = format!("ami-rust-{version}-transport.json");
    let sbom = format!("{archive}.spdx.json");
    let payload = read_directory_map(&root)?;
    let required = std::collections::BTreeSet::from([
        archive.clone(),
        transport.clone(),
        sbom.clone(),
        format!("{archive}.sigstore.json"),
        format!("{transport}.sigstore.json"),
    ]);
    if payload
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != required
    {
        return Err(Refusal::new(
            "outer finalization requires exactly the five prepared assets",
        ));
    }
    for name in [
        format!("{archive}.sigstore.json"),
        format!("{transport}.sigstore.json"),
    ] {
        let parsed = parse_json_value(
            &payload[&name],
            JsonProfile::PublisherPolicyAndAuthenticationMetadata,
        )?;
        if parsed.as_object().is_none_or(|object| object.is_empty()) {
            return Err(Refusal::new(
                "outer signature is not a nonempty JSON object",
            ));
        }
    }
    let record = parse_native_transport_record(&payload[&transport])?;
    unpack_native_transport(
        fs::File::open(root.join(&archive))?,
        &archive,
        &Directory::open(&root)?,
        ".native-finalize-readback",
        &record,
        || false,
    )?;
    let readback = root.join(".native-finalize-readback");
    let inner = read_directory_map(&readback)?;
    let manifest = ami_rust_core::release_manifest::parse_native_release_manifest(
        inner
            .get("release.json")
            .ok_or_else(|| Refusal::new("outer capsule has no release manifest"))?,
        true,
    )?;
    if manifest.version != version || inner.get("sbom.spdx.json") != payload.get(&sbom) {
        return Err(Refusal::new(
            "outer version or SBOM differs from the packed native release",
        ));
    }
    let sbom_pin = manifest
        .assets
        .iter()
        .find(|row| row.path == "sbom.spdx.json")
        .ok_or_else(|| Refusal::new("native release has no SPDX asset pin"))?;
    if sbom_pin.bytes != payload[&sbom].len() as u64
        || sbom_pin.sha256.as_str() != sha256_bytes(&payload[&sbom])
    {
        return Err(Refusal::new(
            "outer SPDX differs from the native manifest asset pin",
        ));
    }
    fs::remove_dir_all(readback)?;
    let checksums = payload
        .iter()
        .map(|(name, raw)| format!("{}  {name}\n", sha256_bytes(raw)))
        .collect::<String>();
    write_new(&root.join("SHA256SUMS"), checksums.as_bytes())?;
    println!(
        "{}",
        serde_json::json!({
            "schema":"ami-rust-native-outer-finalized-v1", "status":"CHECKSUMS_BOUND_SIGNATURES_UNVERIFIED",
            "sdk_version":version, "checksums_sha256":sha256_bytes(checksums.as_bytes()),
            "claim":"Exact six-asset byte inventory only; real outer verification and release acceptance remain separate"
        })
    );
    Ok(())
}

fn run_native_outer(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !["--bundle", "--policy", "--output"]
            .iter()
            .any(|candidate| key == *candidate)
        {
            return Err(Refusal::new("unknown native-outer argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("native-outer option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("native-outer options may occur only once"));
        }
    }
    let bundle = fs::canonicalize(PathBuf::from(take(&mut options, "--bundle")?))?;
    let policy = PathBuf::from(take(&mut options, "--policy")?);
    let output = PathBuf::from(take(&mut options, "--output")?);
    let parent = fs::canonicalize(output.parent().unwrap_or(Path::new(".")))?;
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| Refusal::new("output must name a fresh directory"))?,
    );
    if output.starts_with(&bundle) || bundle.starts_with(&output) {
        return Err(Refusal::new(
            "native outer output must be disjoint from its inner bundle",
        ));
    }
    let before = read_directory_map(&bundle)?;
    let policy_raw = read_bounded(&policy, 2 * 1024 * 1024)?;
    let verified = verify_publisher_bundle(&bundle, &policy, || false)?;
    if read_bounded(&policy, 2 * 1024 * 1024)? != policy_raw {
        return Err(Refusal::new(
            "publisher policy changed across native outer verification",
        ));
    }
    let runs = &verified.authentication().report.workflow_runs;
    if runs.len() != 1 || runs[0].host_profile != ami_rust_core::records::Host::LinuxX86_64 {
        return Err(Refusal::new(
            "native outer candidate requires the common Linux-signed inner bundle",
        ));
    }
    if read_directory_map(&bundle)? != before {
        return Err(Refusal::new(
            "inner bundle changed across publisher verification",
        ));
    }
    let draft = native_outer::prepare_native_outer(&before, &policy_raw)?;
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let write = || -> Result<()> {
        for (name, raw) in &draft.assets {
            write_new(&output.join(name), raw)?;
        }
        let version = &verified.manifest().version;
        let archive_name = format!("ami-rust-{version}-release.tar.xz");
        let record_name = format!("ami-rust-{version}-transport.json");
        let record = parse_native_transport_record(&draft.assets[&record_name])?;
        // Exercise the actual consumer extractor against the produced archive,
        // rather than accepting the producer's own inventory as readback proof.
        let receipt = unpack_native_transport(
            fs::File::open(output.join(&archive_name))?,
            &archive_name,
            &Directory::open(&output)?,
            ".native-readback",
            &record,
            || false,
        )?;
        let readback = output.join(".native-readback");
        if read_directory_map(&readback)? != before {
            return Err(Refusal::new(
                "native transport readback differs from its authenticated inner bundle",
            ));
        }
        fs::remove_dir_all(readback)?;
        println!(
            "{}",
            serde_json::json!({
                "schema":"ami-rust-native-outer-draft-v1", "status":"INNER_AUTHENTICATED_OUTER_UNSIGNED",
                "sdk_version":version, "inner_manifest_sha256":sha256_bytes(verified.raw_manifest()),
                "transport_sha256":sha256_bytes(&draft.assets[&record_name]),
                "readback_files":receipt.files.len(),
                "claim":"Inner publisher verification and exact native transport readback only; outer signatures, package lifecycle and release acceptance remain separate"
            })
        );
        Ok(())
    };
    write().map_err(|error| {
        Refusal::new(format!(
            "{error}; partial outer draft retained at {}",
            output.display()
        ))
    })
}

fn run_native_package(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if ![
            "--pins",
            "--proof-index",
            "--launcher",
            "--assets",
            "--proofs",
            "--notices",
            "--output",
        ]
        .iter()
        .any(|candidate| key == *candidate)
        {
            return Err(Refusal::new("unknown native-package argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("native-package option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("native-package options may occur only once"));
        }
    }
    let pins_raw = read_bounded(
        &PathBuf::from(take(&mut options, "--pins")?),
        2 * 1024 * 1024,
    )?;
    let proofs_raw = read_bounded(
        &PathBuf::from(take(&mut options, "--proof-index")?),
        2 * 1024 * 1024,
    )?;
    let pins = parse_native_package_pins(&pins_raw)?;
    let launcher = read_bounded(
        &PathBuf::from(take(&mut options, "--launcher")?),
        128 * 1024 * 1024,
    )?;
    let mut roots = Vec::new();
    let mut maps = Vec::new();
    for name in ["--assets", "--proofs", "--notices"] {
        let root = fs::canonicalize(PathBuf::from(take(&mut options, name)?))?;
        maps.push(read_directory_map(&root)?);
        roots.push(root);
    }
    let output = PathBuf::from(take(&mut options, "--output")?);
    let parent = fs::canonicalize(output.parent().unwrap_or(Path::new(".")))?;
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| Refusal::new("output must name a fresh directory"))?,
    );
    if roots
        .iter()
        .any(|input| output.starts_with(input) || input.starts_with(&output))
    {
        return Err(Refusal::new(
            "native package output must be disjoint from its inputs",
        ));
    }
    let draft = native_package::assemble_native_package(
        &pins_raw,
        &proofs_raw,
        &launcher,
        &maps[0],
        &maps[1],
        &maps[2],
    )?;
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let write = || -> Result<()> {
        for (path, contents) in &draft.files {
            let destination = output.join(path);
            fs::create_dir_all(
                destination
                    .parent()
                    .ok_or_else(|| Refusal::new("package file has no parent"))?,
            )?;
            write_new(&destination, contents)?;
            fs::set_permissions(
                &destination,
                fs::Permissions::from_mode(native_package::native_package_file_mode(path)),
            )?;
        }
        let checked = check_native_package_root(
            &output,
            PackageRuntime {
                host: pins.host,
                cli_version: &pins.cli_version,
            },
        )?;
        println!(
            "{}",
            serde_json::json!({
                "schema":"ami-rust-native-package-draft-v1", "status":"BYTE_CONSISTENT_PACKAGE_DRAFT",
                "host":pins.host, "package_version":pins.package_version,
                "inventory_sha256":sha256_bytes(checked.raw_inventory()),
                "files":draft.files.len(),
                "claim":"Native package consistency only; publisher authentication, consumer qualification and release acceptance remain separate"
            })
        );
        Ok(())
    };
    write().map_err(|error| {
        Refusal::new(format!(
            "{error}; partial package retained at {}",
            output.display()
        ))
    })
}

/// Read a bounded producer input tree through the same descriptor-relative
/// file reader as consumers. Links and special files never become draft data.
fn read_directory_map(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let root = Directory::open(path)?;
    let mut pending = vec![String::new()];
    let mut files = BTreeMap::new();
    let mut entries = 0_usize;
    let mut total = 0_usize;
    while let Some(relative) = pending.pop() {
        let directory = root.relative_directory(&relative)?;
        for name in directory.names(16_384 - entries)? {
            entries += 1;
            let name_str = name
                .to_str()
                .ok_or_else(|| Refusal::new("producer path is not UTF-8"))?;
            let child = if relative.is_empty() {
                name_str.to_owned()
            } else {
                format!("{relative}/{name_str}")
            };
            let kind = fs::symlink_metadata(path.join(&child))?.file_type();
            if kind.is_dir() {
                pending.push(child);
            } else if kind.is_file() {
                let raw = read_bundle_file(&root, &child, 128 * 1024 * 1024)?;
                total = total
                    .checked_add(raw.len())
                    .ok_or_else(|| Refusal::new("producer input byte overflow"))?;
                if total > 512 * 1024 * 1024 {
                    return Err(Refusal::new("producer tree exceeds package profile"));
                }
                files.insert(child, raw);
            } else {
                return Err(Refusal::new(
                    "producer tree contains a link or special file",
                ));
            }
        }
    }
    Ok(files)
}

fn run_native_sdk(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !["--source-sdk", "--source-commit", "--version", "--output"]
            .iter()
            .any(|candidate| key == *candidate)
        {
            return Err(Refusal::new("unknown native-sdk argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("native-sdk option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("native-sdk options may occur only once"));
        }
    }
    let source = PathBuf::from(take(&mut options, "--source-sdk")?);
    let output = PathBuf::from(take(&mut options, "--output")?);
    let commit = take(&mut options, "--source-commit")?
        .into_string()
        .map_err(|_| Refusal::new("source commit must be UTF-8"))?;
    let version = take(&mut options, "--version")?
        .into_string()
        .map_err(|_| Refusal::new("SDK version must be UTF-8"))?;
    let members = read_legacy_sdk(&source)?;
    let draft = sdk::assemble_native_sdk(&members, &commit, &version)?;
    let parent = fs::canonicalize(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| Refusal::new("output must name a fresh directory"))?,
    );
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let write = || -> Result<()> {
        write_new(&output.join("sdk.tar.xz"), &draft.archive)?;
        write_new(&output.join("sdk-manifest.json"), &draft.manifest)?;
        let summary = serde_json::json!({
            "schema":"ami-rust-native-sdk-draft-v1", "status":"UNSIGNED_DRAFT",
            "version":version, "source_identity":commit, "sdk_manifest_sha256":draft.manifest_sha256,
            "archive":{"path":"sdk.tar.xz","bytes":draft.archive.len(),"sha256":sha256_bytes(&draft.archive)},
            "files":draft.files.len(),
            "claim":"Unchanged target/component inputs assembled into SDK-v2; no producer authentication, host launcher binding, native qualification, signing or publication established"
        });
        write_new(
            &output.join("native-sdk-draft.json"),
            &serde_json::to_vec_pretty(&summary).map_err(|e| Refusal::new(e.to_string()))?,
        )?;
        println!("{}", summary);
        Ok(())
    };
    write().map_err(|error| {
        Refusal::new(format!(
            "{error}; partial draft retained at {}",
            output.display()
        ))
    })
}

fn run_native_release(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if ![
            "--source-bundle",
            "--source-commit",
            "--version",
            "--linux-cli",
            "--macos-cli",
            "--producer-file",
            "--native-notices",
            "--output",
        ]
        .iter()
        .any(|candidate| key == *candidate)
        {
            return Err(Refusal::new("unknown native-release argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("native-release option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("native-release options may occur only once"));
        }
    }
    let source = fs::canonicalize(PathBuf::from(take(&mut options, "--source-bundle")?))?;
    let output = PathBuf::from(take(&mut options, "--output")?);
    let commit = take(&mut options, "--source-commit")?
        .into_string()
        .map_err(|_| Refusal::new("source commit must be UTF-8"))?;
    let version = take(&mut options, "--version")?
        .into_string()
        .map_err(|_| Refusal::new("SDK version must be UTF-8"))?;
    let linux = PathBuf::from(take(&mut options, "--linux-cli")?);
    let macos = PathBuf::from(take(&mut options, "--macos-cli")?);
    let producer_path = PathBuf::from(take(&mut options, "--producer-file")?);
    let notices_root = fs::canonicalize(PathBuf::from(take(&mut options, "--native-notices")?))?;
    let notices = read_directory_map(&notices_root)?;
    let parent = fs::canonicalize(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| Refusal::new("output must name a fresh directory"))?,
    );
    if output.starts_with(&source)
        || source.starts_with(&output)
        || fs::symlink_metadata(&output).is_ok()
    {
        return Err(Refusal::new(
            "native release output must be fresh and disjoint from the accepted input bundle",
        ));
    }
    let manifest = read_bounded(&source.join("release.json"), 4 * 1024 * 1024)?;
    let mut assets = BTreeMap::new();
    for path in native_release::legacy_preservation_paths(&manifest)? {
        assets.insert(
            path.clone(),
            read_bounded(&source.join(path), 16 * 1024 * 1024)?,
        );
    }
    let sdk = sdk::assemble_native_sdk(
        &read_legacy_sdk(&source.join("sdk.tar.xz"))?,
        &commit,
        &version,
    )?;
    let launchers = BTreeMap::from([
        (
            "linux-x86_64".to_owned(),
            read_bounded(&linux, 16 * 1024 * 1024)?,
        ),
        (
            "macos-aarch64".to_owned(),
            read_bounded(&macos, 16 * 1024 * 1024)?,
        ),
    ]);
    let producer = parse_json_value(
        &read_bounded(&producer_path, 2 * 1024 * 1024)?,
        JsonProfile::SdkComponentManifest,
    )?;
    let draft = native_release::assemble_native_release_v2(
        &manifest, &assets, &sdk, &launchers, &producer,
    )?;
    let draft = native_notices::bind_native_notices(draft, &notices)?;
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    let write = || -> Result<()> {
        for (path, bytes) in &draft.assets {
            let destination = output.join(path);
            fs::create_dir_all(
                destination
                    .parent()
                    .ok_or_else(|| Refusal::new("asset has no parent"))?,
            )?;
            write_new(&destination, bytes)?;
        }
        write_new(&output.join("release.json"), &draft.manifest)?;
        // The output bundle has a closed inventory. Draft commentary goes to
        // stdout instead of creating an unbound file inside that inventory.
        println!(
            "{}",
            serde_json::json!({
                "schema":"ami-rust-native-release-draft-v1", "status":"UNSIGNED_DRAFT",
                "version":version, "source_identity":commit,
                "release_manifest_sha256":draft.manifest_sha256,
                "sdk_manifest_sha256":sdk.manifest_sha256, "assets":draft.assets.len(),
                "claim":"Declared identities and byte inventories only; no authentication, qualification, signing or publication established"
            })
        );
        Ok(())
    };
    write().map_err(|error| {
        Refusal::new(format!(
            "{error}; partial draft retained at {}",
            output.display()
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

/// This is a maintainer input reader, never a consumer legacy driver. The
/// selected payload is checked again against the immutable target baseline.
fn read_legacy_sdk(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    const LIMIT: usize = 16 * 1024 * 1024;
    let mut compressed = Vec::new();
    fs::File::open(path)?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut compressed)?;
    // This migration input is the immutable accepted SDK archive, including
    // its original legal notices. Checking only the copied target files would
    // leave other retained asset bytes outside the compiled baseline pin.
    let baseline = parse_json_value(
        include_bytes!("../../../fixtures/accepted-r1-inputs.json"),
        JsonProfile::SdkComponentManifest,
    )?;
    let pin = &baseline["accepted_release"]["sdk_archive"];
    if pin["bytes"].as_u64() != Some(compressed.len() as u64)
        || pin["sha256"].as_str() != Some(sha256_bytes(&compressed).as_str())
    {
        return Err(Refusal::new(
            "source SDK archive differs from the immutable accepted baseline",
        ));
    }
    let mut decoded = Vec::new();
    copy_xz(
        &compressed,
        &mut decoded,
        DecodeLimits {
            max_compressed_bytes: LIMIT,
            max_decoded_bytes: LIMIT,
            max_xz_memory_kib: 64 * 1024,
        },
    )?;
    let mut archive = tar::Archive::new(decoded.as_slice());
    let mut members = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || members.len() >= 1_000 {
            return Err(Refusal::new(
                "source SDK must contain at most 1000 regular files",
            ));
        }
        let path = entry
            .path()?
            .to_str()
            .ok_or_else(|| Refusal::new("source SDK member is not UTF-8"))?
            .to_owned();
        ami_rust_core::files::validate_relative_inventory_path(&path)?;
        let mut raw = Vec::new();
        entry.read_to_end(&mut raw)?;
        if members.insert(path, raw).is_some() {
            return Err(Refusal::new("duplicate source SDK member"));
        }
    }
    let raw = members
        .get("contract/sdk.json")
        .ok_or_else(|| Refusal::new("source SDK omits its manifest"))?;
    let manifest = parse_json_value(raw, JsonProfile::SdkComponentManifest)?;
    if manifest["schema"] != "ami-rust-sdk-v1"
        || manifest["version"] != "0.1.0"
        || manifest["qualification_only"] != false
    {
        return Err(Refusal::new(
            "draft input must be the historical production SDK-v1 source format",
        ));
    }
    let rows = manifest["files"]
        .as_array()
        .ok_or_else(|| Refusal::new("source SDK inventory missing"))?;
    let mut expected = Vec::new();
    for row in rows {
        let path = row["path"]
            .as_str()
            .ok_or_else(|| Refusal::new("source SDK member path missing"))?;
        if path == "contract/sdk.json" {
            return Err(Refusal::new("source SDK has a self-referential inventory"));
        }
        let size = row["bytes"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| Refusal::new("source SDK member size invalid"))?;
        let sha = row["sha256"]
            .as_str()
            .ok_or_else(|| Refusal::new("source SDK member digest missing"))?;
        expected.push(ExpectedFile {
            path,
            size,
            sha256: sha,
        });
    }
    let manifest_sha = sha256_bytes(raw);
    expected.push(ExpectedFile {
        path: "contract/sdk.json",
        size: raw.len(),
        sha256: &manifest_sha,
    });
    verify_publisher_sdk_tar(&decoded, &expected)?;
    Ok(members)
}

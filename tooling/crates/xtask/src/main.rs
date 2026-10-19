//! Maintainer operations. Producing a draft never authorizes signing/publication.
mod native_release;
mod sdk;

use ami_rust_core::{
    Refusal, Result,
    compression::{DecodeLimits, copy_xz},
    digest::sha256_bytes,
    json::{JsonProfile, parse_json_value},
    publisher_tar::{ExpectedFile, verify_publisher_sdk_tar},
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
        Some("native-sdk") => run_native_sdk(arguments),
        Some("native-release") => run_native_release(arguments),
        _ => Err(Refusal::new(
            "usage: ami-rust-xtask {native-sdk|native-release} OPTIONS; outputs are unsigned drafts",
        )),
    }
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

//! Internal pre-signing byte check. This never installs, signs or publishes.

use ami_rust_core::{
    Refusal, Result,
    digest::sha256_bytes,
    files::read_regular_bounded,
    json::{JsonProfile, parse_json_value},
    toolchain_release::{
        RustupManifestFiles, RustupManifestRequest, parse_toolchain_release,
        render_rustup_manifest, verify_unsigned_payloads,
    },
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::PathBuf,
    time::{Duration, Instant},
};

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let started = Instant::now();
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if key != "--inventory" && key != "--payloads" && key != "--rustup-request" {
            return Err(usage());
        }
        let value = arguments.next().ok_or_else(usage)?;
        if options.insert(key, value).is_some() {
            return Err(usage());
        }
    }
    if let Some(request) = options.remove(std::ffi::OsStr::new("--rustup-request")) {
        if !options.is_empty() {
            return Err(usage());
        }
        let raw = read_regular_bounded(
            &PathBuf::from(request),
            JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes(),
        )?;
        let rendered = render_request(&raw)?;
        println!(
            "{}",
            serde_json::json!({
                "schema":"ami-rust-rustup-manifest-render-v1", "status":"UNSIGNED_METADATA_ONLY",
                "request_sha256":sha256_bytes(&raw), "files":rendered,
                "claim":"Canonical metadata from declarations only; no archive verification, install, source/publisher authentication, signing or publication."
            })
        );
        return Ok(());
    }
    let inventory = PathBuf::from(
        options
            .remove(std::ffi::OsStr::new("--inventory"))
            .ok_or_else(usage)?,
    );
    let payloads = PathBuf::from(
        options
            .remove(std::ffi::OsStr::new("--payloads"))
            .ok_or_else(usage)?,
    );
    let raw = read_regular_bounded(
        &inventory,
        JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes(),
    )?;
    let release = parse_toolchain_release(&raw)?;
    let readback = verify_unsigned_payloads(&payloads, &release, || {
        if started.elapsed() >= Duration::from_secs(1200) {
            Err(Refusal::new(
                "toolchain inventory readback exceeded its 1200-second deadline",
            ))
        } else {
            Ok(())
        }
    })?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "ami-rust-toolchain-inventory-readback-v1",
            "status": "UNSIGNED_PAYLOADS_MATCH_INVENTORY",
            "inventory_sha256": sha256_bytes(&raw),
            "readback": readback,
            "publication_order_claim": release.publication_order()?,
            "expected_final_assets": release.expected_assets(),
            "claim": "Pre-signing file bytes and inventory shape only. Actual packaged crate dependency/identity binding, publisher ownership, signatures, provenance, complete signed candidate and RC3 acceptance remain required. No install, network, signing or publication performed."
        })
    );
    Ok(())
}

fn render_request(raw: &[u8]) -> Result<RustupManifestFiles> {
    let value = parse_json_value(raw, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let request: RustupManifestRequest = serde_json::from_value(value)
        .map_err(|error| Refusal::new(format!("invalid rustup manifest request: {error}")))?;
    render_rustup_manifest(&request)
}

fn usage() -> Refusal {
    Refusal::new(
        "usage: ami-rust-xtask toolchain-release-inventory (--inventory FILE --payloads DIRECTORY | --rustup-request FILE)",
    )
}

#[cfg(test)]
mod tests {
    use super::render_request;
    #[test]
    fn canonical_manifest_matches_frozen_fixture() {
        let request = include_bytes!("../../../fixtures/rustup-manifest-request-v1.json");
        let rendered = render_request(request).unwrap();
        assert_eq!(
            rendered.manifest,
            include_str!("../../../fixtures/rustup-manifest-v1.toml")
        );
        assert_eq!(rendered.manifest_name, "channel-rust-0.2.0.toml");
        assert_eq!(
            rendered.checksum,
            format!(
                "{}  channel-rust-0.2.0.toml\n",
                ami_rust_core::digest::sha256_bytes(rendered.manifest.as_bytes())
            )
        );
    }
    #[test]
    fn duplicate_json_and_unknown_fields_refuse() {
        let raw = include_str!("../../../fixtures/rustup-manifest-request-v1.json");
        assert!(
            render_request(format!("{{\"version\":\"0.2.0\",{}", &raw[1..]).as_bytes()).is_err()
        );
        let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
        value["untrusted_url"] = serde_json::json!("https://attacker.invalid");
        assert!(render_request(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

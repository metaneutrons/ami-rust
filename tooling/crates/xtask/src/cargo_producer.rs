//! Internal maintainer entrypoint for the pinned host Cargo producer.

use ami_rust_core::{
    Refusal, Result,
    cargo_producer::{self, Phase, ProducerOptions, Profile},
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::PathBuf,
};

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let phase = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| match value.as_str() {
            "provision" => Some(Phase::Provision),
            "build" => Some(Phase::Build),
            _ => None,
        })
        .ok_or_else(usage)?;
    let mut options = BTreeMap::new();
    let mut share_supervisor_group = false;
    while let Some(key) = arguments.next() {
        if key == "--share-supervisor-group" {
            if share_supervisor_group {
                return Err(Refusal::new(
                    "producer options may occur only once: --share-supervisor-group",
                ));
            }
            share_supervisor_group = true;
            continue;
        }
        if ![
            "--source",
            "--host-rust",
            "--work",
            "--vendor",
            "--record",
            "--recipe",
            "--vendor-overlay-receipt",
            "--resource-policy",
            "--profile",
        ]
        .iter()
        .any(|candidate| key == *candidate)
        {
            return Err(Refusal::new("unknown cargo-repro-producer argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("cargo-repro-producer option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new(
                "cargo-repro-producer options may occur only once",
            ));
        }
    }
    for required in [
        "--source",
        "--host-rust",
        "--work",
        "--vendor",
        "--record",
        "--recipe",
    ] {
        if !options.contains_key(OsStr::new(required)) {
            return Err(usage());
        }
    }
    let profile_name = options
        .remove(OsStr::new("--profile"))
        .map(|value| value.into_string())
        .transpose()
        .map_err(|_| Refusal::new("producer profile is not UTF-8"))?;
    let profile = match profile_name.as_deref().unwrap_or("dev") {
        "dev" => Profile::Dev,
        "release" => Profile::Release,
        _ => return Err(Refusal::new("producer profile must be dev or release")),
    };
    let request = ProducerOptions {
        phase,
        source: PathBuf::from(take(&mut options, "--source")?),
        host_rust: PathBuf::from(take(&mut options, "--host-rust")?),
        work: PathBuf::from(take(&mut options, "--work")?),
        vendor: PathBuf::from(take(&mut options, "--vendor")?),
        record: PathBuf::from(take(&mut options, "--record")?),
        recipe: PathBuf::from(take(&mut options, "--recipe")?),
        vendor_overlay_receipt: options
            .remove(OsStr::new("--vendor-overlay-receipt"))
            .map(PathBuf::from),
        resource_policy: options
            .remove(OsStr::new("--resource-policy"))
            .map(PathBuf::from),
        profile,
        share_supervisor_group,
    };
    if !options.is_empty() {
        return Err(Refusal::new("unrecognized cargo-repro-producer options"));
    }
    cargo_producer::produce(request)?;
    Ok(())
}

fn take(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<OsString> {
    options.remove(OsStr::new(name)).ok_or_else(usage)
}

fn usage() -> Refusal {
    Refusal::new(
        "usage: ami-rust-xtask cargo-repro-producer {provision|build} --source PATH --host-rust PATH --work PATH --vendor PATH --record PATH --recipe DIR [--resource-policy JSON] [--vendor-overlay-receipt JSON] [--profile dev|release] [--share-supervisor-group]",
    )
}

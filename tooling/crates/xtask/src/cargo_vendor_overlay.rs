//! Internal Cargo vendor overlay maintainer command.

use ami_rust_core::{
    Refusal, Result,
    cargo_vendor_overlay::{prepare_overlay, verify_overlay},
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::PathBuf,
};

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let operation = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;
    let allowed: &[&str] = match operation.as_str() {
        "prepare" => &[
            "--source-vendor",
            "--output-vendor",
            "--receipt",
            "--recipe",
        ],
        "verify" => &["--vendor", "--receipt", "--recipe"],
        _ => return Err(usage()),
    };
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !allowed.iter().any(|candidate| key == *candidate) {
            return Err(Refusal::new("unknown cargo-vendor-overlay argument"));
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("cargo-vendor-overlay option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new(
                "cargo-vendor-overlay options may occur only once",
            ));
        }
    }
    if options.len() != allowed.len() {
        return Err(usage());
    }
    let recipe = PathBuf::from(take(&mut options, "--recipe")?);
    let summary = match operation.as_str() {
        "prepare" => prepare_overlay(
            &PathBuf::from(take(&mut options, "--source-vendor")?),
            &PathBuf::from(take(&mut options, "--output-vendor")?),
            &PathBuf::from(take(&mut options, "--receipt")?),
            &recipe,
        )?,
        "verify" => verify_overlay(
            &PathBuf::from(take(&mut options, "--vendor")?),
            &PathBuf::from(take(&mut options, "--receipt")?),
            &recipe,
        )?,
        _ => unreachable!("operation was validated"),
    };
    println!("{summary}");
    Ok(())
}

fn take(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<OsString> {
    options
        .remove(OsStr::new(name))
        .ok_or_else(|| Refusal::new(format!("missing {name}")))
}

fn usage() -> Refusal {
    Refusal::new(
        "usage: ami-rust-xtask cargo-vendor-overlay {prepare --source-vendor PATH --output-vendor PATH --receipt PATH --recipe DIR|verify --vendor PATH --receipt PATH --recipe DIR}",
    )
}

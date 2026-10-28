//! Internal maintainer entrypoint for one-command native qualification.

use ami_rust_core::{
    Refusal, Result, files::read_regular_bounded, json::JsonProfile, qualification_command,
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::PathBuf,
};

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if key != "--request" && key != "--record" {
            return Err(usage());
        }
        let value = arguments
            .next()
            .ok_or_else(|| Refusal::new("qualification option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new("qualification options may occur only once"));
        }
    }
    if options.len() != 2 {
        return Err(usage());
    }
    let request_path = PathBuf::from(take(&mut options, "--request")?);
    let record_path = PathBuf::from(take(&mut options, "--record")?);
    let raw = read_regular_bounded(
        &request_path,
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let request = qualification_command::parse_request(&raw)?;
    let record = qualification_command::run_and_record(&request, &raw, &record_path)?;

    if record.passed && record.result_published {
        println!(
            "{}",
            serde_json::json!({
                "schema":"ami-rust-native-command-qualification-result-v1",
                "passed":true,
                "request_sha256":record.request_sha256,
                "record":record_path.join("result.json").display().to_string()
            })
        );
        Ok(())
    } else {
        let reason = record
            .refusal
            .as_deref()
            .unwrap_or("command qualification refused");
        let retained = if record.result_published {
            format!(
                "logs and final refusal record retained at {}",
                record_path.display()
            )
        } else if record.pending_retained {
            format!(
                "logs and nonauthoritative pending report retained at {}",
                record_path.display()
            )
        } else {
            format!(
                "logs retained at {}; no report was committed",
                record_path.display()
            )
        };
        Err(Refusal::new(format!("{reason}; {retained}"))
            .with_exit_code(u8::try_from(record.cli_exit_code()).unwrap_or(2)))
    }
}

fn take(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<OsString> {
    options.remove(OsStr::new(name)).ok_or_else(usage)
}

fn usage() -> Refusal {
    Refusal::new("usage: ami-rust-xtask qualification-command --request JSON --record DIR")
}

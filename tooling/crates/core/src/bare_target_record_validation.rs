//! Readback validation for the five retained bare-target producer commands.
//!
//! This internal module validates one producer's raw command records. It does
//! not run commands or qualify a complete producer, SDK, or release.

use crate::{
    Refusal, Result,
    digest::{encode_hex, is_sha256_digest, sha256_bytes},
    files::{open_regular_nofollow, read_regular_bounded, validate_relative_inventory_path},
    json::{JsonProfile, parse_json_value},
    qualification_command::{CommandBudgets, CommandRequest, parse_request},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

pub const INNER_COMMAND_LABELS: [&str; 5] = [
    "rustc-version",
    "rustc-sysroot",
    "cargo-version",
    "rust-objcopy-version",
    "source-production",
];

pub const INNER_LIMITS: CommandBudgets = CommandBudgets {
    seconds: 1_200,
    rss_bytes: 4 * 1024 * 1024 * 1024,
    workspace_bytes: 12 * 1024 * 1024 * 1024,
    log_bytes: 16 * 1024 * 1024,
};

pub const MAX_PARENT_RSS_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_COMBINED_RSS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_CAMPAIGN_NANOS: u64 = 5_100 * 1_000_000_000;

const MAX_RECORD_BYTES: usize = JsonProfile::PackageMetadataStateSelection.max_bytes();

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InnerCommandSummary {
    pub aggregate_peak_rss_bytes: u64,
    pub child_exit_code: i32,
    pub label: String,
    pub passed: bool,
    pub peak_log_bytes: u64,
    pub peak_workspace_bytes: u64,
    pub record_path: String,
    pub request_path: String,
    pub request_sha256: String,
    pub result_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedInnerCommand {
    pub label: String,
    pub request_sha256: String,
    pub result_sha256: String,
    /// Record-schema conservative sum of helper `ru_maxrss` and child-tree peak.
    pub aggregate_peak_rss_bytes: u64,
    pub workspace_bytes_at_finish: u64,
    pub log_bytes_at_finish: u64,
    pub elapsed_nanos: u64,
}

/// Resource envelopes computed from independently sampled high-water marks.
///
/// These sums are conservative bounds, not simultaneous RSS observations:
/// the command helper's `ru_maxrss`, the child process-tree sample peak, and
/// the outer caller's `ru_maxrss` can occur at different times.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerValidationSummary {
    pub commands: Vec<ValidatedInnerCommand>,
    /// Maximum of the per-command conservative helper-plus-child envelopes.
    pub inner_rss_envelope_bytes: u64,
    /// Parent high-water mark plus the maximum inner envelope; not a sampled
    /// simultaneous campaign RSS peak.
    pub combined_rss_envelope_bytes: u64,
    pub total_log_bytes: u64,
    pub total_elapsed_nanos: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedInnerResource {
    pub label: String,
    pub path: String,
    pub sha256: String,
    pub passed: Option<bool>,
    pub aggregate_peak_rss_bytes: Option<u64>,
}

/// Validate one captured request/record pair against the existing inner-command contract.
///
/// `label` fixes the known phase name but does not identify the command's
/// expected executable, arguments, working directory, environment, or roots.
/// Callers that use this readback for acceptance must separately compare the
/// request and `record.command` binding with the host-pinned command contract.
pub fn validate_inner_record(
    label: &str,
    request_sha256: &str,
    request: &CommandRequest,
    record: &Value,
) -> Result<u64> {
    if !INNER_COMMAND_LABELS.contains(&label) {
        return Err(Refusal::new("unknown bare-target inner command label"));
    }
    if request.schema != crate::qualification_command::REQUEST_SCHEMA
        || request.limits != INNER_LIMITS
        || record.get("schema").and_then(Value::as_str)
            != Some("ami-rust-native-command-qualification-record-v1")
        || record.get("request_sha256").and_then(Value::as_str) != Some(request_sha256)
        || !is_sha256_digest(request_sha256)
        || budgets(record.get("limits"))? != INNER_LIMITS
        || record.get("passed").and_then(Value::as_bool) != Some(true)
        || !record.get("refusal").is_some_and(Value::is_null)
        || record.get("capture_complete").and_then(Value::as_bool) != Some(true)
        || !record.get("capture_error").is_some_and(Value::is_null)
        || record.get("child_exit_code").and_then(Value::as_i64) != Some(0)
        || !record.get("child_signal").is_some_and(Value::is_null)
    {
        return Err(Refusal::new(format!(
            "inner qualified command request/record differs from the pinned contract: {label}"
        )));
    }

    let peak = number(record, "aggregate_peak_rss_bytes")?;
    let workspace = number(record, "workspace_bytes_at_finish")?;
    let logs = number(record, "log_bytes_at_finish")?;
    let elapsed = number(record, "elapsed_nanos")?;
    let report = record
        .get("resource_report")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("inner command resource report is missing"))?;

    let own_peak = number(record, "own_peak_rss_bytes")?;
    let child_peak = number(record, "child_peak_visible_rss_bytes")?;
    let report_child_peak = report
        .get("peak_visible_rss_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new("inner child RSS sample peak is missing or invalid"))?;
    let derived_aggregate = own_peak
        .checked_add(child_peak)
        .ok_or_else(|| Refusal::new("inner helper plus child RSS envelope overflows"))?;
    if child_peak != report_child_peak || peak != derived_aggregate {
        return Err(Refusal::new(format!(
            "inner aggregate RSS differs from its helper/child measurements: {label}"
        )));
    }
    if peak > INNER_LIMITS.rss_bytes
        || workspace > INNER_LIMITS.workspace_bytes
        || logs > INNER_LIMITS.log_bytes
        || elapsed > INNER_LIMITS.seconds * 1_000_000_000
    {
        return Err(Refusal::new(format!(
            "inner qualified command resource total exceeds its bound: {label}"
        )));
    }
    if report.get("incomplete_cleanup").and_then(Value::as_bool) != Some(false)
        || report.get("last_sample_complete").and_then(Value::as_bool) != Some(true)
        || report
            .get("sample_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            < 1
    {
        return Err(Refusal::new(format!(
            "inner command cleanup or resource sampling is incomplete: {label}"
        )));
    }
    for key in [
        "peak_visible_rss_bytes",
        "peak_workspace_bytes",
        "peak_log_bytes",
        "current_visible_rss_bytes",
        "current_workspace_bytes",
        "current_log_bytes",
    ] {
        let value = report
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::new(format!("resource report field is invalid: {key}")))?;
        let limit = match key {
            "peak_visible_rss_bytes" | "current_visible_rss_bytes" => INNER_LIMITS.rss_bytes,
            "peak_workspace_bytes" | "current_workspace_bytes" => INNER_LIMITS.workspace_bytes,
            _ => INNER_LIMITS.log_bytes,
        };
        if value > limit {
            return Err(Refusal::new(format!(
                "inner resource report exceeds its bound: {label}/{key}"
            )));
        }
    }

    for stream_name in ["stdout", "stderr"] {
        let stream = record
            .get(stream_name)
            .and_then(Value::as_object)
            .ok_or_else(|| {
                Refusal::new(format!("inner command {stream_name} metadata is missing"))
            })?;
        if stream.get("bytes").and_then(Value::as_u64).is_none()
            || !stream
                .get("sha256")
                .and_then(Value::as_str)
                .is_some_and(is_sha256_digest)
        {
            return Err(Refusal::new(format!(
                "inner command {stream_name} metadata is invalid: {label}"
            )));
        }
    }
    Ok(peak)
}

/// Validate all five ordered summaries, raw request/result records, and log files.
/// `remote_output_root` is the exact producer output path recorded by the host.
///
/// This function validates record shape, ordering, budgets, and file bindings.
/// It does not compare command semantics to a host-pinned command list; its
/// caller must perform that binding before treating the result as acceptance.
pub fn validate_inner_commands(
    output_root: &Path,
    remote_output_root: &str,
    summaries: &[InnerCommandSummary],
    parent_peak_rss_bytes: u64,
) -> Result<InnerValidationSummary> {
    if !Path::new(remote_output_root).is_absolute()
        || remote_output_root.ends_with('/')
        || remote_output_root.contains("//")
        || remote_output_root.contains("/./")
        || remote_output_root.contains("/../")
        || summaries.len() != INNER_COMMAND_LABELS.len()
    {
        return Err(Refusal::new(
            "inner command set or producer output root is invalid",
        ));
    }
    if parent_peak_rss_bytes > MAX_PARENT_RSS_BYTES {
        return Err(Refusal::new(
            "parent process RSS exceeds its reserved budget",
        ));
    }

    let mut commands = Vec::with_capacity(INNER_COMMAND_LABELS.len());
    let mut inner_rss_envelope = 0_u64;
    let mut total_log_bytes = 0_u64;
    let mut total_elapsed_nanos = 0_u64;
    let mut raw_streams = Vec::with_capacity(INNER_COMMAND_LABELS.len());

    // Read and validate every record's stream sizes before opening any raw log.
    // This makes the campaign ceiling a preflight bound, not a check reached
    // only after earlier streams have already been hashed.
    for (summary, expected_label) in summaries.iter().zip(INNER_COMMAND_LABELS) {
        if summary.label != expected_label
            || !summary.passed
            || summary.child_exit_code != 0
            || !is_sha256_digest(&summary.request_sha256)
            || !is_sha256_digest(&summary.result_sha256)
            || summary.aggregate_peak_rss_bytes > INNER_LIMITS.rss_bytes
            || summary.peak_workspace_bytes > INNER_LIMITS.workspace_bytes
            || summary.peak_log_bytes > INNER_LIMITS.log_bytes
        {
            return Err(Refusal::new(format!(
                "inner command summary violates order, status, digest, or bounds: {expected_label}"
            )));
        }

        let request_relative = format!("requests/{expected_label}.json");
        let result_relative = format!("records/{expected_label}/result.json");
        if summary.request_path != format!("{remote_output_root}/{request_relative}")
            || summary.record_path != format!("{remote_output_root}/{result_relative}")
        {
            return Err(Refusal::new(format!(
                "inner command summary path escapes its bound output root: {expected_label}"
            )));
        }
        validate_relative_inventory_path(&request_relative)?;
        validate_relative_inventory_path(&result_relative)?;

        let request_path = output_root.join(&request_relative);
        let result_path = output_root.join(&result_relative);
        let request_bytes = read_regular_bounded(&request_path, MAX_RECORD_BYTES)?;
        let result_bytes = read_regular_bounded(&result_path, MAX_RECORD_BYTES)?;
        if sha256_bytes(&request_bytes) != summary.request_sha256
            || sha256_bytes(&result_bytes) != summary.result_sha256
        {
            return Err(Refusal::new(format!(
                "inner command request/result digest mismatch: {expected_label}"
            )));
        }
        let request = parse_request(&request_bytes)?;
        let record = parse_json_value(&result_bytes, JsonProfile::PackageMetadataStateSelection)?;
        let peak =
            validate_inner_record(expected_label, &summary.request_sha256, &request, &record)?;
        let record_workspace = number(&record, "workspace_bytes_at_finish")?;
        let record_logs = number(&record, "log_bytes_at_finish")?;
        if peak != summary.aggregate_peak_rss_bytes
            || record_workspace != summary.peak_workspace_bytes
            || record_logs != summary.peak_log_bytes
        {
            return Err(Refusal::new(format!(
                "inner command summary totals differ from its record: {expected_label}"
            )));
        }

        let record_directory = output_root.join("records").join(expected_label);
        let mut stream_metadata = Vec::with_capacity(2);
        for stream_name in ["stdout", "stderr"] {
            let stream = record
                .get(stream_name)
                .and_then(Value::as_object)
                .ok_or_else(|| Refusal::new("inner stream metadata is missing"))?;
            let expected_bytes = stream
                .get("bytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| Refusal::new("inner stream byte count is invalid"))?;
            let expected_sha = stream
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| Refusal::new("inner stream digest is invalid"))?;
            if !is_sha256_digest(expected_sha) {
                return Err(Refusal::new(format!(
                    "inner raw {stream_name} digest is invalid: {expected_label}"
                )));
            }
            total_log_bytes = checked_raw_log_total(total_log_bytes, expected_bytes)?;
            stream_metadata.push((
                stream_name.to_owned(),
                expected_bytes,
                expected_sha.to_owned(),
            ));
        }
        if record_logs < total_log_bytes {
            return Err(Refusal::new(format!(
                "inner command cumulative log count understates retained raw streams: {expected_label}"
            )));
        }

        let elapsed = number(&record, "elapsed_nanos")?;
        total_elapsed_nanos = total_elapsed_nanos
            .checked_add(elapsed)
            .ok_or_else(|| Refusal::new("campaign command time overflow"))?;
        if total_elapsed_nanos > MAX_CAMPAIGN_NANOS {
            return Err(Refusal::new(
                "inner command campaign exceeds its active-time budget",
            ));
        }
        inner_rss_envelope = inner_rss_envelope.max(peak);
        commands.push(ValidatedInnerCommand {
            label: expected_label.to_owned(),
            request_sha256: summary.request_sha256.clone(),
            result_sha256: summary.result_sha256.clone(),
            aggregate_peak_rss_bytes: peak,
            workspace_bytes_at_finish: summary.peak_workspace_bytes,
            log_bytes_at_finish: summary.peak_log_bytes,
            elapsed_nanos: elapsed,
        });
        raw_streams.push((record_directory, stream_metadata));
    }

    let mut hashed_log_bytes = 0_u64;
    for (record_directory, stream_metadata) in raw_streams {
        for (stream_name, expected_bytes, expected_sha) in stream_metadata {
            let log_path = record_directory.join(format!("{stream_name}.log"));
            let file = open_regular_nofollow(&log_path)?;
            let initial_length = file
                .metadata()
                .map_err(|error| Refusal::new(format!("could not inspect inner raw log: {error}")))?
                .len();
            let remaining_campaign_bytes = INNER_LIMITS
                .log_bytes
                .checked_sub(hashed_log_bytes)
                .ok_or_else(|| Refusal::new("campaign raw log budget arithmetic underflow"))?;
            let stream_digest = hash_open_file_bounded(
                file,
                initial_length,
                expected_bytes,
                remaining_campaign_bytes,
            )?;
            if stream_digest.bytes != expected_bytes || stream_digest.sha256 != expected_sha {
                return Err(Refusal::new(format!(
                    "inner raw {stream_name} log differs from its recorded size/digest: {}",
                    record_directory.display()
                )));
            }
            hashed_log_bytes = checked_raw_log_total(hashed_log_bytes, stream_digest.bytes)?;
        }
    }
    if hashed_log_bytes != total_log_bytes {
        return Err(Refusal::new("campaign raw log byte accounting changed"));
    }

    let combined_rss_envelope_bytes = inner_rss_envelope
        .checked_add(parent_peak_rss_bytes)
        .ok_or_else(|| Refusal::new("combined parent and child RSS envelope overflow"))?;
    if combined_rss_envelope_bytes > MAX_COMBINED_RSS_BYTES {
        return Err(Refusal::new(
            "combined inner-command and parent RSS envelope exceeds the 4 GiB campaign limit",
        ));
    }
    Ok(InnerValidationSummary {
        commands,
        inner_rss_envelope_bytes: inner_rss_envelope,
        combined_rss_envelope_bytes,
        total_log_bytes,
        total_elapsed_nanos,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundedStreamDigest {
    bytes: u64,
    sha256: String,
}

/// Count bytes with a per-stream and campaign ceiling before opening or hashing a stream.
fn checked_raw_log_total(current: u64, next: u64) -> Result<u64> {
    if next > INNER_LIMITS.log_bytes {
        return Err(Refusal::new(
            "one raw command stream exceeds the 16 MiB limit",
        ));
    }
    let total = current
        .checked_add(next)
        .ok_or_else(|| Refusal::new("campaign raw log total overflow"))?;
    if total > INNER_LIMITS.log_bytes {
        return Err(Refusal::new("campaign raw logs exceed the 16 MiB limit"));
    }
    Ok(total)
}

/// Hash one already-open regular file without reopening its path or reading beyond `limit`.
///
/// `initial_length` must come from this handle before this call. The caller
/// compares it with the retained record before hashing. The same handle is
/// used for bounded reads and the final size check, so path replacement cannot
/// redirect the digest. Growth beyond the remaining budget is detected by a
/// one-byte probe; truncation or any size change is refused.
fn hash_open_file_bounded(
    mut file: File,
    initial_length: u64,
    expected_bytes: u64,
    limit: u64,
) -> Result<BoundedStreamDigest> {
    if initial_length != expected_bytes || expected_bytes > limit {
        return Err(Refusal::new(
            "inner raw stream size differs from its bounded record",
        ));
    }

    let mut digest = Sha256::new();
    let mut read_total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = limit
            .checked_sub(read_total)
            .ok_or_else(|| Refusal::new("inner raw stream limit arithmetic underflow"))?;
        let probe_bytes = remaining
            .checked_add(1)
            .ok_or_else(|| Refusal::new("inner raw stream limit cannot be probed safely"))?;
        let read_capacity = usize::try_from(probe_bytes.min(buffer.len() as u64))
            .map_err(|_| Refusal::new("inner raw stream read size is not representable"))?;
        match file.read(&mut buffer[..read_capacity]) {
            Ok(0) => break,
            Ok(read) => {
                let read_bytes = u64::try_from(read)
                    .map_err(|_| Refusal::new("inner raw stream read exceeds u64"))?;
                if read_bytes > remaining {
                    return Err(Refusal::new("inner raw stream grew beyond its byte limit"));
                }
                read_total = read_total
                    .checked_add(read_bytes)
                    .ok_or_else(|| Refusal::new("inner raw stream byte count overflow"))?;
                digest.update(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not hash the opened inner raw stream: {error}"
                )));
            }
        }
    }

    let final_length = file
        .metadata()
        .map_err(|error| {
            Refusal::new(format!(
                "could not recheck opened inner raw stream: {error}"
            ))
        })?
        .len();
    if read_total != expected_bytes || final_length != initial_length {
        return Err(Refusal::new(
            "inner raw stream was truncated or changed size while being hashed",
        ));
    }
    let digest: [u8; 32] = digest.finalize().into();
    Ok(BoundedStreamDigest {
        bytes: read_total,
        sha256: encode_hex(&digest),
    })
}

/// Retain ordered resource rows for every readable `records/*/result.json` file.
pub fn retained_inner_resources(output_root: &Path) -> (Vec<RetainedInnerResource>, Vec<String>) {
    let records_root = output_root.join("records");
    let root_metadata = match fs::symlink_metadata(&records_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (Vec::new(), Vec::new());
        }
        Err(error) => return (Vec::new(), vec![format!("producer records root: {error}")]),
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return (
            Vec::new(),
            vec!["producer records root is not a regular directory".into()],
        );
    }

    let mut errors = Vec::new();
    let entries = match fs::read_dir(&records_root) {
        Ok(entries) => entries,
        Err(error) => return (Vec::new(), vec![format!("producer records root: {error}")]),
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                let result_path = entry.path().join("result.json");
                if result_path.exists() || fs::symlink_metadata(&result_path).is_ok() {
                    paths.push((
                        entry.file_name().to_string_lossy().into_owned(),
                        result_path,
                    ));
                }
            }
            Err(error) => errors.push(format!("producer record directory: {error}")),
        }
    }
    paths.sort_by_key(|(label, _)| {
        (
            INNER_COMMAND_LABELS
                .iter()
                .position(|known| *known == label)
                .unwrap_or(INNER_COMMAND_LABELS.len()),
            label.clone(),
        )
    });

    let mut rows = Vec::new();
    for (label, path) in paths {
        let relative = match path.strip_prefix(output_root) {
            Ok(relative) => relative.to_string_lossy().into_owned(),
            Err(_) => {
                errors.push(format!("{label}: result path escapes producer output"));
                continue;
            }
        };
        if let Err(error) = validate_relative_inventory_path(&relative) {
            errors.push(format!("{label}: result path is not relative: {error}"));
            continue;
        }
        let bytes = match read_regular_bounded(&path, MAX_RECORD_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(format!(
                    "{label}: result is not a readable regular file: {error}"
                ));
                continue;
            }
        };
        let record = match parse_json_value(&bytes, JsonProfile::PackageMetadataStateSelection) {
            Ok(record) => record,
            Err(error) => {
                errors.push(format!("{label}: result JSON is invalid: {error}"));
                continue;
            }
        };
        let peak = record
            .get("aggregate_peak_rss_bytes")
            .and_then(Value::as_u64);
        if peak.is_none() {
            errors.push(format!("{label}: aggregate RSS is missing or invalid"));
        }
        let passed = record.get("passed").and_then(Value::as_bool);
        rows.push(RetainedInnerResource {
            label,
            path: relative,
            sha256: sha256_bytes(&bytes),
            passed,
            aggregate_peak_rss_bytes: peak,
        });
    }
    (rows, errors)
}

fn budgets(value: Option<&Value>) -> Result<CommandBudgets> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("inner command budgets are missing"))?;
    if object.len() != 4 {
        return Err(Refusal::new("inner command budgets have unexpected fields"));
    }
    Ok(CommandBudgets {
        seconds: object
            .get("seconds")
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::new("inner command seconds limit is invalid"))?,
        rss_bytes: object
            .get("rss_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::new("inner command RSS limit is invalid"))?,
        workspace_bytes: object
            .get("workspace_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::new("inner command workspace limit is invalid"))?,
        log_bytes: object
            .get("log_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::new("inner command log limit is invalid"))?,
    })
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(format!("inner command field is invalid: {field}")))
}

#[cfg(test)]
mod tests {
    use super::{
        INNER_COMMAND_LABELS, INNER_LIMITS, InnerCommandSummary, MAX_PARENT_RSS_BYTES,
        checked_raw_log_total, hash_open_file_bounded, retained_inner_resources,
        validate_inner_commands,
    };
    use crate::files::open_regular_nofollow;
    use serde_json::{Value, json};
    use std::{
        fs,
        io::Write,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bare-target-records/actual-macos/producer"
    );
    const REMOTE_OUTPUT_ROOT: &str = "/Users/runner/work/_temp/ami-rust-bare-target-libraries/39807569612-1/macos-aarch64/outer-output/artifact/producer";
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let parent = std::env::temp_dir();
            for _ in 0..100 {
                let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    "ami-rust-inner-record-test-{}-{id}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
            panic!("could not allocate temporary directory");
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn fixture_copy(&self) -> PathBuf {
            let output = self.0.join("producer");
            copy_tree(Path::new(FIXTURE), &output);
            output
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create fixture directory");
        for entry in fs::read_dir(source).expect("read fixture directory") {
            let entry = entry.expect("fixture entry");
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if source_path.is_dir() {
                copy_tree(&source_path, &destination_path);
            } else {
                fs::copy(source_path, destination_path).expect("copy fixture file");
            }
        }
    }

    fn summaries(root: &Path) -> Vec<InnerCommandSummary> {
        let producer: Value =
            serde_json::from_slice(&fs::read(root.join("producer.json")).unwrap()).unwrap();
        serde_json::from_value(producer["qualification_commands"].clone()).unwrap()
    }

    fn validate(
        root: &Path,
        rows: &[InnerCommandSummary],
        parent_peak: u64,
    ) -> crate::Result<super::InnerValidationSummary> {
        validate_inner_commands(root, REMOTE_OUTPUT_ROOT, rows, parent_peak)
    }

    fn resign_record(root: &Path, label: &str, record: &Value, rows: &mut [InnerCommandSummary]) {
        let record_path = root.join("records").join(label).join("result.json");
        fs::write(&record_path, serde_json::to_vec(record).unwrap()).unwrap();
        let index = INNER_COMMAND_LABELS
            .iter()
            .position(|known| *known == label)
            .unwrap();
        rows[index].result_sha256 = crate::digest::sha256_file(&record_path).unwrap();
    }

    #[test]
    fn retained_macos_producer_records_pass_and_match_resource_inventory() {
        let root = Path::new(FIXTURE);
        let rows = summaries(root);
        let result = validate(root, &rows, MAX_PARENT_RSS_BYTES).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.label.as_str())
                .collect::<Vec<_>>(),
            INNER_COMMAND_LABELS
        );
        assert_eq!(result.commands.len(), 5);
        assert_eq!(result.total_log_bytes, 52_706);
        assert!(result.total_elapsed_nanos < 5_100_000_000_000);
        assert!(result.combined_rss_envelope_bytes <= 4 * 1024 * 1024 * 1024);
        let (resources, errors) = retained_inner_resources(root);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(resources.len(), 5);
        assert!(resources.iter().all(|row| row.passed == Some(true)));
        assert!(
            resources
                .iter()
                .all(|row| row.aggregate_peak_rss_bytes.is_some())
        );
    }

    #[test]
    fn rejects_a_changed_raw_stream_even_when_the_json_record_is_unchanged() {
        let temp = TempDir::new();
        let root = temp.fixture_copy();
        let rows = summaries(&root);
        let log = root.join("records/source-production/stdout.log");
        let mut bytes = fs::read(&log).unwrap();
        bytes[0] ^= 1;
        fs::write(log, bytes).unwrap();
        assert!(validate(&root, &rows, 0).is_err());
        let _keep_temp_root = temp.path();
    }

    #[test]
    fn rejects_request_digest_and_summary_path_substitution() {
        let temp = TempDir::new();
        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        rows[0].request_sha256.replace_range(..1, "0");
        assert!(validate(&root, &rows, 0).is_err());
        let mut rows = summaries(&root);
        rows[0].record_path = format!("{REMOTE_OUTPUT_ROOT}/records/../../outside/result.json");
        assert!(validate(&root, &rows, 0).is_err());
    }

    #[test]
    fn rejects_duplicate_or_missing_phases_and_incomplete_cleanup() {
        let temp = TempDir::new();
        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        rows[1].label = rows[0].label.clone();
        assert!(validate(&root, &rows, 0).is_err());
        let rows = summaries(&root);
        assert!(validate(&root, &rows[..4], 0).is_err());

        let mut record: Value = serde_json::from_slice(
            &fs::read(root.join("records/rustc-version/result.json")).unwrap(),
        )
        .unwrap();
        record["resource_report"]["incomplete_cleanup"] = json!(true);
        fs::write(
            root.join("records/rustc-version/result.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let mut rows = summaries(&root);
        rows[0].result_sha256 =
            crate::digest::sha256_file(&root.join("records/rustc-version/result.json")).unwrap();
        assert!(validate(&root, &rows, 0).is_err());
    }

    #[test]
    fn rejects_parent_resource_overrun_and_changed_record_totals() {
        let temp = TempDir::new();
        let root = temp.fixture_copy();
        let rows = summaries(&root);
        assert!(validate(&root, &rows, MAX_PARENT_RSS_BYTES + 1).is_err());
        let mut rows = summaries(&root);
        rows[0].peak_workspace_bytes += 1;
        assert!(validate(&root, &rows, 0).is_err());
    }

    #[test]
    fn rejects_incomplete_samples_and_parent_plus_child_rss_overrun() {
        let temp = TempDir::new();
        let root = temp.fixture_copy();
        let mut record: Value = serde_json::from_slice(
            &fs::read(root.join("records/rustc-version/result.json")).unwrap(),
        )
        .unwrap();
        record["resource_report"]["sample_count"] = json!(0);
        fs::write(
            root.join("records/rustc-version/result.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let mut rows = summaries(&root);
        rows[0].result_sha256 =
            crate::digest::sha256_file(&root.join("records/rustc-version/result.json")).unwrap();
        assert!(validate(&root, &rows, 0).is_err());

        let root = temp.fixture_copy();
        let mut record: Value = serde_json::from_slice(
            &fs::read(root.join("records/source-production/result.json")).unwrap(),
        )
        .unwrap();
        let high_child_peak = 3_900 * 1024 * 1024_u64;
        let mut rows = summaries(&root);
        let own_peak = record["own_peak_rss_bytes"].as_u64().unwrap();
        let aggregate = own_peak.checked_add(high_child_peak).unwrap();
        record["child_peak_visible_rss_bytes"] = json!(high_child_peak);
        record["resource_report"]["peak_visible_rss_bytes"] = json!(high_child_peak);
        record["aggregate_peak_rss_bytes"] = json!(aggregate);
        rows[4].aggregate_peak_rss_bytes = aggregate;
        resign_record(&root, "source-production", &record, &mut rows);
        assert!(validate(&root, &rows, MAX_PARENT_RSS_BYTES).is_err());
    }

    #[test]
    fn rejects_understated_aggregate_or_child_rss_measurements() {
        let temp = TempDir::new();
        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        let path = root.join("records/source-production/result.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let aggregate = record["aggregate_peak_rss_bytes"].as_u64().unwrap();
        record["aggregate_peak_rss_bytes"] = json!(aggregate - 1);
        rows[4].aggregate_peak_rss_bytes = aggregate - 1;
        resign_record(&root, "source-production", &record, &mut rows);
        assert!(validate(&root, &rows, 0).is_err());

        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        let path = root.join("records/source-production/result.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let child = record["child_peak_visible_rss_bytes"].as_u64().unwrap();
        record["child_peak_visible_rss_bytes"] = json!(child - 1);
        resign_record(&root, "source-production", &record, &mut rows);
        assert!(validate(&root, &rows, 0).is_err());

        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        let path = root.join("records/source-production/result.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let report_peak = record["resource_report"]["peak_visible_rss_bytes"]
            .as_u64()
            .unwrap();
        record["resource_report"]["peak_visible_rss_bytes"] = json!(report_peak - 1);
        resign_record(&root, "source-production", &record, &mut rows);
        assert!(validate(&root, &rows, 0).is_err());
    }

    #[test]
    fn rejects_helper_plus_child_rss_envelope_overflow() {
        let temp = TempDir::new();
        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        let path = root.join("records/rustc-version/result.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record["own_peak_rss_bytes"] = json!(u64::MAX);
        record["child_peak_visible_rss_bytes"] = json!(1_u64);
        record["resource_report"]["peak_visible_rss_bytes"] = json!(1_u64);
        record["aggregate_peak_rss_bytes"] = json!(u64::MAX);
        rows[0].aggregate_peak_rss_bytes = u64::MAX;
        resign_record(&root, "rustc-version", &record, &mut rows);
        assert!(validate(&root, &rows, 0).is_err());
    }

    #[test]
    fn refuses_oversized_raw_streams_and_campaign_totals_before_hashing() {
        assert_eq!(
            checked_raw_log_total(INNER_LIMITS.log_bytes - 1, 1).unwrap(),
            INNER_LIMITS.log_bytes
        );
        assert!(checked_raw_log_total(INNER_LIMITS.log_bytes - 1, 2).is_err());
        assert!(checked_raw_log_total(0, INNER_LIMITS.log_bytes + 1).is_err());

        let temp = TempDir::new();
        let path = temp.0.join("oversized.blob");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(INNER_LIMITS.log_bytes + 1).unwrap();
        drop(file);
        let opened = open_regular_nofollow(&path).unwrap();
        let length = opened.metadata().unwrap().len();
        assert!(hash_open_file_bounded(opened, length, length, INNER_LIMITS.log_bytes).is_err());

        // Missing raw files prove metadata limits are checked for the whole
        // campaign before the first stream is opened or hashed.
        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        let path = root.join("records/rustc-version/result.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record["stdout"]["bytes"] = json!(INNER_LIMITS.log_bytes + 1);
        resign_record(&root, "rustc-version", &record, &mut rows);
        fs::remove_file(root.join("records/rustc-version/stdout.log")).unwrap();
        let refusal = validate(&root, &rows, 0).unwrap_err().to_string();
        assert!(refusal.contains("one raw command stream exceeds the 16 MiB limit"));

        let root = temp.fixture_copy();
        let mut rows = summaries(&root);
        let path = root.join("records/source-production/result.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let stderr_bytes = record["stderr"]["bytes"].as_u64().unwrap();
        record["stdout"]["bytes"] = json!(INNER_LIMITS.log_bytes - stderr_bytes);
        resign_record(&root, "source-production", &record, &mut rows);
        fs::remove_file(root.join("records/rustc-version/stdout.log")).unwrap();
        let refusal = validate(&root, &rows, 0).unwrap_err().to_string();
        assert!(refusal.contains("campaign raw logs exceed the 16 MiB limit"));
        let _keep_temp_root = temp.path();
    }

    #[test]
    fn bounded_stream_hash_uses_one_handle_and_refuses_truncation_or_growth() {
        let temp = TempDir::new();

        let replaced_path = temp.0.join("replaced.blob");
        fs::write(&replaced_path, b"original bytes").unwrap();
        let opened = open_regular_nofollow(&replaced_path).unwrap();
        let initial = opened.metadata().unwrap().len();
        let detached_path = temp.0.join("detached.blob");
        fs::rename(&replaced_path, &detached_path).unwrap();
        let mut replacement = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&replaced_path)
            .unwrap();
        replacement.set_len(INNER_LIMITS.log_bytes * 2).unwrap();
        replacement.flush().unwrap();
        let digest =
            hash_open_file_bounded(opened, initial, initial, INNER_LIMITS.log_bytes).unwrap();
        assert_eq!(digest.bytes, initial);
        assert_eq!(
            digest.sha256,
            crate::digest::sha256_bytes(b"original bytes")
        );

        let truncated_path = temp.0.join("truncated.blob");
        fs::write(&truncated_path, b"truncate me").unwrap();
        let opened = open_regular_nofollow(&truncated_path).unwrap();
        let initial = opened.metadata().unwrap().len();
        fs::OpenOptions::new()
            .write(true)
            .open(&truncated_path)
            .unwrap()
            .set_len(1)
            .unwrap();
        assert!(hash_open_file_bounded(opened, initial, initial, INNER_LIMITS.log_bytes).is_err());

        let grown_path = temp.0.join("grown.blob");
        fs::write(&grown_path, b"x").unwrap();
        let opened = open_regular_nofollow(&grown_path).unwrap();
        let initial = opened.metadata().unwrap().len();
        fs::OpenOptions::new()
            .write(true)
            .open(&grown_path)
            .unwrap()
            .set_len(INNER_LIMITS.log_bytes * 2)
            .unwrap();
        assert!(hash_open_file_bounded(opened, initial, initial, INNER_LIMITS.log_bytes).is_err());
    }
}

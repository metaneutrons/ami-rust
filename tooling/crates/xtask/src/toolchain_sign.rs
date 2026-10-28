//! Protected-release Sigstore signing.
//!
//! This is an internal maintainer task. It consumes a short-lived OIDC
//! credential file supplied by the protected GitHub workflow, validates the
//! source-pinned Cosign binary, signs only the selected release subjects, and
//! removes the credential before returning. It never publishes a release.

use ami_rust_core::{
    Refusal, Result,
    digest::sha256_file,
    files::read_regular_bounded,
    json::{JsonProfile, parse_json_value},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const DEADLINE: Duration = Duration::from_secs(1_200);
const COMMAND_DEADLINE: Duration = Duration::from_secs(60);
const PIN_LIMIT: usize = 1024 * 1024;
const CREDENTIAL_LIMIT: usize = 4 * 1024 * 1024;
pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let options = parse_options(&mut arguments)?;
    let credential = PathBuf::from(required(&options, "--credentials")?);
    let result = (|| {
        let started = Instant::now();
        let private = read_credential(&credential)?;
        let source = canonical_directory(PathBuf::from(required(&options, "--source-root")?), "source root")?;
        let host = required(&options, "--host")?;
        let gh = PathBuf::from(required(&options, "--gh")?);
        let cosign = PathBuf::from(required(&options, "--cosign")?);
        verify_pinned_verifiers(&source, host, &gh, &cosign)?;
        let plan = PathBuf::from(required(&options, "--plan")?);
        let subjects = read_subjects(&plan)?;
        let payloads = canonical_directory(PathBuf::from(required(&options, "--payloads")?), "payload directory")?;
        let logs = canonical_directory(PathBuf::from(required(&options, "--logs")?), "signing log directory")?;
        sign_subjects(&cosign, &payloads, &logs, &subjects, &private, started)?;
        let status = match subjects.len() {
            31 => "31_SIGNING_COMMANDS_SUCCEEDED",
            32 => "32_SIGNING_COMMANDS_SUCCEEDED",
            _ => "RP3_PROTECTED_SIGNATURES_SUCCEEDED",
        };
        Ok(json!({
            "status": status,
            "signature_subjects": subjects,
            "claim": "Signing command exits only; final pinned cryptographic verification remains required."
        }))
    })();
    let removal = fs::remove_file(&credential)
        .map_err(|error| Refusal::new(format!("could not remove ephemeral signing credential: {error}")));
    let value = match (result, removal) {
        (Err(error), _) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
        (Ok(value), Ok(())) => value,
    };
    println!(
        "{}",
        serde_json::to_string(&value)
            .map_err(|error| Refusal::new(format!("could not render signing result: {error}")))?
    );
    Ok(())
}

fn parse_options(arguments: &mut impl Iterator<Item = OsString>) -> Result<BTreeMap<OsString, OsString>> {
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if ![
            "--plan",
            "--payloads",
            "--source-root",
            "--gh",
            "--cosign",
            "--credentials",
            "--logs",
            "--host",
        ]
        .iter()
        .any(|candidate| key == *candidate)
        {
            return Err(usage());
        }
        let value = arguments.next().ok_or_else(usage)?;
        if options.insert(key, value).is_some() {
            return Err(usage());
        }
    }
    for name in [
        "--plan",
        "--payloads",
        "--source-root",
        "--gh",
        "--cosign",
        "--credentials",
        "--logs",
        "--host",
    ] {
        let _ = required(&options, name)?;
    }
    let host = required(&options, "--host")?;
    if !matches!(host, "linux-x86_64" | "macos-aarch64") {
        return Err(Refusal::new("unsupported protected signing host"));
    }
    Ok(options)
}

fn required<'a>(options: &'a BTreeMap<OsString, OsString>, name: &str) -> Result<&'a str> {
    options
        .get(std::ffi::OsStr::new(name))
        .and_then(|value| value.to_str())
        .ok_or_else(usage)
}

fn read_credential(path: &Path) -> Result<PrivateCredential> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Refusal::new(format!("could not inspect ephemeral signing credential: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != effective_uid()
        || metadata.nlink() != 1
    {
        return Err(Refusal::new(
            "ephemeral signing credential must be an owner-only regular file",
        ));
    }
    let raw = read_regular_bounded(path, CREDENTIAL_LIMIT)?;
    let value = parse_json_value(&raw, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("ephemeral signing credential must be an object"))?;
    let expected = [
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    ];
    if object.len() != expected.len()
        || expected.iter().any(|key| !object.contains_key(*key))
    {
        return Err(Refusal::new(
            "ephemeral signing credential has an invalid shape",
        ));
    }
    let token = string_field(object, expected[0], "ephemeral signing credential")?.to_owned();
    let url = string_field(object, expected[1], "ephemeral signing credential")?.to_owned();
    if token.is_empty() || !url.starts_with("https://") {
        return Err(Refusal::new(
            "ephemeral signing credential has an invalid shape",
        ));
    }
    Ok(PrivateCredential { token, url })
}

fn verify_pinned_verifiers(source: &Path, host: &str, gh: &Path, cosign: &Path) -> Result<()> {
    let pins = read_regular_bounded(&source.join("release/ci-auth-tools.json"), PIN_LIMIT)?;
    let value = parse_json_value(&pins, JsonProfile::PublisherPolicyAndAuthenticationMetadata)?;
    let root = value
        .as_object()
        .ok_or_else(|| Refusal::new("source-pinned verifier inputs must be an object"))?;
    if root.get("schema").and_then(Value::as_str) != Some("ami-rust-ci-auth-tools-v1") {
        return Err(Refusal::new("unsupported source-pinned verifier inputs"));
    }
    let host_pin = root
        .get("hosts")
        .and_then(Value::as_object)
        .and_then(|hosts| hosts.get(host))
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("unsupported source-pinned verifier host"))?;
    let roots = root
        .get("roots")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("source-pinned verifier roots are missing"))?;
    for (name, binary) in [("gh", gh), ("cosign", cosign)] {
        let binary_pin = host_pin
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| Refusal::new(format!("{name} binary pin is missing")))?;
        let expected_bytes = u64_field(binary_pin, "binary_bytes", "verifier binary pin")?;
        let expected_digest = string_field(binary_pin, "binary_sha256", "verifier binary pin")?;
        if !is_sha256(expected_digest) {
            return Err(Refusal::new("verifier binary pin has an invalid SHA-256 digest"));
        }
        let metadata = fs::symlink_metadata(binary)
            .map_err(|error| Refusal::new(format!("could not inspect {name} executable: {error}")))?;
        if !metadata.file_type().is_file()
            || metadata.len() != expected_bytes
            || metadata.mode() & 0o111 == 0
            || sha256_file(binary)? != expected_digest
        {
            return Err(Refusal::new(format!(
                "verifier executable differs from trusted source pin: {name}"
            )));
        }
        let root_pin = roots
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| Refusal::new(format!("{name} trust root is missing from source pins")))?;
        let relative = string_field(root_pin, "path", "verifier trust-root pin")?;
        validate_relative_path(relative)?;
        let root_path = source.join(relative);
        let expected_root_bytes = u64_field(root_pin, "bytes", "verifier trust-root pin")?;
        let actual_root = read_regular_bounded(
            &root_path,
            usize::try_from(expected_root_bytes)
                .map_err(|_| Refusal::new("verifier trust-root size cannot be represented"))?,
        )?;
        if actual_root.len() as u64 != expected_root_bytes
            || sha256_file(&root_path)?
                != string_field(root_pin, "sha256", "verifier trust-root pin")?
        {
            return Err(Refusal::new(format!(
                "verifier root differs from trusted source pin: {name}"
            )));
        }
    }
    Ok(())
}

fn read_subjects(path: &Path) -> Result<Vec<String>> {
    let raw = read_regular_bounded(path, CREDENTIAL_LIMIT)?;
    let value = parse_json_value(&raw, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("signature subject plan must be an object"))?;
    let subjects = object
        .get("signature_subjects")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("signature subject plan must select signature subjects"))?;
    let rp3 = object.get("schema").and_then(Value::as_str)
        == Some("ami-rust-rp3-signature-plan-v1");
    if (!rp3 && !matches!(subjects.len(), 31 | 32))
        || (rp3 && !(12..=64).contains(&subjects.len()))
    {
        return Err(Refusal::new(
            "signature plan has an unsupported subject count",
        ));
    }
    let names = subjects
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Refusal::new("signature plan contains a non-string subject"))?;
    if names.iter().any(|name| !safe_asset_name(name))
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
    {
        return Err(Refusal::new(
            "signature plan must select distinct safe subjects",
        ));
    }
    if rp3 {
        if object.get("status").and_then(Value::as_str)
            != Some("READY_FOR_PROTECTED_SIGNATURES")
            || object.get("subject_count").and_then(Value::as_u64)
                != Some(names.len() as u64)
        {
            return Err(Refusal::new("RP3 signature plan identity is invalid"));
        }
        return Ok(names);
    }
    let expected_status = if names.len() == 31 {
        "READY_FOR_31_REAL_SIGNATURES_AND_JOINT_87_SUBJECT_ATTESTATION"
    } else {
        "READY_FOR_32_REAL_SIGNATURES_AND_JOINT_90_SUBJECT_ATTESTATION"
    };
    if object.get("status").is_some_and(|value| value.as_str() != Some(expected_status)) {
        return Err(Refusal::new(
            "signature subjects do not match the exact assembly profile status",
        ));
    }
    if names.len() == 32 && object.get("status").is_none() {
        return Err(Refusal::new(
            "signature subjects do not match the exact assembly profile status",
        ));
    }
    Ok(names)
}

fn sign_subjects(
    cosign: &Path,
    payloads: &Path,
    logs: &Path,
    subjects: &[String],
    credential: &PrivateCredential,
    started: Instant,
) -> Result<()> {
    let home = std::env::var_os("HOME").ok_or_else(|| Refusal::new("HOME is required for signing"))?;
    let temporary = std::env::var_os("TMPDIR").ok_or_else(|| Refusal::new("TMPDIR is required for signing"))?;
    for name in subjects {
        check_deadline(started)?;
        let input = payloads.join(name);
        let bundle = payloads.join(format!("{name}.sigstore.json"));
        if fs::symlink_metadata(&bundle).is_ok() {
            return Err(Refusal::new("signature output must be fresh"));
        }
        let stdout = create_new(&logs.join(format!("sign-{name}.stdout.log")))?;
        let stderr = create_new(&logs.join(format!("sign-{name}.stderr.log")))?;
        let mut command = Command::new(cosign);
        command
            .arg("sign-blob")
            .arg("--yes")
            .arg("--bundle")
            .arg(&bundle)
            .arg(&input)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", home.clone())
            .env("TMPDIR", temporary.clone())
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env("GITHUB_ACTIONS", "true")
            .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", &credential.token)
            .env("ACTIONS_ID_TOKEN_REQUEST_URL", &credential.url)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut child = command
            .spawn()
            .map_err(|error| Refusal::new(format!("could not start pinned Cosign: {error}")))?;
        let command_started = Instant::now();
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| Refusal::new(format!("could not observe pinned Cosign: {error}")))?
            {
                if !status.success() {
                    return Err(Refusal::new(format!("pinned Cosign rejected a signature subject: {name}")));
                }
                break;
            }
            if command_started.elapsed() >= COMMAND_DEADLINE || started.elapsed() >= DEADLINE {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Refusal::new("signing exceeded the existing command deadline"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    check_deadline(started)
}

fn create_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Refusal::new(format!("could not create signing log {}: {error}", path.display())))
}

fn canonical_directory(path: PathBuf, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| Refusal::new(format!("could not inspect {label}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Refusal::new(format!("{label} must be a real directory")));
    }
    fs::canonicalize(&path).map_err(|error| Refusal::new(format!("could not canonicalize {label}: {error}")))
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, name: &str, label: &str) -> Result<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("{label} has an invalid {name}")))
}

fn u64_field(object: &serde_json::Map<String, Value>, name: &str, label: &str) -> Result<u64> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(format!("{label} has an invalid {name}")))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_asset_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn validate_relative_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(Refusal::new("Cosign trust-root pin has an invalid path"));
    }
    Ok(())
}

fn check_deadline(started: Instant) -> Result<()> {
    if started.elapsed() >= DEADLINE {
        Err(Refusal::new("signing exceeded the existing command deadline"))
    } else {
        Ok(())
    }
}

struct PrivateCredential {
    token: String,
    url: String,
}

#[allow(unsafe_code, reason = "geteuid reads the caller's effective UID and takes no pointers")]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no pointers and only reads the current process UID.
    unsafe { libc::geteuid() }
}

fn usage() -> Refusal {
    Refusal::new(
        "usage: ami-rust-xtask toolchain-sign --plan FILE --payloads DIRECTORY --source-root DIRECTORY --gh FILE --cosign FILE --credentials FILE --logs DIRECTORY --host HOST",
    )
}

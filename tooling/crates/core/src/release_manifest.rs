//! Pure parsing for the legacy ami-rust-release-v1 manifest.
//!
//! This parser checks schema, paths, digest syntax and the legacy size bounds;
//! it performs no filesystem or signature verification, publisher
//! authentication, or release qualification. The caller must state whether it
//! is using the production installer route because the two routes accept
//! different qualification_only values.
//!
//! The legacy producer object is intentionally opaque and untrusted. A
//! borrowed `RawValue` prepass preserves its original JSON bytes; a temporary
//! validation copy replaces only producer integer tokens with zero so the
//! shared `serde_json::Value` parser can still check duplicates, depth and the
//! outer schema. Python's former 4,300-digit integer limit is enforced locally
//! for producer integers. Float tokens and all other fields retain the shared
//! parser's normal numeric behavior. In particular, an overflowing float such
//! as `1e400` is refused as non-finite, a deliberate tightening relative to
//! Python's default `json.loads` float handling.

use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Refusal, Result,
    digest::is_sha256_digest,
    json::JsonProfile,
    publisher_tar::validate_portable_path,
    records::{Host, Sha256},
};

const MANIFEST_SCHEMA: &str = "ami-rust-release-v1";
const NATIVE_MANIFEST_SCHEMA: &str = "ami-rust-release-v2";
const ASSET_FILE_LIMIT: u64 = 16 * 1024 * 1024;
const ASSET_TOTAL_LIMIT: u64 = 32 * 1024 * 1024;
const SDK_FILE_LIMIT: u64 = 16 * 1024 * 1024;
const SDK_TOTAL_LIMIT: u64 = 16 * 1024 * 1024;
const INVENTORY_COUNT_LIMIT: usize = 1_000;
const RELEASE_VERSION_MAX_BYTES: usize = 64;
const PYTHON_MAX_INTEGER_DIGITS: usize = 4_300;

/// A file pin from either legacy release inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: Sha256,
}

/// Python-runtime digests embedded by the legacy release schema.
///
/// These are parsed metadata only: this type does not locate or execute those
/// interpreters. The Rust release-v2 schema replaces them with native launchers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostInterpreterDigests {
    pub linux_x86_64: Sha256,
    pub macos_aarch64: Sha256,
}

impl HostInterpreterDigests {
    pub fn for_host(&self, host: Host) -> &Sha256 {
        match host {
            Host::LinuxX86_64 => &self.linux_x86_64,
            Host::MacosAarch64 => &self.macos_aarch64,
        }
    }
}

/// Structurally validated but unauthenticated release-v1 fields.
#[derive(Clone, Debug)]
pub struct ReleaseManifest {
    pub version: String,
    pub qualification_only: bool,
    pub sdk_archive: String,
    pub sdk_manifest_sha256: Sha256,
    pub assets: Vec<ReleaseFile>,
    pub sdk_files: Vec<ReleaseFile>,
    /// Opaque producer JSON retained byte-for-byte from the input.
    pub producer: Box<RawValue>,
    pub host_interpreters: HostInterpreterDigests,
}

/// A native launcher row structurally bound to one asset inventory row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHostLauncher {
    pub path: String,
    pub bytes: u64,
    pub sha256: Sha256,
}

/// The two host-specific launcher rows required by release-v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHostLaunchers {
    pub linux_x86_64: NativeHostLauncher,
    pub macos_aarch64: NativeHostLauncher,
}

impl NativeHostLaunchers {
    pub fn for_host(&self, host: Host) -> &NativeHostLauncher {
        match host {
            Host::LinuxX86_64 => &self.linux_x86_64,
            Host::MacosAarch64 => &self.macos_aarch64,
        }
    }
}

/// Structurally validated but unauthenticated release-v2 fields. Launcher
/// rows are checked against the declared asset inventory; no file bytes or
/// publisher authentication are verified by this parser.
#[derive(Clone, Debug)]
pub struct NativeReleaseManifest {
    pub version: String,
    pub qualification_only: bool,
    pub sdk_archive: String,
    pub sdk_manifest_sha256: Sha256,
    pub assets: Vec<ReleaseFile>,
    pub sdk_files: Vec<ReleaseFile>,
    /// Opaque producer JSON retained byte-for-byte from the input.
    pub producer: Box<RawValue>,
    pub host_launchers: NativeHostLaunchers,
}

/// Parse one bounded legacy release manifest.
///
/// Pass production=true only for the production installation route. Both routes
/// accept qualification_only=true; the production route also accepts false,
/// while the qualification route refuses it. A successful parse is not
/// evidence that the manifest signature, listed bytes, or publisher are trusted.
pub fn parse_release_manifest(raw: &[u8], production: bool) -> Result<ReleaseManifest> {
    let (manifest, producer) = parse_release_document(raw, MANIFEST_SCHEMA, "host_interpreters")?;
    let body = parse_release_body(&manifest, producer, production)?;
    let object = manifest
        .as_object()
        .ok_or_else(|| Refusal::new("release manifest must be an object"))?;
    let host_interpreters = parse_host_interpreters(object.get("host_interpreters"))?;

    Ok(ReleaseManifest {
        version: body.version,
        qualification_only: body.qualification_only,
        sdk_archive: body.sdk_archive,
        sdk_manifest_sha256: body.sdk_manifest_sha256,
        assets: body.assets,
        sdk_files: body.sdk_files,
        producer: body.producer,
        host_interpreters,
    })
}

/// Parse the frozen native v2 schema without claiming authentication or file
/// verification. The host launchers must exactly bind to asset inventory rows.
pub fn parse_native_release_manifest(
    raw: &[u8],
    production: bool,
) -> Result<NativeReleaseManifest> {
    let (manifest, producer) =
        parse_release_document(raw, NATIVE_MANIFEST_SCHEMA, "host_launchers")?;
    let body = parse_release_body(&manifest, producer, production)?;
    let object = manifest
        .as_object()
        .ok_or_else(|| Refusal::new("release manifest must be an object"))?;
    let host_launchers = parse_host_launchers(object.get("host_launchers"), &body.assets)?;

    Ok(NativeReleaseManifest {
        version: body.version,
        qualification_only: body.qualification_only,
        sdk_archive: body.sdk_archive,
        sdk_manifest_sha256: body.sdk_manifest_sha256,
        assets: body.assets,
        sdk_files: body.sdk_files,
        producer: body.producer,
        host_launchers,
    })
}

struct ReleaseManifestBody {
    version: String,
    qualification_only: bool,
    sdk_archive: String,
    sdk_manifest_sha256: Sha256,
    assets: Vec<ReleaseFile>,
    sdk_files: Vec<ReleaseFile>,
    producer: Box<RawValue>,
}

fn parse_release_document(
    raw: &[u8],
    expected_schema: &str,
    host_field: &'static str,
) -> Result<(Value, Box<RawValue>)> {
    let profile = JsonProfile::ReleaseManifestAndInstallReceipt;
    if raw.len() > profile.max_bytes() {
        return Err(Refusal::new("oversized release manifest"));
    }
    check_prepass_depth(raw)?;

    // Borrow raw values so producer integers outside serde_json's native
    // integer range do not become rounded floating-point values in this
    // extraction pass. The complete Value pass still rejects duplicate keys.
    let envelope: BTreeMap<String, &RawValue> = serde_json::from_slice(raw)
        .map_err(|error| Refusal::new(format!("invalid release manifest: {error}")))?;
    let producer_raw = envelope
        .get("producer")
        .ok_or_else(|| Refusal::new("release producer identity must be a non-empty object"))?;
    let producer = (*producer_raw).to_owned();
    let validation_copy = producer_validation_copy(raw, producer_raw)?;
    let manifest = crate::json::parse_json_value(&validation_copy, profile)?;
    let object = manifest
        .as_object()
        .ok_or_else(|| Refusal::new("release manifest must be an object"))?;
    let required_fields = BTreeSet::from([
        "schema",
        "version",
        "qualification_only",
        "sdk_archive",
        "sdk_manifest_sha256",
        "assets",
        "sdk_files",
        "producer",
        host_field,
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != required_fields
        || object.get("schema").and_then(Value::as_str) != Some(expected_schema)
    {
        return Err(Refusal::new("incompatible release manifest schema"));
    }
    if !object
        .get("producer")
        .is_some_and(|value| value.as_object().is_some_and(|fields| !fields.is_empty()))
    {
        return Err(Refusal::new(
            "release producer identity must be a non-empty object",
        ));
    }
    Ok((manifest, producer))
}

fn parse_release_body(
    manifest: &Value,
    producer: Box<RawValue>,
    production: bool,
) -> Result<ReleaseManifestBody> {
    let object = manifest
        .as_object()
        .ok_or_else(|| Refusal::new("release manifest must be an object"))?;
    let version = required_string(object.get("version"), "release version")?;
    if !is_valid_version(version) {
        return Err(Refusal::new("invalid release version"));
    }

    let qualification_only = object
        .get("qualification_only")
        .and_then(Value::as_bool)
        .ok_or_else(|| Refusal::new("release qualification_only must be a boolean"))?;
    if !qualification_only && !production {
        return Err(Refusal::new(
            "release qualification_only value is incompatible with this installer route",
        ));
    }

    let sdk_archive = required_string(object.get("sdk_archive"), "SDK archive name")?;
    if sdk_archive != "sdk.tar.xz" {
        return Err(Refusal::new("release sdk_archive must be sdk.tar.xz"));
    }
    let sdk_manifest_sha256 =
        parse_digest(object.get("sdk_manifest_sha256"), "SDK manifest SHA-256")?;

    let assets = parse_inventory(
        object.get("assets"),
        "asset",
        ASSET_TOTAL_LIMIT,
        ASSET_FILE_LIMIT,
    )?;
    if !assets.iter().any(|entry| entry.path == "sdk.tar.xz") {
        return Err(Refusal::new(
            "release asset inventory is missing sdk.tar.xz",
        ));
    }
    for entry in &assets {
        let folded = entry.path.to_ascii_lowercase();
        if matches!(folded.as_str(), "release.json" | "release.json.sig")
            || folded.starts_with("release.json/")
            || folded.starts_with("release.json.sig/")
        {
            return Err(Refusal::new(
                "release manifest and signature paths are reserved",
            ));
        }
    }

    let sdk_files = parse_inventory(
        object.get("sdk_files"),
        "SDK file",
        SDK_TOTAL_LIMIT,
        SDK_FILE_LIMIT,
    )?;
    let contract = sdk_files
        .iter()
        .find(|entry| entry.path == "contract/sdk.json")
        .ok_or_else(|| {
            Refusal::new("sdk_files must pin contract/sdk.json to sdk_manifest_sha256")
        })?;
    if contract.sha256 != sdk_manifest_sha256 {
        return Err(Refusal::new(
            "sdk_files must pin contract/sdk.json to sdk_manifest_sha256",
        ));
    }

    Ok(ReleaseManifestBody {
        version: version.to_owned(),
        qualification_only,
        sdk_archive: sdk_archive.to_owned(),
        sdk_manifest_sha256,
        assets,
        sdk_files,
        producer,
    })
}

/// Check only the bounded lexical nesting precondition before serde's borrowed
/// RawValue pass. Full syntax, duplicate and depth validation follows in
/// `parse_json` after constructing the temporary validation copy.
fn check_prepass_depth(raw: &[u8]) -> Result<()> {
    crate::json::check_raw_value_prepass(raw, JsonProfile::ReleaseManifestAndInstallReceipt)
}

/// Build a validation-only document copy. Producer integer tokens become a
/// small valid integer, while producer strings and floating-point tokens are
/// copied exactly. Exact `-0` integer tokens elsewhere become `0` because
/// Python's JSON parser treats them as integer zero; `-0.0` and `-0e0` remain
/// floats and are refused by the typed inventory parser. Returned producer
/// data always comes from the original borrowed RawValue, never from this copy.
fn producer_validation_copy(raw: &[u8], producer: &RawValue) -> Result<Vec<u8>> {
    let producer_bytes = producer.get().as_bytes();
    let start = (producer_bytes.as_ptr() as usize)
        .checked_sub(raw.as_ptr() as usize)
        .ok_or_else(|| Refusal::new("producer token is outside its source manifest"))?;
    let end = start
        .checked_add(producer_bytes.len())
        .filter(|end| *end <= raw.len())
        .ok_or_else(|| Refusal::new("producer token range overflow"))?;
    if raw.get(start..end) != Some(producer_bytes) {
        return Err(Refusal::new(
            "producer token does not match its source manifest range",
        ));
    }

    let mut copy = Vec::new();
    copy.try_reserve_exact(raw.len())
        .map_err(|_| Refusal::new("could not allocate bounded release validation copy"))?;
    let mut position = 0;
    while position < raw.len() {
        if raw[position] == b'"' {
            let string_start = position;
            position += 1;
            let mut escaped = false;
            while position < raw.len() {
                let byte = raw[position];
                position += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break;
                }
            }
            copy.extend_from_slice(&raw[string_start..position]);
            continue;
        }

        let byte = raw[position];
        if byte == b'-' || byte.is_ascii_digit() {
            let token_start = position;
            if byte == b'-' {
                position += 1;
            }
            let integer_digits_start = position;
            while raw.get(position).is_some_and(u8::is_ascii_digit) {
                position += 1;
            }
            if position == integer_digits_start {
                return Err(Refusal::new("invalid producer number token"));
            }
            let mut is_integer = true;
            if raw.get(position) == Some(&b'.') {
                is_integer = false;
                position += 1;
                while raw.get(position).is_some_and(u8::is_ascii_digit) {
                    position += 1;
                }
            }
            if raw
                .get(position)
                .is_some_and(|byte| matches!(*byte, b'e' | b'E'))
            {
                is_integer = false;
                position += 1;
                if raw
                    .get(position)
                    .is_some_and(|byte| matches!(*byte, b'+' | b'-'))
                {
                    position += 1;
                }
                while raw.get(position).is_some_and(u8::is_ascii_digit) {
                    position += 1;
                }
            }
            let token = &raw[token_start..position];
            let in_producer = token_start >= start && position <= end;
            if in_producer && is_integer {
                let digit_count = token.iter().filter(|byte| byte.is_ascii_digit()).count();
                if digit_count > PYTHON_MAX_INTEGER_DIGITS {
                    return Err(Refusal::new(
                        "producer integer exceeds Python's 4,300 digit limit",
                    ));
                }
                copy.push(b'0');
            } else if !in_producer && is_integer && token == b"-0" {
                copy.push(b'0');
            } else {
                copy.extend_from_slice(token);
            }
            continue;
        }

        copy.push(byte);
        position += 1;
    }
    Ok(copy)
}

fn required_string<'a>(value: Option<&'a Value>, label: &str) -> Result<&'a str> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("{label} must be a string")))
}

fn parse_digest(value: Option<&Value>, label: &str) -> Result<Sha256> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("invalid {label}")))?;
    if !is_sha256_digest(value) {
        return Err(Refusal::new(format!("invalid {label}")));
    }
    serde_json::from_value(Value::String(value.to_owned()))
        .map_err(|error| Refusal::new(format!("invalid {label}: {error}")))
}

fn parse_host_interpreters(value: Option<&Value>) -> Result<HostInterpreterDigests> {
    let hosts = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("release must pin Python hashes for both supported hosts"))?;
    if hosts.len() != 2
        || !hosts.contains_key("linux-x86_64")
        || !hosts.contains_key("macos-aarch64")
    {
        return Err(Refusal::new(
            "release must pin Python hashes for both supported hosts",
        ));
    }
    let linux_x86_64 = parse_host_interpreter(hosts.get("linux-x86_64"), "linux-x86_64")?;
    let macos_aarch64 = parse_host_interpreter(hosts.get("macos-aarch64"), "macos-aarch64")?;
    Ok(HostInterpreterDigests {
        linux_x86_64,
        macos_aarch64,
    })
}

fn parse_host_launchers(
    value: Option<&Value>,
    assets: &[ReleaseFile],
) -> Result<NativeHostLaunchers> {
    let hosts = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("release must pin both native host launchers"))?;
    if hosts.len() != 2
        || !hosts.contains_key("linux-x86_64")
        || !hosts.contains_key("macos-aarch64")
    {
        return Err(Refusal::new("release must pin both native host launchers"));
    }
    Ok(NativeHostLaunchers {
        linux_x86_64: parse_host_launcher(hosts.get("linux-x86_64"), "linux-x86_64", assets)?,
        macos_aarch64: parse_host_launcher(hosts.get("macos-aarch64"), "macos-aarch64", assets)?,
    })
}

fn parse_host_launcher(
    value: Option<&Value>,
    host: &str,
    assets: &[ReleaseFile],
) -> Result<NativeHostLauncher> {
    let entry = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new(format!("invalid host_launchers entry: {host}")))?;
    if entry.len() != 3
        || !entry.contains_key("path")
        || !entry.contains_key("bytes")
        || !entry.contains_key("sha256")
    {
        return Err(Refusal::new(format!(
            "invalid host_launchers entry: {host}"
        )));
    }
    let path = required_string(entry.get("path"), &format!("{host} launcher path"))?;
    let path = validate_portable_path(path.as_bytes())?;
    let bytes = entry
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(format!("invalid {host} launcher byte length")))?;
    let sha256 = parse_digest(entry.get("sha256"), &format!("{host} launcher SHA-256"))?;
    let asset = assets
        .iter()
        .find(|asset| asset.path == path)
        .ok_or_else(|| Refusal::new(format!("{host} launcher is missing from asset inventory")))?;
    if asset.bytes != bytes || asset.sha256 != sha256 {
        return Err(Refusal::new(format!(
            "{host} launcher does not match asset inventory"
        )));
    }
    Ok(NativeHostLauncher {
        path,
        bytes,
        sha256,
    })
}

fn parse_host_interpreter(value: Option<&Value>, host: &str) -> Result<Sha256> {
    let entry = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new(format!("invalid host_interpreters entry: {host}")))?;
    if entry.len() != 1 || !entry.contains_key("sha256") {
        return Err(Refusal::new(format!(
            "invalid host_interpreters entry: {host}"
        )));
    }
    parse_digest(entry.get("sha256"), &format!("{host} Python SHA-256"))
}

fn parse_inventory(
    value: Option<&Value>,
    label: &str,
    total_limit: u64,
    file_limit: u64,
) -> Result<Vec<ReleaseFile>> {
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new(format!("invalid {label} inventory length")))?;
    if rows.is_empty() || rows.len() > INVENTORY_COUNT_LIMIT {
        return Err(Refusal::new(format!("invalid {label} inventory length")));
    }

    let mut entries = Vec::with_capacity(rows.len());
    let mut total = 0_u64;
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| Refusal::new(format!("invalid {label} inventory entry")))?;
        if row.len() != 3
            || !row.contains_key("path")
            || !row.contains_key("bytes")
            || !row.contains_key("sha256")
        {
            return Err(Refusal::new(format!("invalid {label} inventory entry")));
        }
        let path = required_string(row.get("path"), &format!("{label} path"))?;
        let path = validate_portable_path(path.as_bytes())?;
        if entries
            .iter()
            .any(|previous: &ReleaseFile| previous.path.eq_ignore_ascii_case(&path))
        {
            return Err(Refusal::new(format!("duplicate {label} path: {path}")));
        }
        let bytes = row
            .get("bytes")
            .and_then(Value::as_u64)
            .filter(|size| *size <= file_limit)
            .ok_or_else(|| Refusal::new(format!("invalid {label} byte length: {path}")))?;
        let sha256 = parse_digest(row.get("sha256"), &format!("{label} file SHA-256"))?;
        total = total
            .checked_add(bytes)
            .ok_or_else(|| Refusal::new(format!("{label} inventory size overflow")))?;
        if total > total_limit {
            return Err(Refusal::new(format!(
                "{label} exceeds its total byte limit"
            )));
        }
        entries.push(ReleaseFile {
            path,
            bytes,
            sha256,
        });
    }

    for entry in &entries {
        let mut parent = String::new();
        let mut components = entry.path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            if entries
                .iter()
                .any(|candidate| candidate.path.eq_ignore_ascii_case(&parent))
            {
                return Err(Refusal::new(format!(
                    "file/directory or case-insensitive path conflict: {}",
                    entry.path
                )));
            }
        }
    }

    Ok(entries)
}

fn is_valid_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= RELEASE_VERSION_MAX_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'+' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{
        NativeReleaseManifest, ReleaseManifest, parse_native_release_manifest,
        parse_release_manifest,
    };
    use serde_json::value::RawValue;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    fn fixture(qualification_only: bool) -> Value {
        let digest = "a".repeat(64);
        json!({
            "schema": "ami-rust-release-v1",
            "version": "0.1.0-rc1",
            "qualification_only": qualification_only,
            "sdk_archive": "sdk.tar.xz",
            "sdk_manifest_sha256": digest,
            "assets": [
                {"path":"sdk.tar.xz", "bytes":3, "sha256":"b".repeat(64)},
                {"path":"manifest.json", "bytes":1, "sha256":"c".repeat(64)}
            ],
            "sdk_files": [
                {"path":"contract/sdk.json", "bytes":1, "sha256":digest},
                {"path":"include/stdio.h", "bytes":2, "sha256":"d".repeat(64)}
            ],
            "producer": {"opaque": {"name":"fixture", "diagnostic":true}},
            "host_interpreters": {
                "linux-x86_64": {"sha256":"e".repeat(64)},
                "macos-aarch64": {"sha256":"f".repeat(64)}
            }
        })
    }

    fn native_fixture(qualification_only: bool) -> Value {
        let mut value = fixture(qualification_only);
        value["schema"] = json!("ami-rust-release-v2");
        let object = value.as_object_mut().expect("fixture object");
        object.remove("host_interpreters");
        value["assets"] = json!([
            {"path":"sdk.tar.xz", "bytes":3, "sha256":"b".repeat(64)},
            {"path":"bin/ami-rust-linux", "bytes":4, "sha256":"c".repeat(64)},
            {"path":"bin/ami-rust-macos", "bytes":5, "sha256":"d".repeat(64)}
        ]);
        value["host_launchers"] = json!({
            "linux-x86_64": {
                "path":"bin/ami-rust-linux", "bytes":4, "sha256":"c".repeat(64)
            },
            "macos-aarch64": {
                "path":"bin/ami-rust-macos", "bytes":5, "sha256":"d".repeat(64)
            }
        });
        value
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("serialize release manifest fixture")
    }

    fn bytes_with_producer(producer: &str) -> Vec<u8> {
        let raw = bytes(&fixture(true));
        let envelope: BTreeMap<String, &RawValue> =
            serde_json::from_slice(&raw).expect("borrow fixture raw values");
        let producer_raw = envelope.get("producer").expect("producer field");
        let start = producer_raw.get().as_ptr() as usize - raw.as_ptr() as usize;
        let end = start + producer_raw.get().len();
        drop(envelope);
        let mut replaced = Vec::with_capacity(raw.len() + producer.len());
        replaced.extend_from_slice(&raw[..start]);
        replaced.extend_from_slice(producer.as_bytes());
        replaced.extend_from_slice(&raw[end..]);
        replaced
    }

    fn parse(value: &Value, production: bool) -> crate::Result<ReleaseManifest> {
        parse_release_manifest(&bytes(value), production)
    }

    fn parse_native(value: &Value, production: bool) -> crate::Result<NativeReleaseManifest> {
        parse_native_release_manifest(&bytes(value), production)
    }

    #[test]
    fn parses_legacy_qualification_and_production_routes_without_auth_claims() {
        let qualification = parse(&fixture(true), false).expect("qualification release");
        assert!(qualification.qualification_only);
        assert_eq!(qualification.version, "0.1.0-rc1");
        assert_eq!(qualification.sdk_archive, "sdk.tar.xz");
        assert_eq!(qualification.assets.len(), 2);
        assert_eq!(qualification.sdk_files.len(), 2);
        let expected_python = "e".repeat(64);
        assert_eq!(
            qualification
                .host_interpreters
                .for_host(crate::records::Host::LinuxX86_64)
                .as_str(),
            expected_python
        );
        let producer: Value =
            serde_json::from_str(qualification.producer.get()).expect("preserved producer JSON");
        assert_eq!(producer["opaque"]["name"], "fixture");

        let production = parse(&fixture(false), true).expect("production release");
        assert!(!production.qualification_only);
        assert!(parse(&fixture(false), false).is_err());
        // The old producer accepted qualification-only manifests through either
        // installer route; production does not force the flag to false.
        assert!(parse(&fixture(true), true).is_ok());
    }

    #[test]
    fn parses_native_v2_on_qualification_and_production_routes() {
        let qualification =
            parse_native(&native_fixture(true), false).expect("native qualification release");
        assert!(qualification.qualification_only);
        assert_eq!(qualification.version, "0.1.0-rc1");
        assert_eq!(qualification.assets.len(), 3);
        assert_eq!(
            qualification
                .host_launchers
                .for_host(crate::records::Host::LinuxX86_64)
                .path,
            "bin/ami-rust-linux"
        );
        assert_eq!(
            qualification
                .host_launchers
                .for_host(crate::records::Host::MacosAarch64)
                .sha256
                .as_str(),
            "d".repeat(64)
        );

        let production =
            parse_native(&native_fixture(false), true).expect("native production release");
        assert!(!production.qualification_only);
        assert!(parse_native(&native_fixture(false), false).is_err());
        assert!(parse_native(&native_fixture(true), true).is_ok());
    }

    #[test]
    fn native_v2_requires_exact_schema_and_asset_bound_host_rows() {
        let mut value = native_fixture(true);
        value["host_launchers"]["windows-x86_64"] = json!({
            "path":"bin/ami-rust-linux", "bytes":4, "sha256":"c".repeat(64)
        });
        assert!(parse_native(&value, false).is_err());

        let mut value = native_fixture(true);
        value["host_launchers"]
            .as_object_mut()
            .expect("host map")
            .remove("linux-x86_64");
        assert!(parse_native(&value, false).is_err());

        let mut value = native_fixture(true);
        value["host_launchers"]["linux-x86_64"]["path"] = json!("bin/other-launcher");
        assert!(parse_native(&value, false).is_err());

        let mut value = native_fixture(true);
        value["host_launchers"]["linux-x86_64"]["bytes"] = json!(3);
        assert!(parse_native(&value, false).is_err());

        let mut value = native_fixture(true);
        value["host_launchers"]["linux-x86_64"]["sha256"] = json!("0".repeat(64));
        assert!(parse_native(&value, false).is_err());

        let mut value = native_fixture(true);
        value["host_launchers"]["linux-x86_64"]["mode"] = json!(0o755);
        assert!(parse_native(&value, false).is_err());

        let mut value = native_fixture(true);
        value["host_interpreters"] = json!({});
        assert!(parse_native(&value, false).is_err());

        let mut value = native_fixture(true);
        value["future_security_field"] = json!(true);
        assert!(parse_native(&value, false).is_err());

        assert!(parse_native(&fixture(true), false).is_err());
        assert!(parse(&native_fixture(true), false).is_err());
    }

    #[test]
    fn refuses_unknown_schema_fields_and_missing_fields() {
        let mut value = fixture(true);
        value["schema"] = json!("ami-rust-release-v2");
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["future_security_field"] = json!(true);
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value.as_object_mut().expect("object").remove("producer");
        assert!(parse(&value, false).is_err());
    }

    #[test]
    fn rejects_recursive_duplicate_json_keys() {
        let text = String::from_utf8(bytes(&fixture(true))).expect("fixture UTF-8");
        let duplicated = text.replace(
            "\"name\":\"fixture\"",
            "\"name\":\"fixture\",\"name\":\"shadow\"",
        );
        assert!(duplicated.len() > text.len());
        assert!(parse_release_manifest(duplicated.as_bytes(), false).is_err());
    }

    #[test]
    fn enforces_inventory_rows_path_collisions_and_exact_asset_requirements() {
        let mut value = fixture(true);
        value["assets"][1]["path"] = json!("release.json/child");
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"][1]["path"] = json!("Release.JSON.SIG/child");
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"][1]["path"] = json!("release.json.sig");
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"].as_array_mut().expect("assets").push(json!({
            "path":"SDK.TAR.XZ", "bytes":1, "sha256":"0".repeat(64)
        }));
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"].as_array_mut().expect("assets").push(json!({
            "path":"dir", "bytes":1, "sha256":"0".repeat(64)
        }));
        value["assets"].as_array_mut().expect("assets").push(json!({
            "path":"dir/file", "bytes":1, "sha256":"0".repeat(64)
        }));
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"][0]["path"] = json!("sdk.tar.xz ");
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"].as_array_mut().expect("assets").remove(0);
        assert!(parse(&value, false).is_err());
    }

    #[test]
    fn rejects_wrong_manifest_digest_asset_limits_and_file_types() {
        let mut value = fixture(true);
        value["sdk_files"][0]["sha256"] = json!("0".repeat(64));
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"][0]["bytes"] = json!(true);
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"][0]["bytes"] = json!(1.0);
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"][0]["bytes"] = json!(16 * 1024 * 1024_u64 + 1);
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["assets"][0]["mode"] = json!(0o644);
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["qualification_only"] = json!(1);
        assert!(parse(&value, false).is_err());
    }

    #[test]
    fn inventory_accepts_only_python_integer_negative_zero() {
        let raw = String::from_utf8(bytes(&fixture(true)))
            .expect("release fixture UTF-8")
            .replace("\"bytes\":3", "\"bytes\":-0")
            .replace("\"bytes\":1", "\"bytes\":-0");
        let parsed = parse_release_manifest(raw.as_bytes(), false)
            .expect("negative zero is a Python integer zero");
        assert_eq!(parsed.assets[0].bytes, 0);
        assert_eq!(parsed.assets[1].bytes, 0);
        assert_eq!(parsed.sdk_files[0].bytes, 0);

        for token in ["-0.0", "-0e0"] {
            let raw = String::from_utf8(bytes(&fixture(true)))
                .expect("release fixture UTF-8")
                .replace("\"bytes\":3", &format!("\"bytes\":{token}"));
            assert!(parse_release_manifest(raw.as_bytes(), false).is_err());
        }
    }

    #[test]
    fn enforces_inventory_count_and_aggregate_byte_bounds() {
        let mut too_many = fixture(true);
        let assets = too_many["assets"].as_array_mut().expect("assets");
        for index in 0..999 {
            assets.push(json!({
                "path":format!("extra/{index}"), "bytes":0, "sha256":"0".repeat(64)
            }));
        }
        assert!(parse(&too_many, false).is_err());

        let mut too_large = fixture(true);
        too_large["assets"][0]["bytes"] = json!(16 * 1024 * 1024_u64);
        too_large["assets"][1]["bytes"] = json!(16 * 1024 * 1024_u64);
        too_large["assets"]
            .as_array_mut()
            .expect("assets")
            .push(json!({
                "path":"third", "bytes":1, "sha256":"0".repeat(64)
            }));
        assert!(parse(&too_large, false).is_err());

        let mut sdk_too_large = fixture(true);
        sdk_too_large["sdk_files"][0]["bytes"] = json!(16 * 1024 * 1024_u64);
        sdk_too_large["sdk_files"][1]["bytes"] = json!(1);
        assert!(parse(&sdk_too_large, false).is_err());
    }

    #[test]
    fn requires_exact_host_interpreter_hash_map_and_digest_syntax() {
        let mut value = fixture(true);
        value["host_interpreters"]["windows-x86_64"] = json!({"sha256":"0".repeat(64)});
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["host_interpreters"]["linux-x86_64"]["mode"] = json!(0o755);
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["host_interpreters"]["macos-aarch64"]["sha256"] = json!("A".repeat(64));
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["sdk_manifest_sha256"] = json!("not-a-digest");
        assert!(parse(&value, false).is_err());
    }

    #[test]
    fn preserves_legacy_producer_opacity_but_requires_nonempty_object() {
        let mut value = fixture(true);
        value["producer"] = json!({"future": ["field", 4, {"nested": true}]});
        let parsed = parse(&value, false).expect("opaque producer metadata");
        let producer: Value = serde_json::from_str(parsed.producer.get()).expect("producer JSON");
        assert_eq!(producer["future"][1], 4);

        let mut value = fixture(true);
        value["producer"] = json!({});
        assert!(parse(&value, false).is_err());

        let mut value = fixture(true);
        value["producer"] = json!("not-object");
        assert!(parse(&value, false).is_err());
    }

    #[test]
    fn preserves_opaque_integer_lexemes_with_python_digit_limit() {
        let native_overflow = bytes_with_producer(r#"{"value":18446744073709551616}"#);
        let parsed = parse_release_manifest(&native_overflow, false)
            .expect("integer beyond serde_json u64 range remains opaque");
        assert_eq!(parsed.producer.get(), r#"{"value":18446744073709551616}"#);

        let four_thousand_three_hundred = format!(
            "{{\"positive\":{},\"negative\":-{},\"text\":\"{}\"}}",
            "9".repeat(4_300),
            "8".repeat(4_300),
            "7".repeat(4_301)
        );
        let raw = bytes_with_producer(&four_thousand_three_hundred);
        let parsed = parse_release_manifest(&raw, false)
            .expect("4,300 digit positive and negative producer integers");
        assert_eq!(parsed.producer.get(), four_thousand_three_hundred);

        for integer in ["9".repeat(4_301), format!("-{}", "8".repeat(4_301))] {
            let producer = format!("{{\"value\":{integer}}}");
            assert!(parse_release_manifest(&bytes_with_producer(&producer), false).is_err());
        }
    }

    #[test]
    fn full_validation_copy_still_rejects_duplicate_keys_and_nonfinite_floats() {
        let duplicate = bytes_with_producer(r#"{"value":1,"value":2}"#);
        assert!(parse_release_manifest(&duplicate, false).is_err());

        let nonfinite = bytes_with_producer(r#"{"float":1e400}"#);
        assert!(parse_release_manifest(&nonfinite, false).is_err());
    }

    #[test]
    fn private_raw_value_lookalikes_are_opaque_and_original_bytes_survive() {
        let producer = r#"{"$serde_json::private::RawValue":"1","decoy":"$serde_json::private::RawValue","wide":18446744073709551616}"#;
        let raw = bytes_with_producer(producer);
        let parsed = parse_release_manifest(&raw, false).expect("opaque marker-like producer");
        assert_eq!(parsed.producer.get(), producer);
    }

    #[test]
    fn raw_value_prepass_accepts_exact_depth_and_refuses_one_more_container() {
        let producer = |nested_arrays: usize| {
            format!(
                "{{\"nested\":{}0{}}}",
                "[".repeat(nested_arrays),
                "]".repeat(nested_arrays)
            )
        };
        let maximum = bytes_with_producer(&producer(126));
        assert!(parse_release_manifest(&maximum, false).is_ok());

        let too_deep = bytes_with_producer(&producer(127));
        assert!(parse_release_manifest(&too_deep, false).is_err());
    }
}

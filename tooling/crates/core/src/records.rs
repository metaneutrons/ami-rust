//! Closed-schema metadata parsing. These values remain untrusted claims until
//! the caller checks the actual host, ownership, receipt and file inventories.
//! Parsing does not access roots, mark a state ready, execute a legacy driver,
//! or rewrite the original bytes whose digest is used by the caller.
use crate::{
    Refusal, Result,
    digest::is_sha256_digest,
    json::{JsonProfile, parse_json},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Sha256(String);

impl Sha256 {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(input)?;
        if !is_sha256_digest(&value) {
            return Err(serde::de::Error::custom(
                "expected 64 lowercase SHA-256 hex characters",
            ));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Host {
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[serde(rename = "macos-aarch64")]
    MacosAarch64,
}

impl Host {
    pub fn current() -> Result<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => Ok(Self::LinuxX86_64),
            ("macos", "aarch64") => Ok(Self::MacosAarch64),
            _ => Err(Refusal::new("unsupported native host profile")),
        }
    }

    pub fn ensure_current(self) -> Result<()> {
        if self != Self::current()? {
            return Err(Refusal::new("record host does not match this host"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum StateSchema {
    #[serde(rename = "ami-rust-package-state-v2")]
    V2,
}

#[derive(Debug, Serialize, Deserialize)]
enum SelectionSchema {
    #[serde(rename = "ami-rust-selection-v2")]
    V2,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum StateStatus {
    Prepared,
    Ready,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageStateV2 {
    schema: StateSchema,
    pub status: StateStatus,
    pub host: Host,
    pub sdk_version: String,
    pub package_version: String,
    pub source_commit: String,
    pub manifest_sha256: Sha256,
    pub install_receipt_sha256: Sha256,
    pub cli_sha256: Sha256,
    pub core_sha256: Sha256,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRoots {
    pub rust: PathBuf,
    pub cargo: PathBuf,
    pub toolchain: PathBuf,
    pub collector: PathBuf,
    pub csdk: PathBuf,
    pub vendor: PathBuf,
}

impl ComponentRoots {
    pub fn entries(&self) -> [(&'static str, &Path); 6] {
        [
            ("rust", &self.rust),
            ("cargo", &self.cargo),
            ("toolchain", &self.toolchain),
            ("collector", &self.collector),
            ("csdk", &self.csdk),
            ("vendor", &self.vendor),
        ]
    }

    /// Lexical checks only. Real directory identity/case aliases, symlinks,
    /// ownership and inventory must still be checked at the filesystem boundary.
    fn check_shape(&self) -> Result<()> {
        let entries = self.entries();
        for (name, path) in entries {
            let normalized: PathBuf = path.components().collect();
            if !path.is_absolute()
                || path.as_os_str() != normalized.as_os_str()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || path
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .any(|byte| *byte < 32 || *byte == 127)
            {
                return Err(Refusal::new(format!(
                    "{name} root must be a normalized absolute path"
                )));
            }
        }
        for (index, (_, left)) in entries.iter().enumerate() {
            for (_, right) in entries.iter().skip(index + 1) {
                if left.starts_with(right) || right.starts_with(left) {
                    return Err(Refusal::new("component roots overlap lexically"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionV2 {
    schema: SelectionSchema,
    pub host: Host,
    pub install_receipt_sha256: Sha256,
    pub components: ComponentRoots,
}

fn decode_schema<T: DeserializeOwned>(bytes: &[u8], expected: &str) -> Result<T> {
    let document: serde_json::Value =
        parse_json(bytes, JsonProfile::PackageMetadataStateSelection)?;
    let schema = document
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(serde_json::Value::as_str);
    if schema != Some(expected) {
        return Err(Refusal::new(format!(
            "unsupported or missing schema; expected {expected}"
        )));
    }
    // The first structural pass already rejected duplicates; the schema is
    // selected before typed field interpretation and no filesystem access occurs.
    T::deserialize(document).map_err(|error| Refusal::new(format!("invalid {expected}: {error}")))
}

pub fn parse_package_state(bytes: &[u8]) -> Result<PackageStateV2> {
    let state: PackageStateV2 = decode_schema(bytes, "ami-rust-package-state-v2")?;
    if state.cli_sha256 != state.core_sha256 {
        return Err(Refusal::new(
            "CLI/core digests differ for the static-core contract",
        ));
    }
    if state.source_commit.len() != 40
        || !state
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Refusal::new(
            "source commit must contain 40 lowercase hex characters",
        ));
    }
    for version in [&state.sdk_version, &state.package_version] {
        if version.is_empty()
            || version
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err(Refusal::new("version identity must be a nonempty token"));
        }
    }
    Ok(state)
}

pub fn parse_selection(bytes: &[u8]) -> Result<SelectionV2> {
    let selection: SelectionV2 = decode_schema(bytes, "ami-rust-selection-v2")?;
    selection.components.check_shape()?;
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn state() -> Value {
        json!({"schema":"ami-rust-package-state-v2","status":"PREPARED","host":"linux-x86_64",
            "sdk_version":"0.2.0-dev","package_version":"0.2.0-dev","source_commit":"a".repeat(40),
            "manifest_sha256":"1".repeat(64),"install_receipt_sha256":"2".repeat(64),
            "cli_sha256":"3".repeat(64),"core_sha256":"3".repeat(64)})
    }
    fn selection() -> Value {
        json!({"schema":"ami-rust-selection-v2","host":"linux-x86_64", "install_receipt_sha256":"1".repeat(64),
            "components":{"rust":"/sdk/rust","cargo":"/sdk/cargo","toolchain":"/sdk/toolchain",
                "collector":"/sdk/collector","csdk":"/sdk/csdk","vendor":"/sdk/vendor"}})
    }
    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn parses_closed_records_without_accessing_or_trusting_claimed_paths() {
        let state = parse_package_state(&bytes(&state())).unwrap();
        assert_eq!(state.status, StateStatus::Prepared);
        assert_eq!(state.cli_sha256, state.core_sha256);
        assert_eq!(
            parse_selection(&bytes(&selection()))
                .unwrap()
                .components
                .entries()
                .len(),
            6
        );
    }

    #[test]
    fn unknown_or_missing_schema_refuses_before_interpreting_fields() {
        for schema in [
            Value::Null,
            json!("ami-rust-package-state-v1"),
            json!("ami-rust-package-state-v999"),
        ] {
            let mut value = state();
            value["schema"] = schema;
            value["cli_sha256"] = json!(false);
            assert!(
                parse_package_state(&bytes(&value))
                    .unwrap_err()
                    .to_string()
                    .contains("schema")
            );
        }
        let mut value = state();
        value.as_object_mut().unwrap().remove("schema");
        assert!(parse_package_state(&bytes(&value)).is_err());
        // The legacy schema-less/Python selection is never an execution fallback.
        assert!(parse_selection(br#"{"python":"/must-not-execute","components":{}}"#).is_err());
    }

    #[test]
    fn refuses_extra_missing_wrong_typed_and_inconsistent_state_fields() {
        for field in [
            "manifest_sha256",
            "install_receipt_sha256",
            "cli_sha256",
            "core_sha256",
        ] {
            for bad in [json!("A".repeat(64)), json!("0".repeat(63)), json!(true)] {
                let mut value = state();
                value[field] = bad;
                assert!(parse_package_state(&bytes(&value)).is_err());
            }
        }
        for (field, bad) in [
            ("status", json!("RUNNING")),
            ("host", json!("linux-aarch64")),
            ("source_commit", json!("a".repeat(39))),
            ("sdk_version", json!("")),
            ("package_version", json!("version with spaces")),
            ("core_sha256", json!("4".repeat(64))),
            ("python", json!("/legacy-driver")),
        ] {
            let mut value = state();
            value[field] = bad;
            assert!(parse_package_state(&bytes(&value)).is_err());
        }
        let mut value = state();
        value.as_object_mut().unwrap().remove("host");
        assert!(parse_package_state(&bytes(&value)).is_err());
    }

    #[test]
    fn selection_requires_exact_separate_normalized_absolute_roots() {
        for bad in [
            "relative",
            "/sdk/rust/",
            "/sdk/./rust",
            "/sdk/../rust",
            "/sdk/cargo",
            "/sdk",
            "/sdk/ru\nst",
        ] {
            let mut value = selection();
            value["components"]["rust"] = json!(bad);
            assert!(parse_selection(&bytes(&value)).is_err(), "{bad:?}");
        }
        let mut value = selection();
        value["components"]["extra"] = json!("/sdk/extra");
        assert!(parse_selection(&bytes(&value)).is_err());
        let mut value = selection();
        value["components"].as_object_mut().unwrap().remove("rust");
        assert!(parse_selection(&bytes(&value)).is_err());
        let mut value = selection();
        value["host"] = json!("macos-aarch64");
        let parsed = parse_selection(&bytes(&value)).unwrap();
        assert_eq!(parsed.host, Host::MacosAarch64);
    }

    #[test]
    fn current_host_check_is_explicit_and_refuses_the_other_profile() {
        let current = Host::current().unwrap();
        current.ensure_current().unwrap();
        let other = if current == Host::LinuxX86_64 {
            Host::MacosAarch64
        } else {
            Host::LinuxX86_64
        };
        assert!(other.ensure_current().is_err());
    }
}

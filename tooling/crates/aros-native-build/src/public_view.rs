//! Shared exact-file policy for the proposed public SDK view.
//!
//! This module is intentionally independent of core/native-build runtime types
//! beyond the common `Refusal` and `Result` error surface. Callers remain
//! responsible for choosing a component profile and verifying parent bytes.

use crate::{Refusal, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The one versioned policy shared by core and aros-native-build.
pub const PUBLIC_VIEW_JSON: &str = include_str!("../pins/public-view-v1.json");

const POLICY_SCHEMA: &str = "ami-rust-public-sdk-exclusion-policy-v1";
const POLICY_VERSION: u32 = 1;
const EXPECTED_COMPONENTS: [&str; 2] = ["llvm", "rust"];
const EXPECTED_EXCLUSION_COUNT: usize = 22;
const EXPECTED_RUST_EXCLUSION_COUNT: usize = 11;
const EXPECTED_LLVM_EXCLUSION_COUNT: usize = 11;
const RUST_SOURCE_TREE_PREFIX: &str = "lib/rustlib/src/rust/";

/// One exact regular-file tuple selected by the public-view policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicViewExclusion {
    pub component: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    schema: String,
    version: u32,
    components: Vec<String>,
    exclusions: Vec<PublicViewExclusion>,
}

/// An owned, validated public-view policy.
#[derive(Clone, Debug)]
pub struct PublicViewPolicy {
    exclusions: Vec<PublicViewExclusion>,
    sha256: String,
}

impl PublicViewPolicy {
    /// Parse and validate the policy bytes embedded with this module.
    pub fn embedded() -> Result<Self> {
        Self::parse(PUBLIC_VIEW_JSON)
    }

    /// Parse an owned policy from JSON, rejecting unsupported or broad rules.
    pub fn parse(json: &str) -> Result<Self> {
        let document: PolicyDocument = serde_json::from_str(json)
            .map_err(|error| Refusal::new(format!("invalid public-view policy JSON: {error}")))?;

        if document.schema != POLICY_SCHEMA || document.version != POLICY_VERSION {
            return Err(Refusal::new(
                "public-view policy has an unsupported schema or version",
            ));
        }
        if document.components.len() != EXPECTED_COMPONENTS.len()
            || document
                .components
                .iter()
                .map(String::as_str)
                .ne(EXPECTED_COMPONENTS)
        {
            return Err(Refusal::new(
                "public-view policy must name exactly the Rust and LLVM components",
            ));
        }
        if document.exclusions.len() != EXPECTED_EXCLUSION_COUNT {
            return Err(Refusal::new(
                "public-view policy has an unexpected number of exact exclusions",
            ));
        }

        let mut seen_paths = BTreeSet::new();
        let mut rust_count = 0;
        let mut llvm_count = 0;
        for exclusion in &document.exclusions {
            if !document
                .components
                .iter()
                .any(|component| component == &exclusion.component)
            {
                return Err(Refusal::new(
                    "public-view policy names an unexpected component",
                ));
            }
            if !is_safe_relative_path(&exclusion.path) {
                return Err(Refusal::new(
                    "public-view policy contains an unsafe or wildcard path",
                ));
            }
            if !is_lowercase_sha256(&exclusion.sha256) {
                return Err(Refusal::new(
                    "public-view policy contains an invalid lowercase SHA-256 digest",
                ));
            }
            if !seen_paths.insert(exclusion.path.as_str()) {
                return Err(Refusal::new(
                    "public-view policy contains a duplicate component-relative path",
                ));
            }
            match exclusion.component.as_str() {
                "rust" => {
                    rust_count += 1;
                    if exclusion.path.starts_with(RUST_SOURCE_TREE_PREFIX) {
                        return Err(Refusal::new(
                            "public-view policy must preserve files inside rust-src",
                        ));
                    }
                }
                "llvm" => llvm_count += 1,
                _ => {
                    return Err(Refusal::new(
                        "public-view policy names an unexpected component",
                    ));
                }
            }
        }
        if rust_count != EXPECTED_RUST_EXCLUSION_COUNT
            || llvm_count != EXPECTED_LLVM_EXCLUSION_COUNT
        {
            return Err(Refusal::new(
                "public-view policy has an unexpected Rust or LLVM exclusion count",
            ));
        }

        Ok(Self {
            exclusions: document.exclusions,
            sha256: sha256_hex(json.as_bytes()),
        })
    }

    /// Return the validated exact tuples as an immutable slice.
    pub fn exclusions(&self) -> &[PublicViewExclusion] {
        &self.exclusions
    }

    /// Return the SHA-256 digest of the policy JSON bytes that were parsed.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Check a component-relative path against its complete pinned tuple.
    ///
    /// Returns `Ok(true)` for an exact selected tuple and `Ok(false)` when the
    /// component/path pair is not selected. A selected path with changed bytes
    /// or SHA-256 is refused so callers cannot silently accept drift.
    pub fn lookup(&self, component: &str, path: &str, bytes: u64, sha256: &str) -> Result<bool> {
        let Some(expected) = self
            .exclusions
            .iter()
            .find(|row| row.component == component && row.path == path)
        else {
            return Ok(false);
        };

        if expected.bytes != bytes || expected.sha256 != sha256 {
            return Err(Refusal::new(
                "selected public-view component path has changed bytes or SHA-256",
            ));
        }
        Ok(true)
    }
}

fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty() || !path.is_ascii() || path.starts_with('/') {
        return false;
    }
    path.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
            })
    })
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{PUBLIC_VIEW_JSON, PublicViewPolicy, RUST_SOURCE_TREE_PREFIX};
    use crate::Result;
    use serde::Deserialize;
    use serde_json::{Value, json};

    #[derive(Deserialize)]
    struct PinInventory {
        files: Vec<PinFile>,
        #[serde(default)]
        symlinks: Vec<PinSymlink>,
    }

    #[derive(Deserialize)]
    struct PinFile {
        path: String,
        bytes: u64,
        sha256: String,
    }

    #[derive(Deserialize)]
    struct PinSymlink {
        path: String,
    }

    struct HostPins {
        name: &'static str,
        rust: PinInventory,
        llvm: PinInventory,
    }

    fn inventory(json: &str) -> PinInventory {
        serde_json::from_str(json).expect("active parent pin JSON should parse")
    }

    fn all_host_pins() -> [HostPins; 3] {
        [
            HostPins {
                name: "macos-aarch64",
                rust: inventory(include_str!("../pins/macos-aarch64/rust-runtime-v2.json")),
                llvm: inventory(include_str!("../pins/macos-aarch64/toolchain.json")),
            },
            HostPins {
                name: "linux-x86_64",
                rust: inventory(include_str!("../pins/linux-x86_64/rust.json")),
                llvm: inventory(include_str!("../pins/linux-x86_64/toolchain.json")),
            },
            HostPins {
                name: "linux-aarch64",
                rust: inventory(include_str!("../pins/linux-aarch64/rust.json")),
                llvm: inventory(include_str!("../pins/linux-aarch64/toolchain.json")),
            },
        ]
    }

    fn policy_value() -> Value {
        serde_json::from_str(PUBLIC_VIEW_JSON).expect("embedded policy JSON should parse")
    }

    fn parse_value(value: &Value) -> Result<PublicViewPolicy> {
        PublicViewPolicy::parse(&value.to_string())
    }

    #[test]
    fn embedded_policy_parses_and_exact_lookup_checks_the_full_tuple() {
        let policy = PublicViewPolicy::embedded().expect("embedded policy should be valid");
        assert_eq!(policy.exclusions().len(), 22);
        assert_eq!(policy.sha256().len(), 64);

        let row = &policy.exclusions()[0];
        assert!(
            policy
                .lookup(&row.component, &row.path, row.bytes, &row.sha256)
                .expect("exact tuple lookup should succeed")
        );
        assert!(
            policy
                .lookup(&row.component, &row.path, row.bytes + 1, &row.sha256)
                .is_err()
        );
        assert!(
            !policy
                .lookup("rust", "bin/not-selected", 1, &"0".repeat(64))
                .expect("unselected path should not match")
        );
    }

    #[test]
    fn every_policy_tuple_matches_regular_files_in_all_three_active_pins() {
        let policy = PublicViewPolicy::embedded().expect("embedded policy should be valid");
        let hosts = all_host_pins();

        for host in &hosts {
            for exclusion in policy.exclusions() {
                let pin = match exclusion.component.as_str() {
                    "rust" => &host.rust,
                    "llvm" => &host.llvm,
                    _ => panic!("validated policy component should be known"),
                };
                let matches: Vec<_> = pin
                    .files
                    .iter()
                    .filter(|row| row.path == exclusion.path)
                    .collect();
                assert_eq!(matches.len(), 1, "{}: {}", host.name, exclusion.path);
                assert_eq!(
                    matches[0].bytes, exclusion.bytes,
                    "{}: {}",
                    host.name, exclusion.path
                );
                assert_eq!(
                    matches[0].sha256, exclusion.sha256,
                    "{}: {}",
                    host.name, exclusion.path
                );
                assert!(pin.symlinks.iter().all(|link| link.path != exclusion.path));
            }

            let preserved_sources: Vec<_> = host
                .rust
                .files
                .iter()
                .filter(|row| {
                    row.path.starts_with(RUST_SOURCE_TREE_PREFIX) && row.path.ends_with(".py")
                })
                .collect();
            assert_eq!(preserved_sources.len(), 5, "{}", host.name);
            for row in preserved_sources {
                assert!(
                    !policy
                        .lookup("rust", &row.path, row.bytes, &row.sha256)
                        .expect("preserved rust-src file should not conflict with policy")
                );
            }
        }
    }

    #[test]
    fn parser_rejects_wrong_schema_version_components_and_unknown_fields() {
        let mut value = policy_value();
        value["schema"] = json!("ami-rust-public-sdk-exclusion-policy-v2");
        assert!(parse_value(&value).is_err());

        let mut value = policy_value();
        value["version"] = json!(2);
        assert!(parse_value(&value).is_err());

        let mut value = policy_value();
        value["components"] = json!(["llvm", "rust", "other"]);
        assert!(parse_value(&value).is_err());

        let mut value = policy_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("status".to_owned(), json!("candidate"));
        assert!(parse_value(&value).is_err());
    }

    #[test]
    fn parser_rejects_duplicate_unsafe_wildcard_and_nonlowercase_digest_rows() {
        let mut value = policy_value();
        let rows = value["exclusions"].as_array_mut().unwrap();
        rows[1]["path"] = rows[0]["path"].clone();
        assert!(parse_value(&value).is_err());

        let mut value = policy_value();
        value["exclusions"][0]["path"] = json!("../outside");
        assert!(parse_value(&value).is_err());

        let mut value = policy_value();
        value["exclusions"][0]["path"] = json!("share/*");
        assert!(parse_value(&value).is_err());

        let mut value = policy_value();
        value["exclusions"][0]["sha256"] = json!("A".repeat(64));
        assert!(parse_value(&value).is_err());
    }
}

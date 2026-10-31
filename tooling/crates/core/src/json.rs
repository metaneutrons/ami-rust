//! Bounded JSON input for Rust-owned host records.
//!
//! The parser first builds a `serde_json::Value` through a recursive visitor.
//! That pass is the security boundary for duplicate keys and container depth;
//! typed deserialization happens only after the entire document passes it.

use std::path::Path;

use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::{Refusal, Result};

/// The frozen maximum nesting depth, counting every JSON array and object.
pub const JSON_MAX_CONTAINER_DEPTH: usize = 128;

pub const PACKAGE_METADATA_STATE_SELECTION_MAX_BYTES: usize = 2_097_152;
pub const PROJECT_LOCK_MAX_BYTES: usize = 1_048_576;
pub const SDK_COMPONENT_MANIFEST_MAX_BYTES: usize = 16_777_216;
pub const RELEASE_MANIFEST_AND_INSTALL_RECEIPT_MAX_BYTES: usize = 4_194_304;
pub const PUBLISHER_POLICY_AND_AUTHENTICATION_METADATA_MAX_BYTES: usize = 1_048_576;
pub const GITHUB_ATTESTATION_BUNDLE_MAX_BYTES: usize = 2_097_152;
pub const COSIGN_BUNDLE_MAX_BYTES: usize = 1_048_576;
pub const TRUSTED_ROOT_MAX_BYTES: usize = 16_777_216;
/// Existing external verifier stdout capture profile (not bundle input size).
pub const VERIFIER_OUTPUT_MAX_BYTES: usize = 4_194_304;
/// Maintainer-only Cargo vendor overlay receipt bound; not an SDK consumer limit.
pub const CARGO_VENDOR_OVERLAY_RECEIPT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Maintainer-only pinned C-SDK compilation database (currently about 38 MiB).
pub const CSDK_COMPILATION_DATABASE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Repository-owned RP1 input and output contract.
pub const PRODUCTION_CONTRACT_MAX_BYTES: usize = 1024 * 1024;

/// A JSON format with an explicit input byte bound.
///
/// Consumer profile limits are frozen in `contracts-v1.json`. The
/// `CargoVendorOverlayReceipt` profile has a separate maintainer-only bound and
/// is not a consumer compatibility limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonProfile {
    PackageMetadataStateSelection,
    ProjectLock,
    SdkComponentManifest,
    ReleaseManifestAndInstallReceipt,
    PublisherPolicyAndAuthenticationMetadata,
    GithubAttestationBundle,
    CosignBundle,
    TrustedRoot,
    VerifierOutput,
    CargoVendorOverlayReceipt,
    CsdkCompilationDatabase,
    ProductionContract,
}

impl JsonProfile {
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::PackageMetadataStateSelection => PACKAGE_METADATA_STATE_SELECTION_MAX_BYTES,
            Self::ProjectLock => PROJECT_LOCK_MAX_BYTES,
            Self::SdkComponentManifest => SDK_COMPONENT_MANIFEST_MAX_BYTES,
            Self::ReleaseManifestAndInstallReceipt => {
                RELEASE_MANIFEST_AND_INSTALL_RECEIPT_MAX_BYTES
            }
            Self::PublisherPolicyAndAuthenticationMetadata => {
                PUBLISHER_POLICY_AND_AUTHENTICATION_METADATA_MAX_BYTES
            }
            Self::GithubAttestationBundle => GITHUB_ATTESTATION_BUNDLE_MAX_BYTES,
            Self::CosignBundle => COSIGN_BUNDLE_MAX_BYTES,
            Self::TrustedRoot => TRUSTED_ROOT_MAX_BYTES,
            Self::VerifierOutput => VERIFIER_OUTPUT_MAX_BYTES,
            Self::CargoVendorOverlayReceipt => CARGO_VENDOR_OVERLAY_RECEIPT_MAX_BYTES,
            Self::CsdkCompilationDatabase => CSDK_COMPILATION_DATABASE_MAX_BYTES,
            Self::ProductionContract => PRODUCTION_CONTRACT_MAX_BYTES,
        }
    }
}

/// Read a bounded regular file and parse one JSON value under its format limit.
///
/// `files::read_regular_bounded` checks the file type and initial size, then
/// enforces the same limit during the read so a growing file is refused.
pub fn read_json<T: DeserializeOwned>(path: &Path, profile: JsonProfile) -> Result<T> {
    let bytes = crate::files::read_regular_bounded(path, profile.max_bytes())?;
    parse_json(&bytes, profile)
}

/// Parse one bounded JSON document, rejecting duplicate keys at every depth.
///
/// JSON numbers retain `serde_json::Number` semantics (`i64`, `u64`, or finite
/// `f64`). After the structural pass, `T` is deserialized from that value, so
/// scalar roots and the exact schema remain the typed caller's responsibility.
/// For an opaque `serde_json::Value` tree, use [`parse_json_value`] directly:
/// its `Deserialize` implementation otherwise recognizes private marker keys.
pub fn parse_json<T: DeserializeOwned>(bytes: &[u8], profile: JsonProfile) -> Result<T> {
    let value = parse_json_value(bytes, profile)?;
    T::deserialize(value)
        .map_err(|error| Refusal::new(format!("JSON value does not match requested type: {error}")))
}

/// Parse a bounded JSON tree without deserializing it a second time.
///
/// Opaque diagnostic objects can contain serde's private marker-like keys.
/// Returning the strict visitor's tree directly preserves those as ordinary
/// map entries instead of interpreting them as a serialization envelope.
pub fn parse_json_value(bytes: &[u8], profile: JsonProfile) -> Result<Value> {
    let limit = profile.max_bytes();
    if bytes.len() > limit {
        return Err(Refusal::new(format!(
            "JSON input exceeds the {} byte limit for {profile:?}",
            limit
        )));
    }

    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Refusal::new("JSON input must not begin with a UTF-8 BOM"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Refusal::new(format!("JSON input is not valid UTF-8: {error}")))?;

    let mut deserializer = serde_json::Deserializer::from_str(text);
    // The default serde_json counter rejects nesting at 128 because it spends
    // one unit on entry. The visitor below counts containers directly so 128
    // is accepted and the 129th container is rejected before its children.
    deserializer.disable_recursion_limit();
    let value = JsonSeed {
        parent_container_depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| Refusal::new(format!("invalid JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| Refusal::new(format!("invalid JSON: {error}")))?;

    Ok(value)
}

/// Guard a borrowed RawValue pass before its syntax parser runs. The full
/// strict-tree pass must still follow: this only bounds bytes and nesting.
pub(crate) fn check_raw_value_prepass(raw: &[u8], profile: JsonProfile) -> Result<()> {
    if raw.len() > profile.max_bytes() {
        return Err(Refusal::new("raw JSON exceeds its profile byte limit"));
    }
    std::str::from_utf8(raw).map_err(|_| Refusal::new("raw JSON is not UTF-8"))?;
    let (mut quoted, mut escaped, mut depth) = (false, false, 0_usize);
    for byte in raw {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > JSON_MAX_CONTAINER_DEPTH {
                    return Err(Refusal::new("raw JSON exceeds container depth"));
                }
            }
            b'}' | b']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| Refusal::new("unbalanced raw JSON container"))?;
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct JsonSeed {
    parent_container_depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonVisitor {
            parent_container_depth: self.parent_container_depth,
        })
    }
}

struct JsonVisitor {
    parent_container_depth: usize,
}

impl JsonVisitor {
    fn next_container_depth<E>(&self) -> std::result::Result<usize, E>
    where
        E: serde::de::Error,
    {
        let depth = self
            .parent_container_depth
            .checked_add(1)
            .ok_or_else(|| E::custom("JSON container depth overflow"))?;
        if depth > JSON_MAX_CONTAINER_DEPTH {
            return Err(E::custom(format!(
                "JSON container depth exceeds the maximum of {JSON_MAX_CONTAINER_DEPTH}"
            )));
        }
        Ok(depth)
    }
}

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = self.next_container_depth()?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonSeed {
            parent_container_depth: depth,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let depth = self.next_container_depth()?;
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let value = object.next_value_seed(JsonSeed {
                parent_container_depth: depth,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CARGO_VENDOR_OVERLAY_RECEIPT_MAX_BYTES, COSIGN_BUNDLE_MAX_BYTES,
        GITHUB_ATTESTATION_BUNDLE_MAX_BYTES, JSON_MAX_CONTAINER_DEPTH, JsonProfile,
        PACKAGE_METADATA_STATE_SELECTION_MAX_BYTES, PROJECT_LOCK_MAX_BYTES,
        PUBLISHER_POLICY_AND_AUTHENTICATION_METADATA_MAX_BYTES,
        RELEASE_MANIFEST_AND_INSTALL_RECEIPT_MAX_BYTES, SDK_COMPONENT_MANIFEST_MAX_BYTES,
        TRUSTED_ROOT_MAX_BYTES, parse_json, parse_json_value,
    };
    use serde_json::Value;

    const PROFILE: JsonProfile = JsonProfile::PackageMetadataStateSelection;

    #[test]
    fn profiles_match_the_frozen_format_contract() {
        let contract: Value =
            serde_json::from_str(include_str!("../tests/fixtures/contracts-v1.json")).unwrap();
        let limits = &contract["proposed_schema_policy"]["metadata_limits"];
        assert_eq!(limits["json_max_container_depth"], JSON_MAX_CONTAINER_DEPTH);
        for (profile, key) in [
            (
                JsonProfile::PackageMetadataStateSelection,
                "package_metadata_state_selection",
            ),
            (JsonProfile::ProjectLock, "project_lock"),
            (JsonProfile::SdkComponentManifest, "sdk_component_manifest"),
            (
                JsonProfile::ReleaseManifestAndInstallReceipt,
                "release_manifest_and_install_receipt",
            ),
            (
                JsonProfile::PublisherPolicyAndAuthenticationMetadata,
                "publisher_policy_and_authentication_metadata",
            ),
            (
                JsonProfile::GithubAttestationBundle,
                "github_attestation_bundle",
            ),
            (JsonProfile::CosignBundle, "cosign_bundle"),
            (JsonProfile::TrustedRoot, "trusted_root"),
        ] {
            assert_eq!(limits[key], profile.max_bytes(), "{key}");
        }
    }

    fn nested_arrays(depth: usize) -> String {
        format!("{}0{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn nested_objects(depth: usize) -> String {
        format!("{}0{}", "{\"x\":".repeat(depth), "}".repeat(depth))
    }

    #[test]
    fn accepts_exact_container_depth_and_refuses_one_more() {
        assert!(
            parse_json::<Value>(nested_arrays(JSON_MAX_CONTAINER_DEPTH).as_bytes(), PROFILE)
                .is_ok()
        );
        let too_deep = nested_arrays(JSON_MAX_CONTAINER_DEPTH + 1);
        let error = parse_json::<Value>(too_deep.as_bytes(), PROFILE).unwrap_err();
        assert!(error.to_string().contains("container depth"));

        assert!(
            parse_json::<Value>(nested_objects(JSON_MAX_CONTAINER_DEPTH).as_bytes(), PROFILE)
                .is_ok()
        );
        let too_deep = nested_objects(JSON_MAX_CONTAINER_DEPTH + 1);
        let error = parse_json::<Value>(too_deep.as_bytes(), PROFILE).unwrap_err();
        assert!(error.to_string().contains("container depth"));
    }

    #[test]
    fn ignores_container_like_text_inside_strings() {
        let text = format!("{:?}", "[".repeat(JSON_MAX_CONTAINER_DEPTH + 1));
        assert_eq!(
            parse_json::<String>(text.as_bytes(), PROFILE)
                .unwrap()
                .len(),
            129
        );
    }

    #[test]
    fn rejects_duplicate_keys_at_each_object_depth() {
        for input in [
            br#"{"x":1,"x":2}"#.as_slice(),
            br#"{"nested":{"x":1,"x":2}}"#.as_slice(),
            br#"[{"x":1,"x":2}]"#.as_slice(),
        ] {
            let error = parse_json::<Value>(input, PROFILE).unwrap_err();
            assert!(error.to_string().contains("duplicate JSON object key"));
        }
    }

    #[test]
    fn direct_tree_preserves_private_marker_like_keys_as_ordinary_data() {
        let tree = parse_json_value(
            br#"{"nested":{"$serde_json::private::RawValue":"{\"changed\":true}"},"$serde_json::private::Number":"123"}"#,
            PROFILE,
        )
        .unwrap();
        assert_eq!(
            tree["nested"]["$serde_json::private::RawValue"],
            Value::String("{\"changed\":true}".into())
        );
        assert_eq!(
            tree["$serde_json::private::Number"],
            Value::String("123".into())
        );
        assert!(tree["nested"].get("changed").is_none());
        assert!(
            parse_json_value(
                br#"{"$serde_json::private::RawValue":"1","$serde_json::private::RawValue":"2"}"#,
                PROFILE,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_bom_invalid_utf8_trailing_values_and_nonfinite_numbers() {
        for (input, expected) in [
            (&b"\xef\xbb\xbfnull"[..], "BOM"),
            (&b"{\xff}"[..], "UTF-8"),
            (&b"null null"[..], "trailing characters"),
            (&b"NaN"[..], "invalid JSON"),
            (&b"Infinity"[..], "invalid JSON"),
            (&b"-Infinity"[..], "invalid JSON"),
        ] {
            let error = parse_json::<Value>(input, PROFILE).unwrap_err();
            assert!(error.to_string().contains(expected), "{input:?}: {error}");
        }
    }

    #[test]
    fn preserves_serde_json_integer_and_finite_float_semantics() {
        assert_eq!(
            parse_json::<i64>(b"-9223372036854775808", PROFILE).unwrap(),
            i64::MIN
        );
        assert_eq!(
            parse_json::<u64>(b"18446744073709551615", PROFILE).unwrap(),
            u64::MAX
        );
        assert_eq!(parse_json::<f64>(b"1.25", PROFILE).unwrap(), 1.25);
        assert!(parse_json::<u64>(b"-1", PROFILE).is_err());
        assert_eq!(
            parse_json::<String>(br#""scalar root""#, PROFILE).unwrap(),
            "scalar root"
        );
    }

    fn padded_null(size: usize) -> Vec<u8> {
        assert!(size >= 4);
        let mut bytes = vec![b' '; size];
        bytes[..4].copy_from_slice(b"null");
        bytes
    }

    #[test]
    fn maintainer_vendor_receipt_accepts_json_above_consumer_limit() {
        const SDK_CONSUMER_LIMIT: usize = 16 * 1024 * 1024;
        let input = padded_null(SDK_CONSUMER_LIMIT + 1);
        assert_eq!(
            parse_json_value(&input, JsonProfile::CargoVendorOverlayReceipt).unwrap(),
            Value::Null
        );
        let error = parse_json_value(&input, JsonProfile::SdkComponentManifest).unwrap_err();
        assert!(error.to_string().contains("byte limit"));
    }

    #[test]
    fn maintainer_vendor_receipt_obeys_exact_64_mib_bound() {
        const MAINTAINER_LIMIT: usize = 64 * 1024 * 1024;
        assert_eq!(CARGO_VENDOR_OVERLAY_RECEIPT_MAX_BYTES, MAINTAINER_LIMIT);
        assert_eq!(
            JsonProfile::CargoVendorOverlayReceipt.max_bytes(),
            MAINTAINER_LIMIT
        );
        let exact = padded_null(MAINTAINER_LIMIT);
        assert_eq!(
            parse_json_value(&exact, JsonProfile::CargoVendorOverlayReceipt).unwrap(),
            Value::Null
        );
        drop(exact);
        let above = padded_null(MAINTAINER_LIMIT + 1);
        let error = parse_json_value(&above, JsonProfile::CargoVendorOverlayReceipt).unwrap_err();
        assert!(error.to_string().contains("byte limit"));
    }

    #[test]
    fn maintainer_vendor_receipt_profile_still_rejects_duplicate_keys() {
        let error = parse_json_value(
            br#"{"receipt":{"version":1,"version":2}}"#,
            JsonProfile::CargoVendorOverlayReceipt,
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate JSON object key"));
    }

    #[test]
    fn enforces_every_frozen_profile_byte_limit_including_exact_boundary() {
        let profiles_and_limits = [
            (
                JsonProfile::PackageMetadataStateSelection,
                PACKAGE_METADATA_STATE_SELECTION_MAX_BYTES,
            ),
            (JsonProfile::ProjectLock, PROJECT_LOCK_MAX_BYTES),
            (
                JsonProfile::SdkComponentManifest,
                SDK_COMPONENT_MANIFEST_MAX_BYTES,
            ),
            (
                JsonProfile::ReleaseManifestAndInstallReceipt,
                RELEASE_MANIFEST_AND_INSTALL_RECEIPT_MAX_BYTES,
            ),
            (
                JsonProfile::PublisherPolicyAndAuthenticationMetadata,
                PUBLISHER_POLICY_AND_AUTHENTICATION_METADATA_MAX_BYTES,
            ),
            (
                JsonProfile::GithubAttestationBundle,
                GITHUB_ATTESTATION_BUNDLE_MAX_BYTES,
            ),
            (JsonProfile::CosignBundle, COSIGN_BUNDLE_MAX_BYTES),
            (JsonProfile::TrustedRoot, TRUSTED_ROOT_MAX_BYTES),
            (
                JsonProfile::VerifierOutput,
                super::VERIFIER_OUTPUT_MAX_BYTES,
            ),
        ];

        for (profile, limit) in profiles_and_limits {
            let exact = padded_null(limit);
            assert_eq!(parse_json::<Value>(&exact, profile).unwrap(), Value::Null);
            let mut oversized = exact;
            oversized.push(b' ');
            let error = parse_json::<Value>(&oversized, profile).unwrap_err();
            assert!(error.to_string().contains("byte limit"));
        }
    }

    #[test]
    fn rejects_malformed_json_and_typed_value_mismatch() {
        assert!(parse_json::<Value>(br#"{"x": "#, PROFILE).is_err());
        assert!(parse_json::<u8>(b"256", PROFILE).is_err());
    }
}

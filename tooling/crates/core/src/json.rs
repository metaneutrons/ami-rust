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

/// A JSON format whose input byte limit is frozen in `contracts-v1.json`.
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
pub fn parse_json<T: DeserializeOwned>(bytes: &[u8], profile: JsonProfile) -> Result<T> {
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

    T::deserialize(value)
        .map_err(|error| Refusal::new(format!("JSON value does not match requested type: {error}")))
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
        COSIGN_BUNDLE_MAX_BYTES, GITHUB_ATTESTATION_BUNDLE_MAX_BYTES, JSON_MAX_CONTAINER_DEPTH,
        JsonProfile, PACKAGE_METADATA_STATE_SELECTION_MAX_BYTES, PROJECT_LOCK_MAX_BYTES,
        PUBLISHER_POLICY_AND_AUTHENTICATION_METADATA_MAX_BYTES,
        RELEASE_MANIFEST_AND_INSTALL_RECEIPT_MAX_BYTES, SDK_COMPONENT_MANIFEST_MAX_BYTES,
        TRUSTED_ROOT_MAX_BYTES, parse_json,
    };
    use serde_json::Value;

    const PROFILE: JsonProfile = JsonProfile::PackageMetadataStateSelection;

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

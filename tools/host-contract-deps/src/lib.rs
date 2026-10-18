//! RC0 host contract probe only. This code is a set of candidate API fixtures,
//! not a production parser, decompressor, archive extractor, CLI, or installer.

use flate2::read::GzDecoder;
use lzma_rust2::XzReader;
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, Cursor, Read};
use tar::Archive;

#[derive(Debug)]
enum JsonNode {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<JsonNode>),
    Object(BTreeMap<String, JsonNode>),
}

impl JsonNode {
    fn into_value(self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::Number(value) => serde_json::Value::Number(value),
            Self::String(value) => serde_json::Value::String(value),
            Self::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(Self::into_value).collect())
            }
            Self::Object(values) => {
                let mut object = serde_json::Map::new();
                for (key, value) in values {
                    object.insert(key, value.into_value());
                }
                serde_json::Value::Object(object)
            }
        }
    }
}

struct JsonNodeVisitor;

impl<'de> Visitor<'de> for JsonNodeVisitor {
    type Value = JsonNode;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(JsonNode::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(JsonNode::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(JsonNode::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(JsonNode::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(JsonNode::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(JsonNode::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(JsonNode::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(JsonNode::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<JsonNode>()? {
            values.push(value);
        }
        Ok(JsonNode::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            let value = map.next_value::<JsonNode>()?;
            values.insert(key, value);
        }
        Ok(JsonNode::Object(values))
    }
}

impl<'de> Deserialize<'de> for JsonNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonNodeVisitor)
    }
}

/// Parse through a recursive visitor that refuses duplicate keys before a
/// typed value is constructed. `Deserializer::end` rejects trailing values.
pub fn parse_json_rejecting_duplicates<T: DeserializeOwned>(input: &[u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let node = JsonNode::deserialize(&mut deserializer)?;
    deserializer.end()?;
    T::deserialize(node.into_value())
}

/// Return the SHA-256 digest as raw bytes for receipt and content checks.
pub fn sha256_digest(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Read at most `limit + 1` decoded bytes. The extra byte distinguishes an
/// exactly-full stream from one that exceeds the contract's output bound.
pub fn read_bounded<R: Read>(mut reader: R, limit: usize) -> io::Result<Vec<u8>> {
    let probe_limit = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output limit overflows"))?;
    let mut output = Vec::with_capacity(probe_limit.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = probe_limit - output.len();
        let request = remaining.min(buffer.len());
        let read = reader.read(&mut buffer[..request])?;
        if read == 0 {
            return Ok(output);
        }
        output.extend_from_slice(&buffer[..read]);
        if output.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded output exceeds configured limit",
            ));
        }
    }
}

pub fn decode_xz_bounded(
    input: &[u8],
    memory_limit_kib: u32,
    output_limit: usize,
) -> io::Result<Vec<u8>> {
    read_bounded(
        XzReader::new_mem_limit(Cursor::new(input), false, memory_limit_kib),
        output_limit,
    )
}

pub fn decode_gzip_bounded(input: &[u8], output_limit: usize) -> io::Result<Vec<u8>> {
    read_bounded(GzDecoder::new(Cursor::new(input)), output_limit)
}

#[derive(Clone, Copy, Debug)]
pub struct TarLimits {
    pub max_entries: usize,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    /// Maximum bytes in the decoded TAR stream, including headers and extensions.
    pub max_archive_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TarSummary {
    pub entries: usize,
    pub expanded_bytes: u64,
}

struct CappedReader<R> {
    inner: R,
    limit: u64,
    consumed: u64,
}

impl<R> CappedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            consumed: 0,
        }
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.consumed);
        if remaining == 0 {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => invalid_data("decoded TAR input exceeds configured archive byte limit"),
            };
        }

        let allowed = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.consumed = self
            .consumed
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TAR input size overflow"))?;
        Ok(read)
    }
}

/// Validate a small set of archive metadata without extracting any member.
/// `max_archive_bytes` caps the complete decoded TAR input, including extension
/// records and bytes after the archive terminator.
/// Hard links and special files are refused; relative symlinks are accepted
/// only when their lexical target remains within the archive root.
pub fn validate_tar_metadata<R: Read>(reader: R, limits: TarLimits) -> io::Result<TarSummary> {
    let mut archive = Archive::new(CappedReader::new(reader, limits.max_archive_bytes));
    let mut seen = HashSet::<String>::new();
    let mut count = 0_usize;
    let mut total = 0_u64;

    for result in archive.entries()? {
        let entry = result?;
        let kind = entry.header().entry_type();
        let is_file = kind.is_file();
        let is_dir = kind.is_dir();
        let is_symlink = kind.is_symlink();
        if !(is_file || is_dir || is_symlink) {
            return invalid_data("unsupported TAR entry type");
        }
        if count == limits.max_entries {
            return invalid_data("TAR member count exceeds configured limit");
        }
        count += 1;

        let raw_path = entry.path_bytes();
        let path = std::str::from_utf8(raw_path.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TAR path is not UTF-8"))?;
        let components = safe_archive_path(path, is_dir)?;
        let canonical = components.join("/");
        if !seen.insert(canonical) {
            return invalid_data("duplicate TAR member path");
        }

        // `Entry::size` includes a PAX `size` override, whereas the header
        // accessor exposes only the raw header field. Reject disagreement so
        // this metadata check and downstream TAR readers cannot account for
        // different member boundaries; use the effective value for all bounds.
        let size = entry.size();
        if entry.header().size()? != size {
            return invalid_data("PAX TAR size conflicts with header size");
        }
        if (is_dir || is_symlink) && size != 0 {
            return invalid_data("directory or symlink has a data body");
        }
        if size > limits.max_member_bytes {
            return invalid_data("TAR member exceeds configured byte limit");
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TAR size overflow"))?;
        if total > limits.max_total_bytes {
            return invalid_data("TAR total expanded bytes exceed configured limit");
        }

        if is_symlink {
            let raw_target = entry.link_name_bytes().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "symlink has no target")
            })?;
            let target = std::str::from_utf8(raw_target.as_ref()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8")
            })?;
            safe_symlink_target(&components, target)?;
        }
    }

    // TAR readers may stop at the end markers. Drain the decoded stream so
    // the archive-wide cap also covers trailing data after those markers.
    io::copy(&mut archive.into_inner(), &mut io::sink())?;

    Ok(TarSummary {
        entries: count,
        expanded_bytes: total,
    })
}

fn safe_archive_path(path: &str, is_dir: bool) -> io::Result<Vec<String>> {
    if path.is_empty() || path.starts_with('/') || path.contains(['\\', ':', '\0']) {
        return invalid_data("absolute, empty, or nonportable TAR path");
    }
    let normalized = if is_dir {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    let mut components = Vec::new();
    for component in normalized.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return invalid_data("TAR path has an empty or traversal component");
        }
        components.push(component.to_owned());
    }
    if components.is_empty() {
        return invalid_data("TAR path names the archive root");
    }
    Ok(components)
}

fn safe_symlink_target(member: &[String], target: &str) -> io::Result<()> {
    if target.is_empty() || target.starts_with('/') || target.contains(['\\', ':', '\0']) {
        return invalid_data("absolute, empty, or nonportable symlink target");
    }
    let mut depth = member.len().saturating_sub(1);
    for component in target.split('/') {
        match component {
            "" | "." => return invalid_data("symlink target is not canonical"),
            ".." => {
                if depth == 0 {
                    return invalid_data("symlink target escapes archive root");
                }
                depth -= 1;
            }
            _ => {
                depth = depth.checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "symlink target depth overflow")
                })?
            }
        }
    }
    Ok(())
}

fn invalid_data<T>(message: &str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use serde::Deserialize;
    use std::io::Write;
    use tar::{Builder, EntryType, Header};

    const XZ_TINY_4K_DICT: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x03, 0xc0, 0x30,
        0x2c, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0xa2, 0x7f, 0x32, 0x01, 0x00,
        0x2b, 0x52, 0x43, 0x30, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x72,
        0x61, 0x63, 0x74, 0x20, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x3a, 0x20, 0x62, 0x6f, 0x75, 0x6e,
        0x64, 0x65, 0x64, 0x20, 0x58, 0x5a, 0x20, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x2e, 0x0a,
        0x00, 0xdb, 0x30, 0xd6, 0xd4, 0x00, 0x01, 0x44, 0x2c, 0xc9, 0x53, 0x4b, 0x86, 0x90, 0x42,
        0x99, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a,
    ];
    const XZ_TINY_64M_DICT: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x04, 0xc0, 0x30,
        0x2c, 0x21, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f, 0x13,
        0x6c, 0x41, 0x01, 0x00, 0x2b, 0x52, 0x43, 0x30, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x63,
        0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x20, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x3a, 0x20,
        0x62, 0x6f, 0x75, 0x6e, 0x64, 0x65, 0x64, 0x20, 0x58, 0x5a, 0x20, 0x6f, 0x75, 0x74, 0x70,
        0x75, 0x74, 0x2e, 0x0a, 0x00, 0xdb, 0x30, 0xd6, 0xd4, 0x00, 0x01, 0x48, 0x2c, 0xc5, 0x1c,
        0xfe, 0x2a, 0x90, 0x42, 0x99, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a,
    ];

    #[derive(Debug, Deserialize, PartialEq)]
    struct JsonFixture {
        kind: String,
        nested: Vec<i64>,
    }

    #[test]
    fn json_visitor_rejects_duplicates_at_every_depth_before_typed_decode() {
        let valid = br#"{"kind":"probe","nested":[1,2,3]}"#;
        let parsed: JsonFixture = parse_json_rejecting_duplicates(valid).unwrap();
        assert_eq!(
            parsed,
            JsonFixture {
                kind: "probe".into(),
                nested: vec![1, 2, 3]
            }
        );

        assert!(parse_json_rejecting_duplicates::<serde_json::Value>(br#"{"a":1,"a":2}"#).is_err());
        assert!(
            parse_json_rejecting_duplicates::<serde_json::Value>(br#"{"a":[{"b":1,"b":2}]}"#)
                .is_err()
        );
    }

    #[test]
    fn json_visitor_rejects_invalid_trailing_and_nonfinite_inputs() {
        for input in [
            &b"{"[..],
            &br#"{"kind":"probe","nested":[1]} trailing"#[..],
            &br#"{"kind":"probe","nested":[NaN]}"#[..],
            &br#"{"kind":"probe","nested":[Infinity]}"#[..],
            &[0xff, 0xfe][..],
        ] {
            assert!(parse_json_rejecting_duplicates::<serde_json::Value>(input).is_err());
        }
    }

    #[test]
    fn sha256_matches_the_published_abc_test_vector() {
        assert_eq!(
            sha256_digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn xz_uses_memory_limit_and_output_cap() {
        let valid = b"RC0 host contract probe: bounded XZ output.\n";
        assert_eq!(
            decode_xz_bounded(XZ_TINY_4K_DICT, 1024, 1024).unwrap(),
            valid
        );
        assert!(decode_xz_bounded(XZ_TINY_4K_DICT, 1024, 8).is_err());
        assert!(decode_xz_bounded(XZ_TINY_64M_DICT, 1024, 1024).is_err());

        let mut corrupt_crc = XZ_TINY_4K_DICT.to_vec();
        let crc_offset = corrupt_crc
            .windows(4)
            .position(|bytes| bytes == [0xdb, 0x30, 0xd6, 0xd4])
            .unwrap();
        corrupt_crc[crc_offset] ^= 0x01;
        assert!(decode_xz_bounded(&corrupt_crc, 1024, 1024).is_err());
    }

    #[test]
    fn gzip_output_is_capped_before_unbounded_expansion() {
        let expanded = vec![b'A'; 64 * 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&expanded).unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(
            decode_gzip_bounded(&compressed, expanded.len()).unwrap(),
            expanded
        );
        assert!(decode_gzip_bounded(&compressed, 128).is_err());
    }

    fn tar_archive(entries: &[(&str, EntryType, Option<&str>, &[u8])]) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            for (path, kind, link, body) in entries {
                let mut header = Header::new_gnu();
                header.set_entry_type(*kind);
                header.set_mode(0o644);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                header.set_size(body.len() as u64);
                header.set_path(path)?;
                if let Some(target) = link {
                    header.set_link_name_literal(target.as_bytes())?;
                }
                header.set_cksum();
                builder.append(&header, Cursor::new(body))?;
            }
            builder.finish()?;
        }
        Ok(bytes)
    }

    fn tar_archive_raw_path(raw_path: &str) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::file());
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(1);
            header.set_path("placeholder")?;
            header.as_mut_bytes()[..100].fill(0);
            header.as_mut_bytes()[..raw_path.len()].copy_from_slice(raw_path.as_bytes());
            header.set_cksum();
            builder.append(&header, Cursor::new(b"x"))?;
            builder.finish()?;
        }
        Ok(bytes)
    }

    fn tar_archive_with_pax_size(entries: &[(&str, u64, &[u8])]) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            for (path, header_size, body) in entries {
                builder.append_pax_extensions([("size", body.len().to_string().as_bytes())])?;

                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::file());
                header.set_mode(0o644);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                header.set_size(*header_size);
                header.set_path(path)?;
                header.set_cksum();
                builder.append(&header, Cursor::new(body))?;
            }
            builder.finish()?;
        }
        Ok(bytes)
    }

    fn tar_archive_with_long_pax_path(path_bytes: usize) -> io::Result<Vec<u8>> {
        let path = vec![b'a'; path_bytes];
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            builder.append_pax_extensions([("path", path.as_slice())])?;

            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::file());
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(1);
            header.set_path("placeholder")?;
            header.set_cksum();
            builder.append(&header, Cursor::new(b"x"))?;
            builder.finish()?;
        }
        Ok(bytes)
    }

    fn tar_archive_with_long_gnu_name(path_bytes: usize) -> io::Result<Vec<u8>> {
        let mut name = vec![b'a'; path_bytes];
        name.push(0);
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            let mut extension = Header::new_gnu();
            extension.set_entry_type(EntryType::GNULongName);
            extension.set_size(name.len() as u64);
            extension.set_cksum();
            builder.append(&extension, Cursor::new(name))?;

            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::file());
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(1);
            header.set_path("placeholder")?;
            header.set_cksum();
            builder.append(&header, Cursor::new(b"x"))?;
            builder.finish()?;
        }
        Ok(bytes)
    }

    fn permissive_test_limits() -> TarLimits {
        TarLimits {
            max_entries: 16,
            max_member_bytes: 1024,
            max_total_bytes: 4096,
            max_archive_bytes: 64 * 1024,
        }
    }

    #[test]
    fn tar_metadata_accepts_safe_paths_and_contained_relative_links() {
        let archive = tar_archive(&[
            ("dir/data.txt", EntryType::file(), None, b"payload"),
            ("dir/link", EntryType::symlink(), Some("data.txt"), b""),
        ])
        .unwrap();
        assert_eq!(
            validate_tar_metadata(Cursor::new(archive), permissive_test_limits()).unwrap(),
            TarSummary {
                entries: 2,
                expanded_bytes: 7
            }
        );
    }

    #[test]
    fn tar_metadata_rejects_traversal_duplicate_and_escaping_link() {
        for raw_path in ["../outside", "/etc/passwd", "safe/../escape"] {
            let unsafe_path = tar_archive_raw_path(raw_path).unwrap();
            assert!(
                validate_tar_metadata(Cursor::new(unsafe_path), permissive_test_limits()).is_err()
            );
        }

        let duplicate = tar_archive(&[
            ("same", EntryType::file(), None, b"a"),
            ("same", EntryType::file(), None, b"b"),
        ])
        .unwrap();
        assert!(validate_tar_metadata(Cursor::new(duplicate), permissive_test_limits()).is_err());

        let escaping_link =
            tar_archive(&[("link", EntryType::symlink(), Some("../outside"), b"")]).unwrap();
        assert!(
            validate_tar_metadata(Cursor::new(escaping_link), permissive_test_limits()).is_err()
        );

        let hard_link =
            tar_archive(&[("link", EntryType::hard_link(), Some("target"), b"")]).unwrap();
        assert!(validate_tar_metadata(Cursor::new(hard_link), permissive_test_limits()).is_err());

        let fifo = tar_archive(&[("pipe", EntryType::fifo(), None, b"")]).unwrap();
        assert!(validate_tar_metadata(Cursor::new(fifo), permissive_test_limits()).is_err());
    }

    #[test]
    fn tar_metadata_enforces_entry_and_expanded_byte_limits() {
        let archive = tar_archive(&[("data", EntryType::file(), None, b"12345")]).unwrap();
        let limits = TarLimits {
            max_entries: 1,
            max_member_bytes: 4,
            max_total_bytes: 4,
            max_archive_bytes: 64 * 1024,
        };
        let error = validate_tar_metadata(Cursor::new(archive), limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "TAR member exceeds configured byte limit"
        );
    }

    #[test]
    fn tar_metadata_rejects_pax_size_conflict_that_bypasses_member_limit() {
        let member_conflict = tar_archive_with_pax_size(&[("large", 1, b"12345")]).unwrap();
        let member_limits = TarLimits {
            max_entries: 1,
            max_member_bytes: 4,
            max_total_bytes: 4,
            max_archive_bytes: 64 * 1024,
        };
        let error = validate_tar_metadata(Cursor::new(member_conflict), member_limits).unwrap_err();
        assert_eq!(error.to_string(), "PAX TAR size conflicts with header size");
    }

    #[test]
    fn tar_metadata_rejects_pax_size_conflicts_that_bypass_total_limit() {
        let total_conflict =
            tar_archive_with_pax_size(&[("one", 1, b"123"), ("two", 1, b"456")]).unwrap();
        let total_limits = TarLimits {
            max_entries: 2,
            max_member_bytes: 4,
            max_total_bytes: 5,
            max_archive_bytes: 64 * 1024,
        };
        let error = validate_tar_metadata(Cursor::new(total_conflict), total_limits).unwrap_err();
        assert_eq!(error.to_string(), "PAX TAR size conflicts with header size");
    }

    #[test]
    fn tar_metadata_caps_complete_stream_before_unbounded_extension_read() {
        let archive = tar_archive(&[("small", EntryType::file(), None, b"x")]).unwrap();
        let mut limits = permissive_test_limits();
        limits.max_archive_bytes = 4096;
        assert!(validate_tar_metadata(Cursor::new(archive), limits).is_ok());

        let large_extension = tar_archive_with_long_pax_path(32 * 1024).unwrap();
        let error = validate_tar_metadata(Cursor::new(large_extension), limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "decoded TAR input exceeds configured archive byte limit"
        );

        let large_gnu_extension = tar_archive_with_long_gnu_name(32 * 1024).unwrap();
        let error = validate_tar_metadata(Cursor::new(large_gnu_extension), limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "decoded TAR input exceeds configured archive byte limit"
        );
    }

    #[test]
    fn tar_metadata_caps_data_after_archive_terminator() {
        let mut archive = tar_archive(&[("small", EntryType::file(), None, b"x")]).unwrap();
        archive.extend(std::iter::repeat_n(0xA5, 4096));
        let mut limits = permissive_test_limits();
        limits.max_archive_bytes = 2048;

        let error = validate_tar_metadata(Cursor::new(archive), limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "decoded TAR input exceeds configured archive byte limit"
        );
    }

    #[test]
    fn tar_metadata_enforces_entry_count_and_total_expanded_bytes() {
        let archive = tar_archive(&[
            ("one", EntryType::file(), None, b"abc"),
            ("two", EntryType::file(), None, b"def"),
        ])
        .unwrap();
        let mut limits = permissive_test_limits();
        limits.max_entries = 1;
        assert!(validate_tar_metadata(Cursor::new(archive.clone()), limits).is_err());

        let mut limits = permissive_test_limits();
        limits.max_total_bytes = 5;
        assert!(validate_tar_metadata(Cursor::new(archive), limits).is_err());
    }
}

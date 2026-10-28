//! Pure verification of the publisher SDK's decoded TAR inventory.
//!
//! This module never writes files. The caller must provide the authenticated
//! inventory and already bounded, fully decoded TAR bytes. Returned contents
//! borrow the input archive and are safe to publish only after verification
//! succeeds for the complete archive.
//!
//! A bounded raw header walk accepts canonical unsigned and historical signed
//! checksums. The reviewed TAR library supplies header/path/type interpretation;
//! no library extraction or hidden extension-body allocation is used.

use std::ops::Range;

use tar::{EntryType, Header};

use crate::{Refusal, Result, digest::is_sha256_digest, digest::sha256_bytes};

/// Maximum decoded TAR byte length accepted by the publisher SDK profile.
pub const MAX_DECODED_TAR_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of logical file members accepted by the publisher profile.
pub const MAX_MEMBERS: usize = 1_000;
/// Maximum declared or authenticated size of one file.
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 240;
const MAX_PATH_COMPONENTS: usize = 24;
const MAX_COMPONENT_BYTES: usize = 120;
const TAR_BLOCK_BYTES: usize = 512;
const MIN_TAR_TRAILER_BYTES: usize = TAR_BLOCK_BYTES * 2;

/// One authenticated SDK file row supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedFile<'a> {
    pub path: &'a str,
    pub size: usize,
    pub sha256: &'a str,
}

/// A verified regular file borrowing its bytes from the decoded TAR input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFile<'a> {
    pub path: String,
    pub contents: &'a [u8],
    /// Normalized publisher install mode: `0o755` if any execute bit was set,
    /// otherwise `0o644`.
    pub mode: u32,
}

/// Verify one complete decoded publisher SDK TAR against its authenticated
/// exact file inventory. The archive and every file size are capped at 16 MiB;
/// the inventory is nonempty and capped at 1,000 files. Only regular-file
/// records are accepted. GNU long-name records are supported when their
/// effective path passes the portable path rules; nonempty PAX records are
/// refused. No filesystem writes occur.
pub fn verify_publisher_sdk_tar<'a>(
    archive_bytes: &'a [u8],
    expected_files: &[ExpectedFile<'_>],
) -> Result<Vec<VerifiedFile<'a>>> {
    if archive_bytes.len() > MAX_DECODED_TAR_BYTES {
        return Err(Refusal::new(format!(
            "decoded SDK TAR exceeds {MAX_DECODED_TAR_BYTES} bytes"
        )));
    }
    validate_expected_inventory(expected_files)?;

    let mut position = 0_usize;
    let mut verified = Vec::new();
    let mut total_file_bytes = 0usize;
    let mut last_end = 0usize;
    let mut pending_long_name: Option<Vec<u8>> = None;
    let mut pending_long_link = false;

    while position < archive_bytes.len() {
        let header_end = position
            .checked_add(TAR_BLOCK_BYTES)
            .ok_or_else(|| Refusal::new("SDK TAR header offset overflow"))?;
        let raw_header = archive_bytes
            .get(position..header_end)
            .ok_or_else(|| Refusal::new("truncated SDK TAR header"))?;
        if raw_header.iter().all(|byte| *byte == 0) {
            break;
        }
        // Header::from_byte_slice requires exactly one checked 512-byte block.
        let header = Header::from_byte_slice(raw_header);
        verify_header_checksum(raw_header)?;
        // Python validates numeric syntax even for ownership/timestamp/device
        // metadata that installation deliberately does not preserve.
        for range in [100..108, 108..116, 116..124, 136..148, 329..337, 337..345] {
            tarfile_number(&raw_header[range])?;
        }
        let entry_type = header.entry_type();
        let declared_size = tarfile_number(&raw_header[124..136])?;
        let declared_size = u64::try_from(declared_size)
            .map_err(|_| Refusal::new("negative SDK TAR member size"))?;
        let range = entry_data_range(archive_bytes, header_end as u64, declared_size)?;
        let size = range.len();
        position = padded_data_end(range.start, size)?;

        match entry_type {
            EntryType::GNULongName => {
                // Python processes nested long-name records recursively, then
                // applies the outermost (first) name last. Only that effective
                // path needs the portable-path check.
                if pending_long_name.is_none() {
                    pending_long_name = Some(parse_gnu_long_name(&archive_bytes[range])?);
                }
            }
            EntryType::GNULongLink => {
                // The publisher profile rejects link members. A long-link
                // record preceding a regular file has no effect on its path,
                // bytes, or installed mode. Python tarfile recognizes it
                // without GNU magic; the outermost record wins. Its target has
                // no effect on accepted regular files.
                pending_long_link = true;
            }
            EntryType::XHeader | EntryType::XGlobalHeader | EntryType::__Nonexhaustive(b'X') => {
                if size != 0 && archive_bytes[range.start] != 0 {
                    return Err(Refusal::new(
                        "SDK TAR PAX extended headers are not accepted",
                    ));
                }
                // Python tarfile stops PAX parsing at a leading NUL. Such a
                // nonempty body still produces an empty pax_headers mapping.
            }
            EntryType::Regular => {
                pending_long_link = false;
                if verified.len() == MAX_MEMBERS {
                    return Err(Refusal::new(format!(
                        "SDK TAR exceeds the {MAX_MEMBERS}-member limit"
                    )));
                }
                if size > MAX_FILE_BYTES {
                    return Err(Refusal::new(format!(
                        "SDK TAR member exceeds {MAX_FILE_BYTES} bytes"
                    )));
                }

                let raw_path = match pending_long_name.take() {
                    Some(path) => path,
                    None => header.path_bytes().into_owned(),
                };
                let path = validate_portable_path(&raw_path)?;
                if verified
                    .iter()
                    .any(|member: &VerifiedFile<'_>| member.path.eq_ignore_ascii_case(&path))
                {
                    return Err(Refusal::new(format!(
                        "duplicate or case-colliding SDK TAR member: {path}"
                    )));
                }

                let contents = &archive_bytes[range.clone()];
                let expected = expected_files
                    .iter()
                    .find(|expected| expected.path == path)
                    .ok_or_else(|| {
                        Refusal::new(format!("SDK TAR inventory contains extra path: {path}"))
                    })?;
                if expected.size != contents.len()
                    || sha256_bytes(contents).as_str() != expected.sha256
                {
                    return Err(Refusal::new(format!(
                        "SDK TAR file identity differs from authenticated inventory: {path}"
                    )));
                }
                total_file_bytes = total_file_bytes
                    .checked_add(contents.len())
                    .ok_or_else(|| Refusal::new("SDK TAR expanded-size total overflow"))?;
                if total_file_bytes > MAX_DECODED_TAR_BYTES {
                    return Err(Refusal::new(format!(
                        "SDK TAR file contents exceed {MAX_DECODED_TAR_BYTES} bytes"
                    )));
                }

                let source_mode = tarfile_number(&header.as_bytes()[100..108])?;
                let mode = if source_mode & 0o111 != 0 {
                    0o755
                } else {
                    0o644
                };
                verified.push(VerifiedFile {
                    path,
                    contents,
                    mode,
                });
                last_end = last_end.max(padded_data_end(range.start, size)?);
            }
            _ => {
                let name = header.path_bytes();
                return Err(Refusal::new(format!(
                    "SDK TAR member is not a plain regular file: {}",
                    String::from_utf8_lossy(&name)
                )));
            }
        }
    }

    if pending_long_name.is_some() || pending_long_link {
        return Err(Refusal::new(
            "GNU long-name or long-link record has no following SDK member",
        ));
    }
    if verified.is_empty() {
        return Err(Refusal::new("SDK TAR has no file members"));
    }
    if verified.len() != expected_files.len() {
        return Err(Refusal::new(format!(
            "SDK TAR inventory is incomplete: found {} of {} authenticated files",
            verified.len(),
            expected_files.len()
        )));
    }
    if last_end > archive_bytes.len() {
        return Err(Refusal::new("SDK TAR file data extends past archive end"));
    }
    let trailer = &archive_bytes[last_end..];
    if trailer.len() < MIN_TAR_TRAILER_BYTES || trailer.iter().any(|byte| *byte != 0) {
        return Err(Refusal::new(
            "SDK TAR must end with at least two zero blocks and zero padding",
        ));
    }

    Ok(verified)
}

fn validate_expected_inventory(expected_files: &[ExpectedFile<'_>]) -> Result<()> {
    if expected_files.is_empty() || expected_files.len() > MAX_MEMBERS {
        return Err(Refusal::new(format!(
            "authenticated SDK inventory must contain 1 to {MAX_MEMBERS} files"
        )));
    }

    let mut total = 0usize;
    for (index, expected) in expected_files.iter().enumerate() {
        validate_portable_path(expected.path.as_bytes())?;
        if expected.size > MAX_FILE_BYTES {
            return Err(Refusal::new(format!(
                "authenticated SDK file exceeds {MAX_FILE_BYTES} bytes: {}",
                expected.path
            )));
        }
        if !is_sha256_digest(expected.sha256) {
            return Err(Refusal::new(format!(
                "authenticated SDK file has an invalid SHA-256 digest: {}",
                expected.path
            )));
        }
        for earlier in &expected_files[..index] {
            if earlier.path == expected.path || earlier.path.eq_ignore_ascii_case(expected.path) {
                return Err(Refusal::new(format!(
                    "authenticated SDK inventory has duplicate or case-colliding path: {}",
                    expected.path
                )));
            }
        }
        total = total
            .checked_add(expected.size)
            .ok_or_else(|| Refusal::new("authenticated SDK inventory size overflow"))?;
        if total > MAX_DECODED_TAR_BYTES {
            return Err(Refusal::new(format!(
                "authenticated SDK inventory exceeds {MAX_DECODED_TAR_BYTES} bytes"
            )));
        }
    }
    for expected in expected_files {
        let mut parent = String::new();
        let mut components = expected.path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            if expected_files
                .iter()
                .any(|candidate| candidate.path.eq_ignore_ascii_case(&parent))
            {
                return Err(Refusal::new(format!(
                    "authenticated SDK inventory has a file/directory path conflict: {}",
                    expected.path
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_portable_path(raw: &[u8]) -> Result<String> {
    if raw.is_empty()
        || raw.len() > MAX_PATH_BYTES
        || raw[0] == b'/'
        || raw
            .iter()
            .any(|byte| *byte == b'\\' || *byte == b':' || !(0x20..0x7f).contains(byte))
    {
        return Err(Refusal::new(
            "SDK member path must be a portable relative ASCII path",
        ));
    }

    let path =
        std::str::from_utf8(raw).map_err(|_| Refusal::new("SDK member path is not valid ASCII"))?;
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_PATH_COMPONENTS {
        return Err(Refusal::new("SDK member path has too many components"));
    }
    for component in components {
        let bytes = component.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_COMPONENT_BYTES
            || component == "."
            || component == ".."
            || component.ends_with('.')
            || !bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'+' | b'-')
            })
        {
            return Err(Refusal::new(format!(
                "SDK member path contains a nonportable component: {component}"
            )));
        }
        let stem = component.split('.').next().unwrap_or(component);
        let upper = stem.to_ascii_uppercase();
        let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                upper.strip_prefix(prefix).is_some_and(|suffix| {
                    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
                })
            });
        if reserved {
            return Err(Refusal::new(format!(
                "SDK member path uses a reserved device name: {component}"
            )));
        }
    }
    Ok(path.to_owned())
}

fn parse_gnu_long_name(raw: &[u8]) -> Result<Vec<u8>> {
    let path = raw
        .iter()
        .position(|byte| *byte == 0)
        .map_or(raw, |index| &raw[..index]);
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(Refusal::new("GNU long SDK member path exceeds 240 bytes"));
    }
    validate_portable_path(path)?;
    Ok(path.to_vec())
}

fn verify_header_checksum(header: &[u8]) -> Result<()> {
    let expected = tarfile_number(&header[148..156])?;
    // The checksum field itself contributes eight ASCII spaces in both forms.
    let mut unsigned = 8_i128 * i128::from(b' ');
    let mut signed = unsigned;
    for byte in header[..148].iter().chain(&header[156..]) {
        unsigned += i128::from(*byte);
        signed += i128::from(*byte as i8);
    }
    if expected != unsigned && expected != signed {
        return Err(Refusal::new("SDK TAR header checksum mismatch"));
    }
    Ok(())
}

fn tarfile_number(field: &[u8]) -> Result<i128> {
    if matches!(field[0], 0o200 | 0o377) {
        let mut value = 0i128;
        for byte in &field[1..] {
            value = value
                .checked_mul(256)
                .and_then(|value| value.checked_add(i128::from(*byte)))
                .ok_or_else(|| Refusal::new("SDK TAR mode is out of range"))?;
        }
        if field[0] == 0o377 {
            let sign = 1i128
                .checked_shl(((field.len() - 1) * 8) as u32)
                .ok_or_else(|| Refusal::new("SDK TAR mode is out of range"))?;
            value = value
                .checked_sub(sign)
                .ok_or_else(|| Refusal::new("SDK TAR mode is out of range"))?;
        }
        return Ok(value);
    }

    // Match tarfile.nti for non-base-256 fields: stop at NUL, trim whitespace,
    // and parse the Python-style signed octal integer (including separators).
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if !field[..end].is_ascii() {
        return Err(Refusal::new("SDK TAR numeric field is not ASCII"));
    }
    let text = std::str::from_utf8(&field[..end])
        .map_err(|_| Refusal::new("invalid SDK TAR member mode encoding"))?
        // Python decodes strict ASCII before str.strip(); its ASCII whitespace
        // includes vertical tab and the four information separators as well.
        .trim_matches(|character: char| matches!(character as u32, 9..=13 | 28..=32));
    if text.is_empty() {
        return Ok(0);
    }
    let (negative, mut digits) = match text.as_bytes()[0] {
        b'+' => (false, &text.as_bytes()[1..]),
        b'-' => (true, &text.as_bytes()[1..]),
        _ => (false, text.as_bytes()),
    };
    if digits.starts_with(b"0o") || digits.starts_with(b"0O") {
        digits = &digits[2..];
        // Python int(text, 8) allows one separator immediately after 0o.
        if digits.starts_with(b"_") {
            digits = &digits[1..];
        }
    }
    let mut value = 0i128;
    let mut previous_was_digit = false;
    for (index, byte) in digits.iter().copied().enumerate() {
        if byte == b'_' {
            if !previous_was_digit
                || digits
                    .get(index + 1)
                    .is_none_or(|next| !(b'0'..=b'7').contains(next))
            {
                return Err(Refusal::new("invalid SDK TAR member mode"));
            }
            previous_was_digit = false;
            continue;
        }
        if !(b'0'..=b'7').contains(&byte) {
            return Err(Refusal::new("invalid SDK TAR member mode"));
        }
        value = value
            .checked_mul(8)
            .and_then(|value| value.checked_add(i128::from(byte - b'0')))
            .ok_or_else(|| Refusal::new("SDK TAR mode is out of range"))?;
        previous_was_digit = true;
    }
    if !previous_was_digit {
        return Err(Refusal::new("invalid SDK TAR member mode"));
    }
    if negative {
        value
            .checked_neg()
            .ok_or_else(|| Refusal::new("SDK TAR mode is out of range"))
    } else {
        Ok(value)
    }
}

fn entry_data_range(archive: &[u8], offset: u64, size: u64) -> Result<Range<usize>> {
    let start = usize::try_from(offset)
        .map_err(|_| Refusal::new("SDK TAR member offset does not fit host"))?;
    let size =
        usize::try_from(size).map_err(|_| Refusal::new("SDK TAR member size does not fit host"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Refusal::new("SDK TAR member range overflow"))?;
    let padded_end = padded_data_end(start, size)?;
    if end > archive.len() || padded_end > archive.len() {
        return Err(Refusal::new("truncated SDK TAR member data"));
    }
    Ok(start..end)
}

fn padded_data_end(start: usize, size: usize) -> Result<usize> {
    let padded_size = size
        .checked_add(TAR_BLOCK_BYTES - 1)
        .ok_or_else(|| Refusal::new("SDK TAR member padding overflow"))?
        / TAR_BLOCK_BYTES
        * TAR_BLOCK_BYTES;
    start
        .checked_add(padded_size)
        .ok_or_else(|| Refusal::new("SDK TAR member range overflow"))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tar::{Builder, EntryType, Header};

    use super::{ExpectedFile, MAX_DECODED_TAR_BYTES, MAX_MEMBERS, verify_publisher_sdk_tar};
    use crate::digest::sha256_bytes;

    fn append_file(builder: &mut Builder<Vec<u8>>, path: &str, bytes: &[u8], mode: u32) {
        let mut header = Header::new_gnu();
        header.set_mode(mode);
        header.set_size(bytes.len() as u64);
        header.set_entry_type(EntryType::Regular);
        builder
            .append_data(&mut header, path, Cursor::new(bytes))
            .expect("append regular test member");
    }

    fn append_record(
        builder: &mut Builder<Vec<u8>>,
        path: &str,
        entry_type: EntryType,
        bytes: &[u8],
    ) {
        let mut header = Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_entry_type(entry_type);
        builder
            .append_data(&mut header, path, Cursor::new(bytes))
            .expect("append test TAR record");
    }

    fn archive_with_file(path: &str, bytes: &[u8], mode: u32) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        append_file(&mut builder, path, bytes, mode);
        builder.into_inner().expect("finish test archive")
    }

    fn expected_row<'a>(path: &'a str, bytes: &[u8]) -> [ExpectedFile<'a>; 1] {
        [ExpectedFile {
            path,
            size: bytes.len(),
            sha256: Box::leak(sha256_bytes(bytes).into_boxed_str()),
        }]
    }

    fn pax_size_record(value: usize) -> Vec<u8> {
        let suffix = format!(" size={value}\n");
        let mut length = suffix.len() + 1;
        loop {
            let next = suffix.len() + length.to_string().len();
            if next == length {
                return format!("{length}{suffix}").into_bytes();
            }
            length = next;
        }
    }

    #[test]
    fn accepts_exact_inventory_and_normalizes_modes() {
        let bytes = b"SDK bytes";
        let archive = archive_with_file("host/tool", bytes, 0o4751);
        let expected = expected_row("host/tool", bytes);
        let verified = verify_publisher_sdk_tar(&archive, &expected).unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].path, "host/tool");
        assert_eq!(verified[0].contents, bytes);
        assert_eq!(verified[0].mode, 0o755);

        let non_executable = archive_with_file("host/data", bytes, 0o666);
        let expected = expected_row("host/data", bytes);
        let verified = verify_publisher_sdk_tar(&non_executable, &expected).unwrap();
        assert_eq!(verified[0].mode, 0o644);
    }

    #[test]
    fn accepts_alternate_regular_type_and_empty_pax_headers() {
        let bytes = b"legacy regular marker";
        let mut archive = archive_with_file("host/file", bytes, 0o644);
        archive[156] = 0;
        fix_header_checksum(&mut archive[..512]);
        let expected = expected_row("host/file", bytes);
        assert!(verify_publisher_sdk_tar(&archive, &expected).is_ok());

        let mut builder = Builder::new(Vec::new());
        append_record(&mut builder, "PaxHeaders.0/file", EntryType::XHeader, b"");
        append_file(&mut builder, "host/file", bytes, 0o644);
        let archive = builder.into_inner().unwrap();
        assert!(verify_publisher_sdk_tar(&archive, &expected).is_ok());
    }

    #[test]
    fn accepts_portable_gnu_long_name() {
        let path = format!("{}/{}", "a".repeat(110), "b".repeat(110));
        let bytes = b"long-name contents";
        let archive = archive_with_file(&path, bytes, 0o644);
        let expected = expected_row(&path, bytes);
        let verified = verify_publisher_sdk_tar(&archive, &expected).unwrap();
        assert_eq!(verified[0].path, path);
    }

    #[test]
    fn matches_historical_gnu_longname_outer_magic_and_nul_rules() {
        let bytes = b"contents";
        let mut builder = Builder::new(Vec::new());
        let mut outer_name = b"host/tool\0ignored unsafe outer suffix".to_vec();
        outer_name.extend_from_slice(&vec![b'x'; 300]);
        append_record(
            &mut builder,
            "LongName.0",
            EntryType::GNULongName,
            &outer_name,
        );
        append_record(
            &mut builder,
            "LongName.1",
            EntryType::GNULongName,
            b"../inner/path\0",
        );
        append_file(&mut builder, "raw/header/path", bytes, 0o644);
        let mut archive = builder.into_inner().unwrap();
        archive[257..265].fill(0);
        fix_header_checksum(&mut archive[..512]);
        let expected = expected_row("host/tool", bytes);
        let verified = verify_publisher_sdk_tar(&archive, &expected).unwrap();
        assert_eq!(verified[0].path, "host/tool");

        let mut links = Builder::new(Vec::new());
        append_record(
            &mut links,
            "LongLink.0",
            EntryType::GNULongLink,
            b"first/target\0",
        );
        append_record(
            &mut links,
            "LongLink.1",
            EntryType::GNULongLink,
            b"last/target\0",
        );
        append_file(&mut links, "host/file", bytes, 0o644);
        let mut links = links.into_inner().unwrap();
        links[257..265].fill(0);
        fix_header_checksum(&mut links[..512]);
        let expected = expected_row("host/file", bytes);
        assert!(verify_publisher_sdk_tar(&links, &expected).is_ok());
    }

    #[test]
    fn accepts_empty_parsed_nonempty_pax_and_base256_mode() {
        let bytes = b"base256 mode";
        let mut builder = Builder::new(Vec::new());
        append_record(
            &mut builder,
            "PaxHeaders.0/file",
            EntryType::XHeader,
            b"\0ignored bytes including size override",
        );
        append_record(&mut builder, "PaxHeaders.1/file", EntryType::new(b'X'), b"");
        append_file(&mut builder, "host/tool", bytes, 0o755);
        let mut archive = builder.into_inner().unwrap();
        let file_header = 1024;
        archive[file_header + 100..file_header + 108]
            .copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 1, 0xed]);
        fix_header_checksum(&mut archive[file_header..file_header + 512]);
        let expected = expected_row("host/tool", bytes);
        let verified = verify_publisher_sdk_tar(&archive, &expected).unwrap();
        assert_eq!(verified[0].mode, 0o755);
    }

    #[test]
    fn rejects_extra_missing_duplicate_case_colliding_and_identity_mismatch() {
        let bytes = b"expected";
        let expected = expected_row("host/tool", bytes);
        let extra = archive_with_file("host/other", bytes, 0o644);
        assert!(verify_publisher_sdk_tar(&extra, &expected).is_err());

        let missing = archive_with_file("host/tool", b"different", 0o644);
        assert!(verify_publisher_sdk_tar(&missing, &expected).is_err());

        let mut duplicate_builder = Builder::new(Vec::new());
        append_file(&mut duplicate_builder, "host/tool", bytes, 0o644);
        append_file(&mut duplicate_builder, "host/tool", bytes, 0o644);
        let duplicate = duplicate_builder.into_inner().unwrap();
        assert!(verify_publisher_sdk_tar(&duplicate, &expected).is_err());

        let mut collision_builder = Builder::new(Vec::new());
        append_file(&mut collision_builder, "Host/tool", bytes, 0o644);
        append_file(&mut collision_builder, "host/tool", bytes, 0o644);
        let collision = collision_builder.into_inner().unwrap();
        assert!(verify_publisher_sdk_tar(&collision, &expected).is_err());

        let wrong_digest = [ExpectedFile {
            path: "host/tool",
            size: bytes.len(),
            sha256: "0".repeat(64).leak(),
        }];
        assert!(
            verify_publisher_sdk_tar(&archive_with_file("host/tool", bytes, 0o644), &wrong_digest)
                .is_err()
        );
    }

    #[test]
    fn rejects_nonempty_pax_size_override_and_size_conflict() {
        let bytes = b"content";
        let mut builder = Builder::new(Vec::new());
        append_record(
            &mut builder,
            "PaxHeaders.0/tool",
            EntryType::XHeader,
            &pax_size_record(bytes.len() + 1),
        );
        append_file(&mut builder, "host/tool", bytes, 0o644);
        let archive = builder.into_inner().unwrap();
        let expected = expected_row("host/tool", bytes);
        let error = verify_publisher_sdk_tar(&archive, &expected).unwrap_err();
        assert!(error.to_string().contains("PAX extended headers"));
    }

    #[test]
    fn rejects_raw_backslash_paths_before_tar_path_normalization() {
        let mut archive = archive_with_file("host/tool", b"bytes", 0o644);
        archive[4] = b'\\';
        fix_header_checksum(&mut archive[..512]);
        assert_eq!(archive[4], b'\\');
        assert_eq!(&archive[..9], b"host\\tool");
        assert_eq!(&archive[512..517], b"bytes");
        let expected = expected_row("host/tool", b"bytes");
        let error = verify_publisher_sdk_tar(&archive, &expected).unwrap_err();
        assert!(error.to_string().contains("portable relative ASCII path"));
    }

    #[test]
    fn rejects_exact_and_casefolded_file_ancestor_conflicts() {
        for (parent, child) in [("host", "host/tool"), ("Host", "host/tool")] {
            let parent_digest = sha256_bytes(b"parent");
            let child_digest = sha256_bytes(b"child");
            let expected = [
                ExpectedFile {
                    path: parent,
                    size: 6,
                    sha256: &parent_digest,
                },
                ExpectedFile {
                    path: child,
                    size: 5,
                    sha256: &child_digest,
                },
            ];
            let error = verify_publisher_sdk_tar(&[], &expected).unwrap_err();
            assert!(error.to_string().contains("file/directory path conflict"));
        }
    }

    #[test]
    fn rejects_sparse_links_and_other_non_regular_records() {
        for entry_type in [
            EntryType::GNUSparse,
            EntryType::Symlink,
            EntryType::Link,
            EntryType::Directory,
            EntryType::Fifo,
            EntryType::Continuous,
        ] {
            let mut builder = Builder::new(Vec::new());
            append_record(&mut builder, "host/unsupported", entry_type, b"");
            let archive = builder.into_inner().unwrap();
            let expected = expected_row("host/unsupported", b"");
            assert!(
                verify_publisher_sdk_tar(&archive, &expected).is_err(),
                "accepted unsupported type {entry_type:?}"
            );
        }
    }

    #[test]
    fn rejects_bad_headers_truncated_data_and_invalid_trailers() {
        let bytes = b"data";
        let expected = expected_row("host/file", bytes);
        let valid = archive_with_file("host/file", bytes, 0o644);

        let mut bad_checksum = valid.clone();
        bad_checksum[0] ^= 1;
        assert!(verify_publisher_sdk_tar(&bad_checksum, &expected).is_err());

        let truncated = &valid[..valid.len() - 512];
        assert!(verify_publisher_sdk_tar(truncated, &expected).is_err());

        let mut nonzero_tail = valid.clone();
        let data_end = 512 + 512;
        nonzero_tail[data_end] = 1;
        assert!(verify_publisher_sdk_tar(&nonzero_tail, &expected).is_err());
    }

    #[test]
    fn accepts_historical_signed_tar_checksum_variant() {
        let bytes = b"signed checksum control";
        let mut archive = archive_with_file("host/file", bytes, 0o755);
        archive[100..108].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 1, 0xed]);
        fix_header_checksum_signed(&mut archive[..512]);
        let expected = expected_row("host/file", bytes);
        assert!(verify_publisher_sdk_tar(&archive, &expected).is_ok());
    }

    #[test]
    fn refuses_non_ascii_whitespace_in_every_numeric_header_field() {
        let expected = expected_row("host/file", b"");
        for range in [
            100..108,
            108..116,
            116..124,
            124..136,
            136..148,
            329..337,
            337..345,
        ] {
            let mut archive = archive_with_file("host/file", b"", 0o644);
            archive[range.clone()].fill(0);
            archive[range.start..range.start + 2].copy_from_slice(&[0xc2, 0xa0]);
            fix_header_checksum(&mut archive[..512]);
            let error = verify_publisher_sdk_tar(&archive, &expected).unwrap_err();
            assert!(
                error.to_string().contains("not ASCII"),
                "{range:?}: {error}"
            );
        }
    }

    #[test]
    fn accepts_octal_prefix_separator_and_ascii_trim_rules() {
        let expected = expected_row("host/file", b"");
        for mode in [
            b"0o_7\0\0\0\0".as_slice(),
            b"\x1c7\x0b\0\0\0\0\0".as_slice(),
        ] {
            let mut archive = archive_with_file("host/file", b"", 0o644);
            archive[100..108].copy_from_slice(mode);
            fix_header_checksum(&mut archive[..512]);
            let files = verify_publisher_sdk_tar(&archive, &expected).unwrap();
            assert_eq!(files[0].mode, 0o755);
        }
    }

    #[test]
    fn validates_full_width_ignored_base256_metadata_without_narrowing_it() {
        let expected = expected_row("host/file", b"");
        let mut archive = archive_with_file("host/file", b"", 0o644);
        archive[136..148].fill(0xff);
        archive[136] = 0x80; // Maximum positive 88-bit mtime; not installed.
        fix_header_checksum(&mut archive[..512]);
        assert!(verify_publisher_sdk_tar(&archive, &expected).is_ok());
        archive[136] = 0xff; // Full-width negative value is equally ignored.
        fix_header_checksum(&mut archive[..512]);
        assert!(verify_publisher_sdk_tar(&archive, &expected).is_ok());
    }

    #[test]
    fn enforces_archive_size_and_member_count_boundaries() {
        let bytes = b"boundary";
        let archive = archive_with_file("host/file", bytes, 0o644);
        let expected = expected_row("host/file", bytes);
        let mut exact_archive_cap = archive.clone();
        exact_archive_cap.resize(MAX_DECODED_TAR_BYTES, 0);
        assert!(verify_publisher_sdk_tar(&exact_archive_cap, &expected).is_ok());
        exact_archive_cap.push(0);
        assert!(verify_publisher_sdk_tar(&exact_archive_cap, &expected).is_err());

        let mut builder = Builder::new(Vec::new());
        for index in 0..=MAX_MEMBERS {
            append_file(&mut builder, &format!("f{index:04}"), b"", 0o644);
        }
        let too_many = builder.into_inner().unwrap();
        assert!(verify_publisher_sdk_tar(&too_many, &expected).is_err());
    }

    #[test]
    fn validates_authenticated_inventory_paths_and_digest_shape() {
        for path in [
            "../outside",
            "/absolute",
            "host\\tool",
            "host:tool",
            "CON.txt",
            "host/COM9",
            "host/trailing.",
            "host//tool",
            "host/non-ascii-é",
        ] {
            let expected = [ExpectedFile {
                path,
                size: 0,
                sha256: &"0".repeat(64),
            }];
            assert!(
                verify_publisher_sdk_tar(&[], &expected).is_err(),
                "accepted {path:?}"
            );
        }
        let expected = [ExpectedFile {
            path: "host/tool",
            size: 0,
            sha256: "ABCDEF",
        }];
        assert!(verify_publisher_sdk_tar(&[], &expected).is_err());
    }

    fn fix_header_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let encoded = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(encoded.as_bytes());
    }

    fn fix_header_checksum_signed(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum: i64 = header[..148]
            .iter()
            .chain(&header[156..])
            .map(|byte| i64::from(*byte as i8))
            .sum::<i64>()
            + 256;
        let encoded = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(encoded.as_bytes());
    }
}

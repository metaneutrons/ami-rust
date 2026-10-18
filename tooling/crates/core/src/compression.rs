//! Strict, bounded decompression for authenticated SDK archive inputs.
//!
//! Decoding writes to the supplied sink as bytes are verified. A later
//! checksum, truncation, or suffix error can leave partial (or complete) bytes
//! in that sink. Callers must use unpublished staging and discard it on error.

use std::io::{Cursor, Read, Write};

use flate2::bufread::GzDecoder;
use lzma_rust2::XzReader;

use crate::{Refusal, Result};

/// Per-input limits supplied by the authenticated inventory or format profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    pub max_compressed_bytes: usize,
    pub max_decoded_bytes: usize,
    /// Per-block XZ decoder memory ceiling in KiB. Ignored by gzip decoding.
    pub max_xz_memory_kib: u32,
}

/// Decode exactly one complete gzip member into `output`.
///
/// The compressed-size limit is checked before decoding. The output limit is
/// enforced before each write, and trailing bytes or another gzip member cause
/// refusal. `write_all` handles short writes; sink errors propagate as refusals.
pub fn copy_gzip(input: &[u8], output: &mut impl Write, limits: DecodeLimits) -> Result<usize> {
    check_compressed_size("gzip", input, limits.max_compressed_bytes)?;

    let mut decoder = GzDecoder::new(Cursor::new(input));
    let decoded_bytes = copy_bounded("gzip", &mut decoder, output, limits.max_decoded_bytes)?;
    let consumed = decoder.into_inner().position();
    require_complete_input("gzip", consumed, input.len())?;
    Ok(decoded_bytes)
}

/// Decode exactly one complete XZ stream into `output` under a per-block
/// decoder memory ceiling.
///
/// The profile requires exact input consumption. Concatenated streams,
/// trailing junk, and even otherwise-valid XZ stream padding are refused.
/// `lzma-rust2`'s memory value is a per-block estimate in KiB, not a
/// whole-process memory budget.
pub fn copy_xz(input: &[u8], output: &mut impl Write, limits: DecodeLimits) -> Result<usize> {
    check_compressed_size("XZ", input, limits.max_compressed_bytes)?;
    if limits.max_xz_memory_kib == 0 {
        return Err(Refusal::new(
            "XZ memory limit must be greater than zero KiB",
        ));
    }

    let mut decoder = XzReader::new_mem_limit(Cursor::new(input), false, limits.max_xz_memory_kib);
    let decoded_bytes = copy_bounded("XZ", &mut decoder, output, limits.max_decoded_bytes)?;
    let consumed = decoder.into_inner().position();
    require_complete_input("XZ", consumed, input.len())?;
    Ok(decoded_bytes)
}

fn check_compressed_size(format: &str, input: &[u8], limit: usize) -> Result<()> {
    if input.len() > limit {
        return Err(Refusal::new(format!(
            "{format} compressed input exceeds configured limit of {limit} bytes"
        )));
    }
    Ok(())
}

fn require_complete_input(format: &str, consumed: u64, input_len: usize) -> Result<()> {
    let input_len = u64::try_from(input_len)
        .map_err(|_| Refusal::new(format!("{format} input length is not representable")))?;
    if consumed != input_len {
        return Err(Refusal::new(format!(
            "{format} input contains trailing bytes or additional streams"
        )));
    }
    Ok(())
}

fn copy_bounded(
    format: &str,
    reader: &mut impl Read,
    output: &mut impl Write,
    decoded_limit: usize,
) -> Result<usize> {
    let mut decoded_bytes = 0usize;
    let mut buffer = [0u8; 8192];

    loop {
        let remaining = decoded_limit - decoded_bytes;
        if remaining == 0 {
            // Probe one byte to distinguish output exactly at the limit from
            // output that exceeds it. The probe is never written to the sink.
            let mut probe = [0u8; 1];
            let read = reader
                .read(&mut probe)
                .map_err(|error| Refusal::new(format!("{format} decoding failed: {error}")))?;
            if read == 0 {
                return Ok(decoded_bytes);
            }
            return Err(Refusal::new(format!(
                "{format} decoded output exceeds configured limit of {decoded_limit} bytes"
            )));
        }

        let request = remaining.min(buffer.len());
        let read = reader
            .read(&mut buffer[..request])
            .map_err(|error| Refusal::new(format!("{format} decoding failed: {error}")))?;
        if read == 0 {
            return Ok(decoded_bytes);
        }

        output.write_all(&buffer[..read]).map_err(|error| {
            Refusal::new(format!("writing decoded {format} data failed: {error}"))
        })?;
        decoded_bytes += read;
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use flate2::{Compression, write::GzEncoder};

    use super::{DecodeLimits, copy_gzip, copy_xz};

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

    const XZ_PLAINTEXT: &[u8] = b"RC0 host contract probe: bounded XZ output.\n";

    fn limits(
        max_compressed_bytes: usize,
        max_decoded_bytes: usize,
        max_xz_memory_kib: u32,
    ) -> DecodeLimits {
        DecodeLimits {
            max_compressed_bytes,
            max_decoded_bytes,
            max_xz_memory_kib,
        }
    }

    fn gzip(input: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_accepts_one_member_at_exact_caps_and_refuses_excess_caps() {
        let plain = b"one complete gzip member";
        let encoded = gzip(plain);
        let mut output = Vec::new();
        assert_eq!(
            copy_gzip(&encoded, &mut output, limits(encoded.len(), plain.len(), 0)).unwrap(),
            plain.len()
        );
        assert_eq!(output, plain);

        let mut short_output = Vec::new();
        assert!(
            copy_gzip(
                &encoded,
                &mut short_output,
                limits(encoded.len(), plain.len() - 1, 0)
            )
            .is_err()
        );
        assert_eq!(short_output, &plain[..plain.len() - 1]);

        let mut untouched = Vec::new();
        assert!(
            copy_gzip(
                &encoded,
                &mut untouched,
                limits(encoded.len() - 1, plain.len(), 0)
            )
            .is_err()
        );
        assert!(untouched.is_empty());
    }

    #[test]
    fn gzip_rejects_trailing_junk_concatenation_truncation_and_bad_crc() {
        let first = gzip(b"first member");
        let second = gzip(b"second member");

        let mut junk = first.clone();
        junk.extend_from_slice(b"junk");
        assert!(copy_gzip(&junk, &mut Vec::new(), limits(junk.len(), 1024, 0)).is_err());

        let mut concatenated = first.clone();
        concatenated.extend_from_slice(&second);
        assert!(
            copy_gzip(
                &concatenated,
                &mut Vec::new(),
                limits(concatenated.len(), 1024, 0)
            )
            .is_err()
        );

        assert!(
            copy_gzip(
                &first[..first.len() - 1],
                &mut Vec::new(),
                limits(first.len(), 1024, 0)
            )
            .is_err()
        );

        let mut bad_crc = first.clone();
        let crc_offset = bad_crc.len() - 8;
        bad_crc[crc_offset] ^= 1;
        assert!(copy_gzip(&bad_crc, &mut Vec::new(), limits(bad_crc.len(), 1024, 0)).is_err());
    }

    #[test]
    fn xz_enforces_compressed_decoded_and_dictionary_limits() {
        let mut output = Vec::new();
        assert_eq!(
            copy_xz(
                XZ_TINY_4K_DICT,
                &mut output,
                limits(XZ_TINY_4K_DICT.len(), XZ_PLAINTEXT.len(), 1024)
            )
            .unwrap(),
            XZ_PLAINTEXT.len()
        );
        assert_eq!(output, XZ_PLAINTEXT);

        let mut short_output = Vec::new();
        assert!(
            copy_xz(
                XZ_TINY_4K_DICT,
                &mut short_output,
                limits(XZ_TINY_4K_DICT.len(), XZ_PLAINTEXT.len() - 1, 1024)
            )
            .is_err()
        );
        assert_eq!(short_output, &XZ_PLAINTEXT[..XZ_PLAINTEXT.len() - 1]);

        let mut untouched = Vec::new();
        assert!(
            copy_xz(
                XZ_TINY_4K_DICT,
                &mut untouched,
                limits(XZ_TINY_4K_DICT.len() - 1, XZ_PLAINTEXT.len(), 1024)
            )
            .is_err()
        );
        assert!(untouched.is_empty());

        assert!(
            copy_xz(
                XZ_TINY_4K_DICT,
                &mut Vec::new(),
                limits(XZ_TINY_4K_DICT.len(), XZ_PLAINTEXT.len(), 1)
            )
            .is_err()
        );
        assert!(
            copy_xz(
                XZ_TINY_64M_DICT,
                &mut Vec::new(),
                limits(XZ_TINY_64M_DICT.len(), 1024, 1024)
            )
            .is_err()
        );
    }

    #[test]
    fn xz_rejects_every_suffix_truncation_and_bad_block_crc() {
        let mut junk = XZ_TINY_4K_DICT.to_vec();
        junk.extend_from_slice(b"junk");
        assert!(copy_xz(&junk, &mut Vec::new(), limits(junk.len(), 1024, 1024)).is_err());

        let mut concatenated = XZ_TINY_4K_DICT.to_vec();
        concatenated.extend_from_slice(XZ_TINY_4K_DICT);
        assert!(
            copy_xz(
                &concatenated,
                &mut Vec::new(),
                limits(concatenated.len(), 1024, 1024)
            )
            .is_err()
        );

        // XZ permits stream padding in multiples of four, but this SDK profile
        // requires exact consumption and deliberately refuses even that form.
        let mut padded = XZ_TINY_4K_DICT.to_vec();
        padded.extend_from_slice(&[0, 0, 0, 0]);
        assert!(copy_xz(&padded, &mut Vec::new(), limits(padded.len(), 1024, 1024)).is_err());

        assert!(
            copy_xz(
                &XZ_TINY_4K_DICT[..XZ_TINY_4K_DICT.len() - 1],
                &mut Vec::new(),
                limits(XZ_TINY_4K_DICT.len(), 1024, 1024)
            )
            .is_err()
        );

        let mut bad_crc = XZ_TINY_4K_DICT.to_vec();
        // The block CRC32 occupies bytes 76..80 in this pinned XZ fixture.
        bad_crc[76] ^= 1;
        assert!(copy_xz(&bad_crc, &mut Vec::new(), limits(bad_crc.len(), 1024, 1024)).is_err());
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        max_write: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let written = buffer.len().min(self.max_write);
            self.bytes.extend_from_slice(&buffer[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingWriter {
        bytes: Vec<u8>,
        fail_after: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.bytes.len() >= self.fail_after {
                return Err(io::Error::other("fixture sink failure"));
            }
            let written = buffer.len().min(self.fail_after - self.bytes.len()).min(3);
            self.bytes.extend_from_slice(&buffer[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_short_writes_are_completed_and_sink_failures_propagate() {
        let plain = b"short writes are handled by write_all";
        let encoded = gzip(plain);

        let mut short_writer = ShortWriter {
            bytes: Vec::new(),
            max_write: 2,
        };
        assert_eq!(
            copy_gzip(
                &encoded,
                &mut short_writer,
                limits(encoded.len(), plain.len(), 0)
            )
            .unwrap(),
            plain.len()
        );
        assert_eq!(short_writer.bytes, plain);

        let mut failing_writer = FailingWriter {
            bytes: Vec::new(),
            fail_after: 5,
        };
        let error = copy_gzip(
            &encoded,
            &mut failing_writer,
            limits(encoded.len(), plain.len(), 0),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("writing decoded gzip data failed")
        );
        assert_eq!(failing_writer.bytes.len(), 5);
    }
}

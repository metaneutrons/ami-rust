#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use amiga_os::{AppStatus, BytePath, Context, Error, File, FileMode, Stderr, Stdout};
use sha2::{Digest, Sha256};

const READ_BUFFER_SIZE: usize = 4096;
const MAX_PATH_BYTES: usize = 127;
// Native startup bounds the combined argument strings to 4096 bytes, including
// NUL terminators, so a single path can contain at most 4095 raw bytes.
const MAX_ARGUMENT_BYTES: usize = 4095;
const DIGEST_BYTES: usize = 32;
const HEX_DIGEST_BYTES: usize = DIGEST_BYTES * 2;
const LINE_BUFFER_SIZE: usize = HEX_DIGEST_BYTES + 2 + MAX_PATH_BYTES + 1;
const ERROR_LINE_BUFFER_SIZE: usize = MAX_ARGUMENT_BYTES + 256;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProcessError {
    File,
    Output,
}

fn record_error(context: &Context, label: &[u8], error: Error) {
    // Preserve the complete signed native error bit pattern; class and
    // operation are separate scalar fields rather than truncating IoErr.
    context.diagnostic(label, error.native as u64);
    context.diagnostic(
        b"sha256sum: class/operation",
        ((error.kind_code() as u64) << 32) | error.operation as u64,
    );
}

fn append_bytes(
    output: &mut [u8; ERROR_LINE_BUFFER_SIZE],
    length: &mut usize,
    bytes: &[u8],
) -> bool {
    let Some(end) = (*length).checked_add(bytes.len()) else {
        return false;
    };
    if end > output.len() {
        return false;
    }
    output[*length..end].copy_from_slice(bytes);
    *length = end;
    true
}

fn append_byte(output: &mut [u8; ERROR_LINE_BUFFER_SIZE], length: &mut usize, byte: u8) -> bool {
    let Some(end) = (*length).checked_add(1) else {
        return false;
    };
    if end > output.len() {
        return false;
    }
    output[*length] = byte;
    *length = end;
    true
}

fn append_u64(
    output: &mut [u8; ERROR_LINE_BUFFER_SIZE],
    length: &mut usize,
    mut value: u64,
) -> bool {
    let mut reversed = [0; 20];
    let mut digits = 0;
    loop {
        reversed[digits] = b'0' + (value % 10) as u8;
        digits += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    while digits != 0 {
        digits -= 1;
        if !append_byte(output, length, reversed[digits]) {
            return false;
        }
    }
    true
}

fn append_i64(output: &mut [u8; ERROR_LINE_BUFFER_SIZE], length: &mut usize, value: i64) -> bool {
    if value < 0 {
        if !append_byte(output, length, b'-') {
            return false;
        }
        // Negating the signed minimum overflows; unsigned two's-complement
        // arithmetic gives its exact magnitude, including i64::MIN.
        append_u64(output, length, (value as u64).wrapping_neg())
    } else {
        append_u64(output, length, value as u64)
    }
}

/// Formats a user-visible error without allocation and copies paths byte-for-byte.
fn format_error_line<'a>(
    label: &[u8],
    path: Option<&[u8]>,
    error: Error,
    output: &'a mut [u8; ERROR_LINE_BUFFER_SIZE],
) -> Option<&'a [u8]> {
    let mut length = 0;
    if !append_bytes(output, &mut length, label) {
        return None;
    }
    if let Some(path) = path {
        if !append_bytes(output, &mut length, b": ") || !append_bytes(output, &mut length, path) {
            return None;
        }
    }
    if !append_bytes(output, &mut length, b": native=")
        || !append_i64(output, &mut length, error.native)
        || !append_bytes(output, &mut length, b" class=")
        || !append_u64(output, &mut length, error.kind_code() as u64)
        || !append_bytes(output, &mut length, b" operation=")
        || !append_u64(output, &mut length, error.operation as u64)
        || !append_byte(output, &mut length, b'\n')
    {
        return None;
    }
    Some(&output[..length])
}

fn format_path_message<'a>(
    label: &[u8],
    path: &[u8],
    output: &'a mut [u8; ERROR_LINE_BUFFER_SIZE],
) -> Option<&'a [u8]> {
    let mut length = 0;
    if !append_bytes(output, &mut length, label)
        || !append_bytes(output, &mut length, b": ")
        || !append_bytes(output, &mut length, path)
        || !append_byte(output, &mut length, b'\n')
    {
        return None;
    }
    Some(&output[..length])
}

fn report_stderr_failure(context: &Context, error: Error) {
    // Do not try to report a broken stderr stream through that same stream.
    record_error(context, b"sha256sum: stderr error", error);
}

fn write_stderr(context: &Context, stderr: &mut Stderr<'_>, bytes: &[u8]) {
    if let Err(error) = stderr.write_all(bytes) {
        report_stderr_failure(context, error);
    }
}

fn report_error(
    context: &Context,
    stderr: &mut Stderr<'_>,
    label: &[u8],
    path: Option<&[u8]>,
    error: Error,
) {
    record_error(context, label, error);
    let mut output = [0; ERROR_LINE_BUFFER_SIZE];
    if let Some(line) = format_error_line(label, path, error, &mut output) {
        write_stderr(context, stderr, line);
    } else {
        context.diagnostic(
            b"sha256sum: error formatting failed",
            path.map_or(0, |p| p.len()) as u64,
        );
    }
}

fn report_path_message(context: &Context, stderr: &mut Stderr<'_>, label: &[u8], path: &[u8]) {
    context.diagnostic(label, 0);
    let mut output = [0; ERROR_LINE_BUFFER_SIZE];
    if let Some(line) = format_path_message(label, path, &mut output) {
        write_stderr(context, stderr, line);
    } else {
        context.diagnostic(b"sha256sum: error formatting failed", path.len() as u64);
    }
}

fn report_message(
    context: &Context,
    stderr: &mut Stderr<'_>,
    label: &[u8],
    code: u64,
    message: &[u8],
) {
    context.diagnostic(label, code);
    write_stderr(context, stderr, message);
}

/// Formats the output record without allocation or path transcoding.
fn format_digest_line<'a>(
    digest: &[u8],
    path: &[u8],
    output: &'a mut [u8; LINE_BUFFER_SIZE],
) -> Option<&'a [u8]> {
    if digest.len() != DIGEST_BYTES || path.len() > MAX_PATH_BYTES {
        return None;
    }

    for (index, byte) in digest.iter().copied().enumerate() {
        output[index * 2] = HEX[(byte >> 4) as usize];
        output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }

    output[HEX_DIGEST_BYTES] = b' ';
    output[HEX_DIGEST_BYTES + 1] = b' ';
    let path_start = HEX_DIGEST_BYTES + 2;
    let path_end = path_start + path.len();
    output[path_start..path_end].copy_from_slice(path);
    output[path_end] = b'\n';

    Some(&output[..path_end + 1])
}

fn process_file(
    context: &Context,
    stdout: &mut Stdout<'_>,
    stderr: &mut Stderr<'_>,
    path: &[u8],
    read_buffer: &mut [u8],
) -> Result<(), ProcessError> {
    let byte_path = match BytePath::new(path) {
        Ok(path) => path,
        Err(error) => {
            report_error(context, stderr, b"sha256sum: file error", Some(path), error);
            return Err(ProcessError::File);
        }
    };

    let mut file = match File::open(context, &byte_path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, stderr, b"sha256sum: file error", Some(path), error);
            return Err(ProcessError::File);
        }
    };

    let mut hasher = Sha256::new();
    let read_error = loop {
        match file.read(read_buffer) {
            Ok(0) => break None,
            Ok(count) => hasher.update(&read_buffer[..count]),
            Err(error) => break Some(error),
        }
    };
    let close_result = file.close();

    let mut file_failed = false;
    if let Some(error) = read_error {
        report_error(context, stderr, b"sha256sum: file error", Some(path), error);
        file_failed = true;
    }
    if let Err(error) = close_result {
        report_error(context, stderr, b"sha256sum: file error", Some(path), error);
        file_failed = true;
    }
    if file_failed {
        return Err(ProcessError::File);
    }

    let digest = hasher.finalize();
    let mut line = [0; LINE_BUFFER_SIZE];
    let Some(line) = format_digest_line(&digest, path, &mut line) else {
        // BytePath::new has already enforced this helper's path bound.
        report_path_message(context, stderr, b"sha256sum: formatting error", path);
        return Err(ProcessError::File);
    };

    if let Err(error) = stdout.write_all(line) {
        report_error(
            context,
            stderr,
            b"sha256sum: stdout error",
            Some(path),
            error,
        );
        Err(ProcessError::Output)
    } else {
        Ok(())
    }
}

fn application(context: &Context) -> AppStatus {
    let mut stderr = match Stderr::new(context) {
        Ok(stderr) => stderr,
        Err(error) => {
            report_stderr_failure(context, error);
            return AppStatus::Error;
        }
    };

    let mut args = context.args();
    let _argv0 = args.next();
    let Some(first_path) = args.next() else {
        report_message(
            context,
            &mut stderr,
            b"usage: sha256sum FILE...",
            0,
            b"usage: sha256sum FILE...\n",
        );
        return AppStatus::Error;
    };

    let mut stdout = match Stdout::new(context) {
        Ok(stdout) => stdout,
        Err(error) => {
            report_error(
                context,
                &mut stderr,
                b"sha256sum: stdout error",
                None,
                error,
            );
            return AppStatus::Error;
        }
    };

    let mut read_buffer = Vec::<u8>::new();
    if read_buffer.try_reserve_exact(READ_BUFFER_SIZE).is_err() {
        report_message(
            context,
            &mut stderr,
            b"sha256sum: buffer allocation failed",
            READ_BUFFER_SIZE as u64,
            b"sha256sum: buffer allocation failed (4096 bytes)\n",
        );
        return AppStatus::Error;
    }
    read_buffer.resize(READ_BUFFER_SIZE, 0);

    let mut had_file_error = false;
    for path in core::iter::once(first_path).chain(args) {
        match process_file(context, &mut stdout, &mut stderr, path, &mut read_buffer) {
            Ok(()) => {}
            Err(ProcessError::File) => had_file_error = true,
            Err(ProcessError::Output) => return AppStatus::Error,
        }
    }

    if had_file_error {
        AppStatus::Error
    } else {
        AppStatus::Success
    }
}

#[cfg(not(test))]
amiga_os::entry!(application, alloc);

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_lowercase_digest_and_preserves_path_bytes() {
        let digest = [0xab; DIGEST_BYTES];
        let path = b"directory/file with spaces";
        let mut output = [0; LINE_BUFFER_SIZE];

        let line = format_digest_line(&digest, path, &mut output).unwrap();

        std::assert_eq!(
            line,
            b"abababababababababababababababababababababababababababababababab  directory/file with spaces\n"
        );
    }

    #[test]
    fn rejects_paths_outside_the_sdk_bound() {
        let digest = [0; DIGEST_BYTES];
        let path = [b'x'; MAX_PATH_BYTES + 1];
        let mut output = [0; LINE_BUFFER_SIZE];

        std::assert!(format_digest_line(&digest, &path, &mut output).is_none());
    }

    #[test]
    fn formats_signed_native_boundaries_and_preserves_raw_path_bytes() {
        let mut output = [0; ERROR_LINE_BUFFER_SIZE];
        let error = Error {
            kind: amiga_os::ErrorKind::Native,
            native: i64::MIN,
            operation: amiga_os::Operation::Stderr,
        };

        let line = format_error_line(
            b"sha256sum: file error",
            Some(b"dir/\xfffile"),
            error,
            &mut output,
        )
        .unwrap();

        std::assert_eq!(
            line,
            b"sha256sum: file error: dir/\xfffile: native=-9223372036854775808 class=1 operation=22\n"
        );

        let error = Error {
            kind: amiga_os::ErrorKind::State,
            native: i64::MAX,
            operation: amiga_os::Operation::FileRead,
        };
        let line = format_error_line(b"sha256sum: stdout error", None, error, &mut output).unwrap();

        std::assert_eq!(
            line,
            b"sha256sum: stdout error: native=9223372036854775807 class=5 operation=5\n"
        );
    }

    #[test]
    fn formats_the_longest_native_argument_path_without_truncation() {
        let path = [b'x'; MAX_ARGUMENT_BYTES];
        let mut output = [0; ERROR_LINE_BUFFER_SIZE];
        let error = Error {
            kind: amiga_os::ErrorKind::Input,
            native: 0,
            operation: amiga_os::Operation::Path,
        };

        let line =
            format_error_line(b"sha256sum: file error", Some(&path), error, &mut output).unwrap();
        let prefix = b"sha256sum: file error: ";
        let suffix = b": native=0 class=2 operation=1\n";

        std::assert_eq!(&line[..prefix.len()], prefix);
        std::assert_eq!(&line[prefix.len()..prefix.len() + path.len()], &path);
        std::assert_eq!(&line[prefix.len() + path.len()..], suffix);
    }
}

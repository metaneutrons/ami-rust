//! SHA-256 helpers for bytes and securely opened regular files.

use crate::{Refusal, Result};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    path::Path,
};

use crate::files::open_regular_nofollow;

/// Return the lowercase SHA-256 digest of an in-memory byte string.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    encode_hex(&digest)
}

/// Stream a regular file through SHA-256 without following path symlinks.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = open_regular_nofollow(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => {
                let value: [u8; 32] = digest.finalize().into();
                return Ok(encode_hex(&value));
            }
            Ok(read) => digest.update(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not hash the opened file: {error}"
                )));
            }
        }
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

/// Return whether `value` is exactly 64 lowercase hexadecimal characters.
pub fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{is_sha256_digest, sha256_bytes, sha256_file};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempFile(PathBuf);

    impl TempFile {
        fn new(contents: &[u8]) -> Self {
            let cwd = std::env::current_dir().expect("current directory");
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = cwd.join(format!(
                    ".ami-rust-digest-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(mut file) => {
                        use std::io::Write;
                        file.write_all(contents).expect("write digest fixture");
                        return Self(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create digest fixture: {error}"),
                }
            }
            panic!("could not allocate a unique digest fixture");
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            fs::remove_file(&self.0).expect("remove digest fixture");
        }
    }

    #[test]
    fn hashes_bytes_and_streams_binary_file_contents() {
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_bytes(b"abc"), abc);

        let binary = [0_u8, 0xff, b'a', b'\n', 0x80];
        let fixture = TempFile::new(&binary);
        assert_eq!(sha256_file(fixture.path()).unwrap(), sha256_bytes(&binary));
    }

    #[test]
    fn validates_only_lowercase_sha256_hex() {
        let valid = sha256_bytes(b"abc");
        assert!(is_sha256_digest(&valid));
        assert!(!is_sha256_digest(""));
        assert!(!is_sha256_digest(&valid.to_uppercase()));
        assert!(!is_sha256_digest(&format!("{}g", &valid[..63])));
        assert!(!is_sha256_digest(&valid[..63]));
    }
}

//! Host-side AROS native ELF validation and section-name compaction.
//!
//! This library does not select SDKs, execute commands, authenticate toolchains,
//! or install a command-line application. Callers validate their inputs and
//! publish an output only after both compaction and audit have succeeded.
#![forbid(unsafe_code)]

mod error;
pub use error::{Refusal, Result};
pub mod compact;
pub mod elf;

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

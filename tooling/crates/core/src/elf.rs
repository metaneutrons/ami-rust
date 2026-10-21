//! Shared AROS ELF audit; the implementation lives in the standalone crate.
use crate::Result;

pub fn audit(bytes: &[u8], variant: &str, path: &str) -> Result<serde_json::Value> {
    aros_elf::elf::audit(bytes, variant, path).map_err(Into::into)
}

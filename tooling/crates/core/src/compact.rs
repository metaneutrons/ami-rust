//! Shared AROS section compaction from the standalone host library.
use crate::Result;
pub use aros_elf::compact::{CompactedElf, CompactionReport, SectionRename};

pub fn compact_elf_sections(bytes: &[u8]) -> Result<Vec<u8>> {
    aros_elf::compact::compact_elf_sections(bytes).map_err(Into::into)
}

pub fn compact_elf_sections_with_report(bytes: &[u8]) -> Result<CompactedElf> {
    aros_elf::compact::compact_elf_sections_with_report(bytes).map_err(Into::into)
}

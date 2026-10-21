//! Ordinary Cargo build-script integration for the pinned AROS x86-64 target.
//!
//! Call [`prepare`] from an application's additive `build.rs`. Cargo continues
//! to resolve dependencies and select the Rust toolchain. The focused
//! `aros-link` binary implements the target linker interface only.
mod build;
mod inputs;
mod link;
mod link_args;
pub mod recipe;

pub use aros_elf::{Refusal, Result};
pub use build::{BuildOptions, prepare};

/// The rustc target-linker entry point. This is not a Cargo command dispatcher.
pub fn link(arguments: &[std::ffi::OsString]) -> Result<()> {
    link::link(arguments)
}

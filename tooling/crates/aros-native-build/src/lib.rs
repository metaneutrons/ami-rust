//! Ordinary Cargo build-script integration for the pinned AROS x86-64 target.
//!
//! Call [`prepare`] from an application's additive `build.rs`. Cargo continues
//! to resolve dependencies and select the Rust toolchain. The focused
//! `aros-link` binary implements the target linker interface only.
mod build;
mod inputs;
mod link;
mod link_args;
/// Shared regular-file portable SDK view policy.
#[doc(hidden)]
pub mod portable_view;
/// Shared versioned public SDK component selection policy.
#[doc(hidden)]
pub mod public_view;
pub mod recipe;

pub use aros_elf::{Refusal, Result};
pub use build::{BuildOptions, prepare};
/// Verified locally composed native-build prefix.
#[doc(hidden)]
pub use inputs::Toolchain;

/// The rustc target-linker entry point. This is not a Cargo command dispatcher.
pub fn link(arguments: &[std::ffi::OsString]) -> Result<()> {
    link::link(arguments)
}

//! Shared host-side consumer implementation. Target SDK crates live separately.
#![deny(unsafe_op_in_unsafe_fn)]

mod error;
pub use error::{Refusal, Result};

pub mod compression;
pub mod digest;
pub mod elf;
pub mod files;
pub mod frontend;
pub mod json;
pub mod records;

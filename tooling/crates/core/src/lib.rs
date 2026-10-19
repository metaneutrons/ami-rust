//! Shared host-side consumer implementation. Target SDK crates live separately.
#![deny(unsafe_op_in_unsafe_fn)]

mod error;
pub use error::{Refusal, Result};

pub mod compression;
pub mod digest;
pub mod directory;
pub mod elf;
pub mod files;
pub mod frontend;
pub mod inventory;
pub mod json;
mod mutations;
pub mod ownership;
pub mod publisher_tar;
pub mod receipts;
pub mod records;
pub mod signals;
pub mod transaction;

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
pub mod process_capture;
pub mod publisher;
pub mod publisher_claims;
pub mod publisher_files;
mod publisher_home;
pub mod publisher_metadata;
pub mod publisher_policy;
pub mod publisher_tar;
pub mod receipts;
pub mod records;
pub mod release_manifest;
pub mod signals;
pub mod transaction;
pub mod workflow_counter;

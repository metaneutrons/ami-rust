//! Shared host-side consumer implementation. Target SDK crates live separately.
#![deny(unsafe_op_in_unsafe_fn)]

mod error;
pub use error::{Refusal, Result};

pub mod acquisition;
pub mod baseline;
pub mod cargo_archive;
pub mod compact;
pub mod component_archive;
pub mod component_install;
pub mod compression;
pub mod consumer_provision;
pub mod consumer_session;
pub mod consumer_source;
pub mod digest;
pub mod directory;
pub mod elf;
pub mod files;
pub mod frontend;
pub mod host_platform;
pub mod inventory;
pub mod json;
#[cfg(target_os = "macos")]
#[path = "../../../macos-host-selection.rs"]
mod macos_host_selection;
pub mod migration_process;
mod mutations;
pub mod native_build;
pub mod native_install;
pub mod native_migrate;
pub mod native_prepare;
pub mod native_project;
pub mod native_recipe;
pub mod ownership;
pub mod package;
pub mod package_records;
pub mod process_capture;
mod process_lease;
pub mod process_snapshot;
pub mod public_transport;
pub mod publisher;
pub mod publisher_claims;
pub mod publisher_files;
mod publisher_home;
pub mod publisher_materials;
pub mod publisher_metadata;
pub mod publisher_policy;
pub mod publisher_tar;
pub mod ready_state;
pub mod receipts;
pub mod records;
pub mod release_manifest;
pub mod resource_capture;
pub mod sdk;
pub mod selected_inputs;
pub mod signals;
pub mod transaction;
pub mod verifier_bootstrap;
pub mod workflow_counter;
pub mod workspace_accounting;

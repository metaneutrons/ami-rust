//! Shared host-side consumer implementation. Target SDK crates live separately.
#![deny(unsafe_op_in_unsafe_fn)]

mod error;
pub use error::{Refusal, Result};

pub mod acquisition;
/// Maintainer-only retained bare-target command readback.
#[doc(hidden)]
pub mod bare_target_record_validation;
pub mod baseline;
pub mod cargo_archive;
pub mod cargo_producer;
pub mod cargo_vendor_overlay;
pub mod compact;
pub mod component_archive;
pub mod component_install;
pub mod compression;
pub mod consumer_provision;
pub mod consumer_session;
pub mod consumer_source;
pub mod csdk_ar;
pub mod csdk_headers;
pub mod csdk_metadata;
pub mod csdk_nouveau;
pub mod csdk_pack;
pub mod csdk_patches;
pub mod csdk_prefix_map;
pub mod csdk_recipes;
pub mod csdk_source;
pub mod csdk_staging;
pub mod digest;
pub mod directory;
pub mod elf;
pub mod files;
pub mod host_platform;
pub mod inventory;
pub mod json;
#[cfg(target_os = "macos")]
#[path = "../../../macos-host-selection.rs"]
mod macos_host_selection;
mod mutations;
pub mod native_install;
/// Maintainer-only local composition of already-authenticated host components.
#[doc(hidden)]
pub mod native_prefix;
pub mod ownership;
pub mod package;
pub mod package_records;
/// Shared regular-file SDK transport derivation.
#[doc(hidden)]
#[path = "../../aros-native-build/src/portable_view.rs"]
pub mod portable_view;
pub mod process_capture;
mod process_lease;
pub mod process_snapshot;
mod process_spawn;
pub mod production_contract;
pub mod public_transport;
/// Shared versioned selection policy for the public toolchain prefix.
#[doc(hidden)]
#[path = "../../aros-native-build/src/public_view.rs"]
pub mod public_view;
pub mod publisher;
pub mod publisher_claims;
pub mod publisher_files;
mod publisher_home;
pub mod publisher_metadata;
pub mod publisher_policy;
pub mod publisher_tar;
/// Maintainer-only one-command qualification API.
#[doc(hidden)]
pub mod qualification_command;
pub mod ready_state;
pub mod receipts;
pub mod records;
pub mod release_manifest;
pub mod resource_capture;
pub mod sdk;
pub mod selected_inputs;
pub mod signals;
/// Maintainer-only deterministic rust-installer component production.
#[doc(hidden)]
pub mod toolchain_package;
/// Maintainer-only inventory for the standard Cargo/rustup toolchain product.
#[doc(hidden)]
pub mod toolchain_release;
pub mod transaction;
pub mod workflow_counter;
pub mod workspace_accounting;

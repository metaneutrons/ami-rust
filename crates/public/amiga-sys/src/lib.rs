#![no_std]
//! Raw ABI types and unsafe calls for the qualified AROS x86-64 ABI-v1 SDK.
//! The facade is restricted to this measured AROS profile; no other Amiga OS is qualified.
pub use aros_sys::*;

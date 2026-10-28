#![no_std]
//! Safe application APIs for the qualified AROS x86-64 ABI-v1 profile.
//!
//! Optional libraries live in focused crates such as `aros-mui`. Raw ABI
//! access remains in `aros-sys`.

#[cfg(feature = "alloc")]
mod allocator;
mod runtime;
mod sdk;

#[cfg(feature = "alloc")]
pub use allocator::ExecAllocator;
pub use runtime::{AppStatus, Args, Context, dispatch};
pub use sdk::*;

#[doc(hidden)]
pub use runtime::__fatal;

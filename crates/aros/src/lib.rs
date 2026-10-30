#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Safe application APIs for the qualified AROS x86-64 ABI-v1 and ABI-v11
//! profiles.
//!
//! `aros` is `no_std` and task-affine. The native C runtime initializes the
//! application, claims one owner task, and calls one Rust entry function. The
//! [`Context`] passed to that function is a borrowed witness for this live
//! application frame; it and every SDK handle derived from it are confined to
//! the same task and cannot outlive the frame. When the function returns, the
//! native runtime reclaims tracked resources, including resources whose Rust
//! handles were forgotten.
//!
//! The safe surface contains bounded file and stream I/O, optional-library
//! handles, signals, private message ports, messages, and synchronous
//! callbacks. Buffers and callback state are borrowed only for the duration of
//! each call. Native handles are represented by private registry tokens rather
//! than exposed pointers. The only raw native-pointer escape hatch,
//! [`Library::raw_base`], is unsafe. Use `aros-sys` when a raw AROS ABI call
//! is required; focused crates such as `aros-mui` provide higher-level
//! library APIs.
//!
//! # Application entry
//!
//! Define a function with the signature `fn(&Context) -> AppStatus`, then
//! invoke [`entry!`] once in the final application crate. The macro exports
//! the native entry symbol and installs a heap-free panic handler. With the
//! default `alloc` feature enabled, `entry!(application, alloc)` also installs
//! [`ExecAllocator`]. The no-allocator form, `entry!(application)`, leaves the
//! global allocator unset.
//!
//! ```ignore
//! use aros::{AppStatus, Context};
//!
//! fn application(_context: &Context) -> AppStatus {
//!     AppStatus::Success
//! }
//!
//! aros::entry!(application, alloc);
//! ```
//!
//! `entry!` must be invoked once because it defines `rust_sdk_main` and the
//! panic handler. A panic does not unwind through the native boundary: the
//! handler enters the native fatal path and the application terminates with
//! [`AppStatus::Fatal`]. Allocation refusal remains possible even when the
//! allocator is installed.
//!
//! # Bounds and failures
//!
//! SDK resources use fixed native registries: at most 16 open files, 4
//! optional libraries, 2 private ports, 4 owned signal slots, and 8 owned
//! messages with payloads of at most 256 bytes. A path carries at most 127
//! bytes before its terminating NUL, and one file or stream transfer is at
//! most 64 KiB. These limits can produce [`ErrorKind::Limit`] errors.
//! Native failures, invalid input or state, and task-ownership violations are
//! reported as allocation-free [`Error`] values. Infallible Rust
//! allocation APIs use Rust's allocation-failure path instead; they do not
//! return an SDK [`Error`].
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

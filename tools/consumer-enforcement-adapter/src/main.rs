// SPDX-License-Identifier: MIT OR Apache-2.0
//! Maintainer-only command enforcement for supported consumer qualification.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod backend;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "linux.rs"]
mod backend;

#[cfg(any(target_os = "macos", all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    backend::main();
}

#[cfg(not(any(target_os = "macos", all(target_os = "linux", target_arch = "x86_64"))))]
fn main() {
    eprintln!("consumer enforcement requires a supported macOS or Linux x86-64 host");
    std::process::exit(2);
}

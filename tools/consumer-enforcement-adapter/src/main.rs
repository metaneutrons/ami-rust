// SPDX-License-Identifier: MIT OR Apache-2.0
//! Maintainer-only command enforcement for supported consumer qualification.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod backend;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64")
))]
#[path = "linux.rs"]
mod backend;

#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64")
))]
fn main() {
    backend::main();
}

#[cfg(not(any(
    target_os = "macos",
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64")
)))]
fn main() {
    eprintln!(
        "consumer enforcement requires a supported macOS, Linux x86-64, or Linux AArch64 host"
    );
    std::process::exit(2);
}

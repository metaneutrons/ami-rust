# ami-rust-minimal

Minimal native startup and ABI reference application. It checks selected layout values, scalar calls, callback dispatch, resource counters, and—when built with the `alloc` feature—an allocation cycle. Build without default features for the `minimal-noalloc` variant or with `alloc` for `minimal-alloc`. This package is a reference fixture, not a general command-line application.
## Ordinary Cargo integration boundary

This package is a development candidate for ordinary Cargo binary integration. Its additive build script requires the pinned `x86_64-aros` target-library candidate and exact `aros-native-build = 0.2.0-dev` host helper. The helper remains an in-workspace `publish = false` crate and currently admits macOS AArch64 and Linux x86_64 only. Private package/archive checks and macOS Cargo builds are recorded in [the development evidence](../../docs/evidence/rc2-cargo-reference-packages-development-20261022.json). They do not replace the outstanding three-host runtime qualification; Linux AArch64 host admission is still missing.

# ami-rust-dependencies

Native dependency integration fixture covering Serde derive, allocation-enabled JSON round trips, and Ed25519 verification. The package exists for the retained qualification harness and is not a standalone application. Its native test build enables the `bind.o` hooks.
## Ordinary Cargo integration boundary

This package is a development candidate for ordinary Cargo binary integration. Its additive build script requires the pinned `x86_64-aros` target-library candidate and exact `aros-native-build = 0.2.0-dev` host helper. The helper remains an in-workspace `publish = false` crate and currently admits macOS AArch64 and Linux x86_64 only. Private package/archive checks and macOS Cargo builds are recorded in [the development evidence](../../docs/evidence/rc2-cargo-reference-packages-development-20261022.json). They do not replace the outstanding three-host runtime qualification; Linux AArch64 host admission is still missing.

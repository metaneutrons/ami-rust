# ami-rust-qualification

Native M1 qualification fixture for the retained host harness. Its argument-selected modes exercise ABI callbacks, allocation, files, libraries, ports and messages, diagnostics, fault injection, and cleanup. The test build enables the native `bind.o` hooks; a passing mode is not an overall qualification claim.
## Ordinary Cargo integration boundary

This package is a development candidate for ordinary Cargo binary integration. Its additive build script requires the pinned `x86_64-aros` target-library candidate and exact `aros-native-build = 0.2.0-dev` host helper. The helper remains an in-workspace `publish = false` crate and currently admits macOS AArch64 and Linux x86_64 only. Private package/archive checks and macOS Cargo builds are recorded in [the development evidence](../../docs/evidence/rc2-cargo-reference-packages-development-20261022.json). They do not replace the outstanding three-host runtime qualification; Linux AArch64 host admission is still missing.

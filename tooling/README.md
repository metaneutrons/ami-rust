# Native host tooling — RC1 development

This separate workspace implements the Rust consumer core. It does not join or
change the target SDK workspace. [RC1 #71](https://github.com/metaneutrons/ami-rust/issues/71)
tracks the complete delivery; the [migration plan](../docs/rust-cli-cargo-migration-plan.md)
defines its acceptance criteria.

The first slice implements JSON, file/path and SHA-256 primitives plus help and
version dispatch. It is not an installable replacement for the released CLI.
The bare development binary reports CLI `0.2.0-dev`, references SDK `0.1.0`, and
uses packaging revision `0` to indicate that this build has no package adapter.
These values do not identify an authenticated installed state or publish a new
SDK. Release/package producers must supply their actual new identities later.

## Build and check

From the repository root, with Rust 1.98.1 available:

```sh
cd tooling
cargo fetch --locked
cargo test --workspace --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo run --locked --offline --package ami-rust-cli -- --version
```

`rust-toolchain.toml` selects the host compiler when working in this directory;
it does not change the AROS target compiler or global rustup defaults. CI uses
the same authenticated bootstrap compiler directly. The first fetch is explicit;
the checks and development command then use locked, offline inputs.

One compiled `ami-rust` binary contains the shared core. The frontend test makes
`cargo-ami` a byte-identical regular-file copy and runs it both directly and
through real Cargo, with a fresh Cargo home. Cargo's injected `ami` token is
removed only for the `cargo-ami` executable name. Installation and retained
ownership of these copies remain later RC1 work.

## Capability ledger

`core::frontend::CAPABILITIES` is the single capability declaration for both
frontend names. Its test compares every entry with the normative contract.
Both names call the same parser/dispatcher; there is no intentional frontend
difference. The ledger describes the full source build, not conditional
compilation detection.

| Capability | Both frontends | Remaining delivery |
| --- | --- | --- |
| Help and version | Implemented | Installed package inventory/identity integration remains RC1 |
| Package verification, prepare, project creation, input check | Refused with status 2 | RC1 authenticated lifecycle and retained state |
| SDK-lock verification/build and package project build | Refused with status 2 | RC1 validation/build behavior, then RC2 normal Cargo integration |
| Release verify/install, project lock, uninstall, migration | Refused with status 2 | RC1 trust, ownership, extraction and migration matrix |

Pending commands never fall back to Python or claim success. Passing these
foundation fixtures does not accept RC1 or establish complete public/producer
Python removal.

## Input boundaries

JSON uses the frozen format byte limits and exactly 128 nested containers.
The structural visitor rejects duplicate keys before typed decoding, invalid
UTF-8/BOM, trailing input and non-finite numbers. The reviewed `serde_json`
source is unchanged; its dependency-free `unbounded_depth` feature permits our
own explicit counter, because its default counter rejects container 128.

File reads walk every path component through no-follow directory descriptors,
accept regular files only and enforce byte limits before and during reading.
The final open is nonblocking to reject FIFOs without waiting for a writer.
These primitives do not yet establish installation ownership, secure mutation,
archive extraction or a snapshot against concurrent writes to the same inode.
Their input-format limits impose no AROS application memory or code-size cap.

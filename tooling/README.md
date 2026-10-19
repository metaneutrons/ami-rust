# Native host tooling — RC1 development

This separate workspace implements the Rust consumer core and both frontend
names, `ami-rust` and `cargo-ami`. It does not change the target SDK workspace.
[RC1 #71](https://github.com/metaneutrons/ami-rust/issues/71) owns execution
status; the [migration plan](../docs/rust-cli-cargo-migration-plan.md) owns
acceptance. Implemented development commands are not an accepted replacement
for the published 0.1.0 packages.

## Architecture and implemented commands

`ami-rust-core` owns validation, publisher authentication, acquisition,
transactions, package/state/lock handling, project generation, the compatibility
build recipe, migration and ELF finalisation/audit. The CLI crate dispatches
both names into that core. The Rust `xtask` reuses its validation and composes
the prospective SDK/release-v2 inventories.

`core::frontend::CAPABILITIES` is the single declaration for both frontend names.
Its test checks every entry against the normative contract. Both names share
the parser and dispatcher; no frontend difference is declared. This ledger
covers the full source build, including the actual Cargo plugin dispatch test.

| Capability | Development implementation | Remaining qualification |
| --- | --- | --- |
| Help, version and package verification | Implemented | Exact installed package identities and complete lifecycle |
| Explicit preparation and input check | Implemented | Positive authenticated native package, cold/warm acquisition and failure matrix |
| New project and SDK lock | Implemented | Full both-host package flow and relocation |
| SDK-lock and package-state build | Implemented with the shared compatibility recipe | Five variants in two roots per host and observed offline/no-Python execution |
| Explicit release verification, install and pinned removal | Implemented for native release-v2/SDK-v2 | Exact protected signatures and complete both-host lifecycle |
| Legacy inspection and explicit migration | Implemented; a separate native lock is written | Both-host retained-state, upgrade/removal and replay matrix |

No supported command falls back to a historical Python driver. Historical
executable bytes are inspected as inert migration inputs. The generated
compatibility build still performs final linking in the Rust core after Cargo
produces its static library. Normal Cargo final linking remains RC2.

The bare development binary reports CLI `0.2.0-dev`, references the immutable
SDK 0.1.0 baseline and uses packaging revision `0`. An owned native package
supplies its actual independent CLI/SDK/package identities. Bare version output
is not publisher authentication or an installed-state receipt.

## Build and check

With Rust 1.98.1 available, run from the repository root:

```sh
unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN
cd tooling
cargo fetch --locked
cargo test --workspace --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo run --locked --offline --package ami-rust-cli -- --version
```

`rust-toolchain.toml` selects the host compiler inside this workspace; target
Rust and global rustup defaults remain unchanged. CI uses the same pinned host
bootstrap compiler directly. Initial fetching is explicit; subsequent checks
are locked/offline. `tools/build-native-cli.sh` produces portable optimized
binaries with source/cache prefix maps and a positive/corrupted-copy path scan.

One compiled binary contains the shared core. `cargo-ami` is a byte-identical
regular-file copy. Cargo's injected `ami` argument is removed only when entered
under that name; the integration test exercises real Cargo with a fresh home.

## Native SDK and publisher integration

The [native producer](../docs/rust-cli-migration/native-producer.md) uses the
protected existing SDK workflow and unchanged compiler/C-SDK component inputs.
Its default-off native branch builds both host binaries, composes SDK/release-v2,
reconstructs source-derived materials and launcher bytes on the signers, signs
the complete outer capsule, and exercises native package preparation, project
creation, offline build and retained replay as well as direct installation/removal. Internal Python coordinates this transitional
producer/test flow; its retirement remains RC4.

`ami-rust-xtask native-sdk`, `native-release`, `native-package` and `native-outer`
compose development payloads. `native-outer` first authenticates the inner bundle
and reads its capsule back through the native consumer. `native-outer-finalize`
binds the five assets to checksums; `native-package-verify` authenticates outer
and inner evidence and their binding. Composition/verification does not accept
a milestone or publish an SDK. Existing
0.1.0 assets, receipts, source obligations and evidence remain immutable.

## Contracts and evidence

- [Native package inventory and root discovery](../docs/rust-cli-migration/native-package-v2.md)
- [Explicit verification and SDK-v2 inputs](../docs/rust-cli-migration/native-sdk-v2.md)
- [Receipt-pinned installation and removal](../docs/rust-cli-migration/native-installation.md)
- [Project, build and migration flow](../docs/rust-cli-migration/rc1-native-project-build.md)
- [Process capture and supervision](../docs/rust-cli-migration/rc1-process-capture.md)

Parsing, local inventory consistency, real cryptographic verification, host
execution, no-Python observation and target runtime acceptance are separate
claims. JSON rejects duplicate keys and excessive nesting; descriptor-relative
file operations refuse unsafe links/types; retained receipts require an
external pin. These checks do not snapshot a tree against its owner or replace
publisher authentication. Host archive/work profiles do not impose AROS
application heap or code-size quotas.

The milestone remains open until every RC1 criterion has exact both-host
lifecycle and native-build evidence. A green component test or an unsigned
synthetic installation does not close those gates.

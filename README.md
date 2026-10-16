# ami-rust

ami-rust is a source SDK and a small Rust interface for native PC x86-64 AROS
ABI-v1. Development uses standard rustup and Cargo with a pinned cross-development
SDK and a small installation, verification and linker boundary.

The initial development hosts are macOS Apple Silicon and Linux x86-64. The
supported target profile is the qualified x86-64 ABI-v1 environment; see
[compatibility](docs/compatibility.md) and the [API scope](docs/api.md).
Native AROS-hosted rustc/Cargo, full Rust std and official rustup target
distribution are outside the current release scope.

R1 remains under qualification; no ami-rust SDK release is published. The
[authoritative release plan](docs/m2-r1-plan.md) defines the acceptance gates.
The [release status](docs/release-status.md) distinguishes inherited local
candidate evidence from protected production and consumer verification.

Source CI runs regression fixtures on both development hosts. The manual
[protected SDK producer](docs/hosted-sdk-producer.md) builds, authenticates and
checks candidates on standard GitHub-hosted runners. Its output is qualification
evidence until every release gate passes. Consumer asset distribution remains separate.
The protected Cargo prerequisite workflow retains its separate producer identity.
The [public release replay](docs/public-release-replay.md) checks retrieval and
consumer use after an accepted candidate is published; it does not publish an SDK.
The [production quickstart](docs/quickstart.md) documents explicit user-local
preparation of pinned prerequisites, installation and offline builds, and a
post-uninstall inventory check. This route still requires actual protected
qualification before it can be advertised as a supported release.

The pinned original and source-derived C-SDK prerequisites and corresponding
source live in this repository. Read their conspicuous
[source-availability notice](release/portable-csdk/SOURCE-AVAILABILITY.md),
[dated changes](release/portable-csdk/CHANGES.md) and original licence terms.
First-party ami-rust code is MIT OR Apache-2.0; third-party code retains its own
terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

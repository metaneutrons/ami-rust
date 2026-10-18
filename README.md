# ami-rust

ami-rust is a source SDK and a small Rust interface for native PC x86-64 AROS
ABI-v1. Cross-development uses a pinned Rust toolchain, a narrowly patched Cargo
and small installation, verification and linker helpers. Prerequisites are
provisioned explicitly without replacing global rustup or Cargo installations.

The initial development hosts are macOS Apple Silicon and Linux x86-64. The
documented target profile is native PC x86-64 AROS ABI-v1 under the qualified
QEMU boot profile; physical hardware and other CPU/ABI combinations are outside
this scope. See [compatibility](docs/compatibility.md) and the [API scope](docs/api.md).
Application allocations use public Exec allocation with checked sizes,
alignment, accounting and ownership. The [memory policy](docs/memory-policy.md)
defines this behavior and its qualification requirements; the SDK does not
impose the historical feasibility allocation or heap quotas. Native
AROS-hosted rustc/Cargo, full Rust std and official rustup target distribution
are outside this SDK's scope.

The [authoritative release plan](docs/m2-r1-plan.md) defines the acceptance gates.
The [dated release status](docs/release-status.md) records the current
acceptance state; consult it before using any version as supported. A protected
CI artifact alone does not establish an accepted release; public consumer and
guest replay must also pass.

Source CI runs regression fixtures on both development hosts. The manual
[protected SDK producer](docs/hosted-sdk-producer.md) builds, authenticates and
checks candidates on standard GitHub-hosted runners; its output is qualification
evidence for the selected source and input identities. The dated release status
records the acceptance state.
The protected Cargo prerequisite workflow retains its separate producer identity.
The [public release replay](docs/public-release-replay.md) authenticates all six
release assets before consumer replay on both hosts; it does not publish an SDK
or declare R1 acceptance. The [versioning and staging procedure](docs/release-versioning.md)
requires A1–A7 qualification of the exact merged release-PR commit before
production tag/draft creation, followed by public replay before stable promotion.
The owner-approved [initial-version replacement exception](docs/release-version-exception-20261018.md)
keeps the corrected candidate at `0.1.0`; its exact source and qualification
record distinguish it from the removed failed prerelease.
The [production quickstart](docs/quickstart.md) documents explicit user-local
preparation of pinned prerequisites, installation, offline builds and new-project
generation from a verified SDK source snapshot. Projects retain that snapshot
after SDK uninstall; a separate recheck verifies the retained prerequisites.
Support for a particular version depends on the R1 acceptance and public replay
recorded in the dated release status.

The pinned original and source-derived C-SDK prerequisites and corresponding
source live in this repository. Read their conspicuous
[source-availability notice](release/portable-csdk/SOURCE-AVAILABILITY.md),
[dated changes](release/portable-csdk/CHANGES.md) and original licence terms.
First-party ami-rust code is MIT OR Apache-2.0; third-party code retains its own
terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

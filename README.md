# ami-rust

ami-rust is a source SDK and a small Rust interface for native PC x86-64 AROS
ABI-v1. Cross-development uses a pinned Rust toolchain, a narrowly patched Cargo
and small installation, verification and linker helpers. Prerequisites are
provisioned explicitly without replacing global rustup or Cargo installations.

The initial development hosts are macOS Apple Silicon and Linux x86-64. The
candidate target is the qualified PC x86-64 ABI-v1 QEMU profile; physical
hardware and other CPU/ABI combinations have no support claim. See
[compatibility](docs/compatibility.md) and the [API scope](docs/api.md).
Application allocations depend on available AROS memory, with overflow and
ownership checks. The SDK does not impose the historical feasibility allocation
or heap quotas. The changed allocator requires new native evidence under the
[memory policy](docs/memory-policy.md) before acceptance.
Native AROS-hosted rustc/Cargo, full Rust std and official rustup target
distribution are outside the current release scope.

The [authoritative release plan](docs/m2-r1-plan.md) defines the acceptance gates.
Check the [release status](docs/release-status.md) and the selected release's
acceptance evidence before using a candidate as supported. A protected CI
artifact alone does not establish an accepted release; public consumer and guest
replay must also pass.

Source CI runs regression fixtures on both development hosts. The manual
[protected SDK producer](docs/hosted-sdk-producer.md) builds, authenticates and
checks candidates on standard GitHub-hosted runners. Its output is qualification
evidence until every release gate passes.
The protected Cargo prerequisite workflow retains its separate producer identity.
The [public release replay](docs/public-release-replay.md) authenticates all six
release assets before consumer replay on both hosts; it does not publish an SDK
or declare R1 acceptance. The [versioning and staging procedure](docs/release-versioning.md)
requires A1–A7 qualification of the exact merged release-PR commit before
production tag/draft creation, followed by public replay before stable promotion.
The [production quickstart](docs/quickstart.md) documents explicit user-local
preparation of pinned prerequisites, installation, offline builds and new-project
generation from a verified SDK source snapshot. Projects retain that snapshot
after SDK uninstall; a separate recheck verifies the retained prerequisites.
This route still requires actual protected qualification before it can be
advertised as a supported release.

The pinned original and source-derived C-SDK prerequisites and corresponding
source live in this repository. Read their conspicuous
[source-availability notice](release/portable-csdk/SOURCE-AVAILABILITY.md),
[dated changes](release/portable-csdk/CHANGES.md) and original licence terms.
First-party ami-rust code is MIT OR Apache-2.0; third-party code retains its own
terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

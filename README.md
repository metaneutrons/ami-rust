# ami-rust

ami-rust is a source SDK and a small Rust interface for the PC x86-64 AROS
ABI-v1 target. This repository is a source and review surface. It does not
publish SDK archives or binary releases.

The current compatibility evidence is limited to the documented x86-64 AROS
ABI-v1 environment. It does not establish support for other AROS targets,
Amiga-compatible systems, physical machines, or arbitrary Rust crates. See
the compatibility and API documents before relying on the interface.

The CI workflow runs isolated installer regression fixtures on Linux and macOS.
It does not build or qualify the SDK, run AROS, validate a publisher identity,
or create release artifacts. An offline test signature is not a publisher
signature. No SDK publication is authorized by this repository workflow.

First-party code is available under either the MIT License or Apache License,
Version 2.0. Third-party files retain their own notices and license terms; see
THIRD_PARTY_NOTICES.md and the individual crate notices.

The [release qualification status](docs/release-status.md) records completed installation/licence checks and the still-open protected SDK provenance gate. Source publication does not authorise SDK release assets.

The manual hosted Cargo prerequisite workflow uses a pinned standalone Python
3.12.15 input on both hosts. The runner system Python performs only the initial
verified runtime bootstrap and cleanup. Cargo production and its resource
receipts use the fixed runtime; bootstrap archives and runtime files are
included in managed workspace accounting and explicitly removed before metadata
upload. This is prerequisite qualification, not an SDK release.

# Licensing scope

Copyright (c) 2026 Fabian Schmieder.

The original ami-rust code and documentation are available, at your option,
under either the MIT license in `LICENSE-MIT` or the Apache License, Version 2.0,
in `LICENSE-APACHE` (SPDX: `MIT OR Apache-2.0`). Fabian selected these terms on
2026-10-15. Workspace packages inherit this expression.

This grant does not relicense third-party material, including AROS interface
contracts and derived declarations, retained measurement code, compiler/Cargo
patch context, Rust dependencies, native startup code, or linked C libraries.
Their original notices and applicable licenses prevail. The distribution
inventory and review record distinguish shipped code from separately provisioned
build tools. An unresolved third-party finding blocks release of affected assets.

An own-code license choice is not an assertion that every existing binary or
prerequisite can be redistributed. See `THIRD_PARTY_NOTICES.md` and
`release/licences/review.json` for the candidate's exact boundary.

The translated AROS declarations in `crates/aros-sys/src/lib.rs` retain the AROS
Public License 1.1 for Covered Code, including its modification requirements.
The crate's composite `LICENSE` preserves that text and the additional grants
for original ami-rust contributions. Its package metadata uses `license-file`
instead of claiming that the complete derived file is exclusively dual licensed.

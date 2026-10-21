# Public CLI retirement — 2026-10-21

Fabian replaced the public CLI product with a standard Rust toolchain and crates.
[Migration plan revision 3](../rust-cli-cargo-migration-plan.md) owns the prospective
requirements. This change removes the previous interface; it does not deliver or
accept the replacement toolchain. RC2–RC5 remain open.

## Removed implementation

- Rust `ami-rust`/`cargo-ami` binary crate, parser/dispatcher, CLI process hook and
  standalone frontend builder.
- Python `host/cli.py`, `packaging/cli.py` and `packaging/worker.py`.
- Orphaned Rust preparation/project/migration/application-build backends. Their
  separate post-Cargo build engine is not retained as a compatibility path.
- CLI-package source collection and launcher generation in `packaging/build.py`.
  Its old producer now refuses before filesystem mutation. The former Homebrew
  CLI formula generator is removed and refuses before output mutation as well.
- The five internal `xtask` CLI-payload production commands and their exclusive
  SDK/package/release/outer-payload generation modules.
- Tests exclusively asserting those deleted commands, package generators and
  retired workflow layouts. Original tests/results remain in immutable history.

`host/build.py` retains only the five shared supervision/storage/capacity helpers;
their function bodies are unchanged. Other pinned source files, producer receipts,
CLI-bound native inputs and old payloads have not been rewritten to fit the new
tree. The old native/Cargo producer preflights must reject the changed helper and
workspace lock. New toolchain production needs a new identified recipe and
qualification.

## Retained libraries and historical readers

Archive/JSON/ownership checks, resource/process measurement, ELF validation and
publisher authentication remain reusable libraries. Historical typed package and
receipt readers retain old executable field names and inert fixtures; those fields
are data, not an executable fallback or a promise to ship another CLI. Generic
security/publication-permission fixtures remain library tests. Existing
no-Python observer positives and intentional interpreter counter-controls remain
in source CI. Internal Python retirement is still RC4/RC5 work.

Existing GitHub release assets, tags, package archive state and the qualified
x86-64 ABI-v1/QEMU baseline are unchanged. No protected AROS checkout is edited.

## Product pipeline boundary

The former `sdk-qualify`, `packages`, `publish-packages`, `requalify-packages` and
`public-replay` workflows are manual, read-only refusals. They cannot rebuild,
stage, publish or replay the removed CLI. Existing public downloads/packages stay
available. These refusals are intentional transition blockers, not green SDK
qualification or publication evidence.

Before enabling replacements, RC2 must prove paired-toolchain selection through
rustup, normal Cargo final linking, packaged crate consumers, both supported
hosts/two roots/five variants and the inherited AROS runtime/memory matrix. RC3
then qualifies authenticated toolchain and crate publication plus the actual
APT/Homebrew/direct lifecycle. Do not turn a renamed CLI or an old receipt into
that evidence.

## Development validation

Local remaining-workspace tests pass: 351 core unit tests, 51 internal-task unit
tests and the non-ignored integration/doc tests. Strict Clippy passes for native
macOS and Linux target configuration; the latter is not Linux runtime execution.
The supervised final Rust check takes 49.24 seconds, with conservative combined
child/driver peak RSS 1,251,753,984 bytes and managed workspace 1,038,748,478 bytes.

All 43 retained source-CI Python library suites have passing local evidence:
42 in the combined follow-up and the SDK library suite in a separate serial run.
The combined run retained two resource-fixture failures in that suite; they did
not reproduce serially. No resource policy or threshold was changed to obtain the
pass. Earlier obsolete-interface failures and compiler warnings remain retained.
These are development checks; exact-source hosted CI and replacement release
qualification remain separate gates. Workflow lint passes for all six changed
workflows. CLI-dependent producer-positive assertions were replaced by explicit
current-source refusal; historical signed input bytes remain unchanged.

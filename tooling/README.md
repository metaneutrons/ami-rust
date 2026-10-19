# Native host tooling — RC1 development

This separate workspace implements the Rust consumer core. It does not join or
change the target SDK workspace. [RC1 #71](https://github.com/metaneutrons/ami-rust/issues/71)
tracks the complete delivery; the [migration plan](../docs/rust-cli-cargo-migration-plan.md)
defines its acceptance criteria.

The workspace implements native validation, transactions, publisher verification
and an explicit release-verification command. It is not yet an installable
replacement for the complete released CLI.
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
| Explicit release verification | Implemented for release-v2/SDK-v2 development inputs | Exact signed native candidate and both-host qualification remain open |
| Explicit release installation and pinned removal | Implemented for development native-v2 inputs | Exact signed candidate, both-host lifecycle and no-Python qualification remain open |
| Project lock and migration | Refused with status 2 | RC1 retained state and migration matrix |

Pending commands never fall back to Python or claim success. Passing these
foundation fixtures does not accept RC1 or establish complete public/producer
Python removal.

## Explicit release verification

After building the development binary, `ami-rust verify --bundle PATH --policy
EXTERNAL_POLICY` authenticates the publisher and checks the retained SDK-v2
archive. The byte-identical `cargo-ami` frontend exposes the same command as
`cargo ami verify`. See the [native SDK contract](../docs/rust-cli-migration/native-sdk-v2.md)
for inputs, output scope and remaining qualification. Existing released SDK-v1
archives are not silently reclassified or executed by this native path.

This command is development functionality. The [native installation/removal flow](../docs/rust-cli-migration/native-installation.md)
now shares this verified payload and a single transaction guard. Preparation,
native builds and retained lifecycle commands remain unfinished. Historical signature evidence
and synthetic archive fixtures do not qualify a signed native-v2 release.

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

## Validation slice

The core also parses the closed state-v2 and selection-v2 metadata shapes.
These are untrusted claims: callers must still verify the actual host, roots,
ownership, receipts and inventories. Lexical path checks do not establish
filesystem identity or make a state ready. No legacy executable driver runs.

Strict gzip/XZ decoding checks compressed, decoded and XZ decoder-memory limits
supplied by the input profile. It refuses corruption, truncation, concatenated
streams and every suffix (including otherwise-valid XZ padding). A failing
operation may have written bytes to its sink; use unpublished staging and discard
it on any error. This module does not yet extract TAR files or install packages.

The in-memory ELF auditor returns the historical complete report, including
relocations, symbols, section hashes and measurements. Reference-size thresholds
remain observations, not AROS application limits. It refuses multiple symbol
tables and overlapping file-backed sections before decoding symbol names. Names
borrow the input rather than copying potentially overlapping string suffixes.
Malformed-input diagnostics have fixed size. Untrusted public integration must
supply input, work and report-output resource supervision: borrowed names avoid
storage amplification but do not eliminate repeated suffix scans or large reports.

[Local validation and full native-report comparison](../docs/rust-cli-migration/evidence/rc1-validation-local-20261019/result.json)
cover this slice only. Four retained native outputs yield full reports equal to
the frozen Python oracle; a deliberately malformed overlapping-section fixture
is rejected more strictly under the ELF gABI. Original and failed evidence is
retained. Neither these fixtures nor foundation CI accepts RC1-A1–A4; the public
commands remain pending until their complete lifecycle is implemented.

## Filesystem and archive verification slice

The project-lock-v2 parser preserves relative SDK/component roots for resolution
against the lock's parent. It checks the closed schema, digest shapes and the
frozen 1 MiB JSON bound; it does not resolve paths, authenticate a receipt or
execute a legacy driver.

Directory enumeration and complete component verification retain no-follow
root handles. They verify every declared regular file, exact symlink bytes,
complete file/link membership and in-root link resolution. Optional inventory
modes are checked when present. Unlisted empty real directories remain allowed,
as in the component reference implementation. Caller-selected tree-entry and
link-work limits apply to host verification; shared writers are not snapshotted.

The publisher SDK TAR verifier is a separate profile from generic prerequisite
archives. It checks the complete decoded archive and authenticated file inventory
before returning borrowed file contents, without any extraction writes. Its
existing 16 MiB/1,000-file bounds apply to the small publisher SDK payload, not
to compiler/component archives or AROS applications. Filesystem staging,
ownership, exclusive publication, authentication and rollback remain subsequent
consumer integration work.

[Local filesystem/archive evidence](../docs/rust-cli-migration/evidence/rc1-filesystem-local-20261019/result.json)
records 73 core cases plus the real Cargo/frontend case. The pinned historical
Python 3.12.15 oracle agrees on 36 publisher archive cases (including all 94
published SDK files) and 14 isolated inventory cases. All six retained macOS
component inventories also match, with 12,544 regular files and 17 links.
These are read-only compatibility checks. Both-host candidate CI and complete
RC1 lifecycle/native qualification remain separate requirements.

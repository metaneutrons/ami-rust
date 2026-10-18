# Repository working memory

## Rust host tooling and Python retirement

Owner decision, 2026-10-18: plan the public ami-rust CLI migration to Rust and
closer Cargo integration. Remove Python from all consumer paths first; Python
may remain temporarily in internal tests/release scripts only. The medium-term
goal is complete retirement from active project tooling, including tests,
qualification, component production and releases. Preserve historical releases,
source obligations and evidence. The authoritative proposal and acceptance
criteria are in `docs/rust-cli-cargo-migration-plan.md`. This is planning only;
implementation is not yet authorised.

## Portability patches

Owner decision, 2026-10-16: small, maintained patches are permitted when needed
to keep ami-rust packages portable and buildable on every supported platform.
Routine patches within the authorised work do not require another permission
request merely because they modify an upstream input in an owned checkout.

- Keep patches narrow, versioned and suitable for upstream submission. Record
  the reason, original source revision, patch digest and resulting component
  identity. Preserve original notices and licence terms.
- Patch source, generators and build recipes. Generate relative provenance
  comments and relocatable `pkg-config` files; use compiler prefix mapping for
  build-path-dependent diagnostics. Preserve compiler metadata and binary
  archive integrity instead of rewriting finished binaries to conceal paths.
- Apply patches in ami-rust-owned checkouts or staging trees. Preserve pinned
  originals and the qualified boot/ABI baseline; keep protected AROS-NX and
  aros-tools checkouts unchanged. Give derived SDK inputs their own identities.
- Verify affected behaviour, relocation and builds on all supported hosts.
  The initial supported hosts are macOS Apple Silicon and Linux x86-64; the
  initial target is native PC x86-64 AROS ABI-v1. Broader platform support
  requires its own evidence.
- Requalify affected release criteria before shipping changed inputs. Retain
  failed results and the original evidence. Remove downstream patches when an
  upstream fix has passed compatibility qualification.

These patches serve the independent ami-rust SDK release. nxpk remains outside
the current scope.
## Local working storage

Owner decision, 2026-10-16: use actual free disk space with 32 GiB operating
headroom after the estimated additional peak of a large operation. Ordinary
source, documentation and licence copies have no per-file/subdirectory quota;
local evidence and backups have no fixed cumulative archive quota. Use
`qualification/hosted_capacity.py` at session start and before large operations;
do not revive the historical reservation
ledger. Preserve original evidence, failures and backup integrity. See
`docs/local-storage-policy.md`. Hosted CI limits, bounded untrusted-input parsing
and AROS runtime/ABI acceptance criteria remain separate and unchanged.


## Practical memory policy

Owner decision, 2026-10-16: use realistic memory requirements. Do not turn
feasibility/reference-program budgets into general SDK application quotas.
Remove the 1 MiB allocation / 16 MiB heap policy and generic ELF size rejection;
use public Exec allocation, representability/overflow checks and actual OOM.
Keep full memory/ownership measurement, leak detection and safe cleanup. The
512 MiB QEMU baseline remains a repeatable test profile. Historical evidence is
immutable; changed native code requires new qualification. See
`docs/memory-policy.md` for exact prospective acceptance and CI separation.

Resource-policy clarification, 2026-10-16: historical specifications and sealed
input JSON files can still contain old heap/code-size quotas. They do not
override the current memory policy. Treat measured peak use and the supported
machine profile as requirements; investigate growth instead of inventing new
application ceilings. Keep checks proportional to the operation. Changing
resource-policy bytes bound to producer receipts requires a new input identity,
not editing old receipts or silently breaking a live qualification run.

## Initial release version exception

Owner decision, 2026-10-18: the corrected initial SDK may still release as
`0.1.0` despite the failed public prerelease. The proposed `0.1.1` migration
is withdrawn. Fabian subsequently requested deleting the old public candidate
and tag; this was completed and the original tag protection restored. No public
archive release is required. Keep already retained local historical evidence;
bind the corrected candidate to fresh source, checksums and provenance. All R1
criteria remain required. See `docs/release-version-exception-20261018.md`.

# Repository working memory

## Local development before protected qualification

Owner decision, 2026-10-23: reproduce and fix affected build paths locally before
relaunching an expensive CI matrix. Use native macOS, Linux ARM64 in an isolated
VM/container and an available native Linux x86-64 host. Run complete locked,
offline dependency resolution and the actual affected build, then the shared
application qualification path. Preserve the independent protected CI gates.
Machine names, VM/container configuration and local cache locations belong in
operator configuration/evidence, not this generic repository workflow.

## Rust host tooling and Python retirement

Owner decision, 2026-10-18: plan the public ami-rust CLI migration to Rust and
closer Cargo integration. Remove Python from all consumer paths first; Python
may remain temporarily in internal tests/release scripts only. The medium-term
goal is complete retirement from active project tooling, including tests,
qualification, component production and releases. Preserve historical releases,
source obligations and evidence. The authoritative proposal and acceptance
criteria are in `docs/rust-cli-cargo-migration-plan.md`. Fabian subsequently
authorised tracking and execution in milestone dependency order on 2026-10-18.
Keep unmet acceptance gates open; no release is accepted merely by starting work.

## Standard toolchain and crates; no public CLI

Owner decision, 2026-10-21: do not build or retain a public `ami-rust` CLI or
`cargo-ami` plugin. Use rustup for selecting versioned toolchains and normal Cargo
for application builds. Deliver AROS/Amiga libraries and necessary focused tools
as crates. Remove active Python/Rust CLI entrypoints, dispatchers and launchers;
reuse shared libraries only for genuine crate/internal-task needs. Do not disguise
the retired CLI as a Cargo executable or add a new general SDK manager.

Direct/APT/Homebrew deliver authenticated toolchain components; opt-in per-user
rustup linking on the existing supported hosts is core scope and does not wait
for AUR. Official upstream rustup target distribution remains separate. Preserve
old releases, tags and evidence; no Python fallback or automatic rewrite of user
projects. The authoritative migration plan revision 4 retains full RC2–RC5 build,
lifecycle, integrity, native runtime/memory and Python-retirement gates.

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

## Native CI evidence retention

Owner decision, 2026-10-21: retain up to 64 MiB per native consumer host
artifact, with 1 MiB reserved for cleanup and ZIP framing. The full native
workflow reserves 448 MiB; the prospective shared Actions artifact pool is
2,048 MiB under `release/ci-artifact-policy.json`. The 2026-10-22 inventory
measured 670,354,805 retained bytes. Another 384 MiB for three bare-target
library producer artifacts plus the 448 MiB native consumer DAG leaves
604,713,611 bytes of headroom; the successful Cargo prerequisites stay retained.
`release/ci-artifact-policy.json` owns current retention independently of the
sealed build-resource policy and its historical retention field. These
are evidence storage limits, independent of command RAM/log/workspace/time
budgets, signed SDK input limits and the AROS baseline. Do not introduce a new
archive format solely to fit the former 32 MiB consumer retention limit.

Owner clarification, 2026-10-21: future measured evidence growth may use a
larger retention limit with reasonable headroom without asking the owner
again. The current qualified campaign remains pinned to its existing 64 MiB
policy. Change future source-controlled policy and qualify affected retention
behavior; never rewrite sealed inputs or historical receipts. Current measured
consumer artifacts are about 29 MiB on macOS and 37.5 MiB on Linux, unpacked.

## Host expansion and native AROS roadmap

Owner decision, 2026-10-21: add Linux ARM64 as a cross-development host alongside
macOS Apple Silicon and Linux x86-64 for the next RC2–RC5 delivery. Host binaries,
APT architecture and target architecture are separate identities. Keep the
`aros-<version>` rustup name portable across hosts; the project is ami-rust.
Original two-host release evidence remains immutable and cannot qualify ARM64.

The longer-term outcome is complete native Rust/Cargo/rustup on both AROS
x86-64 and AArch64, including native application builds and authenticated
installation/update/recovery. It requires separately qualified AArch64 target,
AROS `std`/OS support, native compiler/Cargo and rustup/distribution work. It is
not established by a rustup alias on macOS/Linux or by copying Linux ARM64
binaries onto AROS. See `docs/platform-roadmap.md`. Do not add a public ami-rust
CLI, alter the current ABI-v1/QEMU baseline, or edit protected AROS checkouts.

Prospective evidence retention, 2026-10-24: `release/ci-artifact-policy.json`
now reserves a 4,096 MiB shared pool for the complete remaining Cargo,
bare-target-library and native-consumer chain. The first Cargo run showed that
a later matrix host sees earlier uploads while conservatively reserving the
whole producer matrix again. Keep the existing 64 MiB consumer and 128 MiB
producer limits and all command budgets. The native Cargo workflow accepts a
host selection so an accepted protected component from another host can be
retained and reused; every reused artifact still needs its own provenance and
input verification. Historical receipts and the qualified AROS baseline stay
immutable.

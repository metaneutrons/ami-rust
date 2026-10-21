# Experimental RC2 Cargo storage split

This maintained source patch implements the storage part of the
[RC2 implementation contract](../../docs/rust-cli-migration/rc2-implementation-contract.md).
The [migration plan](../../docs/rust-cli-cargo-migration-plan.md) owns acceptance;
[issue #72](https://github.com/metaneutrons/ami-rust/issues/72) owns execution.
It is an experimental component, not a selected SDK input or accepted RC2 build.
Existing producers, signed inputs, receipts and released Cargo binaries continue
to use their original identities.

Apply `cargo-storage.patch` after the original
`host/cargo-repro/cargo-metadata.patch` to upstream Cargo commit
`3efb1f477e99b42974b982d939fd100303cdf7db`. `source.json` binds both patch digests
and the experimental effective source. Preserve upstream licences/notices.
There are no dependency or lockfile changes.

## Behavior

An explicit `AMI_RUST_CARGO_STORAGE_ROOT` selects the existing canonical cache
directory on supported Unix hosts. It must be absolute, owned by the effective
user, and not writable by group or others; an owned `0755` directory is valid.
Read OS paths without converting them to TOML or Unicode. Invalid roots refuse
before workspace/storage work; the patch does not create the selected root.

Registry/Git data, package-cache locks, the SQLite global-cache database/GC,
cache templates and enabled analysis logs follow the selected store. Related
fingerprint, workspace-search and fix protections follow that same boundary.
Normal `HOME`/`CARGO_HOME` discovery continues to select configuration,
credentials and executable lookup; unrelated installation semantics remain
unchanged. The selector absent retains stock behavior. This is a local storage
split, not authenticated SDK selection or a sandbox for project/provider code.

Use Cargo's resolved raw `[env]` table before child-env filtering. A selector
resolving to the identical OS path is nonconflicting; a different value refuses
even with `force = false`. Recheck after configuration merge and on context
continuation. Best-effort completion retains Cargo's existing UI behavior.
The shared activation layer must still validate association/disjointness and
the remaining effective compiler/target/output/source inputs.

## Current development evidence

The [bounded proof](../../docs/rust-cli-migration/evidence/rc2-cargo-storage-development-20261021.json)
binds a real macOS build and synthetic host-only comparisons against the exact
RC1 packaged Cargo. Eight path/template units pass; 38 actual runtime commands exercise
30 checks, including 14 expected refusals. Original-home configuration,
extensionless project configuration, relative path origins, CLI precedence,
Git cache/locks/database routing and a cached executable pass their stated
comparisons. A fresh patch replay reproduces all 2,928 inventoried source files.
The first compiler type-inference failure and its executed source/driver/logs
are retained separately. Independent source review then identified a non-UTF-8
build-directory conversion failure. The fix keeps selected template values as
literal OS strings through Cargo's own grammar/origin resolver; selector-absent
resolution remains unchanged. The final source passes a fresh-target offline
Cargo build, eight units and the stated actual template/config/storage cases.
The predecessor incremental build/runtime proof remains retained separately.

These results do not qualify Linux, registry/provider authentication, nested
or concurrent Cargo, failure/retry/interruption, enabled analysis logs, full
selector-absent behavior, activation, final AROS linking or runtime/memory.
Both-host component equivalence and producer closure must pass before selecting
this new Cargo identity. Existing RC1 replay and the target compiler, C-SDK,
ABI-v1 and QEMU baseline remain unchanged.

## Reusable host component qualification

`ami-rust-xtask cargo-storage-probe` is an internal Rust maintainer operation.
It compares explicit original/derived Cargo binaries with local synthetic
inputs, records actual command status and raw streams, and checks the exact
host-specific outcomes and complete command/expected-exit inventory in
`runtime-checks.json`. It requires explicit
`--control`, `--derived`, `--rustc`, `--rustdoc`, `--work`, and `--output` paths;
work/output must be fresh and separate from the selected tools.

The [Rust development proof](../../docs/rust-cli-migration/evidence/rc2-cargo-storage-rust-fixtures-20261021.json)
records the macOS run: 43 commands and 37 checks, including an actual compiler
failure with empty fresh artifact export, a successful retry, an unchanged
previous executable, and restored project inputs. The original failed fixture
and its missing unstable-option switch remain recorded separately. Linux adds
raw non-UTF-8 cache/template cases. The first protected run passed macOS but
failed Linux at an added successful-compilation expectation for invalid UTF-8
compiler paths. The unchanged pinned compiler and original Cargo reproduce that
limitation. The corrected probe preserves byte-routing checks and explicitly
characterizes the same compiler failure against both controls; it does not claim
successful compilation using invalid UTF-8 paths. The corrected Linux probe
remains unqualified until executed on Linux. Registry resolution uses an empty local directory source; only the
synthetic file-Git input is fetched. A registry-dependency counter must fail
against that source. This is not a general network sandbox.

The manual **RC2 Cargo storage component** workflow runs only on protected
`main`, using standard Linux x86-64 and macOS ARM runners. It first produces
an original-source control with unchanged pins, derives Cargo with the owned
storage patch, verifies all 2,928 regular source files and unchanged original
symlink targets, and builds the derived component offline. A fresh control is
not claimed byte-identical to the older RC1 binary. The coordinator checks
the Rust receipt, complete named outcomes, the exact command inventory and
expected exits, every raw stream and selected tool identity before reporting
component success. Truncated or invented command lists refuse even if all
reported outcome rows claim success.

This workflow uploads bounded reports/source snapshots/logs, never Cargo or
SDK packages. Each host reserves 32 MiB including cleanup/framing. Its
90-minute component campaign has 15 minutes of job setup/cleanup headroom.
The 4 GiB aggregate observed RSS, 12 GiB combined workspace and 16 MiB logs
remain separate limits. Cleanup validates all ownership paths and a finalized
receipt before deleting work. Abrupt termination without that receipt refuses
retirement; it cannot produce an accepted component result. SIGTERM/SIGINT
cancellation is deferred through guarded process cleanup, including a signal
during detached process creation. Four isolated cancellation controls retain
failed receipts, leave no live child groups and permit owned cleanup.

The temporary Python coordinator is internal release infrastructure and remains
in the RC4 retirement scope. Both-host component qualification, activation,
providers, nested/concurrent Cargo, complete AROS builds and runtime/memory
criteria are still required before RC2 acceptance or a changed SDK release.

## Extended fixture development

The [extended development record](../../docs/rust-cli-migration/evidence/rc2-storage-extended-development-20261021.json)
binds one exact-source macOS suite: 140 actual commands and 181 named checks,
plus 38 receipt/raw-data positive and corrupted-copy controls. Pinned Rust build,
11 storage units and strict all-target Clippy pass; Linux configuration compiles
and lints, but no expanded Linux runtime is claimed.

| Internal maintainer operation | Commands | Checks | Scope |
| --- | ---: | ---: | --- |
| `cargo-storage-probe` | 43 | 37 | Existing config, templates, storage, expected refusals and export retry |
| `cargo-storage-lifecycle-probe` | 24 | 37 | Actual intermediates, executable, enabled/disabled analysis and sessions |
| `cargo-storage-registry-probe` | 26 | 33 | Synthetic sparse registry, external Get(Read), original credential lookup and refusals |
| `cargo-storage-nested-probe` | 24 | 32 | Literal relative homes, distinct config, nested fetch/build and wrong-token retry |
| `cargo-storage-concurrent-gc-probe` | 9 | 9 | Two live same-store readers and actual expired-index deletion/fresh preservation |
| `cargo-storage-git-helper-probe` | 14 | 33 | libgit2 helper lookup, matching protected retry and 401/no-helper refusal |

The lifecycle operation retains all four bounded original JSONL files under its
output, with byte/digest/session joins and strict object-record validation. The
readback hashes and parses one bounded read; linked or changed runtime roots
refuse. The selected-home credential fixtures use synthetic values only and
preserve original configuration. The maintainer `--cargo-plugin` and
`--rc2-git-credential` entries implement only those synthetic protocols.

The Git lock seed uses a private local-file URL rewrite. The helper accepts the
pinned git2 EOF wire form; a checked loopback-only `localhost` URL supplies its
required domain host/port field. A numeric URL cannot establish that helper
request because the pinned binding omits its host. No real credential store,
external service or successful authenticated smart-HTTP clone is claimed.

The coordinator invokes all six operations with separate fresh work/output
roots and exact checked-in command/exit/outcome contracts. This source is not a
fresh two-host protected result or a selected SDK component. GC during active
readers, concurrent fetch, GC control/absent comparisons, full bounded
selector-absent parity, activation and complete AROS qualification remain open.

## Compiler-bound paths

The pinned host Rust 1.98.1 accepts Unicode and spaces but panics when a compiler
argument contains invalid UTF-8 bytes. This also occurs with the original Cargo
when `CARGO_TARGET_DIR` supplies that path; original Cargo rejects invalid UTF-8
CLI arguments earlier. Cargo storage discovery and local fetch may preserve raw
OS path bytes without establishing compiler support for those paths.

Keep the failed protected run and original controls. The Linux probe checks the
specific unchanged compiler panic, byte-preserving template routing and original
home preservation. Its expected failure is a compatibility characterization,
never a successful compilation claim. Normal compilation remains required. The
RC2 activation/compiler roles must diagnose unsupported compiler-bound paths
before native writes; that guard and full RC2 qualification remain unfinished.
The target Rust, C-SDK and ABI-v1/QEMU baseline are unchanged.

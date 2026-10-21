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

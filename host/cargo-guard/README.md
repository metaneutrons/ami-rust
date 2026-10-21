# Experimental RC2 Cargo input guard

This maintained patch implements Cargo-owned early input export and callback
hooks for the [RC2 implementation contract](../../docs/rust-cli-migration/rc2-implementation-contract.md).
[Issue #72](https://github.com/metaneutrons/ami-rust/issues/72) owns execution;
the [migration plan](../../docs/rust-cli-cargo-migration-plan.md) owns acceptance.
This is an experimental source component. Existing producers, SDK pins and
receipts do not select it.

Apply, in order, `host/cargo-repro/cargo-metadata.patch`,
`host/cargo-storage/cargo-storage.patch` and this directory's `cargo-guard.patch`
to upstream Cargo `3efb1f477e99b42974b982d939fd100303cdf7db`.
`source.json` records the three patch identities, changed files and resulting
2,929-file source identity. Dependencies, lockfile and upstream notices remain
unchanged. The public patch replays against a fresh archive of the pinned tree;
all regular files and 121 symlink targets match the built development source.

## Behavior and trust boundary

The private `AMI_RUST_CARGO_GUARD` and `AMI_RUST_CARGO_OVERLAY` selectors choose
an owned executable callback and an owned regular generated config file.
Both must be present; `CARGO_CACHE_RUSTC_INFO=0` is required. Selectors absent
retain the normal Cargo route. These selectors establish no publisher trust.
The forthcoming native activation role must authenticate the callback, selected
Cargo engine, overlay and local invocation before using this hook.

Cargo resolves normal configuration with its existing parser, include rules,
precedence and path origins. Before derived build/tool caches are populated,
it sends a bounded JSON record to the callback's private stdin. A refusal stops
before the generated configuration can shadow conflicting caller inputs.
Approval merges the self-contained overlay once. An overlay already loaded by
user config, an include or a hardlink alias refuses. Ordinary user includes keep
their existing behavior; a generated overlay cannot include other config files.

Records include compiler/wrapper/build controls, raw target/host/unstable
configuration, typed target flags/linkers, each array item's origin, relevant
process and configured child environment, and source replacement/directory
origins obtained through Cargo's own source-config types. This avoids a second
TOML resolver. No source is loaded or fetched to construct that source record.

A second callback runs before each supported `metadata`, `check` or `build`,
including `metadata --no-deps` and unchanged builds. It records the actual
workspace, output paths and command selection, including package, feature and
target selectors. Unsupported commands and bypass routes refuse. The hook does
not itself decide SDK policy, compile target C, link AROS or authenticate a role.

Each record is limited to 1 MiB. Callback delivery has a 30-second timeout,
nonblocking writes, and child kill/reap on failure. Callback stdout/stderr are
discarded; configuration records are not persisted or printed by the patch.
All identity checks here are local checks, not a sandbox against the same user.

## Development evidence and remaining work

The [development record](../../docs/rust-cli-migration/evidence/rc2-cargo-guard-development-20261021.json)
binds the exact patch, macOS binary, source, independent delta reviews and
fresh patch replay. A real offline release build succeeds with the pinned host
compiler; eight existing storage/path units pass. The synthetic native callback
fixture passes 46 checks over 43 actual commands, covering raw origins and
one-time overlay merge, expected refusals, target selectors, cold/warm host
builds and checks, preflight on cache hits, a real callback timeout and oversized
record refusal. Earlier failures and raw local reports remain retained.

This proves local callback plumbing only. Native activation authentication and
policy, portable project/local activation/invocation records, target/cfg graph
validation, compiler/build-script/linker roles, both-host fresh production,
relocation, no-Python observation and the complete AROS runtime/memory matrix
remain required. No RC2 acceptance or SDK publication is implied.

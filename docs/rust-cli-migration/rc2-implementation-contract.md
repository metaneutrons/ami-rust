# RC2 implementation contract

Date: 2026-10-21. Design for implementation; no RC2 acceptance claim.

The [revision-2 migration plan](../rust-cli-cargo-migration-plan.md#rc2--cargo-owns-the-complete-application-build)
owns RC2-A1–A4. [Issue #72](https://github.com/metaneutrons/ami-rust/issues/72)
owns execution state. This document consolidates the reviewed activation and
configuration/storage decisions; it neither changes those criteria nor treats
an implementation design as a qualification result.

RC1 was accepted through [PR #117](https://github.com/metaneutrons/ami-rust/pull/117),
merged at `be1fb88f44ab6997ffa45a832b2331fc819d435a`.
The [RC1 acceptance record](rc1-acceptance.md) remains bound to its original
qualified tools and source. RC2 uses a separate branch and new derived identities.

## One Cargo engine, shared native roles

After explicit preparation, activation creates a fresh immutable generation
under `<project>/.ami-rust/activations/<generation-id>/`. It reports the exact
generation, record digest and `bin/cargo` entry. No global Cargo shim, rustup
default change, shell edit or mutable current-generation alias is required.

The generation contains copies of the retained native CLI, dispatching through
one Rust core:

| Entry | Responsibility |
| --- | --- |
| `bin/cargo` | Per-command preflight, selected engine supervision, input recheck and read-only result validation |
| `bin/ami-rust-rustc` | Validate the actual compiler, host/target context and effective compiler/linker arguments before execution |
| `bin/ami-rust-build-script` | Produce the frozen target C/startup inputs and Cargo directives when Cargo executes the application build script |
| `bin/ami-rust-link` | Collect, strip, compact and audit the executable during Cargo's link operation |

Role dispatch requires the actual executable placement, owner and digest to
match the adjacent activation inventory and retained package receipt. A caller's
`argv[0]` or environment value alone cannot establish that identity. The Cargo
engine is the authenticated component's absolute executable, distinct from
every role entry; no ambient Cargo fallback or recursive launcher lookup.
Declare the roles and activation options in the shared capability contract
before exposing them through either frontend.

Both public build frontends call this same launch core. Cargo retains dependency
resolution, feature/package selection, compilation, fingerprints and artifact
export, including normal `--locked`/`--offline` decisions and diagnostics. Do not
regenerate a lock silently or acquire missing inputs during an offline build.
The launcher does not compile C, manually link or finish an executable
after Cargo exits. It may inspect finished outputs read-only and record them.
The retained RC1 engine remains available only through its unchanged old state;
the new facade does not hide a second legacy build engine.

The documented selected-Cargo route covers `metadata`, `check` and `build`,
including normal development and release builds. It does not claim target
`test`, `run`, rust-analyzer or arbitrary Cargo subcommands. A selected entry's
preflight runs even for `metadata --no-deps`, compiler-query cache hits and
unchanged builds: those paths may invoke no compiler or linker. This is the
plan's local trust model, not a sandbox against deliberate tool replacement.

## Portable project, explicit local activation

A new portable `ami-rust-cargo-project-v1` marker describes the shared SDK
generation, native build/target contract, relative workspace manifest and
application-selection policy. Host receipts and absolute component paths belong
in the separate local `ami-rust-cargo-activation-v1` record. Existing host-bound
SelectionV2 and project-lock records are never reinterpreted as portable records.

The activation binds owner UID, canonical project/state/retained-package roots,
marker digest, installation/selection digests, exact helper and component
identities, generated configuration, role inventory, target/sysroot/vendor and
host-tool identities. Publish a complete generation atomically from private
sibling staging; refuse an existing destination. Mutable targets and invocation
records live outside that immutable inventory, with checked ownership and an
activation-associated advisory lock.

Relocation requires explicit creation of a new local generation; preserve and
refuse stale generations rather than silently redirecting them. Frontends select
exactly one generation matching the explicit project/state/marker association.
An explicit selector resolves coexisting matches; directory order or newest
timestamp never chooses the state. An edited marker requires a new activation.
Ordinary application source, manifest, feature or lock changes are evaluated
per invocation and do not by themselves require another activation.

## Cargo build-script and invocation context

A portable ordinary `build.rs` calls the authenticated build-script role through
the runtime `AMI_RUST_BUILD_HELPER` route and forwards failure. The role verifies
Cargo's `HOST`, `TARGET`, application association, `CARGO_MANIFEST_DIR` and owned
`OUT_DIR` before producing target objects. Dependency scripts and proc macros
remain host code. Reuse the shared native recipe, including testing-only bridge
objects; do not copy its implementation into generated project code.

The launcher creates a fresh invocation record and supplies its absolute path
through `AMI_RUST_BUILD_INVOCATION`. The record binds the activation digest,
project/marker, current graph/lock, selected application set, target/host, recipe,
nonce and running stage. Helpers require the exact current association inside
the checked private invocation area; missing, foreign, escaping, stale or
completed records refuse before native writes. This local record is not
publisher trust or a same-user security secret.

Refuse conflicting caller values for `AMI_RUST_BUILD_HELPER` and
`AMI_RUST_BUILD_INVOCATION` before mutation; supply the checked invocation's own
values. Runtime routing information alone never substitutes for identity checks.

Use ordinary rerun declarations for stable activation/recipe and real C/header
inputs. Do not emit `rerun-if-env-changed=AMI_RUST_BUILD_INVOCATION` or compile
that changing path with `env!`: a new invocation alone must not invalidate the
build-script cache. When a script is cached, no helper execution is claimed;
command preflight and read-only final-output checks still apply.

New-project generation supplies the composition hook. Migration stages a
separate project/selection and reports the changed executable contract. Preserve
an existing developer `build.rs`; incompatible composition requires an explicit
reviewed edit, not automatic replacement. Preserve old projects and RC1 replay.

## Preserve Cargo configuration; separate mutable storage

Keep Cargo's own configuration resolver and original path origins. A private
`CARGO_HOME` plus copied config, symlink or include bridge does not preserve all
legacy filenames, relative includes, literal paths, precedence and ancestor
de-duplication. Do not create a second TOML/configuration resolver in ami-rust.

Derive a narrow additional patch to the existing qualified Cargo source
`3efb1f477e99b42974b982d939fd100303cdf7db`, retaining its reproducibility patch.
The proposed downstream selector `AMI_RUST_CARGO_STORAGE_ROOT` selects an
absolute private mutable-storage root while normal `HOME`/`CARGO_HOME` discovery
continues to select configuration and credentials. With the selector absent,
retain original behavior. A relative `CARGO_HOME` remains inherited and resolves
again against each nested Cargo invocation's cwd; do not normalize it silently.

The storage split must cover registry/git sources and downloads, package-cache
locks, the global-cache database and GC, managed temporary data and enabled
analysis logs. Adjust cache-root invariants, fingerprint exclusions, workspace
discovery boundaries and cache-home output templates consistently. Preserve
configuration/credential origins, executable lookup and unrelated install
semantics. Merely moving registry sources is incomplete.

Generated activation configuration is a separate file, never an overwrite of
developer `.cargo/config` or `.cargo/config.toml`. Preserve normal nonconflicting
user/ancestor/project/CLI configuration. Before implementing effective-input
validation, finish the pinned-source mapping of reserved keys, their environment
counterparts and CLI precedence through Cargo's resolver. It must include
compiler/wrappers, target/sysroot/linker/rustflags, target/build/export paths,
vendor/source replacement and the activation/helper/storage selectors. Validate
encoded rustflags, recursive includes and `[env]` selector conflicts; appending
generated `--config` alone does not establish absence of a conflict. Do not
discard all user configuration to make the guard pass.

The new Cargo is a separately identified derived component, requiring patch
hashes, effective source identity, both host binaries and producer closure.
Old SDK pins and receipts are immutable. Target Rust, C-SDK and the qualified
ABI-v1/QEMU baseline stay unchanged. Storage/configuration equivalence must pass
before the replacement is accepted as RC2 tooling.

Supported resolution/build operations may request credential `Get(Read)`;
Cargo has no `Refresh` action. Preserve lookup in original configuration and
credentials without copies or token logging. External providers, OS stores,
Git helpers and SSH agents retain their own persistence boundaries. The storage
selector does not sandbox them. Test only disposable synthetic credentials and
stores; Cargo-managed original configuration/cache paths must remain unchanged
in supported lifecycle fixtures. Direct Login/Logout are out-of-surface controls.

## Artifact discovery and success

Resolve current applications through Cargo metadata and normal command selection.
Do not freeze starter manifest hashes or infer success from a guessed filename.
Reject export basename collisions before build. The pinned source supports
`build -Z unstable-options --artifact-dir <fresh-empty-directory>` for fresh and
cached final outputs. The [bounded macOS host-fixture proof](evidence/rc2-cargo-export-design-20261021.json)
confirms that the exact RC1 packaged Cargo exports fresh/cached selected binaries,
selects multiple binaries and leaves an empty export for a failed build. It does
not establish Linux, AROS or full RC2 behavior. Metadata/check have no final
executable export claim.

Each invocation owns a fresh export directory. Require the exact resolved native
outputs and audit them read-only: Linux exports may hard-link Cargo's cache.
Never mutate exports to finish them. Failed checks, engine failure, cancellation
or changed inputs yield no success receipt for that invocation; an old successful
receipt or cached output cannot provide its success. Preserve prior user outputs
and retain honest failure/cleanup evidence.

## Delivery order and evidence

1. Use the versioned pinned-Cargo host export proof and its failure control as
   bounded design evidence. Qualify the selected artifact route in the actual
   both-host AROS build integration; preserve the proof's explicit limitations.
2. Complete and review the effective-input/storage patch mapping, then implement
   and qualify the derived Cargo without changing existing accepted states.
3. Implement typed project/activation/invocation records, shared role dispatch,
   build-script/linker integration and the thin compatibility facade.
4. Run the full RC2 matrix: both hosts, two roots, five variants, spaces/relocation,
   metadata/check/build, normal configuration/credential fixtures, features,
   packages, proc macros, cache/invalidation, concurrent supported commands and
   their private cache/database/lock effects, failure/retry/interruption and
   actual selected tool observations. Keep host metadata/Serde qualification.
5. Compare native output with R1, identify and independently review intentional
   differences, then run the inherited full AROS runtime/memory matrix on the
   unchanged baseline. Do not normalize `.rlib` metadata or change golden hashes
   as a substitute for evidence.

Per-command resource, observation and no-Python requirements remain inherited.
Local evidence/storage headroom and CI artifact retention are separate policies.
RC3 publication/channel gates and RC4/RC5 retirement/rollback requirements remain
open. This contract publishes no SDK and accepts no implementation milestone.

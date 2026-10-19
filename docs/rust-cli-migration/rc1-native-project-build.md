# Native project and compatibility build implementation

This describes development tooling for RC1, not the released 0.1.0 CLI or an
accepted native SDK release. [The migration plan](../rust-cli-cargo-migration-plan.md)
remains the acceptance authority; [RC1](https://github.com/metaneutrons/ami-rust/issues/71)
tracks the remaining lifecycle and platform qualification.

## Consumer flow

After native package preparation, `new --state STATE --project ABSOLUTE_PATH`
creates a fresh `hello-aros` static-library project, a source copy of its SDK,
and a versioned project lock. `build --state STATE --project ABSOLUTE_PATH
--output-dir FRESH_OUTPUT` uses the same core as direct SDK builds. Both
`ami-rust` and `cargo ami` dispatch through one capability list and parser.

Direct SDK consumers can create a lock using `lock --prefix PREFIX --selection
SELECTION --project PROJECT --output FRESH_LOCK`, inspect its installed inputs
with `verify --sdk-lock LOCK`, and invoke the explicit compatibility recipe:

```text
ami-rust build --sdk-lock LOCK --output-dir FRESH_OUTPUT -- build \
  --manifest-path PROJECT/Cargo.toml --package PACKAGE --release --locked --offline
```

The installed SDK, external receipt pin, host CLI/core identity and all six
component inventories must agree. Lock verification checks those inputs; the
build additionally checks the explicitly selected Cargo manifest and lockfile.
Unknown or conflicting Cargo options refuse before mutation. Existing output
directories and overlapping input/output roots refuse without replacing user
data. No global Cargo or rustup configuration is changed.

## One build recipe

`native_recipe` describes the unchanged C compilation, startup adaptation,
qualified Cargo invocation, collector library order and stripping commands.
`native_build` supervises them, selects exactly one Cargo static-library
artifact, compacts section names and audits the final AROS ELF in Rust, then
rechecks inputs before writing `ami-rust-native-build-receipt-v1`.

Host remapping and target flags remain separate. The pinned custom Cargo and
paired rustc are selected explicitly; no ambient compiler fallback is used.
The compatibility command currently performs final linking after Cargo's
static-library compilation. RC2 will reuse this recipe for Cargo-owned final
linking; this implementation alone does not satisfy direct-Cargo acceptance.

Completed child failures preserve their exit status, including Cargo's 101.
Failed builds retain diagnostic evidence and do not produce a successful build
receipt. Signals and resource-monitor failures use the shared supervision path.
Resource reports are sampled host observations, not containment or atomic
snapshots against concurrent same-user modification.

## Existing projects

`migrate --dry-run --project PROJECT` inspects the conventional historical lock
without executing its recorded interpreter. Omitting `--dry-run` still performs
inspection unless all explicit write options are supplied:

```text
ami-rust migrate --project PROJECT --from-lock OLD_LOCK \
  --install-prefix NATIVE_PREFIX --receipt-sha256 EXTERNAL_RECEIPT_SHA256 \
  --output FRESH_LOCK
```

Migration checks the old SDK/component inventories, project Cargo hashes and
compiler against the separately selected native installation. It writes a
separate native lock, preserving the old lock, SDK binding and source files.
Use the new lock explicitly with `build --sdk-lock FRESH_LOCK`; migration does
not activate it by overwriting the project's conventional lock. It does not
reauthenticate the publisher or change the selected compiler. Unsupported
schemas and incompatible or changed inputs refuse.

The historical bootstrap interpreter is read only as pinned data. Its original
`0775` mode is preserved and accepted for inspection; links, another owner's
file, world-writable/set-ID files and changed bytes refuse. The strict ownership
and permission checks for executable inputs of the new tooling remain in force.

## SDK draft assembly

The internal Rust `native-sdk` maintainer task converts the retained historical
SDK into a deterministic SDK-v2 draft. It preserves all 56 initial target
inputs, twelve component manifests and four legal notices. The C measurement
header needed by the qualification/dependency variants is separately pinned in
`tooling/fixtures/accepted-r1-support-inputs.json`, derived from the immutable
published SDK. The original 56-file ledger is unchanged. No Python consumer
driver is copied into the new draft.

Production Cargo inventories contain an opaque `producer_identity_spec` object.
Selection accepts that known data field while retaining duplicate-key and
unknown-field rejection. The complete profile bytes remain bound to the SDK;
reading this object does not reauthenticate a producer or execute its historical
helper references.

A local draft is explicitly unsigned. A manually assembled local installation
can exercise consistency checks and native builds, but its synthetic receipt
fields and inert signature marker are never publisher-verification evidence.
Real native-v2 authentication, both-host no-Python observation, differential
compatibility, two-root build reproduction and the retained lifecycle remain
required before accepting RC1.

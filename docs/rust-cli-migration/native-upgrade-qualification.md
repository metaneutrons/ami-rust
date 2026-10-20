# Native package upgrade qualification

This procedure supplies the native-to-native upgrade evidence for
[RC1-A4](../rust-cli-cargo-migration-plan.md#rc1--rust-consumer-cli-with-equivalent-behaviour).
Execution status and acceptance evidence belong to
[#71](https://github.com/metaneutrons/ami-rust/issues/71). A component test, a
successful package composition or this procedure alone does not accept RC1.

## Inputs and identity

The earlier **unpublished, unaccepted** native preview is SDK `0.2.0`, CLI
`0.2.0-dev`, package `0.2.0-1`, source
`5135254310dba8d7ad2886332fb888b9518c159c`, protected SDK run
`39422283932`, attempt `1`. Its original producer run failed its Linux consumer;
that failure remains part of the history. Authentication of its produced bytes
does not turn it into an accepted release.

The new protected producer emits package `0.2.0-2`. Its SDK manifest and source
identity must differ from the old preview. The CLI executable can legitimately
remain byte-identical when the change is to packaging or qualification; the
package version, authenticated capsule and READY ownership still change.
This is an unpublished qualification identity, not a replacement for an existing
release. The accepted `0.1.0` SDK and its packaging assets remain untouched.

The workflow selects earlier inputs by exact run and artifact ID:

| Input | Artifact ID | Original ZIP SHA-256 |
| --- | --- | --- |
| Outer candidate, package pins and proofs | `12264163294` | `06d2d6359c02696012e2840ee4edc0103d78d244b4c1a951e35ff9a6088ece12` |
| Original Linux inner authentication | `12264328204` | `89656376473bf2353e8542381caaef413d3abdc1a2c2f92d15fc53889500f3bd` |
| Original macOS inner authentication | `12265142248` | `8132af924c0c44a30a89e35c6de87447798778bbd9c4fb80e09f61bf5bc180a7` |

The ZIP digests identify retained transport evidence. After extraction, the
coordinator checks the archived host package-pins and original authentication
record hashes, source/run/attempt, selected launcher and manifest identities.
The Rust consumer separately verifies real publisher signatures using the
historical source/input policy. The old package is composed from its original
launcher, outer assets, proof records and signed notice inputs. The outer
package verifier also checks the common Linux-signed inner capsule on both
hosts; the original host-profiled inner bundle is independently verified.

These CI artifacts initially expire on **2026-10-27**. Preserve all three until
the proof is durably retained or an authenticated replacement input location is
qualified. A local backup is recovery evidence, not a path hosted runners can
read. Missing or expired input is a failed precondition; never synthesize a new
old version or replace its original proof metadata.

## Observed transition

The existing signed lifecycle first establishes a working new native READY
state/project and its canonical executable, alongside the real historical
`0.1.0` preservation population. The upgrade then:

1. Authenticates and composes the real old and new native packages. All SDK
   members except the generated `contract/sdk.json` must match between previews;
   that contract has a new producer source identity. Compiler, target code,
   component manifests, vendor, ABI and boot baseline stay pinned.
2. Uses the old native launcher to prepare an independent old READY state,
   generate its project and produce a real offline build.
3. Replaces a private active-package selector from revision 1 to revision 2.
   The new launcher must reject both old-state recheck and old-state build with
   the explicit retained-owner diagnostic and no output publication.
4. Removes the replaced old package root. The old state's exact retained
   launcher must still recheck inputs and build its old project offline.
5. Rechecks and builds the new state/project through the active new package.
   Both old builds and the new build must match the already established
   canonical executable.
6. Compares complete byte/link/metadata snapshots of old/new states, projects,
   original builds, historical rollback data, private global Cargo/rustup
   configuration, unrelated SDK and user-data fixtures throughout the change.

Every consumer invocation goes through `native-consumer-observe` and the
existing enforcement adapter, including the old native preparation and retained
replay. Cold preparation admits explicit acquisition; builds and rechecks deny
network access. Python execution/libraries remain excluded. Internal Python
test coordination is outside the consumer tree and remains RC4 retirement work.

The existing aggregate limits remain **4 GiB RSS, 12 GiB managed workspace,
16 MiB logs and 1200 seconds per command**. Old input roots are charged alongside
all existing live work; no additional runner or independent unaccounted build is
introduced. Evidence stays within the existing 32 MiB per-host consumer artifact
ceiling. The coordinator preserves completed earlier matrix evidence if a later
upgrade step fails.

## Evidence and boundaries

Each supported host must retain `native-package-upgrade.json`, all named command
results, raw adapter captures, policies/closures and aggregate resource records.
Readback must bind these records to the exact current source/run and archived
old inputs, inspect actual exits and file effects, and verify preservation and
canonical output equality. Refusal fixtures exercise incorrect owners, changed
inputs, mutated protected data and changed replay bytes; they are development
controls, not substitutes for both-host execution.

The private selector models versioned package-root replacement. It does not
claim an APT or Homebrew transaction; those channel upgrade/reinstall/removal
tests belong to RC3. No SDK is published by this qualification.

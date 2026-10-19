# Native SDK producer integration

This is RC1 implementation work under [#71](https://github.com/metaneutrons/ami-rust/issues/71),
not RC1 acceptance or SDK publication. The revision 2 migration plan and its
RC0–RC5 criteria remain unchanged.

The protected `sdk-qualify.yml` workflow has a default-off `native_tooling`
dispatch input. It cannot be combined with `reference_proposal`. Its native
branch uses standard Ubuntu 24.04 x86-64 and macOS 26 arm64 runners and the
existing protected `release` environment. Default legacy/reference execution
remains available on its existing identities.

## Producer and signer flow

1. Each host bootstraps the existing pinned Rust 1.98.1 compiler. The reviewed
   29 registry package identities remain unchanged. Cargo verifies the locked
   archives during explicit fetching; subsequent builds are locked and offline.
2. Each host builds the native CLI and Rust maintainer task from the exact
   checkout. The existing portability builder checks local path prefixes and
   rejects an isolated copy containing an appended source path. Publication
   registry credentials are removed from build/probe environments.
3. The maintainer task produces SDK-v2 from the entire hash-pinned immutable
   0.1.0 SDK archive. The target sources, measurement support header and six
   prerequisite component inventories retain their accepted identities.
   Historical Python sources in the input capsule remain inert.
4. The Linux assembler requires both producer reports to select the same
   protected source/run, reviewed lock and SDK bytes. The Rust `native-release`
   task composes the new inventory with both real host binaries, unchanged
   custom-Cargo archives, SHAUTIL and the applicable original legal/source
   assets. Historical public Python helpers are excluded.
5. Both signers independently recompose the candidate from the pinned inputs
   and both host outputs before using OIDC. Each also requires its independently
   built local launcher to match the corresponding incoming host bytes exactly. Existing GH attestations and Cosign
   signatures cover exactly `release.json`, `sdk.tar.xz` and `SHAUTIL`; the
   signed manifest binds both host launcher hashes. Signing does not accept RC1.
6. The protected Linux outer producer uses the Rust verifier before transport
   composition and reads the canonical 64 MiB transport back through the native
   extractor. The existing signing tools attest four outer subjects and sign
   the archive/transport. Native package records bind the six assets, proofs,
   source/tree/run and each host launcher; no published release is changed.
7. Both consumer hosts use the same Linux-signed candidate and independently
   build their verifier CLI from source. They verify actual signatures, reject
   isolated altered GH/Cosign proofs in the named real verifier, reject a changed
   SDK, install with an external receipt pin, preserve the installation on
   collision/wrong-pin refusals, then remove it while preserving the pin.
8. Each host composes its actual native package from the signed outer assets
   and selected launcher, authenticates the complete package, prepares a fresh
   state, creates a project and builds offline. Before package removal, the
   packaged frontend creates locks for two independent SDK project copies and
   builds all five frozen variants in fresh output roots, including a path with
   spaces. Every response and receipt binds its output paths, project lock and
   SDK identity. Canonical bytes must match the exact host reference and the
   other root. Only after all ten builds pass are the five executables and three
   unchanged dependency archives retained for independent cross-host review.
   Mismatch diagnostics are moved into consumer output before failure/cleanup;
   raw retention adapts to remaining hosted artifact/workspace headroom and the
   structured report states any omitted bytes. Removing the private package
   directory must preserve the state, project and an unrelated user file; the
   retained launcher must then reproduce the same native executable.

The Rust task emits unsigned draft commentary on stdout. It writes only the
closed release inventory into the output bundle; no unbound draft status file
is mixed into the distribution payload. `qualification_only: false` describes
the production-shaped manifest, not an authentication or acceptance result.

## Inputs and transitional code

`release/native-tooling-inputs.json` selects prospective SDK `0.2.0`, development
CLI `0.2.0-dev`, the exact Cargo lock, registry archives and native source paths.
The source-derived SLSA materials extend the historical closure with these
inputs and the accepted release capsule. Producer and Rust consumer calculate
identical canonical material bytes. SDK 0.1.0 retains its byte-exact historical
material closure and container profiles.

The native notice inputs preserve all 61 reviewed file identities in 31 exact
crate texts, plus the full upstream standard-library copyright document. The
source inventory and distributed notice links are bound to the new release;
a new SPDX document describes the launchers and 29 locked host build inputs,
while the exact original component SPDX remains an explicitly historical asset.
Final release license acceptance remains open.

The new Rust maintainer task owns SDK/release/transport/package composition; the Rust core owns
consumer verification/installation. `release/ci_native.py` and `release/ci_native_outer.py` coordinate internal
builds, protected signing phases and qualification using the pinned Python runtime, together with the
existing authentication scripts. These internal Python tasks remain RC4 work;
they are not a supported public preparation dependency. A complete port of
compiler/C-SDK production is not a prerequisite for this RC1 producer branch.

The native workflow admits its complete 384 MiB artifact ceiling before any
producer upload: two 16 MiB host outputs, one 64 MiB unsigned candidate, two
64 MiB authenticated candidates, two 32 MiB consumer reports and one 96 MiB outer-candidate/proof artifact. These are
prospective hosted artifact profiles, not local evidence or AROS application
quotas. Native-v2 authentication uses its existing 64 MiB bundle profile;
historical-v1 retains 32 MiB. No release or package channel is mutated.
The complete native consumer job uses the existing full-consumer 80-minute
allowance rather than the earlier direct-verification-only 20 minutes. Its
supervised commands retain the existing 1,200-second, 4 GiB RSS, 12 GiB workspace
and 16 MiB log limits. A job deadline is not a promise of that running time.

## Remaining acceptance

The first real protected native run
[39263593629, attempt 2](https://github.com/metaneutrons/ami-rust/actions/runs/39263593629/attempts/2)
completed production and authentication at exact source
`c34adc55b9c4c77ccf1d624eaee13a1f4dfd2671`. The SDK source archive and manifest
were byte-identical on both hosts; independently rebuilt host launchers matched
before signing. Actual inner/outer GH and Cosign verification and altered-proof
controls passed. [Durable reports and artifact digests](evidence/native-39263593629-attempt2/result.json)
preserve those measured results. All six artifact ZIPs were archived and checked
against GitHub's SHA-256 digests, including per-member integrity checks.

Both native consumer jobs were **skipped**: their condition inherited GitHub's
implicit `success()` across a deliberately skipped legacy consumer ancestor.
The workflow's green aggregate therefore did not establish preparation, build
or retained replay. The corrected consumer condition explicitly evaluates
`always()`, cancellation, selected mode and successful direct authentication/
transport dependencies. Positive and deliberately broken-condition fixtures
check this branch, but only a new real run can prove its hosted execution.

A subsequent local execution of the actual signed `c34adc55` package passed
package consistency and complete outer/inner publisher authentication, then
failed cold preparation while publishing an extracted component: the
sibling-only atomic rename helper correctly refused different parent
directories. Component provisioning now uses a separate directory-only,
same-filesystem, descriptor-relative no-replace move; transaction/receipt
publication retains its original sibling-only restriction. No copy fallback
or overwrite is permitted.

The [real-input regression](evidence/rc1-component-publication-development-20261019.json)
then provisioned and checked all six component inventories on macOS using the
retained authenticated installation and copied checked source inputs. It took
165.039 seconds, with observed peaks of 1,625,800,704 bytes RSS and
3,607,935,297 bytes managed workspace. An earlier attempt was stopped by the
unchanged workspace monitor because an inactive local build cache was still
inside the checkout; that cache was moved intact to historical working storage.
This proves the component correction on real inputs, not complete corrected-CLI
preparation, READY, both-host qualification or no-Python acceptance. The next
protected campaign must contain the corrected newly signed CLI.

Even a passing direct lifecycle report does not close RC1-A1–A4:
complete package preparation, cold/warm acquisition, no-Python observation,
differential decisions, five variants in two fresh roots per host, cancellation,
migration, upgrade/removal and retained replay remain required on exact inputs.

The full two-root matrix, native package consumer execution, final source/license
audit and complete qualification remain required before release acceptance.
The preserved old legal assets apply to their unchanged components; they are
not a claim that the new host binary dependencies have already passed a new
distribution license audit. Existing published 0.1.0 assets and the qualified
AROS ABI-v1/QEMU baseline remain unchanged.

### Retained launcher replay and historical comparisons

After the component correction passed both-host component CI and merged, a real
local current-core preparation completed on the unchanged signed c34 package.
The subsequent ten-build matrix returned after its strict reference/two-root
checks, but final replay through `retained/bin/ami-rust` refused a symlink path.
Invoking the same retained bytes through their resolved file path rebuilt the
same native executable. macOS can return the invoked alias from `current_exe`;
the CLI digest check now resolves that OS-provided location before its existing
no-follow hash and both receipt-identity comparisons. Project/component input
path restrictions are unchanged. Positive, changed-target, wrong-digest and
dangling-alias fixtures cover the correction.

The lifecycle coordinator now persists the completed matrix report before
package removal, including when retained replay later fails. Explicit maintainer
tests additionally pair the frozen Python functions with current Rust across
131 parser/claim cases, nine filesystem transaction cases and 50 inventory/TAR
cases on both CI hosts. The filesystem replay uses the current compiled core
against the same pinned inputs as the historical functions, comparing all
decisions and wrapper decision exits plus complete accepted TAR reports. It
does not substitute those API comparisons for full consumer CLI lifecycle
acceptance. Both complete historical source files and the internal interpreter
are pinned; the active source/test/helper identities are recorded per run.
Ordinary workspace tests leave these historical tests ignored; the named CI
step supplies the pinned internal Python and records exact counts and source
identities. Python is outside the consumer process tree and this temporary
historical comparison is retired with active internal Python in RC4.

[Development evidence](evidence/rc1-retained-launcher-development-20261019.json)
keeps the actual failure and narrower successful controls distinct. The signed
new CLI, full both-host no-Python lifecycle and remaining RC1 criteria are still
unaccepted; no SDK or package channel is published by these tests.

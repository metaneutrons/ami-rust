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
   state, creates a project and builds offline. Removing the private package
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
Exact linked standard-library and final release license acceptance remain open.

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

Local unit fixtures and an unsigned draft do not establish a real protected
producer run. Even a passing direct lifecycle report does not close RC1-A1–A4:
complete package preparation, cold/warm acquisition, no-Python observation,
differential decisions, five variants in two fresh roots per host, cancellation,
migration, upgrade/removal and retained replay remain required on exact inputs.

The native notice/SPDX and outer transport/package paths are implementation,
not a protected-run result. Their actual both-host execution, final source/license
audit and complete qualification remain required before release acceptance.
The preserved old legal assets apply to their unchanged components; they are
not a claim that the new host binary dependencies have already passed a new
distribution license audit. Existing published 0.1.0 assets and the qualified
AROS ABI-v1/QEMU baseline remain unchanged.

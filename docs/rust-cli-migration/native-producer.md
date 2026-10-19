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
   and both host outputs before using OIDC. Existing GH attestations and Cosign
   signatures cover exactly `release.json`, `sdk.tar.xz` and `SHAUTIL`; the
   signed manifest binds both host launcher hashes. Signing does not accept RC1.
6. Both consumer hosts use the same Linux-signed candidate and independently
   build their verifier CLI from source. They verify actual signatures, reject
   isolated altered GH/Cosign proofs in the named real verifier, reject a changed
   SDK, install with an external receipt pin, preserve the installation on
   collision/wrong-pin refusals, then remove it while preserving the pin.

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

The new Rust maintainer task owns SDK/release composition; the Rust core owns
consumer verification/installation. `release/ci_native.py` coordinates internal
builds and qualification using the pinned Python runtime, together with the
existing authentication scripts. These internal Python tasks remain RC4 work;
they are not a supported public preparation dependency. A complete port of
compiler/C-SDK production is not a prerequisite for this RC1 producer branch.

The native workflow admits its complete 288 MiB artifact ceiling before any
producer upload: two 16 MiB host outputs, one 64 MiB unsigned candidate, two
64 MiB authenticated candidates and two 32 MiB consumer reports. These are
prospective hosted artifact profiles, not local evidence or AROS application
quotas. Native-v2 authentication uses its existing 64 MiB bundle profile;
historical-v1 retains 32 MiB. No release or package channel is mutated.

## Remaining acceptance

Local unit fixtures and an unsigned draft do not establish a real protected
producer run. Even a passing direct lifecycle report does not close RC1-A1–A4:
complete package preparation, cold/warm acquisition, no-Python observation,
differential decisions, five variants in two fresh roots per host, cancellation,
migration, upgrade/removal and retained replay remain required on exact inputs.

The complete native tooling license/notices inventory, new SPDX and outer
transport/package integration must be completed before release qualification.
The preserved old legal assets apply to their unchanged components; they are
not a claim that the new host binary dependencies have already passed a new
distribution license audit. Existing published 0.1.0 assets and the qualified
AROS ABI-v1/QEMU baseline remain unchanged.

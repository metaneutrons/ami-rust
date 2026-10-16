# Protected hosted SDK candidate qualification

The manual `Hosted SDK candidate producer` workflow is restricted to protected
`main` in `metaneutrons/ami-rust`, using the `release` environment and standard
`macos-26` ARM64 / `ubuntu-24.04` x86-64 GitHub-hosted runners. It has no SDK
publication job. R1 acceptance is defined by the [release plan](m2-r1-plan.md).

The workflow builds the pinned custom Cargo prerequisite from source, provisions
separately identified Rust/toolchain/collector/vendor inputs, and regenerates the
complete portable C-SDK independently on each host. The C-SDK source capsule and
four narrow patches are in the same repository; source code, generators and
build recipes are patched in disposable owned trees. The original C-SDK and
qualified AROS boot/ABI baseline remain unchanged. The fresh C-SDK must match the
complete candidate profile and golden archive before use in native builds.

The candidate SDK uses the derived C-SDK's own profile. The consumer provisions
that prerequisite from this repository at the authenticated source commit and
checks its complete inventory. The original archive is only an immutable build
input. Full source and [notices](../release/portable-csdk/SOURCE-AVAILABILITY.md)
accompany both repository prerequisites. The historical original source prefix
is retained only as build-counterproof data; it is excluded from the end-user
SDK manifest. No compiler metadata or finished binary is edited to remove paths.

The producer builds all five native variants in two clean roots on each host,
then checks exact canonical native/library outputs under the approved host
metadata comparison. The subsequent jobs assemble bounded payloads, create
GitHub provenance and Cosign signatures for the three subjects, and independently
verify/install/build/uninstall them on both hosts. Counter-cases cover corrupted
assets, identities and provenance. Actual successful runs, their source commits
and evidence are required; tests of the helpers do not establish authentication.

`release/ci-sdk-inputs.json`, `release/portable-csdk/spec.json` and
`release/ci-resources.json` are normative inputs. The resource policy requires
6 GiB physical RAM and 24 GiB free disk, two jobs, 4 GiB aggregate observed RSS,
20 minutes per command, 12 GiB managed work and 16 MiB logs. All downloads,
checkouts, installed prerequisites, work trees and controlled temporary/cache
roots count. Cleanup receipts are required before retiring transient holdings.
Retained artifacts have their own aggregate pool and fixed per-artifact bounds.
Concrete qualification campaigns retain 90-minute clocks and a review reserve;
sealed failures and previous campaign clocks remain unchanged.

Current status: the complete shared C-SDK producer passed locally on macOS with
full process-tree measurement. Latest-source protected two-host production,
authentication, independent clean consumers, final binary-linkage/licence review
and R1 acceptance remain open. See the [portability record](r1-portability-follow-up-20261016.md).


## Establishing changed native references

Dispatch with the explicit boolean `reference_proposal=true` only when changed
SDK sources require new native qualification. Both hosts still build all five
variants in two clean roots, verify real files against their receipts and demand
complete within-host byte equality. They retain the five executables and raw
canonical hash maps under `PRODUCED_NATIVE_REFERENCE_PROPOSAL_NOT_FOR_AUTHENTICATION`.
The three unmodified Serde/Curve25519/Ed25519 `.rlib` archives are also retained
for the independent member/metadata comparison. The ordinary mode remains
strict against accepted references.

This proposal mode skips assembly and consequently signing and consumers. The
assembler also rejects proposal receipts. It does not overwrite accepted hash
maps or pass runtime acceptance. Independently compare the two host maps under
the approved metadata contract, run the complete affected native matrix and new
memory probes on the unchanged boot/ABI profile, then freeze reviewed new
references and their source/evidence identities in a separate change. Only the
normal protected production mode can subsequently produce an authenticated
candidate against those accepted references. No SDK publication is performed.

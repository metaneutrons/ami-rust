# R1 portability follow-up — 2026-10-16

Status: preparation and component checks in progress. R1-A6 remains OPEN. No
SDK release has been published. The existing AROS boot/ABI-v1 baseline and the
protected AROS-NX/aros-tools checkouts remain unchanged. nxpk is out of scope.

## Original inputs and patch boundary

Direct readback of the original C-SDK verified all 2,835 regular files and
51,045,644 expanded bytes against the retained inventory. Its 5,621,776-byte
archive retains SHA-256
`70cc3e45969c6e1eca7e4c5c2183429b88424f6c22c8ec6bb90e6cc70452ab87`.
All 530 headers with absolute provenance paths equal their frozen source-capsule
counterparts. Receipt: `qualification/r1-ci-20261016/original-csdk-direct-readback.json`.

The source capsule retains SHA-256
`7e62e28fb025e31aacdd3b6a6d14cef7d76703eb59dbaca02f2e2b4de68c6914`.
Its frozen recipes identify 106 public-header invocations, 27 classic C
genmodule sources and 825 direct Nouveau compile records. The initial
GenmoduleHeaders.cmake-only patch covered five headers. The prepared series now
also patches AROS.cmake, covering the remaining 525. The original failed
preparation is retained; it is not relabelled as a passing full derivation.

The four patches change the two public-header callers, the Nouveau target's
compiler prefix mapping and the libaom pkg-config generator. They apply only in
ami-rust-owned copies. Source revisions, before/after hashes and patch hashes
are recorded in `release/patches/portable-csdk/series.json`. Finished binary
archives and Rust compiler metadata are never edited to conceal build paths.

## Component checks and remaining acceptance

The exact pinned macOS LLVM 11 compiler produces identical source/header
`__FILE__` mappings from two roots, including one with spaces. Unmapped and
wrong-prefix counter-cases retain the absolute path as expected. The repeated
probe captures command records, observed descendant RSS, workspace and logs;
the earlier receipt without resource peaks remains preserved. Linux remains
unqualified for this subcheck.

The local header campaign passed on macOS: 530 headers are byte-identical
between the two roots, and only their provenance paths differ from the frozen
originals. The absolute-config counter-case exposes its prefix as expected.
Observed peak descendant RSS was 70,991,872 bytes; counted checkout/workspace
peak was 1,409,050,798 bytes. These are observed process samples, not an assertion
of exact instantaneous RSS. The campaign replays all frozen generator arguments with the
source-relative config/cwd change. It compares every public header against the
original and permits only the provenance path to change. This is a C-SDK
component reproduction check; it does not claim a new OS reconfiguration or
an independently qualified boot image. Its concrete clock, failures and
results live in `qualification/r1-csdk-local-20261016/`.

The subsequent macOS Nouveau campaign passed its component boundary in
794.790 seconds, including failed attempts and final readback. All 825 direct C
sources compiled with the exact pinned LLVM 11 toolchain. Of the resulting
archive members, 616 are byte-identical to the original; exactly 209 changed,
and those are precisely the members containing historical absolute source
paths. A separate compiler counter-case maps the owned source root back to the
historical prefix and reproduces all 209 original objects byte-for-byte. No
object or archive payload was rewritten.

Two fresh deterministic GNU archives agree at SHA-256
`98c9e2e6e2d4a9fb724d49cacc0a8a86ec627e4c04465b748f346acbd33aeb1d`.
All 825 member names/order and 4,515 symbol-to-member ordinal entries agree with
the original, including duplicate member basenames. The macOS derived C-SDK
contains the complete 2,835-file set, exactly the allowed 532 changed files, and
no detected local build prefix. Its canonical 5,619,304-byte archive has SHA-256
`942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b`;
its full file-profile SHA-256 is
`e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337`.
These identify a macOS component candidate; they do not replace the original
C-SDK pin or establish cross-host qualification.

The first plan rejected a missing empty include directory; the complete frozen
source inventory contains no files below that recipe path. The caller then
created that empty directory in its owned source tree. The next compile stopped
at the adapter's 64 KiB per-stream guard on existing `pci.c` warnings. The revised
guard admits 512 KiB per stream and reserves both active compiler log pairs
within the unchanged aggregate 16 MiB limit; overflow controls still pass. The
fresh-output precondition caught another retry before compilation. Partial
objects, failed plans and bounded failure logs remain preserved.

Final tests passed: archive readback 3, Nouveau/compiler supervision 13 and SDK
inventory 18. Independent complete-candidate readback also passed. Observed
compiler-scope RSS across attempts peaked at 584,876,032 bytes; all retained
campaign logs total 6,591,874 bytes. The inner archive-tool RSS measurement did
not cover the Python orchestration process; the separately supervised readback
covers the complete archive verification. A fresh production producer must
supervise its entire Python process tree. After complete per-file readback,
30,090 recoverable source-cache files and 9,052 staging files were retired;
original inputs, all patched sources, raw evidence and candidate bytes remain.
The sealed clock, failures, member comparisons, counterproof and retirement
receipts are in `qualification/r1-csdk-nouveau-20261016/`.

The reusable `release/csdk_metadata.py` API also passes six isolated fixtures
and an actual macOS call using the pinned AOM archive, unchanged original
metadata and patched source. Both source/output paths contain spaces. The
complete Python helper and descendants are supervised in this check; sampled
RSS peaks at 84,459,520 bytes. Generated metadata retains SHA-256
`44e60ded4d7fa63dceeca042abfca86b841632586aaba5437c45fa96a99f5de7`,
and relocation and both original-generator counter-cases pass. This prepares
the common producer interface; it is not an actual Linux or full SDK producer
result. Evidence: `qualification/r1-csdk-metadata-api-20261016/`.

Before accepting a derived C-SDK, require:

1. All 530 regenerated headers agree between unrelated source roots on each
   host and between the two supported hosts. A control using an absolute config
   must expose the path, demonstrating that the comparison detects the defect.
2. Recompile all 825 Nouveau source records with the pinned cross compiler and
   source prefix mapping. Preserve archive member order and every other build
   flag. Compare unaffected members and reject unexplained differences. No
   generated proxy wrappers are used by these 825 inputs.
3. Generate relocatable aom.pc from its patched source and verify include/library
   paths after moving the Developer tree. The macOS two-root relocation probe
   passes, including paths with spaces. The patch also avoids the host-dependent
   `-lm` branch for AROS, whose pinned SDK provides math through stdc and has no
   separate libm. Set target/platform normal variables in an owned CMake wrapper:
   script-mode host variables shadow command-line cache entries. The original
   generator counter-case must expose both its absolute prefix and the wrong
   `-lm` dependency. Actual Linux reproduction remains mandatory.
4. Preserve the original 2,835-file set. Identify and justify every changed file;
   only the 530 headers, libdrm_nouveau.a and aom.pc are initially allowed to
   differ. Reject unexpected additions, removals or local path strings.
5. Compare complete derived C-SDK profiles and canonical archive bytes across
   the standard macOS ARM64 and Linux x86-64 runners. Pin the resulting component
   separately from the original C-SDK.
6. Integrate that exact profile into production-candidate packaging. Run all
   affected native comparisons, real protected GH/Cosign authentication,
   corruption cases and complete clean installation/build/uninstallation replay
   on both hosts. Runtime/memory evidence transfers only through exact native
   byte identity; otherwise the affected guest matrix must be repeated.

## Authentication and source preservation

Independent review found and corrected missing protected-context variables in
the authentication-tool bootstrap and an incompatible consumer requirement for
two host runs in a per-host signed bundle. The consumer now requires exactly
one run matching its current host, with wrong-host and two-host counter-cases.
These are fixture/static results, not evidence of actual signatures.

The publisher input manifest additionally binds the pinned authentication-tool
downloads, trust roots, source capsule and individual source patches. Changing
those bytes must fail validation. Actual protected production and cryptographic
verification remain pending.

The expanded Cargo source/notices capsule v3 is 4,176,344 bytes, SHA-256
`da23b154fd15d595329de28cbf1db650bf8b1da57679ef270c09c9d7e84dc62f`.
Independent readback verifies 2,672 members / 17,622,807 expanded bytes, all
523 locked package notice records, three complete MPL source packages and the
lock-matched complete libgit2-sys source archive. Original recovered licence
texts and attribution evidence remain included. This preserves source and
notices; final binary linkage, SBOM scope and release licence acceptance still
require their separate checks. The expanded candidate SBOM now has 586 records:
57 inherited runtime/SDK records, 523 host registry lock-closure packages and
six Cargo/native identity records. All new records distinguish declared source
licences from a final licence conclusion. The apparent Cargo `sys:0.21.0`
version discrepancy is resolved: the pinned CLI prints the git2 wrapper's own
version in that field, while the locked libgit2-sys crate is 0.18.5+1.9.4. V1 and
v2 archives remain unchanged.

Individual concrete test campaigns retain a 5,400-second ceiling, a 5,100-second
test cutoff and 300 seconds for review. Preparation does not reset sealed
campaign clocks or reopen earlier failures. Hosted resource policy and guest
budgets remain unchanged. The independent overall R1 goal has no new deadline.


## Shared producer and repository prerequisite (2026-10-16)

The full common C-SDK producer now passes a fresh macOS run, including all 825
native compiles and an additional full 825-object original-prefix counterproof.
Both archive constructions preserve all 4,515 symbol-to-member index entries.
The resulting canonical archive is 5,619,304 bytes, SHA-256
`942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b`;
its profile SHA-256 remains
`e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337`.
The complete Python process tree and descendants were supervised: the native
producer took 564.213 seconds, with sampled peak RSS 676,364,288 bytes and managed
work 1,435,834,468 bytes. The campaign closed at 1,162.653 seconds after the
integration review; all tests preceded the cutoff. Linux production remains open.

The native proof's exact producer source is retained with its loaded-helper
identities in `qualification/r1-csdk-common-20261016/control-output/`. Subsequent
explicit host-utility CLI plumbing and strict native-count guards passed the
75 affected integration fixtures. The latest source still requires actual
production on both hosted platforms. Source/staging caches were retired only
after complete per-file readback (30,094 source and 9,052 staging files); raw
logs, patch snapshots, plans, comparisons, counterproofs and final archives remain.

Keep the C-SDK as a separately provisioned repository prerequisite, identified
at the same immutable source commit as the authenticated SDK. Each protected
host producer must independently regenerate the complete candidate, compare it
with both the pinned profile and repository golden archive, and build against
its freshly generated bytes. Consumers verify and install the exact derived
repository prerequisite. The original archive remains a preserved build input.
This preserves the 94-file SDK inventory and existing 32 MiB signed-bundle limit.
No archive is silently substituted under the original identity.

Production SDK metadata embeds a `distribution_spec` without the historical
absolute prefix used only by the source counterproof. The full build spec's
path, byte count and SHA-256 remain bound, and the original counter input stays
in the source repository. No binary metadata is rewritten. A regression fixture
rejects leakage of that historical prefix into the packaged SDK manifest.

The publisher material inventory now binds the complete source capsule, source
manifest, four portability patches, both archive/profile identities and both
cross-toolchain profiles. The adjacent source-availability notice, complete APL
and dated change record address the two identified APL documentation gaps.
Actual public availability, protected generation, production authentication,
clean consumers and final licence/binary-linkage acceptance remain separate open
R1 gates. No SDK release has been published.

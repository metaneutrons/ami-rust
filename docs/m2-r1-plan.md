# ami-rust M2 and independent R1 plan — revision 24

**Current resource policy — revision 23:** [Memory policy](memory-policy.md)
is authoritative for the current candidate. There is no fixed per-allocation,
application-heap, whole-application or generic ELF-size quota. Available native
memory, checked layouts/ownership and actual allocation failure govern use.
Measure loader/startup, application and teardown memory; reject leaks,
corruption and broken cleanup. Investigate unexpected growth against the
measured workload and document the resulting machine requirement.

The unchanged 512 MiB QEMU/ABI-v1 configuration is the qualification machine;
128 KiB startup stack and at most 96 KiB measured stack use define the current
supported stack profile. These values do not establish a universal AROS memory
limit. Hosted build settings are operational requirements, based on observed
build use, and may be adjusted prospectively when measurements justify it.
Neither a historical feasibility quota nor an unused CI ceiling justifies
rejecting an application. Changed native code still requires fresh qualification.

Earlier M0/M1/R3 records and sealed input files retain their original numbers
and outcomes. Their heap/code-size limits describe those experiments only.
The `runtime_budgets` prose in the frozen `release/ci-resources.json` predates
this decision; it does not reinstate those application quotas. Its bytes remain
pinned to existing producer receipts until a newly identified producer input
is prepared. No historical PASS, FAIL or clock is changed by this clarification.

Status (inherited evidence): the inherited third qualification campaign (retained
development record: `r1-qualification-r3-20261015.md`) remains technically PASS.
The installation/licensing follow-up (retained development record:
`r1-installation-qualification-20261015.md`) records its two-host
installation/deinstallation recipe, project reproduction and candidate
licence/source review. These are historical candidate results; they do not
qualify changed native inputs or the final versioned release. The public source
repository is [metaneutrons/ami-rust](https://github.com/metaneutrons/ami-rust);
its protected source CI passes. M0 has GO and M1 technical acceptance is
recorded in the sealed M1 decision (retained development record:
`../evidence/current-campaign/decision.md`). The prospective hosted CI resource
amendment below applies to new CI phases.

## Current native profile and protected proposal status — revision 24 (2026-10-17)

The current native profile received technical GO on its exact inputs and
supported profile in the [public R4 qualification record](../release/candidate-r4/qualification.json)
(SHA-256 `c5e559f592c7300b502ebf976ecd5b65c9191a130dbc2f7b5c9ed68a7045982c`).
The native closure passed after 2,641.44 seconds with no exceptions: all 155
cases, plus Linux-derived-output checks and malformed LoadSeg. The immutable
boot image, ABI and guest profile remain unchanged. Regular, non-injected
SDK-owner diagnostics allocated zero. Declared positive controls intentionally
allocate nine times per full/large phase; their 36 allocations are accounted
separately.

The protected two-host proposal for source `1d0fe4f` passed in
[run 38964667415](https://github.com/metaneutrons/ami-rust/actions/runs/38964667415):
five ELF outputs were byte-identical, and 104 canonical outputs passed on each
host. Source and native-compiler pins remain unchanged. This GO applies only to
the current native profile and protected proposal. Final raw-metadata
verification, exact-version SDK production authentication/readback, four final
consumer builds, documented installation/uninstall/recheck, final Cargo
linkage, licence review and independent R1-A7 review remain open. R1-A8
publication/readback/two-host replay remains mandatory after A1-A7. R1 is not
release-qualified, no SDK release has been published, and this status update
does not change any acceptance criterion, resource policy, baseline identity or
historical result.

The [2026-10-16 portability follow-up](r1-portability-follow-up-20261016.md)
records the expanded C-SDK patch scope, direct original-input readback and
the successful macOS complete shared-producer counterproof and remaining two-host
derivation gates. A prepared source patch or a macOS-only
probe does not close R1-A6. Derived C-SDK bytes require their own component
identity and complete affected release qualification before publication.

The [protected SDK producer attempt of 2026-10-16](r1-sdk-producer-20261016.md)
failed after successful Cargo prerequisites because the source-frozen reports
bound the earlier resource policy. Refreshed reports and early validation
prepare a new attempt; they do not establish SDK or R1 acceptance.

## Authority and authorised amendment

This repository owns the ami-rust SDK and its host integration. Fabian explicitly
authorised an independent ami-rust entry point in this repository on 2026-10-15,
with the planning change recorded here first and protected AROS-NX/aros-tools
checkouts unchanged. His follow-up requests using standard rustup/Cargo as far
as practical to minimise maintenance. A thin standalone verification/build CLI is now a development prototype alongside
the measured standard Cargo path; the installer has passed local candidate qualification; production release authentication remains open. On 2026-10-15 Fabian separately authorised a public source repository. On the same date Fabian additionally authorised SDK publication once all release acceptance criteria pass. This is a conditional authorisation; it is not evidence that the release gates passed.

For M2/R1 host ownership and entry-point naming, this file supersedes the
external initiative revision 8 requirement for `aros cargo`. The external plan
continues to define unchanged M0/M1 and other initiative strands. It has not
been edited. The host-entry-point amendment retained the acceptance bar. On 2026-10-15 Fabian explicitly authorised the narrow R1-A2 metadata comparison amendment below; every other acceptance criterion and sealed campaign/runtime budget remains unchanged. A later prospective hosted-resource decision is documented below. A CLI adapter,
Cargo configuration, linker adapter or custom toolchain registration must meet
exactly the same lock, integrity, host, runtime and release requirements.

Base document: `AROS-NX/docs/plans/ami-rust-nxpk-initiative-plan.md`, revision 8.
Base SHA-256: `8e0f9bc4a42bb0ca84187f9fb96bc1fea106ba9ee606cdb4945c8b50a9770d65`.

## Integration and maintenance constraints

- Keep SDK/runtime/host-integration ownership and release versioning in ami-rust.
  aros-tools is not a required SDK frontend. Existing pinned collector/compiler
  prerequisites retain their producer identities and separate provenance.
- Prefer upstream rustup, Cargo, conventional project configuration and a small
  installation/verification/linker boundary. Do not build a second package
  manager, dependency resolver or general build orchestrator.
- A local `rustup toolchain link` registration is distinct from official
  `rustup target add` distribution. Do not advertise official AROS target support,
  full `std`, automatic updates or native AROS-hosted Rust/Cargo.
- Do not claim that a common prebuilt sysroot removes the need for a Cargo fix
  until cross-host archive and executable comparisons pass. Any frontend patch
  is a separately identified, reproducibly produced and audited tool input; it
  must not overwrite installed upstream toolchains or weaken acceptance.
- Freeze the chosen interface before final qualification. Include all helper
  sources/binaries, interpreter dependencies, configuration and producer hashes
  in the manifest and maintenance inventory. Upstream acceptance is not assumed.
- Small source, generator and build-recipe portability patches are authorised
  under [repository memory](../AGENTS.md). Preserve original pins, identify every
  derived component, and requalify the affected release criteria on both hosts.
  Never rewrite finished compiler metadata or native archives to remove paths.
- The immutable boot/ABI baseline remains unchanged. Current application-memory acceptance follows [memory policy](memory-policy.md); old campaigns retain their original numeric gates. New hosted CI phases use the recorded runner profile.
  Final campaign evidence is separate from M1; the old closed M1 clock is never
  reused. The separate 2026-10-15 campaign uses one 5,400-second clock, including failed attempts. Its results do not change these acceptance criteria.
- nxpk is out of scope. The owner’s conditional publication authorisation applies only after R1-A1 through R1-A7 pass; public readback and two-host replay remain mandatory under R1-A8.

## Hosted CI and conditional publication amendment (2026-10-15)

The owner selected standard GitHub-hosted runners and one public ami-rust
repository. The proposed temporary/self-hosted runner and private companion
repository design is retired. No runner was registered, installed or started.
The additional private `metaneutrons/ami-rust-ci-inputs` repository was deleted
at the owner's explicit request after its complete history and both input
archives were verified and preserved locally. Its two deploy keys were revoked,
its two `release` environment secrets removed, and authenticated API readback
returned HTTP 404. The local retirement receipt is
`qualification/r1-auth/preparation/private-retirement.json`.

Build scripts, complete input pins, packaging data and redistributable dependency
sources belong in the ordinary source repository. The full compiled C-SDK's
source/notice review now covers all 2,835 prerequisite SDK files, with the full
corresponding-source capsule, preserved vendor archives and dated portability
patch record. The adjacent [source-availability notice](../release/portable-csdk/SOURCE-AVAILABILITY.md)
and [change record](../release/portable-csdk/CHANGES.md) address the concrete APL
documentation conditions. Actual public source availability must be verified
after integration. This review does not establish SDK release acceptance.
The complete selected Rust vendor tree is 3,070 files / 39,739,700 bytes;
its newly prepared exact archive is 3,264,952 bytes, SHA-256
`84fb6e3e1710f13e85450cce1db541c3967520f996a3f17efbd5a7a8345b1c7e`.
The earlier M0 vendor archive omitted 290 selected files and is not an accepted
substitute. No baseline or selected input bytes changed.

The owner authorised measuring standard hosted resources first and, if needed,
prospectively revising CI resource requirements. This does not retroactively
waive a failed budget or silently change the existing 16 GiB physical-RAM /
24 GiB free-disk preflight. The manual capacity workflow measures actual host
RAM, free disk and interpreter identity without SDK inputs, signing or publication.
A nominal provider disk specification is not a measurement of available free disk.
Any revised supported host profile and transient CI storage/time allowance must
be concretely recorded before admitting an SDK build; the existing guest, ABI,
application memory and deterministic-output limits remain unchanged.

The current R1-A6 clock remains fixed at 5,400 seconds including failed/rejected
preparation and 300 seconds reserved for review. It is not reset by these decisions.
R1-A6 remains OPEN until a protected hosted producer, actual production signatures
and provenance, and independent consumer verification all pass. The current
signature-verifier and producer drafts are not qualified delivery code.

Fabian's conditional SDK publication authorisation now removes the requirement
to ask again after all gates pass. It does not permit publishing a failing or
incompletely qualified candidate. R1-A8 still requires public byte-for-byte
readback, signature/provenance verification and the complete consumer replay on
both supported hosts before the release is promoted as supported.

## Portable C-SDK production amendment (2026-10-16)

The original C-SDK remains immutable. The separately identified derived archive
and profiles in `release/portable-csdk/spec.json` are candidate inputs until
complete two-host qualification passes. Each protected host producer regenerates
all affected headers, native objects and pkg-config metadata, verifies the full
2,835-file profile and golden archive identity, and uses its fresh output.
Consumers provision the exact derived archive from `release/inputs/` at the
authenticated SDK source commit. Corresponding source, licence notices and
versioned patches accompany those repository prerequisites. They do not add
another asset to the signed SDK bundle or change its 32 MiB limit.

The complete shared producer passed on macOS with full Python/descendant resource
measurement and the full 825-member original-prefix counterproof. The subsequent
current-source protected two-host proposal passed in
[run 38964667415](https://github.com/metaneutrons/ami-rust/actions/runs/38964667415):
five ELF outputs were byte-identical, and 104 canonical outputs passed on each
host. The [R4 qualification record](../release/candidate-r4/qualification.json)
records the current native-profile GO. Exact-version SDK authentication and
independent final consumer replay remain required. The detailed scope and
immutable evidence references are in the [portability follow-up](r1-portability-follow-up-20261016.md).
No numeric release gate, old campaign result or baseline identity is changed by this edit.

## Production consumer preparation follow-up (2026-10-16)

R1-A5 remains open for the real production trust route. The inherited local
candidate's 12-command installation recipe remains valid evidence within its
scope, but CI-only prerequisite setup does not establish a usable fresh-user
installation. Add an executable documented preparation path for pinned Python,
GH/Cosign and trust roots, a locally generated external policy, all six verified
component roots, and selection.json. Keep the existing 12 signed SDK commands.

Use the exact publisher source/workflow commit selected through the trusted
public source channel; require a clean matching source checkout. Do not derive
that trust anchor solely from the unverified candidate, accept its bundled test
policy, or simulate a protected GitHub environment on a user's computer.
Share existing download/extraction/inventory and source-policy logic between
consumer CI and the preparation entry point. This adds no resolver, automatic
update service or second package manager. No installed upstream Rust toolchain
or protected source checkout is modified.

Acceptance additionally requires verbatim execution of the documented preparation
and original SDK recipe on both supported hosts, positive verification before
extracting bundled Cargo, rejection of wrong source/workflow policy and corrupted
inputs before installation, complete six-component inventory checks, and an
executable reuse check after uninstall. Missing/altered prerequisites require an
explicit fresh preparation root; no silent replacement is permitted. Align the
public quickstart and interpreter requirements with the authenticated production
recipe. Existing resource limits, baseline and all R1 criteria remain unchanged.
Cold preparation retains the 6 GiB RAM / 24 GiB free-space admission on its
managed STATE volume. Reading source pins does not admit a different read-only
source volume for builds. The post-uninstall check performs no provisioning or
build; its temporary source-SDK extraction is capped at 512 MiB and requires
560 MiB free scratch space including existing log/output ceilings. It preserves
6 GiB physical RAM, 4 GiB observed RSS, 12 GiB managed work and 20-minute command
limits. The complete preparation CLI is itself bounded to 20 minutes in hosted
replay; this is stricter than only timing its individual child commands.
The evidence review is retained as
`qualification/r1-hosted/preparation/fresh-consumer-documentation-review.json`.

## Follow-up acceptance record (2026-10-15)

The remaining-gates campaign has its own single 5,400-second clock, including failed prototypes, resource accounting, independent review and verified recovery. It does not reopen or replace the sealed third campaign. See its final receipt for the measured elapsed time and storage charge. Stop test execution at 5,100 seconds; reserve 300 seconds for review.

- Delivered candidate: `0.1.0-rc.3-local`, manifest SHA-256 `a3da1702f6d5899818c72e6e42fdcbfefc0268f31deff181aba49797e6666d85`. Its SDK archive and all SDK files are unchanged from the full 20-build consumer candidate (`73fa0401f2f32d30011059a37f1602667ef3b1615c9c61eacfdfd32ee02d4e62`). Only the project generator and quickstart were corrected.
- Two hosts each replayed the complete 12-command five-variant recipe in two clean roots. All 104 canonical outputs per root match the qualified R3 comparison for the corresponding host. The authorised cross-host metadata distinction remains in force.
- The initial external-path demo projects failed byte reproduction. The corrected relative SDK-source snapshot recipe passed in four fresh roots, with all 15 canonical project outputs byte-identical across hosts. Failed attempts remain in the evidence.
- All 22 installer fixtures pass on each qualified host and on both protected public source CI runners. Six project-copy positive/counter-probes pass. Full post-uninstall prerequisite inventories pass (12,549 macOS files; 12,559 Linux files).
- First-party licensing is MIT OR Apache-2.0. AROS-derived declarations retain their original terms. The candidate includes 83 complete licence texts, a 57-package SPDX inventory and a verified 341-file AROS corresponding-source capsule. The independent candidate licence/source decision is PASS for qualification.
- Native post-install smoke and final timing/capacity/recovery outcomes are recorded in the follow-up receipt. Existing full memory/diagnostic evidence transfers only through exact unchanged SDK/native artifact hashes; the new demo smoke makes no new memory claim.
- Public GitHub source CI tests the installer. It does not build/sign the SDK or establish SDK producer provenance. R1-A6 and complete R1 acceptance remain open; no SDK release was published.

## Acceptance criteria

<a id="m2"></a>

### M2 — Locked host runner and SDK selection

**Dependencies:** M1.

**Outcome:** The delivered ami-rust Cargo-facing SDK entry point builds native artifacts from project-locked SDK inputs on both initial hosts. Its exact executable/configuration and command are frozen with the release manifest and executed verbatim for acceptance.

- **M2-A1 — two-host replay:** Clean macOS Apple Silicon and Linux x86-64 build the same example with committed dependency locks and recorded target-nightly/SDK identities; run each artifact through M1. No manual exports or global active SDK are required. Explain differing hashes; claim byte reproducibility only if measured.
- **M2-A2 — selection integrity:** Missing locks/components, altered SDK manifests, compiler/schema mismatch and incompatible linkers fail before build acceptance. No silent download/selection or host-toolchain change. Document explicit provisioning, offline replay and actionable diagnostics.
- **M2-A3 — separation:** Host commands retain their compiler contract; targets use separately pinned nightly/`rust-src`. CI identifies both and checks locks. Forwarding, exit status and artifact discovery have positive/counter-probes on both hosts.

<a id="sdk-r1"></a>

### R1 — Independent first x86-64 ami-rust SDK release

**Dependencies:** M1 and M2 accepted for the final SDK inputs; accepted runtime-strand M0 evidence and G1 authorisation recorded in this repository. No dependency on M0 OS/storage feasibility, M3-M7, `nxpk` packages, repository protocol, network/TLS, GUI or atomic OS updates.

**Outcome:** A self-contained, versioned cross-development SDK release candidate for native PC x86-64 AROS, usable from macOS Apple Silicon and Linux x86-64, with one useful reference application and auditable support limits. This is not native `rustc`/Cargo running inside AROS, full `std`, multi-architecture support or a general-purpose safe Amiga SDK.

The minimum delivery comprises target specification, startup/FFI bridge sources, `amiga-sys`, `amiga-alloc`, bounded `amiga-os` interfaces, dependency locks, selected Rust/SDK/runner identities, build recipes, release manifest, documentation, and reference utility source plus its native executable. Existing compiler/SDK/runner prerequisites may be separately installed from pinned verified producer artifacts; they need not be redistributed or forked. Installation/build/run must work without `nxpk`, a package repository or boot modifications. R1 has its own version and artifact inventory; it does not wait for an `nxpk` release version or `aros pkg` features.

**Qualification state:** R1-qualified requires R1-A1 through R1-A7, dependencies and independent acceptance review. R1-A8 applies after R1-A1 through R1-A7 pass under the owner’s conditional publication authorisation recorded on 2026-10-15. Report a public release only after public readback and two-host replay pass. No gate is satisfied by this planning edit.

- **R1-A1 — frozen release contract:** The release manifest identifies an immutable candidate/version, source and dependency commits/hashes, dated target nightly and `rust-src`, JSON/schema/LLVM, SDK/compiler/linker/collector inputs, compatible ami-rust host integration version and upstream Cargo/rustup identities, and every delivered asset. Freeze the exact x86-64 CPU features, native image/boot profile, minimum AROS/library versions, host versions and supported API subset. The supported runtime matrix contains the measured M0/M1 profile; unsupported target/ABI/compiler/SDK combinations fail selection with documented status rather than silently building. No requirement references a future `nxpk` asset.
- **R1-A2 — reproducible consumer builds:** Using the exact delivered quickstart/recipe, an independent reviewer performs two clean builds in different absolute directories on each of macOS Apple Silicon and Linux x86-64. Source/dependency inputs are locked, and no ambient global SDK, manual exports or cached compiled objects are needed. All four builds produce byte-identical canonical native reference executables, every native bridge/runtime object, and every non-`lib.rmeta` member (including symbol indices and `.rmeta-link`) of each library generated by the SDK release recipe. Complete `.rlib` files and `lib.rmeta` bytes must additionally match between the two clean directories on each host. Cross-host `lib.rmeta` is qualified separately, with unchanged raw archive/member hashes, strict identification and review of the host-proc-macro dependency differences, successful downstream consumption, and actual Serde `Serialize`/`Deserialize` derive expansion and positive/negative round-trip probes on both host builds. Every unexpected metadata difference or changed native/index member fails qualification. No metadata is edited, stripped, normalised or assigned a fabricated compiler identity; separately provisioned compiler/SDK prerequisites retain their own verified producer hashes; timestamps/paths are controlled by the recipe, not removed ad hoc after a mismatch. Host binaries are compared only within their own host profile. Signatures/attestations are separately verified and excluded from deterministic payload comparison. An altered SDK/lockfile or wrong target compiler fails the build gate; provisioning failures leave a usable prior host setup. Offline replay succeeds after explicit verified provisioning, without contacts to `nxpk` infrastructure.
- **R1-A3 — final-artifact runtime qualification:** Build and run the M1 ABI/allocator/failure/lifetime suite through the released runner against the exact SDK candidate. Inspect delivered ELF headers, entry bridge, loadable sections and relocation types, and load/run the utility built on each host in the pinned native QEMU image. Each completes ten consecutive invocations with expected output/status. Deliberately unsupported relocation or malformed ELF fixtures are rejected by loader/compatibility qualification rather than counted as runnable artifacts; the shell remains usable. Re-exercise over-alignment, forced OOM, panic and failed library-open cleanup on final inputs. Run and document the mandatory standalone SDK dependency probes from M1-A4 on the final inputs; these do not select package protocols or imply arbitrary crate compatibility.
- **R1-A4 — useful reference application:** Ship a native read-only SHA-256 file-checksum CLI using the released Rust allocation and DOS I/O wrappers, not only a diagnostic banner. It accepts multiple paths including spaces, reads files in bounded chunks, emits deterministic hashes and reports failures with nonzero status without modifying input files. On artifacts from both hosts, compare output with an independently generated golden manifest for empty, one-byte, binary and 1 MiB fixtures; exercise missing/unreadable files and injected read error/OOM. Record unchanged input hashes/attributes and continued shell usability. No download, package format, network stack or OS update is needed to demonstrate its usefulness.
- **R1-A5 — documentation and maintenance:** Deliver and execute verbatim installation, clean build and utility-run instructions on both supported hosts. Provide a minimal new-project example, target API reference, unsafe-boundary/task-affinity notes, compiler/SDK compatibility table, panic/OOM semantics, troubleshooting and explicit exclusions (`std`, native compiler, other CPUs/OSes and unqualified hardware). Document host uninstall/restore without deleting unrelated SDKs. A named maintainer owns dependency/security intake and compiler/SDK upgrade qualification; changing qualified inputs requires compatibility evidence before updating the supported matrix, not a floating nightly or an invented support-duration promise.
- **R1-A6 — independent release integrity:** The SDK/reference-executable artifact set uses hardened binary-release controls independently of M7: commit-pinned build actions, protected publication credentials, asset checksums, signatures, provenance attestations, dependency/SBOM inventory and license/redistribution review for shipped bridge/SDK/runtime/dependencies. A clean-room consumer verifies every declared asset from its recorded producer identity, installs the SDK without package-manager support and runs the utility. A modified archive/executable, missing declared asset or inconsistent manifest fails verification before acceptance. Publisher private keys and local absolute development paths are absent from distributed payloads; reviewer records actual verification identities/results rather than assuming trust from filenames.
- **R1-A7 — independent acceptance and limits:** A reviewer other than the artifact author maps R1-A1 through R1-A6 and inherited M1/M2 criteria to durable final-candidate evidence, including artifact hashes, host/guest matrices, actual RAM/code-size measurements under the current memory policy and positive/counter-probes. Historical experiment quotas do not reject otherwise valid applications. Include a support statement in the unpublished candidate documentation confined to the qualified PC x86-64 QEMU profile; physical machines require additional evidence before being advertised. Unresolved `nxpk`, repository, GUI or OS-atomicity criteria are listed as outside this release and do not block R1; unresolved SDK ABI, runtime, reproducibility or provenance failures do block it. Mark R1-qualified only when all relevant evidence passes; leave other milestone issues open.
- **R1-A8 — separately authorised publication:** After explicit publication authorisation, publish the qualified SDK/reference assets and release notes under their own version without a `nxpk` prerequisite. Verify publicly retrieved payload bytes against R1-qualified hashes, signatures/attestations and complete asset manifest, then replay the documented consumer install/build/run from those retrieved assets on both hosts. Failed/incomplete publication must not be promoted as a supported release; preserve or restore the previously usable release channel. Record actual release URL and verification evidence as R1-published separately from R1-qualified. The owner’s conditional authorisation is recorded, but the still-open R1-A6 and R1-A7 gates prevent publication now.


Measured hosted capacity, remaining prerequisite blockers and the original resource proposal are recorded in the hosted preparation record (retained development record: `r1-hosted-ci-preparation-20261015.md`). This record does not close R1-A6.

The [public replay operator procedure](public-release-replay.md) describes the
read-only R1-A8 host workflow. Guest execution and final acceptance remain separate.

## Local storage amendment — revision 21 (2026-10-16)

Fabian explicitly replaces the small local file/directory quotas and fixed
4 GiB incremental / 6 GiB combined archive ceilings with realistic free-space
accounting. [Local storage policy](local-storage-policy.md) is authoritative for
new maintainer preparation, evidence and backup operations. Keep at least
32 GiB free on each affected volume after the estimated additional peak of a
large operation. Ordinary source, documentation and licence edits/copies use
a session-level free-space check; they require no per-file reservation ledger.
There is no fixed cumulative local archive quota. Retain all original evidence,
failed attempts, hashes and backups. Historic resource results and clocks are
unchanged. This amendment supersedes only the local retained-storage part of
the earlier decision below; hosted RAM/workspace/log/time/remote-artifact limits,
consumer installation requirements and AROS ABI/boot baseline remain unchanged.
Application-memory acceptance follows [memory policy](memory-policy.md).
No release gate is closed by this amendment.

## Prospective hosted resource decision — revision 16

After the completed standard-host survey, the owner’s instruction to measure and
if necessary redefine runner resources is implemented in `release/ci-resources.json`.
This decision applies before the new hosted campaign executes SDK production;
it does not revise prior pass/fail, peaks, retained holdings, or clocks.

- Minimum physical RAM: 6 GiB; minimum free disk remains 24 GiB.
- Per build: two jobs, 1,200 seconds, at most 4 GiB observed aggregate RSS and
  12 GiB workspace. The RSS ceiling is stricter than the historical 8 GiB cap.
- Historical retained-evidence adoption (superseded for new local work by revision 21):
  retained ami-rust evidence, including local files, Git objects, backups,
  remotely retained source/proof copies, uploads and reservations: at most
  4 GiB incremental and 6 GiB combined with the unchanged conservative M0 charge.
  The former 2/4 GiB limits remain the authority for the sealed prior campaigns.
- Transient managed hosted workspaces: at most 12 GiB per job, two jobs concurrently,
  24 GiB globally. Every archive, source/prerequisite/checkout, cache, target,
  staging tree and tool-controlled HOME/temp directory counts. A receipt must
  prove retirement before a transient admission is released; retained uploads
  additionally count against retained evidence. No existing holding is discarded.
- The new phase retains one 5,400-second campaign clock with 300 seconds for
  review. Its preflight is conservatively charged 600 seconds. No earlier clock
  is restarted. A resource admission is not qualification.

The SDK host preflight now accepts an explicit manifest-bound hosted profile and
keeps the legacy 16 GiB/24 GiB requirement for manifests without that profile.
Newly supported profiles must cap build RSS at 4 GiB. Real positive/counter
admission probes cover the measured hosts, exact RAM/disk boundaries, legacy
refusal, malformed schemas and oversized RSS. The actual hosted builds still
must pass the full R1 criteria; changing a host helper does not transfer native
or reproducibility evidence without an exact output comparison.

The AROS baseline/ABI, guest RAM, supported stack profile, loader/startup
coverage, diagnostics and native invocation criteria remain unchanged. Current
application heap and code-size acceptance follows [memory policy](memory-policy.md),
which supersedes the earlier experimental quotas. nxpk is out of scope, and
protected AROS-NX/aros-tools checkouts remain untouched.

## First protected hosted prerequisite result and portable runtime correction

The first protected two-host Cargo prerequisite run is FAIL as a matrix:
Linux completed within the admitted per-build ceilings; macOS refused the
runner-provided Python hash before creating work. The correction pins a
standalone CPython 3.12.15 archive and executable for each host, includes its
owned prefix in workspace accounting and preserves failure metadata before
cleanup. Both archives were hash-checked and the Mac runtime was executed
locally; a successful corrected hosted matrix is still required. The current
campaign clock is unchanged and does not admit another complete producer run.
No SDK production, production signature acceptance or SDK publication follows
from prerequisite success. See the qualification record (retained development record: `r1-hosted-ci-qualification-20261015.md`).

## Timing scope correction — revision 16

The owner clarified that the 90-minute limits apply to individual concrete
qualification campaigns. They are not an overall preparation or R1-project
time limit and do not impose repeated permission gates on authorised work.
The earlier closed clocks, FAIL results, peaks and evidence remain unchanged.
Each new test campaign records its own start, scope, failures and 300-second
review reserve before execution. Preparation can continue outside those
measured test windows. Baseline, runtime, host resource and publication
acceptance criteria remain unchanged. The owner said Go to completing R1.

## Corrected prerequisite result and relocatable inventory (2026-10-16)

The protected [corrected Cargo prerequisite run](https://github.com/metaneutrons/ami-rust/actions/runs/38860315967)
passed on both standard hosted runners at source
`ea0cf65e46d56b6e7b8154e0ce1369a7b33b1d2b`. macOS took 947.123 seconds,
with 2,043,133,952 bytes observed aggregate RSS and 3,832,518,210 managed bytes;
Linux took 590.195 seconds, with 2,460,196,864 bytes RSS and 4,343,563,168
managed bytes. Both cleanup receipts report zero remaining managed work and
Python-runtime bytes. API artifact digests and all receipts were read back.
The concrete campaign closed within its prospective 90-minute limit. This
qualifies the Cargo prerequisite only; SDK production and R1-A6 remain open.

The original Rust prerequisite inventories inadvertently included five
installation-dependent administrative files: `lib/rustlib/install.log` and
the four `manifest-*` records for cargo, rustc, rust-src and host rust-std.
They encode the installer's local prefix. The explicit production candidate
omits exactly these five records from each Rust profile and deletes exactly
those files from each freshly provisioned owned prefix. Every remaining file
and symlink is still subject to the complete pinned component inventory.
Compiler, libraries and Rust source bytes are unchanged; no compiler metadata
is rewritten. Nine packaging fixtures pass. Fresh SDK production and two-host
native comparison must still establish that the corrected inventory is usable.

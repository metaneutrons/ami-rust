# Release qualification status — 2026-10-17

R1 remains open, and no ami-rust SDK GitHub Release has been published. The
current native profile received technical GO on its exact inputs and supported
profile in the [R4 qualification record](../release/candidate-r4/qualification.json)
(SHA-256 `c5e559f592c7300b502ebf976ecd5b65c9191a130dbc2f7b5c9ed68a7045982c`).
The native run completed all 155 cases, plus Linux-derived-output checks and
malformed LoadSeg, in 2,641.44 seconds with no exceptions. The immutable
boot image, ABI and guest profile are unchanged. The zero-allocation result
applies to regular, non-injected SDK-owner diagnostics. Declared positive
controls intentionally allocate nine times per full/large phase; their 36
allocations are reported separately.

The latest normal SDK attempt from source `182f7eae` failed in
[run 38992120851](https://github.com/metaneutrons/ami-rust/actions/runs/38992120851).
Linux completed production and its source-bound artifact readback passed.
macOS stopped during C-SDK derivation after 1,206.794 seconds at the unchanged
1,200-second command limit. Assembly, authentication, consumers and complete
transport authentication were skipped; no final native campaign started.
The preceding [run 38989581905](https://github.com/metaneutrons/ami-rust/actions/runs/38989581905)
failed artifact-storage admission before either SDK producer started. Both
failures and their clocks are retained.

[PR 43](https://github.com/metaneutrons/ami-rust/pull/43) combines workspace and
log accounting into one complete inventory per root and sample. It preserves
all resource limits, process monitoring and C-SDK proof commands. The exact
merged source passed [two-host source CI 38995796330](https://github.com/metaneutrons/ami-rust/actions/runs/38995796330).
Local inventory measurements do not establish hosted C-SDK completion. Fresh
versioned SDK production, authentication, four consumer builds, final native
qualification and independent R1-A1 through R1-A7 acceptance remain required.

The normal 0.1.0 SDK campaign from source `570ff730` failed in
[run 38981262735](https://github.com/metaneutrons/ami-rust/actions/runs/38981262735).
Both host producers and the common unsigned assembly succeeded; the five native
payloads and source SDK archive matched between hosts. Both authentication jobs
then failed at GitHub's first attestation ingestion because `publisherPolicy`
was placed in the standard SLSA run-metadata object. Consumers and complete
transport authentication were skipped. The source correction places the same
signed policy in `buildDefinition.internalParameters` and retains every exact
policy check. Local tests and the upstream protobuf parser do not establish
successful provider ingestion: fresh protected authentication and all remaining
consumer, native and release gates are still required. This failed campaign is
retained and does not qualify R1.

The earlier protected two-host proposal passed in
[run 38964667415](https://github.com/metaneutrons/ami-rust/actions/runs/38964667415)
from source `1d0fe4f`: five ELF outputs matched byte-for-byte, and the 104
canonical-output comparison passed on each host. The source and native-compiler
pins are unchanged. This proposal and the native-profile GO do not establish a
qualified SDK release. Final raw-metadata verification, exact-version SDK
production authentication/readback, four final consumer builds, documented
installation/recheck, final Cargo linkage, licence review, independent A7
review, and A8 publication/readback/replay remain open. See the
[revision 24 repository plan](m2-r1-plan.md) for acceptance status.

The [prospective memory change](memory-policy.md) removes artificial application
allocation/heap and generic ELF size quotas. The current R4 native input has
its own runtime/memory qualification; the following R3 evidence remains
historical and cannot substitute for that result.

The inherited local R3 candidate passed its four clean consumer builds,
new-project builds, installation/deinstallation and native runtime, memory and
allocation-free diagnostic matrix on the pinned x86-64 ABI-v1 QEMU baseline.
Those records retain their exact artifact identities and qualification-only
signer. They establish no production publisher identity. Evidence transfers to
new candidates only through verified unchanged artifact bytes and scope review.

The refreshed protected Cargo prerequisite builds passed on both standard hosted
runners in [run 38914054466](https://github.com/metaneutrons/ami-rust/actions/runs/38914054466),
using the reviewed host-path remapping supervisor. Both complete producer reports
passed the strict input/resource/helper validation. The macOS Cargo binary has a
new identity; the Linux binary retains its previous identity. This prerequisite
success does not qualify an SDK or transfer historical native results.

The subsequent complete [protected proposal 38922417085](https://github.com/metaneutrons/ami-rust/actions/runs/38922417085)
failed. Linux completed all five variants in two fresh roots; macOS stopped
before SDK compilation because its newly built Cargo differed from the frozen
prerequisite receipt. The [Cargo context diagnostic](hosted-cargo-context-probe.md)
preserves both actual binaries and build contexts for investigation. In
[run 38933076655](https://github.com/metaneutrons/ami-rust/actions/runs/38933076655),
Linux reproduced its frozen bytes in both contexts. macOS reproduced the two
previous identities: twelve linker-generated bootstrap debug-map paths differed
with the work root. Its driver separately exceeded an unnecessary 256 MiB
self-memory guard after preserving both binaries. That failed result is retained;
the policy-derived driver guard and Darwin linker-path generation are corrected
in source. Fresh protected builds must prove complete raw byte equality before
selecting any new Cargo reference. No new Cargo reference identity or native
acceptance follows from the diagnostic or this source edit.

The complete original and derived C-SDK prerequisites, corresponding source,
patches and selected vendor archive are public repository inputs with their
own pinned identities and preserved notices. The earlier protected
two-host proposal passed in [run 38964667415](https://github.com/metaneutrons/ami-rust/actions/runs/38964667415):
five ELF outputs matched byte-for-byte, and the 104 canonical-output comparison
passed on each host. Source and native-compiler pins and the qualified boot
image, ABI and guest profile are unchanged. Exact-version production
authentication and final consumer replay remain open.

The [native reference follow-up](r1-native-reproducibility-20261016.md) preserves
the failed second protected proposal and its two-root dependency-output mismatch.
A local four-build investigation reproduced the path-dependent output and then
obtained 35 byte-identical outputs with the source/build-recipe correction. The
fix is merged. The subsequent protected two-host proposal and the current native
profile now have passing evidence for their identified inputs; the retained
failures remain historical. Final exact-version production and consumer/release
gates remain open.

The production path uses real GitHub attestations and Cosign signatures. Its
helper fixtures and public source CI establish control flow only. The current
protected proposal and native-profile qualification passed for their identified
inputs, but final versioned SDK production/authentication, raw-metadata and
publisher verification, tamper probes, the four final consumer builds,
documented fresh-user preparation/build/uninstall/recheck on both hosts, final
Cargo linkage and licence review, and independent R1-A7 acceptance remain open.
R1-A8 publication and public replay also remain open. The
[producer workflow](hosted-sdk-producer.md) cannot publish an SDK release.

[Production quickstart](quickstart.md) includes explicit pinned Python/tool
preparation, external source-policy selection, all six component inventories
and post-uninstall reuse verification. The exact-version authenticated
preparation and full consumer recipe still require final two-host replay.
Missing or altered inputs require a fresh preparation state; no ambient Rust
toolchain is replaced.

The adopted [hosted resource policy](../release/ci-resources.json) requires
6 GiB physical RAM, 24 GiB free disk, two jobs, 4 GiB aggregate observed RSS,
12 GiB managed work and 16 MiB logs. Concrete campaigns keep 90-minute clocks
with a review reserve. Historical failed clocks and earlier limits remain
historical evidence. The retained CI artifact pool stays at 512 MiB; the whole
seven-artifact candidate DAG must fit before either producer begins uploading.

Source, inputs and packaging data use this repository and standard GitHub-hosted
runners. The former private input repository was deleted at the owner's request;
its deploy keys and environment secrets were removed. No self-hosted runner
was registered. Protected AROS-NX and aros-tools checkouts remain unchanged.
nxpk, native AROS-hosted rustc/Cargo, full std, other CPU/ABI combinations and
physical hardware are outside this release's qualified scope.

The subsequent [paired Cargo qualification 38946497526](https://github.com/metaneutrons/ami-rust/actions/runs/38946497526)
passed on both hosts. All four exact reports pass strict canonical checks; the
two complete executables within each host match byte-for-byte and contain no
private host/build-root markers. Independent readback supports the refreshed
Cargo prerequisite identities. The earlier failures remain historical evidence.
Complete fresh SDK builds, new native runtime/memory evidence and the final
trust/consumer/release gates remain open.

# Release qualification status — 2026-10-16

R1 is not release-qualified. The owner authorised SDK publication only after
R1-A1 through R1-A7 pass; public readback and two-host replay remain mandatory
under R1-A8. No ami-rust SDK GitHub Release is published. The
[revision 22 repository plan](m2-r1-plan.md) is the acceptance authority.

The [prospective memory change](memory-policy.md) removes artificial application
allocation/heap and generic ELF size quotas. Changed native code requires a new
runtime/memory qualification; the following R3 evidence remains historical and
cannot substitute for that rerun.

The inherited local R3 candidate passed its four clean consumer builds,
new-project builds, installation/deinstallation and native runtime, memory and
allocation-free diagnostic matrix on the pinned x86-64 ABI-v1 QEMU baseline.
Those records retain their exact artifact identities and qualification-only
signer. They establish no production publisher identity. Evidence transfers to
new candidates only through verified unchanged artifact bytes and scope review.

The protected Cargo prerequisite builds passed on both standard hosted runners
in [run 38860315967](https://github.com/metaneutrons/ami-rust/actions/runs/38860315967).
The complete original and derived C-SDK prerequisites, corresponding source,
patches and selected vendor archive are public repository inputs with their
own pinned identities and preserved notices. The shared portable C-SDK producer
passed locally on macOS; latest-source two-host derivation remains unqualified.
The qualified boot image, ABI and guest budgets are unchanged.

The [native reference follow-up](r1-native-reproducibility-20261016.md) records
a concrete two-root dependency-output mismatch in the second protected proposal.
That failure remains open; retained prerequisite success cannot qualify its SDK.

The current production path uses real GitHub attestations and Cosign signatures.
Its helper fixtures and public source CI establish control flow only. Actual
protected SDK production, publisher verification and tamper probes, documented
fresh-user preparation/build/uninstall/recheck on both hosts, final Cargo linkage
and licence review, and independent R1 acceptance remain open. The
[producer workflow](hosted-sdk-producer.md) cannot publish an SDK release.

[Production quickstart](quickstart.md) includes explicit pinned Python/tool
preparation, external source-policy selection, all six component inventories
and post-uninstall reuse verification. Its new entry commands still require
actual protected two-host execution. Missing or altered inputs require a fresh
preparation state; no ambient Rust toolchain is replaced.

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

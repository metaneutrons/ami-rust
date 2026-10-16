# Release qualification status — 2026-10-16

R1 is not release-qualified. The owner authorised SDK publication only after
R1-A1 through R1-A7 pass; public readback and two-host replay remain mandatory
under R1-A8. No ami-rust SDK GitHub Release is published. The
[revision 23 repository plan](m2-r1-plan.md) is the acceptance authority.

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
own pinned identities and preserved notices. The shared portable C-SDK producer
passed locally on macOS; latest-source two-host derivation remains unqualified.
The qualified boot image, ABI and guest profile are unchanged.

The [native reference follow-up](r1-native-reproducibility-20261016.md) preserves
the failed second protected proposal and its two-root dependency-output mismatch.
A local four-build investigation reproduced the path-dependent output and then
obtained 35 byte-identical outputs with the source/build-recipe correction. The
fix is merged. A new complete protected SDK proposal and native qualification
are still required; the local diagnostic is not R1 acceptance.

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

The subsequent [paired Cargo qualification 38946497526](https://github.com/metaneutrons/ami-rust/actions/runs/38946497526)
passed on both hosts. All four exact reports pass strict canonical checks; the
two complete executables within each host match byte-for-byte and contain no
private host/build-root markers. Independent readback supports the refreshed
Cargo prerequisite identities. The earlier failures remain historical evidence.
Complete fresh SDK builds, new native runtime/memory evidence and the final
trust/consumer/release gates remain open.

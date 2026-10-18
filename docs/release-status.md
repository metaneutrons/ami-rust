# Release qualification status — 2026-10-18

**R1 remains open. The former `0.1.0` prerelease failed R1-A8 and must not be promoted
to stable/latest.** A corrected source-bound `0.1.0` candidate is required under the owner-approved
one-time version-reuse exception.

The retired candidate's immutable publisher source was
`e3d0adbd25aee4ad61a0506f7a451e69955cecba`, tree
`29957f13f2618accc31b4483e13914b5ed38867e`. At Fabian's explicit request,
the old public release (ID `416229826`), its six assets and tag `v0.1.0`
were deleted on 2026-10-18. API readback confirmed the release and tag absent;
the original release-tag protection was restored after the exact-tag exception.
Already retained local evidence remains historical; no public archive is required.

The corrected candidate source is
`b4ebb9cce5decd01616b75acf451d0eba9995ee3`, tree
`c5d9eed6b057ddadd17356801f8b3897e3e430dc`, merged through
[PR 58](https://github.com/metaneutrons/ami-rust/pull/58).
Its protected SDK [run 39121017959](https://github.com/metaneutrons/ami-rust/actions/runs/39121017959)
completed with all nine jobs successful, including both independent consumers
using the same Linux-authenticated distribution and their own host tools.
A separately bounded local recovery has now verified all eight exact workflow
artifacts, both producer readbacks, four consumer build roots, the inner and
outer signatures/provenance, and the installation, uninstall and licence
records. Independent distribution review found no open defect. The original
failed ZIP-download campaign remains preserved as a failed attempt.

Native qualification remains open. The first current-source attempt completed
the Linux-produced 48-case phase; the macOS-produced phase captured all 48
statuses but failed during host-QEMU evidence capture. A complete repeat uses
fresh evidence paths and controlled process input under the original deadline.
Neither that partial result nor a successful hosted workflow establishes R1
acceptance. The full native result, independent acceptance, public installation
and replay, and stable promotion remain required.

The following records describe the retired candidate and its failed public replay:

| Evidence | Actual result and limit |
| --- | --- |
| Protected SDK [run 39089771746](https://github.com/metaneutrons/ami-rust/actions/runs/39089771746) | Nine jobs passed; 32 prepublication M1/M2/R1-A1–A7 criteria passed independent review for e3 |
| Prepublication native campaign | 155 measured cases plus Linux derive and malformed LoadSeg passed on the unchanged ABI-v1/QEMU baseline |
| Anonymous public assets | All six files matched accepted sizes/digests; four GitHub attestation and two Cosign checks passed |
| Public [run 39100250839](https://github.com/metaneutrons/ami-rust/actions/runs/39100250839) | Failed on both hosts: mixed tool-metadata accounting; bootstrap cleanup permissions also failed |
| Public [run 39104753593](https://github.com/metaneutrons/ami-rust/actions/runs/39104753593) | Failed on both hosts: GitHub CLI `.local` state was counted as extra proof output |
| Complete local consumer diagnostic | Actual proof retrieval and cryptography passed after the CLI-state fix. It then exposed the publisher/consumer host conflation, including the frozen documented preparation command on macOS |
| Fresh public-input native replay | Not started; requires a successful corrected public consumer flow |
| Stable/latest release | Not accepted or promoted |

The common release bundle was authenticated under a Linux publisher run.
macOS consumers correctly select the macOS tools, but the old preparation
validator required that authenticated publisher run itself to be macOS. The
prepublication host tests used producer-matched per-host bundles and missed
this cross-host distribution case. A private replay-wrapper fix cannot make
the old signed source's documented preparation command pass unchanged.

The repair isolates CLI home/configuration/cache state from proof output and
binds the exact publisher run/attempt to the authenticated release producer.
Publisher and consumer host profiles are validated separately. The corrected
source requires complete version-bound qualification. Its protected workflow has
now exercised both supported hosts consuming the same authenticated distribution
bundle; the remaining independent and native gates are still open. Existing acceptance
criteria remain in force; old prepublication results do not substitute for the
new candidate or its public replay.

Fabian explicitly authorised reusing `0.1.0` on 2026-10-18; the proposed
`0.1.1` migration is withdrawn. The corrected candidate retains `0.1.0`, with
fresh source/input identities, signatures and complete qualification. The old
public candidate has been removed as requested. The exception does not waive
any R1 test or authorise promoting the failed bytes. See the
[version exception](release-version-exception-20261018.md). No complete corrected SDK
qualification, R1 acceptance or publication is claimed here.

The target remains native PC x86-64 AROS ABI-v1, with macOS Apple Silicon and
Linux x86-64 development hosts. The qualified 512 MiB QEMU profile remains
unchanged. Physical hardware, other CPUs/ABIs/Amiga OSes, AROS-hosted Rust/Cargo,
`std`, arbitrary crates, networking, GUI and nxpk remain outside this release.
See [compatibility](compatibility.md) and the [revision 25 plan](m2-r1-plan.md).

The [2026-10-17 status](release-status-20261017.md) and earlier failed campaigns
remain historical records. The generic allocation/heap/ELF quotas are not
reintroduced; current [memory policy](memory-policy.md) remains authoritative.

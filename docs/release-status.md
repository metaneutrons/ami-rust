# Release qualification status — 2026-10-18

**R1 is complete. The corrected `0.1.0` SDK is the stable/latest GitHub release.
All prepublication criteria and public replay checks passed independent review;
final anonymous downloads matched the six qualified release files exactly.**

The release source is `b4ebb9cce5decd01616b75acf451d0eba9995ee3`, tree
`c5d9eed6b057ddadd17356801f8b3897e3e430dc`, merged through
[PR 58](https://github.com/metaneutrons/ami-rust/pull/58).
The corrected [stable release](https://github.com/metaneutrons/ami-rust/releases/tag/v0.1.0)
has release ID `416548451`. Use its authenticated source and asset digests;
version alone does not distinguish it from the deleted earlier candidate.

| Gate | Current evidence |
| --- | --- |
| Protected SDK production | [Run 39121017959](https://github.com/metaneutrons/ami-rust/actions/runs/39121017959): all nine jobs successful; both consumer hosts use the same authenticated distribution and select their own tools |
| Prepublication native qualification | Complete 155 measured cases plus two checks passed on the unchanged ABI-v1/QEMU baseline; the earlier capture failure is preserved |
| Independent M1/M2/R1-A1–A7 acceptance | All 32 criteria passed; cross-host Rust metadata differences directly identified with the pinned compiler, without changing metadata |
| Anonymous prerelease bytes and authentication | All six release files matched accepted sizes/digests; four GitHub attestation and two Cosign checks passed |
| Public consumer installation/build/uninstall | [Run 39143613042](https://github.com/metaneutrons/ami-rust/actions/runs/39143613042), attempt 1: both supported hosts passed; independent review verified the retained archives, all four roots and preserved user/prerequisite state |
| Fresh public-input AROS runtime/memory replay | PASS: all 155 measured cases plus two checks passed independent review using the actual public consumer outputs and a distinct clock; the complete campaign closed in 2,188.69 seconds including preparation charge, without exception |
| Independent R1-A8 acceptance | Public assets, both consumer hosts and the fresh complete native replay passed independent review for the same source, release and asset inventory |
| Stable/latest release and final anonymous stable readback | PASS: release `416548451` is stable and latest; two anonymous identity reads and all six anonymous downloads matched the accepted source, asset IDs, sizes and SHA-256 values |

The [public evidence summary](evidence/r1-0.1.0.json) records the exact source,
producer and consumer runs, asset inventory, baseline, acceptance identities
and individual prepublication criterion results. It distinguishes qualification
from publication and does not treat a green workflow as native acceptance.

The local artifact-capture defects and earlier failed campaigns remain retained.
The public two-host result was recovered from the original downloaded bytes and
successful reader receipts after a private summary-writer error; it was not
obtained by rerunning CI, downloading replacement bytes or resetting its clock.
The host campaign closed inside its original budget. The final guest replay
uses a distinct prospective campaign with the same tests, baseline and resource
contract.

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
bundle. Current independent prepublication acceptance, fresh public-input native
replay, stable promotion and final anonymous readback are complete. Existing
acceptance criteria remain in force; retired candidate results do not substitute
for current-source evidence.

Fabian explicitly authorised reusing `0.1.0` on 2026-10-18; the proposed
`0.1.1` migration is withdrawn. The corrected candidate retains `0.1.0`, with
fresh source/input identities, signatures and complete qualification. The old
public candidate has been removed as requested. The exception does not waive
any R1 test or authorise promoting the failed bytes. See the
[version exception](release-version-exception-20261018.md). Corrected SDK
qualification, independent R1-A8 acceptance and stable publication are complete
as recorded above.

The target remains native PC x86-64 AROS ABI-v1, with macOS Apple Silicon and
Linux x86-64 development hosts. The qualified 512 MiB QEMU profile remains
unchanged. Physical hardware, other CPUs/ABIs/Amiga OSes, AROS-hosted Rust/Cargo,
`std`, arbitrary crates, networking, GUI and nxpk remain outside this release.
See [compatibility](compatibility.md) and the [revision 26 plan](m2-r1-plan.md).

The [2026-10-17 status](release-status-20261017.md) and earlier failed campaigns
remain historical records. The generic allocation/heap/ELF quotas are not
reintroduced; current [memory policy](memory-policy.md) remains authoritative.

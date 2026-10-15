# Standard hosted CI capacity — 2026-10-15

This is preparation evidence, not a protected SDK producer or R1-A6 acceptance.
The owner selected one public ami-rust repository, standard GitHub-hosted runners,
and conditional SDK publication after every release acceptance gate passes.

## Actual hosted measurement

[Capacity run](https://github.com/metaneutrons/ami-rust/actions/runs/38807604508)
executed the read-only survey from protected main
`e779d46d529bddc742b9d937e5461284916665f2` after
[PR #3](https://github.com/metaneutrons/ami-rust/pull/3) passed the required source
CI. Both survey jobs passed. This workflow performs no checkout, dependency
installation, SDK build, signing or publication.

| Profile | Physical RAM | Workspace free disk | Existing RAM gate | Existing disk gate |
| --- | ---: | ---: | --- | --- |
| macOS 26 ARM64 | 7,516,192,768 B (7 GiB) | 103,125,716,992 B | FAIL | PASS |
| Ubuntu 24.04 x86-64 | 16,766,414,848 B (15.62 GiB) | 92,126,691,328 B | FAIL | PASS |

The current preflight requires 16 GiB physical RAM and 24 GiB free disk. The
Ubuntu physical RAM reported to the guest OS is also below 16 GiB. The previous
survey's claim that a nominal 14 GB provider disk specification proves failure
of the free-disk gate was incorrect; actual free disk passes on both hosts.
Neither host is admitted to the existing unchanged producer profile.

The macOS Python 3.15.0 executable hash equals the selected qualified macOS pin:
`1955899cb535256cfa477d926d016819e52e747984722c44f76e39a4950fee0e`.
Ubuntu supplies Python 3.12.3, hash
`e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f`,
which is not the selected qualified Linux interpreter. No substitute interpreter
was accepted and no executable identity was fabricated.

Exact values and image versions are retained in
[the measurement receipt](hosted-capacity-20261015.json); original logs are
available from the linked public workflow run. The full preparation and recovery
history remains preserved locally.

## Concrete prospective resource proposal

A future hosted profile can be assessed with 6 GiB minimum physical RAM,
unchanged 24 GiB free disk, two build jobs, 1,200 seconds per build, a stricter
4 GiB aggregate observed RSS limit, and the existing 12 GiB workspace limit.
Retained R1 build receipts, including failed/superseded attempts, contain a
maximum observed RSS of 2,336,669,696 bytes and workspace of 2,808,530,761 bytes.
These observations provide a sizing basis; they do not qualify a new host.

The proposal is **not enabled or qualified**. A source/profile change, enforced
new limits and actual cold hosted producer/consumer evidence are required.
The existing 2 GiB global evidence accountant includes active remote copies;
selected host prerequisites alone add 850,260,621 / 1,093,791,084 bytes. The
remaining allowance cannot admit either complete new host input tree. Before
producer execution, a concrete prospective retained-proof/transient-workspace
contract is required; no temporary CI files have silently been exempted.
The sealed earlier clocks and this A6 clock remain unchanged.

## Remaining R1-A6 dependencies

- Provision the complete selected vendor tree (3,070 files) through the ordinary
  repository, with all notices; the newly prepared 3,264,952-byte archive has
  SHA-256 `84fb6e3e1710f13e85450cce1db541c3967520f996a3f17efbd5a7a8345b1c7e`.
- Complete the full C-SDK redistribution/source mapping before public check-in.
  It has 2,835 files, including 135 static archives; the accepted candidate review
  covers 23 linked members/startup and 341 corresponding-source files.
- Provision the pinned custom Cargo/bootstrap inputs and host interpreters.
- Qualify actual protected hosted SDK production, real signatures/attestations,
  independent consumer verification and every required counter-probe.
- Obtain independent R1-A1 through R1-A7 acceptance, then use the owner's recorded
  conditional publication authorisation and perform R1-A8 public readback/replay.

No SDK release exists. No baseline, AROS-NX or aros-tools checkout was changed;
nxpk remains outside scope. The rejected self-hosted producer and synthetic
signature adapter drafts are preserved as unqualified preparation, not shipped
or treated as gate evidence.

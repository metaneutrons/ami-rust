# RC0 acceptance — contracts and feasibility design

Date: 2026-10-19. Decision: **accepted for RC1 implementation** against
[plan revision 2](../rust-cli-cargo-migration-plan.md), source
`d7ac89004a8f805e6f1e3efaf9242fed976803ab`. Tracking: [RC0 #70](https://github.com/metaneutrons/ami-rust/issues/70),
[epic #69](https://github.com/metaneutrons/ami-rust/issues/69).

The reviewed design/probe deliveries are PRs 77–79. PR 78 qualified candidate
`5a1ad03bd50cdf0484c32efea03dfa614024c838` and merged at
`b16a025a7b3b1d072b1633e1f5cbd4d927fdd80e`. PR 79 qualified candidate
`f356132d31bd68515d3fd6cdb1b5ee50f1719c43` and merged at
`8777a4166ef5e988f7c21f3f10d8d2602fb4a9b1`. This record reconciles the older
partial survey snapshots; their measured outcomes and failed attempts remain
preserved.

| Criterion | Accepted evidence | Boundary |
| --- | --- | --- |
| RC0-A1 | [104-file task/removal inventory](python-dependencies.json), [actual producer closure](producer-executable-closure.md), all 523 registry source archives and 27 Cargo path inputs in the [source inventory](evidence/cargo-source-inventory/index.json). The corrected [native Ubuntu query](evidence/native-source-39173711603/result.json) selects 341 package identities and 36 build scripts, matching the reviewed identity sets; valid/altered lock controls and all 11 graph counterprobes pass. | Actual protected producer execution and removal of Python orchestration remain RC4/RC5. The supported C-SDK scope is explicit below. |
| RC0-A2 | [Machine contract](contracts-v1.json), [schema/trust/ownership decisions](contract-decisions.md), one frontend capability list, [36 pinned legacy files / 145 named oracle cases](legacy-fixture-pins.json), [host compiler and reviewed 29-crate lock](host-dependency-selection.md). Source/license checks and pinned advisory scan pass. The corrected 13 API tests pass on both hosts in [39173711594](https://github.com/metaneutrons/ami-rust/actions/runs/39173711594), alongside existing installer/package and 50 host contract/CLI cases. | The standalone lock is the reviewed development input. The production workspace/lock and feature changes must retain reviewed crate identities and receive their own tests/audit. Archive filesystem extraction, full schema enforcement and differential consumer behavior are RC1. |
| RC0-A3 | [Hosted integration 39170474195](https://github.com/metaneutrons/ami-rust/actions/runs/39170474195), [durable results and audit summaries](evidence/rc0-integration-39170474195/index.json), [activation/C generation recipe](rc0-integration-probes.md). Normal selected Cargo metadata/check/build succeeds for two fresh roots per host, including spaces; host build.rs regenerates C bridge/startup objects and Cargo's linker operation returns the audited final ELF. | This is the minimal design control. Production input/compiler guards, complete ELF auditor, five build variants and AROS runtime/memory acceptance remain RC1/RC2. |
| RC0-A4 | The same integration run and [Linux controls](evidence/rc0-integration-39170474195/linux-interpreter-controls.json) pass 12 cases. [macOS controls](evidence/rc0-integration-39170474195/macos-interpreter-controls.json) pass ten named routes with independent kernel observation of all ten, four interpreter positives and four exact-target EPERM refusals. Direct, descendant, absolute-path, shebang and C/libpython controls distinguish passing native execution from refused interpreter routes. | The macOS report remains PARTIAL for full production/OS shared-cache closure. The controlled-route mechanism is accepted; no universal detector for arbitrary static interpreter semantics is claimed. Reviewed source/build/dependency provenance and actual supported process trees must complete the later closure. |

All four native design outputs have size 342,136 bytes and SHA-256
`f43ba62f560fbca46f11486a95c433cabba83a24ba52bd8ed130cfa025524acd`.
Observed native-design peaks stay within the admitted 4 GiB RSS / 12 GiB
workspace profile: Linux 1,834,442,752 / 4,382,713,573 bytes; macOS
1,709,998,080 / 3,585,602,688 bytes. These experiment limits do not create
application allocation/heap/code-size quotas.

## Supported producer boundary

RC5 supports the existing bounded portable C-SDK derivation with its frozen
selected native inputs and outputs. The full upstream AROS Ninja build is
outside this supported producer. Its archived 72 Python command records
(nine RUN_PYTHON, 54 PYTHON_EXECUTABLE, nine direct scripts) remain inert
corresponding-source and recipe data, excluded from active execution. The
bounded producer may parse recipe data to select its reviewed native commands;
it must not execute the excluded graph.

Current Python orchestration and any selected interpreter-dependent derivation
remain RC4 replacement obligations. RC5 still requires actual two-host
no-Python producer/process/provenance qualification. Adding a full Ninja build
later requires a separately reviewed executable closure. This resolves the
survey's open choice without removing a previously supported producer or
changing native inputs; the plan explicitly preserves inert upstream sources.

## Interpretation and next delivery

RC0 accepts the design, contracts, development inputs and controlled feasibility
mechanisms. It does not accept a Rust consumer CLI, the full migration,
Python-free protected production, new AROS runtime behavior or a release.
Historical first-query run 39172161134 and first integration run 39169664621
remain FAIL. Their corrected successors do not rewrite those outcomes.

RC1 now implements the separate host workspace: shared core and one native
binary installed under both frontend names, then typed input validation,
authenticated acquisition, safe extraction, lifecycle/build behavior and the
full differential/two-host matrix. Active Python removal is accepted only at
the corresponding later gates. Existing releases, target compilers, the QEMU
ABI-v1 baseline and protected AROS-NX/aros-tools checkouts remain unchanged;
nxpk is excluded.

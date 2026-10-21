# RC1 acceptance — native Rust consumer tooling

Date: 2026-10-21. Decision: **RC1-A1–A4 are satisfied for RC2 implementation**
by source `4350aeae331dbccb190bc7be6938306644e4d4af`, tree
`25d3b14be3c779d34d713a47d405206b49cf9e82`. The acceptance becomes the execution
state in [RC1 #71](https://github.com/metaneutrons/ami-rust/issues/71) when this
record is merged. [RC0](rc0-acceptance.md) is already accepted. The authority is
[plan revision 2](https://github.com/metaneutrons/ami-rust/blob/d7ac89004a8f805e6f1e3efaf9242fed976803ab/docs/rust-cli-cargo-migration-plan.md#rc1--rust-consumer-cli-with-equivalent-behaviour),
not a reduced set of criteria. Tracking: [epic #69](https://github.com/metaneutrons/ami-rust/issues/69).

The protected [SDK qualification 39553656864](https://github.com/metaneutrons/ami-rust/actions/runs/39553656864)
attempt 1 succeeded with all nine required jobs. All eight original provider
ZIPs and job-log responses were retained before offline readback. Both native
consumer host artifacts are present. The complete [SDK readback](evidence/rc1-acceptance-20261021/sdk-readback.json)
validates transport, source, both protected signer bundles, the actual
consumer authentication route, interruption, lifecycle, native upgrade, matrix
and exact-byte metadata/runtime reuse. Its SHA-256 is
`b55d1b501c092db6dcc334a967f42bc8cff623dc7ac06b7611d924437d88b590`.

The [regular-CI readback](evidence/rc1-acceptance-20261021/regular-ci-readback.json)
binds [run 39549340970](https://github.com/metaneutrons/ami-rust/actions/runs/39549340970)
and [focused Linux run 39549340932](https://github.com/metaneutrons/ami-rust/actions/runs/39549340932)
to the same qualified tree. Their candidate commit `4d5579a6ea0a264970e728b3e5ebb77fb609df99`
and CI checkout `1ac5dd39312d769db03a8f9006046f0a5edc7246` differ from the SDK
commit; the exact tree and source hashes establish the content join. The
[final criterion join](evidence/rc1-acceptance-20261021/criterion-join.json)
rereads all 83 compiled inputs, six declared/base inputs and 31 regular-CI
source-map entries. Its SHA-256 is
`abc147d4295353bd769ea9e7ff77ce6182c87c5cf014c66a68eb5d7a5d808e10`.

| Criterion | Accepted evidence | Boundary |
| --- | --- | --- |
| RC1-A1 | Exact-source shared frontend capability ledger passes on both hosts with 13 implemented capabilities. The SDK lifecycle binds 54 Linux / 53 macOS command observations, raw exits/captures, input closures, CLI identities and native observer/enforcement reports. Both-host regular CI validates interpreter controls: 15 Linux and 12 macOS cases, including direct, descendant, shebang, embedded-runtime, restricted counterparts and native-positive routes. | Maintainer-side Python coordinates qualification. It is outside the accepted Rust consumer process tree. This accepts the reviewed source/dependency and process-enforcement mechanism for the supported commands, not a universal detector of arbitrary statically embedded interpreter semantics. |
| RC1-A2 | Each host passes 192 historical/current pairs: 131 parser, 50 filesystem, nine transaction and two receipt-lifecycle cases, with isolated fixture identities and raw decisions/exits/effects. These include duplicate keys, wrong identity/host/publisher, altered/missing files, unsafe paths/links, stale ownership pins and preserved user data. Both current SDK hosts pass the actual historical/native interrupted-prepare semantic pair, including unchanged retry refusal. | Common historical receipt-v1/v2 semantics remain distinct from the deliberate native receipt-v3 schema. The current typed parser and owned install/removal tests pass on both hosts; actual authenticated install, occupied-target refusal, wrong-pin refusal, removal and migration bind their produced digest and effects. The SDK artifacts do not duplicate the raw install-receipt-v3 JSON. |
| RC1-A3 | Each current host passes two fresh roots, five variants and ten builds, including paths with spaces. All 208 canonical artifact rows per host match the unchanged reference. The current raw dependency archive pins match the separately retained eligibility evidence; compiler/recipe/source/reference scope is unchanged. The final join preserves the separately qualified host-specific metadata and Serde-derive/runtime evidence. | Exact-byte historical runtime/metadata reuse is conditional on those current matches. No new guest-runtime run is claimed. No `.rlib` or compiler metadata was rewritten. |
| RC1-A4 | Both hosts pass actual revision `0.2.0-1` to `0.2.0-2` package replacement, old-state/new-owner refusals, old-package removal and retained recheck/offline replay, with 14 upgrade commands and four preservation checkpoints. Old/new state, projects/builds, global Cargo/rustup settings, unrelated SDKs and user data have matching protected snapshots. Published-v1 migration and package rollback/removal also pass. | The READY entry wrapper and the invoked versioned retained core are distinct paths. Actual replays use `retained/libexec/ami-rust/<package-version>/bin/ami-rust` with the authenticated old core digest. Removal is evidenced by the source-bound coordinator assertion and subsequent retained executions; no separate post-removal filesystem scan is claimed. |

## Deliberate schema and enforcement boundaries

The [contract decisions](contract-decisions.md) and [installation contract](native-installation.md)
define receipt-v3's host, core/CLI and publisher-report identities. Both-host
CI uniquely records passing receipt schema, exact-field, duplicate-key and
publisher-mismatch tests and the isolated native install/removal parent test.
That parent actually runs successful owned removal, extra-user-file refusal,
changed-SDK/stale-pin refusal, invalid-policy refusal and all-six-component
selection/recheck cases. Its ignored child listing is not counted as another
passing test. Historical Python is not claimed as a v3 oracle.

On Linux, migration reads the pinned legacy interpreter as inert identity
bytes. The CLI installs its irreversible TSYNC seccomp no-exec filter before
rendering either migration form. Source-bound CI tests check execve/execveat,
x32 and thread inheritance in an isolated child. The SDK observer separately
requires that exact inert-read path, no interpreter executable grant, no derived
execution subtree, denied interpreter-library loading and denied outbound
network. macOS uses its explicit sandbox interpreter denial. This is a
source/control/process-policy join; no raw syscall trace is claimed.

## Offline reader corrections and refusal controls

The final reader corrects representation assumptions without changing the
provider artifacts, target inputs, acceptance criteria or compiler metadata:

- Standalone published-transition/removal reports were serialized before the
  last native-upgrade preservation checkpoint. The producer shares one list;
  the final lifecycle contains exactly one additional unchanged row. The
  reader requires the complete ordered prefix, exact final row/name/archive
  pin and stable roots, with every other field exactly equal. It separately
  requires the complete native-upgrade reader.
- Linux and macOS adapter reports have different exact exit, executable-hash
  and library-denial field shapes. Both are checked against their pinned
  backend. The policy grants the exact `/dev/null` device for preparation and
  build phases; other phases do not receive that grant.
- READY/package pins identify `release.json`; project locks and build receipts
  identify the separate installed `contract/sdk.json`. Each retains its own
  digest binding. Component roots are the six exact provisioning-stage roots,
  rather than children of the installed SDK tree.

The [lifecycle reader controls](evidence/rc1-acceptance-20261021/lifecycle-reader-controls.json)
contain both actual host positives and 20 isolated semantic refusals. The
[upgrade controls](evidence/rc1-acceptance-20261021/upgrade-reader-controls.json)
contain both actual full upgrade positives and 16 isolated owner/argv refusals;
those helper controls do not claim repackaged, reauthenticated provider ZIPs.
The [composition control](evidence/rc1-acceptance-20261021/composition-reader-control.json)
refuses a synthetic failed raw Linux job even when the retained summary claims
success. The [regular-CI reader controls](evidence/rc1-acceptance-20261021/regular-ci-reader-controls.json)
refuse four altered semantic observations. The final criterion join additionally
refuses five wrong-source/missing-host/variant/pair-count/metadata cases.
Original failed reader attempts and SDK runs remain retained. A bounded
independent review confirmed the two-time report relationship and the
source-backed upgrade corrections; its retained report SHA-256 is
`d6b0e293733e4d6675cb1024d84ed7bb4ade7b23b353c6258f059b8b587ef750`.

## Capacity, retention and next delivery

The [measured unpacked consumer artifacts](evidence/rc1-acceptance-20261021/capacity-measurement.json)
are 30,400,420 bytes on macOS and 39,355,847 bytes on Linux. Both fit the pinned
64 MiB artifact / 63 MiB writer policy. The owner has authorized prospective
increases with measured headroom. This is evidence retention, separate from
SDK application memory and the unchanged per-command resource profile.

The [evidence index](evidence/rc1-acceptance-20261021/index.json) preserves these
result bytes and digests in the repository. Individual reader reports keep
their original `NOT_RC1_ACCEPTANCE` or pending-publication labels; this
criterion reconciliation supplies the reviewed milestone decision. Original
provider ZIPs, complete logs and reader sources remain retained separately.

RC2 now owns normal Cargo metadata/check/build, final ELF linking and the thin
compatibility facade. RC3 still requires a new public release and distribution
qualification. RC4 still replaces active Python maintainer/test/producer paths;
RC5 still requires the complete supported Python-free production/release and
rollback evidence. This accepts no SDK release, RC2, RC3, RC4 or RC5. The
qualified x86-64 ABI-v1/QEMU baseline and protected AROS checkouts are unchanged;
nxpk remains outside scope.

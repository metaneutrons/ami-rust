# Package channel status

Updated 2026-10-18. The original [SDK 0.1.0 release](release-status.md) is stable
and unchanged. APT and Homebrew are separate follow-up deliveries tracked by
[initiative #60](https://github.com/metaneutrons/ami-rust/issues/60).

| Gate | Current evidence |
| --- | --- |
| Package identities and ownership | [Delivery contract](distribution-package-contract.md); SDK 0.1.0, Debian 0.1.0-2, Homebrew revision 2 |
| Local cold adapter consumer | Preparation, new project, offline build, input check and R1-identical SHA utility passed in a fresh macOS 26 state; earlier failures retained |
| APT archive registration | [APT archive PR #26](https://github.com/metaneutrons/apt-archive/pull/26), merged after all required checks |
| Homebrew host policy | [Tap PR #70](https://github.com/metaneutrons/homebrew-tap/pull/70), merged after all required checks |
| Producer development preflight | Pinned verifier downloads, public SDK retrieval and deterministic package/metadata generation passed locally; exact publisher proof selection is frozen |
| Protected package production and staged readback | [39159711172/1](https://github.com/metaneutrons/ami-rust/actions/runs/39159711172): exact revision-2 public bytes, signatures, provenance and counter-probes passed |
| Actual package-manager lifecycle on both hosts | Linux passed; macOS install/build/remove/reinstall passed, but its active-keg query rejected valid retained versions after upgrade; unchanged candidate requalification required |
| Attested formula PR, qualification and tap readback | Pending |
| Signed public APT metadata, SHA512 by-hash, exact package and real client | Pending |

Neither channel is accepted as available until its public client gate passes.
The additional packaging release does not replace the default/latest SDK release.
Prospective instructions: [APT](../packaging/INSTALL-APT.md),
[Homebrew](../packaging/INSTALL-HOMEBREW.md),
[explicit user preparation](../packaging/README.md).

## Preserved first packaging attempt

Protected producer [39158406951/1](https://github.com/metaneutrons/ami-rust/actions/runs/39158406951)
passed package generation, signing, provenance verification and corrupted-input
counter-tests. Staging then failed because GitHub did not expose its private
draft through the release-by-tag endpoint. The tag `v0.1.0+packaging.1` and its
12 signed draft assets remain preserved. That draft was never made public and
neither APT nor Homebrew was changed by that run.

The next candidate uses packaging revision 2 with SDK 0.1.0 unchanged. Staging
uses the confirmed release ID and reconciles hidden drafts before creating a
release. Final public clients also preserve the original cold-preparation
receipts, component footprints, command RSS observations and sampled volume
free-space delta. The volume delta is an observation of the runner volume;
it is not represented as an exact per-process disk peak.

## Immutable candidate requalification

Revision 2 remains the same twelve signed assets from producer 39159711172/1.
macOS's upgrade installed both `0.1.0_2` and the lower fixture keg; the test
controller incorrectly treated that valid Homebrew inventory as a package
identity error. No package or SDK input is changed to correct the query.
The protected requalification workflow reads an explicit candidate identity,
checks its original successful staging gates and signatures, and reruns both
host lifecycles with the corrected controller. Publication requires that new
qualification to pass; the original failed run remains failed and preserved.
The public APT client also exercises signed-archive upgrade and documented
source/keyring removal before acceptance.

# Package channel status

Updated 2026-10-18. D0, D1-APT and D1-BREW are accepted against the unchanged
criteria in the [distribution plan](distribution-channels-plan.md). SDK 0.1.0
remains the stable/latest SDK release. Its separate package release is stable,
and both package channels are available on their qualified hosts.

| Result | Evidence |
| --- | --- |
| Package contract and acceptance | SDK 0.1.0, Debian 0.1.0-2, Homebrew revision 2; all D0-A1–A5, APT-A1–A3 and BREW-A1–A3 passed. See the [criterion mapping and measurements](evidence/distribution-0.1.0.json). |
| Sealed candidate | Producer 39159711172/1; source `a65b6d22bce94e30d5f89627dc176ff01117ebef`, tree `2db2669e54bf121274ac2f231fa21ad16c75fe80`, candidate SHA-256 `9052d51fe4689f5842ecee6e03624ecd6e6eb9363e1b47be231ceed4f3f5e247`. The same twelve signed files were requalified and published. |
| Corrected two-host package requalification | [Run 39161396600/1](https://github.com/metaneutrons/ami-rust/actions/runs/39161396600): all five gates passed. Linux lifecycle: 223.827 seconds; macOS lifecycle: 436.200 seconds. |
| Homebrew formula | [Tap PR #71](https://github.com/metaneutrons/homebrew-tap/pull/71) merged at `26405acd7542221463e1892f00c13e1ab4549ada` after required qualification [run 39162144348](https://github.com/metaneutrons/homebrew-tap/actions/runs/39162144348). |
| Signed APT archive | Publication [run 39162383740](https://github.com/metaneutrons/apt-archive/actions/runs/39162383740) succeeded; central archive head `f77c41de39f6bf26367e259969809e77dcbe8e35`. The archive was read and exercised by the Ubuntu public client. |
| Package release and public client gates | [Run 39162102531/1](https://github.com/metaneutrons/ami-rust/actions/runs/39162102531): all four gates passed. `v0.1.0+packaging.2` is stable (release `416661964`); the unchanged `v0.1.0` SDK release remains stable/latest (release `416548451`, six original assets). |
| Public APT client | Available on Ubuntu 24.04 amd64. The signed archive install, exact-version upgrade, project rebuild, package cleanup, and source/keyring removal passed in 261.0439 seconds. |
| Public Homebrew client | Available on macOS 26 Apple Silicon. The public formula install/test, preparation/build, retained-state rebuild and removal passed in 359.333 seconds; upgrade and reinstall passed in the separate lifecycle campaign above. |
| Shared native and resource result | Both clients rebuilt the 928,208-byte R1 reference executable with SHA-256 `85a2171d918423eb56b1a65757b72597e8902dad72f3a924fe277d253b7db162`. All recorded resource observations passed; cold receipts were retained. |

The [APT instructions](../packaging/INSTALL-APT.md) and
[Homebrew instructions](../packaging/INSTALL-HOMEBREW.md) contain the channel
commands. Both require the separate [explicit user preparation](../packaging/README.md)
before the first build. APT support is limited to Ubuntu 24.04 amd64; Homebrew
support is limited to macOS 26 Apple Silicon. The package release does not
replace the default/latest SDK release. AUR and rustup remain
[deferred](distribution-channels-plan.md).

## Preserved first packaging attempt

Protected producer [39158406951/1](https://github.com/metaneutrons/ami-rust/actions/runs/39158406951)
passed package generation, signing, provenance verification and corrupted-input
counter-tests. Staging then failed because GitHub did not expose its private
draft through the release-by-tag endpoint. The tag `v0.1.0+packaging.1` and its
12 signed draft assets remain preserved. That draft was never made public and
neither APT nor Homebrew was changed by that run.

## Revision 2 candidate and requalification history

The original revision-2 package campaign [39159711172/1](https://github.com/metaneutrons/ami-rust/actions/runs/39159711172)
successfully staged the twelve signed candidate files and passed the Linux
lifecycle. Its macOS controller rejected a valid two-keg inventory after
upgrade. The package and SDK inputs were left unchanged. The protected
requalification workflow verified the original staging gates, signatures and
candidate SHA, then reran both host lifecycles with the corrected controller;
[run 39161396600/1](https://github.com/metaneutrons/ami-rust/actions/runs/39161396600)
passed all five gates. The original failed result remains preserved.

The public APT client also exercised upgrade from an isolated lower-revision
fixture to the exact final package through the signed archive, then removed its
source and keyring as documented. The fixture was not published and did not
change the sealed candidate.

## Measured public-client cost

| Observation | Ubuntu APT | macOS Homebrew |
| --- | --- | --- |
| Prepared user-state files | 1.83 GiB | 1.42 GiB |
| Retained adapter/input snapshot | 25.91 MiB | 25.91 MiB |
| Source checkout including Git metadata | 260.83 MiB | 260.83 MiB |
| Observed runner-volume free-space delta | 2.56 GiB | 2.37 GiB |

Filesystem scopes overlap and must not be summed. The volume delta describes
the observed shared runner volume, not a process-isolated disk peak. Original
cold-preparation receipts, command RSS/work observations and warm timings are
retained in the acceptance record and CI artifacts. Preparation keeps the
6 GiB RAM / 24 GiB free-space host requirement. No new SDK application quota
was introduced.

The independent macOS APT-archive readback also exposed a GnuPG compatibility
issue: some `gpgv` versions authenticate InRelease without extracting its
plaintext. [PR #67](https://github.com/metaneutrons/ami-rust/pull/67) preserves the
pinned-signature check and extracts with GPG explicitly; real signed/tampered
fixtures and live public-archive checks passed. The Ubuntu public APT gate had
already passed with its original verifier. No published package changed.

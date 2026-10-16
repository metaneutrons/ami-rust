# C-SDK source availability and licences

**The APL-covered source for both C-SDK prerequisite archives is available under
the AROS Public License 1.1.** The corresponding source, original notices,
licences, build inputs and portability patches are distributed in this same
repository. Read [the complete APL 1.1](APL-1.1.txt).

These AROS-covered modifications are derived from Original Code provided by the
AROS Development Team (Initial Developer). See the dated
[modification record](CHANGES.md).

| Prerequisite archive | SHA-256 |
| --- | --- |
| [`csdk.tar.xz`](../inputs/csdk.tar.xz), original | `70cc3e45969c6e1eca7e4c5c2183429b88424f6c22c8ec6bb90e6cc70452ab87` |
| [`portable-csdk.tar.xz`](../inputs/portable-csdk.tar.xz), derived | `942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b` |

Obtain the corresponding source from
[`csdk-corresponding-source.tar.xz`](../csdk-source/csdk-corresponding-source.tar.xz)
(SHA-256 `7e62e28fb025e31aacdd3b6a6d14cef7d76703eb59dbaca02f2e2b4de68c6914`).
The [complete inventory](../csdk-source/manifest.json) identifies its members.
It contains the pinned AROS and aros-tools regular source trees, all 18 original
vendor archives, generated build inputs and frozen build recipes. Extract it
with standard XZ and tar tools. The derived archive additionally uses the four
patches in the [patch series](../patches/portable-csdk/series.json), the dated
[change record](CHANGES.md), and the producer helpers in `release/`.

Public repository: <https://github.com/metaneutrons/ami-rust>. Retrieve the source
and patches from the same Git commit as the prerequisite archive. For an
ami-rust SDK distributed later, use the exact source commit authenticated by its
release provenance. Archive identities and the complete profiles are specified
in [spec.json](spec.json). Retain this notice, the licence and the source links
when redistributing these prerequisites.

The source capsule preserves the original per-component terms, including APL,
LGPL and permissive vendor licences. The ami-rust first-party MIT OR Apache-2.0
licence does not replace those terms. No ownership or relicensing of third-party
code is asserted here.

The distributor must keep the corresponding APL-covered source available for
the periods required by APL 1.1 section 3.2, including when a hosting provider is
unavailable. This repository's retention policy is at least 12 months after the
latest distribution of each covered version; this exceeds the six-month period
for a subsequent version. Original source and qualified evidence must not be
removed merely because a new derived version is prepared.

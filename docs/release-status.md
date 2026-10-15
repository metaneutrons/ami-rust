# Release qualification status — 2026-10-15

Public source publication is authorised. On 2026-10-15 the owner also authorised SDK publication conditional on all release acceptance criteria passing. No SDK archive, native executable release asset or GitHub Release has been published. This source repository is not yet an R1-qualified SDK distribution.

## Completed candidate checks

- macOS Apple Silicon and Linux x86-64 each replayed the five-variant SDK consumer recipe in two clean roots: 20 cold variant builds. All 104 canonical outputs per root match the previously qualified host result under the approved native-code/host-metadata comparison.
- The corrected new-project recipe uses an independently verified, bounded relative SDK source snapshot. Its four clean builds produce all 15 canonical outputs byte-identically across both hosts. Failed earlier prototypes remain in the private qualification history.
- Installation and deinstallation pass the delivered recipe on both hosts. All 22 installer fixtures pass on each qualified host; public source CI also passes all 22 on macOS and Linux. Interrupted installs, altered assets, unsafe archives, wrong trust, bad receipts and uninstall protections are covered.
- Complete shared-prerequisite inventories remain unchanged after deinstallation: 12,549 files on macOS and 12,559 on Linux.
- Native AROS smoke passes on the unchanged x86-64 ABI-v1 baseline: both installed-host builds return the expected digest and status 0; the new demo runs; a missing file reports failure and leaves the shell usable. Boot took 9 seconds and the native test script 2.7 seconds. This smoke does not make a fresh memory-measurement claim; the complete earlier memory/diagnostic matrix applies only to exact unchanged SDK/native artifacts.
- Candidate licensing review passes: first-party MIT OR Apache-2.0, preserved AROS-derived terms, 83 original licence texts, a 57-package SPDX inventory, and a verified 341-file corresponding-source capsule. Binary candidate materials remain unpublished.

The final local candidate manifest SHA-256 is `a3da1702f6d5899818c72e6e42fdcbfefc0268f31deff181aba49797e6666d85`. Its SDK archive and SDK inventory are identical to the fully replayed 20-build candidate. Only the quickstart and project generator changed; their affected recipe was rerun in all four roots. Local signing used an explicitly qualification-only test publisher.

## R1-A6 remains open

A public repository and green installer fixture CI do not authenticate an SDK producer. R1 still requires the actual protected SDK build/packaging workflow, production publisher signatures/build attestations, and consumer verification with wrong issuer/identity, missing/altered assets and provenance-mismatch probes. The current offline installer deliberately accepts only qualification test manifests.

The complete C SDK and dependency vendor inputs currently lack an accepted immutable CI producer/provisioning path. Custom Cargo and its bootstrap inputs must also be provisioned under the protected producer contract. Existing pinned compiler/toolchain public inputs remain separate producer identities. Resolve these inputs, run the real protected candidate producer, qualify its authentic consumer path, then obtain independent R1-A1 through R1-A7 acceptance. All existing resource and runtime criteria remain in force.

Conditional publication authorisation is now recorded; it does not close R1-A6 or replace independent R1-A1 through R1-A7 acceptance. Once those gates pass, release the exact accepted bytes and perform the public readback and two-host replay required by R1-A8. nxpk is outside this gate. This is cross-development for AROS, not native AROS-hosted rustc/Cargo, full std, or official rustup target distribution.

## CI ownership and capacity

The approved design uses this repository and standard GitHub-hosted runners.
An additional private input repository was created during preparation and then
deleted at the owner's explicit request. Its two deploy keys were revoked and
their two environment secrets removed; all build inputs remain preserved locally.
No self-hosted runner was registered or started.

Build recipes, input pins, packaging data and redistributable dependency sources
belong in this repository. Publishing the complete compiled C SDK still requires
checking its full redistribution/source obligations; the existing review covers
the selected release candidate, not every file of that prerequisite SDK.

The manual `Hosted capacity survey` workflow measures actual RAM, free disk,
architecture and Python identity on macOS ARM64 and Linux x86-64. It has read-only
permissions, installs no SDK inputs and neither builds nor signs a release.
Published runner specifications do not establish actual available free disk.
The existing build preflight requires 16 GiB physical RAM and 24 GiB free disk.
Any prospective revision must be explicit, based on measurements, and qualified
before a hosted SDK build is accepted. Guest/baseline limits remain unchanged.

## Operating limits

The source snapshot/installation recipe requires a fresh WORK root disjoint from the bundle and installed SDK. Review found that a caller can currently choose a fresh destination inside the bundle; the qualified recipe avoids that destination. Installed SDK inventory validation rejects modifications. Same-user hostile concurrent mutation is outside the verified installation model. The generated demo preserves license files in its SDK source subtree; publishing an adapted application requires its own licensing decision.

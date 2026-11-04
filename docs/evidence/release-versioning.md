---
title: Release and version model
---

# Release and version model

ami-rust uses one semantic version for the public SDK distribution. The new
repository begins at 0.1.0. `version.txt` and
`.release-please-manifest.json` record the last released SDK version; the
release proposal moves both.

The Cargo workspace crates use the SDK version. The 13 library and build
crates (`aros`, `aros-sys`, `aros-mui`, `aros-mui-sys`, `aros-timer`,
`aros-graphics`, `aros-intuition`, `aros-asl`, `aros-locale`, `aros-icon`,
`aros-workbench`, `aros-elf`, `aros-native-build`) are published only to the
ami-rust Cargo registry (`publish = ["metaneutrons"]`); the examples and test
applications stay `publish = false`. A crates.io release requires a separate
API, naming, ownership, licence, and dependency review.

Production tags have the form `vMAJOR.MINOR.PATCH`. Only the protected release
workflow may create them. A normal source push, merge, or CI run must not create
a tag, GitHub Release, rustup catalog, or package publication.

The release sequence is:

1. manually open and merge the reviewed release proposal;
2. qualify the exact candidate on all supported hosts and on AROS;
3. review the generated rustup catalog as source;
4. sign the exact candidate and retain it as a private workflow artifact,
   without creating a tag or GitHub Release;
5. after a separate maintainer command, attest and publish the unchanged bytes
   as a draft prerelease;
6. verify the public bytes and promote the unchanged release;
7. package the 13 crates offline from the release commit and append them to the
   registry, never changing a published version, and read every byte back.
8. mark the merged release proposal `autorelease: tagged` (a non-fatal step of the
   release job), because release-please opens no new proposal while a merged one
   is still `autorelease: pending`.

APT, Homebrew, AUR, and crates.io are not 0.2.0 publication channels. Packaging
corrections after publication require a new semantic version; old release bytes
and tags remain immutable.

The prepared 0.1.0 candidate, reviewed catalog and unpublished signature set
are bound in the [M7 qualification record](https://ami-rust.metaneutrons.cc/m7-qualification/); those of 0.2.0 in
the [M10 qualification record](m10-qualification.md). Preparing that
set does not create a tag or grant publication authority.

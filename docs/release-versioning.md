# Release and version model

ami-rust uses one semantic version for the public SDK distribution. The new
repository begins at 0.1.0. `version.txt` is the prospective SDK version;
`.release-please-manifest.json` remains at 0.0.0 until the initial release
proposal is accepted.

The Cargo workspace currently uses 0.1.0 for project crates, which remain
`publish = false`. A future crates.io release requires a separate API, naming,
ownership, licence, and dependency review.

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
6. verify the public bytes and promote the unchanged release.

APT, Homebrew, AUR, and crates.io are not 0.1.0 publication channels. Packaging
corrections after publication require a new semantic version; old release bytes
and tags remain immutable.

The prepared 0.1.0 candidate, reviewed catalog and unpublished signature set
are bound in the [M7 qualification record](m7-qualification.md). Preparing that
set does not create a tag or grant publication authority.

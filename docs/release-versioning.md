---
title: Release and version model
---

# Release and version model

ami-rust uses semantic versioning for the SDK distribution. A release is an
immutable GitHub Release containing the matching versioned rustup toolchain.
Normal source pushes and pull-request checks never create tags, releases, or
publish package artifacts.

The initial 0.1 line uses GitHub Releases and rustup. APT, Homebrew, AUR, and
crates.io are not 0.1 distribution channels. The public Rust crates remain
Git-delivered until their names, ownership, and API boundaries are ready for a
deliberate registry publication.

Release preparation selects one source revision, builds the SDK for each
supported host, validates the target artifacts, signs the unchanged output,
and then publishes it through the protected release workflow. Packaging fixes
after publication require a new semantic version; an existing release's bytes
and tag are never replaced.

For installation and target selection, use the
[toolchain guide](https://ami-rust.metaneutrons.cc/quickstart-toolchain/).

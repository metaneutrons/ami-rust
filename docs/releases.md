---
title: Releases and versions
description: The current release, how this documentation relates to it, and the version and distribution model.
---

## Current release

| Item | Detail |
| --- | --- |
| Version | 0.1.0 |
| Source tag | [`v0.1.0`](https://github.com/metaneutrons/ami-rust/releases/tag/v0.1.0), commit `8456843ca869a738dde6dc7b7a062a2fdc3b6597` |
| Toolchain | rustup toolchain `0.1.0`, [installed](/quickstart-toolchain/) from the signed release archives or the immutable rustup catalog |
| Crates | Git dependencies pinned to the tagged revision; not on crates.io |

## How this documentation relates to the release

This site is built from the repository's `main` branch, and the footer of every page shows the commit it was built from. It is **not** frozen at the tag, so it can run ahead of the released source in two ways:

- **Documentation.** Rustdoc comments, examples and guides can be newer than the tag. The [API reference](/reference/) comes from `main` and may carry documentation the tagged source does not.
- **Examples.** The [MUI hello](/mui-hello/) example lives in the repository's `main` branch and is not part of the `v0.1.0` tag. The SHA-256 example is in both.

The **public declarations** of `aros` and `aros-mui` on `main` are the same as at the tag: no public item has been added, removed or changed since `v0.1.0`. A project that pins the tagged revision therefore compiles against the API this site documents. To read the source exactly as released, check out the tag:

```sh
git clone https://github.com/metaneutrons/ami-rust.git
cd ami-rust
git checkout v0.1.0
```

## Version model

- One semantic version covers the whole SDK distribution: the toolchain, the libraries and the build tools.
- Release tags have the form `vMAJOR.MINOR.PATCH` and are created only by the protected release workflow.
- Release bytes and tags are **immutable**. A correction to a published release is a new version, not a replacement.
- Release archives are signed and listed with their digests in a signed publication inventory, so you can [verify what you download](/quickstart-toolchain/#install-the-direct-archive).

## Distribution channels

0.1.0 is distributed through GitHub Release archives and an immutable rustup catalog. APT, Homebrew, AUR and crates.io are not channels for 0.1.0. Publishing the crates to crates.io would need its own review of names, public API, ownership and licences.

## Changes

See the [changelog](/changelog/) and the [GitHub releases](https://github.com/metaneutrons/ami-rust/releases). The [platform roadmap](/platform-roadmap/) describes what comes next.

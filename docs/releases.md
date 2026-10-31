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

## Documentation versions

The documentation is versioned. Use the version selector in the page header, or the address:

| Address | Documents |
| --- | --- |
| `/` and `/v0.1.0/` | The latest release, 0.1.0. |
| `/v<version>/` | Each other published release. |
| `/next/` | The development branch, `main`. It may describe behaviour that is not released yet, and search engines are asked not to index it. |

Switching version keeps you on the same page when that page exists in the other version. A banner appears on every page that is not for the latest release.

The documentation of a release is built from that release's tag. The tag is immutable and contains the guides, examples and API reference that the release shipped, so a published version's documentation does not change afterwards. A correction goes into the next release, and shows up in the development docs straight away. The footer of every page shows the commit it was built from.

The 0.1.0 documentation is the one exception. The documentation site was added after the 0.1.0 release, so the `v0.1.0` tag has no site sources. The 0.1 documentation is built from the `release/0.1` branch instead, and corrections to it are made there. Every release from the first one that contains the site is built from its tag.

The **public declarations** of `aros` and `aros-mui` in the 0.1 documentation are the same as at the `v0.1.0` tag: no public item has been added, removed or changed since. A project that pins the tagged revision therefore compiles against the API the 0.1 documentation describes. Two things in it are newer than the tag: Rustdoc comments and guides, and the [MUI hello](/mui-hello/) example, which is not part of the `v0.1.0` tag (the SHA-256 example is). To read the source exactly as released, check out the tag:

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

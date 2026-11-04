---
title: Releases and versions
description: The current release, how this documentation relates to it, and the version and distribution model.
---

## Current release

| Item | Detail |
| --- | --- |
| Version | 0.2.0 |
| Source tag | [`v0.2.0`](https://github.com/metaneutrons/ami-rust/releases/tag/v0.2.0) |
| Toolchain | rustup toolchain `0.2.0`, [installed](/quickstart-toolchain/) from the signed release archives or the immutable rustup catalog |
| Crates | The 13 `aros-*` library and build crates in the ami-rust registry at `crates.metaneutrons.cc`, or as Git dependencies pinned to the tagged revision; not on crates.io |

## Documentation versions

The documentation is versioned. Use the version selector in the page header, or the address:

| Address | Documents |
| --- | --- |
| `/` and `/v0.2.0/` | The latest release, 0.2.0. |
| `/v<version>/` | Each other published release, such as `/v0.1.0/`. |
| `/next/` | The development branch, `main`. It may describe behaviour that is not released yet, and search engines are asked not to index it. |

Switching version keeps you on the same page when that page exists in the other version. A banner appears on every page that is not for the latest release.

The documentation of a release is built from that release's tag. The tag is immutable and contains the guides, examples and API reference that the release shipped, so a published version's documentation does not change afterwards. A correction goes into the next release, and shows up in the development docs straight away. The footer of every page shows the commit it was built from.

The 0.1.0 documentation is the one exception. The documentation site was added after the 0.1.0 release, so the `v0.1.0` tag has no site sources. The 0.1 documentation is built from the `release/0.1` branch instead, and corrections to it are made there. Every release from 0.2.0 on is built from its tag. To read the source exactly as released, check out the tag:

```sh
git clone https://github.com/metaneutrons/ami-rust.git
cd ami-rust
git checkout v0.2.0
```

## Version model

- One semantic version covers the whole SDK distribution: the toolchain, the libraries and the build tools.
- Release tags have the form `vMAJOR.MINOR.PATCH` and are created only by the protected release workflow.
- Release bytes and tags are **immutable**. A correction to a published release is a new version, not a replacement.
- Release archives are signed and listed with their digests in a signed publication inventory, so you can [verify what you download](/quickstart-toolchain/#install-the-direct-archive).

## Distribution channels

0.2.0 is distributed through GitHub Release archives and an immutable rustup catalog. APT, Homebrew, AUR and crates.io are not channels for 0.2.0. The 13 `aros-*` library crates and build tooling crates (`aros-native-build`, `aros-elf`) are also delivered through the read-only ami-rust Cargo registry at `crates.metaneutrons.cc`, which 0.2.0 is the first release to fill: the protected release workflow packages them offline from the release commit, appends them to the static index without ever changing a published version, and reads every byte back publicly. Publishing the crates to crates.io would need its own review of names, public API, ownership and licences.

## Changes

See the [changelog](/changelog/) and the [GitHub releases](https://github.com/metaneutrons/ami-rust/releases). The [platform roadmap](/platform-roadmap/) describes what comes next.

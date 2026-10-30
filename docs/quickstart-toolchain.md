---
title: Install and build
description: Install the ami-rust toolchain with rustup, configure Cargo and build a native AROS executable.
---

ami-rust 0.1.0 is distributed as authenticated GitHub Release archives and as an immutable rustup catalog. Both routes install the same qualified SDK, and neither replaces your default toolchain. Once it is installed you build with ordinary Cargo and cross-compile for AROS from macOS or Linux.

## Prerequisites

| Need | Detail |
| --- | --- |
| Development host | macOS on Apple Silicon, Ubuntu 24.04 on x86-64, or Ubuntu 24.04 on ARM64. These are the three hosts the release was qualified on. |
| `rustup` | An unmodified upstream rustup client. |
| Native build tools | Xcode Command Line Tools on macOS; a C compiler, binutils and libc development headers on Ubuntu. Cargo needs them for host build scripts and procedural macros. |
| Target | An AROS x86-64 system to run the result on: [ABI-v1 or ABI-v11](/targets-and-abis/). |

The direct-archive route additionally needs `curl`, `cosign`, `jq`, `shasum` and `tar`.

## Install with rustup

The rustup catalog is rooted at an immutable, reviewed Git commit; its component URLs select the signed GitHub Release assets.

```sh
version=0.1.0
catalog_commit=bb5cc2e428b89685eeec2ae249701cc23fd135d7
export RUSTUP_DIST_SERVER="https://raw.githubusercontent.com/metaneutrons/ami-rust/$catalog_commit/distribution/rustup/$version"
rustup toolchain install "$version" --profile minimal --no-self-update
```

`RUSTUP_DIST_SERVER` only matters for the install. Afterwards rustup selects the toolchain by name, `+0.1.0`, on every supported host.

## Install the direct archive

Use this route when you want to verify the signatures yourself, or when rustup's catalog is not an option.

```sh
version=0.1.0
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) host=aarch64-apple-darwin; platform=macos-aarch64 ;;
  Linux:x86_64) host=x86_64-unknown-linux-gnu; platform=linux-x86_64 ;;
  Linux:aarch64|Linux:arm64) host=aarch64-unknown-linux-gnu; platform=linux-aarch64 ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
base="https://github.com/metaneutrons/ami-rust/releases/download/v$version"
archive="ami-rust-$version-$platform.tar.xz"
for file in "$archive" "$archive.sigstore.json" publication-inventory.json publication-inventory.json.sigstore.json; do
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --remote-name "$base/$file"
done
```

Verify the signed inventory and the archive, then extract it and register the prefix with rustup:

```sh
identity="https://github.com/metaneutrons/ami-rust/.github/workflows/toolchain-release.yml@refs/heads/main"
issuer="https://token.actions.githubusercontent.com"
cosign verify-blob --offline \
  --bundle publication-inventory.json.sigstore.json \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  publication-inventory.json
cosign verify-blob --offline \
  --bundle "$archive.sigstore.json" \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  "$archive"
expected="$(jq -er --arg name "$archive" '.assets[] | select(.name == $name).sha256' publication-inventory.json)"
printf '%s  %s\n' "$expected" "$archive" | shasum -a 256 --check
mkdir "ami-rust-$version"
tar -xJf "$archive" -C "ami-rust-$version"
rustup toolchain link "ami-rust-$version-$host" "$PWD/ami-rust-$version/libexec/ami-rust/$version"
```

The inventory lists the exact digest of every archive. Moving branch URLs are not an installation interface.

## Verify the installation

```sh
rustup toolchain list      # shows 0.1.0-<host> (rustup route)
cargo +0.1.0 --version     # a nightly-based Cargo
rustc +0.1.0 -vV           # release 1.100.0-nightly, LLVM 23.1.1
```

The compiler is a nightly-based build because the AROS targets are custom target specifications, which stable Rust does not accept. That is also why the Cargo configuration below passes `-Zunstable-options`.

## Configure Cargo

Add this to your project's `.cargo/config.toml`:

```toml
[target.x86_64-unknown-aros-abi1]
linker = "aros-link"
rustflags = ["-Zunstable-options"]

[target.x86_64-unknown-aros-abi11]
linker = "aros-link"
rustflags = ["-Zunstable-options"]
```

`aros-link` is the target linker shipped in the toolchain. Rustup puts the toolchain's `bin` directory on `PATH` for the Cargo it launches, so the bare name resolves. Do not put that directory ahead of the rustup proxies in your own `PATH`, and do not set `RUST_TARGET_PATH`. Both bypass the toolchain selection that the build verifies. See [build system](/build-system/) for what is checked.

## Build

Pick the target that matches the AROS you will run on. The [targets and ABIs](/targets-and-abis/) page explains the choice. Your application source is the same for both.

```sh
toolchain=0.1.0
cargo +"$toolchain" fetch --locked
cargo +"$toolchain" build --target x86_64-unknown-aros-abi11 --release --locked --offline
cargo +"$toolchain" build --target x86_64-unknown-aros-abi1  --release --locked --offline
```

The first resolution writes `Cargo.lock`; commit it. After a successful `cargo fetch` the build runs offline. The executable is `target/<target>/release/<package-name>`.

To get started, copy the minimal program from the [consumer guide](/consumer-guide/#a-minimal-program) or the [MUI hello example](/mui-hello/). Then see [Run on AROS](/run-on-aros/) for getting the result onto a system and starting it.

If a build fails with a message about `RUSTC_WRAPPER`, `RUST_TARGET_PATH` or `-Zunstable-options`, see [Troubleshooting](/troubleshooting/).

## Boundaries

- The compiler runs on the macOS or Linux development host; the executable runs on AROS x86-64.
- The libraries provide `no_std` and `alloc`, not full `std`.
- There is no `ami-rust` command-line tool and no Cargo plugin.
- An AROS-hosted Rust compiler and other target architectures are separate [roadmap](/platform-roadmap/) items.

## For maintainers: build the repository tooling

This section is for working on ami-rust itself, not for building applications. The repository builds its internal task with authenticated, pinned host components and a checked-in offline vendor archive. The work directory must be fresh and outside the checkout:

```sh
git clone https://github.com/metaneutrons/ami-rust.git
cd ami-rust
work="$(mktemp -d)/ami-rust-maintainer"
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) host=aarch64-apple-darwin ;;
  Linux:x86_64) host=x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) host=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
bash tools/build-maintainer-task.sh "$work" "$host"
"$work/target/release/ami-rust-xtask" --help
```

The bootstrap validates the compiler, Cargo, vendor archive, lockfiles and source revision before it produces the task. Its receipt is written below the work directory. This is a development check, not an SDK installation.

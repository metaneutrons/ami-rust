# Toolchain installation and source checkout

ami-rust 0.1.0 is distributed as authenticated GitHub Release archives and
through an immutable rustup catalog. Both routes install the same qualified SDK
without replacing the user's default toolchain.

## Maintainer bootstrap

The repository builds its internal Rust task with authenticated, pinned host
components and the checked-in offline vendor archive:

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

The bootstrap validates the compiler, Cargo, vendor archive, lockfiles, and
source revision before it produces the task. Its receipt is written below the
fresh work directory. This is a development check, not an SDK installation.

## Install with rustup

The rustup catalog is rooted at the immutable reviewed Git commit
`bb5cc2e428b89685eeec2ae249701cc23fd135d7`; its component URLs select the
signed GitHub Release assets. Installation and later version selection use an
unmodified rustup client:

```sh
version=0.1.0
catalog_commit=bb5cc2e428b89685eeec2ae249701cc23fd135d7
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) host=aarch64-apple-darwin; platform=macos-aarch64 ;;
  Linux:x86_64) host=x86_64-unknown-linux-gnu; platform=linux-x86_64 ;;
  Linux:aarch64|Linux:arm64) host=aarch64-unknown-linux-gnu; platform=linux-aarch64 ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
export RUSTUP_DIST_SERVER="https://raw.githubusercontent.com/metaneutrons/ami-rust/$catalog_commit/distribution/rustup/$version"
rustup toolchain install "$version-$host" --profile minimal --no-self-update
```

Once the versioned toolchain is installed, an application uses ordinary Cargo
with either canonical target. Add the linker and nightly custom-target flag to
the project's Cargo configuration:

```toml
# .cargo/config.toml
[target.x86_64-unknown-aros-abi1]
linker = "aros-link"
rustflags = ["-Zunstable-options"]

[target.x86_64-unknown-aros-abi11]
linker = "aros-link"
rustflags = ["-Zunstable-options"]
```

Fetch the locked dependencies once, then build offline:

```sh
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) toolchain=0.1.0-aarch64-apple-darwin ;;
  Linux:x86_64) toolchain=0.1.0-x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) toolchain=0.1.0-aarch64-unknown-linux-gnu ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
cargo +"$toolchain" fetch --locked
cargo +"$toolchain" build --target x86_64-unknown-aros-abi1 --release --locked --offline
cargo +"$toolchain" build --target x86_64-unknown-aros-abi11 --release --locked --offline
```

## Install the direct archive

The direct archive contains the same SDK tree. Select the host as above, then
download the archive, its bundle, and the signed publication inventory:

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
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --remote-name "$base/$archive"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --remote-name "$base/$archive.sigstore.json"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --remote-name "$base/publication-inventory.json"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --remote-name "$base/publication-inventory.json.sigstore.json"
```

Verify the signed inventory and archive, then extract and register the prefix:

```sh
identity="https://github.com/metaneutrons/ami-rust/.github/workflows/toolchain-release.yml@refs/heads/main"
issuer="https://token.actions.githubusercontent.com"
cosign verify-blob --offline \
  --bundle publication-inventory.json.sigstore.json \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  publication-inventory.json
cosign verify-blob --offline \
  --bundle "$archive.sigstore.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$archive"
expected="$(jq -er --arg name "$archive" '.assets[] | select(.name == $name).sha256' publication-inventory.json)"
printf '%s  %s\n' "$expected" "$archive" | shasum -a 256 --check
mkdir "ami-rust-$version"
tar -xJf "$archive" -C "ami-rust-$version"
direct_toolchain="ami-rust-$version-$host"
rustup toolchain link "$direct_toolchain" \
  "$PWD/ami-rust-$version/libexec/ami-rust/$version"
```

The release asset inventories contain the exact archive digests. Moving branch
URLs are not an installation interface.

Project crates initially use immutable Git revision
`95795520653aca959bb17b3b73cf025261d049a7` from this repository and commit
`Cargo.lock`. They are intentionally not on crates.io yet.

## Boundaries

- The compiler runs on the macOS or Linux development host.
- The produced executable runs on AROS x86-64 ABI-v1 or ABI-v11.
- The initial libraries provide `no_std` and `alloc`, not full `std`.
- There is no `ami-rust` CLI or Cargo plugin.
- Native AROS-hosted Rust and additional target architectures are separate
  roadmap items.

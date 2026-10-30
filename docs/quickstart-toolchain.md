# Toolchain installation and source checkout

The exact ami-rust 0.1.0 candidate is qualified and signed, but not published.
Until the separate publication decision is made, there is no supported public
rustup URL or direct binary installation.

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

## User workflow after publication

The rustup catalog is rooted at the immutable reviewed Git commit
`bb5cc2e428b89685eeec2ae249701cc23fd135d7`; its component URLs select the
signed GitHub Release assets. Installation and later version selection use
unmodified rustup without replacing the user's default toolchain. The command
becomes usable only after the referenced `v0.1.0` assets have been published:

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
with either canonical target:

```sh
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) toolchain=0.1.0-aarch64-apple-darwin ;;
  Linux:x86_64) toolchain=0.1.0-x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) toolchain=0.1.0-aarch64-unknown-linux-gnu ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
cargo +"$toolchain" build --target x86_64-unknown-aros-abi1 --release --locked --offline
cargo +"$toolchain" build --target x86_64-unknown-aros-abi11 --release --locked --offline
```

The direct archive contains the same SDK tree. Verify both its recorded
SHA-256 digest and Sigstore bundle before extraction, then register the prefix:

```sh
cosign verify-blob --offline \
  --bundle "ami-rust-0.1.0-$platform.tar.xz.sigstore.json" \
  --certificate-identity "https://github.com/metaneutrons/ami-rust/.github/workflows/toolchain-release.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ami-rust-0.1.0-$platform.tar.xz"
mkdir ami-rust-0.1.0
tar -xJf "ami-rust-0.1.0-$platform.tar.xz" -C ami-rust-0.1.0
direct_toolchain="ami-rust-0.1.0-$host"
rustup toolchain link "$direct_toolchain" \
  "$PWD/ami-rust-0.1.0/libexec/ami-rust/0.1.0"
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

# Source checkout guide

ami-rust 0.1.0 is not published yet. Until the protected release is complete,
there is no supported rustup URL or direct binary installation.

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

## User workflow after 0.1.0

The release documentation will provide the exact authenticated rustup catalog
commit, release URL, checksums, Sigstore bundles, and verification commands.
The catalog is a normal rustup distribution server rooted at the immutable
reviewed Git commit; its component URLs select the signed GitHub Release
assets. Installation and update therefore use unmodified rustup without
replacing the user's default toolchain.

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

The direct archive contains the same SDK tree and is registered with
`rustup toolchain link` after its checksum and Sigstore bundle have been
verified. The final guide will add every catalog and release identity from the
exact 0.1.0 candidate; moving branch URLs are not an installation interface.

Project crates will initially use immutable Git revisions from this repository
and commit `Cargo.lock`. They are intentionally not on crates.io yet. The final
0.1.0 guide will supply the exact release commit instead of a moving branch.

## Boundaries

- The compiler runs on the macOS or Linux development host.
- The produced executable runs on AROS x86-64 ABI-v1 or ABI-v11.
- The initial libraries provide `no_std` and `alloc`, not full `std`.
- There is no `ami-rust` CLI or Cargo plugin.
- Native AROS-hosted Rust and additional target architectures are separate
  roadmap items.

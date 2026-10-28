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
URL and checksums. Installation will not replace the user's default toolchain.
Once the versioned toolchain is installed and linked as `aros`, an application
uses ordinary Cargo:

```sh
cargo +aros build --target x86_64-aros --release --locked --offline
```

Project crates will initially use immutable Git revisions from this repository
and commit `Cargo.lock`. They are intentionally not on crates.io yet. The final
0.1.0 guide will supply the exact release commit instead of a moving branch.

## Boundaries

- The compiler runs on the macOS or Linux development host.
- The produced executable runs on AROS x86-64 ABI-v1.
- The initial libraries provide `no_std` and `alloc`, not full `std`.
- There is no `ami-rust` CLI or Cargo plugin.
- Native AROS-hosted Rust and additional target architectures are separate
  roadmap items.

# Contributing

Use a focused branch and a Conventional Commit title. Repository text, commit
messages, pull requests, and issues are English. Do not add AI attribution
trailers.

The public interface is rustup plus Cargo. Changes must not introduce an
`ami-rust` CLI, a Cargo wrapper, or a Python execution path. Preserve the AROS
x86-64 ABI-v1 baseline and keep AROS-NX and aros-tools outside this repository.

Run the Rust maintainer workspace through the same pinned bootstrap used by CI:

```bash
set -euo pipefail
repo=$(pwd -P)
root=$(mktemp -d)
root=$(cd "$root" && pwd -P)
case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) host=aarch64-apple-darwin ;;
  Linux:x86_64) host=x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) host=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported development host" >&2; exit 2 ;;
esac
bash tools/build-maintainer-task.sh "$root/maintainer" "$host"
work="$root/maintainer"
toolchain="$work/bootstrap/toolchain"
mkdir -m 700 "$work/test-target"
env -i \
  HOME="$work/home" TMPDIR="$work/tmp" \
  PATH="$toolchain/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/test-target" \
  CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  RUSTC="$toolchain/bin/rustc" RUSTDOC="$toolchain/bin/rustdoc" \
  RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' \
  LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 \
  "$toolchain/bin/cargo" test --workspace --all-targets --locked --offline \
    --manifest-path "$repo/tooling/Cargo.toml" -j 2
```

Local success covers repository tooling only. Protected three-host production,
publisher provenance, native AROS execution, and exact-candidate acceptance are
independent release gates.

Do not commit credentials, private signing keys, local paths, generated SDK
archives, or local qualification output. New third-party inputs require their
licence, source identity, digest, and corresponding-source record.

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Fast local development gate, before the protected application matrix.
set -euo pipefail
umask 077
[[ $# == 3 ]] || { echo 'usage: check-native-cargo-offline.sh HOST_TRIPLE PINNED_BOOTSTRAP_PREFIX FRESH_WORK_ROOT' >&2; exit 2; }
triple=$1
bootstrap=$2
work=$3
case "$triple:$(uname -s):$(uname -m)" in
  aarch64-apple-darwin:Darwin:arm64|aarch64-apple-darwin:Darwin:aarch64|x86_64-unknown-linux-gnu:Linux:x86_64|aarch64-unknown-linux-gnu:Linux:aarch64|aarch64-unknown-linux-gnu:Linux:arm64) ;;
  *) echo 'requested host does not match this machine' >&2; exit 2 ;;
esac
for path in "$bootstrap" "$work"; do
  case "$path" in /*) ;; *) echo 'absolute paths required' >&2; exit 2 ;; esac
  [[ "$path" != *'/../'* && "$path" != *'/./'* ]] || exit 2
done
[[ ! -e "$work" && ! -L "$work" ]] || { echo 'work root must be fresh' >&2; exit 2; }
source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
profile="$source_root/release/native-cargo-vendor-inputs.json"
archive="$source_root/release/inputs/native-cargo-vendor.tar.xz"
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
jq -e '.schema == "ami-rust-native-cargo-vendor-inputs-v1" and .path == "release/inputs/native-cargo-vendor.tar.xz" and .component_root == "vendor"' "$profile" >/dev/null
for lock in Cargo.lock tooling/Cargo.lock; do
  [[ $(sha "$source_root/$lock") == "$(jq -er --arg lock "$lock" '.source_locks[$lock]' "$profile")" ]] || { echo 'native vendor source lock differs' >&2; exit 1; }
done
[[ $(wc -c < "$archive" | tr -d '[:space:]') == "$(jq -er '.bytes' "$profile")" && $(sha "$archive") == "$(jq -er '.sha256' "$profile")" ]] || { echo 'native vendor archive identity differs' >&2; exit 1; }
rustc_version=$("$bootstrap/bin/rustc" -Vv)
cargo_version=$("$bootstrap/bin/cargo" -Vv)
[[ "$rustc_version" == *'commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985'* && "$rustc_version" == *"host: $triple"* ]] || exit 1
[[ "$cargo_version" == *'commit-hash: 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d'* && "$cargo_version" == *"host: $triple"* ]] || exit 1
mkdir -m 700 "$work" "$work/home" "$work/tmp" "$work/cargo-home" "$work/target"
printf '%s\n' "$rustc_version" > "$work/rustc-version.txt"
printf '%s\n' "$cargo_version" > "$work/cargo-version.txt"
tar -tf "$archive" | awk '{ p=$0; sub(/\/+$/, "", p); if (p == "" || p ~ /^\// || p ~ /(^|\/)\.\.?($|\/)/ || (p != "vendor" && substr(p,1,7) != "vendor/")) bad=1; n++ } END { if (!n || bad) exit 1 }'
tar -xf "$archive" -C "$work"
jq -nr --arg directory "$work/vendor" \
  '"[net]\noffline = true\n[source.crates-io]\nreplace-with = \"qualification-vendor\"\n[source.qualification-vendor]\ndirectory = " + ($directory | tojson)' \
  > "$work/cargo-home/config.toml"
cargo() {
  env -i HOME="$work/home" TMPDIR="$work/tmp" PATH="$bootstrap/bin:/usr/bin:/bin" \
    CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" CARGO_BUILD_JOBS=2 \
    CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true RUSTC="$bootstrap/bin/rustc" \
    RUSTDOC="$bootstrap/bin/rustdoc" RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER= \
    LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 "$bootstrap/bin/cargo" "$@"
}
cargo metadata --locked --offline --format-version 1 --manifest-path "$source_root/Cargo.toml" > "$work/application-metadata.json"
cargo metadata --locked --offline --format-version 1 --manifest-path "$source_root/tooling/Cargo.toml" > "$work/tooling-metadata.json"
cargo build --locked --offline --release --target "$triple" --manifest-path "$source_root/tooling/Cargo.toml" -p aros-native-build --bin aros-link -j 2
linker="$work/target/$triple/release/aros-link"
[[ -f "$linker" && ! -L "$linker" && -x "$linker" ]]
jq -n --arg host "$triple" --arg linker_sha256 "$(sha "$linker")" \
  --arg vendor_sha256 "$(sha "$archive")" \
  '{status:"PASS_LOCAL_OFFLINE_LINKER_PREFLIGHT",host:$host,linker_sha256:$linker_sha256,vendor_sha256:$vendor_sha256,claim:"Local development gate: both locked offline metadata graphs and actual native linker build. No application, SDK, runtime or release acceptance."}' \
  > "$work/result.json"
cat "$work/result.json"

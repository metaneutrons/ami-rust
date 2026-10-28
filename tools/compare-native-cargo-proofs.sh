#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Aggregate this workflow's retained host proofs, without rebuilding the SDK.
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo "usage: compare-native-cargo-proofs.sh PROOFS FRESH_WORK FRESH_OUTPUT" >&2
  exit 2
fi
proofs=$1
work=$2
output=$3
for directory in "$proofs" "$work" "$output"; do
  case "$directory" in /*) ;; *) echo "absolute operational paths required" >&2; exit 2 ;; esac
done
test -d "$proofs" && test ! -L "$proofs"
test ! -e "$work" && test ! -L "$work"
test ! -e "$output" && test ! -L "$output"
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
head=$(git -C "$source_root" rev-parse HEAD)
test "$head" = "${GITHUB_SHA:?}"
mkdir -m 700 "$work" "$output" "$work/home" "$work/tmp" "$work/cargo-home" "$work/vendor"
# The archive and both locks have an existing reviewed source identity. A new
# mismatch refuses before extracting or building anything.
profile="$source_root/release/native-cargo-vendor-inputs.json"
archive="$source_root/release/inputs/native-cargo-vendor.tar.xz"
test "$(jq -er '.schema' "$profile")" = ami-rust-native-cargo-vendor-inputs-v1
test "$(jq -er '.path' "$profile")" = release/inputs/native-cargo-vendor.tar.xz
test "$(jq -er '.component_root' "$profile")" = vendor
for lock in Cargo.lock tooling/Cargo.lock; do
  actual=$(sha256sum "$source_root/$lock")
  test "${actual%% *}" = "$(jq -er --arg lock "$lock" '.source_locks[$lock]' "$profile")"
done
test "$(wc -c < "$archive" | tr -d ' ')" = "$(jq -er '.bytes' "$profile")"
actual=$(sha256sum "$archive")
test "${actual%% *}" = "$(jq -er '.sha256' "$profile")"
tar -xJf "$archive" -C "$work/vendor"
test -z "$(find "$work/vendor" -type l -print -quit)"
jq -nr --arg directory "$work/vendor/vendor" \
  '"[net]\noffline = true\n[source.crates-io]\nreplace-with = \"qualification-vendor\"\n[source.qualification-vendor]\ndirectory = " + ($directory | tojson)' \
  > "$work/cargo-home/config.toml"
bash "$source_root/tools/bootstrap-host-rust.sh" "$work/bootstrap" x86_64-unknown-linux-gnu \
  > "$output/bootstrap.log" 2>&1
env -i HOME="$work/home" TMPDIR="$work/tmp" PATH="$work/bootstrap/toolchain/bin:/usr/bin:/bin" \
  LC_ALL=C TZ=UTC CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" \
  RUSTC="$work/bootstrap/toolchain/bin/rustc" RUSTDOC="$work/bootstrap/toolchain/bin/rustdoc" \
  CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER= \
  "$work/bootstrap/toolchain/bin/cargo" build --locked --offline --release \
  --manifest-path "$source_root/tooling/Cargo.toml" -p ami-rust-xtask \
  > "$output/helper-build.log" 2>&1
"$work/target/release/ami-rust-xtask" native-cargo-compare --source-head "$head" \
  --macos-proof "$proofs/macos-aarch64" --linux-x86-proof "$proofs/linux-x86_64" \
  --linux-arm-proof "$proofs/linux-aarch64" --output "$output/comparison.json"
# The three input artifacts remain retained independently. Only the small
# receipt/bootstrap/build logs add to the campaign's existing reservation.
retained=$(find "$output" -type f -exec wc -c {} \; | awk '{sum += $1} END {printf "%.0f\n", sum}')
test "$retained" -le 1048576

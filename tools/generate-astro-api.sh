#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Generate the public Rust API reference consumed by the Astro documentation.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'usage: generate-astro-api.sh FRESH_ABSOLUTE_WORK OUTPUT_DIR HOST_TRIPLE'
requested_work=$1
requested_output=$2
host_triple=$3

case "$requested_work" in /*) ;; *) fail 'work root must be absolute' ;; esac
case "$requested_output" in /*) ;; *) fail 'output directory must be absolute' ;; esac
[[ "$requested_work" != / && "$requested_work" != */ ]] || fail 'work root must name a fresh directory'
case "/$requested_work/" in *'/../'*|*'/./'*) fail 'work root must be normalized' ;; esac

for tool in awk bash env git jq node shasum tar tr wc; do command -v "$tool" >/dev/null || fail "missing required tool: $tool"; done

source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work_parent=$(cd -P -- "$(dirname -- "$requested_work")" && pwd -P)
work="$work_parent/${requested_work##*/}"
output=$requested_output
expected_output="$source_root/docs/reference/generated"

[[ "$output" == "$expected_output" ]] || fail "output directory must be $expected_output"
[[ ! -e "$work" && ! -L "$work" ]] || fail 'work root must be fresh and absent'
case "$work/" in "$source_root/"*) fail 'work root must be outside the source checkout' ;; esac
case "$source_root/" in "$work/"*) fail 'work root overlaps the source checkout' ;; esac

mkdir -m 700 -- "$work"
mkdir -m 700 -- "$work/home" "$work/tmp" "$work/cargo-home" "$work/vendor-unpack" "$work/source"
bash "$source_root/tools/bootstrap-host-rust.sh" "$work/bootstrap" "$host_triple"

git -C "$source_root" archive --format=tar HEAD \
  Cargo.toml Cargo.lock crates examples/minimal examples/sha256sum \
  tests/qualification tests/dependencies native tooling/crates/aros-elf \
  tooling/crates/aros-native-build | tar -xf - -C "$work/source"
node "$source_root/website/scripts/prepare-rustdoc-source.mjs" "$work/source"

sha() { shasum -a 256 "$1" | awk '{print $1}'; }
size() { wc -c < "$1" | tr -d '[:space:]'; }
vendor_profile="$source_root/release/native-cargo-vendor-inputs.json"
vendor_archive="$source_root/release/inputs/native-cargo-vendor.tar.xz"
jq -e '.schema == "ami-rust-native-cargo-vendor-inputs-v1" and .path == "release/inputs/native-cargo-vendor.tar.xz" and .component_root == "vendor"' "$vendor_profile" >/dev/null || fail 'native Cargo vendor input profile is malformed'
vendor_bytes=$(jq -er '.bytes' "$vendor_profile")
vendor_sha=$(jq -er '.sha256' "$vendor_profile")
[[ -f "$vendor_archive" && ! -L "$vendor_archive" && $(size "$vendor_archive") == "$vendor_bytes" && $(sha "$vendor_archive") == "$vendor_sha" ]] || fail 'native Cargo vendor archive identity differs'
for lock in Cargo.lock tooling/Cargo.lock; do
  actual=$(sha "$source_root/$lock")
  expected=$(jq -er --arg lock "$lock" '.source_locks[$lock]' "$vendor_profile")
  [[ "$actual" == "$expected" ]] || fail "native vendor source lock differs: $lock"
done
tar -tf "$vendor_archive" | awk '{ p=$0; sub(/\/+$/, "", p); if (p == "" || p ~ /^\// || p ~ /(^|\/)\.\.?($|\/)/ || (p != "vendor" && substr(p,1,7) != "vendor/")) bad=1; n++ } END { if (!n || bad) exit 1 }' || fail 'vendor archive members escape the declared root'
tar -xf "$vendor_archive" -C "$work/vendor-unpack"
[[ -d "$work/vendor-unpack/vendor" && ! -L "$work/vendor-unpack/vendor" ]] || fail 'authenticated vendor archive root is missing'
jq -nr --arg directory "$work/vendor-unpack/vendor" '"[net]\noffline = true\n[source.crates-io]\nreplace-with = \"maintainer-vendor\"\n[source.maintainer-vendor]\ndirectory = " + ($directory | tojson)' > "$work/cargo-home/config.toml"

toolchain="$work/bootstrap/toolchain/bin"
cargo="$toolchain/cargo"
rustc="$toolchain/rustc"
rustdoc="$toolchain/rustdoc"
[[ -x "$cargo" && -x "$rustc" && -x "$rustdoc" ]] || fail 'pinned host Rust toolchain is incomplete'

tool_path="$toolchain:/usr/bin:/bin:/usr/sbin:/sbin"
generate_profile() {
  local profile=$1
  local target_dir="$work/api-target-$profile"
  env -i \
    HOME="$work/home" TMPDIR="$work/tmp" PATH="$tool_path" \
    CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$target_dir" \
    CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
    RUSTC="$rustc" RUSTDOC="$rustdoc" RUSTC_BOOTSTRAP=1 \
    RUSTDOCFLAGS="-Z unstable-options --output-format json -Aexplicit_builtin_cfgs_in_flags --cfg target_os=\"aros\" --cfg target_abi=\"$profile\" --cfg target_arch=\"x86_64\"" \
    LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 \
    "$cargo" doc --manifest-path "$work/source/Cargo.toml" --locked --offline --no-deps -p aros -p aros-mui

  local aros_json="$target_dir/doc/aros.json"
  local aros_mui_json="$target_dir/doc/aros_mui.json"
  [[ -s "$aros_json" && -s "$aros_mui_json" ]] || fail "$profile rustdoc JSON output is incomplete"
  node "$source_root/website/scripts/generate-rust-api.mjs" \
    "$output" "$profile" "$aros_json" "$aros_mui_json"
}

generate_profile abi1
generate_profile abi11

[[ -s "$output/index.md" && -s "$output/abi1/aros/index.md" && \
   -s "$output/abi1/aros_mui/index.md" && -s "$output/abi11/aros/index.md" && \
   -s "$output/abi11/aros_mui/index.md" ]] || \
  fail 'Astro API reference is incomplete'

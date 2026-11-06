#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Package the publishable aros-* crates from the checked-out revision, offline,
# with the pinned host Rust and the authenticated vendor archive. The crates are
# those whose Cargo.toml `publish` list names the registry; the archives are
# plain `cargo package` output.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 5 ]] || fail 'usage: package-crates.sh FRESH_ABSOLUTE_WORK OUTPUT_DIR HOST_TRIPLE REGISTRY_NAME REGISTRY_INDEX_URL'
requested_work=$1
requested_output=$2
host_triple=$3
registry_name=$4
registry_index=$5

case "$requested_work" in /*) ;; *) fail 'work root must be absolute' ;; esac
case "$requested_output" in /*) ;; *) fail 'output directory must be absolute' ;; esac
[[ "$requested_work" != / && "$requested_work" != */ ]] || fail 'work root must name a fresh directory'
case "/$requested_work/" in *'/../'*|*'/./'*) fail 'work root must be normalized' ;; esac
[[ "$registry_name" =~ ^[a-z][a-z0-9-]*$ ]] || fail 'registry name is malformed'
[[ "$registry_index" =~ ^sparse\+https://[a-z0-9.-]+/$ ]] || fail 'registry index URL is malformed'

for tool in awk bash env git jq node shasum tar wc; do command -v "$tool" >/dev/null || fail "missing required tool: $tool"; done

source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work_parent=$(cd -P -- "$(dirname -- "$requested_work")" && pwd -P)
work="$work_parent/${requested_work##*/}"
[[ ! -e "$work" && ! -L "$work" ]] || fail 'work root must be fresh and absent'
[[ ! -e "$requested_output" && ! -L "$requested_output" ]] || fail 'output directory must be fresh and absent'
case "$work/" in "$source_root/"*) fail 'work root must be outside the source checkout' ;; esac
case "$source_root/" in "$work/"*) fail 'work root overlaps the source checkout' ;; esac
case "$requested_output/" in "$source_root/"*) fail 'output directory must be outside the source checkout' ;; esac

mkdir -m 700 -- "$work"
mkdir -m 700 -- "$work/home" "$work/tmp" "$work/cargo-home" "$work/vendor-unpack" "$work/source"
bash "$source_root/tools/bootstrap-host-rust.sh" "$work/bootstrap" "$host_triple"

git -C "$source_root" archive --format=tar HEAD \
  Cargo.toml Cargo.lock crates examples/minimal examples/sha256sum \
  tests/qualification tests/dependencies tooling/crates/aros-elf \
  tooling/crates/aros-native-build | tar -xf - -C "$work/source"

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
# Cargo needs the registry the crates declare in `publish` to be known when it packages them.
printf '[registries.%s]\nindex = "%s"\n' "$registry_name" "$registry_index" >> "$work/cargo-home/config.toml"

toolchain="$work/bootstrap/toolchain/bin"
cargo="$toolchain/cargo"
rustc="$toolchain/rustc"
[[ -x "$cargo" && -x "$rustc" ]] || fail 'pinned host Rust toolchain is incomplete'
tool_path="$toolchain:/usr/bin:/bin:/usr/sbin:/sbin"

# The crates to publish are named by the manifests, not by a list here.
crates=()
while IFS= read -r name; do crates+=("$name"); done < <(node "$source_root/tools/registry/registry.mjs" crates --source "$work/source" --registry "$registry_name")
[[ ${#crates[@]} -gt 0 ]] || fail 'no crate names the registry in its publish list'
node "$source_root/tools/registry/registry.mjs" stage --source "$work/source" --registry "$registry_name"

mkdir -m 700 -- "$requested_output"
target_dir="$work/package-target"
# One invocation for all crates: the crates depend on each other by path and
# version, and Cargo resolves them against the packages it is producing.
package_arguments=()
for crate in "${crates[@]}"; do package_arguments+=(--package "$crate"); done
env -i \
  HOME="$work/home" TMPDIR="$work/tmp" PATH="$tool_path" \
  CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$target_dir" \
  CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  RUSTC="$rustc" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 \
  "$cargo" package --manifest-path "$work/source/Cargo.toml" "${package_arguments[@]}" \
    --locked --offline --no-verify --allow-dirty
for crate in "${crates[@]}"; do
  count=$(ls "$target_dir/package/${crate}-"[0-9]*.crate 2>/dev/null | wc -l | tr -d ' ')
  [[ "$count" == 1 ]] || fail "unexpected package output for $crate"
  cp -- "$target_dir/package/${crate}-"[0-9]*.crate "$requested_output/"
done
[[ $(ls "$requested_output" | wc -l | tr -d ' ') == "${#crates[@]}" ]] || fail 'the output does not hold exactly the requested crates'
ls -l "$requested_output"

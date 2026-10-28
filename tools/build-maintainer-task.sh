#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build the maintainer xtask with the pinned native Rust and offline vendor set.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: build-maintainer-task.sh FRESH_ABSOLUTE_WORK HOST_TRIPLE'
requested_work=$1
host_triple=$2
case "$requested_work" in /*) ;; *) fail 'work root must be absolute' ;; esac
[[ "$requested_work" != / && "$requested_work" != */ ]] || fail 'work root must name a fresh directory'
case "/$requested_work/" in *'/../'*|*'/./'*) fail 'work root must be normalized' ;; esac
case "$host_triple:$(uname -s):$(uname -m)" in
  aarch64-apple-darwin:Darwin:arm64|aarch64-apple-darwin:Darwin:aarch64|x86_64-unknown-linux-gnu:Linux:x86_64|aarch64-unknown-linux-gnu:Linux:aarch64|aarch64-unknown-linux-gnu:Linux:arm64) ;;
  *) fail 'requested host triple does not match this machine' ;;
esac
for tool in awk bash curl env git jq shasum tar tr wc; do command -v "$tool" >/dev/null || fail "missing required tool: $tool"; done

source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work_parent=$(cd -P -- "$(dirname -- "$requested_work")" && pwd -P)
work="$work_parent/${requested_work##*/}"
case "$work/" in "$source_root/"*) fail 'work root must be outside the source checkout' ;; esac
case "$source_root/" in "$work/"*) fail 'work root overlaps the source checkout' ;; esac
[[ ! -e "$work" && ! -L "$work" ]] || fail 'work root must be fresh and absent'
git -C "$source_root" rev-parse --is-inside-work-tree >/dev/null || fail 'source root must be a Git working tree'
source_head=$(git -C "$source_root" rev-parse HEAD)
source_tree=$(git -C "$source_root" rev-parse 'HEAD^{tree}')
source_status=$(git -C "$source_root" status --porcelain --untracked-files=all)
source_dirty=false
[[ -z "$source_status" ]] || source_dirty=true

vendor_profile="$source_root/release/native-cargo-vendor-inputs.json"
vendor_archive="$source_root/release/inputs/native-cargo-vendor.tar.xz"
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
size() { wc -c < "$1" | tr -d '[:space:]'; }
jq -e '.schema == "ami-rust-native-cargo-vendor-inputs-v1" and .path == "release/inputs/native-cargo-vendor.tar.xz" and .component_root == "vendor"' "$vendor_profile" >/dev/null || fail 'native Cargo vendor input profile is malformed'
vendor_profile_sha=$(sha "$vendor_profile")
vendor_bytes=$(jq -er '.bytes' "$vendor_profile")
vendor_sha=$(jq -er '.sha256' "$vendor_profile")
[[ -f "$vendor_archive" && ! -L "$vendor_archive" && $(size "$vendor_archive") == "$vendor_bytes" && $(sha "$vendor_archive") == "$vendor_sha" ]] || fail 'native Cargo vendor archive identity differs'
for lock in Cargo.lock tooling/Cargo.lock; do
  actual=$(sha "$source_root/$lock")
  expected=$(jq -er --arg lock "$lock" '.source_locks[$lock]' "$vendor_profile")
  [[ "$actual" == "$expected" ]] || fail "native vendor source lock differs: $lock"
  if [[ "$lock" == Cargo.lock ]]; then application_lock_sha=$actual; else tooling_lock_sha=$actual; fi
done
tar -tf "$vendor_archive" | awk '{ p=$0; sub(/\/+$/, "", p); if (p == "" || p ~ /^\// || p ~ /(^|\/)\.\.?($|\/)/ || (p != "vendor" && substr(p,1,7) != "vendor/")) bad=1; n++ } END { if (!n || bad) exit 1 }' || fail 'vendor archive members escape the declared root'

mkdir -m 700 -- "$work"
mkdir -m 700 -- "$work/home" "$work/tmp" "$work/cargo-home" "$work/vendor-unpack" "$work/target"
tar -xf "$vendor_archive" -C "$work/vendor-unpack"
[[ -d "$work/vendor-unpack/vendor" && ! -L "$work/vendor-unpack/vendor" ]] || fail 'authenticated vendor archive root is missing'
jq -nr --arg directory "$work/vendor-unpack/vendor" '"[net]\noffline = true\n[source.crates-io]\nreplace-with = \"maintainer-vendor\"\n[source.maintainer-vendor]\ndirectory = " + ($directory | tojson)' > "$work/cargo-home/config.toml"

bootstrap_profile="$source_root/release/maintainer-rust-bootstrap-inputs.json"
bootstrap_profile_sha=$(sha "$bootstrap_profile")
bootstrap_script_sha=$(sha "$source_root/tools/bootstrap-host-rust.sh")
builder_script_sha=$(sha "$source_root/tools/build-maintainer-task.sh")
env -i HOME="$work/home" TMPDIR="$work/tmp" PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 \
  bash "$source_root/tools/bootstrap-host-rust.sh" "$work/bootstrap" "$host_triple" > "$work/bootstrap.log" 2>&1 || { cat "$work/bootstrap.log" >&2; fail 'pinned Rust bootstrap failed'; }
rustc="$work/bootstrap/toolchain/bin/rustc"
cargo_bin="$work/bootstrap/toolchain/bin/cargo"
tool_path="$work/bootstrap/toolchain/bin:/usr/bin:/bin:/usr/sbin:/sbin"
clean_tool() { env -i HOME="$work/home" TMPDIR="$work/tmp" PATH="$tool_path" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 "$@"; }
rustc_version=$(clean_tool "$rustc" -Vv 2>&1)
cargo_version=$(clean_tool "$cargo_bin" -Vv 2>&1)
printf '%s\n' "$rustc_version" > "$work/rustc-version.log"
printf '%s\n' "$cargo_version" > "$work/cargo-version.log"
[[ "$rustc_version" == *'commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985'* && "$rustc_version" == *"host: $host_triple"* ]] || fail 'bootstrapped rustc identity differs'
[[ "$cargo_version" == *'commit-hash: 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d'* && "$cargo_version" == *"host: $host_triple"* ]] || fail 'bootstrapped cargo identity differs'

build_cargo() {
  env -i HOME="$work/home" TMPDIR="$work/tmp" PATH="$tool_path" CARGO_HOME="$work/cargo-home" \
    CARGO_TARGET_DIR="$work/target" CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
    RUSTC="$rustc" RUSTDOC="$work/bootstrap/toolchain/bin/rustdoc" RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER= \
    LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 "$cargo_bin" "$@"
}
if ! build_cargo build --locked --offline --release --manifest-path "$source_root/tooling/Cargo.toml" -p ami-rust-xtask -j 2 > "$work/build.log" 2>&1; then
  cat "$work/build.log" >&2
  fail 'offline maintainer xtask build failed'
fi
executable="$work/target/release/ami-rust-xtask"
[[ -f "$executable" && ! -L "$executable" && -x "$executable" ]] || fail 'release xtask executable is missing'

bootstrap_rustc_archive="$work/bootstrap/downloads/rustc-1.98.1-$host_triple.tar.xz"
bootstrap_cargo_archive="$work/bootstrap/downloads/cargo-1.98.1-$host_triple.tar.xz"
bootstrap_std_archive="$work/bootstrap/downloads/rust-std-1.98.1-$host_triple.tar.xz"
jq -n \
  --arg host "$host_triple" --arg executable "$executable" --arg executable_sha "$(sha "$executable")" --argjson executable_bytes "$(size "$executable")" \
  --arg source_root "$source_root" --arg source_head "$source_head" --arg source_tree "$source_tree" --argjson source_dirty "$source_dirty" --arg source_status "$source_status" \
  --arg application_lock_sha "$application_lock_sha" --arg tooling_lock_sha "$tooling_lock_sha" \
  --arg vendor_profile_sha "$vendor_profile_sha" --arg vendor_sha "$vendor_sha" --argjson vendor_bytes "$vendor_bytes" \
  --arg bootstrap_profile_sha "$bootstrap_profile_sha" --arg bootstrap_script_sha "$bootstrap_script_sha" --arg builder_script_sha "$builder_script_sha" --arg bootstrap_rustc_archive_sha "$(sha "$bootstrap_rustc_archive")" --arg bootstrap_cargo_archive_sha "$(sha "$bootstrap_cargo_archive")" --arg bootstrap_std_archive_sha "$(sha "$bootstrap_std_archive")" \
  --arg bootstrapped_rustc_sha "$(sha "$rustc")" --arg bootstrapped_cargo_sha "$(sha "$cargo_bin")" --arg rustc_version "$rustc_version" --arg cargo_version "$cargo_version" \
  '{schema:"ami-rust-maintainer-task-build-v1",status:"PASS_LOCAL_OFFLINE_MAINTAINER_BUILD",host_triple:$host,executable:{path:$executable,bytes:$executable_bytes,sha256:$executable_sha},source:{root:$source_root,head:$source_head,tree:$source_tree,dirty:$source_dirty,revision:(if $source_dirty then $source_head+"+working-tree" else $source_head end),status:$source_status},locks:{"Cargo.lock":$application_lock_sha,"tooling/Cargo.lock":$tooling_lock_sha},vendor:{profile_sha256:$vendor_profile_sha,archive_bytes:$vendor_bytes,archive_sha256:$vendor_sha},bootstrap:{profile_sha256:$bootstrap_profile_sha,script_sha256:$bootstrap_script_sha,rustc_archive_sha256:$bootstrap_rustc_archive_sha,cargo_archive_sha256:$bootstrap_cargo_archive_sha,rust_std_archive_sha256:$bootstrap_std_archive_sha,rustc_sha256:$bootstrapped_rustc_sha,cargo_sha256:$bootstrapped_cargo_sha,rustc_version:$rustc_version,cargo_version:$cargo_version},build:{script_sha256:$builder_script_sha,release:true,locked:true,offline:true,jobs:2,incremental:false}}' > "$work/build-receipt.json"
cat "$work/build-receipt.json"

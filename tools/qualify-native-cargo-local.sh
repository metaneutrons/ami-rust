#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Local development of the same native Cargo proof used by protected CI.
set -euo pipefail
umask 077
[[ $# == 5 ]] || { echo 'usage: qualify-native-cargo-local.sh HOST PINNED_ZIP_CACHE PINNED_BOOTSTRAP_PREFIX RUSTUP_BINARY FRESH_BASE' >&2; exit 2; }
host=$1
cache=$2
bootstrap=$3
rustup=$4
base=$5
case "$host:$(uname -s):$(uname -m)" in
  macos-aarch64:Darwin:arm64|macos-aarch64:Darwin:aarch64|linux-x86_64:Linux:x86_64|linux-aarch64:Linux:aarch64|linux-aarch64:Linux:arm64) ;;
  *) echo 'requested host does not match this machine' >&2; exit 2 ;;
esac
case "$base" in /*) ;; *) echo 'absolute fresh base required' >&2; exit 2 ;; esac
[[ "$base" != *'/../'* && "$base" != *'/./'* && ! -e "$base" && ! -L "$base" ]] || exit 2
base="$(cd -P -- "$(dirname -- "$base")" && pwd -P)/$(basename -- "$base")"
source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
pins="$source_root/release/native-cargo-qualification-prerequisites.json"
jq -e --arg host "$host" '.native_cargo.hosts[$host] != null and .bare_target_libraries.hosts[$host] != null' "$pins" >/dev/null
[[ -f "$rustup" && -x "$rustup" && -x "$bootstrap/bin/cargo" && -x "$bootstrap/bin/rustc" ]] || exit 2
mkdir -m 700 "$base"
export RUNNER_TEMP="$base"
export NATIVE_CAMPAIGN_START_EPOCH
NATIVE_CAMPAIGN_START_EPOCH=${NATIVE_CAMPAIGN_START_EPOCH:-$(date +%s)}
[[ "$NATIVE_CAMPAIGN_START_EPOCH" =~ ^[1-9][0-9]{0,9}$ ]] || exit 2
elapsed=$(( $(date +%s) - NATIVE_CAMPAIGN_START_EPOCH ))
[[ $elapsed -ge 0 && $elapsed -le 3900 ]] || { echo 'campaign clock lacks a complete command window' >&2; exit 2; }
managed="$base/ami-rust-native-cargo-consumer/$host"
mkdir -p "$managed"
mkdir -m 700 "$managed/auth" "$managed/downloads" "$managed/bootstrap-home" "$managed/tmp" "$managed/bootstrap" "$managed/local-tools"
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
for component in native_cargo bare_target_libraries linux_aarch64_csdk; do
  [[ "$component" != linux_aarch64_csdk || "$host" == linux-aarch64 ]] || continue
  row=$(jq -ce --arg key "$component" --arg host "$host" '.[$key] as $run | $run + (if $run.hosts then $run.hosts[$host] else {} end)' "$pins")
  if [[ "$component" == linux_aarch64_csdk ]]; then input="$cache/$component.zip"; else input="$cache/$component-$host.zip"; fi
  [[ -f "$input" && ! -L "$input" && $(wc -c < "$input" | tr -d '[:space:]') == "$(jq -er '.zip_bytes' <<<"$row")" && $(sha "$input") == "$(jq -er '.zip_sha256' <<<"$row")" ]] || { echo 'cached prerequisite ZIP identity differs' >&2; exit 1; }
  unzip -tq "$input" >/dev/null
  command cp "$input" "$managed/downloads/$component.zip"
done
case "$(uname -s)" in
  Darwin) command cp -cR "$bootstrap" "$managed/bootstrap/toolchain" ;;
  Linux) command cp -a --reflink=auto "$bootstrap" "$managed/bootstrap/toolchain" ;;
  *) exit 2 ;;
esac
command cp "$rustup" "$managed/local-tools/rustup"
chmod 0755 "$managed/local-tools/rustup"
export PATH="$managed/local-tools:$PATH"
# These copies never change the user's toolchain, defaults or registry cache.
jq -n --arg host "$host" --arg bootstrap "$bootstrap" --arg rustup_sha256 "$(sha "$rustup")" \
  '{host:$host,bootstrap_source:$bootstrap,rustup_sha256:$rustup_sha256,claim:"Local pinned-byte reuse; no new GitHub publisher authentication or release acceptance."}' \
  > "$managed/auth/local-inputs.json"
runner="$source_root/tools/qualify-native-cargo-consumer.sh"
bash "$runner" compile-helper "$host" "$managed" > "$managed/auth/helper-build-wrapper.log" 2>&1
bash "$runner" measure-stage "$host" "$managed"
bash "$runner" prove "$host" "$managed"
jq -e '.status == "PASS_LOCAL_NATIVE_CARGO_QUALIFICATION"' "$managed/proof/result.json" >/dev/null
cat "$managed/proof/result.json"

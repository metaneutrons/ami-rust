#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Maintainer-only bootstrap for the Linux AArch64 observer's negative Python counter.
set -euo pipefail
unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN

if [ "$#" -ne 1 ]; then
  echo "usage: bootstrap-python-counter-linux-aarch64.sh FRESH_PREFIX" >&2
  exit 2
fi
cli_prefix=$1
case "$cli_prefix" in /*) ;; *) echo "prefix must be absolute" >&2; exit 2 ;; esac
if [ -e "$cli_prefix" ] || [ -L "$cli_prefix" ]; then
  echo "prefix must be fresh and absent" >&2
  exit 2
fi

cli_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cli_pins="$cli_root/release/ci-python-counter-linux-aarch64-inputs.json"
test "$(jq -er '.schema' "$cli_pins")" = ami-rust-ci-python-counter-linux-aarch64-inputs-v1
test "$(uname -m)" = aarch64
test "$(jq -er '.host' "$cli_pins")" = linux-aarch64
test "$(jq -er '.runtime.elf.machine' "$cli_pins")" = 183
cli_manifest_url=$(jq -er '.manifest.url' "$cli_pins")
cli_manifest_bytes=$(jq -er '.manifest.bytes' "$cli_pins")
cli_manifest_sha=$(jq -er '.manifest.sha256' "$cli_pins")
cli_archive_url=$(jq -er '.archive.url' "$cli_pins")
cli_archive_name=$(jq -er '.archive.filename' "$cli_pins")
cli_archive_bytes=$(jq -er '.archive.bytes' "$cli_pins")
cli_archive_sha=$(jq -er '.archive.sha256' "$cli_pins")
cli_manifest_line=$(jq -er '.archive.manifest_line' "$cli_pins")
cli_runtime_relative=$(jq -er '.runtime.runtime_relative_path' "$cli_pins")
cli_runtime_bytes=$(jq -er '.runtime.runtime_bytes' "$cli_pins")
cli_runtime_sha=$(jq -er '.runtime.runtime_sha256' "$cli_pins")

test "$cli_manifest_url" = "https://github.com/astral-sh/python-build-standalone/releases/download/20261013/SHA256SUMS"
test "$cli_manifest_bytes" = 142015
test "$cli_manifest_sha" = 6f1da4ab940bfca4471b0816828f16942a149de31e7ac4745e90902d5e7d3ebd
test "$cli_archive_url" = "https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-aarch64-unknown-linux-gnu-install_only.tar.gz"
test "$cli_archive_name" = "cpython-3.12.15+20261013-aarch64-unknown-linux-gnu-install_only.tar.gz"
test "$cli_archive_bytes" = 52391962
test "$cli_archive_sha" = 34a43010cc05982d8b5debbad7d09f7b1200117ebf018f7acfd656895e408205
test "$cli_manifest_line" = "34a43010cc05982d8b5debbad7d09f7b1200117ebf018f7acfd656895e408205  cpython-3.12.15+20261013-aarch64-unknown-linux-gnu-install_only.tar.gz"
test "$cli_runtime_relative" = "python/bin/python3.12"
test "$cli_runtime_bytes" = 62839864
test "$cli_runtime_sha" = a8dfeaae509054434bf7f6faf32402e35df03f72ad83ac6bb20af543b78f33ec

mkdir -m 700 -- "$cli_prefix"
mkdir -m 700 -- "$cli_prefix/downloads" "$cli_prefix/runtime"
cli_manifest="$cli_prefix/downloads/SHA256SUMS"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --max-time 120 --max-filesize "$cli_manifest_bytes" \
  --output "$cli_manifest" "$cli_manifest_url"
test "$(wc -c < "$cli_manifest" | tr -d ' ')" = "$cli_manifest_bytes"
cli_manifest_actual=$(shasum -a 256 "$cli_manifest")
test "${cli_manifest_actual%% *}" = "$cli_manifest_sha"
test "$(grep -Fxc -- "$cli_manifest_line" "$cli_manifest")" = 1

cli_archive="$cli_prefix/downloads/$cli_archive_name"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --max-time 120 --max-filesize "$cli_archive_bytes" \
  --output "$cli_archive" "$cli_archive_url"
test "$(wc -c < "$cli_archive" | tr -d ' ')" = "$cli_archive_bytes"
cli_archive_actual=$(shasum -a 256 "$cli_archive")
test "${cli_archive_actual%% *}" = "$cli_archive_sha"

# The exact archive hash is bound to the retained full member/type/path and
# symlink-closure inventory; extract that reviewed artifact under a fresh root.
tar --extract --gzip --file "$cli_archive" --directory "$cli_prefix/runtime" \
  --no-same-owner --no-same-permissions
cli_runtime="$cli_prefix/runtime/$cli_runtime_relative"
test -f "$cli_runtime"
test -x "$cli_runtime"
test ! -L "$cli_runtime"
test "$(wc -c < "$cli_runtime" | tr -d ' ')" = "$cli_runtime_bytes"
cli_runtime_actual=$(shasum -a 256 "$cli_runtime")
test "${cli_runtime_actual%% *}" = "$cli_runtime_sha"
printf 'verified pinned Linux AArch64 Python counter: %s\n' "$cli_runtime"

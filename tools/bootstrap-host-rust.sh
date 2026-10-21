#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Install the existing authenticated host bootstrap inputs into a fresh prefix.
# This does not change rustup defaults or select a new AROS target compiler.
set -euo pipefail
unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN

if [ "$#" -ne 2 ]; then
  echo "usage: bootstrap-host-rust.sh FRESH_PREFIX HOST_TRIPLE" >&2
  exit 2
fi
cli_prefix=$1
cli_triple=$2
case "$cli_prefix" in /*) ;; *) echo "prefix must be absolute" >&2; exit 2 ;; esac
if [ -e "$cli_prefix" ] || [ -L "$cli_prefix" ]; then
  echo "prefix must be fresh and absent" >&2
  exit 2
fi
cli_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
case "$cli_triple" in
  aarch64-apple-darwin|x86_64-unknown-linux-gnu)
    cli_pins="$cli_root/release/ci-bootstrap-inputs.json"
    cli_pin_schema=ami-rust-ci-cargo-inputs-v1
    ;;
  aarch64-unknown-linux-gnu)
    cli_pins="$cli_root/release/ci-bootstrap-linux-aarch64-inputs.json"
    cli_pin_schema=ami-rust-ci-bootstrap-linux-aarch64-inputs-v1
    ;;
  *) echo "unsupported host" >&2; exit 2 ;;
esac
test "$(jq -er '.schema' "$cli_pins")" = "$cli_pin_schema"
cli_commit=$(jq -er '.rust.commit' "$cli_pins")
test "$cli_commit" = 48a229ceaefd4985c50990b14116b6d856af0985
cli_cargo_commit=$(jq -er '.rust.cargo_commit' "$cli_pins")
test "$cli_cargo_commit" = 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d
cli_release=$(jq -er '.rust.release' "$cli_pins")
test "$cli_release" = 1.98.1
if [ "$cli_triple" = aarch64-unknown-linux-gnu ]; then
  test "$(jq -er '.host_triple' "$cli_pins")" = "$cli_triple"
  test "$(jq -er '.rust.manifest.url' "$cli_pins")" = "https://static.rust-lang.org/dist/channel-rust-1.98.1.toml"
  test "$(jq -er '.rust.manifest.sha256' "$cli_pins")" = a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e
  test "$(jq -er '.rust.manifest.bytes' "$cli_pins")" = 898637
fi
mkdir -p -- "$cli_prefix/downloads" "$cli_prefix/unpacked"

for cli_component in rustc cargo rust-std; do
  cli_url=$(jq -er --arg triple "$cli_triple" --arg component "$cli_component" '.rust.components[$triple][$component].url' "$cli_pins")
  cli_sha=$(jq -er --arg triple "$cli_triple" --arg component "$cli_component" '.rust.components[$triple][$component].sha256' "$cli_pins")
  cli_size=$(jq -er --arg triple "$cli_triple" --arg component "$cli_component" '.rust.components[$triple][$component].http_content_length' "$cli_pins")
  cli_name="$cli_component-$cli_release-$cli_triple"
  test "$cli_url" = "https://static.rust-lang.org/dist/2026-09-03/$cli_name.tar.xz"
  [[ "$cli_sha" =~ ^[0-9a-f]{64}$ ]]
  [[ "$cli_size" =~ ^[1-9][0-9]*$ ]]
  cli_archive="$cli_prefix/downloads/$cli_name.tar.xz"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --max-time 120 --max-filesize "$cli_size" \
    --output "$cli_archive" "$cli_url"
  test "$(wc -c < "$cli_archive" | tr -d ' ')" = "$cli_size"
  cli_actual=$(shasum -a 256 "$cli_archive")
  test "${cli_actual%% *}" = "$cli_sha"
  tar -xJf "$cli_archive" -C "$cli_prefix/unpacked"
  bash "$cli_prefix/unpacked/$cli_name/install.sh" --prefix="$cli_prefix/toolchain" --disable-ldconfig
done

cli_version=$("$cli_prefix/toolchain/bin/rustc" -Vv)
case "$cli_version" in *"commit-hash: $cli_commit"*) ;; *) echo "host compiler mismatch" >&2; exit 1 ;; esac
printf '%s\n' "$cli_version"
"$cli_prefix/toolchain/bin/cargo" -Vv

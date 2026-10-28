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
  aarch64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "unsupported host" >&2; exit 2 ;;
esac
cli_pins="$cli_root/release/maintainer-rust-bootstrap-inputs.json"
test "$(jq -er '.schema' "$cli_pins")" = ami-rust-maintainer-rust-bootstrap-inputs-v1
test "$(jq -er '.status' "$cli_pins")" = pinned
cli_commit=$(jq -er '.rust.commit' "$cli_pins")
test "$cli_commit" = 48a229ceaefd4985c50990b14116b6d856af0985
cli_cargo_commit=$(jq -er '.rust.cargo_commit' "$cli_pins")
test "$cli_cargo_commit" = 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d
cli_release=$(jq -er '.rust.release' "$cli_pins")
test "$cli_release" = 1.98.1
test "$(jq -er '.rust.manifest.url' "$cli_pins")" = "https://static.rust-lang.org/dist/channel-rust-1.98.1.toml"
test "$(jq -er '.rust.manifest.sha256' "$cli_pins")" = a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e
test "$(jq -er '.rust.manifest.bytes' "$cli_pins")" = 898637
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

if [ "$cli_triple" = aarch64-apple-darwin ]; then
  cli_llvm_library="$cli_prefix/toolchain/lib/libLLVM.dylib"
  cli_objcopy="$cli_prefix/toolchain/lib/rustlib/aarch64-apple-darwin/bin/rust-objcopy"
  cli_objcopy_lib="$cli_prefix/toolchain/lib/rustlib/aarch64-apple-darwin/lib"
  cli_llvm_alias="$cli_objcopy_lib/libLLVM.dylib"
  cli_llvm_alias_target=../../../libLLVM.dylib

  if [ ! -f "$cli_llvm_library" ]; then
    echo "installed macOS Rust toolchain is missing lib/libLLVM.dylib" >&2
    exit 1
  fi
  if [ ! -f "$cli_objcopy" ] || [ ! -x "$cli_objcopy" ]; then
    echo "installed macOS Rust toolchain is missing executable rust-objcopy" >&2
    exit 1
  fi

  mkdir -p -- "$cli_objcopy_lib"
  if [ -L "$cli_llvm_alias" ]; then
    if [ "$(readlink "$cli_llvm_alias")" != "$cli_llvm_alias_target" ] \
      || [ ! "$cli_llvm_alias" -ef "$cli_llvm_library" ]; then
      echo "installed macOS Rust toolchain has an unexpected libLLVM.dylib alias" >&2
      exit 1
    fi
  elif [ -e "$cli_llvm_alias" ]; then
    echo "refusing to replace existing rust-objcopy libLLVM.dylib file" >&2
    exit 1
  else
    ln -s "$cli_llvm_alias_target" "$cli_llvm_alias"
  fi

  if [ ! -L "$cli_llvm_alias" ] || [ ! "$cli_llvm_alias" -ef "$cli_llvm_library" ]; then
    echo "macOS Rust libLLVM.dylib alias does not resolve to the installed library" >&2
    exit 1
  fi
  # Clear only loader override variables for this smoke command; preserve the caller's environment.
  /usr/bin/env \
    -u DYLD_LIBRARY_PATH \
    -u DYLD_FRAMEWORK_PATH \
    -u DYLD_FALLBACK_LIBRARY_PATH \
    -u DYLD_FALLBACK_FRAMEWORK_PATH \
    -u DYLD_VERSIONED_LIBRARY_PATH \
    -u DYLD_VERSIONED_FRAMEWORK_PATH \
    -u DYLD_INSERT_LIBRARIES \
    -u DYLD_ROOT_PATH \
    -u DYLD_IMAGE_SUFFIX \
    "$cli_objcopy" --version
fi

cli_version=$("$cli_prefix/toolchain/bin/rustc" -Vv)
case "$cli_version" in *"commit-hash: $cli_commit"*) ;; *) echo "host compiler mismatch" >&2; exit 1 ;; esac
printf '%s\n' "$cli_version"
"$cli_prefix/toolchain/bin/cargo" -Vv

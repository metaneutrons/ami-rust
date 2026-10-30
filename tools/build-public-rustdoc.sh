#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Produce the public Rust API reference with the pinned host toolchain.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: build-public-rustdoc.sh FRESH_ABSOLUTE_WORK HOST_TRIPLE'
requested_work=$1
host_triple=$2
case "$requested_work" in /*) ;; *) fail 'work root must be absolute' ;; esac
[[ "$requested_work" != / && "$requested_work" != */ ]] || fail 'work root must name a fresh directory'
case "/$requested_work/" in *'/../'*|*'/./'*) fail 'work root must be normalized' ;; esac

source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work_parent=$(cd -P -- "$(dirname -- "$requested_work")" && pwd -P)
work="$work_parent/${requested_work##*/}"
case "$work/" in "$source_root/"*) fail 'work root must be outside the source checkout' ;; esac
case "$source_root/" in "$work/"*) fail 'work root overlaps the source checkout' ;; esac
[[ ! -e "$work" && ! -L "$work" ]] || fail 'work root must be fresh and absent'

# This establishes the authenticated bootstrap and the offline vendor source
# before documentation is built. It also leaves a hermetic host toolchain in
# the work root for the command below.
bash "$source_root/tools/build-maintainer-task.sh" "$work" "$host_triple"

toolchain="$work/bootstrap/toolchain"
tool_path="$toolchain/bin:/usr/bin:/bin:/usr/sbin:/sbin"
env -i \
  HOME="$work/home" TMPDIR="$work/tmp" PATH="$tool_path" \
  CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/public-rustdoc" \
  CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  RUSTC="$toolchain/bin/rustc" RUSTDOC="$toolchain/bin/rustdoc" \
  RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER= RUSTDOCFLAGS='-D warnings' \
  LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 \
  "$toolchain/bin/cargo" doc --locked --offline --no-deps \
    --manifest-path "$source_root/Cargo.toml" -p aros -p aros-mui -j 2

for page in "$work/public-rustdoc/doc/aros/index.html" "$work/public-rustdoc/doc/aros_mui/index.html"; do
  [[ -f "$page" && ! -L "$page" ]] || fail "public Rustdoc page is missing: $page"
done
printf '%s\n' "$work/public-rustdoc/doc"

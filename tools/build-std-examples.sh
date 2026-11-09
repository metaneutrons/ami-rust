#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build `std` programs of this tree for both ABIs with a toolchain that ships `std`, using plain
# `cargo build` (no `build-std`) and the offline vendor set of the native Cargo qualification.
# It proves that an installed toolchain carries a working `std` and a usable `aros-link`; it does
# not run the programs (the native matrix does that).
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -ge 3 ]] || fail 'usage: build-std-examples.sh TOOLCHAIN_ROOT FRESH_WORK_DIR OUTPUT_DIR [EXAMPLE...]'
root=$1
work=$2
out=$3
shift 3
examples=("$@")
[[ ${#examples[@]} -gt 0 ]] || examples=(std-path std-threads)
for path in "$root" "$work" "$out"; do
  case "$path" in /*) ;; *) fail "path must be absolute: $path" ;; esac
done
[[ -x "$root/bin/cargo" && -x "$root/bin/rustc" && -x "$root/bin/aros-link" ]] || fail 'toolchain root lacks cargo, rustc or aros-link'
[[ ! -e "$work" ]] || fail 'work directory must be fresh and absent'
repo=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

mkdir -p "$work/cargo-home" "$work/target" "$out"
tar -xJf "$repo/release/inputs/native-cargo-vendor.tar.xz" -C "$work"
cat > "$work/cargo-home/config.toml" <<EOF
[net]
offline = true

[source.crates-io]
replace-with = "vendor"

[source.vendor]
directory = "$work/vendor"
EOF

# A toolchain with no std libraries must fail here, not later in a build.
for abi in abi1 abi11; do
  libdir="$root/lib/rustlib/x86_64-unknown-aros-$abi/lib"
  for crate in std panic_abort core alloc; do
    ls "$libdir"/lib"$crate"-*.rlib "$libdir"/lib"$crate"-*.rmeta >/dev/null 2>&1 || fail "toolchain lacks lib$crate for $abi"
  done
done

for example in "${examples[@]}"; do
  [[ -f "$repo/examples/$example/Cargo.toml" ]] || fail "unknown example: $example"
  ! grep -q 'build-std' "$repo/examples/$example/.cargo/config.toml" || fail "$example still asks for build-std"
  for abi in abi1 abi11; do
    target="x86_64-unknown-aros-$abi"
    (
      cd "$repo/examples/$example"
      env -i \
        HOME="$work" PATH="$root/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" \
        RUSTC="$root/bin/rustc" CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true LC_ALL=C TZ=UTC \
        ${SDKROOT:+SDKROOT="$SDKROOT"} \
        "$root/bin/cargo" build --release --locked --offline --target "$target"
    )
    elf="$work/target/$target/release/$example"
    [[ -s "$elf" ]] || fail "no program was built: $example for $target"
    cp "$elf" "$out/$example-$abi"
    printf 'built %s for %s: %s bytes\n' "$example" "$target" "$(wc -c < "$elf" | tr -d '[:space:]')"
  done
done

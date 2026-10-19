#!/usr/bin/env bash
# Build host tooling with explicit, already-pinned Rust inputs. No publication.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo 'usage: build-native-cli.sh TARGET_DIRECTORY' >&2
  exit 2
fi
: "${CLI_CARGO:?explicit host Cargo executable required}"
: "${RUSTC:?explicit host Rust compiler required}"
: "${RUSTDOC:?explicit host Rust documentation executable required}"
: "${CARGO_HOME:?explicit host registry cache required}"
for cli_tool in "$CLI_CARGO" "$RUSTC" "$RUSTDOC"; do
  [[ "$cli_tool" = /* && -x "$cli_tool" ]]
done
cli_source=$(git rev-parse --show-toplevel)
cli_sysroot=$("$RUSTC" --print sysroot)
[[ "$1" = /* && "$CARGO_HOME" = /* ]]
unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN RUSTFLAGS
export CARGO_BUILD_JOBS=2
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s' "--remap-path-prefix=$cli_source=/ami-rust" "--remap-path-prefix=$CARGO_HOME=/cargo")
export CARGO_ENCODED_RUSTFLAGS
if [[ "$(uname -s)" == Darwin ]]; then
  # Remove the per-root Rust sysroot prefix from the linker debug map before
  # computing its UUID. Keep LC_UUID: macOS 26 requires it at load time.
  CARGO_ENCODED_RUSTFLAGS+=$(printf '\037%s' "-Clink-arg=-Wl,-oso_prefix,$cli_sysroot/")
  export CARGO_ENCODED_RUSTFLAGS
  # The pinned macOS rust-objcopy links libLLVM from the toolchain's lib
  # directory, which is outside its embedded runtime search paths.
  DYLD_LIBRARY_PATH="$cli_sysroot/lib" \
    "$CLI_CARGO" build --release --locked --offline --package ami-rust-cli \
      --manifest-path "$cli_source/tooling/Cargo.toml" --target-dir "$1"
else
  "$CLI_CARGO" build --release --locked --offline --package ami-rust-cli \
    --manifest-path "$cli_source/tooling/Cargo.toml" --target-dir "$1"
fi
cli_binary="$1/release/ami-rust"

portable_cli() {
  local cli_scan_status cli_prefix
  for cli_prefix in "$cli_source" "$CARGO_HOME" "$cli_sysroot"; do
    if LC_ALL=C grep -aFq -- "$cli_prefix" "$1"; then
      printf 'native CLI embeds build path prefix: %s\n' "$cli_prefix" >&2
      return 1
    else
      cli_scan_status=$?
      if [ "$cli_scan_status" -ne 1 ]; then
        return "$cli_scan_status"
      fi
    fi
  done
}

portable_cli "$cli_binary"
# Corrupt an isolated copy to prove the path scan detects its own input.
cli_counter="$1/native-cli-path-counterprobe"
if [[ -e "$cli_counter" || -L "$cli_counter" ]]; then
  echo 'path counterprobe destination already exists' >&2
  exit 2
fi
command cp "$cli_binary" "$cli_counter"
printf '%s' "$cli_source" >> "$cli_counter"
if portable_cli "$cli_counter"; then
  echo 'native CLI path scan accepted the corrupted control' >&2
  exit 1
else
  cli_counter_status=$?
  test "$cli_counter_status" = 1
fi
command rm "$cli_counter"
"$cli_binary" --version
printf 'Native CLI bytes: '
wc -c < "$cli_binary"
printf 'Native CLI path scan: PASS; isolated counterprobe: REFUSED\n'

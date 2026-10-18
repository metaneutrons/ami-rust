#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Internal RC0 proof driver. Inputs come from immutable, reviewed release pins.
# Not a consumer installer, authentication policy or RC1 replacement CLI.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo 'usage: rc0-native-probe.sh FRESH_ROOT HOST_PROFILE [EXISTING_SELECTION_JSON]' >&2
  exit 2
fi
probe_out=$1
probe_host=$2
probe_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# A hidden Cargo override can alter the target or host recipe before a linker
# ever runs. Reject it before creating a state/output directory.
while IFS= read -r probe_variable; do
  case "$probe_variable" in
    CARGO_*|RUSTFLAGS|RUSTC|RUSTDOC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTC_BOOTSTRAP|RUSTDOCFLAGS)
      echo "ambient compiler/Cargo override refused: $probe_variable" >&2
      exit 2 ;;
  esac
done < <(compgen -e)
case "$probe_out" in /*) ;; *) exit 2 ;; esac
case "$probe_host" in macos-aarch64) probe_triple=aarch64-apple-darwin ;; linux-x86_64) probe_triple=x86_64-unknown-linux-gnu ;; *) exit 2 ;; esac
test ! -e "$probe_out"
mkdir -p -- "$probe_out/downloads" "$probe_out/components" "$probe_out/evidence"
probe_out=$(cd -- "$probe_out" && pwd)
probe_pins="$probe_source/release/ci-sdk-inputs.json"

probe_hash() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
probe_download() {
  local url=$1 file=$2 bytes=$3 sha=$4
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]]
  [[ "$bytes" =~ ^[1-9][0-9]*$ ]]
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --max-time 300 --max-filesize "$bytes" --output "$file" "$url"
  test "$(wc -c < "$file" | tr -d ' ')" = "$bytes"
  test "$(probe_hash "$file")" = "$sha"
}

if [ "$#" = 3 ]; then
  probe_selection=$3
  for probe_component in rust cargo toolchain collector csdk vendor; do
    probe_path=$(jq -er --arg name "$probe_component" '.components[$name]' "$probe_selection")
    test -d "$probe_path"
    ln -s -- "$probe_path" "$probe_out/components/$probe_component"
  done
else
  # Only this bounded internal experiment consumes the old SDK payload. It is
  # inert source/input material; none of its Python launchers is executed.
  probe_release="$probe_out/downloads/release.tar.xz"
  probe_download 'https://github.com/metaneutrons/ami-rust/releases/download/v0.1.0/ami-rust-0.1.0-release.tar.xz' \
    "$probe_release" 25902508 f4a8cbc562d3c43c573a5a34ddfa99d74928ded94c47df45f4182fde71567d5c
  mkdir "$probe_out/old-bundle" "$probe_out/unpacked"
  tar -xJf "$probe_release" -C "$probe_out/old-bundle"
  test -f "$probe_out/old-bundle/cargo-$probe_host.tar.xz"
  mkdir "$probe_out/components/cargo"
  tar -xJf "$probe_out/old-bundle/cargo-$probe_host.tar.xz" -C "$probe_out/components/cargo"
  mkdir "$probe_out/components/rust"
  while IFS=$'\t' read -r probe_url probe_bytes probe_sha; do
    probe_name=${probe_url##*/}
    probe_archive="$probe_out/downloads/$probe_name"
    probe_download "$probe_url" "$probe_archive" "$probe_bytes" "$probe_sha"
    tar -xJf "$probe_archive" -C "$probe_out/unpacked"
    bash "$probe_out/unpacked/${probe_name%.tar.xz}/install.sh" \
      --prefix="$probe_out/components/rust" --disable-ldconfig
  done < <(jq -er --arg host "$probe_host" '.hosts[$host].rust.archives[] | [.url,.bytes,.sha256] | @tsv' "$probe_pins")
  for probe_component in toolchain collector; do
    probe_url=$(jq -er --arg host "$probe_host" --arg name "$probe_component" '.hosts[$host][$name].url' "$probe_pins")
    probe_bytes=$(jq -er --arg host "$probe_host" --arg name "$probe_component" '.hosts[$host][$name].bytes' "$probe_pins")
    probe_sha=$(jq -er --arg host "$probe_host" --arg name "$probe_component" '.hosts[$host][$name].sha256' "$probe_pins")
    probe_archive="$probe_out/downloads/$probe_component.tar"
    probe_download "$probe_url" "$probe_archive" "$probe_bytes" "$probe_sha"
    mkdir "$probe_out/unpacked/$probe_component"
    tar -xf "$probe_archive" -C "$probe_out/unpacked/$probe_component"
    probe_subdir=$(jq -er --arg host "$probe_host" --arg name "$probe_component" '.hosts[$host][$name].archive_root' "$probe_pins")
    ln -s "$probe_out/unpacked/$probe_component/$probe_subdir" "$probe_out/components/$probe_component"
  done
  test "$(probe_hash "$probe_source/release/inputs/portable-csdk.tar.xz")" = 942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b
  test "$(probe_hash "$probe_source/release/inputs/vendor.tar.xz")" = 84fb6e3e1710f13e85450cce1db541c3967520f996a3f17efbd5a7a8345b1c7e
  mkdir "$probe_out/unpacked/csdk" "$probe_out/unpacked/vendor"
  tar -xJf "$probe_source/release/inputs/portable-csdk.tar.xz" -C "$probe_out/unpacked/csdk"
  tar -xJf "$probe_source/release/inputs/vendor.tar.xz" -C "$probe_out/unpacked/vendor"
  ln -s "$probe_out/unpacked/csdk/Developer" "$probe_out/components/csdk"
  ln -s "$probe_out/unpacked/vendor/vendor" "$probe_out/components/vendor"
fi

probe_components="$probe_out/components"
probe_rust_real=$(cd "$probe_components/rust" && pwd -P)
probe_vendor_real=$(cd "$probe_components/vendor" && pwd -P)
"$probe_components/rust/bin/rustc" -Vv | tee "$probe_out/evidence/target-rust.txt"
grep -Fx 'commit-hash: 330d317121e16b5db8e5adc63595910528ff2ee7' "$probe_out/evidence/target-rust.txt"
grep -Fx "host: $probe_triple" "$probe_out/evidence/target-rust.txt"
probe_cargo_sha=$(jq -er '.custom_cargo_artifact.sha256' "$probe_source/release/ci-cargo-producers/$probe_host.json")
test "$(probe_hash "$probe_components/cargo/bin/cargo")" = "$probe_cargo_sha"
"$probe_components/cargo/bin/cargo" -Vv > "$probe_out/evidence/target-cargo.txt"

# Host Rust is selected independently and may be prebootstrapped by CI.
probe_host_bin=${AMI_RC0_HOST_BIN:-}
if [ -z "$probe_host_bin" ]; then
  bash "$probe_source/tools/bootstrap-host-rust.sh" "$probe_out/host" "$probe_triple" > "$probe_out/evidence/host-bootstrap.log" 2>&1
  probe_host_bin="$probe_out/host/toolchain/bin"
fi
"$probe_host_bin/rustc" -Vv > "$probe_out/evidence/host-rust.txt"
grep -Fx 'commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985' "$probe_out/evidence/host-rust.txt"
RUSTC="$probe_host_bin/rustc" "$probe_host_bin/cargo" build --release --locked --offline \
  --manifest-path "$probe_source/tools/cargo-native-spike/Cargo.toml" --target-dir "$probe_out/host-target" \
  > "$probe_out/evidence/host-build.log" 2>&1

mkdir "$probe_out/bin"
# The collector deliberately resolves sibling tools beside its physical binary
# on Linux. A symlink resolves back to the input capsule, outside this adapter.
command cp "$probe_components/collector/bin/aros-collect" "$probe_out/bin/collect-aros"
chmod 755 "$probe_out/bin/collect-aros"
test "$(probe_hash "$probe_out/bin/collect-aros")" = "$(probe_hash "$probe_components/collector/bin/aros-collect")"
for probe_tool in llvm-objdump llvm-nm llvm-ar llvm-strip ld.lld; do
  ln -s "$probe_components/toolchain/bin/$probe_tool" "$probe_out/bin/$probe_tool"
done

for probe_case in 'root-a' 'root b with spaces'; do
  probe_project="$probe_out/$probe_case"
  mkdir -p "$probe_project/src" "$probe_project/.cargo" "$probe_project/cargo-home" "$probe_project/tmp"
  # Keep path dependencies inside the portable application. Cargo package IDs
  # for external path dependencies otherwise include a host checkout context.
  mkdir "$probe_project/sdk-source"
  command cp -R "$probe_source/crates" "$probe_source/examples" "$probe_source/tests" "$probe_project/sdk-source/"
  command cp "$probe_source/Cargo.toml" "$probe_source/Cargo.lock" "$probe_project/sdk-source/"
  command cp "$probe_source/tools/cargo-native-spike/project-build.rs" "$probe_project/build.rs"
  cat > "$probe_project/src/main.rs" <<'RS'
#![no_std]
#![no_main]
use amiga_os::{AppStatus, Context};
fn application(_: &Context) -> AppStatus { AppStatus::Success }
amiga_os::entry!(application);
RS
  cat > "$probe_project/Cargo.toml" <<EOF
[workspace]
resolver = "3"
[workspace.package]
version = "0.1.0"
edition = "2024"
publish = false
license = "MIT OR Apache-2.0"
[package]
name = "rc0-native-design"
version = "0.0.0"
edition = "2024"
publish = false
[dependencies]
amiga-os = { path = "sdk-source/crates/public/amiga-os", default-features = false }
[profile.release]
opt-level = 2
panic = "abort"
lto = false
codegen-units = 1
incremental = false
debug = 0
strip = "none"
[profile.release.package.compiler_builtins]
codegen-units = 1
EOF
  # Only local activation has absolute paths; no portable state is rewritten.
  probe_remaps=$(jq -cn --arg source "$probe_source" --arg output "$probe_out" --arg vendor "$probe_vendor_real" --arg rust "$probe_rust_real" --arg project "$probe_project" \
    '[[$source,"/ami-rust"],[$output,"/build"],[$vendor,"/vendor"],[$rust,"/rust-toolchain"],[$project,"/project"]] | map("--remap-path-prefix="+.[0]+"="+.[1])')
  probe_target_flags=$(jq -cn --argjson remaps "$probe_remaps" \
    '["-Copt-level=2","-Cpanic=abort","-Ccodegen-units=1","-Cembed-bitcode=no","-Clto=off","-Clink-arg=--no-gc-sections"] + $remaps')
  cat > "$probe_project/.cargo/config.toml" <<EOF
target-applies-to-host = false
[unstable]
host-config = true
target-applies-to-host = true
ami-rust-reproducible-cross = true
build-std = ["core", "alloc"]
build-std-features = ["compiler-builtins-mem"]
json-target-spec = true
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = $(printf '%s' "$probe_components/vendor" | jq -Rs .)
[build]
target = $(printf '%s' "$probe_source/targets/x86_64-aros.json" | jq -Rs .)
jobs = 2
[host.$probe_triple]
rustflags = $probe_remaps
[target.x86_64-aros]
linker = $(printf '%s' "$probe_out/host-target/release/ami-rust-cargo-native-spike" | jq -Rs .)
rustflags = $probe_target_flags
EOF
  (
    cd "$probe_project"
    export HOME="$probe_project" CARGO_HOME="$probe_project/cargo-home" TMPDIR="$probe_project/tmp"
    export PATH="$probe_out/bin:$probe_components/cargo/bin:$probe_components/rust/bin:$probe_components/toolchain/bin:/usr/bin:/bin"
    export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true SOURCE_DATE_EPOCH=1791936000
    export LC_ALL=C TZ=UTC
    export RUSTC="$probe_components/rust/bin/rustc" RUSTDOC="$probe_components/rust/bin/rustdoc"
    export AMI_SPIKE_COLLECTOR="$probe_out/bin/collect-aros" AMI_SPIKE_TOOLCHAIN="$probe_components/toolchain"
    export AMI_SPIKE_CSDK="$probe_components/csdk" AMI_SPIKE_SDK_SOURCE="$probe_source"
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    "$probe_components/cargo/bin/cargo" generate-lockfile --offline
    "$probe_components/cargo/bin/cargo" metadata --locked --offline --format-version 1 > "$probe_out/evidence/$probe_case-metadata.json"
    "$probe_components/cargo/bin/cargo" check --locked --offline -vv > "$probe_out/evidence/$probe_case-check.stdout.log" 2> "$probe_out/evidence/$probe_case-check.stderr.log"
    "$probe_components/cargo/bin/cargo" build --release --locked --offline -vv > "$probe_out/evidence/$probe_case-build.stdout.log" 2> "$probe_out/evidence/$probe_case-build.stderr.log"
  )
  probe_final="$probe_project/target/x86_64-aros/release/rc0-native-design"
  test -f "$probe_final"
  command cp "$probe_final" "$probe_out/evidence/$probe_case-native-elf"
  shasum -a 256 "$probe_final" > "$probe_out/evidence/$probe_case-sha256.txt"
done
cmp "$probe_out/evidence/root-a-native-elf" "$probe_out/evidence/root b with spaces-native-elf"
printf '%s\n' 'PASS: Cargo metadata, check and build; two roots; C objects generated by build.rs; native-link design only' | tee "$probe_out/evidence/result.txt"

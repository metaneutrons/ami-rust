#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Private CI staging/qualification; never install an SDK into user state.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'usage: qualify-native-cargo-consumer.sh MODE HOST ABSOLUTE_MANAGED_ROOT'
mode=$1
host=$2
managed=$3
source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
pins="$source_root/release/native-cargo-qualification-prerequisites.json"
inputs="$source_root/release/native-cargo-consumer-inputs.json"
case "$host:$(uname -s):$(uname -m)" in
  macos-aarch64:Darwin:arm64|macos-aarch64:Darwin:aarch64) triple=aarch64-apple-darwin ;;
  linux-x86_64:Linux:x86_64) triple=x86_64-unknown-linux-gnu ;;
  linux-aarch64:Linux:aarch64|linux-aarch64:Linux:arm64) triple=aarch64-unknown-linux-gnu ;;
  *) fail 'requested host does not match the native runner' ;;
esac
case "$managed" in "${RUNNER_TEMP:?}/ami-rust-native-cargo-consumer/"*) ;; *) fail 'managed root is outside the CI namespace' ;; esac
[[ "$managed" != *'/../'* && "$managed" != *'/./'* && ! -L "$managed" ]] || fail 'unsafe managed root'
for tool in jq curl tar unzip shasum awk wc git; do command -v "$tool" >/dev/null || fail "missing $tool"; done
jq -e '.schema == "ami-rust-native-cargo-qualification-prerequisites-v1"' "$pins" >/dev/null
jq -e --arg host "$host" --arg triple "$triple" '.schema == "ami-rust-native-cargo-consumer-inputs-v1" and .hosts[$host].rust_host_triple == $triple' "$inputs" >/dev/null

sha() { shasum -a 256 "$1" | awk '{print $1}'; }
size() { wc -c < "$1" | tr -d '[:space:]'; }
verify() { [[ -f "$1" && ! -L "$1" && $(size "$1") == "$2" && $(sha "$1") == "$3" ]] || fail "input identity differs: $1"; }
active() { [[ $(( $(date +%s) - ${NATIVE_CAMPAIGN_START_EPOCH:?} )) -lt 5100 ]] || fail 'active campaign cutoff reached'; }
canonical_program() {
  local path=$1 link count=0
  while [[ -L "$path" ]]; do
    count=$((count + 1)); [[ $count -le 40 ]] || fail 'excessive executable symlink chain'
    link=$(readlink "$path")
    case "$link" in /*) path=$link ;; *) path="$(dirname -- "$path")/$link" ;; esac
  done
  [[ -f "$path" && -x "$path" ]] || fail 'required executable is missing'
  printf '%s/%s\n' "$(cd -P -- "$(dirname -- "$path")" && pwd -P)" "$(basename -- "$path")"
}
safe_tar() {
  local archive=$1 root=$2 destination=$3
  mkdir -m 700 "$destination"
  tar -tf "$archive" | awk -v root="$root" '
    { path=$0; sub(/\/+$/, "", path);
      if (path == "" || path ~ /^\// || path ~ /(^|\/)\.\.?($|\/)/ ||
          (path != root && substr(path,1,length(root)+1) != root "/")) bad=1; n++ }
    END { if (!n || bad) exit 1 }' || fail 'archive members escape their declared root'
  tar -xf "$archive" -C "$destination"
  [[ -d "$destination/$root" && ! -L "$destination/$root" ]] || fail 'archive root is missing'
}
download() {
  local row=$1 target=$2 url bytes digest
  url=$(jq -er '.url' <<<"$row"); bytes=$(jq -er '.bytes' <<<"$row"); digest=$(jq -er '.sha256' <<<"$row")
  case "$url" in https://static.rust-lang.org/dist/*|https://github.com/metaneutrons/aros-toolchains/releases/download/*|https://github.com/metaneutrons/aros-tools/releases/download/*) ;; *) fail 'unadmitted download origin' ;; esac
  active
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 30 --max-time 180 --max-filesize "$bytes" --output "$target" "$url"
  verify "$target" "$bytes" "$digest"
}

# This authenticated bootstrap boundary does not serialize a token into a
# qualification request or retain one in any output. The later measured commands
# receive an explicit environment with no GitHub credentials.
authenticate() {
  [[ ${GITHUB_REPOSITORY:?} == metaneutrons/ami-rust && ${GITHUB_REF:?} == refs/heads/main && ${NATIVE_REF_PROTECTED:?} == true ]] || fail 'protected publisher main is required'
  [[ ! -e "$managed" ]] || fail 'attempt root already exists'
  mkdir -p -- "$(dirname -- "$managed")"
  mkdir -m 700 "$managed" "$managed/auth" "$managed/downloads" "$managed/bootstrap-home" "$managed/tmp" "$managed/artifact"
  [[ $(git -C "$source_root" rev-parse HEAD) == "${GITHUB_SHA:?}" ]] || fail 'checkout does not match the protected source SHA'
  [[ -z $(git -C "$source_root" status --porcelain --untracked-files=all) ]] || fail 'source checkout is dirty'
  git -C "$source_root" rev-parse 'HEAD^{tree}' > "$managed/auth/source-tree.txt"
  for key in native_cargo bare_target_libraries linux_aarch64_csdk; do
    [[ "$key" != linux_aarch64_csdk || "$host" == linux-aarch64 ]] || continue
    local row run attempt head workflow artifact name bytes digest tree
    row=$(jq -ce --arg key "$key" --arg host "$host" '.[$key] as $run | $run + (if $run.hosts then $run.hosts[$host] else {} end)' "$pins")
    run=$(jq -er '.run_id' <<<"$row"); attempt=$(jq -er '.attempt' <<<"$row"); head=$(jq -er '.head' <<<"$row")
    workflow=$(jq -er '.workflow' <<<"$row"); artifact=$(jq -er '.artifact_id' <<<"$row"); name=$(jq -er '.artifact_name' <<<"$row")
    bytes=$(jq -er '.zip_bytes' <<<"$row"); digest=$(jq -er '.zip_sha256' <<<"$row")
    gh api "repos/metaneutrons/ami-rust/actions/runs/$run" > "$managed/auth/$key.run.json"
    jq -e --argjson run "$run" --argjson attempt "$attempt" --arg head "$head" --arg workflow "$workflow" \
      '.id == $run and .run_attempt == $attempt and .repository.full_name == "metaneutrons/ami-rust" and .event == "workflow_dispatch" and .head_branch == "main" and .head_sha == $head and .path == $workflow and .status == "completed" and .conclusion == "success"' \
      "$managed/auth/$key.run.json" >/dev/null || fail 'prerequisite run identity/status differs'
    tree=$(jq -r '.tree // empty' <<<"$row")
    if [[ -n "$tree" ]]; then
      gh api "repos/metaneutrons/ami-rust/git/commits/$head" > "$managed/auth/$key.commit.json"
      jq -e --arg tree "$tree" '.tree.sha == $tree' "$managed/auth/$key.commit.json" >/dev/null || fail 'prerequisite source tree differs'
    fi
    gh api "repos/metaneutrons/ami-rust/actions/artifacts/$artifact" > "$managed/auth/$key.artifact.json"
    jq -e --argjson id "$artifact" --arg name "$name" --argjson bytes "$bytes" --arg digest "sha256:$digest" --argjson run "$run" --arg head "$head" \
      '.id == $id and .name == $name and .size_in_bytes == $bytes and .digest == $digest and .expired == false and .workflow_run.id == $run and .workflow_run.head_sha == $head' \
      "$managed/auth/$key.artifact.json" >/dev/null || fail 'prerequisite artifact metadata differs'
    gh api "repos/metaneutrons/ami-rust/actions/artifacts/$artifact/zip" > "$managed/downloads/$key.zip"
    verify "$managed/downloads/$key.zip" "$bytes" "$digest"
    unzip -tq "$managed/downloads/$key.zip" >/dev/null
    active
  done
  jq -n --arg head "$GITHUB_SHA" --arg tree "$(cat "$managed/auth/source-tree.txt")" --arg pins "$(sha "$pins")" --arg inputs "$(sha "$inputs")" \
    '{schema:"ami-rust-native-cargo-source-handoff-v1",head:$head,tree:$tree,prerequisites_sha256:$pins,acquisition_inputs_sha256:$inputs,claim:"Reviewed prior-run artifacts authenticated; no consumer, SDK, or release acceptance."}' > "$managed/auth/handoff.json"
}

build_helper() {
  active
  bash "$source_root/tools/bootstrap-host-rust.sh" "$managed/bootstrap" "$triple" > "$managed/auth/bootstrap.log" 2>&1
  compile_helper
}

compile_helper() {
  active
  mkdir -m 700 "$managed/tooling-home" "$managed/tooling-target"
  local vendor_profile="$source_root/release/native-cargo-vendor-inputs.json"
  local archive="$source_root/release/inputs/native-cargo-vendor.tar.xz" lock
  jq -e '.schema == "ami-rust-native-cargo-vendor-inputs-v1" and .path == "release/inputs/native-cargo-vendor.tar.xz" and .component_root == "vendor"' "$vendor_profile" >/dev/null
  for lock in Cargo.lock tooling/Cargo.lock; do
    [[ $(sha "$source_root/$lock") == "$(jq -er --arg lock "$lock" '.source_locks[$lock]' "$vendor_profile")" ]] || fail 'native vendor source lock differs'
  done
  verify "$archive" "$(jq -er '.bytes' "$vendor_profile")" "$(jq -er '.sha256' "$vendor_profile")"
  safe_tar "$archive" vendor "$managed/tooling-vendor"
  jq -nr --arg directory "$managed/tooling-vendor/vendor" \
    '"[net]\noffline = true\n[source.crates-io]\nreplace-with = \"qualification-vendor\"\n[source.qualification-vendor]\ndirectory = " + ($directory | tojson)' \
    > "$managed/tooling-home/config.toml"
  env -i HOME="$managed/bootstrap-home" PATH='/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin' \
    LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 CARGO_BUILD_JOBS=2 \
    CARGO_HOME="$managed/tooling-home" CARGO_TARGET_DIR="$managed/tooling-target" \
    RUSTC="$managed/bootstrap/toolchain/bin/rustc" RUSTDOC="$managed/bootstrap/toolchain/bin/rustdoc" \
    "$managed/bootstrap/toolchain/bin/cargo" build --locked --offline --release --manifest-path "$source_root/tooling/Cargo.toml" -p ami-rust-xtask \
    > "$managed/auth/helper-build.log" 2>&1
  active
}

stage() {
  active
  [[ ! -e "$managed/components" ]] || fail 'component staging already exists'
  mkdir -m 700 "$managed/components" "$managed/components/rust" "$managed/components/cargo" "$managed/components/cargo/bin" "$managed/components/target_libraries" "$managed/unpacked"
  local row component root archive rel member destination
  while IFS= read -r row; do
    component=$(jq -er '.component' <<<"$row"); root=$(jq -er '.archive_root' <<<"$row")
    case "$component" in rustc|rust-std|rust-src|cargo) ;; *) fail 'unknown Rust component' ;; esac
    archive="$managed/downloads/rust-$component.tar.xz"
    download "$row" "$archive"
    safe_tar "$archive" "$root" "$managed/unpacked/rust-$component"
    bash "$managed/unpacked/rust-$component/$root/install.sh" --prefix="$managed/components/rust" --disable-ldconfig
    command rm -rf -- "$managed/unpacked/rust-$component"
    command rm -f -- "$archive"
  done < <(jq -ce --arg host "$host" '.hosts[$host].rust.archives[]' "$inputs")
  while IFS= read -r rel; do
    case "$rel" in lib/rustlib/install.log|lib/rustlib/manifest-cargo|lib/rustlib/manifest-rust-src|lib/rustlib/manifest-rustc|"lib/rustlib/manifest-rust-std-$triple") ;; *) fail 'unexpected Rust administrative removal' ;; esac
    [[ -f "$managed/components/rust/$rel" && ! -L "$managed/components/rust/$rel" ]] || fail 'expected installer state is missing'
    command rm -f -- "$managed/components/rust/$rel"
  done < <(jq -er --arg host "$host" '.hosts[$host].rust.remove_installer_administrative_files[]' "$inputs")
  for component in llvm collector; do
    row=$(jq -ce --arg host "$host" --arg component "$component" '.hosts[$host][$component]' "$inputs")
    root=$(jq -er '.archive_root' <<<"$row"); archive="$managed/downloads/$component.archive"
    download "$row" "$archive"; safe_tar "$archive" "$root" "$managed/unpacked/$component"
    command mv -- "$managed/unpacked/$component/$root" "$managed/components/$component"
    command rm -f -- "$archive"
  done
  row=$(jq -ce --arg host "$host" '.native_cargo.hosts[$host]' "$pins")
  unzip -p "$managed/downloads/native_cargo.zip" cargo > "$managed/components/cargo/bin/cargo"
  verify "$managed/components/cargo/bin/cargo" "$(jq -er '.payload_bytes' <<<"$row")" "$(jq -er '.payload_sha256' <<<"$row")"
  chmod 0755 "$managed/components/cargo/bin/cargo"
  local cargo_profile="$source_root/tooling/crates/aros-native-build/pins/$host/cargo.json" producer
  if jq -e '.files | any(.path == "producer.json")' "$cargo_profile" >/dev/null; then
    producer=$(jq -ce '[.files[] | select(.path == "producer.json")] | if length == 1 then .[0] else error("ambiguous producer record") end' "$cargo_profile")
    # Reproduce the embedded original bytes, then require their exact pinned identity.
    jq -S '.producer_identity_spec.record | select(type == "object")' "$cargo_profile" > "$managed/components/cargo/producer.json"
    verify "$managed/components/cargo/producer.json" "$(jq -er '.bytes' <<<"$producer")" "$(jq -er '.sha256' <<<"$producer")"
  fi
  while IFS= read -r member; do
    case "$member" in producer/libraries/lib*.rlib) ;; *) fail 'unexpected target library member' ;; esac
    destination="$managed/components/target_libraries/${member##*/}"
    [[ ! -e "$destination" ]] || fail 'duplicate target library destination'
    unzip -p "$managed/downloads/bare_target_libraries.zip" "$member" > "$destination"
  done < <(jq -er --arg host "$host" '.bare_target_libraries.hosts[$host].library_paths[]' "$pins")
  if [[ "$host" == linux-aarch64 ]]; then
    row=$(jq -ce '.linux_aarch64_csdk' "$pins")
    archive="$managed/downloads/csdk-component.tar.xz"
    unzip -p "$managed/downloads/linux_aarch64_csdk.zip" "$(jq -er '.component_path' <<<"$row")" > "$archive"
    verify "$archive" "$(jq -er '.component_bytes' <<<"$row")" "$(jq -er '.component_sha256' <<<"$row")"
  else
    row=$(jq -ce '.shared.csdk' "$inputs"); archive="$source_root/$(jq -er '.path' <<<"$row")"
    verify "$archive" "$(jq -er '.bytes' <<<"$row")" "$(jq -er '.sha256' <<<"$row")"
  fi
  safe_tar "$archive" Developer "$managed/unpacked/csdk"
  command mv -- "$managed/unpacked/csdk/Developer" "$managed/components/csdk"
  active
}

request_and_run() {
  local program=$2 args=$3 request="$managed/$1.outer-request.json" record="$managed/$1.record" remaining
  active; remaining=$((5100 - ($(date +%s) - NATIVE_CAMPAIGN_START_EPOCH)))
  [[ $remaining -le 1200 ]] || remaining=1200
  jq -n --arg program "$program" --argjson args "$args" --arg cwd "$managed" --arg source "$source_root" --arg managed "$managed" --argjson seconds "$remaining" --arg runner_temp "$RUNNER_TEMP" --arg start "$NATIVE_CAMPAIGN_START_EPOCH" \
    '{schema:"ami-rust-native-command-qualification-request-v1",program:$program,args:$args,cwd:$cwd,environment:{HOME:($managed+"/bootstrap-home"),PATH:"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",RUNNER_TEMP:$runner_temp,NATIVE_CAMPAIGN_START_EPOCH:$start,LC_ALL:"C",TZ:"UTC",SOURCE_DATE_EPOCH:"1791936000",TMPDIR:($managed+"/tmp")},required_roots:[$managed,$source],limits:{seconds:$seconds,rss_bytes:3758096384,workspace_bytes:12884901888,log_bytes:16777216}}' > "$request"
  "$managed/tooling-target/release/ami-rust-xtask" qualification-command --request "$request" --record "$record"
  jq -e '.passed == true and .capture_complete == true and .child_exit_code == 0 and .resource_report.incomplete_cleanup == false and .resource_report.last_sample_complete == true' "$record/result.json" >/dev/null
  active
}

prove() {
  local request="$managed/consumer.request.json" rustup_binary
  rustup_binary=$(canonical_program "$(command -v rustup)")
  [[ ! -e "$request" ]] || fail 'consumer request already exists'
  mkdir -m 700 "$managed/selector"
  command cp "$rustup_binary" "$managed/selector/rustup"
  verify "$managed/selector/rustup" "$(size "$rustup_binary")" "$(sha "$rustup_binary")"
  chmod 0755 "$managed/selector/rustup"
  jq -n --arg source "$rustup_binary" --arg sha256 "$(sha "$rustup_binary")" \
    '{schema:"ami-rust-rustup-probe-copy-v1",source:$source,sha256:$sha256,claim:"Identical private selector copy; no global rustup modification."}' > "$managed/auth/rustup-copy.json"
  rustup_binary="$managed/selector/rustup"
  jq -n --arg host "$host" --arg triple "$triple" --arg source "$source_root" --arg managed "$managed" --arg rustup "$rustup_binary" \
    '{schema:"ami-rust-native-cargo-qualification-request-v1",host_key:$host,rust_host_triple:$triple,source_root:$source,managed_root:$managed,work_root:($managed+"/work"),output_root:($managed+"/proof"),component_roots:{rust:($managed+"/components/rust"),cargo:($managed+"/components/cargo"),llvm:($managed+"/components/llvm"),csdk:($managed+"/components/csdk"),collector:($managed+"/components/collector"),target_libraries:($managed+"/components/target_libraries")},bootstrap:{cargo:($managed+"/bootstrap/toolchain/bin/cargo"),rustc:($managed+"/bootstrap/toolchain/bin/rustc"),rustup:$rustup}}' > "$request"
  request_and_run consumer "$managed/tooling-target/release/ami-rust-xtask" "$(jq -nc --arg request "$request" '["native-cargo-qualification","--request",$request]')"
  jq -e --arg host "$host" '.schema == "ami-rust-native-cargo-qualification-result-v1" and .status == "PASS_LOCAL_NATIVE_CARGO_QUALIFICATION" and .host_key == $host' "$managed/proof/result.json" >/dev/null
}

case "$mode" in
  authenticate) authenticate ;;
  build-helper) build_helper ;;
  compile-helper) compile_helper ;;
  stage) stage ;;
  measure-stage) request_and_run stage "$(canonical_program /bin/bash)" "$(jq -nc --arg script "$source_root/tools/qualify-native-cargo-consumer.sh" --arg host "$host" --arg root "$managed" '[ $script,"stage",$host,$root ]')" ;;
  prove) prove ;;
  *) fail 'unknown internal staging mode' ;;
esac

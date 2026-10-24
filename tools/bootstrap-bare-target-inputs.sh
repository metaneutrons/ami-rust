#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Maintainer-only staging of pinned Rust inputs for the internal bare-target producer.
# This is not a public SDK command and never runs downloaded installers or binaries.
set -euo pipefail
umask 077
unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN

cli_fail() {
  printf 'bootstrap-bare-target-inputs: %s\n' "$1" >&2
  exit "${2:-1}"
}

if [[ "$#" -ne 2 ]]; then
  printf 'usage: bootstrap-bare-target-inputs.sh HOST_KEY ABSOLUTE_FRESH_PREFIX\n' >&2
  exit 2
fi
cli_host_key=$1
cli_prefix_arg=$2

case "$cli_host_key" in
  macos-aarch64)
    cli_host_triple='aarch64-apple-darwin'
    cli_expected_profile='tooling/crates/aros-native-build/pins/macos-aarch64/rust.json'
    cli_expected_profile_sha='9acf02ab3d4a22137b6c5f82294e35c518ff1ffdbad5a701d5f3cdb0910668ea'
    cli_expected_cargo_id='12559051826'
    cli_expected_cargo_arch='arm64'
    cli_expected_cargo_format='Mach-O'
    ;;
  linux-x86_64)
    cli_host_triple='x86_64-unknown-linux-gnu'
    cli_expected_profile='tooling/crates/aros-native-build/pins/linux-x86_64/rust.json'
    cli_expected_profile_sha='7a88373f28d19d6d61494587240681999adfb2bec964b4c3d74fae9718f097e8'
    cli_expected_cargo_id='12556876494'
    cli_expected_cargo_arch='x86_64'
    cli_expected_cargo_format='ELF'
    ;;
  linux-aarch64)
    cli_host_triple='aarch64-unknown-linux-gnu'
    cli_expected_profile='release/bare-target-libraries/linux-aarch64-rust.json'
    cli_expected_profile_sha='862be6c4c1d29c59fc774e2d38f046672fcd0aa0978a869be9af2752fb4f76ee'
    cli_expected_cargo_id='12556322768'
    cli_expected_cargo_arch='aarch64'
    cli_expected_cargo_format='ELF'
    ;;
  *)
    cli_fail 'unsupported host key' 2
    ;;
esac

cli_system=$(uname -s)
cli_machine=$(uname -m)
case "$cli_system:$cli_machine" in
  Darwin:arm64|Darwin:aarch64) cli_detected_host='macos-aarch64' ;;
  Linux:x86_64|Linux:amd64) cli_detected_host='linux-x86_64' ;;
  Linux:aarch64|Linux:arm64) cli_detected_host='linux-aarch64' ;;
  *) cli_fail "unsupported native host $cli_system/$cli_machine" 2 ;;
esac
[[ "$cli_detected_host" == "$cli_host_key" ]] || cli_fail "requested host $cli_host_key does not match native host $cli_detected_host" 2

case "$cli_prefix_arg" in
  /*) ;;
  *) cli_fail 'prefix must be absolute' 2 ;;
esac
[[ "$cli_prefix_arg" != */ ]] || cli_fail 'prefix must not end in a slash' 2
cli_prefix_leaf=${cli_prefix_arg##*/}
[[ -n "$cli_prefix_leaf" && "$cli_prefix_leaf" != '.' && "$cli_prefix_leaf" != '..' ]] || cli_fail 'invalid prefix leaf' 2
cli_prefix_parent=${cli_prefix_arg%/*}
[[ -n "$cli_prefix_parent" ]] || cli_prefix_parent='/'
[[ -d "$cli_prefix_parent" ]] || cli_fail 'prefix parent must already exist' 2
cli_prefix_parent=$(cd -P -- "$cli_prefix_parent" && pwd -P)
cli_prefix="$cli_prefix_parent/$cli_prefix_leaf"
[[ ! -e "$cli_prefix" && ! -L "$cli_prefix" ]] || cli_fail 'prefix must be fresh and absent' 2

for cli_tool in jq curl gh tar unzip awk wc tr cp chmod mkdir rm find cmp readlink shasum sha256sum; do
  if [[ "$cli_tool" == 'shasum' || "$cli_tool" == 'sha256sum' ]]; then
    continue
  fi
  command -v "$cli_tool" >/dev/null 2>&1 || cli_fail "required tool is missing: $cli_tool" 2
 done
if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
  cli_fail 'shasum or sha256sum is required' 2
fi
[[ -n "${GH_TOKEN:-}" ]] || cli_fail 'GH_TOKEN must be supplied in the environment' 2

cli_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cli_manifest="$cli_root/release/bare-target-libraries-inputs.json"
[[ -f "$cli_manifest" && ! -L "$cli_manifest" ]] || cli_fail 'release/bare-target-libraries-inputs.json is missing or not a regular file'

cli_sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}
cli_file_bytes() { wc -c < "$1" | tr -d '[:space:]'; }

cli_expected_manifest_sha='3887976912a7cc67d207bcb17c207ddf2521daef0d810c5daaaf7c9c2814eb79'
cli_manifest_bytes=$(cli_file_bytes "$cli_manifest")
cli_manifest_sha=$(cli_sha256_file "$cli_manifest")
[[ "$cli_manifest_bytes" == '20060' && "$cli_manifest_sha" == "$cli_expected_manifest_sha" ]] || cli_fail 'frozen bare-target input manifest size or SHA-256 mismatch'
jq -e '
  .schema == "ami-rust-bare-target-libraries-inputs-proposal-v2" and
  .status == "PROPOSAL_ONLY_INTERNAL_PRODUCER_INPUTS_NOT_ADMITTED" and
  (has("native_cargo_run") | not) and
  (has("duplicate_artifacts") | not) and
  .target.key == "x86_64-aros" and
  .target.rustc_commit == "330d317121e16b5db8e5adc63595910528ff2ee7" and
  .target.rust_channel == "nightly-2026-09-18" and
  .target.target_spec.sha256 == "de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71" and
  .target.target_pin.sha256 == "33fdd3d97053370eb3db9e05ea75721dafcfc7f4b5f8c218acaab1911984c341" and
  .component_selection.selected_rust_components == ["rustc","rust-std","rust-src"] and
  (.hosts | length) == 3 and
  ([.hosts[].host] | sort) == ["linux-aarch64","linux-x86_64","macos-aarch64"] and
  ([.hosts[] | select(
    .native_cargo.host != .host or
    .native_cargo.host_triple != .host_triple or
    (.native_cargo.producer | type) != "object" or
    .native_cargo.producer.repository != "metaneutrons/ami-rust" or
    (.native_cargo.producer.workflow_run_id | type) != "number" or
    .native_cargo.producer.workflow_run_id < 1 or
    (.native_cargo.producer.workflow_run_id | floor) != .native_cargo.producer.workflow_run_id or
    (.native_cargo.producer.attempt | type) != "number" or
    .native_cargo.producer.attempt < 1 or
    (.native_cargo.producer.attempt | floor) != .native_cargo.producer.attempt or
    (.native_cargo.producer.head | test("^[0-9a-f]{40}$") | not) or
    (.native_cargo.producer.tree | test("^[0-9a-f]{40}$") | not) or
    .native_cargo.producer.workflow_path != ".github/workflows/cargo-native-prerequisite.yml" or
    (.native_cargo.producer.workflow_sha256 | test("^[0-9a-f]{64}$") | not) or
    .native_cargo.artifact_name != ("native-cargo-component-" + .host_triple + "-" + (.native_cargo.producer.workflow_run_id | tostring) + "-" + (.native_cargo.producer.attempt | tostring)) or
    (.native_cargo.producer.actual_review | type) != "object" or
    (.native_cargo.producer.actual_review.path | type) != "string" or
    (.native_cargo.producer.actual_review.path | length) == 0 or
    (.native_cargo.producer.actual_review.sha256 | test("^[0-9a-f]{64}$") | not) or
    (.native_cargo.producer.actual_review.verdict | type) != "string" or
    (.native_cargo.producer.actual_review.verdict | length) == 0
  )] | length) == 0
' "$cli_manifest" >/dev/null || cli_fail 'input manifest schema or fixed source pins are not accepted'

cli_host_row=$(jq -ce --arg host "$cli_host_key" '
  [.hosts[] | select(.host == $host)] |
  if length == 1 then .[0] else error("host row cardinality") end
' "$cli_manifest") || cli_fail 'host row is missing or ambiguous'
cli_actual_triple=$(jq -er '.host_triple' <<<"$cli_host_row")
cli_profile_rel=$(jq -er '.rust_profile.repo_relative_path_or_proposed_path' <<<"$cli_host_row")
cli_profile_sha=$(jq -er '.rust_profile.sha256' <<<"$cli_host_row")
cli_profile_bytes=$(jq -er '.rust_profile.bytes' <<<"$cli_host_row")
[[ "$cli_actual_triple" == "$cli_host_triple" ]] || cli_fail 'manifest host triple differs from fixed native-host mapping'
[[ "$cli_profile_rel" == "$cli_expected_profile" && "$cli_profile_sha" == "$cli_expected_profile_sha" ]] || cli_fail 'manifest host profile path or SHA-256 differs from fixed mapping'
[[ "$cli_profile_bytes" =~ ^[1-9][0-9]*$ ]] || cli_fail 'manifest host profile size is invalid'
cli_profile_source="$cli_root/$cli_profile_rel"
[[ -f "$cli_profile_source" && ! -L "$cli_profile_source" ]] || cli_fail 'pinned full host profile is missing or not a regular file'
[[ "$(cli_file_bytes "$cli_profile_source")" == "$cli_profile_bytes" ]] || cli_fail 'full host profile size mismatch'
[[ "$(cli_sha256_file "$cli_profile_source")" == "$cli_profile_sha" ]] || cli_fail 'full host profile SHA-256 mismatch'

cli_components=$(jq -ce --arg host "$cli_host_key" '
  [.hosts[] | select(.host == $host)][0].rust_components
' "$cli_manifest") || cli_fail 'Rust component selection is missing'
[[ "$(jq 'length' <<<"$cli_components")" == '3' ]] || cli_fail 'exactly three Rust archive components are required'
for cli_component in rustc rust-std rust-src; do
  [[ "$(jq --arg component "$cli_component" '[.[] | select(.component == $component)] | length' <<<"$cli_components")" == '1' ]] || cli_fail "component row is missing or duplicated: $cli_component"
done

case "$cli_host_key" in
  macos-aarch64) cli_rustc_url="https://static.rust-lang.org/dist/2026-09-18/rustc-nightly-$cli_host_triple.tar.xz"; cli_std_url="https://static.rust-lang.org/dist/2026-09-18/rust-std-nightly-$cli_host_triple.tar.xz" ;;
  linux-x86_64) cli_rustc_url="https://static.rust-lang.org/dist/2026-09-18/rustc-nightly-$cli_host_triple.tar.xz"; cli_std_url="https://static.rust-lang.org/dist/2026-09-18/rust-std-nightly-$cli_host_triple.tar.xz" ;;
  linux-aarch64) cli_rustc_url="https://static.rust-lang.org/dist/2026-09-18/rustc-nightly-$cli_host_triple.tar.xz"; cli_std_url="https://static.rust-lang.org/dist/2026-09-18/rust-std-nightly-$cli_host_triple.tar.xz" ;;
esac
cli_src_url='https://static.rust-lang.org/dist/2026-09-18/rust-src-nightly.tar.xz'
for cli_component in rustc rust-std rust-src; do
  cli_component_row=$(jq -ce --arg component "$cli_component" '[.[] | select(.component == $component)] | .[0]' <<<"$cli_components") || cli_fail "invalid component row: $cli_component"
  cli_url=$(jq -er '.url' <<<"$cli_component_row")
  cli_sha=$(jq -er '.sha256' <<<"$cli_component_row")
  cli_size=$(jq -er '.bytes' <<<"$cli_component_row")
  case "$cli_component" in
    rustc) cli_expected_url=$cli_rustc_url ;;
    rust-std) cli_expected_url=$cli_std_url ;;
    rust-src) cli_expected_url=$cli_src_url ;;
  esac
  [[ "$cli_url" == "$cli_expected_url" ]] || cli_fail "non-pinned $cli_component URL"
  [[ "$cli_sha" =~ ^[0-9a-f]{64}$ && "$cli_size" =~ ^[1-9][0-9]*$ ]] || cli_fail "invalid $cli_component digest or byte size"
done

cli_cargo_row=$(jq -ce --arg host "$cli_host_key" '
  [.hosts[] | select(.host == $host)][0].native_cargo
' "$cli_manifest") || cli_fail 'native Cargo artifact row is missing'
jq -e --arg host "$cli_host_key" '
  ([.hosts[] | select(.host == $host)] | length) == 1 and
  ([.hosts[] | select(.host == $host)][0] as $row |
    $row.native_cargo.host == $host and
    $row.native_cargo.host_triple == $row.host_triple and
    $row.native_cargo.producer.workflow_path == ".github/workflows/cargo-native-prerequisite.yml")
' "$cli_manifest" >/dev/null || cli_fail 'host Cargo row does not match its per-host producer binding'
cli_cargo_id=$(jq -er '.artifact_id' <<<"$cli_cargo_row")
cli_cargo_triple=$(jq -er '.host_triple' <<<"$cli_cargo_row")
cli_cargo_zip_bytes=$(jq -er '.artifact_zip.bytes' <<<"$cli_cargo_row")
cli_cargo_zip_sha=$(jq -er '.artifact_zip.sha256' <<<"$cli_cargo_row")
cli_cargo_member_path=$(jq -er '.member.path' <<<"$cli_cargo_row")
cli_cargo_member_count=$(jq -er '.member.unique_count' <<<"$cli_cargo_row")
cli_cargo_member_bytes=$(jq -er '.member.bytes' <<<"$cli_cargo_row")
cli_cargo_member_sha=$(jq -er '.member.sha256' <<<"$cli_cargo_row")
[[ "$cli_cargo_id" == "$cli_expected_cargo_id" && "$cli_cargo_triple" == "$cli_host_triple" ]] || cli_fail 'native Cargo artifact identity differs from fixed host mapping'
[[ "$cli_cargo_member_path" == 'cargo' && "$cli_cargo_member_count" == '1' ]] || cli_fail 'Cargo artifact must contain one root-level cargo member'
[[ "$cli_cargo_zip_bytes" =~ ^[1-9][0-9]*$ && "$cli_cargo_member_bytes" =~ ^[1-9][0-9]*$ ]] || cli_fail 'native Cargo byte size is invalid'
[[ "$cli_cargo_zip_sha" =~ ^[0-9a-f]{64}$ && "$cli_cargo_member_sha" =~ ^[0-9a-f]{64}$ ]] || cli_fail 'native Cargo SHA-256 is invalid'
[[ "$(jq -er '.binary_architecture' <<<"$cli_cargo_row")" == "$cli_expected_cargo_arch" ]] || cli_fail 'native Cargo architecture differs from fixed host mapping'
[[ "$(jq -er '.binary_format' <<<"$cli_cargo_row")" == "$cli_expected_cargo_format" ]] || cli_fail 'native Cargo binary format differs from fixed host mapping'

for cli_tool in curl gh tar unzip awk wc tr cp chmod mkdir rm find cmp readlink; do
  command -v "$cli_tool" >/dev/null 2>&1 || cli_fail "required tool is missing: $cli_tool" 2
 done
mkdir -m 700 "$cli_prefix" || cli_fail 'could not create fresh owned prefix'
mkdir -m 700 "$cli_prefix/downloads" "$cli_prefix/unpacked" "$cli_prefix/records" "$cli_prefix/source-sysroot" "$cli_prefix/native-cargo" "$cli_prefix/native-cargo/bin" "$cli_prefix/inputs"
command cp "$cli_manifest" "$cli_prefix/inputs/bare-target-libraries-inputs.json"
command cp "$cli_profile_source" "$cli_prefix/inputs/source-profile.json"
[[ "$(cli_file_bytes "$cli_prefix/inputs/source-profile.json")" == "$cli_profile_bytes" ]] || cli_fail 'copied host profile size mismatch'
[[ "$(cli_sha256_file "$cli_prefix/inputs/source-profile.json")" == "$cli_profile_sha" ]] || cli_fail 'copied host profile SHA-256 mismatch'
[[ "$(cli_sha256_file "$cli_prefix/inputs/bare-target-libraries-inputs.json")" == "$cli_manifest_sha" ]] || cli_fail 'copied input manifest SHA-256 mismatch'

cli_download_component() {
  local cli_comp=$1 cli_component_row=$2
  local cli_url cli_sha cli_size cli_name cli_path cli_actual_sha cli_actual_bytes
  cli_url=$(jq -er '.url' <<<"$cli_component_row")
  cli_sha=$(jq -er '.sha256' <<<"$cli_component_row")
  cli_size=$(jq -er '.bytes' <<<"$cli_component_row")
  cli_name=${cli_url##*/}
  cli_path="$cli_prefix/downloads/$cli_name"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 60 --max-time 1200 --max-filesize "$cli_size" \
    --output "$cli_path" "$cli_url" || cli_fail "download failed for $cli_comp"
  cli_actual_bytes=$(cli_file_bytes "$cli_path")
  cli_actual_sha=$(cli_sha256_file "$cli_path")
  [[ "$cli_actual_bytes" == "$cli_size" && "$cli_actual_sha" == "$cli_sha" ]] || cli_fail "download size or SHA-256 mismatch for $cli_comp"
  printf '%s\n' "$cli_path"
}

cli_extract_component() {
  local cli_comp=$1 cli_archive=$2 cli_payload_name=$3
  local cli_base cli_list cli_payload
  cli_base=${cli_archive##*/}
  cli_base=${cli_base%.tar.xz}
  cli_list="$cli_prefix/records/$cli_base.members.txt"
  tar -tJf "$cli_archive" > "$cli_list" || cli_fail "cannot list archive $cli_base"
  awk -v root="$cli_base" '
    {
      path=$0
      sub(/\/+$/, "", path)
      if (path == "") bad=1
      else if (path != root && (path ~ /^\// || path ~ /(^|\/)\.\.(\/|$)/ || path ~ /(^|\/)\.(\/|$)/ || substr(path,1,length(root)+1) != root "/")) bad=1
      count++
    }
    END { if (count == 0 || bad) exit 1 }
  ' "$cli_list" || cli_fail "archive member paths are not confined to $cli_base"
  tar -xJf "$cli_archive" -C "$cli_prefix/unpacked" || cli_fail "cannot extract archive $cli_base"
  cli_payload="$cli_prefix/unpacked/$cli_base/$cli_payload_name"
  [[ -d "$cli_payload" && ! -L "$cli_payload" ]] || cli_fail "expected component payload is absent: $cli_comp"
  printf '%s\n' "$cli_payload"
}

cli_merge_payload() {
  local cli_payload=$1 cli_component=$2 cli_entry cli_relative cli_destination cli_source_link cli_destination_link
  while IFS= read -r -d '' cli_entry; do
    cli_relative=${cli_entry#"$cli_payload"/}
    if [[ "$cli_relative" == 'manifest.in' || "$cli_relative" == '.manifest.in' ]]; then
      printf '%s\n' "$cli_component/$cli_relative" >> "$cli_prefix/records/excluded-installer-metadata.txt"
      continue
    fi
    cli_destination="$cli_prefix/source-sysroot/$cli_relative"
    if [[ -e "$cli_destination" || -L "$cli_destination" ]]; then
      if [[ -L "$cli_entry" && -L "$cli_destination" ]]; then
        cli_source_link=$(readlink "$cli_entry")
        cli_destination_link=$(readlink "$cli_destination")
        [[ "$cli_source_link" == "$cli_destination_link" ]] || cli_fail "conflicting component symlinks at $cli_relative"
        printf '%s\tidentical-symlink\n' "$cli_relative" >> "$cli_prefix/records/duplicate-identical-component-paths.txt"
        continue
      fi
      if [[ -f "$cli_entry" && ! -L "$cli_entry" && -f "$cli_destination" && ! -L "$cli_destination" ]] && cmp -s "$cli_entry" "$cli_destination"; then
        printf '%s\tidentical-file\n' "$cli_relative" >> "$cli_prefix/records/duplicate-identical-component-paths.txt"
        continue
      fi
      cli_fail "conflicting component payload at $cli_relative"
    fi
    mkdir -p "$(dirname -- "$cli_destination")"
    command cp -a "$cli_entry" "$cli_destination" || cli_fail "could not stage payload from $cli_component"
  done < <(find "$cli_payload" \( -type f -o -type l \) -print0)
}

cli_rustc_row=$(jq -ce '[.[] | select(.component == "rustc")] | .[0]' <<<"$cli_components")
cli_std_row=$(jq -ce '[.[] | select(.component == "rust-std")] | .[0]' <<<"$cli_components")
cli_src_row=$(jq -ce '[.[] | select(.component == "rust-src")] | .[0]' <<<"$cli_components")
cli_rustc_archive=$(cli_download_component rustc "$cli_rustc_row")
cli_std_archive=$(cli_download_component rust-std "$cli_std_row")
cli_src_archive=$(cli_download_component rust-src "$cli_src_row")
cli_rustc_payload=$(cli_extract_component rustc "$cli_rustc_archive" rustc)
cli_std_payload=$(cli_extract_component rust-std "$cli_std_archive" "rust-std-$cli_host_triple")
cli_src_payload=$(cli_extract_component rust-src "$cli_src_archive" rust-src)
cli_merge_payload "$cli_rustc_payload" rustc
cli_merge_payload "$cli_std_payload" rust-std
cli_merge_payload "$cli_src_payload" rust-src

cli_admin_list="$cli_prefix/records/excluded-installer-state.txt"
: > "$cli_admin_list"
for cli_relpath in \
  lib/rustlib/components \
  lib/rustlib/install.log \
  lib/rustlib/manifest-cargo \
  lib/rustlib/manifest-rustc \
  lib/rustlib/manifest-rust-src \
  "lib/rustlib/manifest-rust-std-$cli_host_triple" \
  lib/rustlib/rust-installer-version \
  lib/rustlib/uninstall.sh; do
  cli_admin_path="$cli_prefix/source-sysroot/$cli_relpath"
  if [[ -e "$cli_admin_path" || -L "$cli_admin_path" ]]; then
    [[ ! -d "$cli_admin_path" ]] || cli_fail "unexpected directory at installer metadata path: $cli_relpath"
    printf '%s\tpresent-and-removed\n' "$cli_relpath" >> "$cli_admin_list"
    command rm -f "$cli_admin_path" || cli_fail "could not exclude installer metadata: $cli_relpath"
  else
    printf '%s\tabsent-from-raw-component-payload\n' "$cli_relpath" >> "$cli_admin_list"
  fi
done

[[ -x "$cli_prefix/source-sysroot/bin/rustc" ]] || cli_fail 'staged rustc is missing or not executable'
[[ -x "$cli_prefix/source-sysroot/bin/rustdoc" ]] || cli_fail 'staged rustdoc is missing or not executable'
[[ -d "$cli_prefix/source-sysroot/lib/rustlib/$cli_host_triple/lib" ]] || cli_fail 'native standard-library payload is missing'
[[ -f "$cli_prefix/source-sysroot/lib/rustlib/src/rust/library/Cargo.toml" ]] || cli_fail 'rust-src library manifest is missing'
[[ ! -e "$cli_prefix/source-sysroot/bin/cargo" ]] || cli_fail 'official Cargo unexpectedly entered source sysroot'
[[ ! -e "$cli_prefix/source-sysroot/bin/aros-link" && ! -L "$cli_prefix/source-sysroot/bin/aros-link" ]] || cli_fail 'unselected aros-link binary entered source sysroot'
[[ ! -e "$cli_prefix/source-sysroot/lib/rustlib/x86_64-aros/lib" ]] || cli_fail 'source sysroot unexpectedly contains prebuilt AROS target libraries'

cli_cargo_zip="$cli_prefix/downloads/native-cargo-$cli_host_key-$cli_cargo_id.zip"
GH_TOKEN="$GH_TOKEN" gh api \
  --header 'Accept: application/vnd.github+json' \
  --header 'X-GitHub-Api-Version: 2022-11-28' \
  "repos/metaneutrons/ami-rust/actions/artifacts/$cli_cargo_id/zip" > "$cli_cargo_zip" || cli_fail 'GitHub Actions Cargo artifact download failed'
[[ "$(cli_file_bytes "$cli_cargo_zip")" == "$cli_cargo_zip_bytes" ]] || cli_fail 'native Cargo ZIP byte size mismatch'
[[ "$(cli_sha256_file "$cli_cargo_zip")" == "$cli_cargo_zip_sha" ]] || cli_fail 'native Cargo ZIP SHA-256 mismatch'
unzip -tq "$cli_cargo_zip" >/dev/null || cli_fail 'native Cargo ZIP CRC check failed'
cli_cargo_member_count_actual=$(unzip -Z1 "$cli_cargo_zip" | awk '$0 == "cargo" { count++ } END { print count+0 }')
[[ "$cli_cargo_member_count_actual" == '1' ]] || cli_fail 'native Cargo ZIP does not contain exactly one root-level cargo member'
unzip -p "$cli_cargo_zip" cargo > "$cli_prefix/native-cargo/bin/cargo" || cli_fail 'could not extract root-level cargo member'
[[ "$(cli_file_bytes "$cli_prefix/native-cargo/bin/cargo")" == "$cli_cargo_member_bytes" ]] || cli_fail 'native Cargo member byte size mismatch'
[[ "$(cli_sha256_file "$cli_prefix/native-cargo/bin/cargo")" == "$cli_cargo_member_sha" ]] || cli_fail 'native Cargo member SHA-256 mismatch'
chmod 0755 "$cli_prefix/native-cargo/bin/cargo"
[[ -x "$cli_prefix/native-cargo/bin/cargo" ]] || cli_fail 'owned Cargo executable mode is not executable'

cli_profile_copy_sha=$(cli_sha256_file "$cli_prefix/inputs/source-profile.json")
cli_cargo_copy_sha=$(cli_sha256_file "$cli_prefix/native-cargo/bin/cargo")
cli_rustc_archive_sha=$(cli_sha256_file "$cli_rustc_archive")
cli_std_archive_sha=$(cli_sha256_file "$cli_std_archive")
cli_src_archive_sha=$(cli_sha256_file "$cli_src_archive")
cli_rustc_archive_bytes=$(cli_file_bytes "$cli_rustc_archive")
cli_std_archive_bytes=$(cli_file_bytes "$cli_std_archive")
cli_src_archive_bytes=$(cli_file_bytes "$cli_src_archive")
cli_receipt="$cli_prefix/bootstrap-inputs-receipt.json"
jq -n \
  --arg schema 'ami-rust-bare-target-input-bootstrap-receipt-v1' \
  --arg status 'STAGED_INPUTS_ONLY_UNQUALIFIED' \
  --arg host "$cli_host_key" \
  --arg host_triple "$cli_host_triple" \
  --arg manifest_sha256 "$cli_manifest_sha" \
  --arg profile_path "$cli_profile_rel" \
  --arg profile_sha256 "$cli_profile_copy_sha" \
  --arg source_sysroot "$cli_prefix/source-sysroot" \
  --arg rustc_archive_name "${cli_rustc_archive##*/}" \
  --arg rustc_archive_sha256 "$cli_rustc_archive_sha" \
  --arg rustc_archive_bytes "$cli_rustc_archive_bytes" \
  --arg rust_std_archive_name "${cli_std_archive##*/}" \
  --arg rust_std_archive_sha256 "$cli_std_archive_sha" \
  --arg rust_std_archive_bytes "$cli_std_archive_bytes" \
  --arg rust_src_archive_name "${cli_src_archive##*/}" \
  --arg rust_src_archive_sha256 "$cli_src_archive_sha" \
  --arg rust_src_archive_bytes "$cli_src_archive_bytes" \
  --arg cargo_zip_name "${cli_cargo_zip##*/}" \
  --arg cargo_zip_sha256 "$cli_cargo_zip_sha" \
  --arg cargo_zip_bytes "$(cli_file_bytes "$cli_cargo_zip")" \
  --arg cargo_artifact_id "$cli_cargo_id" \
  --arg cargo_sha256 "$cli_cargo_copy_sha" \
  --arg cargo_bytes "$(cli_file_bytes "$cli_prefix/native-cargo/bin/cargo")" \
  --arg cargo_path "$cli_prefix/native-cargo/bin/cargo" \
  --arg target_spec_path 'targets/x86_64-aros.json' \
  --arg target_spec_sha256 'de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71' \
  --arg target_alias_path 'lib/rustlib/x86_64-aros/target.json' \
  --arg target_alias_target 'x86_64-aros.json' \
  --arg excluded_admin_file 'records/excluded-installer-state.txt' \
  --arg excluded_component_metadata_file 'records/excluded-installer-metadata.txt' \
  '{schema:$schema,status:$status,host:$host,host_triple:$host_triple,manifest_sha256:$manifest_sha256,source_profile:{path:$profile_path,sha256:$profile_sha256},source_sysroot:$source_sysroot,rust_archives:{rustc:{name:$rustc_archive_name,bytes:($rustc_archive_bytes|tonumber),sha256:$rustc_archive_sha256},rust_std:{name:$rust_std_archive_name,bytes:($rust_std_archive_bytes|tonumber),sha256:$rust_std_archive_sha256},rust_src:{name:$rust_src_archive_name,bytes:($rust_src_archive_bytes|tonumber),sha256:$rust_src_archive_sha256}},native_cargo:{artifact_id:($cargo_artifact_id|tonumber),zip:{name:$cargo_zip_name,bytes:($cargo_zip_bytes|tonumber),sha256:$cargo_zip_sha256},binary:{path:$cargo_path,bytes:($cargo_bytes|tonumber),sha256:$cargo_sha256,mode_octal:"0755"}},target_spec:{path:$target_spec_path,sha256:$target_spec_sha256,staged_by_later_producer:true},target_alias:{path:$target_alias_path,target:$target_alias_target,materialized_by_later_producer:true},excluded_installer_state_record:$excluded_admin_file,excluded_component_installer_metadata_record:$excluded_component_metadata_file,execution:{downloaded_install_sh_executed:false,downloaded_rustc_or_cargo_executed:false,archive_extraction_only:true}}' > "$cli_receipt"
printf 'Staged pinned Rust inputs for %s under %s\n' "$cli_host_key" "$cli_prefix"
printf 'Receipt: %s\n' "$cli_receipt"

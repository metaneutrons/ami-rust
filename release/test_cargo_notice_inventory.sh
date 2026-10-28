#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
CAPSULE="$ROOT/release/cargo-notices/payload-v3"
ARCHIVE="$CAPSULE/cargo-notices-corresponding-source-v3.tar.xz"
INVENTORY="$CAPSULE/inventory.json"
BUNDLE_FILES="$ROOT/release/bundle-files.json"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ami-rust-notice-inventory.XXXXXX")"

cleanup() {
  command rm -rf -- "$TMP_ROOT"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fatal() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

reject() {
  printf 'REJECTED: %s\n' "$*" >&2
  return 1
}

sha256_rows() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

sha256_file() {
  local result
  result="$(sha256_rows "$1")" || return 1
  printf '%s\n' "${result%% *}"
}

file_bytes() {
  wc -c < "$1" | tr -d '[:space:]'
}

validate_archive() {
  local archive="$1"
  local index="$2"
  local state="$3"
  local listing="$state/members.txt"
  local verbose="$state/verbose.txt"
  local actual_sorted="$state/members.sorted"
  local unique_sorted="$state/members.unique"
  local expected_sorted="$state/expected.sorted"
  local prefixes="$state/prefixes.sorted"
  local conflicts="$state/prefix-conflicts.txt"
  local rows="$state/rows.tsv"
  local sizes="$state/sizes.actual.tsv"
  local sizes_expected="$state/sizes.expected.tsv"
  local hashes="$state/hashes.actual.tsv"
  local hashes_expected="$state/hashes.expected.tsv"
  local member row member_count verbose_count unique_count
  local extract="$state/extracted"
  local -a files

  if ! jq -e 'type == "object" and (.files | type == "array")' "$index" >/dev/null; then
    reject "inventory files must be a list"
    return 1
  fi
  if ! jq -e 'all(.files[]; type == "object")' "$index" >/dev/null; then
    reject "inventory file rows must be objects"
    return 1
  fi
  if ! jq -e 'all(.files[]; (.path | type == "string" and test("^[A-Za-z0-9._+/-]+$") and (startswith("/") | not) and (split("/") | all(. != "" and . != "." and . != ".."))) and (.bytes | type == "number" and . >= 0 and floor == .) and (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))' "$index" >/dev/null; then
    reject "inventory rows contain an invalid path, byte count, or SHA-256"
    return 1
  fi
  if jq -e 'any(.files[]; .path == "inventory.json")' "$index" >/dev/null; then
    reject "inventory.json must be excluded from its own files list"
    return 1
  fi
  if ! jq -e '([.files[].path] | length == (unique | length))' "$index" >/dev/null; then
    reject "inventory contains duplicate paths"
    return 1
  fi
  if ! jq -e '(.expanded_bytes_before_inventory | type == "number" and . >= 0 and floor == .) and (([.files[].bytes] | add // 0) == .expanded_bytes_before_inventory)' "$index" >/dev/null; then
    reject "expanded_bytes_before_inventory differs from listed member bytes"
    return 1
  fi

  if ! mkdir -p "$state"; then
    reject "cannot create validation directory"
    return 1
  fi
  if ! tar -tf "$archive" > "$listing"; then
    reject "cannot list source archive"
    return 1
  fi
  if ! tar -tvf "$archive" > "$verbose"; then
    reject "cannot inspect source archive member types"
    return 1
  fi

  member_count=0
  while IFS= read -r member || [[ -n "$member" ]]; do
    member_count=$((member_count + 1))
    if [[ ! "$member" =~ ^[A-Za-z0-9._+/-]+$ ]] || [[ "$member" == /* ]]; then
      reject "unsafe archive member path"
      return 1
    fi
    case "/$member/" in
      *"//"*|*"/./"*|*"/../"*)
        reject "unsafe archive member path"
        return 1
        ;;
    esac
  done < "$listing"

  verbose_count=0
  while IFS= read -r row || [[ -n "$row" ]]; do
    verbose_count=$((verbose_count + 1))
    if [[ "${row:0:1}" != "-" ]]; then
      reject "non-regular archive member"
      return 1
    fi
  done < "$verbose"
  if [[ "$verbose_count" -ne "$member_count" ]]; then
    reject "archive member type listing is incomplete"
    return 1
  fi

  if ! LC_ALL=C sort "$listing" > "$actual_sorted"; then
    reject "cannot sort archive member list"
    return 1
  fi
  if ! LC_ALL=C sort -u "$listing" > "$unique_sorted"; then
    reject "cannot check archive member uniqueness"
    return 1
  fi
  unique_count="$(awk 'END { print NR }' "$unique_sorted")" || return 1
  if [[ "$unique_count" -ne "$member_count" ]]; then
    reject "duplicate archive member"
    return 1
  fi

  if ! jq -r '.files[].path' "$index" > "$rows"; then
    reject "cannot read inventory member paths"
    return 1
  fi
  if ! printf 'inventory.json\n' >> "$rows"; then
    reject "cannot complete expected member list"
    return 1
  fi
  if ! LC_ALL=C sort "$rows" > "$expected_sorted"; then
    reject "cannot sort expected member list"
    return 1
  fi
  if ! cmp -s "$actual_sorted" "$expected_sorted"; then
    reject "archive member set differs from inventory files plus inventory.json"
    return 1
  fi

  if ! awk -F/ '{ path=""; for (i=1; i<NF; i++) { path=(path == "" ? $i : path "/" $i); print path } }' "$listing" | LC_ALL=C sort -u > "$prefixes"; then
    reject "cannot inspect archive path hierarchy"
    return 1
  fi
  if ! LC_ALL=C comm -12 "$actual_sorted" "$prefixes" > "$conflicts"; then
    reject "cannot check archive path hierarchy"
    return 1
  fi
  if [[ -s "$conflicts" ]]; then
    reject "archive file is also a parent path"
    return 1
  fi

  if [[ -e "$extract" || -L "$extract" ]]; then
    reject "extraction directory already exists"
    return 1
  fi
  if ! mkdir "$extract"; then
    reject "cannot create extraction directory"
    return 1
  fi
  if ! tar -xf "$archive" -C "$extract"; then
    reject "cannot extract validated source archive"
    return 1
  fi

  files=()
  while IFS= read -r member || [[ -n "$member" ]]; do
    files[${#files[@]}]="./$member"
  done < <(jq -r '.files[].path' "$index")
  if [[ "${#files[@]}" -gt 0 ]]; then
    if ! (cd "$extract" && wc -c "${files[@]}" | awk 'NF == 2 && $2 != "total" { path=$2; sub(/^\.\//, "", path); print path "\t" $1 }' | LC_ALL=C sort) > "$sizes"; then
      reject "cannot measure extracted inventory files"
      return 1
    fi
    if ! jq -r '.files[] | [.path, .bytes] | @tsv' "$index" | LC_ALL=C sort > "$sizes_expected"; then
      reject "cannot read inventory byte counts"
      return 1
    fi
    if ! cmp -s "$sizes" "$sizes_expected"; then
      reject "byte count mismatch for an inventory file"
      return 1
    fi
    if ! (cd "$extract" && sha256_rows "${files[@]}" | awk '{ path=$2; sub(/^\.\//, "", path); print path "\t" $1 }' | LC_ALL=C sort) > "$hashes"; then
      reject "cannot hash extracted inventory files"
      return 1
    fi
    if ! jq -r '.files[] | [.path, .sha256] | @tsv' "$index" | LC_ALL=C sort > "$hashes_expected"; then
      reject "cannot read inventory SHA-256 values"
      return 1
    fi
    if ! cmp -s "$hashes" "$hashes_expected"; then
      reject "SHA-256 mismatch for an inventory file"
      return 1
    fi
  fi

  ARCHIVE_MEMBER_COUNT="$member_count"
  EXPANDED_BYTES="$(jq -r '.expanded_bytes_before_inventory' "$index")" || return 1
}

expect_rejection() {
  local expected="$1"
  local label="$2"
  local log="$TMP_ROOT/$label.log"
  shift 2

  if "$@" > "$log" 2>&1; then
    fatal "$label counterexample was accepted"
  fi
  if ! grep -Fq "$expected" "$log"; then
    cat "$log" >&2
    fatal "$label counterexample failed for an unexpected reason"
  fi
  printf 'PASS: %s counterexample refused (%s)\n' "$label" "$expected"
}

check_bundle_pin() {
  local manifest_path="$1"
  local source_path="$2"
  local source_file="$3"
  local count expected_bytes expected_sha actual_bytes actual_sha

  count="$(jq --arg path "$manifest_path" '[.files[] | select(.path == $path)] | length' "$BUNDLE_FILES")" || fatal "cannot read bundle manifest rows"
  [[ "$count" == 1 ]] || fatal "bundle manifest must contain exactly one $manifest_path row"
  if ! jq -e --arg path "$manifest_path" --arg source "$source_path" 'any(.files[]; .path == $path and .source == $source)' "$BUNDLE_FILES" >/dev/null; then
    fatal "bundle manifest source mismatch for $manifest_path"
  fi
  expected_bytes="$(jq -r --arg path "$manifest_path" '.files[] | select(.path == $path) | .bytes' "$BUNDLE_FILES")" || fatal "cannot read bundle byte pin"
  expected_sha="$(jq -r --arg path "$manifest_path" '.files[] | select(.path == $path) | .sha256' "$BUNDLE_FILES")" || fatal "cannot read bundle SHA-256 pin"
  actual_bytes="$(file_bytes "$source_file")" || fatal "cannot measure $source_file"
  actual_sha="$(sha256_file "$source_file")" || fatal "cannot hash $source_file"
  [[ "$actual_bytes" == "$expected_bytes" ]] || fatal "bundle byte pin mismatch for $manifest_path"
  [[ "$actual_sha" == "$expected_sha" ]] || fatal "bundle SHA-256 pin mismatch for $manifest_path"
}

check_bundle_pin "cargo-notices-corresponding-source.tar.xz" "release/cargo-notices/payload-v3/cargo-notices-corresponding-source-v3.tar.xz" "$ARCHIVE"
check_bundle_pin "cargo-source-inventory.json" "release/cargo-notices/payload-v3/inventory.json" "$INVENTORY"

if ! validate_archive "$ARCHIVE" "$INVENTORY" "$TMP_ROOT/actual"; then
  fatal "published Cargo notice source archive failed inventory validation"
fi
if ! cmp -s "$INVENTORY" "$TMP_ROOT/actual/extracted/inventory.json"; then
  fatal "archive inventory.json bytes differ from the external inventory"
fi
[[ "$(jq -r '.files | length' "$INVENTORY")" == 2671 ]] || fatal "expected 2671 listed files"
[[ "$ARCHIVE_MEMBER_COUNT" == 2672 ]] || fatal "expected 2672 archive members"
[[ "$EXPANDED_BYTES" == 16772015 ]] || fatal "unexpected expanded byte total"
if ! jq -e 'any(.limitations[]; contains("inventory.json is excluded from its own files list") and contains("release/bundle-files.json"))' "$INVENTORY" >/dev/null; then
  fatal "inventory limitation does not identify the external bundle-manifest pin"
fi
printf 'PASS: published archive has 2671 indexed files, 2672 members, and 16772015 expanded bytes\n'

FIXTURE="$TMP_ROOT/fixture"
mkdir "$FIXTURE"
printf 'original' > "$FIXTURE/payload.txt"
FIXTURE_BYTES="$(file_bytes "$FIXTURE/payload.txt")" || fatal "cannot measure fixture payload"
FIXTURE_SHA="$(sha256_file "$FIXTURE/payload.txt")" || fatal "cannot hash fixture payload"
jq -n --arg path "payload.txt" --arg sha "$FIXTURE_SHA" --argjson bytes "$FIXTURE_BYTES" --argjson expanded "$FIXTURE_BYTES" '{expanded_bytes_before_inventory:$expanded,files:[{bytes:$bytes,path:$path,sha256:$sha}]}' > "$TMP_ROOT/fixture-index.json"
command cp "$TMP_ROOT/fixture-index.json" "$FIXTURE/inventory.json"
tar -cf "$TMP_ROOT/fixture-valid.tar" -C "$FIXTURE" inventory.json payload.txt
if ! validate_archive "$TMP_ROOT/fixture-valid.tar" "$TMP_ROOT/fixture-index.json" "$TMP_ROOT/fixture-valid"; then
  fatal "valid archive fixture failed"
fi
printf 'PASS: small archive fixture accepted\n'

jq '.files += [{bytes:0,path:"inventory.json",sha256:"0000000000000000000000000000000000000000000000000000000000000000"}]' "$TMP_ROOT/fixture-index.json" > "$TMP_ROOT/self-entry-index.json"
expect_rejection "inventory.json must be excluded from its own files list" self-entry validate_archive "$TMP_ROOT/fixture-valid.tar" "$TMP_ROOT/self-entry-index.json" "$TMP_ROOT/self-entry"

jq '.files = [] | .expanded_bytes_before_inventory = 0' "$TMP_ROOT/fixture-index.json" > "$TMP_ROOT/missing-index.json"
expect_rejection "archive member set differs" missing-member validate_archive "$TMP_ROOT/fixture-valid.tar" "$TMP_ROOT/missing-index.json" "$TMP_ROOT/missing-member"

mkdir "$TMP_ROOT/changed"
command cp "$FIXTURE/inventory.json" "$TMP_ROOT/changed/inventory.json"
printf 'mutated!' > "$TMP_ROOT/changed/payload.txt"
tar -cf "$TMP_ROOT/changed.tar" -C "$TMP_ROOT/changed" inventory.json payload.txt
expect_rejection "SHA-256 mismatch" changed-bytes validate_archive "$TMP_ROOT/changed.tar" "$TMP_ROOT/fixture-index.json" "$TMP_ROOT/changed-check"

tar -cf "$TMP_ROOT/duplicate.tar" -C "$FIXTURE" inventory.json payload.txt
tar -rf "$TMP_ROOT/duplicate.tar" -C "$FIXTURE" payload.txt
expect_rejection "duplicate archive member" duplicate-member validate_archive "$TMP_ROOT/duplicate.tar" "$TMP_ROOT/fixture-index.json" "$TMP_ROOT/duplicate-check"

mkdir "$TMP_ROOT/nonregular"
command cp "$FIXTURE/inventory.json" "$TMP_ROOT/nonregular/inventory.json"
command cp "$FIXTURE/payload.txt" "$TMP_ROOT/nonregular/payload.txt"
ln -s payload.txt "$TMP_ROOT/nonregular/link"
tar -cf "$TMP_ROOT/nonregular.tar" -C "$TMP_ROOT/nonregular" inventory.json payload.txt link
expect_rejection "non-regular archive member" nonregular-member validate_archive "$TMP_ROOT/nonregular.tar" "$TMP_ROOT/fixture-index.json" "$TMP_ROOT/nonregular-check"

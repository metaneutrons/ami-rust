#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Offline control-flow fixtures for authenticate mode; never publisher evidence.
set -euo pipefail
umask 077

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for tool in bash git jq zip shasum unzip awk wc date cmp grep mktemp rm mkdir uname dd; do
  command -v "$tool" >/dev/null || fail "missing test prerequisite: $tool"
done

repo_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
tmp_parent=${TMPDIR:-/tmp}
tmp_parent=$(cd -P -- "$tmp_parent" && pwd -P)
test_root=$(mktemp -d "$tmp_parent/ami-rust-native-cargo-auth.XXXXXX")
test_root=$(cd -P -- "$test_root" && pwd -P)
cleanup() {
  case "$test_root" in
    "$tmp_parent"/ami-rust-native-cargo-auth.*) command rm -rf -- "$test_root" ;;
    *) printf 'refusing cleanup outside this test\047s mktemp root: %s\n' "$test_root" >&2; exit 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:aarch64) host=macos-aarch64; triple=aarch64-apple-darwin ;;
  Linux:x86_64) host=linux-x86_64; triple=x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) host=linux-aarch64; triple=aarch64-unknown-linux-gnu ;;
  *) fail 'the host does not match an admitted native host mapping' ;;
esac

source_fixture="$test_root/source"
runner_temp="$test_root/runner-temp"
fake_bin="$test_root/fake-bin"
fixture_data="$test_root/gh-fixtures"
mkdir -p "$source_fixture/tools" "$source_fixture/release" "$runner_temp" "$fake_bin" "$fixture_data"
command cp "$repo_root/tools/qualify-native-cargo-consumer.sh" "$source_fixture/tools/qualify-native-cargo-consumer.sh"
chmod 0755 "$source_fixture/tools/qualify-native-cargo-consumer.sh"

native_payload="$fixture_data/native-payload"
bare_payload="$fixture_data/bare-payload/producer/libraries"
mkdir -p "$native_payload" "$bare_payload"
printf '%s\n' 'UNIT_FIXTURE native cargo payload' > "$native_payload/cargo"
printf '%s\n' 'UNIT_FIXTURE target library' > "$bare_payload/libcore-fixture.rlib"
(
  cd -P -- "$native_payload"
  zip -q -X "$fixture_data/native-cargo.zip" cargo
)
(
  cd -P -- "$fixture_data/bare-payload"
  zip -q -X "$fixture_data/bare-target-libraries.zip" producer/libraries/libcore-fixture.rlib
)
command cp "$fixture_data/native-cargo.zip" "$fixture_data/native-cargo-corrupt.zip"
printf '\0' | dd of="$fixture_data/native-cargo-corrupt.zip" bs=1 seek=35 conv=notrunc 2>/dev/null

native_zip_bytes=$(wc -c < "$fixture_data/native-cargo.zip" | tr -d '[:space:]')
native_zip_sha=$(shasum -a 256 "$fixture_data/native-cargo.zip" | awk '{print $1}')
bare_zip_bytes=$(wc -c < "$fixture_data/bare-target-libraries.zip" | tr -d '[:space:]')
bare_zip_sha=$(shasum -a 256 "$fixture_data/bare-target-libraries.zip" | awk '{print $1}')
native_head=$(printf '%040d' 0 | tr '0' 'a')
bare_head=$(printf '%040d' 0 | tr '0' 'b')
csdk_head=$(printf '%040d' 0 | tr '0' 'c')
native_tree=$(printf '%040d' 0 | tr '0' 'd')
bare_tree=$(printf '%040d' 0 | tr '0' 'e')
payload_sha=$(printf '%064d' 0 | tr '0' 'f')
profile_sha=$(printf '%064d' 0 | tr '0' '1')
csdk_component_sha=$(printf '%064d' 0 | tr '0' '2')
csdk_profile_sha=$(printf '%064d' 0 | tr '0' '3')

jq -n \
  --arg host "$host" --arg triple "$triple" \
  --arg native_sha "$native_zip_sha" --argjson native_bytes "$native_zip_bytes" \
  --arg bare_sha "$bare_zip_sha" --argjson bare_bytes "$bare_zip_bytes" \
  --arg native_head "$native_head" --arg bare_head "$bare_head" --arg csdk_head "$csdk_head" \
  --arg native_tree "$native_tree" --arg bare_tree "$bare_tree" \
  --arg payload_sha "$payload_sha" --arg profile_sha "$profile_sha" \
  --arg csdk_component_sha "$csdk_component_sha" --arg csdk_profile_sha "$csdk_profile_sha" \
  '{schema:"ami-rust-native-cargo-qualification-prerequisites-v1",
    native_cargo:{run_id:70101,artifact_id:80101,workflow:".github/workflows/cargo-native-prerequisite.yml",artifact_name:"native-cargo-fixture.zip",repository:"metaneutrons/ami-rust",attempt:2,head:$native_head,tree:$native_tree,zip_bytes:$native_bytes,zip_sha256:$native_sha,payload_path:"cargo",payload_bytes:1,payload_sha256:$payload_sha,hosts:{($host):{artifact_id:80101,artifact_name:"native-cargo-fixture.zip",zip_bytes:$native_bytes,zip_sha256:$native_sha,payload_path:"cargo",payload_bytes:1,payload_sha256:$payload_sha,native_host:$triple}}},
    bare_target_libraries:{run_id:70102,artifact_id:80102,workflow:".github/workflows/bare-target-libraries.yml",artifact_name:"bare-libraries-fixture.zip",repository:"metaneutrons/ami-rust",attempt:2,head:$bare_head,tree:$bare_tree,zip_bytes:$bare_bytes,zip_sha256:$bare_sha,payload_path:"cargo",payload_bytes:1,payload_sha256:$payload_sha,profile_path:"target-libraries.json",profile_sha256:$profile_sha,hosts:{($host):{artifact_id:80102,artifact_name:"bare-libraries-fixture.zip",zip_bytes:$bare_bytes,zip_sha256:$bare_sha,library_paths:["producer/libraries/libcore-fixture.rlib"]}}},
    linux_aarch64_csdk:(if $host == "linux-aarch64" then {run_id:70103,artifact_id:80103,workflow:".github/workflows/csdk-linux-aarch64-producer.yml",artifact_name:"csdk-fixture.zip",repository:"metaneutrons/ami-rust",attempt:2,head:$csdk_head,zip_bytes:$bare_bytes,zip_sha256:$bare_sha,component_path:"csdk-component.tar.xz",component_bytes:1,component_sha256:$csdk_component_sha,profile_path:"csdk-profile.json",profile_bytes:1,profile_sha256:$csdk_profile_sha} else null end)}' \
  > "$source_fixture/release/native-cargo-qualification-prerequisites.json"
jq -n --arg host "$host" --arg triple "$triple" \
  '{schema:"ami-rust-native-cargo-consumer-inputs-v1",hosts:{($host):{rust_host_triple:$triple}}}' \
  > "$source_fixture/release/native-cargo-consumer-inputs.json"

fixture_key_fields() {
  case "$1" in
    native_cargo)
      FIXTURE_RUN=70101 FIXTURE_ARTIFACT=80101 FIXTURE_WORKFLOW=.github/workflows/cargo-native-prerequisite.yml
      FIXTURE_NAME=native-cargo-fixture.zip FIXTURE_HEAD=$native_head FIXTURE_TREE=$native_tree
      FIXTURE_ZIP_BYTES=$native_zip_bytes FIXTURE_ZIP_SHA=$native_zip_sha ;;
    bare_target_libraries)
      FIXTURE_RUN=70102 FIXTURE_ARTIFACT=80102 FIXTURE_WORKFLOW=.github/workflows/bare-target-libraries.yml
      FIXTURE_NAME=bare-libraries-fixture.zip FIXTURE_HEAD=$bare_head FIXTURE_TREE=$bare_tree
      FIXTURE_ZIP_BYTES=$bare_zip_bytes FIXTURE_ZIP_SHA=$bare_zip_sha ;;
    linux_aarch64_csdk)
      FIXTURE_RUN=70103 FIXTURE_ARTIFACT=80103 FIXTURE_WORKFLOW=.github/workflows/csdk-linux-aarch64-producer.yml
      FIXTURE_NAME=csdk-fixture.zip FIXTURE_HEAD=$csdk_head FIXTURE_TREE=
      FIXTURE_ZIP_BYTES=$bare_zip_bytes FIXTURE_ZIP_SHA=$bare_zip_sha ;;
    *) fail "unknown fixture key: $1" ;;
  esac
}

write_fixture_json() {
  local file=$1 value=$2
  mkdir -p "$(dirname -- "$file")"
  printf '%s\n' "$value" > "$file"
}

cases='positive wrong_repository wrong_head wrong_attempt wrong_digest expired malformed_run wrong_source_tree wrong_zip'
keys='native_cargo bare_target_libraries'
[[ "$host" != linux-aarch64 ]] || keys="$keys linux_aarch64_csdk"
for fixture_case in $cases; do
  for key in $keys; do
    fixture_key_fields "$key"
    run_repository=metaneutrons/ami-rust
    run_head=$FIXTURE_HEAD
    run_attempt=2
    artifact_digest="sha256:$FIXTURE_ZIP_SHA"
    expired=false
    if [[ "$fixture_case" == wrong_repository && "$key" == native_cargo ]]; then run_repository=another/repository; fi
    if [[ "$fixture_case" == wrong_head && "$key" == native_cargo ]]; then run_head=$(printf '%040d' 0 | tr '0' '9'); fi
    if [[ "$fixture_case" == wrong_attempt && "$key" == native_cargo ]]; then run_attempt=3; fi
    if [[ "$fixture_case" == wrong_digest && "$key" == native_cargo ]]; then artifact_digest="sha256:$(printf '%064d' 0 | tr '0' '0')"; fi
    if [[ "$fixture_case" == expired && "$key" == native_cargo ]]; then expired=true; fi
    run_json=$(jq -n --argjson id "$FIXTURE_RUN" --argjson attempt "$run_attempt" --arg repository "$run_repository" \
      --arg head "$run_head" --arg workflow "$FIXTURE_WORKFLOW" \
      '{id:$id,run_attempt:$attempt,repository:{full_name:$repository},event:"workflow_dispatch",head_branch:"main",head_sha:$head,path:$workflow,status:"completed",conclusion:"success"}')
    commit_tree=$FIXTURE_TREE
    if [[ "$fixture_case" == wrong_source_tree && "$key" == native_cargo ]]; then commit_tree=$(printf '%040d' 0 | tr '0' '8'); fi
    if [[ -n "$FIXTURE_TREE" ]]; then
      commit_json=$(jq -n --arg tree "$commit_tree" '{tree:{sha:$tree}}')
      write_fixture_json "$fixture_data/$fixture_case/$key.commit.json" "$commit_json"
    fi
    artifact_json=$(jq -n --argjson id "$FIXTURE_ARTIFACT" --arg name "$FIXTURE_NAME" \
      --argjson bytes "$FIXTURE_ZIP_BYTES" --arg digest "$artifact_digest" --argjson expired "$expired" \
      --argjson run "$FIXTURE_RUN" --arg head "$FIXTURE_HEAD" \
      '{id:$id,name:$name,size_in_bytes:$bytes,digest:$digest,expired:$expired,workflow_run:{id:$run,head_sha:$head}}')
    write_fixture_json "$fixture_data/$fixture_case/$key.run.json" "$run_json"
    write_fixture_json "$fixture_data/$fixture_case/$key.artifact.json" "$artifact_json"
    zip_source="$fixture_data/bare-target-libraries.zip"
    [[ "$key" != native_cargo ]] || zip_source="$fixture_data/native-cargo.zip"
    if [[ "$fixture_case" == wrong_zip && "$key" == native_cargo ]]; then zip_source="$fixture_data/native-cargo-corrupt.zip"; fi
    command cp "$zip_source" "$fixture_data/$fixture_case/$key.zip"
  done
  if [[ "$fixture_case" == malformed_run ]]; then
    printf '{"id":\n' > "$fixture_data/$fixture_case/native_cargo.run.json"
  fi
done
printf 'created UNIT_FIXTURE archives and metadata for %s\n' "$host"

GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -c init.defaultBranch=main -C "$source_fixture" init --quiet
git -C "$source_fixture" add -- tools/qualify-native-cargo-consumer.sh release/native-cargo-qualification-prerequisites.json release/native-cargo-consumer-inputs.json
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
GIT_AUTHOR_NAME='Qualification Fixture' GIT_AUTHOR_EMAIL='fixture@example.invalid' \
GIT_COMMITTER_NAME='Qualification Fixture' GIT_COMMITTER_EMAIL='fixture@example.invalid' \
GIT_AUTHOR_DATE='2026-10-23T00:00:00Z' GIT_COMMITTER_DATE='2026-10-23T00:00:00Z' \
  git -c commit.gpgsign=false -C "$source_fixture" commit --quiet -m 'UNIT_FIXTURE source snapshot'
source_sha=$(git -C "$source_fixture" rev-parse HEAD)
source_tree=$(git -C "$source_fixture" rev-parse 'HEAD^{tree}')

cat > "$fake_bin/gh" <<'GH_STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && $1 == api ]] || { printf 'unexpected fake gh invocation\n' >&2; exit 64; }
endpoint=$2
printf '%s\n' "$endpoint" >> "$GH_CALL_LOG"
case "$endpoint" in
  repos/metaneutrons/ami-rust/actions/runs/70101) key=native_cargo; kind=run ;;
  repos/metaneutrons/ami-rust/actions/runs/70102) key=bare_target_libraries; kind=run ;;
  repos/metaneutrons/ami-rust/actions/runs/70103) key=linux_aarch64_csdk; kind=run ;;
  repos/metaneutrons/ami-rust/git/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) key=native_cargo; kind=commit ;;
  repos/metaneutrons/ami-rust/git/commits/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) key=bare_target_libraries; kind=commit ;;
  repos/metaneutrons/ami-rust/actions/artifacts/80101) key=native_cargo; kind=artifact ;;
  repos/metaneutrons/ami-rust/actions/artifacts/80102) key=bare_target_libraries; kind=artifact ;;
  repos/metaneutrons/ami-rust/actions/artifacts/80103) key=linux_aarch64_csdk; kind=artifact ;;
  repos/metaneutrons/ami-rust/actions/artifacts/80101/zip) key=native_cargo; kind=zip ;;
  repos/metaneutrons/ami-rust/actions/artifacts/80102/zip) key=bare_target_libraries; kind=zip ;;
  repos/metaneutrons/ami-rust/actions/artifacts/80103/zip) key=linux_aarch64_csdk; kind=zip ;;
  *) printf 'unhandled fake gh API path: %s\n' "$endpoint" >&2; exit 65 ;;
esac
case "$kind" in
  zip) cat "$GH_FIXTURE_DIR/$GH_CASE/$key.zip" ;;
  *) cat "$GH_FIXTURE_DIR/$GH_CASE/$key.$kind.json" ;;
esac
GH_STUB
chmod 0755 "$fake_bin/gh"

cat > "$fake_bin/curl" <<'CURL_STUB'
#!/usr/bin/env bash
printf 'unexpected curl invocation\n' >> "$CURL_CALL_LOG"
exit 66
CURL_STUB
chmod 0755 "$fake_bin/curl"

export PATH="$fake_bin:$PATH"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export RUNNER_TEMP="$runner_temp"
export GITHUB_REPOSITORY=metaneutrons/ami-rust
export GITHUB_REF=refs/heads/main
export NATIVE_REF_PROTECTED=true
export GITHUB_SHA="$source_sha"
campaign_start=$(date +%s)
export NATIVE_CAMPAIGN_START_EPOCH="$campaign_start"
export GH_FIXTURE_DIR="$fixture_data"
export CURL_CALL_LOG="$test_root/curl-calls.log"

run_auth() {
  local case_name=$1 sha_override=${2:-$source_sha}
  local managed="$RUNNER_TEMP/ami-rust-native-cargo-consumer/$case_name"
  local calls="$test_root/$case_name.gh-calls.log"
  export GH_CASE="$case_name" GH_CALL_LOG="$calls" GITHUB_SHA="$sha_override"
  if "$source_fixture/tools/qualify-native-cargo-consumer.sh" authenticate "$host" "$managed" \
      >"$test_root/$case_name.stdout" 2>"$test_root/$case_name.stderr"; then
    return 0
  else
    return $?
  fi
}

assert_no_zip_fetch() {
  local case_name=$1
  local calls="$test_root/$case_name.gh-calls.log"
  [[ -f "$calls" ]] || return 0
  if grep -q '/zip$' "$calls"; then fail "$case_name requested ZIP bytes before metadata authentication completed"; fi
}

if ! run_auth positive; then fail 'positive authentication fixture was refused'; fi
success_root="$RUNNER_TEMP/ami-rust-native-cargo-consumer/positive"
[[ -f "$success_root/auth/handoff.json" ]] || fail 'success handoff receipt was not retained'
jq -e --arg head "$source_sha" --arg tree "$source_tree" \
  --arg pins "$(shasum -a 256 "$source_fixture/release/native-cargo-qualification-prerequisites.json" | awk '{print $1}')" \
  --arg inputs "$(shasum -a 256 "$source_fixture/release/native-cargo-consumer-inputs.json" | awk '{print $1}')" \
  '.schema == "ami-rust-native-cargo-source-handoff-v1" and .head == $head and .tree == $tree and .prerequisites_sha256 == $pins and .acquisition_inputs_sha256 == $inputs and .claim == "Reviewed prior-run artifacts authenticated; no consumer, SDK, or release acceptance."' \
  "$success_root/auth/handoff.json" >/dev/null || fail 'success handoff identity differs'
[[ $(cat "$success_root/auth/source-tree.txt") == "$source_tree" ]] || fail 'retained source tree differs'

for key in native_cargo bare_target_libraries; do
  cmp -s "$success_root/auth/$key.run.json" "$fixture_data/positive/$key.run.json" || fail "$key run identity was not retained exactly"
  cmp -s "$success_root/auth/$key.commit.json" "$fixture_data/positive/$key.commit.json" || fail "$key source tree identity was not retained exactly"
  cmp -s "$success_root/auth/$key.artifact.json" "$fixture_data/positive/$key.artifact.json" || fail "$key artifact identity was not retained exactly"
  cmp -s "$success_root/downloads/$key.zip" "$fixture_data/positive/$key.zip" || fail "$key ZIP bytes differ from the authenticated fixture"
done
if [[ "$host" == linux-aarch64 ]]; then
  key=linux_aarch64_csdk
  cmp -s "$success_root/auth/$key.run.json" "$fixture_data/positive/$key.run.json" || fail 'CSDK run identity was not retained exactly'
  cmp -s "$success_root/auth/$key.artifact.json" "$fixture_data/positive/$key.artifact.json" || fail 'CSDK artifact identity was not retained exactly'
  cmp -s "$success_root/downloads/$key.zip" "$fixture_data/positive/$key.zip" || fail 'CSDK ZIP bytes differ from authenticated fixture'
fi
[[ ! -s "$CURL_CALL_LOG" ]] || fail 'authentication unexpectedly used curl/download transport'

for rejected in wrong_repository wrong_head wrong_attempt wrong_digest expired malformed_run wrong_source_tree; do
  if run_auth "$rejected"; then fail "$rejected metadata was unexpectedly accepted"; fi
  assert_no_zip_fetch "$rejected"
  case "$rejected" in
    wrong_repository|wrong_head|wrong_attempt) diagnostic='prerequisite run identity/status differs' ;;
    wrong_digest|expired) diagnostic='prerequisite artifact metadata differs' ;;
    wrong_source_tree) diagnostic='prerequisite source tree differs' ;;
    malformed_run) diagnostic='parse error' ;;
  esac
  grep -Fq "$diagnostic" "$test_root/$rejected.stderr" || fail "$rejected failed for an unrelated reason"
done
if run_auth wrong_source_sha "0000000000000000000000000000000000000000"; then fail 'wrong checkout source SHA was accepted'; fi
assert_no_zip_fetch wrong_source_sha
[[ ! -s "$test_root/wrong_source_sha.gh-calls.log" ]] || fail 'wrong source SHA reached the GitHub API'
grep -Fq 'checkout does not match the protected source SHA' "$test_root/wrong_source_sha.stderr" || fail 'wrong source SHA failed for an unrelated reason'
if run_auth wrong_zip; then fail 'modified original ZIP bytes were accepted'; fi
grep -q '/actions/artifacts/80101/zip$' "$test_root/wrong_zip.gh-calls.log" || fail 'wrong ZIP fixture did not reach the artifact-byte check'
grep -Fq 'input identity differs:' "$test_root/wrong_zip.stderr" || fail 'modified ZIP failed for an unrelated reason'

printf 'PASS: authenticate mode fixture controls completed for %s; metadata failures stopped before ZIP fetch, and altered ZIP bytes were refused. Fixtures are UNIT_FIXTURE only.\n' "$host"

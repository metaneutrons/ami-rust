#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Internal native-Cargo development prerequisite. Not SDK or release admission.
set -Eeuo pipefail
umask 077

readonly REQUEST_SCHEMA=ami-rust-native-command-qualification-request-v1
readonly HELPER_RECORD_SCHEMA=ami-rust-native-command-qualification-record-v1
readonly CARGO_SOURCE_COMMIT=3efb1f477e99b42974b982d939fd100303cdf7db
readonly RUSTC_COMMIT=48a229ceaefd4985c50990b14116b6d856af0985
readonly CARGO_COMMIT=797e8a9bca276c1c9f9f738d2a20f484fa4eea9d
readonly SOURCE_PATCH_SHA=1f22b7e2c6a7f4469cc6c2f4a84019d8d8ade558e78241d1e996d88a7f1de97f
readonly RESOURCE_POLICY_SHA=b9a5fbfff842847c30b5f56ea4e1d3a368f4bda30689f0407ed9d33610571646
readonly MAX_SECONDS=1200
readonly HELPER_MAX_RSS=3758096384
readonly MAX_WORKSPACE=12884901888
readonly MAX_LOG=16777216
readonly CAMPAIGN_SECONDS=5400
readonly REVIEW_RESERVE=300
readonly ARTIFACT_PAYLOAD_MAX=133165056 # 127 MiB less 4 KiB for final metadata.
readonly TRIPLE="${NATIVE_HOST_TRIPLE:?workflow must select a native Linux host}"
readonly REPO="$GITHUB_WORKSPACE/source"
readonly ROOT="${NATIVE_MANAGED_ROOT:?preflight must create the managed root}"
readonly CAMPAIGN_START="${NATIVE_CAMPAIGN_START_EPOCH:?preflight must start the campaign clock}"
readonly BOOTSTRAP="$ROOT/bootstrap"
readonly TOOLING="$ROOT/tooling"
readonly TOOLING_HOME="$TOOLING/cargo-home"
readonly TOOLING_TMP="$TOOLING/tmp"
readonly TOOLING_TARGET="$TOOLING/target"
readonly TOOLING_VENDOR="$TOOLING/vendor"
readonly UPSTREAM="$ROOT/upstream-cargo"
readonly PRODUCER="$ROOT/producer"
readonly SETUP="$ROOT/setup"
readonly ARTIFACT="${NATIVE_OUTER_OUTPUT:?preflight must create the outer output root}/artifact"
readonly PHASE_ACTIVE="$ROOT/native-cargo-active-phase"
readonly RECORDS="$ROOT/command-records"
readonly REQUESTS="$ROOT/requests"
readonly PHASE_INDEX="$ROOT/phase-index"
readonly HELPER_CLI="$ROOT/helper-cli"

phase=initialization
final_status=FAILED
failure_stage=not-completed
sequence=0
cargo_binary=
xtask_binary=
source_commit=
source_head=
policy_sha=
tooling_lock_sha=
xtask_sha=
cargo_sha=
LAST_RECORD=
LAST_REQUEST_SHA=

mkdir -p "$TOOLING" "$TOOLING_HOME" "$TOOLING_TMP" \
  "$TOOLING_TARGET" "$SETUP" "$ARTIFACT" "$RECORDS" "$REQUESTS" \
  "$PHASE_INDEX" "$HELPER_CLI" "$PRODUCER" "$TOOLING/home" \
  "$ROOT/control" "$ROOT/smoke"
test -d "$REPO"
test -d "$ROOT"
test -d "$RUNNER_TEMP"
test "$NATIVE_EVENT_NAME" = workflow_dispatch
test "$NATIVE_REPOSITORY" = metaneutrons/ami-rust
test "$NATIVE_REF_NAME" = refs/heads/main
test "$NATIVE_REF_PROTECTED" = true
test "$NATIVE_RUN_ID" = "$GITHUB_RUN_ID"
test "$NATIVE_RUN_ATTEMPT" = "$GITHUB_RUN_ATTEMPT"
test "$NATIVE_HOST_TRIPLE" = "$TRIPLE"

sha256_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

require_sha() {
  local file=$1 expected=$2 actual
  actual=$(sha256_file "$file")
  if [ "$actual" != "$expected" ]; then
    echo "input digest mismatch: $file" >&2
    return 1
  fi
}

campaign_budget() {
  local now elapsed remaining
  now=$(date +%s)
  elapsed=$((now - CAMPAIGN_START))
  remaining=$((CAMPAIGN_SECONDS - elapsed))
  if (( remaining <= REVIEW_RESERVE )); then
    echo "campaign exhausted its 300-second review reserve" >&2
    return 1
  fi
  printf '%s\n' "$((remaining - REVIEW_RESERVE))"
}

compress_streams() {
  local directory=$1 stream
  for stream in stdout stderr; do
    if [ -f "$directory/$stream.log" ]; then
      gzip -n -c "$directory/$stream.log" > "$directory/$stream.raw.gz" || return 1
      rm -- "$directory/$stream.log" || return 1
    fi
  done
}

setup_run() {
  local label=$1 limit=$2 log="$SETUP/$1.log"
  shift 2
  local start end rc
  start=$(date +%s)
  if timeout --foreground --kill-after=10 "$limit" \
    env -i \
      PATH="$BOOTSTRAP/toolchain/bin:/usr/bin:/bin" \
      HOME="$TOOLING/home" \
      TMPDIR="$TOOLING_TMP" \
      CARGO_HOME="$TOOLING_HOME" \
      CARGO_TARGET_DIR="$TOOLING_TARGET" \
      CARGO_BUILD_JOBS="2" \
      CARGO_PROFILE_DEV_DEBUG=0 \
      CARGO_PROFILE_DEV_INCREMENTAL=false \
      CARGO_INCREMENTAL=0 \
      LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1791936000 \
      "$@" > "$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  end=$(date +%s)
  jq -n \
    --arg schema ami-rust-native-cargo-setup-phase-v1 \
    --arg phase "$label" \
    --arg status "$([ "$rc" -eq 0 ] && echo complete || echo failed)" \
    --argjson started_epoch "$start" \
    --argjson ended_epoch "$end" \
    --argjson elapsed_seconds "$((end - start))" \
    --argjson exit_code "$rc" \
    --arg accounting "unqualified setup measurement: launcher wall time only; no aggregate RSS or full helper root scan" \
    '{schema:$schema,phase:$phase,status:$status,started_epoch:$started_epoch,ended_epoch:$ended_epoch,elapsed_seconds:$elapsed_seconds,exit_code:$exit_code,accounting:$accounting}' \
    > "$SETUP/$label.json"
  gzip -n -c "$log" > "$SETUP/$label.output.gz"
  wc -c < "$log" | tr -d ' ' > "$SETUP/$label.output.bytes"
  rm -- "$log"
  if [ "$rc" -ne 0 ]; then
    failure_stage=$label
    echo "$label failed with status $rc; see retained compressed setup log" >&2
    return "$rc"
  fi
}

driver_env() {
  jq -cn \
    --arg home "$TOOLING/home" \
    --arg tmp "$TOOLING_TMP" \
    --arg cargo_home "$TOOLING_HOME" \
    --arg target "$TOOLING_TARGET" \
    --arg rustc "$BOOTSTRAP/toolchain/bin/rustc" \
    --arg rustdoc "$BOOTSTRAP/toolchain/bin/rustdoc" \
    --arg path "$BOOTSTRAP/toolchain/bin:/usr/bin:/bin" \
    '{
      PATH:$path,HOME:$home,TMPDIR:$tmp,CARGO_HOME:$cargo_home,
      CARGO_TARGET_DIR:$target,RUSTC:$rustc,RUSTDOC:$rustdoc,
      CARGO_BUILD_JOBS:"2",CARGO_INCREMENTAL:"0",
      CARGO_PROFILE_DEV_DEBUG:"0",CARGO_PROFILE_DEV_INCREMENTAL:"false",
      CARGO_PROFILE_RELEASE_DEBUG:"0",CARGO_PROFILE_RELEASE_INCREMENTAL:"false",
      LC_ALL:"C",TZ:"UTC",SOURCE_DATE_EPOCH:"1791936000",
      GIT_CONFIG_NOSYSTEM:"1",GIT_CONFIG_GLOBAL:"/dev/null",
      GIT_TERMINAL_PROMPT:"0"
    }'
}

run_q() {
  local label=$1 program=$2 cwd=$3 environment_json=$4
  shift 4
  local campaign_limit limit record request_path cli_path request request_sha limits_json record_request_sha record_child_exit rc cleanup_status actual_program
  case "$program" in
    /*) ;;
    *) echo "qualification command program must be absolute: $program" >&2; return 125 ;;
  esac
  actual_program=$(/usr/bin/readlink -e -- "$program") || {
    echo "qualification command program cannot be resolved: $program" >&2
    return 125
  }
  if [ ! -f "$actual_program" ] || [ ! -x "$actual_program" ]; then
    echo "qualification command program is not an executable regular file: $program" >&2
    return 125
  fi
  campaign_limit=$(campaign_budget) || return 124
  limit=$MAX_SECONDS
  sequence=$((sequence + 1))
  record="$RECORDS/$(printf '%03d' "$sequence")-$label"
  request_path="$REQUESTS/$(printf '%03d' "$sequence")-$label.json"
  cli_path="$HELPER_CLI/$(printf '%03d' "$sequence")-$label"
  if [ -e "$record" ] || [ -L "$record" ] || [ -e "$request_path" ] || [ -L "$request_path" ]; then
    echo "qualification record path is not fresh: $label" >&2
    return 125
  fi
  mkdir -m 700 "$cli_path" || return 125
  request=$(jq -cn \
    --arg schema "$REQUEST_SCHEMA" \
    --arg program "$actual_program" \
    --arg cwd "$cwd" \
    --argjson environment "$environment_json" \
    --arg root_source "$REPO" \
    --arg root_managed "$ROOT" \
    --argjson seconds "$limit" \
    --argjson rss "$HELPER_MAX_RSS" \
    --args \
    '{
      schema:$schema,program:$program,args:$ARGS.positional,cwd:$cwd,
      environment:$environment,required_roots:[$root_source,$root_managed],
      limits:{seconds:$seconds,rss_bytes:$rss,
        workspace_bytes:12884901888,log_bytes:16777216}
    }' -- "$@") || return 125
  printf '%s\n' "$request" > "$request_path" || return 125
  request_sha=$(sha256_file "$request_path") || return 125
  limits_json=$(jq -cn --argjson seconds "$limit" --argjson rss "$HELPER_MAX_RSS" \
    '{seconds:$seconds,rss_bytes:$rss,workspace_bytes:12884901888,log_bytes:16777216}') || return 125
  jq -n \
    --arg schema ami-rust-native-cargo-phase-input-index-v1 \
    --arg phase "$label" \
    --arg request_sha256 "$request_sha" \
    --arg record "$record/result.json" \
    --arg program "$actual_program" \
    --arg requested_program "$program" \
    --arg cwd "$cwd" \
    --argjson limits "$limits_json" \
    '{schema:$schema,phase:$phase,request_sha256:$request_sha256,record:$record,requested_program:$requested_program,program:$program,cwd:$cwd,limits:$limits}' \
    > "$PHASE_INDEX/$(printf '%03d' "$sequence")-$label.json" || return 125

  if [ -e "$PHASE_ACTIVE" ] || [ -e "$PHASE_ACTIVE.tmp" ]; then
    echo "native Cargo active-phase marker is not fresh" >&2
    return 125
  fi
  printf '%s\n' "$label" > "$PHASE_ACTIVE.tmp" || return 125
  command mv -f -- "$PHASE_ACTIVE.tmp" "$PHASE_ACTIVE" || return 125
  if timeout --foreground --kill-after=10 "$campaign_limit" \
    env -i PATH="/usr/bin:/bin" HOME="$TOOLING/home" TMPDIR="$TOOLING_TMP" LC_ALL=C TZ=UTC \
    "$XTASK" qualification-command --request "$request_path" --record "$record" \
    > "$cli_path/stdout.log" 2> "$cli_path/stderr.log"; then
    rc=0
  else
    rc=$?
  fi
  cleanup_status=0
  rm -- "$PHASE_ACTIVE" || cleanup_status=1
  rm -- "$request_path" || cleanup_status=1
  if [ "$cleanup_status" -ne 0 ]; then
    echo "helper phase marker or request cleanup failed for $label" >&2
    return 125
  fi
  if [ ! -f "$record/result.json" ]; then
    compress_streams "$cli_path" || return 125
    echo "qualification helper did not produce a typed result for $label" >&2
    return 125
  fi
  if ! jq -e --arg schema "$HELPER_RECORD_SCHEMA" \
    '.schema == $schema and .request_sha256 != null' "$record/result.json" >/dev/null; then
    compress_streams "$record" || return 125
    compress_streams "$cli_path" || return 125
    echo "qualification helper record schema mismatch for $label" >&2
    return 125
  fi
  record_request_sha=$(jq -er '.request_sha256 | select(type == "string")' "$record/result.json") || return 125
  if [ "$record_request_sha" != "$request_sha" ]; then
    compress_streams "$record" || return 125
    compress_streams "$cli_path" || return 125
    echo "qualification helper request binding mismatch for $label" >&2
    return 125
  fi
  if [ "$rc" -eq 0 ]; then
    compress_streams "$cli_path" || return 125
    jq -e \
      --arg schema ami-rust-native-command-qualification-result-v1 \
      --arg request_sha256 "$request_sha" \
      --arg record "$record/result.json" \
      '.schema == $schema and .passed == true and
       .request_sha256 == $request_sha256 and .record == $record' \
      <(gzip -cd "$cli_path/stdout.raw.gz") >/dev/null || return 125
    jq -e \
      --argjson rss "$HELPER_MAX_RSS" \
      --argjson workspace "$MAX_WORKSPACE" \
      --argjson logs "$MAX_LOG" \
      '.passed == true and .capture_complete == true and
       .child_exit_code == 0 and .child_signal == null and
       .aggregate_peak_rss_bytes != null and
       .aggregate_peak_rss_bytes <= $rss and
       .workspace_bytes_at_finish != null and
       .workspace_bytes_at_finish <= $workspace and
       .log_bytes_at_finish != null and
       .log_bytes_at_finish <= $logs' \
      "$record/result.json" >/dev/null || return 125
  else
    jq -e '.passed == false' "$record/result.json" >/dev/null || return 125
    record_child_exit=$(jq -er '.child_exit_code // 0' "$record/result.json") || return 125
    if [ "$record_child_exit" -ne "$rc" ]; then
      compress_streams "$record" || return 125
      compress_streams "$cli_path" || return 125
      echo "helper did not preserve the child exit status for $label" >&2
      return 125
    fi
  fi
  compress_streams "$record" || return 125
  compress_streams "$cli_path" || return 125
  LAST_RECORD=$record
  LAST_REQUEST_SHA=$request_sha
  return "$rc"
}

expect_stdout_line() {
  local label=$1 expected=$2 directory=$3
  if ! grep -Fqx -- "$expected" <(gzip -cd "$directory/stdout.raw.gz"); then
    echo "expected output line missing for $label" >&2
    return 1
  fi
}

# shellcheck disable=SC2329 # Invoked by the EXIT trap.
finalize() {
  local original_rc=$? end_epoch elapsed payload_bytes measured_bytes stable iteration path copied_cargo_sha
  trap - EXIT
  set +e
  mark_finalize_failure() {
    failure_stage=$1
    original_rc=1
    final_status=FAILED
  }
  if ! rm -f -- "$PHASE_ACTIVE" "$PHASE_ACTIVE.tmp"; then
    mark_finalize_failure active-phase-marker-cleanup
  fi
  if ! end_epoch=$(date +%s); then
    end_epoch=$CAMPAIGN_START
    mark_finalize_failure result-clock
  fi
  elapsed=$((end_epoch - CAMPAIGN_START))
  if [ "$original_rc" -ne 0 ]; then
    final_status=FAILED
    if [ "$failure_stage" = not-completed ]; then failure_stage=$phase; fi
  fi
  if [ "$final_status" = FAILED ] && [ "$original_rc" -eq 0 ]; then original_rc=1; fi

  if [ -n "$cargo_binary" ] && [ -f "$cargo_binary" ] && [ -s "$cargo_binary" ]; then
    if ! command cp -- "$cargo_binary" "$ARTIFACT/cargo" \
      || [ ! -f "$ARTIFACT/cargo" ] || [ ! -s "$ARTIFACT/cargo" ] \
      || ! copied_cargo_sha=$(sha256_file "$ARTIFACT/cargo") \
      || [ "$copied_cargo_sha" != "$cargo_sha" ]; then
      mark_finalize_failure cargo-artifact-copy
    fi
  elif [ "$final_status" = PREREQUISITE_ONLY ]; then
    mark_finalize_failure cargo-artifact-missing
  fi
  local -a evidence_paths=()
  for path in preflight.json setup phase-index helper-cli command-records native-cargo-elf-inspection.json; do
    if [ -e "$ROOT/$path" ]; then evidence_paths+=("$path"); fi
  done
  for path in producer/provision/record producer/build/record producer/overlay/receipt.json smoke control; do
    if [ -e "$ROOT/$path" ]; then evidence_paths+=("$path"); fi
  done
  if [ "${#evidence_paths[@]}" -gt 0 ]; then
    if ! tar -czf "$ARTIFACT/evidence.tar.gz" -C "$ROOT" "${evidence_paths[@]}"; then
      mark_finalize_failure artifact-package
    fi
  else
    mark_finalize_failure artifact-package
  fi

  write_result() {
    if ! end_epoch=$(date +%s); then return 1; fi
    elapsed=$((end_epoch - CAMPAIGN_START))
    jq -n \
      --arg schema ami-rust-native-cargo-workflow-result-v1 \
      --arg status "$final_status" \
      --arg phase "$phase" \
      --arg failure_stage "$failure_stage" \
      --arg repository "$NATIVE_REPOSITORY" \
      --arg ref "$NATIVE_REF_NAME" \
      --arg head "$GITHUB_SHA" \
      --arg source_head "$source_head" \
      --arg triple "$TRIPLE" \
      --arg run_id "$NATIVE_RUN_ID" \
      --arg run_attempt "$NATIVE_RUN_ATTEMPT" \
      --argjson campaign_start_epoch "$CAMPAIGN_START" \
      --argjson ended_epoch "$end_epoch" \
      --argjson elapsed_seconds "$elapsed" \
      --argjson exit_code "$original_rc" \
      --arg cargo_source_commit "$source_commit" \
      --arg cargo_binary_sha256 "$cargo_sha" \
      --arg xtask_sha256 "$xtask_sha" \
      --arg resource_policy_sha256 "$policy_sha" \
      --arg tooling_lock_sha256 "$tooling_lock_sha" \
      '{schema:$schema,status:$status,phase:$phase,failure_stage:$failure_stage,repository:$repository,ref:$ref,head:$head,source_head:$source_head,native_host:$triple,run_id:$run_id,run_attempt:$run_attempt,campaign:{started_epoch:$campaign_start_epoch,ended_epoch:$ended_epoch,elapsed_seconds:$elapsed_seconds,review_reserve_seconds:300},exit_code:$exit_code,cargo_source_commit:$cargo_source_commit,cargo_binary_sha256:$cargo_binary_sha256,xtask_sha256:$xtask_sha256,resource_policy_sha256:$resource_policy_sha256,tooling_lock_sha256:$tooling_lock_sha256,claim:"native Linux host Cargo prerequisite only"}' \
      > "$ARTIFACT/native-cargo-result.tmp" || return 1
    command mv -f -- "$ARTIFACT/native-cargo-result.tmp" "$ARTIFACT/native-cargo-result.json" || return 1
  }
  if ! write_result; then
    mark_finalize_failure result-serialization
    if ! write_result; then echo "typed result serialization failed" >&2; fi
  fi

  write_artifact_size() {
    local measured_bytes stable=false iteration
    payload_bytes=0
    for ((iteration = 0; iteration < 8; iteration++)); do
      jq -n \
        --arg schema ami-rust-native-cargo-artifact-size-v1 \
        --argjson payload_bytes "$payload_bytes" \
        --argjson payload_limit_bytes "$ARTIFACT_PAYLOAD_MAX" \
        --arg framing_reserve "1 MiB" \
        '{schema:$schema,payload_bytes:$payload_bytes,payload_limit_bytes:$payload_limit_bytes,upload_framing_reserve:$framing_reserve}' \
        > "$ARTIFACT/artifact-size.json" || return 1
      measured_bytes=$(find "$ARTIFACT" -type f -printf '%s\n' | awk '{sum += $1} END {printf "%.0f\n", sum}') || return 1
      case "$measured_bytes" in ''|*[!0-9]*) return 1 ;; esac
      if [ "$measured_bytes" -eq "$payload_bytes" ]; then stable=true; break; fi
      payload_bytes=$measured_bytes
    done
    [ "$stable" = true ]
  }

  if ! write_artifact_size; then
    failure_stage=artifact-size-accounting
    original_rc=1
    final_status=FAILED
    if ! write_result; then echo "failed typed result serialization after artifact-size refusal" >&2; fi
    if ! write_artifact_size; then
      echo "artifact size receipt could not stabilize after failure" >&2
    fi
  fi
  if [ "$payload_bytes" -gt "$ARTIFACT_PAYLOAD_MAX" ]; then
    mark_finalize_failure artifact-size
    if ! write_result; then echo "failed typed result serialization after artifact-size refusal" >&2; fi
    if ! write_artifact_size; then
      echo "artifact size receipt could not restabilize after limit refusal" >&2
    fi
  fi
  exit "$original_rc"
}
trap finalize EXIT

phase=identity
failure_stage=identity
test "$GITHUB_REPOSITORY" = "$NATIVE_REPOSITORY"
test "$GITHUB_REF" = "$NATIVE_REF_NAME"
test -n "$GITHUB_SHA"
test "$NATIVE_REF_PROTECTED" = true
source_head=$(git -C "$REPO" rev-parse HEAD)
test "$source_head" = "$GITHUB_SHA"
test -z "$(git -C "$REPO" status --porcelain --untracked-files=all)"
test "$(uname -s)" = Linux
case "$TRIPLE:$(uname -m)" in
  x86_64-unknown-linux-gnu:x86_64|aarch64-unknown-linux-gnu:aarch64) ;;
  *) echo "runner architecture does not match the native producer host" >&2; exit 1 ;;
esac

case "$TRIPLE" in
  x86_64-unknown-linux-gnu)
    bootstrap_pins="$REPO/release/ci-bootstrap-inputs.json"
    expected_bootstrap_sha=5c3557a2696457d76562f8883efa2c7d2c4cfc583f4f5814a722907a1f639f81
    ;;
  aarch64-unknown-linux-gnu)
    bootstrap_pins="$REPO/release/ci-bootstrap-linux-aarch64-inputs.json"
    expected_bootstrap_sha=60d8bab5bd3cc043e47b0cff2fc62e38285f2fa85be8fd5f7ce376a3623384d7
    ;;
  *) echo "unsupported native host" >&2; exit 1 ;;
esac

phase=input-binding
failure_stage=inputs
require_sha "$bootstrap_pins" "$expected_bootstrap_sha"
require_sha "$REPO/tools/bootstrap-host-rust.sh" dfa41aa97181d7b2516e8f4b42b18793a2f35cdba969dd430be269adcf1754a3
require_sha "$REPO/tooling/Cargo.toml" 13ac0ca9ac4437c7ac77b066b5a044ea30f935ffef0446dad7146132eda12a3f
require_sha "$REPO/tooling/Cargo.lock" 9268b294c6d697a3914b735f775a0c2b0543e775de3f6bf10b2f964baf5de6cd
require_sha "$REPO/release/ci-resources.json" "$RESOURCE_POLICY_SHA"
require_sha "$REPO/host/cargo-repro/three-host-v2/source.json" 73c9fc79976541cb43cefb39ce878218a3245493e86bb37fac449ec3bee00a52
require_sha "$REPO/host/cargo-repro/three-host-v2/cargo-metadata.patch" "$SOURCE_PATCH_SHA"
require_sha "$REPO/host/cargo-repro/three-host-v2/openssl-overlay.json" 676f1c208fe63f57014120f7461383a9f1da351565a5ea8b9dfe8a2dd109e944
require_sha "$REPO/host/cargo-repro/three-host-v2/openssl-paths.patch" 0bc0e316c16658c7be01baa8d14070efebbe0b115a26224b2ae75ac12667069e
policy_sha=$(sha256_file "$REPO/release/ci-resources.json")
tooling_lock_sha=$(sha256_file "$REPO/tooling/Cargo.lock")
command cp -- "$bootstrap_pins" "$SETUP/bootstrap-pins.json"
command cp -- "$REPO/release/ci-resources.json" "$SETUP/ci-resources.json"
jq -n \
  --arg schema ami-rust-native-cargo-setup-bindings-v1 \
  --arg repository "$NATIVE_REPOSITORY" \
  --arg ref "$NATIVE_REF_NAME" \
  --arg head "$GITHUB_SHA" \
  --arg source_head "$source_head" \
  --arg triple "$TRIPLE" \
  --arg bootstrap_pins_sha256 "$expected_bootstrap_sha" \
  --arg bootstrap_script_sha256 dfa41aa97181d7b2516e8f4b42b18793a2f35cdba969dd430be269adcf1754a3 \
  --arg tooling_manifest_sha256 13ac0ca9ac4437c7ac77b066b5a044ea30f935ffef0446dad7146132eda12a3f \
  --arg tooling_lock_sha256 "$tooling_lock_sha" \
  --arg resource_policy_sha256 "$policy_sha" \
  --arg recipe_source_sha256 73c9fc79976541cb43cefb39ce878218a3245493e86bb37fac449ec3bee00a52 \
  --arg cargo_source_patch_sha256 "$SOURCE_PATCH_SHA" \
  --arg overlay_pin_sha256 676f1c208fe63f57014120f7461383a9f1da351565a5ea8b9dfe8a2dd109e944 \
  --arg overlay_patch_sha256 0bc0e316c16658c7be01baa8d14070efebbe0b115a26224b2ae75ac12667069e \
  --arg workflow_sha256 "$(sha256_file "$REPO/.github/workflows/cargo-native-prerequisite.yml")" \
  '{schema:$schema,repository:$repository,ref:$ref,head:$head,source_head:$source_head,native_host:$triple,bootstrap_pins_sha256:$bootstrap_pins_sha256,bootstrap_script_sha256:$bootstrap_script_sha256,tooling_manifest_sha256:$tooling_manifest_sha256,tooling_lock_sha256:$tooling_lock_sha256,resource_policy_sha256:$resource_policy_sha256,recipe_source_sha256:$recipe_source_sha256,cargo_source_patch_sha256:$cargo_source_patch_sha256,overlay_pin_sha256:$overlay_pin_sha256,overlay_patch_sha256:$overlay_patch_sha256,workflow_sha256:$workflow_sha256}' \
  > "$SETUP/input-bindings.json"

jq -n \
  --arg schema ami-rust-native-cargo-measurement-gap-v1 \
  --arg classification UNQUALIFIED_EXTERNAL_SETUP \
  --arg detail "The outer temporary Python supervisor measures bootstrap, tooling cargo vendor, xtask build, the full Bash producer and raw logs. GitHub checkout/upload and final wrapper serialization remain outside observation; no no-Python descendant observer is provided." \
  '{schema:$schema,classification:$classification,managed_bytes_before:null,managed_bytes_after:null,detail:$detail,no_python_execution_proof:false}' \
  > "$SETUP/measurement-gap.json"

phase=bootstrap
failure_stage=bootstrap
bootstrap_budget=$(campaign_budget)
if (( bootstrap_budget > MAX_SECONDS )); then bootstrap_budget=$MAX_SECONDS; fi
setup_run bootstrap "$bootstrap_budget" bash "$REPO/tools/bootstrap-host-rust.sh" "$BOOTSTRAP" "$TRIPLE"
for component in rustc cargo rust-std; do
  archive="$BOOTSTRAP/downloads/$component-1.98.1-$TRIPLE.tar.xz"
  expected_sha=$(jq -er --arg triple "$TRIPLE" --arg component "$component" \
    '.rust.components[$triple][$component].sha256' "$bootstrap_pins")
  expected_bytes=$(jq -er --arg triple "$TRIPLE" --arg component "$component" \
    '.rust.components[$triple][$component].http_content_length' "$bootstrap_pins")
  actual_sha=$(sha256_file "$archive")
  actual_bytes=$(wc -c < "$archive" | tr -d ' ')
  test "$actual_sha" = "$expected_sha"
  test "$actual_bytes" = "$expected_bytes"
  printf '%s\t%s\t%s\n' "$component" "$actual_bytes" "$actual_sha" >> "$SETUP/bootstrap-archive-identities.tsv"
done
"$BOOTSTRAP/toolchain/bin/rustc" -Vv > "$SETUP/rustc-vv.txt"
"$BOOTSTRAP/toolchain/bin/cargo" -Vv > "$SETUP/cargo-vv.txt"
grep -Fqx "release: 1.98.1" "$SETUP/rustc-vv.txt"
grep -Fqx "commit-hash: $RUSTC_COMMIT" "$SETUP/rustc-vv.txt"
grep -Fqx "host: $TRIPLE" "$SETUP/rustc-vv.txt"
grep -Fqx "commit-hash: $CARGO_COMMIT" "$SETUP/cargo-vv.txt"
grep -Fqx "host: $TRIPLE" "$SETUP/cargo-vv.txt"

phase=tooling-vendor
failure_stage=tooling-vendor
setup_before=$(du -sb "$REPO" "$ROOT" | awk '{sum += $1} END {printf "%.0f\n",sum}')
vendor_budget=$(campaign_budget)
if (( vendor_budget > MAX_SECONDS )); then vendor_budget=$MAX_SECONDS; fi
setup_run tooling-cargo-vendor "$vendor_budget" "$BOOTSTRAP/toolchain/bin/cargo" \
  vendor --locked --versioned-dirs --manifest-path "$REPO/tooling/Cargo.toml" "$TOOLING_VENDOR"
test -d "$TOOLING_VENDOR"
jq -nr --arg directory "$TOOLING_VENDOR" \
  '"[source.crates-io]\nreplace-with = \"vendored-sources\"\n[source.vendored-sources]\ndirectory = \($directory | @json)\n"' \
  > "$TOOLING_HOME/config.toml"
find "$TOOLING_VENDOR" -type f -name .cargo-checksum.json -print0 \
  | sort -z \
  | xargs -0 -r sha256sum > "$SETUP/tooling-vendor-index.sha256"
vendor_count=$(wc -l < "$SETUP/tooling-vendor-index.sha256" | tr -d ' ')
test "$vendor_count" -eq 29
setup_after=$(du -sb "$REPO" "$ROOT" | awk '{sum += $1} END {printf "%.0f\n",sum}')
jq -n \
  --arg schema ami-rust-native-cargo-measurement-gap-v1 \
  --arg classification UNQUALIFIED_EXTERNAL_SETUP \
  --argjson managed_bytes_before "$setup_before" \
  --argjson managed_bytes_after "$setup_after" \
  --arg detail "Whole producer-process measurement is supplied by the temporary outer adapter. GitHub checkout/upload and final wrapper serialization remain outside observation; this record is not complete RC4 or Python-retirement evidence." \
  '{schema:$schema,classification:$classification,managed_bytes_before:$managed_bytes_before,managed_bytes_after:$managed_bytes_after,detail:$detail,no_python_execution_proof:false}' \
  > "$SETUP/measurement-gap.json"

phase=xtask-build
failure_stage=xtask-build
build_budget=$(campaign_budget)
if (( build_budget > MAX_SECONDS )); then build_budget=$MAX_SECONDS; fi
setup_run tooling-xtask-build "$build_budget" "$BOOTSTRAP/toolchain/bin/cargo" \
  build --locked --offline --manifest-path "$REPO/tooling/Cargo.toml" --package ami-rust-xtask
xtask_binary="$TOOLING_TARGET/debug/ami-rust-xtask"
test -x "$xtask_binary"
xtask_sha=$(sha256_file "$xtask_binary")
printf '%s  %s\n' "$xtask_sha" "$xtask_binary" > "$SETUP/xtask-binary.sha256"

mkdir -m 700 "$ROOT/home" "$ROOT/tmp"
export XTASK="$xtask_binary"
environment_json=$(driver_env)
phase=qualification-command-component-test
failure_stage=$phase
run_q qualification-command-component-test "$BOOTSTRAP/toolchain/bin/cargo" "$REPO/tooling" "$environment_json" \
  test --locked --offline -p ami-rust-core qualification_command -- --test-threads=1
test -s "$LAST_RECORD/stdout.raw.gz"
if ! gzip -cd "$LAST_RECORD/stdout.raw.gz" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
  echo "helper test filter ran no matching tests or failed" >&2
  exit 1
fi
jq -e \
  '.passed == true and .own_ru_maxrss_raw != null and
   .own_peak_rss_bytes != null and .aggregate_peak_rss_bytes != null and
   .own_ru_maxrss_unit != null and .own_rss_boundary != null' \
  "$LAST_RECORD/result.json" >/dev/null

phase=qualification-command-child-exit-seven
failure_stage=$phase
child_exit_script="$ROOT/control/child-exit-seven.sh"
cat > "$child_exit_script" <<'CHILD'
printf '%s\n' 'ami-rust-command-child-exit7-stdout-v1'
printf '%s\n' 'ami-rust-command-child-exit7-stderr-v1' >&2
exit 7
CHILD
chmod 700 "$child_exit_script"
if run_q actual-linux-cli-child-exit-seven /bin/sh "$ROOT/control" "$environment_json" "$child_exit_script"; then
  echo "helper CLI unexpectedly accepted child exit status 7" >&2
  exit 1
else
  child_exit_rc=$?
  child_exit_record=$LAST_RECORD
fi
test "$child_exit_rc" -eq 7
jq -e --arg request_sha256 "$LAST_REQUEST_SHA" \
  '.schema == "ami-rust-native-command-qualification-record-v1" and
   .request_sha256 == $request_sha256 and .passed == false and
   .capture_complete == true and .capture_error == null and
   .child_exit_code == 7 and .child_signal == null' \
  "$child_exit_record/result.json" >/dev/null
expect_stdout_line actual-linux-cli-child-exit-seven \
  ami-rust-command-child-exit7-stdout-v1 "$child_exit_record"
grep -Fqx -- ami-rust-command-child-exit7-stderr-v1 \
  <(gzip -cd "$child_exit_record/stderr.raw.gz")
child_exit_index="$PHASE_INDEX/$(printf '%03d' "$sequence")-actual-linux-cli-child-exit-seven.json"
jq -e --arg request_sha256 "$LAST_REQUEST_SHA" \
  --arg record "$child_exit_record/result.json" \
  '.phase == "actual-linux-cli-child-exit-seven" and
   .request_sha256 == $request_sha256 and .record == $record' \
  "$child_exit_index" >/dev/null

phase=upstream-cargo-checkout
failure_stage=$phase
git_environment=$(driver_env)
run_q cargo-source-init /usr/bin/git "$ROOT" "$git_environment" init --quiet "$UPSTREAM"
run_q cargo-source-origin /usr/bin/git "$UPSTREAM" "$git_environment" \
  remote add origin https://github.com/rust-lang/cargo.git
run_q cargo-source-fetch /usr/bin/git "$UPSTREAM" "$git_environment" \
  fetch --quiet --depth=1 origin "$CARGO_SOURCE_COMMIT"
run_q cargo-source-checkout /usr/bin/git "$UPSTREAM" "$git_environment" \
  checkout --quiet --detach FETCH_HEAD
run_q cargo-source-head /usr/bin/git "$UPSTREAM" "$git_environment" rev-parse HEAD
source_commit=$(gzip -cd "$LAST_RECORD/stdout.raw.gz" | tr -d '\r\n')
test "$source_commit" = "$CARGO_SOURCE_COMMIT"

phase=source-patch-apply
failure_stage=$phase
run_q cargo-source-original-hashes /usr/bin/sha256sum "$UPSTREAM" "$git_environment" \
  src/compiler/build_runner/compilation_files.rs src/workspace/features.rs
mapfile -t original_hashes < <(gzip -cd "$LAST_RECORD/stdout.raw.gz" | awk '{print $1}')
test "${#original_hashes[@]}" -eq 2
test "${original_hashes[0]}" = 275e1ff7e6512bbbb3b30a7f0ceb9c7d455745e6aafce0484cb73d8fe31e0e67
test "${original_hashes[1]}" = 2747b5598654963df7d9270b07fc7dbd80a700cf219b26db71b0d2291ea74638
run_q cargo-source-apply-check /usr/bin/git "$UPSTREAM" "$git_environment" \
  apply --check "$REPO/host/cargo-repro/three-host-v2/cargo-metadata.patch"
run_q cargo-source-apply /usr/bin/git "$UPSTREAM" "$git_environment" \
  apply "$REPO/host/cargo-repro/three-host-v2/cargo-metadata.patch"
run_q cargo-source-changed-paths /usr/bin/git "$UPSTREAM" "$git_environment" \
  diff --name-only --no-renames
mapfile -t changed_paths < <(gzip -cd "$LAST_RECORD/stdout.raw.gz")
test "${#changed_paths[@]}" -eq 2
test "${changed_paths[0]}" = src/compiler/build_runner/compilation_files.rs
test "${changed_paths[1]}" = src/workspace/features.rs
run_q cargo-source-patched-hashes /usr/bin/sha256sum "$UPSTREAM" "$git_environment" \
  src/compiler/build_runner/compilation_files.rs src/workspace/features.rs
mapfile -t patched_hashes < <(gzip -cd "$LAST_RECORD/stdout.raw.gz" | awk '{print $1}')
test "${#patched_hashes[@]}" -eq 2
test "${patched_hashes[0]}" = b572e74e742cca08765540aa9f611b1877defc08d146cff52fcd9b0c039106db
test "${patched_hashes[1]}" = 0db8ba62877729fdee23ee8ae26f11a7b79fdd8bf086845a53c5f097eb1eacc3

phase=producer-provision
failure_stage=$phase
mkdir -p "$PRODUCER/provision"
provision_work="$PRODUCER/provision/work"
provision_vendor="$PRODUCER/provision/vendor"
provision_record="$PRODUCER/provision/record"
run_q producer-provision "$xtask_binary" "$UPSTREAM" "$environment_json" \
  cargo-repro-producer provision \
  --source "$UPSTREAM" --host-rust "$BOOTSTRAP/toolchain" \
  --work "$provision_work" --vendor "$provision_vendor" --record "$provision_record" \
  --recipe "$REPO/host/cargo-repro/three-host-v2" \
  --resource-policy "$REPO/release/ci-resources.json" --profile release
test -f "$provision_record/inputs.json"
test -f "$provision_record/result.json"
test -f "$provision_record/stdout.log"
test -f "$provision_record/stderr.log"
test -d "$provision_vendor"
compress_streams "$provision_record"

phase=overlay-prepare
failure_stage=$phase
mkdir -p "$PRODUCER/overlay"
overlay_vendor="$PRODUCER/overlay/vendor"
overlay_receipt="$PRODUCER/overlay/receipt.json"
run_q overlay-prepare "$xtask_binary" "$UPSTREAM" "$environment_json" \
  cargo-vendor-overlay prepare \
  --source-vendor "$provision_vendor" --output-vendor "$overlay_vendor" \
  --receipt "$overlay_receipt" --recipe "$REPO/host/cargo-repro/three-host-v2"
test -f "$overlay_receipt"
phase=overlay-verify
failure_stage=$phase
run_q overlay-verify "$xtask_binary" "$UPSTREAM" "$environment_json" \
  cargo-vendor-overlay verify \
  --vendor "$overlay_vendor" --receipt "$overlay_receipt" \
  --recipe "$REPO/host/cargo-repro/three-host-v2"

phase=overlay-receipt-corruption-control
failure_stage=$phase
original_overlay_receipt_sha=$(sha256_file "$overlay_receipt")
corrupt_receipt="$ROOT/control/corrupted-overlay-receipt.json"
jq '.overlay_pin_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$overlay_receipt" > "$corrupt_receipt"
test "$(sha256_file "$corrupt_receipt")" != "$original_overlay_receipt_sha"
if run_q expected-corrupted-overlay-receipt-rejection "$xtask_binary" "$UPSTREAM" "$environment_json" \
  cargo-vendor-overlay verify \
  --vendor "$overlay_vendor" --receipt "$corrupt_receipt" \
  --recipe "$REPO/host/cargo-repro/three-host-v2"; then
  echo "corrupted overlay receipt was unexpectedly accepted" >&2
  exit 1
else
  corrupted_receipt_rc=$?
  corrupted_receipt_record=$LAST_RECORD
fi
test "$corrupted_receipt_rc" -ne 0
jq -e --argjson rc "$corrupted_receipt_rc" \
  '.passed == false and .capture_complete == true and
   .child_exit_code == $rc and .child_signal == null' \
  "$corrupted_receipt_record/result.json" >/dev/null
if ! grep -Fq 'vendor overlay receipt identity mismatch' \
  <(gzip -cd "$corrupted_receipt_record/stderr.raw.gz"); then
  echo "corrupted overlay receipt failed for an unexpected reason" >&2
  exit 1
fi
test "$(sha256_file "$overlay_receipt")" = "$original_overlay_receipt_sha"
test -d "$overlay_vendor"
jq -n \
  --arg schema ami-rust-native-cargo-failure-control-v1 \
  --arg status EXPECTED_RECEIPT_REJECTION \
  --arg host "$TRIPLE" \
  --arg helper_result "$corrupted_receipt_record/result.json" \
  --arg mutated_copy "$corrupt_receipt" \
  --arg original_receipt_sha256 "$original_overlay_receipt_sha" \
  '{schema:$schema,status:$status,native_host:$host,helper_result:$helper_result,mutated_copy:$mutated_copy,original_receipt_sha256:$original_receipt_sha256,producer_receipt_unchanged:true,overlay_vendor_preserved:true}' \
  > "$ROOT/control/corrupted-receipt-control.json"

phase=producer-build
failure_stage=$phase
mkdir -p "$PRODUCER/build"
build_work="$PRODUCER/build/work"
build_record="$PRODUCER/build/record"
run_q producer-build "$xtask_binary" "$UPSTREAM" "$environment_json" \
  cargo-repro-producer build \
  --source "$UPSTREAM" --host-rust "$BOOTSTRAP/toolchain" \
  --work "$build_work" --vendor "$overlay_vendor" --record "$build_record" \
  --recipe "$REPO/host/cargo-repro/three-host-v2" \
  --resource-policy "$REPO/release/ci-resources.json" \
  --vendor-overlay-receipt "$overlay_receipt" --profile release
test -f "$build_record/inputs.json"
test -f "$build_record/result.json"
test -f "$build_record/stdout.log"
test -f "$build_record/stderr.log"
test -d "$overlay_vendor"
cargo_binary="$build_work/target/release/cargo"
test -x "$cargo_binary"
cargo_sha=$(sha256_file "$cargo_binary")
producer_cargo_sha=$(jq -er '.artifact.sha256' "$build_record/result.json")
test "$cargo_sha" = "$producer_cargo_sha"
printf '%s  %s\n' "$cargo_sha" "$cargo_binary" > "$SETUP/native-cargo-binary.sha256"
compress_streams "$build_record"

phase=native-cargo-version
failure_stage=$phase
run_q native-cargo-version "$cargo_binary" "$UPSTREAM" "$environment_json" -Vv
case "$TRIPLE" in
  x86_64-unknown-linux-gnu) cargo_host_line="host: x86_64-unknown-linux-gnu" ;;
  aarch64-unknown-linux-gnu) cargo_host_line="host: aarch64-unknown-linux-gnu" ;;
esac
expect_stdout_line native-cargo-version "$cargo_host_line" "$LAST_RECORD"
expect_stdout_line native-cargo-version "commit-hash: $CARGO_SOURCE_COMMIT" "$LAST_RECORD"

phase=native-cargo-elf-header
failure_stage=$phase
run_q native-cargo-elf-header /usr/bin/readelf "$UPSTREAM" "$environment_json" -h "$cargo_binary"
header_record=$LAST_RECORD
case "$TRIPLE" in
  x86_64-unknown-linux-gnu) expected_machine='Advanced Micro Devices X86-64' ;;
  aarch64-unknown-linux-gnu) expected_machine='AArch64' ;;
esac
if ! grep -E "Machine:[[:space:]]*$expected_machine" <(gzip -cd "$header_record/stdout.raw.gz") >/dev/null; then
  echo "native Cargo ELF machine does not match the runner" >&2
  exit 1
fi

phase=native-cargo-elf-program-headers
failure_stage=$phase
run_q native-cargo-elf-program-headers /usr/bin/readelf "$UPSTREAM" "$environment_json" -l "$cargo_binary"
program_headers_record=$LAST_RECORD
run_q native-cargo-elf-dynamic-dependencies /usr/bin/readelf "$UPSTREAM" "$environment_json" -d "$cargo_binary"
dynamic_dependencies_record=$LAST_RECORD
interpreter=$(gzip -cd "$program_headers_record/stdout.raw.gz" \
  | sed -n 's/.*Requesting program interpreter: \(.*\)]/\1/p')
if [ -n "$interpreter" ]; then
  test "$(printf '%s\n' "$interpreter" | wc -l | tr -d ' ')" -eq 1
  case "$TRIPLE:$interpreter" in
    x86_64-unknown-linux-gnu:/lib64/ld-linux-x86-64.so.2|x86_64-unknown-linux-gnu:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2|aarch64-unknown-linux-gnu:/lib/ld-linux-aarch64.so.1|aarch64-unknown-linux-gnu:/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1) ;;
    *) echo "unexpected native Cargo ELF interpreter: $interpreter" >&2; exit 1 ;;
  esac
  test -x "$interpreter"
  phase=native-cargo-runtime-dependencies
  failure_stage=$phase
  run_q native-cargo-runtime-dependencies /usr/bin/ldd "$UPSTREAM" "$environment_json" "$cargo_binary"
  runtime_dependencies_record=$LAST_RECORD
  if grep -Fq 'not found' <(gzip -cd "$LAST_RECORD/stdout.raw.gz"); then
    echo "native Cargo has an unresolved ELF dependency" >&2
    exit 1
  fi
else
  if grep -Eq '\(NEEDED\)' <(gzip -cd "$LAST_RECORD/stdout.raw.gz"); then
    echo "ELF has dynamic dependencies but no recorded interpreter" >&2
    exit 1
  fi
  runtime_dependencies_record=
fi
jq -n \
  --arg schema ami-rust-native-cargo-elf-inspection-v1 \
  --arg status PASS \
  --arg host "$TRIPLE" \
  --arg interpreter "$interpreter" \
  --arg header_record "$header_record/result.json" \
  --arg program_headers_record "$program_headers_record/result.json" \
  --arg dynamic_dependencies_record "$dynamic_dependencies_record/result.json" \
  --arg runtime_dependencies_record "$runtime_dependencies_record" \
  '{schema:$schema,status:$status,host:$host,interpreter:(if $interpreter == "" then null else $interpreter end),header_record:$header_record,program_headers_record:$program_headers_record,dynamic_dependencies_record:$dynamic_dependencies_record,runtime_dependencies_record:(if $runtime_dependencies_record == "" then null else ($runtime_dependencies_record + "/result.json") end)}' \
  > "$ROOT/native-cargo-elf-inspection.json"

phase=standalone-offline-smoke
failure_stage=$phase
smoke="$ROOT/smoke/standalone-host-crate"
mkdir -p "$smoke/src" "$smoke/home/cargo" "$smoke/tmp" "$smoke/target"
cat > "$smoke/Cargo.toml" <<'TOML'
[package]
name = "native-cargo-smoke"
version = "0.1.0"
edition = "2024"

[dependencies]
TOML
cat > "$smoke/Cargo.lock" <<'LOCK'
version = 4

[[package]]
name = "native-cargo-smoke"
version = "0.1.0"
LOCK
cat > "$smoke/src/main.rs" <<'RS'
fn main() {
    println!("ami-rust-native-cargo-smoke-v1");
}
RS
smoke_env=$(jq -cn \
  --arg path "$BOOTSTRAP/toolchain/bin:/usr/bin:/bin" \
  --arg home "$smoke/home" \
  --arg tmp "$smoke/tmp" \
  --arg cargo_home "$smoke/home/cargo" \
  --arg target "$smoke/target" \
  --arg rustc "$BOOTSTRAP/toolchain/bin/rustc" \
  --arg rustdoc "$BOOTSTRAP/toolchain/bin/rustdoc" \
  '{
    PATH:$path,HOME:$home,TMPDIR:$tmp,CARGO_HOME:$cargo_home,
    CARGO_TARGET_DIR:$target,RUSTC:$rustc,RUSTDOC:$rustdoc,
    CARGO_NET_OFFLINE:"true",CARGO_BUILD_JOBS:"2",
    CARGO_INCREMENTAL:"0",CARGO_PROFILE_DEV_DEBUG:"0",
    CARGO_PROFILE_DEV_INCREMENTAL:"false",LC_ALL:"C",TZ:"UTC",
    SOURCE_DATE_EPOCH:"1791936000"
  }')
run_q standalone-offline-cargo-build "$cargo_binary" "$smoke" "$smoke_env" \
  build --locked --offline --manifest-path "$smoke/Cargo.toml"
smoke_binary="$smoke/target/debug/native-cargo-smoke"
test -x "$smoke_binary"
run_q standalone-offline-cargo-execute "$smoke_binary" "$smoke" "$smoke_env"
expect_stdout_line standalone-offline-cargo-execute ami-rust-native-cargo-smoke-v1 "$LAST_RECORD"
jq -n \
  --arg schema ami-rust-native-cargo-smoke-result-v1 \
  --arg status PASS \
  --arg host "$TRIPLE" \
  --arg cargo_sha256 "$cargo_sha" \
  --arg smoke_binary_sha256 "$(sha256_file "$smoke_binary")" \
  --arg expected_output ami-rust-native-cargo-smoke-v1 \
  --arg execution_record "$LAST_RECORD/result.json" \
  '{schema:$schema,status:$status,host:$host,cargo_sha256:$cargo_sha256,smoke_binary_sha256:$smoke_binary_sha256,expected_output:$expected_output,execution_record:$execution_record}' \
  > "$ROOT/smoke/result.json"

phase=wrong-host-failure-control
failure_stage=$phase
fake_host_rust="$ROOT/control/fake-host-rust"
mkdir -p "$fake_host_rust/bin"
cat > "$fake_host_rust/bin/rustc" <<'RUSTC'
#!/bin/sh
if [ "$#" -ne 1 ] || [ "$1" != -Vv ]; then
  exit 64
fi
printf '%s\n' \
  'rustc 1.98.1 (pinned-fake-host-control)' \
  'binary: rustc' \
  'commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985' \
  'commit-date: 2026-09-03' \
  'host: i686-unknown-linux-gnu' \
  'release: 1.98.1' \
  'LLVM version: 21.1.0'
RUSTC
chmod 700 "$fake_host_rust/bin/rustc"
fake_work="$ROOT/control/rejected-work"
fake_vendor="$ROOT/control/rejected-vendor"
fake_producer_record="$ROOT/control/rejected-producer-record"
test ! -e "$fake_work"
test ! -e "$fake_vendor"
test ! -e "$fake_producer_record"
if run_q expected-wrong-host-rejection "$xtask_binary" "$UPSTREAM" "$environment_json" \
  cargo-repro-producer provision \
  --source "$UPSTREAM" --host-rust "$fake_host_rust" \
  --work "$fake_work" --vendor "$fake_vendor" --record "$fake_producer_record" \
  --recipe "$REPO/host/cargo-repro/three-host-v2" \
  --resource-policy "$REPO/release/ci-resources.json" --profile release; then
  echo "wrong-host fake compiler was unexpectedly accepted" >&2
  exit 1
else
  expected_reject_rc=$?
  expected_reject_record=$LAST_RECORD
fi
test "$expected_reject_rc" -eq 2
jq -e \
  '.passed == false and .child_exit_code == 2 and .child_signal == null and
   .capture_complete == true and .refusal == "child exited with status 2"' \
  "$expected_reject_record/result.json" >/dev/null
if ! gzip -cd "$expected_reject_record/stderr.raw.gz" \
  | grep -Fq 'host rustc target does not match the native producer host'; then
  echo "wrong-host control failed for an unexpected reason" >&2
  exit 1
fi
test ! -e "$fake_work"
test ! -e "$fake_vendor"
test ! -e "$fake_producer_record"
jq -n \
  --arg schema ami-rust-native-cargo-failure-control-v1 \
  --arg status EXPECTED_REJECTION_BEFORE_OUTPUTS \
  --arg host "$TRIPLE" \
  --arg helper_result "$expected_reject_record/result.json" \
  --arg reason "fake rustc reports the pinned release and commit but an i686 host" \
  '{schema:$schema,status:$status,native_host:$host,helper_result:$helper_result,reason:$reason,producer_work_absent:true,vendor_absent:true,producer_record_absent:true}' \
  > "$ROOT/control/wrong-host-control.json"

phase=complete
failure_stage=none
final_status=PREREQUISITE_ONLY
exit 0

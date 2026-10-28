#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Check local free-space headroom before a build, download or recovery operation.
set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 1; }

reserve=0
if [[ $# -gt 0 ]]; then
  [[ $# == 2 && $1 == --reserve-bytes ]] || fail 'usage: check-local-capacity.sh [--reserve-bytes NONNEGATIVE_INTEGER]'
  reserve=$2
fi
[[ $reserve =~ ^[0-9]+$ ]] || fail 'reserve bytes must be a nonnegative integer'

source_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
policy="$source_root/release/ci-resources.json"
minimum=$(jq -er '
  .local_storage
  | select(
      .schema == "ami-rust-local-storage-v2" and
      .mode == "free-space-headroom" and
      (.minimum_free_bytes | type) == "number" and
      .minimum_free_bytes > 0 and
      .per_file_quotas == false and
      .fixed_archive_quota_bytes == null and
      .preserve_existing_evidence == true
    )
  | .minimum_free_bytes
' "$policy") || fail 'invalid local free-space policy'

required=$((minimum + reserve))
[[ $required -ge $minimum ]] || fail 'required free-space size overflow'

device_id() {
  case $(uname -s) in
    Darwin) stat -f '%d' "$1" ;;
    Linux) stat -c '%d' "$1" ;;
    *) fail 'local capacity check supports macOS and Linux only' ;;
  esac
}

free_bytes() {
  local blocks
  blocks=$(LC_ALL=C df -Pk "$1" | awk 'NR > 1 { value=$4 } END { if (value ~ /^[0-9]+$/) print value; else exit 1 }') \
    || fail "could not determine free space for $1"
  printf '%s\n' "$((blocks * 1024))"
}

paths=("$source_root")
ancestor=$source_root
while [[ $ancestor != / ]]; do
  if [[ -d "$ancestor/AROS-M0-Backups" ]]; then
    paths+=("$(cd -P -- "$ancestor/AROS-M0-Backups" && pwd -P)")
    break
  fi
  ancestor=${ancestor%/*}
  [[ -n $ancestor ]] || ancestor=/
done

devices=()
volumes='[]'
for path in "${paths[@]}"; do
  device=$(device_id "$path")
  duplicate=false
  for seen in "${devices[@]}"; do
    [[ $seen == "$device" ]] && duplicate=true
  done
  $duplicate && continue
  devices+=("$device")

  free=$(free_bytes "$path")
  [[ $free -ge $required ]] \
    || fail "insufficient free disk space for the operation and local headroom: $path"
  volumes=$(jq -cn \
    --argjson current "$volumes" \
    --arg path "$path" \
    --argjson free "$free" \
    --argjson reserve "$reserve" \
    '$current + [{path:$path,free_bytes:$free,planned_additional_peak_bytes:$reserve,free_after_planned_peak_bytes:($free-$reserve)}]')
done

jq -cn \
  --argjson minimum "$minimum" \
  --argjson volumes "$volumes" \
  '{schema:"ami-rust-local-disk-capacity-v2",minimum_free_bytes:$minimum,volumes:$volumes,per_file_quotas:false,fixed_archive_quota_bytes:null}'

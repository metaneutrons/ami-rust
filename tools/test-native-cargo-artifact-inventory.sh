#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Offline controls for the actual hosted artifact-capacity parser.
set -euo pipefail
root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
filter="$root/tools/native-cargo-artifact-inventory.jq"
accepted=0
rejected=0
accept() {
  local actual
  actual=$(jq -ec -f "$filter" <<<"$1")
  test "$(jq -r 'map(.size_in_bytes) | add // 0' <<<"$actual")" = "$2"
  accepted=$((accepted + 1))
}
reject() {
  if jq -ec -f "$filter" <<<"$1" >/dev/null 2>&1; then
    echo 'invalid artifact inventory was accepted' >&2
    exit 1
  fi
  rejected=$((rejected + 1))
}
row='{"id":1,"name":"native-artifact","expired":false,"size_in_bytes":7}'
accept "[{\"artifacts\":[$row]}]" 7
accept '[{"artifacts":[]}]' 0
accept "$(jq -nc --argjson row "$row" '[{artifacts:[$row | .expired=true]}]')" 0
for mutation in 'del(.expired)' 'del(.size_in_bytes)' 'del(.id)' '.size_in_bytes=0.5' '.size_in_bytes="7"' '.size_in_bytes=-1'; do
  reject "$(jq -nc --argjson row "$row" "[{artifacts:[\$row | $mutation]}]")"
done
reject '[{}]'
reject '[]'
reject "[{\"artifacts\":[$row]},{\"artifacts\":[$row]}]"
reject "$(jq -nc --argjson row "$row" '[{artifacts:[($row | .size_in_bytes=9007199254740991),($row | .id=2)]}]')"
printf 'PASS artifact inventory fixtures: %s valid, %s refused\n' "$accepted" "$rejected"

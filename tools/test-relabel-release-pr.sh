#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Tests of tools/relabel-release-pr.sh with a fake gh that records its calls:
# one positive probe and a counter-probe for every refusal and every no-op.
set -euo pipefail

here=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
script="$here/relabel-release-pr.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

# The fake answers from files in $work: release.json, issues.json; every call is logged.
cat > "$work/gh" <<'F'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$*" in
  "api repos/o/r/releases/tags/v"*"--jq .draft")
    [[ -s "$FAKE_DIR/release.json" ]] || exit 1
    jq -r '.draft' "$FAKE_DIR/release.json" ;;
  "api repos/o/r/issues?state=closed&labels=autorelease%3A+pending&per_page=100") cat "$FAKE_DIR/issues.json" ;;
  "api -X POST repos/o/r/issues/"*) echo '[]' ;;
  "api -X DELETE repos/o/r/issues/"*)
    if [[ -n "${FAKE_DELETE_ERROR:-}" ]]; then echo "$FAKE_DELETE_ERROR" >&2; exit 1; fi
    echo '[]' ;;
  *) echo "unexpected call: $*" >&2; exit 99 ;;
esac
F
chmod +x "$work/gh"

# run NAME EXPECTED_EXIT EXPECTED_MUTATIONS VERSION: arrange files first.
run() {
  local name=$1 want_exit=$2 want_mutations=$3 version=$4 got_exit=0 mutations
  : > "$work/log"
  FAKE_DIR=$work FAKE_LOG=$work/log GH=$work/gh GITHUB_REPOSITORY=o/r bash "$script" "$version" > "$work/out" 2>&1 || got_exit=$?
  mutations=$(grep -c -E 'api -X (POST|DELETE)' "$work/log" || true)
  if [[ "$got_exit" == "$want_exit" && "$mutations" == "$want_mutations" ]]; then
    printf 'ok    %s\n' "$name"
  else
    printf 'FAIL  %s: exit %s (want %s), mutations %s (want %s)\n' "$name" "$got_exit" "$want_exit" "$mutations" "$want_mutations"
    sed 's/^/        /' "$work/out"
    failures=$((failures + 1))
  fi
}
issue() { # number title merged(true|false)
  local merged=null; [[ "$3" == true ]] && merged='"2026-11-04T10:00:00Z"'
  printf '{"number":%s,"title":"%s","pull_request":{"merged_at":%s}}' "$1" "$2" "$merged"
}
public='{"draft":false}'

echo "$public" > "$work/release.json"
echo "[$(issue 101 'chore(main): release 0.2.0' true)]" > "$work/issues.json"
run 'marks the one merged proposal of the version' 0 2 0.2.0
grep -q 'issues/101/labels -f labels\[\]=autorelease: tagged' "$work/log" || { echo 'FAIL  adds the tagged label to #101'; failures=$((failures + 1)); }
grep -q 'DELETE repos/o/r/issues/101/labels/autorelease%3A%20pending' "$work/log" || { echo 'FAIL  removes the pending label from #101'; failures=$((failures + 1)); }

FAKE_DELETE_ERROR='gh: Label does not exist (HTTP 404)' run 'the pending label already removed counts as done' 0 2 0.2.0
FAKE_DELETE_ERROR='gh: Resource not accessible by integration (HTTP 403)' run 'counter-probe: any other failure to remove the label is an error' 1 2 0.2.0

echo "[$(issue 33 'chore(main): release 0.1.0' true)]" > "$work/issues.json"
run 'counter-probe: another version is left alone' 0 0 0.2.0

echo "[$(issue 101 'chore(main): release 0.2.0' false)]" > "$work/issues.json"
run 'counter-probe: a closed but unmerged proposal is left alone' 0 0 0.2.0

echo '[]' > "$work/issues.json"
run 'counter-probe: no pending proposal is a no-op, not an error' 0 0 0.2.0

echo "[$(issue 101 'chore(main): release 0.2.0' true),$(issue 102 'chore(main): release 0.2.0' true)]" > "$work/issues.json"
run 'counter-probe: two matching proposals are refused' 1 0 0.2.0

echo "[$(issue 101 'chore(main): release 0.2.0' true)]" > "$work/issues.json"
echo '{"draft":true}' > "$work/release.json"
run 'counter-probe: a draft release is refused' 1 0 0.2.0

: > "$work/release.json"
run 'counter-probe: a missing release is refused' 1 0 0.2.0

echo "$public" > "$work/release.json"
for bad in '' 0.2 v0.2.0 '0.2.0; rm' '../0.2.0' 01.2.0; do
  run "counter-probe: version '$bad' is refused" 1 0 "$bad"
done

if (( failures )); then printf '%s test(s) failed\n' "$failures" >&2; exit 1; fi
echo 'all relabel-release-pr tests passed'

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# After a release is public, mark its merged release proposal as tagged.
#
# release-please refuses to open the next release proposal while a merged
# proposal is still labelled "autorelease: pending". This project tags and
# publishes through the protected release workflow instead of release-please,
# so nothing else would ever move the label.
#
# usage: relabel-release-pr.sh VERSION
# environment: GITHUB_REPOSITORY (owner/name); GH names the gh executable
#              (default: gh); the token needs permission to edit pull requests.
#
# The script acts only on the one merged pull request titled
# "chore(main): release VERSION" that carries the pending label, and only when
# the release v VERSION exists and is public. Finding none is not an error (the
# proposal was already marked, or there never was one); finding more than one,
# or a release that is a draft, is refused without changing anything.
set -euo pipefail

fail() { printf 'relabel-release-pr: %s\n' "$*" >&2; exit 1; }

[[ $# == 1 ]] || fail 'usage: relabel-release-pr.sh VERSION'
version=$1
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail "not a stable version: $version"
repository=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "malformed repository: $repository"
gh=${GH:-gh}
tagged='autorelease: tagged'
title="chore(main): release $version"

draft=$("$gh" api "repos/$repository/releases/tags/v$version" --jq '.draft') || fail "release v$version does not exist"
[[ "$draft" == false ]] || fail "release v$version is still a draft; not marking its proposal as tagged"

candidates=$("$gh" api "repos/$repository/issues?state=closed&labels=autorelease%3A+pending&per_page=100" |
  jq -c --arg title "$title" '[.[] | select(.pull_request.merged_at != null and .title == $title) | .number]')
count=$(jq 'length' <<<"$candidates")
if [[ "$count" == 0 ]]; then
  printf 'relabel-release-pr: no merged proposal "%s" with the pending label; nothing to do\n' "$title"
  exit 0
fi
[[ "$count" == 1 ]] || fail "$count merged proposals match \"$title\" (${candidates}); refusing to guess"
number=$(jq -r '.[0]' <<<"$candidates")
"$gh" api -X POST "repos/$repository/issues/$number/labels" -f "labels[]=$tagged" >/dev/null
# The filtered listing above can lag a moment behind a change, so a repeated run
# may find the label already gone. That is the wanted end state, not a failure.
if ! removal=$("$gh" api -X DELETE "repos/$repository/issues/$number/labels/autorelease%3A%20pending" 2>&1); then
  [[ "$removal" == *'Label does not exist'* ]] || fail "could not remove the pending label from #$number: $removal"
fi
printf 'relabel-release-pr: pull request #%s is now labelled "%s"\n' "$number" "$tagged"

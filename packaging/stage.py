#!/usr/bin/env python3
"""Stage exact package assets without changing the original SDK release."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

REPO = "metaneutrons/ami-rust"
RELEASES_PER_PAGE = 100
MAX_RELEASE_PAGES = 100


def api(path, *, method="GET", data=None, missing=False):
    request = Request("https://api.github.com/" + path, method=method,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json", "Content-Type": "application/json",
                 "X-GitHub-Api-Version": "2022-11-28"},
        data=None if data is None else json.dumps(data).encode())
    try:
        with urlopen(request, timeout=90) as response:
            return json.load(response)
    except HTTPError as error:
        if missing and error.code == 404:
            return None
        raise RuntimeError(f"GitHub {method} {path} failed with HTTP {error.code}") from None


def verify_assets(release, expected):
    assets = release["assets"]
    if len(assets) != len(expected) or {row["name"] for row in assets} != set(expected):
        raise ValueError("release asset set differs from the sealed candidate")
    for row in assets:
        wanted = expected[row["name"]]
        if row["size"] != wanted["bytes"] or row.get("digest") != "sha256:" + wanted["sha256"]:
            raise ValueError("release asset identity differs: " + row["name"])


def _release_id(release, tag):
    if (type(release) is not dict or release.get("tag_name") != tag
            or type(release.get("id")) is not int or release["id"] <= 0):
        raise ValueError("packaging release identity is malformed or names another tag")
    return release["id"]


def _list_release_by_tag(tag):
    """Reconcile a tag-lookup 404 against the bounded, authenticated release list."""
    matches = []
    for page in range(1, MAX_RELEASE_PAGES + 1):
        path = (f"repos/{REPO}/releases?per_page={RELEASES_PER_PAGE}"
                f"&page={page}")
        rows = api(path)
        if (type(rows) is not list or len(rows) > RELEASES_PER_PAGE
                or any(type(row) is not dict or type(row.get("tag_name")) is not str
                       for row in rows)):
            raise ValueError("GitHub release list is malformed; cannot reconcile packaging draft")
        matches.extend(row for row in rows if row["tag_name"] == tag)
        if len(rows) < RELEASES_PER_PAGE:
            break
    else:
        raise ValueError("GitHub release list is truncated; refusing to create another release")
    if len(matches) > 1:
        raise ValueError("multiple GitHub releases use the packaging tag")
    if matches:
        _release_id(matches[0], tag)
        return matches[0]
    return None


def original_sdk(pins):
    ref = api(f"repos/{REPO}/git/ref/tags/" + quote(pins["sdk_tag"], safe=""))
    obj = ref["object"]
    if obj["type"] == "tag":
        obj = api(f"repos/{REPO}/git/tags/" + obj["sha"])["object"]
    if obj["type"] != "commit" or obj["sha"] != pins["source_commit"]:
        raise ValueError("original SDK tag no longer matches its frozen source")
    release = api(f"repos/{REPO}/releases/tags/" + quote(pins["sdk_tag"], safe=""))
    if release["draft"] or release["prerelease"]:
        raise ValueError("original SDK is no longer the accepted stable release")
    verify_assets(release, {row["path"]: row for row in pins["assets"]})
    return release["id"]


def run(directory, pins, gh, receipt):
    candidate = json.loads((directory / "candidate.json").read_text())
    expected = {row["path"]: row for row in candidate["assets"]}
    for name in ("candidate.json", "SHA256SUMS"):
        raw = (directory / name).read_bytes()
        expected[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    # Read-only preflight precedes the first tag, draft or asset mutation.
    sdk_id = original_sdk(pins)
    tag = pins["packaging_tag"]
    ref_path = f"repos/{REPO}/git/ref/tags/" + quote(tag, safe="")
    ref = api(ref_path, missing=True)
    if ref is not None and (ref["object"]["type"] != "commit"
                            or ref["object"]["sha"] != candidate["source_commit"]):
        raise ValueError("packaging tag already names a different source")
    endpoint = f"repos/{REPO}/releases/tags/" + quote(tag, safe="")
    release = api(endpoint, missing=True)
    if release is None:
        # GitHub may hide a private draft from the tag endpoint. Reconcile the
        # authenticated release list before deciding that it is safe to create.
        release = _list_release_by_tag(tag)
    if release is not None and not (release["draft"] or release["prerelease"]):
        raise ValueError("stable packaging release cannot be restaged")
    if release is None:
        if ref is None:
            api(f"repos/{REPO}/git/refs", method="POST",
                data={"ref": "refs/tags/" + tag, "sha": candidate["source_commit"]})
        sdk_version = pins["sdk_version"]
        revision = pins["packaging_revision"]
        release = api(f"repos/{REPO}/releases", method="POST", data={
            "tag_name": tag, "target_commitish": candidate["source_commit"],
            "name": f"ami-rust {sdk_version} — APT and Homebrew packaging {revision}",
            "draft": True, "prerelease": True, "make_latest": "false",
            "body": f"Package-manager delivery of the unchanged SDK {sdk_version}. "
                    f"The separate packaging tag identifies adapter and package metadata revision {revision}. "
                    "Channel availability is qualified separately; see the repository distribution status. "
                    "One explicit user preparation step is required before building."})
    release_id = _release_id(release, tag)
    release_endpoint = f"repos/{REPO}/releases/{release_id}"
    # Use the returned/listed release identity from here onward. Private draft
    # releases are not consistently addressable through the tag endpoint.
    release = api(release_endpoint)
    _release_id(release, tag)
    existing = {row["name"] for row in release["assets"]}
    if not existing <= set(expected) or len(existing) != len(release["assets"]):
        raise ValueError("existing release has unexpected or repeated assets")
    for row in release["assets"]:
        wanted = expected[row["name"]]
        if row["size"] != wanted["bytes"] or row.get("digest") != "sha256:" + wanted["sha256"]:
            raise ValueError("existing asset collision; never overwrite release bytes")
    missing = set(expected) - existing
    if missing and not release["draft"]:
        raise ValueError("a public candidate must already contain the complete sealed asset set")
    if missing:
        subprocess.run([str(gh), "release", "upload", tag, "--repo", REPO,
                        *(str(directory / name) for name in sorted(missing))], check=True, timeout=600)
    # Private draft readback checks actual bytes before any public exposure.
    readback = receipt.parent / "draft-readback"
    readback.mkdir(mode=0o700)
    subprocess.run([str(gh), "release", "download", tag, "--repo", REPO,
                    "--dir", str(readback)], check=True, timeout=600)
    if {path.name for path in readback.iterdir()} != set(expected):
        raise ValueError("draft readback set differs")
    for name, row in expected.items():
        raw = (readback / name).read_bytes()
        if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("draft readback bytes differ: " + name)
    release = api(release_endpoint)
    _release_id(release, tag)
    verify_assets(release, expected)
    if release["draft"]:
        api(release_endpoint, method="PATCH",
            data={"draft": False, "prerelease": True, "make_latest": "false"})
    release = api(release_endpoint)
    _release_id(release, tag)
    verify_assets(release, expected)
    for row in release["assets"]:
        # No bearer token is sent to the consumer download path.
        with urlopen(row["browser_download_url"], timeout=180) as response:
            raw = response.read(expected[row["name"]]["bytes"] + 1)
        wanted = expected[row["name"]]
        if len(raw) != wanted["bytes"] or hashlib.sha256(raw).hexdigest() != wanted["sha256"]:
            raise ValueError("anonymous public download differs: " + row["name"])
    original_sdk(pins)
    latest = api(f"repos/{REPO}/releases/latest")
    if latest["id"] != sdk_id:
        raise ValueError("packaging staging changed the latest SDK release")
    with receipt.open("x") as stream:
        json.dump({"status": "PASS_PUBLIC_PACKAGING_STAGE_NOT_CHANNEL_ACCEPTANCE", "tag": tag,
                   "release_id": release["id"], "source_commit": candidate["source_commit"],
                   "assets": expected, "original_sdk_unchanged": True}, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--gh", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    run(args.directory, json.loads(args.pins.read_text()), args.gh, args.receipt)

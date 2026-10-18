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
    if release is not None and not (release["draft"] or release["prerelease"]):
        raise ValueError("stable packaging release cannot be restaged")
    if ref is None:
        api(f"repos/{REPO}/git/refs", method="POST",
            data={"ref": "refs/tags/" + tag, "sha": candidate["source_commit"]})
    if release is None:
        release = api(f"repos/{REPO}/releases", method="POST", data={
            "tag_name": tag, "target_commitish": candidate["source_commit"],
            "name": "ami-rust 0.1.0 — APT and Homebrew packaging 1",
            "draft": True, "prerelease": True, "make_latest": "false",
            "body": "Package-manager delivery of the unchanged SDK 0.1.0. "
                    "The separate packaging tag identifies the adapter and package metadata. "
                    "Channel availability is qualified separately; see the repository distribution status. "
                    "One explicit user preparation step is required before building."})
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
    release = api(endpoint)
    verify_assets(release, expected)
    if release["draft"]:
        api(f"repos/{REPO}/releases/{release['id']}", method="PATCH",
            data={"draft": False, "prerelease": True, "make_latest": "false"})
    release = api(endpoint)
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

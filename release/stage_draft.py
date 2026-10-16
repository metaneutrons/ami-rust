#!/usr/bin/env python3
"""Upload an exact candidate into an existing draft and read back every byte.

The caller must qualify/authenticate the candidate separately. This controller
does not create tags, publish, promote, sign, or claim cryptographic acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_candidate

REPOSITORY = "metaneutrons/ami-rust"
API = "repos/" + REPOSITORY


class GitHub:
    def __init__(self, executable: Path, host: str):
        self.executable = Path(executable).absolute()
        tools = json.loads(Path(__file__).with_name("ci-auth-tools.json").read_bytes())
        if host not in tools["hosts"]:
            raise ValueError("unsupported publication host")
        pin = tools["hosts"][host]["gh"]
        if self.executable.is_symlink() or not self.executable.is_file():
            raise ValueError("pinned GH executable must be a regular file")
        with self.executable.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if self.executable.stat().st_size != pin["binary_bytes"] or digest != pin["binary_sha256"]:
            raise ValueError("GH executable differs from source-pinned publication tool")

    def json(self, endpoint: str, *, paginate: bool = False):
        command = [str(self.executable), "api", "--hostname", "github.com", endpoint]
        if paginate:
            command += ["--paginate", "--slurp"]
        result = subprocess.run(command, capture_output=True, check=True, timeout=120)
        return json.loads(result.stdout)

    def upload(self, tag: str, path: Path):
        subprocess.run([str(self.executable), "release", "upload", tag, str(path),
                        "--repo", "github.com/" + REPOSITORY],
                       check=True, capture_output=True, timeout=300)

    def download(self, asset_id: int, destination: Path, expected_bytes: int):
        def bound_file_output():
            resource.setrlimit(resource.RLIMIT_FSIZE, (expected_bytes, expected_bytes))
        with destination.open("xb") as stream:
            subprocess.run([str(self.executable), "api", "--hostname", "github.com", "--allow-escape-sequences",
                            API + "/releases/assets/" + str(asset_id),
                            "-H", "Accept: application/octet-stream"],
                           stdout=stream, stderr=subprocess.PIPE, check=True, timeout=300,
                           preexec_fn=bound_file_output)


def require_source(source: str):
    if type(source) is not str or re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise ValueError("source must be an independently selected full lowercase commit SHA")


def tag_target(github, tag: str) -> str:
    stage_candidate.asset_names(tag)  # Canonical SemVer before endpoint construction.
    obj = github.json(API + "/git/ref/tags/" + tag)["object"]
    seen = set()
    for _ in range(8):
        kind, digest = obj.get("type"), obj.get("sha")
        require_source(digest)
        if kind == "commit":
            return digest
        if kind != "tag" or digest in seen:
            raise ValueError("release tag does not resolve to one commit")
        seen.add(digest)
        obj = github.json(API + "/git/tags/" + digest)["object"]
    raise ValueError("release tag indirection exceeds the supported depth")


def require_draft(github, tag: str, source: str, release_id: int | None = None):
    if tag_target(github, tag) != source:
        raise ValueError("release tag target differs from qualified publisher source")
    release = github.json(API + "/releases/tags/" + tag)
    if (release.get("draft") is not True or release.get("tag_name") != tag
            or type(release.get("id")) is not int or release["id"] <= 0
            or (release_id is not None and release["id"] != release_id)):
        raise ValueError("an unchanged existing draft release is required")
    return release


def remote_assets(github, release_id: int):
    pages = github.json(API + "/releases/" + str(release_id) + "/assets?per_page=100", paginate=True)
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError("unexpected paginated release asset response")
    result = {}
    for page in pages:
        for row in page:
            if (not isinstance(row, dict) or not isinstance(row.get("name"), str)
                    or row["name"] in result or type(row.get("id")) is not int or row["id"] <= 0
                    or type(row.get("size")) is not int or row["size"] < 0
                    or row.get("state") != "uploaded"):
                raise ValueError("release contains a duplicate, incomplete or malformed asset")
            result[row["name"]] = row
    return result


def reconcile(remote, expected, *, complete: bool):
    if set(remote) - set(expected) or (complete and set(remote) != set(expected)):
        raise ValueError("draft release asset set differs from the exact candidate")
    for name, row in remote.items():
        pin = expected[name]
        if row["size"] != pin["bytes"] or row.get("digest") != "sha256:" + pin["sha256"]:
            raise ValueError("existing draft asset differs from candidate: " + name)


def stage(github, tag: str, source: str, candidate: Path, readback: Path):
    require_source(source)
    candidate = Path(candidate).absolute()
    readback = Path(readback).absolute()
    verified = stage_candidate.verify_candidate(candidate, tag)
    if verified.get("source_commit") != source:
        raise ValueError("candidate publisher source differs from independently selected source")
    # The module's sole expected inventory is derived from the shared asset list.
    expected = {row["path"]: row for row in verified["assets"]}
    if set(expected) != set(stage_candidate.asset_names(tag).values()):
        raise ValueError("candidate verifier returned an inconsistent asset inventory")
    if (readback.exists() or readback.is_symlink()
            or readback.parent.resolve(strict=True) != readback.parent
            or candidate == readback or candidate in readback.parents or readback in candidate.parents):
        raise ValueError("readback must be a fresh independent directory with a real parent")
    permission = github.json(API).get("permissions", {})
    if permission.get("push") is not True:
        raise ValueError("repository preflight did not confirm reported push permission")
    release = require_draft(github, tag, source)
    release_id = release["id"]
    initial = remote_assets(github, release_id)
    reconcile(initial, expected, complete=False)
    readback.mkdir(mode=0o700)
    uploaded = []
    for name in sorted(expected):
        if name not in initial:
            # Every upload has a fresh identity/draft preflight; never clobber.
            require_draft(github, tag, source, release_id)
            if stage_candidate.verify_candidate(candidate, tag) != verified:
                raise ValueError("local candidate changed before upload")
            github.upload(tag, candidate / name)
            uploaded.append(name)
    require_draft(github, tag, source, release_id)
    final = remote_assets(github, release_id)
    reconcile(final, expected, complete=True)
    for name, row in sorted(final.items()):
        destination = readback / name
        github.download(row["id"], destination, expected[name]["bytes"])
        with destination.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if destination.stat().st_size != expected[name]["bytes"] or digest != expected[name]["sha256"]:
            raise ValueError("downloaded draft bytes differ from candidate: " + name)
    if stage_candidate.verify_candidate(readback, tag) != verified:
        raise ValueError("downloaded draft inventory differs from qualified candidate")
    require_draft(github, tag, source, release_id)
    reconcile(remote_assets(github, release_id), expected, complete=True)
    return {"schema": "ami-rust-draft-readback-v1",
            "status": "DRAFT_BYTES_STAGED_NOT_PUBLISHED_NOT_CRYPTO_VERIFIED",
            "repository": REPOSITORY, "tag": tag, "source_commit": source,
            "release_id": release_id, "uploaded": uploaded, "assets": verified["assets"],
            "readback": str(readback), "SDK_published": False,
            "qualification_and_signature_verification": "required separately"}


def receipt_path(path: Path, candidate: Path, readback: Path):
    path = Path(path).absolute()
    if (path.exists() or path.is_symlink()
            or path.parent.resolve(strict=True) != path.parent
            or any(root.absolute() == path or root.absolute() in path.parents
                   for root in (candidate, readback))):
        raise ValueError("receipt must be fresh and outside candidate/readback trees")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--readback", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--gh", required=True, type=Path, help="source-pinned GH executable")
    parser.add_argument("--host", required=True, choices=("linux-x86_64", "macos-aarch64"))
    args = parser.parse_args()
    args.receipt = receipt_path(args.receipt, args.candidate, args.readback)
    record = stage(GitHub(args.gh, args.host), args.tag, args.source_commit, args.candidate, args.readback)
    with args.receipt.open("x") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()

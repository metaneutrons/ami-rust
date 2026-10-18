#!/usr/bin/env python3
"""Bind publication to a successful producer and dispatch the shared archive."""
from __future__ import annotations

import argparse
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ami_rust_stage_control", HERE / "stage.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
api = stage.api
REPO = stage.REPO
ARCHIVE = "metaneutrons/apt-archive"


def producer(run_id):
    if not re.fullmatch(r"[1-9][0-9]*", str(run_id)):
        raise ValueError("producer run must be a positive integer")
    run = api(f"repos/{REPO}/actions/runs/{run_id}")
    if (run["conclusion"] != "success" or run["status"] != "completed"
            or run["event"] != "workflow_dispatch" or run["head_branch"] != "main"
            or run["path"].split("@", 1)[0] != ".github/workflows/packages.yml"
            or run["repository"]["full_name"] != REPO):
        raise ValueError("producer is not a successful protected package qualification")
    attempt = run["run_attempt"]
    records = api(f"repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    jobs = records["jobs"]
    if records["total_count"] != len(jobs):
        raise ValueError("producer job response is incomplete")
    for name in ("Protected source and channel access", "Build, authenticate and stage package bytes",
                 "Package lifecycle (linux-x86_64)", "Package lifecycle (macos-aarch64)", "Package qualification"):
        selected = [row for row in jobs if row["name"] == name]
        if len(selected) != 1 or selected[0]["conclusion"] != "success":
            raise ValueError("producer gate is absent, repeated or unsuccessful: " + name)
    commit = run["head_sha"]
    comparison = api(f"repos/{REPO}/compare/{commit}...main")
    if comparison["merge_base_commit"]["sha"] != commit or comparison["status"] not in ("ahead", "identical"):
        raise ValueError("qualified package source is no longer an ancestor of main")
    source = api(f"repos/{REPO}/git/commits/{commit}")
    epoch = int(datetime.fromisoformat(source["committer"]["date"].replace("Z", "+00:00")).timestamp())
    return {"commit": commit, "tree": source["tree"]["sha"], "epoch": epoch,
            "run_id": int(run_id), "attempt": attempt}


def stable(directory, run_id):
    identity = producer(run_id)
    candidate = json.loads((directory / "candidate.json").read_text())
    if (candidate["source_commit"] != identity["commit"] or candidate["source_tree"] != identity["tree"]
            or candidate["run_id"] != identity["run_id"] or candidate["run_attempt"] != identity["attempt"]):
        raise ValueError("stable promotion candidate differs from qualified producer")
    pins = json.loads((HERE / "pins.json").read_text())
    original_id = stage.original_sdk(pins)
    ref = api(f"repos/{REPO}/git/ref/tags/" + quote(pins["packaging_tag"], safe=""))
    if ref["object"]["sha"] != identity["commit"] or ref["object"]["type"] != "commit":
        raise ValueError("packaging tag differs from qualified source")
    release = api(f"repos/{REPO}/releases/tags/" + quote(pins["packaging_tag"], safe=""))
    expected = {row["path"]: row for row in candidate["assets"]}
    for name in ("candidate.json", "SHA256SUMS"):
        import hashlib
        raw = (directory / name).read_bytes()
        expected[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    stage.verify_assets(release, expected)
    if release["draft"]:
        raise ValueError("stable promotion requires an already verified public candidate")
    if release["prerelease"]:
        api(f"repos/{REPO}/releases/{release['id']}", method="PATCH",
            data={"prerelease": False, "make_latest": "false"})
    actual = api(f"repos/{REPO}/releases/{release['id']}")
    stage.verify_assets(actual, expected)
    if actual["draft"] or actual["prerelease"]:
        raise ValueError("packaging release did not become stable")
    if api(f"repos/{REPO}/releases/latest")["id"] != original_id:
        raise ValueError("stable packaging promotion changed the latest SDK release")
    return {"status": "PASS_STABLE_PACKAGING_NOT_APT_ACCEPTANCE", "release_id": actual["id"], **identity}


def dispatch_archive():
    installation = api("installation/repositories")
    if installation["total_count"] != 1 or [row["full_name"] for row in installation["repositories"]] != [ARCHIVE]:
        raise ValueError("archive token is not restricted to the existing archive repository")
    workflow = api(f"repos/{ARCHIVE}/actions/workflows/publish.yml")
    if workflow["state"] != "active":
        raise ValueError("archive publish workflow is not active")
    head = api(f"repos/{ARCHIVE}/git/ref/heads/main")["object"]["sha"]
    # GitHub returns this dispatch's run identity; no latest-run guess or race.
    dispatch = api(f"repos/{ARCHIVE}/actions/workflows/publish.yml/dispatches", method="POST",
                   data={"ref": "main", "inputs": {"domain": "metaneutrons.cc", "project": "ami-rust"},
                         "return_run_details": True})
    run_id = dispatch["workflow_run_id"]
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("archive dispatch returned no exact run identity")
    deadline = time.monotonic() + 2700
    delay = 60
    while True:
        run = api(f"repos/{ARCHIVE}/actions/runs/{run_id}")
        if run["head_sha"] != head or run["event"] != "workflow_dispatch" or run["head_branch"] != "main":
            raise ValueError("archive dispatch source/event identity changed")
        if run["status"] == "completed":
            if run["conclusion"] != "success":
                raise ValueError("shared archive publication failed; retain its exact run for diagnosis")
            return {"status": "PASS_SHARED_ARCHIVE_PUBLICATION_NOT_CLIENT_ACCEPTANCE",
                    "run_id": run_id, "source_commit": head, "url": run["html_url"]}
        if time.monotonic() + delay > deadline:
            raise TimeoutError("shared archive publication did not finish in 45 minutes")
        time.sleep(delay)
        delay = min(delay * 2, 300)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("producer", "stable", "dispatch-archive"))
    parser.add_argument("--producer-run-id")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if args.mode == "producer":
        result = producer(args.producer_run_id)
        if "GITHUB_OUTPUT" in os.environ:
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                for name, value in result.items():
                    stream.write(f"{name}={value}\n")
    elif args.mode == "stable":
        result = stable(args.directory, args.producer_run_id)
    else:
        result = dispatch_archive()
    with args.receipt.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))

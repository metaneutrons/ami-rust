#!/usr/bin/env python3
"""Bind publication to a successful producer and dispatch the shared archive."""
from __future__ import annotations

import argparse
import base64
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
PACKAGE_WORKFLOW = ".github/workflows/packages.yml"
REQUALIFICATION_WORKFLOW = ".github/workflows/requalify-packages.yml"
REQUALIFICATION_PATH = "packaging/requalification.json"
REQUALIFICATION_SCHEMA = "ami-rust-package-requalification-v1"
MAX_REQUALIFICATION_BYTES = 64 * 1024
MAX_REQUALIFICATION_BASE64_BYTES = ((MAX_REQUALIFICATION_BYTES + 2) // 3) * 4 + 2048
SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

PACKAGE_GATES = (
    "Protected source and channel access",
    "Build, authenticate and stage package bytes",
    "Package lifecycle (linux-x86_64)",
    "Package lifecycle (macos-aarch64)",
    "Package qualification",
)
REQUALIFICATION_GATES = (
    "Protected source and channel access",
    "Authenticate sealed package candidate",
    "Package lifecycle (linux-x86_64)",
    "Package lifecycle (macos-aarch64)",
    "Package qualification",
)


def _source_identity(commit):
    if type(commit) is not str or SHA40_RE.fullmatch(commit) is None:
        raise ValueError("qualified source commit is malformed")
    source = api(f"repos/{REPO}/git/commits/{commit}")
    tree = source.get("tree", {}).get("sha")
    committer = source.get("committer", {})
    date = committer.get("date")
    if type(tree) is not str or SHA40_RE.fullmatch(tree) is None or type(date) is not str:
        raise ValueError("qualified source commit metadata is malformed")
    try:
        parsed_date = datetime.fromisoformat(date.replace("Z", "+00:00"))
        if parsed_date.tzinfo is None:
            raise ValueError("commit date has no timezone")
        epoch = int(parsed_date.timestamp())
    except (OverflowError, TypeError) as error:
        raise ValueError("qualified source commit date is malformed") from error
    except ValueError as error:
        raise ValueError("qualified source commit date is malformed") from error
    return {"commit": commit, "tree": tree, "epoch": epoch}


def _compare_ancestor(commit, head, message):
    comparison = api(f"repos/{REPO}/compare/{commit}...{head}")
    if (comparison.get("merge_base_commit", {}).get("sha") != commit
            or comparison.get("status") not in ("ahead", "identical")):
        raise ValueError(message)


def _load_requalification(controller_commit):
    if type(controller_commit) is not str or SHA40_RE.fullmatch(controller_commit) is None:
        raise ValueError("requalification controller source commit is malformed")
    endpoint = (f"repos/{REPO}/contents/{REQUALIFICATION_PATH}"
                f"?ref={controller_commit}")
    response = api(endpoint)
    if (response.get("type") != "file" or response.get("path") != REQUALIFICATION_PATH
            or response.get("encoding") != "base64" or type(response.get("content")) is not str):
        raise ValueError("requalification pins are missing or malformed at the controller source")
    if len(response["content"]) > MAX_REQUALIFICATION_BASE64_BYTES:
        raise ValueError("requalification pins exceed the encoded byte bound")
    encoded = "".join(response["content"].split())
    if len(encoded) > ((MAX_REQUALIFICATION_BYTES + 2) // 3) * 4:
        raise ValueError("requalification pins exceed the byte bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("requalification pins are not valid base64") from error
    if (not raw or len(raw) > MAX_REQUALIFICATION_BYTES
            or type(response.get("size")) is not int or response["size"] != len(raw)):
        raise ValueError("requalification pins are empty, oversized or have a mismatched size")

    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("requalification pins contain a duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(value):
        raise ValueError("requalification pins contain a nonstandard JSON constant")

    try:
        pins = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("requalification pins are not valid bounded JSON") from error
    if (type(pins) is not dict or set(pins) != {"schema", "candidate", "reason"}
            or pins.get("schema") != REQUALIFICATION_SCHEMA):
        raise ValueError("requalification pins have an unsupported schema or fields")
    candidate = pins["candidate"]
    fields = {"commit", "tree", "epoch", "run_id", "attempt", "candidate_sha256"}
    if type(candidate) is not dict or set(candidate) != fields:
        raise ValueError("requalification candidate identity has missing or extra fields")
    for field in ("commit", "tree"):
        if type(candidate[field]) is not str or SHA40_RE.fullmatch(candidate[field]) is None:
            raise ValueError(f"requalification candidate {field} is malformed")
    if (type(candidate["epoch"]) is not int or candidate["epoch"] < 0
            or type(candidate["run_id"]) is not int or candidate["run_id"] <= 0
            or type(candidate["attempt"]) is not int or candidate["attempt"] <= 0
            or type(candidate["candidate_sha256"]) is not str
            or SHA256_RE.fullmatch(candidate["candidate_sha256"]) is None):
        raise ValueError("requalification candidate identity has invalid values")
    reason = pins["reason"]
    if type(reason) is not str or not reason.strip() or len(reason) > 1024 or "\x00" in reason:
        raise ValueError("requalification reason is empty or exceeds its bound")
    return candidate


def requalification_input(controller_commit):
    """Validate the original immutable candidate using pins in this controller commit."""
    _compare_ancestor(controller_commit, "main",
                      "requalification controller source is no longer an ancestor of main")
    candidate = _load_requalification(controller_commit)

    original_id = candidate["run_id"]
    original = api(f"repos/{REPO}/actions/runs/{original_id}")
    if (original.get("conclusion") not in ("success", "failure") or original.get("status") != "completed"
            or original.get("event") != "workflow_dispatch" or original.get("head_branch") != "main"
            or original.get("path", "").split("@", 1)[0] != PACKAGE_WORKFLOW
            or original.get("repository", {}).get("full_name") != REPO
            or original.get("run_attempt") != candidate["attempt"]
            or original.get("head_sha") != candidate["commit"]):
        raise ValueError("pinned original producer run identity is not the successful package run")

    records = api(f"repos/{REPO}/actions/runs/{original_id}/attempts/{candidate['attempt']}/jobs?per_page=100")
    jobs = records.get("jobs")
    if type(jobs) is not list or records.get("total_count") != len(jobs):
        raise ValueError("pinned original producer job response is incomplete")
    required = (PACKAGE_GATES[0], PACKAGE_GATES[1])
    for name in required:
        selected = [row for row in jobs if type(row) is dict and row.get("name") == name]
        if len(selected) != 1 or selected[0].get("conclusion") != "success":
            raise ValueError("pinned original producer staging gate is absent, repeated or unsuccessful: " + name)

    _compare_ancestor(candidate["commit"], controller_commit,
                      "original candidate source is not an ancestor of the requalification controller")
    identity = _source_identity(candidate["commit"])
    if (identity["tree"] != candidate["tree"] or identity["epoch"] != candidate["epoch"]):
        raise ValueError("requalification pins do not match the original candidate source tree and epoch")
    return {
        **identity,
        "run_id": original_id,
        "attempt": candidate["attempt"],
        "candidate_sha256": candidate["candidate_sha256"],
        "newcontroller_source_commit": controller_commit,
    }


def producer(run_id):
    if not re.fullmatch(r"[1-9][0-9]*", str(run_id)):
        raise ValueError("producer run must be a positive integer")
    run = api(f"repos/{REPO}/actions/runs/{run_id}")
    workflow = run.get("path", "").split("@", 1)[0]
    if workflow == PACKAGE_WORKFLOW:
        gates = PACKAGE_GATES
    elif workflow == REQUALIFICATION_WORKFLOW:
        gates = REQUALIFICATION_GATES
    else:
        raise ValueError("producer is not a successful protected package qualification")
    if (run.get("conclusion") != "success" or run.get("status") != "completed"
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main"
            or run.get("repository", {}).get("full_name") != REPO):
        raise ValueError("producer is not a successful protected package qualification")
    attempt = run.get("run_attempt")
    if type(attempt) is not int or attempt <= 0:
        raise ValueError("producer run attempt is malformed")
    records = api(f"repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    jobs = records.get("jobs")
    if type(jobs) is not list or records.get("total_count") != len(jobs):
        raise ValueError("producer job response is incomplete")
    for name in gates:
        selected = [row for row in jobs if type(row) is dict and row.get("name") == name]
        if len(selected) != 1 or selected[0].get("conclusion") != "success":
            raise ValueError("producer gate is absent, repeated or unsuccessful: " + name)
    commit = run.get("head_sha")
    if type(commit) is not str or SHA40_RE.fullmatch(commit) is None:
        raise ValueError("producer source commit is malformed")
    if workflow == REQUALIFICATION_WORKFLOW:
        identity = requalification_input(commit)
        return {**identity, "qualification_run_id": int(run_id)}
    _compare_ancestor(commit, "main", "qualified package source is no longer an ancestor of main")
    return {**_source_identity(commit), "run_id": int(run_id), "attempt": attempt}


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
    parser.add_argument("mode", choices=("producer", "requalification-input", "stable", "dispatch-archive"))
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
    elif args.mode == "requalification-input":
        result = requalification_input(os.environ.get("GITHUB_SHA"))
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

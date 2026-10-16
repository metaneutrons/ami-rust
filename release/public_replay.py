#!/usr/bin/env python3
"""Replay one publicly retrieved SDK bundle through the documented consumer flow.

This client records publisher evidence verification and a hosted consumer replay.
It does not publish a release, accept R1, or run an AROS guest. Run this driver
with the pinned Python interpreter in isolated, no-bytecode mode.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any


RESULT_SCHEMA = "ami-rust-public-consumer-replay-v1"
RESULT_STATUS = "PASS_PUBLIC_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE"
FAILURE_SCHEMA = "ami-rust-public-consumer-replay-failure-v1"
FAILURE_NAME = "public-replay-failure.json"
RESULT_NAME = "public-replay.json"
OUTER_RECEIPT_NAME = "public-candidate-authentication.json"
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
SEMVER_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
RELEASE_TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:" + SEMVER_IDENTIFIER + r")(?:\." + SEMVER_IDENTIFIER + r")*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
APPROVED_REPOSITORY = "metaneutrons/ami-rust"
PUBLIC_REPLAY_CONTROL_PATHS = (
    "release/public_replay.py",
    "release/public_candidate.py",
    "release/candidate_auth.py",
    "release/stage_candidate.py",
    "release/verify_publisher.py",
    "release/ci_verify.py",
    "release/ci_auth.py",
    "release/ci_sdk.py",
    "release/ci_cargo.py",
    "release/prepare_sdk.py",
    "release/consumer_inputs.py",
    "release/public_transport.py",
)
REQUIRED_CONSUMER_ASSETS = (
    "sdk.tar.xz", "SHAUTIL", "install.py", "install_publisher.py",
    "verify_publisher.py", "new_project.py", "QUICKSTART.md",
)


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _absolute_real_directory(label: str, value: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(label + " must be an absolute path")
    resolved = path.resolve(strict=True)
    if path != resolved or not resolved.is_dir():
        raise ValueError(label + " must be an existing real directory without symlink components")
    return resolved


def release_core(release_tag: str) -> str:
    """Return the SemVer release core from a canonical v-prefixed tag."""
    if not isinstance(release_tag, str) or RELEASE_TAG_RE.fullmatch(release_tag) is None:
        raise ValueError("release tag must be a canonical v-prefixed SemVer value")
    return release_tag[1:].split("-", 1)[0].split("+", 1)[0]


def _load_trusted_helpers(source: Path, controls_root: Path | None = None) -> ModuleType:
    """Load trusted replay code, optionally from the frozen workflow controls."""
    script_root = source if controls_root is None else controls_root
    script = script_root / "release" / "ci_verify.py"
    if script.is_symlink() or not script.is_file():
        raise ValueError("trusted controls have no regular release/ci_verify.py")
    name = "_ami_rust_public_replay_ci_verify"
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load hosted consumer helpers from trusted controls")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    if controls_root is not None:
        controls_root = _absolute_real_directory("--controls", controls_root)
        loaded = [module, module.ci_sdk, module.ci_auth, module.consumer_inputs,
                  module.ci_sdk.ci_cargo, module.ci_sdk.prepare_sdk]
        for helper in loaded:
            helper_path = Path(helper.__file__).resolve(strict=True)
            if controls_root not in helper_path.parents:
                raise ValueError("loaded hosted consumer helper escaped the frozen controls tree")
            if hasattr(helper, "ROOT"):
                helper.ROOT = source
    if Path(module.ROOT).resolve(strict=True) != source:
        raise ValueError("loaded consumer helpers are not bound to the selected source checkout")
    return module


def _frozen_control_record(controls_root: Path) -> dict[str, Any]:
    """Verify and describe the exact workflow helper sources frozen before checkout."""
    path = controls_root / "control-source.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("frozen workflow control source record is missing or linked")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
        raise ValueError("frozen workflow control source record is oversized or not regular")
    raw = path.read_bytes()
    if len(raw) != info.st_size:
        raise ValueError("frozen workflow control source record changed while being read")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("frozen workflow control source record is invalid JSON") from error
    if (type(record) is not dict
            or record.get("schema") != "ami-rust-public-replay-control-source-v1"
            or type(record.get("workflow_source_commit")) is not str
            or COMMIT_RE.fullmatch(record["workflow_source_commit"]) is None
            or type(record.get("controls")) is not dict
            or set(record["controls"]) != set(PUBLIC_REPLAY_CONTROL_PATHS)):
        raise ValueError("frozen workflow control source record has an unexpected identity or file set")
    for relative in PUBLIC_REPLAY_CONTROL_PATHS:
        row = record["controls"][relative]
        if (type(row) is not dict or set(row) != {"source_path", "bytes", "sha256"}
                or row.get("source_path") != relative or type(row.get("bytes")) is not int
                or row["bytes"] < 0 or type(row.get("sha256")) is not str
                or DIGEST_RE.fullmatch(row["sha256"]) is None):
            raise ValueError("frozen workflow control source entry is malformed: " + relative)
        frozen = controls_root / relative
        if frozen.is_symlink() or not frozen.is_file():
            raise ValueError("frozen workflow control source is missing or linked: " + relative)
        frozen_info = frozen.lstat()
        if (not stat.S_ISREG(frozen_info.st_mode)
                or frozen_info.st_size != row["bytes"]
                or sha256(frozen) != row["sha256"]):
            raise ValueError("frozen workflow control source differs from its record: " + relative)
    return {
        "workflow_source_commit": record["workflow_source_commit"],
        "record_sha256": hashlib.sha256(raw).hexdigest(),
        "files": {relative: record["controls"][relative]["sha256"]
                  for relative in PUBLIC_REPLAY_CONTROL_PATHS},
    }


def _git_preflight(source: Path, expected_commit: str) -> None:
    """Validate the selected checkout with read-only Git commands before import."""
    git_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(source),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["/usr/bin/git", "-C", str(source), "-c", "core.fsmonitor=false", *arguments],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=30,
                env=git_env, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("selected source Git preflight could not complete") from error
        if result.returncode != 0:
            raise ValueError("selected source Git preflight failed")
        return result.stdout.strip()

    top_level = Path(git("rev-parse", "--show-toplevel")).resolve(strict=True)
    if top_level != source:
        raise ValueError("--source must name the selected Git checkout root")
    if git("rev-parse", "HEAD") != expected_commit:
        raise ValueError("selected source HEAD differs from the external source commit")
    if git("status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"):
        raise ValueError("selected source checkout has tracked, untracked, or submodule modifications")

    raw_origins = git("config", "--local", "--get-all", "remote.origin.url").splitlines()
    if len(raw_origins) != 1:
        raise ValueError("selected source must have exactly one configured origin URL")
    configured_origin = raw_origins[0].removesuffix(".git")
    effective_origin = git("remote", "get-url", "origin").removesuffix(".git")
    approved = {
        "https://github.com/" + APPROVED_REPOSITORY,
        "git@github.com:" + APPROVED_REPOSITORY,
    }
    if configured_origin not in approved or effective_origin not in approved:
        raise ValueError("selected source origin is not the approved publisher repository")


def _verify_release_tag_target(source: Path, release_tag: str,
                              expected_commit: str) -> str:
    """Peel one exact release tag and bind it and HEAD to the external source pin."""
    if RELEASE_TAG_RE.fullmatch(release_tag) is None:
        raise ValueError("release tag must be a canonical v-prefixed SemVer value")
    if not COMMIT_RE.fullmatch(expected_commit):
        raise ValueError("publisher source must be an exact lowercase 40-character Git commit")

    git_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(source),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["/usr/bin/git", "-C", str(source), "-c", "core.fsmonitor=false", *arguments],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=30,
                env=git_env, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("selected release tag Git verification could not complete") from error
        if result.returncode != 0:
            raise ValueError("selected release tag Git verification failed")
        return result.stdout.strip()

    head = git("rev-parse", "--verify", "HEAD")
    if head != expected_commit:
        raise ValueError("selected source HEAD differs from the external source commit")

    # A fully qualified tag ref avoids DWIM and abbreviated-ref selection.
    # ^{commit} peels annotated tags and accepts lightweight tags while
    # rejecting tags that do not ultimately name a commit.
    target = git("rev-parse", "--verify", "--quiet",
                 "refs/tags/" + release_tag + "^{commit}")
    if COMMIT_RE.fullmatch(target) is None:
        raise ValueError("selected release tag did not resolve to one exact commit")
    if target != expected_commit:
        raise ValueError("selected release tag target differs from the external source commit")
    return target


def _load_selected_trusted_helpers(source: Path, expected_commit: str,
                                   controls_root: Path | None = None) -> ModuleType:
    """Run the clean checkout preflight before importing its trusted helpers."""
    _git_preflight(source, expected_commit)
    return _load_trusted_helpers(source, controls_root)


def _empty_managed_roots(work: Path, output: Path) -> None:
    for label, root in (("work", work), ("output", output)):
        if root.is_symlink() or not root.is_dir():
            raise ValueError(label + " must be a real managed directory")
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError(label + " must be private and owned by the current user")
        if next(root.iterdir(), None) is not None:
            raise ValueError(label + " must be fresh and empty")


def _write_failure(output: Path, phase: str, error: Exception,
                   release_tag: str, source_commit: str, manifest_sha256: str,
                   supervisor: Any | None,
                   release_tag_target_commit: str | None = None,
                   public_transport_verified_by_harness: bool = False) -> None:
    """Keep a bounded, environment-free failure receipt when output is safe."""
    try:
        if output.is_symlink() or not output.is_dir():
            return
        info = output.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            return
        destination = output / FAILURE_NAME
        if destination.exists() or destination.is_symlink():
            return
        record = {
            "schema": FAILURE_SCHEMA,
            "status": "FAIL_PUBLIC_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE",
            "phase": phase,
            "release_tag": release_tag,
            "source_commit": source_commit,
            "expected_release_manifest_sha256": manifest_sha256,
            "error_type": type(error).__name__,
            "error": str(error)[:2000],
            "commands": list(getattr(supervisor, "commands", ()))[:256],
            "claims": {"R1_accepted": False, "published_by_harness": False,
                       "aros_guest_run": False,
                       "public_transport_verified_by_harness":
                           public_transport_verified_by_harness},
        }
        if release_tag_target_commit is not None:
            record["release_tag_target_commit"] = release_tag_target_commit
        raw = _canonical_json(record)
        if len(raw) > 256 * 1024:
            record["commands"] = []
            record["error"] = str(error)[:512]
            raw = _canonical_json(record)
        with destination.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        destination.chmod(0o600)
    except OSError:
        # Preserve the originating exception; never mask it with report I/O.
        return


def _write_success(output: Path, helpers: ModuleType, report: dict) -> None:
    destination = output / RESULT_NAME
    if destination.exists() or destination.is_symlink():
        raise ValueError("public replay result destination must be fresh")
    max_output = helpers.MAX_OUTPUT_BYTES
    base_bytes = helpers.ci_sdk.directory_bytes(output)
    report["output_bytes"] = 0
    for _ in range(3):
        raw = helpers.canonical_json(report)
        expected = base_bytes + len(raw)
        if report["output_bytes"] == expected:
            break
        report["output_bytes"] = expected
    raw = helpers.canonical_json(report)
    output_bytes = base_bytes + len(raw)
    if output_bytes > max_output:
        raise ValueError("replay metadata and native payloads exceed the existing output bound")
    report["output_bytes"] = output_bytes
    raw = helpers.canonical_json(report)
    if base_bytes + len(raw) != output_bytes:
        raise RuntimeError("public replay result size calculation did not converge")
    with destination.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    destination.chmod(0o600)


def _new_private_directory(path: Path, label: str) -> Path:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError(label + " directory must be fresh")
    path.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError(label + " directory must be private and owned by the current user")
    return path.resolve(strict=True)


def _load_public_candidate(controls_root: Path) -> ModuleType:
    script = controls_root / "release" / "public_candidate.py"
    if script.is_symlink() or not script.is_file():
        raise ValueError("frozen controls have no regular release/public_candidate.py")
    spec = importlib.util.spec_from_file_location(
        "_ami_rust_public_replay_public_candidate", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen public candidate verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if Path(module.ROOT).resolve(strict=True) != controls_root:
        raise ValueError("public candidate verifier is not bound to the frozen controls tree")
    return module


def _candidate_asset_bytes(candidate: Path, tag: str,
                           stage_candidate: ModuleType) -> int:
    """Measure only the six flat candidate files before tool bootstrap or extraction."""
    names = stage_candidate.asset_names(tag)
    expected = set(names.values())
    limits = stage_candidate._outer_limits(names)
    if len(expected) != 6 or set(limits) != expected:
        raise ValueError("frozen candidate helper does not define six bounded public assets")
    entries = list(candidate.iterdir())
    if {path.name for path in entries} != expected or len(entries) != 6:
        raise ValueError("downloaded public candidate must contain exactly six flat assets")
    total = 0
    for path in entries:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("downloaded candidate assets must be unlinked regular files")
        if info.st_size <= 0 or info.st_size > limits[path.name]:
            raise ValueError("downloaded candidate asset exceeds its pinned per-file bound")
        total += info.st_size
    if total > 96 * 1024**2:
        raise ValueError("downloaded candidate exceeds its existing candidate-and-proof storage bound")
    return total


def _write_private_file(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def _parse_json_line(raw: bytes) -> dict:
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise ValueError("GH proof JSON line contains a duplicate key")
            value[key] = item
        return value

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=lambda token: (_ for _ in ()).throw(
                           ValueError("GH proof JSON line contains a nonstandard constant")))
    if type(value) is not dict:
        raise ValueError("GH proof JSONL entry must be a JSON object")
    return value


def _download_public_gh_proofs(candidate: Path, tag: str, gh_path: Path,
                               work: Path, stage_candidate: ModuleType,
                               retrieval_token: str | None
                               ) -> dict[str, list[Path]]:
    """Fetch bounded public proof bundles with a token scoped to GH retrieval."""
    if not retrieval_token:
        raise ValueError("GH_TOKEN is required only to retrieve public attestation bundles")

    proof_limit = 8
    bundle_limit = 2 * 1024**2
    per_subject_jsonl_limit = proof_limit * bundle_limit
    all_proof_bytes = 0
    names = stage_candidate.asset_names(tag)
    subjects = {names[key] for key in ("payload", "sbom", "transport", "checksums")}
    download_root = _new_private_directory(work / "gh-downloads", "GH download")
    snapshot_root = _new_private_directory(work / "gh-proof-snapshots", "GH proof snapshot")
    output: dict[str, list[Path]] = {}
    gh_token = retrieval_token
    env: dict[str, str] | None = None
    try:
        for index, subject in enumerate(sorted(subjects)):
            asset = candidate / subject
            info = asset.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("attestation subject must be a regular candidate asset")
            subject_digest = sha256(asset)
            subject_dir = _new_private_directory(
                download_root / ("subject-" + str(index)), "GH subject download")
            config_dir = _new_private_directory(subject_dir / "gh-config", "GH config")
            env = {
                "PATH": str(gh_path.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(subject_dir),
                "GH_CONFIG_DIR": str(config_dir),
                "GH_TOKEN": gh_token,
                "GH_PROMPT_DISABLED": "1",
                "NO_COLOR": "1",
                "LC_ALL": "C",
                "LANG": "C",
            }
            command = [str(gh_path), "attestation", "download", str(asset),
                       "--repo", APPROVED_REPOSITORY, "--hostname", "github.com",
                       "--predicate-type", "https://slsa.dev/provenance/v1",
                       "--limit", str(proof_limit)]
            try:
                process = subprocess.run(
                    command, cwd=subject_dir, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=300, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("pinned GH could not download public attestation proofs") from error
            env.pop("GH_TOKEN", None)
            env = None
            if process.returncode != 0:
                raise ValueError("pinned GH rejected public attestation proof retrieval")
            entries = list(subject_dir.iterdir())
            files = [entry for entry in entries if entry.name not in {"gh-config"}]
            if len(files) != 1:
                raise ValueError("GH attestation download did not produce exactly one JSONL file")
            jsonl = files[0]
            if (jsonl.is_symlink() or not stat.S_ISREG(jsonl.lstat().st_mode)
                    or re.fullmatch(r"sha256[:-]" + re.escape(subject_digest) + r"\.jsonl",
                                    jsonl.name) is None
                    or jsonl.stat().st_size > per_subject_jsonl_limit):
                raise ValueError("GH attestation JSONL output has an unexpected name or size")
            raw = jsonl.read_bytes()
            if len(raw) != jsonl.stat().st_size or not raw:
                raise ValueError("GH attestation JSONL output changed or is empty")
            lines = raw.splitlines()
            if not 1 <= len(lines) <= proof_limit:
                raise ValueError("GH attestation JSONL exceeds its per-subject proof count bound")
            subject_snapshot_root = _new_private_directory(
                snapshot_root / ("subject-" + str(index)), "GH subject proof snapshot")
            snapshots: list[Path] = []
            for proof_index, line in enumerate(lines):
                if not line or len(line) > bundle_limit:
                    raise ValueError("GH proof JSONL entry is empty or exceeds the 2 MiB bundle bound")
                _parse_json_line(line)
                all_proof_bytes += len(line)
                if all_proof_bytes > 32 * 1024**2:
                    raise ValueError("GH proof set exceeds the existing 32 MiB verification-tree bound")
                digest = hashlib.sha256(line).hexdigest()
                path = subject_snapshot_root / (digest + ".json")
                if path.exists() or path.is_symlink():
                    if sha256(path) != digest:
                        raise ValueError("duplicate GH proof snapshot changed content")
                    snapshots.append(path)
                    continue
                _write_private_file(path, line)
                if sha256(path) != digest:
                    raise ValueError("GH proof snapshot failed its SHA-256 readback check")
                snapshots.append(path)
            if not snapshots:
                raise ValueError("GH attestation download yielded no bounded proof entries")
            output[subject] = snapshots
    finally:
        gh_token = None
        retrieval_token = None
        if env is not None:
            env.clear()
    return output


def _retain_outer_receipt(receipt_path: Path, output: Path) -> tuple[Path, str]:
    source = Path(receipt_path)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError("outer authentication receipt must be a regular file under 1 MiB")
    raw = source.read_bytes()
    if len(raw) != info.st_size:
        raise ValueError("outer authentication receipt changed while being read")
    destination = output / OUTER_RECEIPT_NAME
    if destination.exists() or destination.is_symlink():
        raise ValueError("outer authentication receipt output must be fresh")
    _write_private_file(destination, raw)
    digest = hashlib.sha256(raw).hexdigest()
    if destination.stat().st_size != len(raw) or sha256(destination) != digest:
        raise ValueError("outer authentication receipt failed its output readback check")
    return destination, digest


def _retain_selected_proofs(receipt: dict, receipt_path: Path,
                            output: Path) -> list[dict[str, Any]]:
    selected = receipt.get("selected_gh_proofs")
    if (type(selected) is not dict or not selected
            or any(type(subject) is not str for subject in selected)):
        raise ValueError("outer authentication receipt has no selected GH proof snapshots")
    evidence_root = Path(receipt_path).parent
    retained_root = output / "public-candidate-proofs"
    _new_private_directory(retained_root, "retained public candidate proof")
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for subject in sorted(selected):
        if (type(subject) is not str or not subject or Path(subject).name != subject
                or subject in {".", ".."} or "/" in subject or "\\" in subject):
            raise ValueError("outer authentication receipt contains an unsafe proof subject")
        proof_rows = selected[subject]
        if type(proof_rows) is not list or not proof_rows:
            raise ValueError("outer authentication receipt has a malformed selected proof map")
        subject_root = _new_private_directory(retained_root / subject, "retained subject proof")
        for proof in proof_rows:
            if type(proof) is not dict:
                raise ValueError("outer authentication receipt contains a malformed proof row")
            digest = proof.get("sha256")
            if type(digest) is not str or DIGEST_RE.fullmatch(digest) is None:
                raise ValueError("outer authentication receipt contains an invalid proof digest")
            statement_digest = proof.get("statement_sha256")
            if (type(statement_digest) is not str
                    or DIGEST_RE.fullmatch(statement_digest) is None):
                raise ValueError("outer authentication receipt contains an invalid statement digest")
            identity = (subject, digest)
            if identity in seen:
                continue
            seen.add(identity)
            source = evidence_root / "gh" / (digest + ".json")
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024**2:
                raise ValueError("selected GH proof snapshot is missing, linked or oversized")
            raw = source.read_bytes()
            if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("selected GH proof snapshot failed its input SHA-256 check")
            destination = subject_root / (digest + ".json")
            _write_private_file(destination, raw)
            if destination.stat().st_size != len(raw) or sha256(destination) != digest:
                raise ValueError("retained GH proof snapshot failed its SHA-256 readback check")
            rows.append({"subject": subject, "path": destination.relative_to(output).as_posix(),
                         "bytes": len(raw), "sha256": digest})
    if not rows:
        raise ValueError("no selected GH proof snapshots were retained")
    return rows


def _retain_outer_evidence(receipt: dict, receipt_path: Path,
                           output: Path) -> tuple[str, list[dict[str, Any]]]:
    _destination, receipt_digest = _retain_outer_receipt(receipt_path, output)
    selected = receipt.get("selected_gh_proofs")
    if receipt.get("authenticated") is True and (type(selected) is not dict or not selected):
        raise ValueError("authenticated outer receipt has no selected GH proof snapshots")
    retained = (_retain_selected_proofs(receipt, receipt_path, output)
                if type(selected) is dict and any(selected.values()) else [])
    return receipt_digest, retained


def _failed_outer_receipt(work: Path) -> tuple[dict | None, Path | None]:
    candidates = []
    for directory in work.glob("candidate-auth-work/public-candidate-*"):
        if directory.is_symlink() or not directory.is_dir():
            continue
        path = directory / "receipt.json"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if type(value) is dict:
            candidates.append((path, value))
    if len(candidates) > 1:
        raise ValueError("more than one public candidate authentication receipt was produced")
    return (candidates[0][1], candidates[0][0]) if candidates else (None, None)


def _authenticate_public_candidate(*, candidate: Path, tag: str,
                                   source: Path, source_commit: str,
                                   transport_sha256: str, manifest_sha256: str,
                                   policy: dict, trusted: ModuleType,
                                   public_candidate: ModuleType,
                                   controls_root: Path | None, work: Path,
                                   output: Path, gh_path: Path,
                                   gh_bundles: dict[str, list[Path]] | None,
                                   retrieval_token: str | None
                                   ) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
    expected_names = public_candidate.stage_candidate.asset_names(tag)
    expected_gh_subjects = {expected_names[key] for key in
                            ("payload", "sbom", "transport", "checksums")}
    trusted_inputs = _new_private_directory(work / "trusted-publisher-inputs",
                                            "trusted publisher input")
    auth_directory = trusted_inputs / ".auth"
    auth_directory.mkdir(mode=0o700)
    materials = trusted.ci_auth.input_manifest(source)
    input_manifest = trusted.ci_auth.encoded(materials)
    if hashlib.sha256(input_manifest).hexdigest() != policy.get("inputs_manifest_sha256"):
        raise ValueError("external publisher input materials differ from the generated policy pin")
    _write_private_file(auth_directory / "inputs.json", input_manifest)

    auth_work = _new_private_directory(work / "candidate-auth-work",
                                       "public candidate verifier work")
    destination = work.parent.resolve(strict=True) / "ami-rust-public-authenticated-bundle"
    if destination.exists() or destination.is_symlink():
        raise ValueError("authenticated bundle destination must be fresh")
    if gh_bundles is None:
        gh_bundles = _download_public_gh_proofs(
            candidate, tag, gh_path, work, public_candidate.stage_candidate,
            retrieval_token)
    retrieval_token = None
    # Verification subprocesses receive candidate_auth's explicit token-free
    # environment even though the workflow token was available for retrieval.
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                 "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        os.environ.pop(name, None)

    receipt_path: Path | None = None
    try:
        receipt = public_candidate.verify_and_unpack(
            candidate, tag, source_commit, transport_sha256, manifest_sha256,
            policy, trusted_inputs, gh_bundles, destination, auth_work,
        )
        if (receipt.get("status") != public_candidate.RECEIPT_STATUS
                or receipt.get("authenticated") is not True
                or receipt.get("unpacked") is not True
                or receipt.get("installed") is not False
                or receipt.get("r1_accepted") is not False
                or receipt.get("transport_sha256") != transport_sha256
                or receipt.get("manifest_sha256") != manifest_sha256
                or receipt.get("source_commit") != source_commit
                or receipt.get("workflow_commit") != source_commit):
            raise ValueError("public candidate verifier returned an incomplete authentication receipt")
        receipt_path = Path(receipt["receipt_path"])
        evidence_directory = Path(receipt.get("evidence_directory", ""))
        if (evidence_directory != receipt_path.parent
                or receipt_path.name != "receipt.json"):
            raise ValueError("public candidate verifier returned an unexpected evidence location")
        persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
        if persisted != receipt:
            raise ValueError("persisted outer authentication receipt differs from the verifier result")
        selected = receipt.get("selected_gh_proofs")
        if (type(selected) is not dict or set(selected) != expected_gh_subjects
                or any(type(selected[subject]) is not list or not selected[subject]
                       for subject in expected_gh_subjects)):
            raise ValueError("public candidate verifier did not select proof bundles for all four subjects")
        candidate_assets = receipt.get("candidate_assets")
        if (type(candidate_assets) is not list
                or len(candidate_assets) != 6
                or {row.get("path") for row in candidate_assets if type(row) is dict}
                != set(expected_names.values())):
            raise ValueError("public candidate verifier receipt does not inventory the exact six assets")
        cosign_proofs = receipt.get("cosign_proofs")
        if (type(cosign_proofs) is not dict
                or set(cosign_proofs) != {expected_names["payload"], expected_names["transport"]}):
            raise ValueError("public candidate verifier receipt omits either outer Cosign proof")
        receipt_digest, retained = _retain_outer_evidence(receipt, receipt_path, output)
        if Path(receipt.get("destination", "")) != destination:
            raise ValueError("public candidate verifier unpacked to an unexpected destination")
        if not destination.is_dir() or destination.is_symlink():
            raise ValueError("public candidate verifier did not create the authenticated bundle")
        if len(set(expected_names.values())) != 6:
            raise ValueError("selected release tag did not produce exactly six canonical asset names")
        evidence = {
            "status": receipt["status"],
            "authenticated": True,
            "unpacked": True,
            "receipt_path": OUTER_RECEIPT_NAME,
            "receipt_sha256": receipt_digest,
            "selected_proofs": retained,
        }
        return destination, evidence, retained
    except Exception:
        if receipt_path is None:
            try:
                _receipt, receipt_path = _failed_outer_receipt(work)
            except Exception:
                receipt_path = None
        if receipt_path is not None and receipt_path.is_file() and not receipt_path.is_symlink():
            try:
                failed_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                if type(failed_receipt) is dict:
                    _retain_outer_evidence(failed_receipt, receipt_path, output)
            except Exception:
                pass
        raise


def replay_public_candidate(*, source: Path, source_commit: str,
                            bundle: Path | None = None,
                            candidate_assets: Path | None = None,
                            transport_sha256: str | None = None,
                            manifest_sha256: str, release_tag: str,
                            work: Path, output: Path,
                            python_bootstrap_root: Path,
                            controls_root: Path | None = None,
                            gh_bundles: dict[str, list[Path]] | None = None,
                            helpers: ModuleType | None = None) -> dict:
    """Authenticate six public assets, then replay their safe-unpacked bundle.

    The `bundle` form remains for the existing offline consumer fixtures. The
    production CLI accepts only `candidate_assets` and performs real outer
    authentication and safe unpacking before it reaches the consumer recipe.
    """
    phase = "input-validation"
    supervisor = None
    release_tag_target_commit = None
    outer_authentication: dict[str, Any] | None = None
    retained_proofs: list[dict[str, Any]] = []
    workflow_control_evidence: dict[str, Any] | None = None
    public_candidate_module: ModuleType | None = None
    external_candidate_bytes = 0
    gh_retrieval_token: str | None = None
    source_commit = str(source_commit)
    manifest_sha256 = str(manifest_sha256)
    release_tag = str(release_tag)
    output_path = Path(output).absolute()
    try:
        if RELEASE_TAG_RE.fullmatch(release_tag) is None:
            raise ValueError("--release-tag must be a v-prefixed SemVer value")
        if not COMMIT_RE.fullmatch(source_commit):
            raise ValueError("--source-commit must be an exact lowercase 40-character Git commit")
        if not DIGEST_RE.fullmatch(manifest_sha256):
            raise ValueError("--manifest-sha256 must be an exact lowercase 64-character digest")
        if candidate_assets is None and bundle is None:
            raise ValueError("public replay requires downloaded candidate assets")
        if candidate_assets is not None and bundle is not None:
            raise ValueError("use either public candidate assets or a fixture bundle, not both")
        outer_mode = candidate_assets is not None
        if outer_mode and (not isinstance(transport_sha256, str)
                           or DIGEST_RE.fullmatch(transport_sha256) is None):
            raise ValueError("--transport-sha256 must be an exact lowercase 64-character digest")
        if outer_mode:
            gh_retrieval_token = os.environ.pop("GH_TOKEN", None)
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                     "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            os.environ.pop(name, None)

        source_path = _absolute_real_directory("--source", Path(source))
        if outer_mode:
            candidate_path = _absolute_real_directory(
                "--candidate-assets", Path(candidate_assets))
            controls_path = _absolute_real_directory(
                "--controls", Path(controls_root) if controls_root is not None
                else Path(__file__).resolve().parent.parent)
            workflow_control_evidence = _frozen_control_record(controls_path)
            public_candidate_module = _load_public_candidate(controls_path)
            external_candidate_bytes = _candidate_asset_bytes(
                candidate_path, release_tag, public_candidate_module.stage_candidate)
            if (source_path == candidate_path or source_path in candidate_path.parents
                    or candidate_path in source_path.parents):
                raise ValueError("public candidate assets must be outside the selected source checkout")
        else:
            candidate_path = None
            controls_path = None
            bundle_path = Path(bundle)
            if not bundle_path.is_absolute():
                raise ValueError("--bundle must be an absolute path")
            if (source_path == bundle_path or source_path in bundle_path.parents
                    or bundle_path in source_path.parents):
                raise ValueError("public bundle must be outside the selected source checkout")

        # Load only from the explicit checkout, then require its actual clean
        # Git identity. This helper does not consult or fabricate CI identity.
        phase = "source-identity"
        trusted = (helpers if helpers is not None
                   else _load_selected_trusted_helpers(
                       source_path, source_commit, controls_path))
        if hasattr(trusted, "ROOT") and Path(trusted.ROOT).resolve(strict=True) != source_path:
            raise ValueError("consumer helper root differs from the selected source checkout")
        identity = trusted.consumer_source_identity(source_commit, source_commit)
        expected_identity = {"source_sha": source_commit, "workflow_sha": source_commit}
        if identity != expected_identity:
            raise ValueError("consumer source identity differs from the externally selected source commit")
        if trusted.ci_auth.REPO != APPROVED_REPOSITORY:
            raise ValueError("selected source helper repository identity differs from the approved origin")

        phase = "release-tag-source-binding"
        release_tag_target_commit = _verify_release_tag_target(
            source_path, release_tag, source_commit)

        phase = "external-manifest-pin"
        if outer_mode:
            original_bundle = None
            external_bundle_bytes = 0
        else:
            original_bundle = bundle_path.absolute()
            _, external_bundle_bytes = trusted._candidate_inventory(original_bundle)
            manifest_path = original_bundle / "release.json"
            observed_manifest_sha = sha256(manifest_path)
            if observed_manifest_sha != manifest_sha256:
                raise ValueError("public release.json differs from the externally supplied manifest SHA-256")

        work_path = Path(work)
        output_path = Path(output)
        python_root = Path(python_bootstrap_root)
        trusted._managed_roots(work_path, output_path, python_root)
        _empty_managed_roots(work_path, output_path)
        if outer_mode:
            assert candidate_path is not None
            if any(candidate_path == path.resolve(strict=True)
                   or candidate_path in path.resolve(strict=True).parents
                   or path.resolve(strict=True) in candidate_path.parents
                   for path in (work_path, output_path, python_root)):
                raise ValueError("public candidate assets must be separate from every managed root")
            authenticated_bundle_path = work_path.parent.resolve(strict=True) / \
                "ami-rust-public-authenticated-bundle"
            if authenticated_bundle_path.exists() or authenticated_bundle_path.is_symlink():
                raise ValueError("authenticated bundle runtime root must be fresh")
            if any(authenticated_bundle_path == path.resolve(strict=True)
                   or authenticated_bundle_path in path.resolve(strict=True).parents
                   or path.resolve(strict=True) in authenticated_bundle_path.parents
                   for path in (candidate_path, work_path, output_path, python_root, source_path)):
                raise ValueError("authenticated bundle destination must be separate from all trusted and managed roots")
        elif any(path.resolve(strict=True) == original_bundle
                 or path.resolve(strict=True) in original_bundle.parents
                 or original_bundle in path.resolve(strict=True).parents
                 for path in (work_path, output_path, python_root)):
            raise ValueError("public bundle must be separate from every managed root")

        phase = "pinned-runtime-and-tools"
        host = trusted.host_identity()
        python, python_bootstrap = trusted.ci_sdk.verify_python_bootstrap(python_root, host)
        tool_manifest_path = source_path / "release" / "ci-auth-tools.json"
        tool_manifest = trusted.strict_json(tool_manifest_path, 1024 * 1024)
        tool_pins = trusted.validate_tool_manifest(tool_manifest, host)

        # The outer files are only size-checked here. Their signatures and
        # attestations are verified before the candidate verifier extracts them.
        external_input_bytes = (external_candidate_bytes if outer_mode
                                else external_bundle_bytes)
        if outer_mode:
            tool_archive_bytes = sum(row["bytes"] for row in tool_pins.values())
            trusted_root_bytes = sum(row["bytes"] for row in tool_manifest["roots"].values())
            preflight_bytes = (trusted.ci_sdk.directory_bytes(source_path)
                               + trusted.ci_sdk.directory_bytes(python_root)
                               + trusted.ci_sdk.directory_bytes(work_path)
                               + trusted.ci_sdk.directory_bytes(output_path)
                               + external_candidate_bytes + trusted.MAX_BUNDLE_BYTES
                               + tool_archive_bytes + trusted_root_bytes
                               + trusted.ci_sdk.MAX_LOG_BYTES)
            if preflight_bytes > trusted.ci_sdk.MAX_WORK_BYTES:
                raise ValueError("source, runtime, candidate, pinned tools and maximum unpack exceed the 12 GiB work bound")
        trusted.bootstrap_tools(work_path, output_path, python_root,
                                source_commit=identity["source_sha"],
                                additional_input_bytes=(0 if outer_mode else external_input_bytes))
        tool_receipt = trusted._verify_tool_receipt(work_path, output_path, host, tool_manifest)
        if {entry.name for entry in output_path.iterdir()} != {"tool-bootstrap.json"}:
            raise ValueError("fresh replay output contains unexpected verifier bootstrap entries")

        roots = tool_receipt["roots"]
        policy_path, policy = trusted._write_source_policy(identity, roots, work_path)
        env = trusted._tool_env(work_path, python)
        supervisor = trusted.ci_sdk.Supervisor(work_path, output_path, python_root, env)
        supervisor.checkout_bytes += external_input_bytes

        gh_text = trusted._version_text(supervisor, work_path / "tools/gh",
                                        ["--version"], "public-replay-verify-gh-version")
        cosign_text = trusted._version_text(supervisor, work_path / "tools/cosign",
                                            ["version"], "public-replay-verify-cosign-version")
        if ("gh version 2.102.0" not in gh_text
                or not re.search(r"\bv?3\.1\.3\b", cosign_text)):
            raise ValueError("pinned verifier tool version changed before public bundle verification")
        if (trusted.sha256(work_path / "tools/gh") != tool_pins["gh"]["binary_sha256"]
                or trusted.sha256(work_path / "tools/cosign") != tool_pins["cosign"]["binary_sha256"]):
            raise ValueError("pinned verifier tool changed before public bundle verification")

        if outer_mode:
            phase = "public-candidate-authentication"
            assert candidate_path is not None and transport_sha256 is not None
            original_bundle, outer_authentication, retained_proofs = _authenticate_public_candidate(
                candidate=candidate_path, tag=release_tag, source=source_path,
                source_commit=source_commit, transport_sha256=transport_sha256,
                manifest_sha256=manifest_sha256, policy=policy, trusted=trusted,
                public_candidate=public_candidate_module,
                controls_root=controls_path, work=work_path, output=output_path,
                gh_path=work_path / "tools" / "gh", gh_bundles=gh_bundles,
                retrieval_token=gh_retrieval_token,
            )
            gh_retrieval_token = None
            _, external_bundle_bytes = trusted._candidate_inventory(original_bundle)
            manifest_path = original_bundle / "release.json"
            if sha256(manifest_path) != manifest_sha256:
                raise ValueError("authenticated public release.json differs from the external SHA-256")
            supervisor.checkout_bytes += external_bundle_bytes

        # Copy and pin one private snapshot. Check the external release manifest
        # both before and after copying; do not parse it before protected verify.
        phase = "candidate-snapshot"
        if original_bundle == work_path or original_bundle in work_path.parents or work_path in original_bundle.parents:
            raise ValueError("public bundle must not overlap managed work")
        if original_bundle == output_path or original_bundle in output_path.parents or output_path in original_bundle.parents:
            raise ValueError("public bundle must not overlap managed output")
        candidate = work_path / "candidate"
        bundle_copy = trusted._copy_candidate(original_bundle, candidate)
        if (bundle_copy["bytes"] != external_bundle_bytes
                or sha256(manifest_path) != manifest_sha256
                or trusted.sha256(candidate / "release.json") != manifest_sha256):
            raise ValueError("public bundle changed after external manifest pinning")

        # This is the first command that parses the candidate release manifest.
        # The verifier program itself comes only from the selected clean source.
        phase = "protected-source-verification"
        verify_row, verify_stdout, _ = trusted._run_supervised(
            supervisor, python, source_path / "release" / "install_publisher.py",
            ["verify", "--bundle", str(candidate), "--policy", str(policy_path)],
            cwd=work_path, label="public-replay-protected-source-verify", timeout=300)
        verified = trusted._parse_command_result(
            verify_stdout, "verified", "selected-source public bundle verifier")
        if verified.get("host") != host or verified.get("qualification_only") is not False:
            raise ValueError("protected-source verifier returned a different host or release route")
        if verified.get("release_manifest_sha256") != manifest_sha256:
            raise ValueError("protected-source verifier did not bind the externally pinned release manifest")
        trusted._validate_trusted_consumer_assets(
            candidate, verified, policy, trusted_source=source_path)

        # Read candidate metadata and documentation only after protected verify.
        candidate_manifest = trusted.strict_json(candidate / "release.json", 1024 * 1024)
        if (not isinstance(candidate_manifest, dict)
                or candidate_manifest.get("version") != release_core(release_tag)):
            raise ValueError("authenticated release manifest version differs from selected release tag")
        asset_rows = {row["path"]: row for row in candidate_manifest.get("assets", [])
                      if isinstance(row, dict) and isinstance(row.get("path"), str)}
        if (len(asset_rows) != len(candidate_manifest.get("assets", []))
                or candidate_manifest.get("qualification_only") is not False):
            raise ValueError("consumer route requires an unambiguous production manifest")
        for name in ("sdk.tar.xz", "SHAUTIL", f"cargo-{host}.tar.xz", *REQUIRED_CONSUMER_ASSETS[2:]):
            if name not in asset_rows:
                raise ValueError("authenticated candidate omits a required consumer asset: " + name)

        phase = "reference-and-replay-preparation"
        reference_inputs, resources, _ = trusted.ci_sdk.read_normative(
            source_path / "release/ci-sdk-inputs.json",
            source_path / "release/ci-resources.json", host)
        capacity = trusted.ci_sdk.validate_resource_policy(resources, work_path.parent)
        reference = trusted.ci_sdk.validate_native_reference(
            trusted.ci_sdk.read_json(source_path / "release/native-reference.json", 2 * 1024**2),
            reference_inputs, reference_inputs["native_reference"]["sha256"])

        probe_rows = trusted.run_negative_probes(
            candidate, policy_path, work_path,
            work_path / "consumers" / "absolute-a" / "sdk-0.1.0",
            lambda probe, probe_policy, label: trusted._expect_verify_rejection(
                supervisor, python, probe, probe_policy, label))

        prepare_command, check_command = trusted._preparation_commands(candidate)
        first_consumer = trusted._create_consumer_roots(work_path)
        preparation_env = dict(supervisor.env)
        preparation_env.update({
            "SOURCE": str(source_path), "SOURCE_COMMIT": identity["source_sha"],
            "WORKFLOW_COMMIT": identity["workflow_sha"], "PREP_PYTHON": str(python),
            "PYTHON_BOOTSTRAP": str(python_root), "PREP": str(work_path),
            "PREP_OUTPUT": str(output_path), "BUNDLE": str(original_bundle),
            "WORK": str(first_consumer),
        })
        prepare_row, prepare_stdout, _ = trusted._run_recipe_line(
            supervisor, preparation_env, first_consumer, prepare_command,
            "public-replay-document-prepare-inputs")
        preparation = trusted._parse_command_result(
            prepare_stdout, "PREPARED_VERIFIED_INPUTS_NOT_INSTALLED",
            "documented consumer preparation")
        if (preparation.get("source_policy") != identity
                or preparation.get("release_manifest_sha256") != manifest_sha256):
            raise ValueError("documented preparation differs from the selected source or public manifest")

        sdk_root = work_path / "verified-source-sdk"
        sdk_manifest_path = sdk_root / "contract" / "sdk.json"
        sdk_info = {
            "root": sdk_root,
            "manifest": trusted.ci_sdk.read_json(sdk_manifest_path, 2 * 1024**2),
            "manifest_sha256": trusted.sha256(sdk_manifest_path),
        }
        sdk_info["component_info"] = trusted.ci_sdk._component_rows_from_sdk(sdk_info, host)
        if (sdk_info["manifest_sha256"] != preparation.get("sdk_manifest_sha256")
                or sdk_info["manifest"].get("source_identity") != identity["source_sha"]):
            raise ValueError("prepared SDK differs from the selected source preparation receipt")
        ordered_components = {name: work_path / "component-staging" / name
                              for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")}
        component_inventories = {
            name: trusted.ci_sdk.verify_component(
                component_root, sdk_info["component_info"][name]["manifest"], name)
            for name, component_root in ordered_components.items()
        }

        commands, quickstart_sha = trusted._recipe_commands(candidate)
        consumer_report = trusted._install_and_run_recipe(
            candidate, work_path, output_path, python, supervisor, host, sdk_info,
            ordered_components, reference, commands)
        if len(consumer_report["retained_native"]) != 5:
            raise ValueError("consumer replay must retain all five native variants")
        if len(consumer_report["retained_metadata"]) != 6:
            raise ValueError("consumer replay must retain all six root-specific metadata archives")

        phase = "post-uninstall-input-recheck"
        check_row, check_stdout, _ = trusted._run_recipe_line(
            supervisor, preparation_env, first_consumer, check_command,
            "public-replay-document-check-inputs-after-uninstall")
        recheck = trusted._parse_command_result(
            check_stdout, "VERIFIED_RETAINED_INPUTS", "documented retained input check")
        if (recheck.get("components") != component_inventories
                or recheck.get("selection_sha256") != preparation.get("selection_sha256")
                or recheck.get("policy_sha256") != preparation.get("policy_sha256")):
            raise ValueError("post-uninstall input recheck differs from the verified preparation")

        trusted._assert_source_clean(identity["source_sha"])
        supervisor.check_limits("completed public consumer replay")
        report = {
            "schema": RESULT_SCHEMA,
            "status": RESULT_STATUS,
            "release_tag": release_tag,
            "release_tag_target_commit": release_tag_target_commit,
            "host": host,
            "source_policy": {
                "source_sha": identity["source_sha"],
                "workflow_sha": identity["workflow_sha"],
                "source_ref": "refs/heads/main",
                "repository": trusted.ci_auth.REPO,
                "inputs_manifest_sha256": policy["inputs_manifest_sha256"],
                "external_policy_sha256": trusted.sha256(policy_path),
                "tool_manifest_sha256": trusted.sha256(tool_manifest_path),
            },
            "python_bootstrap": {
                "archive_sha256": python_bootstrap["archive_sha256"],
                "runtime_sha256": python_bootstrap["runtime_sha256"],
            },
            "tools": tool_receipt["tools"],
            "roots": tool_receipt["roots"],
            "candidate": {
                "release_manifest_sha256": manifest_sha256,
                "bundle_copy": bundle_copy,
                "external_bundle_bytes": external_bundle_bytes,
                "version": candidate_manifest["version"],
                "sdk_manifest_sha256": sdk_info["manifest_sha256"],
                "sdk_archive_sha256": asset_rows["sdk.tar.xz"]["sha256"],
                "qualification_only": False,
            },
            "protected_source_verification": {
                "process": verify_row,
                "status": verified["status"],
                "release_manifest_sha256": verified["release_manifest_sha256"],
                "authentication": verified["authentication"],
            },
            "public_candidate_authentication": outer_authentication,
            "negative_verification": probe_rows,
            "provisioning": {"components": component_inventories,
                             **preparation.get("provisioning", {})},
            "documented_preparation": {
                "command": prepare_command,
                "process": prepare_row,
                "receipt_sha256": trusted.sha256(output_path / "consumer-preparation.json"),
                "after_uninstall": {"command": check_command, "process": check_row,
                                    "result": recheck},
            },
            "consumer_recipe": {
                "quickstart_sha256": quickstart_sha,
                "commands_per_root": list(commands),
                "roots": consumer_report["commands"],
                "uninstall": consumer_report["uninstall"],
                "prerequisite_inventories_after_uninstall":
                    consumer_report["prerequisite_inventories_after_uninstall"],
                "unrelated_sibling_marker_sha256":
                    consumer_report["unrelated_sibling_marker_sha256"],
            },
            "retained_native": consumer_report["retained_native"],
            "retained_metadata": consumer_report["retained_metadata"],
            "budgets": {"workspace_bytes": trusted.ci_sdk.MAX_WORK_BYTES,
                        "rss_bytes": trusted.ci_sdk.MAX_RSS_BYTES,
                        "log_bytes": trusted.ci_sdk.MAX_LOG_BYTES,
                        "command_seconds": trusted.ci_sdk.MAX_COMMAND_SECONDS,
                        "output_bytes_limit": trusted.MAX_OUTPUT_BYTES},
            "capacity_preflight": capacity,
            "peaks": {"checkout_bytes": supervisor.checkout_bytes,
                      "workspace_bytes": supervisor.peak_workspace,
                      "rss_bytes": supervisor.peak_rss,
                      "logs_bytes": supervisor.peak_logs,
                      "commands": supervisor.commands},
            "claims": {
                "publisher_evidence_verified": True,
                "public_transport_verified_by_harness": outer_authentication is not None,
                "publisher_release_acceptance": False,
                "r1_accepted": False,
                "published_by_harness": False,
                "aros_guest_run": False,
                "two_host_replay_complete": False,
            },
        }
        if workflow_control_evidence is not None:
            report["workflow_control_sources"] = workflow_control_evidence
        phase = "write-replay-result"
        _write_success(output_path, trusted, report)
        return report
    except Exception as error:
        gh_retrieval_token = None
        _write_failure(output_path, phase, error, release_tag, source_commit,
                       manifest_sha256, supervisor, release_tag_target_commit,
                       outer_authentication is not None)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True,
                        help="clean public publisher source checkout")
    parser.add_argument("--source-commit", required=True,
                        help="externally selected exact publisher source commit")
    parser.add_argument("--candidate-assets", type=Path, required=True,
                        help="fresh flat directory containing the six downloaded public release assets")
    parser.add_argument("--transport-sha256", required=True,
                        help="externally recorded transport inventory SHA-256")
    parser.add_argument("--manifest-sha256", required=True,
                        help="externally recorded release.json SHA-256")
    parser.add_argument("--release-tag", required=True,
                        help="externally selected v-prefixed semantic-version release tag")
    parser.add_argument("--work", type=Path, required=True,
                        help="fresh private work directory")
    parser.add_argument("--output", type=Path, required=True,
                        help="fresh private output directory")
    parser.add_argument("--python-bootstrap-root", type=Path, required=True,
                        help="pinned ami-rust-python-bootstrap directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not sys.flags.isolated or not sys.dont_write_bytecode:
            raise ValueError("run public_replay.py under the pinned Python with -I -B")
        replay_public_candidate(
            source=args.source, source_commit=args.source_commit,
            candidate_assets=args.candidate_assets,
            transport_sha256=args.transport_sha256,
            manifest_sha256=args.manifest_sha256, release_tag=args.release_tag,
            work=args.work, output=args.output,
            python_bootstrap_root=args.python_bootstrap_root,
            controls_root=Path(__file__).resolve().parent.parent,
        )
        return 0
    except Exception as error:
        print(json.dumps({"status": "FAIL_PUBLIC_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE",
                          "error_type": type(error).__name__,
                          "error": str(error)[:2000]}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

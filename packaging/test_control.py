#!/usr/bin/env python3
"""Offline gates for qualification-bound promotion and archive dispatch."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone
from urllib.parse import quote
from unittest import mock


_HERE = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


control = load_module("ami_rust_control_test", _HERE / "control.py")
candidate = load_module("ami_rust_candidate_control_test", _HERE / "candidate.py")
REPO = "metaneutrons/ami-rust"
ARCHIVE = "metaneutrons/apt-archive"
RUN_ID = 39121017959
ATTEMPT = 2
COMMIT = "a" * 40
TREE = "b" * 40
SDK_RELEASE_ID = 410
PACKAGING_RELEASE_ID = 520
JOB_NAMES = (
    "Protected source and channel access",
    "Build, authenticate and stage package bytes",
    "Package lifecycle (linux-x86_64)",
    "Package lifecycle (macos-aarch64)",
    "Package qualification",
)
REQUALIFICATION_JOB_NAMES = (
    "Protected source and channel access",
    "Authenticate sealed package candidate",
    "Package lifecycle (linux-x86_64)",
    "Package lifecycle (macos-aarch64)",
    "Package qualification",
)
ORIGINAL_RUN_ID = 39159711172
ORIGINAL_ATTEMPT = 1
ORIGINAL_COMMIT = "a65b6d22bce94e30d5f89627dc176ff01117ebef"
ORIGINAL_TREE = "2db2669e54bf121274ac2f231fa21ad16c75fe80"
CONTROLLER_COMMIT = "c" * 40
CONTROLLER_TREE = "d" * 40
REQUALIFICATION_RUN_ID = 39160000123
CANDIDATE_SHA256 = "9052d51fe4689f5842ecee6e03624ecd6e6eb9363e1b47be231ceed4f3f5e247"
ORIGINAL_EPOCH = 1792352194
ORIGINAL_DATE = datetime.fromtimestamp(ORIGINAL_EPOCH, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def producer_responses(*, run_changes: dict | None = None, jobs: list | None = None,
                       comparison_changes: dict | None = None) -> dict[str, dict]:
    run = {
        "conclusion": "success",
        "status": "completed",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "path": ".github/workflows/packages.yml@refs/heads/main",
        "repository": {"full_name": REPO},
        "run_attempt": ATTEMPT,
        "head_sha": COMMIT,
    }
    run.update(run_changes or {})
    selected_jobs = ([{"name": name, "conclusion": "success"} for name in JOB_NAMES]
                     if jobs is None else jobs)
    comparison = {"merge_base_commit": {"sha": COMMIT}, "status": "ahead"}
    comparison.update(comparison_changes or {})
    source = {
        "tree": {"sha": TREE},
        "committer": {"date": "2026-10-17T12:00:00Z"},
    }
    return {
        f"repos/{REPO}/actions/runs/{RUN_ID}": run,
        f"repos/{REPO}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100": {
            "total_count": len(selected_jobs), "jobs": selected_jobs,
        },
        f"repos/{REPO}/compare/{COMMIT}...main": comparison,
        f"repos/{REPO}/git/commits/{COMMIT}": source,
    }


class CandidateDirectory:
    def __init__(self, path: Path, *, source_commit: str = COMMIT,
                 source_tree: str = TREE, run_id: int = RUN_ID,
                 run_attempt: int = ATTEMPT) -> None:
        self.path = path
        self.path.mkdir(parents=True)
        pins = json.loads((_HERE / "pins.json").read_text(encoding="utf-8"))
        rows = []
        for name in candidate.asset_names(pins):
            raw = ("candidate asset fixture: " + name + "\n").encode()
            (self.path / name).write_bytes(raw)
            rows.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        record = {
            "schema": "ami-rust-package-candidate-v1",
            "source_commit": source_commit,
            "source_tree": source_tree,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "epoch": 1_800_000_000,
            "original_sdk": {"source_commit": pins["source_commit"]},
            "assets": rows,
        }
        self.record = record
        (self.path / "candidate.json").write_text(
            json.dumps(record, sort_keys=True) + "\n", encoding="utf-8"
        )
        (self.path / "SHA256SUMS").write_text("candidate fixture checksums\n", encoding="ascii")
        self.assets = self.release_assets()

    def release_assets(self) -> list[dict]:
        rows = [{"name": row["path"], "size": row["bytes"], "digest": "sha256:" + row["sha256"]}
                for row in self.record["assets"]]
        for name in ("candidate.json", "SHA256SUMS"):
            raw = (self.path / name).read_bytes()
            rows.append({"name": name, "size": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest()})
        return rows


def recording_api(responses: dict[str, dict]):
    calls: list[tuple[str, str, dict | None, bool]] = []

    def api(path: str, *, method: str = "GET", data: dict | None = None,
            missing: bool = False):
        calls.append((path, method, data, missing))
        if method != "GET" or path not in responses:
            raise AssertionError(f"unexpected API request: {method} {path}")
        return responses[path]

    return api, calls


class ControlTests(unittest.TestCase):
    def requalification_pins(self, **overrides) -> dict:
        identity = {
            "commit": ORIGINAL_COMMIT,
            "tree": ORIGINAL_TREE,
            "epoch": ORIGINAL_EPOCH,
            "run_id": ORIGINAL_RUN_ID,
            "attempt": ORIGINAL_ATTEMPT,
            "candidate_sha256": CANDIDATE_SHA256,
        }
        identity.update(overrides)
        return {
            "schema": "ami-rust-package-requalification-v1",
            "candidate": identity,
            "reason": "Correct the lifecycle controller while retaining the sealed package candidate.",
        }

    def requalification_responses(self, *, pins: dict | None = None,
                                  original_run_changes: dict | None = None,
                                  original_jobs: list | None = None,
                                  controller_compare_changes: dict | None = None,
                                  candidate_compare_changes: dict | None = None,
                                  original_source_changes: dict | None = None,
                                  qualification_jobs: list | None = None) -> dict[str, dict]:
        pins = self.requalification_pins() if pins is None else pins
        encoded_pins = (json.dumps(pins, sort_keys=True) + "\n").encode()
        original_run = {
            "conclusion": "failure", "status": "completed", "event": "workflow_dispatch",
            "head_branch": "main", "path": ".github/workflows/packages.yml@refs/heads/main",
            "repository": {"full_name": REPO}, "run_attempt": ORIGINAL_ATTEMPT,
            "head_sha": ORIGINAL_COMMIT,
        }
        original_run.update(original_run_changes or {})
        original_gate_jobs = ([{"name": name, "conclusion": "failure"
                                if name in (JOB_NAMES[3], JOB_NAMES[4]) else "success"}
                               for name in JOB_NAMES]
                              if original_jobs is None else original_jobs)
        controller_gates = ([{"name": name, "conclusion": "success"}
                             for name in REQUALIFICATION_JOB_NAMES]
                            if qualification_jobs is None else qualification_jobs)
        controller_comparison = {"merge_base_commit": {"sha": CONTROLLER_COMMIT}, "status": "ahead"}
        controller_comparison.update(controller_compare_changes or {})
        candidate_comparison = {"merge_base_commit": {"sha": ORIGINAL_COMMIT}, "status": "ahead"}
        candidate_comparison.update(candidate_compare_changes or {})
        original_source = {"tree": {"sha": ORIGINAL_TREE}, "committer": {"date": ORIGINAL_DATE}}
        original_source.update(original_source_changes or {})
        return {
            f"repos/{REPO}/actions/runs/{REQUALIFICATION_RUN_ID}": {
                "conclusion": "success", "status": "completed", "event": "workflow_dispatch",
                "head_branch": "main",
                "path": ".github/workflows/requalify-packages.yml@refs/heads/main",
                "repository": {"full_name": REPO}, "run_attempt": 1,
                "head_sha": CONTROLLER_COMMIT,
            },
            f"repos/{REPO}/actions/runs/{REQUALIFICATION_RUN_ID}/attempts/1/jobs?per_page=100": {
                "total_count": len(controller_gates), "jobs": controller_gates,
            },
            f"repos/{REPO}/compare/{CONTROLLER_COMMIT}...main": controller_comparison,
            f"repos/{REPO}/contents/packaging/requalification.json?ref={CONTROLLER_COMMIT}": {
                "type": "file", "path": "packaging/requalification.json", "encoding": "base64",
                "size": len(encoded_pins), "content": base64.b64encode(encoded_pins).decode() + "\n",
            },
            f"repos/{REPO}/actions/runs/{ORIGINAL_RUN_ID}": original_run,
            f"repos/{REPO}/actions/runs/{ORIGINAL_RUN_ID}/attempts/{ORIGINAL_ATTEMPT}/jobs?per_page=100": {
                "total_count": len(original_gate_jobs), "jobs": original_gate_jobs,
            },
            f"repos/{REPO}/compare/{ORIGINAL_COMMIT}...{CONTROLLER_COMMIT}": candidate_comparison,
            f"repos/{REPO}/git/commits/{ORIGINAL_COMMIT}": original_source,
        }

    def test_producer_accepts_five_successful_gates_and_exact_attempt_ancestor(self) -> None:
        responses = producer_responses()
        api, calls = recording_api(responses)
        with mock.patch.object(control, "api", side_effect=api):
            result = control.producer(RUN_ID)

        self.assertEqual(result["commit"], COMMIT)
        self.assertEqual(result["tree"], TREE)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["attempt"], ATTEMPT)
        self.assertEqual(result["epoch"], 1_792_238_400)
        self.assertEqual([call[0] for call in calls], list(responses))
        self.assertTrue(all(call[1] == "GET" for call in calls))
        self.assertEqual(calls[1][0], f"repos/{REPO}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100")

    def test_producer_rejects_missing_failed_wrong_ref_and_non_ancestor_gates(self) -> None:
        missing_preflight = [{"name": name, "conclusion": "success"}
                             for name in JOB_NAMES if name != JOB_NAMES[0]]
        failed_qualification = [{"name": name,
                                 "conclusion": "failure" if name == JOB_NAMES[-1] else "success"}
                                for name in JOB_NAMES]
        cases = (
            ("missing host gate", {}, missing_preflight, {}, 2),
            ("failed package gate", {}, failed_qualification, {}, 2),
            ("wrong event", {"event": "push"}, None, {}, 1),
            ("wrong branch/ref", {"head_branch": "feature/channel"}, None, {}, 1),
            ("wrong workflow", {"path": ".github/workflows/ci.yml@refs/heads/main"}, None, {}, 1),
            ("source is no longer an ancestor", {}, None, {"status": "behind"}, 3),
        )
        for label, run_changes, jobs, compare_changes, expected_calls in cases:
            with self.subTest(label=label):
                responses = producer_responses(
                    run_changes=run_changes, jobs=jobs, comparison_changes=compare_changes
                )
                api, calls = recording_api(responses)
                with mock.patch.object(control, "api", side_effect=api):
                    with self.assertRaises(ValueError):
                        control.producer(RUN_ID)
                self.assertEqual(len(calls), expected_calls)
                self.assertTrue(all(method == "GET" for _, method, _, _ in calls))

    def test_requalification_input_accepts_exact_pinned_staged_candidate(self) -> None:
        responses = self.requalification_responses()
        api, calls = recording_api(responses)
        with mock.patch.object(control, "api", side_effect=api):
            result = control.requalification_input(CONTROLLER_COMMIT)

        self.assertEqual(result, {
            "commit": ORIGINAL_COMMIT,
            "tree": ORIGINAL_TREE,
            "epoch": ORIGINAL_EPOCH,
            "run_id": ORIGINAL_RUN_ID,
            "attempt": ORIGINAL_ATTEMPT,
            "candidate_sha256": CANDIDATE_SHA256,
            "newcontroller_source_commit": CONTROLLER_COMMIT,
        })
        self.assertIn(
            (f"repos/{REPO}/contents/packaging/requalification.json?ref={CONTROLLER_COMMIT}",
             "GET", None, False),
            calls,
        )
        self.assertIn(
            (f"repos/{REPO}/actions/runs/{ORIGINAL_RUN_ID}/attempts/{ORIGINAL_ATTEMPT}/jobs?per_page=100",
             "GET", None, False),
            calls,
        )

    def test_requalification_producer_requires_its_five_gates_and_returns_original_identity(self) -> None:
        responses = self.requalification_responses()
        api, calls = recording_api(responses)
        with mock.patch.object(control, "api", side_effect=api):
            result = control.producer(REQUALIFICATION_RUN_ID)
        self.assertEqual(result["run_id"], ORIGINAL_RUN_ID)
        self.assertEqual(result["attempt"], ORIGINAL_ATTEMPT)
        self.assertEqual(result["candidate_sha256"], CANDIDATE_SHA256)
        self.assertEqual(result["qualification_run_id"], REQUALIFICATION_RUN_ID)
        self.assertEqual(result["newcontroller_source_commit"], CONTROLLER_COMMIT)

        missing_auth_gate = [{"name": name, "conclusion": "success"}
                             for name in REQUALIFICATION_JOB_NAMES
                             if name != "Authenticate sealed package candidate"]
        responses = self.requalification_responses(qualification_jobs=missing_auth_gate)
        api, calls = recording_api(responses)
        with mock.patch.object(control, "api", side_effect=api):
            with self.assertRaisesRegex(ValueError, "Authenticate sealed package candidate"):
                control.producer(REQUALIFICATION_RUN_ID)
        self.assertEqual(len(calls), 2)

    def test_requalification_rejects_failed_original_staging_and_identity_mismatches(self) -> None:
        failed_original_jobs = [
            {"name": JOB_NAMES[0], "conclusion": "success"},
            {"name": JOB_NAMES[1], "conclusion": "failure"},
        ]
        cases = (
            ("failed staging", {"original_jobs": failed_original_jobs}, "unsuccessful"),
            ("wrong original source", {"original_run_changes": {"head_sha": "9" * 40}},
             "original producer run identity"),
            ("mutated candidate source pin", {"pins": self.requalification_pins(commit="9" * 40)},
             "original producer run identity"),
            ("wrong original attempt", {"original_run_changes": {"run_attempt": 2}},
             "original producer run identity"),
            ("candidate source is not an ancestor", {"candidate_compare_changes": {"status": "behind"}},
             "not an ancestor"),
            ("tree pin mismatch", {"original_source_changes": {"tree": {"sha": "8" * 40}}},
             "tree and epoch"),
            ("epoch pin mismatch", {"pins": self.requalification_pins(epoch=ORIGINAL_EPOCH + 1)},
             "tree and epoch"),
            ("controller not on main", {"controller_compare_changes": {"status": "behind"}},
             "controller source is no longer an ancestor"),
        )
        for label, options, message in cases:
            with self.subTest(label=label):
                responses = self.requalification_responses(**options)
                api, calls = recording_api(responses)
                with mock.patch.object(control, "api", side_effect=api):
                    with self.assertRaisesRegex(ValueError, message):
                        control.requalification_input(CONTROLLER_COMMIT)

    def test_requalification_rejects_malformed_pins_and_non_package_original_run(self) -> None:
        invalid_pins = (
            self.requalification_pins(commit="not-a-commit"),
            self.requalification_pins(candidate_sha256="xyz"),
        )
        for pins in invalid_pins:
            with self.subTest(pins=pins["candidate"]):
                responses = self.requalification_responses(pins=pins)
                api, _ = recording_api(responses)
                with mock.patch.object(control, "api", side_effect=api):
                    with self.assertRaisesRegex(ValueError, "candidate (commit|identity)"):
                        control.requalification_input(CONTROLLER_COMMIT)

        responses = self.requalification_responses(
            original_run_changes={"path": ".github/workflows/ci.yml@refs/heads/main"}
        )
        api, _ = recording_api(responses)
        with mock.patch.object(control, "api", side_effect=api):
            with self.assertRaisesRegex(ValueError, "original producer run identity"):
                control.requalification_input(CONTROLLER_COMMIT)

        content_path = f"repos/{REPO}/contents/packaging/requalification.json?ref={CONTROLLER_COMMIT}"
        duplicate_json = b'{"schema":"ami-rust-package-requalification-v1",' \
            b'"schema":"ami-rust-package-requalification-v1"}'
        responses = self.requalification_responses()
        responses[content_path]["content"] = base64.b64encode(duplicate_json).decode()
        responses[content_path]["size"] = len(duplicate_json)
        api, _ = recording_api(responses)
        with mock.patch.object(control, "api", side_effect=api):
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                control.requalification_input(CONTROLLER_COMMIT)

        responses = self.requalification_responses()
        responses[content_path]["content"] = " " * (control.MAX_REQUALIFICATION_BASE64_BYTES + 1)
        api, _ = recording_api(responses)
        with mock.patch.object(control, "api", side_effect=api):
            with self.assertRaisesRegex(ValueError, "encoded byte bound"):
                control.requalification_input(CONTROLLER_COMMIT)

    def stable_responses(self, directory: CandidateDirectory, *, tag_sha: str = COMMIT,
                         assets: list[dict] | None = None) -> tuple[dict[str, dict], dict]:
        responses = producer_responses()
        pins = json.loads((_HERE / "pins.json").read_text(encoding="utf-8"))
        tag_ref = f"repos/{REPO}/git/ref/tags/" + quote(pins["packaging_tag"], safe="")
        tag_release = f"repos/{REPO}/releases/tags/" + quote(pins["packaging_tag"], safe="")
        release_path = f"repos/{REPO}/releases/{PACKAGING_RELEASE_ID}"
        release = {
            "id": PACKAGING_RELEASE_ID,
            "draft": False,
            "prerelease": True,
            "assets": directory.assets if assets is None else assets,
        }
        responses[tag_ref] = {"object": {"type": "commit", "sha": tag_sha}}
        responses[tag_release] = release
        responses[release_path] = release
        responses[f"repos/{REPO}/releases/latest"] = {"id": SDK_RELEASE_ID}
        return responses, {"release": release, "release_path": release_path}

    def test_stable_promotion_preserves_sdk_latest_and_marks_packaging_not_latest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = CandidateDirectory(Path(temporary) / "candidate")
            responses, state = self.stable_responses(directory)
            calls: list[tuple[str, str, dict | None, bool]] = []
            current_release = dict(state["release"])

            def api(path: str, *, method: str = "GET", data: dict | None = None,
                    missing: bool = False):
                calls.append((path, method, data, missing))
                if path in producer_responses() and method == "GET":
                    return producer_responses()[path]
                if path == f"repos/{REPO}/git/ref/tags/" + quote(
                        json.loads((_HERE / "pins.json").read_text())["packaging_tag"], safe=""):
                    return responses[path]
                if path == f"repos/{REPO}/releases/tags/" + quote(
                        json.loads((_HERE / "pins.json").read_text())["packaging_tag"], safe=""):
                    return current_release
                if path == state["release_path"] and method == "PATCH":
                    current_release.update(data or {})
                    return current_release
                if path == state["release_path"] and method == "GET":
                    return current_release
                if path == f"repos/{REPO}/releases/latest":
                    return {"id": SDK_RELEASE_ID}
                raise AssertionError(f"unexpected API request: {method} {path}")

            with (
                mock.patch.object(control, "api", side_effect=api),
                mock.patch.object(control.stage, "original_sdk", return_value=SDK_RELEASE_ID) as original_sdk,
            ):
                result = control.stable(directory.path, RUN_ID)

        self.assertEqual(result["status"], "PASS_STABLE_PACKAGING_NOT_APT_ACCEPTANCE")
        self.assertEqual(result["release_id"], PACKAGING_RELEASE_ID)
        self.assertEqual(result["commit"], COMMIT)
        original_sdk.assert_called_once()
        patches = [(path, data) for path, method, data, _ in calls if method == "PATCH"]
        self.assertEqual(patches, [
            (f"repos/{REPO}/releases/{PACKAGING_RELEASE_ID}",
             {"prerelease": False, "make_latest": "false"}),
        ])
        self.assertEqual(current_release["prerelease"], False)
        self.assertTrue(any(path == f"repos/{REPO}/releases/latest" for path, *_ in calls))
        self.assertFalse(any(method == "PATCH" and path != state["release_path"]
                             for path, method, _, _ in calls))

    def test_stable_rejects_candidate_tag_and_asset_mismatches_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            wrong_candidate = CandidateDirectory(root / "wrong-candidate", source_commit="f" * 40)
            responses, _ = self.stable_responses(wrong_candidate)
            api, calls = recording_api(responses)
            with (
                mock.patch.object(control, "api", side_effect=api),
                mock.patch.object(control.stage, "original_sdk", return_value=SDK_RELEASE_ID) as original_sdk,
            ):
                with self.assertRaisesRegex(ValueError, "candidate differs from qualified producer"):
                    control.stable(wrong_candidate.path, RUN_ID)
            original_sdk.assert_not_called()
            self.assertTrue(all(method == "GET" for _, method, _, _ in calls))

            wrong_tag = CandidateDirectory(root / "wrong-tag")
            responses, _ = self.stable_responses(wrong_tag, tag_sha="d" * 40)
            api, calls = recording_api(responses)
            with (
                mock.patch.object(control, "api", side_effect=api),
                mock.patch.object(control.stage, "original_sdk", return_value=SDK_RELEASE_ID) as original_sdk,
            ):
                with self.assertRaisesRegex(ValueError, "packaging tag differs"):
                    control.stable(wrong_tag.path, RUN_ID)
            original_sdk.assert_called_once()
            self.assertFalse(any(method == "PATCH" for _, method, _, _ in calls))

            wrong_asset_set = CandidateDirectory(root / "wrong-asset-set")
            altered_assets = wrong_asset_set.assets[:-1]
            responses, _ = self.stable_responses(wrong_asset_set, assets=altered_assets)
            api, calls = recording_api(responses)
            with (
                mock.patch.object(control, "api", side_effect=api),
                mock.patch.object(control.stage, "original_sdk", return_value=SDK_RELEASE_ID) as original_sdk,
            ):
                with self.assertRaisesRegex(ValueError, "release asset set differs"):
                    control.stable(wrong_asset_set.path, RUN_ID)
            original_sdk.assert_called_once()
            self.assertFalse(any(method == "PATCH" for _, method, _, _ in calls))

    def dispatch_responses(self, *, installation: dict | None = None,
                           workflow_state: str = "active", run_id: int = 77001) -> dict[str, dict]:
        return {
            "installation/repositories": installation or {
                "total_count": 1, "repositories": [{"full_name": ARCHIVE}],
            },
            f"repos/{ARCHIVE}/actions/workflows/publish.yml": {"state": workflow_state},
            f"repos/{ARCHIVE}/git/ref/heads/main": {"object": {"sha": COMMIT}},
            f"repos/{ARCHIVE}/actions/workflows/publish.yml/dispatches": {
                "workflow_run_id": run_id,
            },
        }

    def test_dispatch_uses_scoped_app_active_workflow_and_exact_returned_run(self) -> None:
        responses = self.dispatch_responses()
        run_path = f"repos/{ARCHIVE}/actions/runs/77001"
        queued = {"head_sha": COMMIT, "event": "workflow_dispatch", "head_branch": "main",
                  "status": "queued", "conclusion": None}
        completed = {**queued, "status": "completed", "conclusion": "success",
                     "html_url": "https://github.com/metaneutrons/apt-archive/actions/runs/77001"}
        calls: list[tuple[str, str, dict | None, bool]] = []
        poll_count = 0

        def api(path: str, *, method: str = "GET", data: dict | None = None,
                missing: bool = False):
            nonlocal poll_count
            calls.append((path, method, data, missing))
            if method == "POST":
                self.assertEqual(path, f"repos/{ARCHIVE}/actions/workflows/publish.yml/dispatches")
                self.assertEqual(data, {
                    "ref": "main",
                    "inputs": {"domain": "metaneutrons.cc", "project": "ami-rust"},
                    "return_run_details": True,
                })
                return responses[path]
            if path == run_path:
                poll_count += 1
                return queued if poll_count == 1 else completed
            if path not in responses:
                raise AssertionError(f"unexpected API request: {method} {path}")
            return responses[path]

        with (
            mock.patch.object(control, "api", side_effect=api),
            mock.patch.object(control.time, "monotonic", return_value=1_000.0),
            mock.patch.object(control.time, "sleep") as sleep,
        ):
            result = control.dispatch_archive()

        self.assertEqual(result["status"], "PASS_SHARED_ARCHIVE_PUBLICATION_NOT_CLIENT_ACCEPTANCE")
        self.assertEqual(result["run_id"], 77001)
        self.assertEqual(result["source_commit"], COMMIT)
        self.assertEqual(result["url"], completed["html_url"])
        self.assertEqual(sleep.call_args_list, [mock.call(60)])
        self.assertEqual([path for path, *_ in calls if "/actions/runs/" in path], [run_path, run_path])
        dispatch_call = next(call for call in calls if call[1] == "POST")
        self.assertEqual(dispatch_call[2]["return_run_details"], True)

    def test_dispatch_rejects_scope_failure_and_raced_or_failed_runs(self) -> None:
        cases = (
            ("unscoped app", {"total_count": 2, "repositories": [
                {"full_name": ARCHIVE}, {"full_name": "metaneutrons/ami-rust"},
            ]}, "active", None, "not restricted"),
            ("inactive workflow", None, "disabled", None, "not active"),
            ("raced source", None, "active", {
                "head_sha": "e" * 40, "event": "workflow_dispatch", "head_branch": "main",
                "status": "in_progress", "conclusion": None,
            }, "identity changed"),
            ("failed run", None, "active", {
                "head_sha": COMMIT, "event": "workflow_dispatch", "head_branch": "main",
                "status": "completed", "conclusion": "failure",
            }, "publication failed"),
        )
        for label, installation, state, run_override, message in cases:
            with self.subTest(label=label):
                responses = self.dispatch_responses(installation=installation, workflow_state=state)
                run_path = f"repos/{ARCHIVE}/actions/runs/77001"
                calls: list[tuple[str, str, dict | None, bool]] = []

                def api(path: str, *, method: str = "GET", data: dict | None = None,
                        missing: bool = False):
                    calls.append((path, method, data, missing))
                    if path == "installation/repositories":
                        return responses[path]
                    if path.endswith("/actions/workflows/publish.yml") and method == "GET":
                        return responses[path]
                    if path == f"repos/{ARCHIVE}/git/ref/heads/main":
                        return responses[path]
                    if method == "POST":
                        return responses[path]
                    if path == run_path and run_override is not None:
                        return run_override
                    raise AssertionError(f"unexpected API request: {method} {path}")

                with (
                    mock.patch.object(control, "api", side_effect=api),
                    mock.patch.object(control.time, "monotonic", return_value=1_000.0),
                    mock.patch.object(control.time, "sleep") as sleep,
                ):
                    with self.assertRaisesRegex(ValueError, message):
                        control.dispatch_archive()
                self.assertFalse(any(method == "PATCH" for _, method, _, _ in calls))
                if label in ("unscoped app", "inactive workflow"):
                    self.assertFalse(any(method == "POST" for _, method, _, _ in calls))
                else:
                    self.assertTrue(any(method == "POST" for _, method, _, _ in calls))
                    self.assertEqual(sleep.call_count, 0)


if __name__ == "__main__":
    unittest.main()

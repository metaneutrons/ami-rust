#!/usr/bin/env python3
"""Offline tests for immutable package-release staging gates."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from urllib.parse import quote
from unittest import mock


_STAGE_PATH = Path(__file__).with_name("stage.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_package_stage_test", _STAGE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
stage = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(stage)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pins_fixture() -> dict:
    source_assets = {
        "SHA256SUMS": b"SDK checksums\n",
        "ami-rust-0.1.0-release.tar.xz": b"SDK archive\n",
        "ami-rust-0.1.0-release.tar.xz.sigstore.json": b"SDK archive bundle\n",
        "ami-rust-0.1.0-release.tar.xz.spdx.json": b"SDK SBOM\n",
        "ami-rust-0.1.0-transport.json": b"SDK transport\n",
        "ami-rust-0.1.0-transport.json.sigstore.json": b"SDK transport bundle\n",
    }
    return {
        "schema": "ami-rust-package-inputs-v1",
        "repository": "metaneutrons/ami-rust",
        "sdk_version": "0.1.0",
        "sdk_tag": "v0.1.0",
        "packaging_revision": 1,
        "package_version": "0.1.0-1",
        "packaging_tag": "v0.1.0+packaging.1",
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "sdk_run_id": 1001,
        "sdk_run_attempt": 1,
        "manifest_sha256": "c" * 64,
        "transport_sha256": digest(source_assets["ami-rust-0.1.0-transport.json"]),
        "assets": [
            {"path": name, "bytes": len(raw), "sha256": digest(raw)}
            for name, raw in sorted(source_assets.items())
        ],
    }


def package_names(pins: dict) -> list[str]:
    archive = f"ami-rust-{pins['sdk_version']}-packaging.{pins['packaging_revision']}.tar.xz"
    deb = f"ami-rust_{pins['package_version']}_amd64.deb"
    payloads = (archive, deb)
    return sorted([
        *payloads,
        *(name + ".spdx.json" for name in payloads),
        "ami-rust.rb", "packaging-report.json", "metadata-report.json",
        *(name + ".sigstore.json" for name in payloads),
        "ami-rust.rb.sigstore.json",
    ])


def package_fixture(root: Path, pins: dict) -> tuple[Path, dict[str, bytes], str]:
    directory = root / "candidate"
    directory.mkdir(parents=True)
    source_commit = "e" * 40
    data = {name: ("candidate bytes:" + name + "\n").encode() for name in package_names(pins)}
    rows = [{"path": name, "bytes": len(raw), "sha256": digest(raw)}
            for name, raw in sorted(data.items())]
    record = {
        "schema": "ami-rust-package-candidate-v1",
        "source_commit": source_commit,
        "source_tree": "f" * 40,
        "run_id": 2002,
        "run_attempt": 3,
        "epoch": 1_800_000_000,
        "original_sdk": {"source_commit": pins["source_commit"]},
        "assets": rows,
    }
    data["candidate.json"] = json.dumps(record, sort_keys=True).encode() + b"\n"
    data["SHA256SUMS"] = b"fixture checksum inventory\n"
    for name, raw in data.items():
        (directory / name).write_bytes(raw)
    return directory, data, source_commit


def sdk_release(pins: dict) -> dict:
    return {
        "id": 41,
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": row["path"], "size": row["bytes"], "digest": "sha256:" + row["sha256"]}
            for row in pins["assets"]
        ],
    }


class AssetSetTests(unittest.TestCase):
    def test_original_release_requires_exact_six_sdk_assets_and_digests(self) -> None:
        pins = pins_fixture()
        expected = {row["path"]: row for row in pins["assets"]}
        release = sdk_release(pins)
        stage.verify_assets(release, expected)

        cases = []
        wrong_digest = {**release, "assets": [dict(row) for row in release["assets"]]}
        wrong_digest["assets"][0]["digest"] = "sha256:" + "0" * 64
        cases.append(wrong_digest)
        cases.append({**release, "assets": release["assets"][:-1]})
        cases.append({**release, "assets": release["assets"] + [{
            "name": "unexpected.asset", "size": 1, "digest": "sha256:" + "1" * 64,
        }]})
        for candidate_release in cases:
            with self.subTest(assets=len(candidate_release["assets"])):
                with self.assertRaises(ValueError):
                    stage.verify_assets(candidate_release, expected)


class StagePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.pins = pins_fixture()
        self.directory, self.data, self.source_commit = package_fixture(self.root, self.pins)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_wrong_original_sdk_reference_stops_before_any_write_or_upload(self) -> None:
        receipt = self.root / "receipt.json"
        api_calls = []

        def api(path, *, method="GET", data=None, missing=False):
            api_calls.append((path, method, data))
            return {"object": {"type": "commit", "sha": "9" * 40}}

        with (
            mock.patch.object(stage, "api", side_effect=api),
            mock.patch.object(stage.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(ValueError, "original SDK tag"):
                stage.run(self.directory, self.pins, Path("/fixture/gh"), receipt)

        run.assert_not_called()
        self.assertEqual(len(api_calls), 1)
        self.assertEqual(api_calls[0][1], "GET")
        self.assertFalse(receipt.exists())
        self.assertFalse((self.root / "draft-readback").exists())

    def test_existing_asset_collision_stops_before_upload_or_patch(self) -> None:
        receipt = self.root / "collision-receipt.json"
        api_calls = []
        expected_name = package_names(self.pins)[0]
        release_ref = "repos/metaneutrons/ami-rust/git/ref/tags/v0.1.0%2Bpackaging.1"
        release_endpoint = "repos/metaneutrons/ami-rust/releases/tags/v0.1.0%2Bpackaging.1"
        release_list = "repos/metaneutrons/ami-rust/releases?per_page=100&page=1"
        release_by_id = "repos/metaneutrons/ami-rust/releases/52"

        def api(path, *, method="GET", data=None, missing=False):
            api_calls.append((path, method))
            if path.endswith("/git/ref/tags/v0.1.0"):
                return {"object": {"type": "commit", "sha": self.pins["source_commit"]}}
            if path.endswith("/releases/tags/v0.1.0"):
                return sdk_release(self.pins)
            if path == release_ref:
                return {"object": {"type": "commit", "sha": self.source_commit}}
            if path == release_endpoint:
                return None
            if path == release_list:
                return [{"id": 52, "tag_name": self.pins["packaging_tag"],
                         "draft": True, "prerelease": True, "assets": [{
                    "name": expected_name, "size": 999, "digest": "sha256:" + "0" * 64,
                }]}]
            if path == release_by_id:
                return {"id": 52, "tag_name": self.pins["packaging_tag"],
                        "draft": True, "prerelease": True, "assets": [{
                            "name": expected_name, "size": 999,
                            "digest": "sha256:" + "0" * 64,
                        }]}
            self.fail(f"unexpected preflight call: {method} {path}")

        with (
            mock.patch.object(stage, "api", side_effect=api),
            mock.patch.object(stage.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(ValueError, "existing asset collision"):
                stage.run(self.directory, self.pins, Path("/fixture/gh"), receipt)

        run.assert_not_called()
        self.assertTrue(all(method == "GET" for _path, method in api_calls))
        self.assertNotIn(("repos/metaneutrons/ami-rust/git/refs", "POST"), api_calls)
        self.assertNotIn(("repos/metaneutrons/ami-rust/releases", "POST"), api_calls)
        self.assertFalse(receipt.exists())
        self.assertFalse((self.root / "draft-readback").exists())

    def test_truncated_release_list_refuses_creation(self) -> None:
        receipt = self.root / "truncated-receipt.json"
        api_calls = []
        release_endpoint = "repos/metaneutrons/ami-rust/releases/tags/v0.1.0%2Bpackaging.1"
        release_list = "repos/metaneutrons/ami-rust/releases?per_page=100&page=1"

        def api(path, *, method="GET", data=None, missing=False):
            api_calls.append((path, method))
            if path.endswith("/git/ref/tags/v0.1.0"):
                return {"object": {"type": "commit", "sha": self.pins["source_commit"]}}
            if path.endswith("/releases/tags/v0.1.0"):
                return sdk_release(self.pins)
            if path == "repos/metaneutrons/ami-rust/git/ref/tags/v0.1.0%2Bpackaging.1":
                return None
            if path == release_endpoint:
                return None
            if path == release_list:
                return [{"id": 100 + index, "tag_name": f"other-{index}"}
                        for index in range(stage.RELEASES_PER_PAGE)]
            self.fail(f"unexpected API call: {method} {path}")

        with (
            mock.patch.object(stage, "api", side_effect=api),
            mock.patch.object(stage, "MAX_RELEASE_PAGES", 1),
            mock.patch.object(stage.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(ValueError, "release list is truncated"):
                stage.run(self.directory, self.pins, Path("/fixture/gh"), receipt)

        run.assert_not_called()
        self.assertTrue(all(method == "GET" for _path, method in api_calls))
        self.assertNotIn(("repos/metaneutrons/ami-rust/git/refs", "POST"), api_calls)
        self.assertNotIn(("repos/metaneutrons/ami-rust/releases", "POST"), api_calls)
        self.assertFalse(receipt.exists())

    def test_duplicate_listed_tag_refuses_ambiguous_recovery(self) -> None:
        receipt = self.root / "duplicate-tag-receipt.json"
        api_calls = []
        release_endpoint = "repos/metaneutrons/ami-rust/releases/tags/v0.1.0%2Bpackaging.1"
        release_list = "repos/metaneutrons/ami-rust/releases?per_page=100&page=1"
        listed = [
            {"id": release_id, "tag_name": self.pins["packaging_tag"],
             "draft": True, "prerelease": True, "assets": []}
            for release_id in (52, 53)
        ]

        def api(path, *, method="GET", data=None, missing=False):
            api_calls.append((path, method))
            if path.endswith("/git/ref/tags/v0.1.0"):
                return {"object": {"type": "commit", "sha": self.pins["source_commit"]}}
            if path.endswith("/releases/tags/v0.1.0"):
                return sdk_release(self.pins)
            if path == "repos/metaneutrons/ami-rust/git/ref/tags/v0.1.0%2Bpackaging.1":
                return {"object": {"type": "commit", "sha": self.source_commit}}
            if path == release_endpoint:
                return None
            if path == release_list:
                return listed
            self.fail(f"unexpected API call: {method} {path}")

        with (
            mock.patch.object(stage, "api", side_effect=api),
            mock.patch.object(stage.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(ValueError, "multiple GitHub releases"):
                stage.run(self.directory, self.pins, Path("/fixture/gh"), receipt)

        run.assert_not_called()
        self.assertTrue(all(method == "GET" for _path, method in api_calls))
        self.assertNotIn(("repos/metaneutrons/ami-rust/git/refs", "POST"), api_calls)
        self.assertNotIn(("repos/metaneutrons/ami-rust/releases", "POST"), api_calls)
        self.assertFalse(receipt.exists())

    def test_complete_stage_checks_private_and_anonymous_public_readback(self) -> None:
        receipt = self.root / "stage-receipt.json"
        pins = dict(self.pins)
        pins.update({"packaging_revision": 2, "package_version": "0.1.0-2",
                     "packaging_tag": "v0.1.0+packaging.2"})
        fixture_root = self.root / "revision-two"
        fixture_root.mkdir()
        directory, data, source_commit = package_fixture(fixture_root, pins)
        sdk = sdk_release(pins)
        encoded_tag = quote(pins["packaging_tag"], safe="")
        release_ref = f"repos/metaneutrons/ami-rust/git/ref/tags/{encoded_tag}"
        release_endpoint = f"repos/metaneutrons/ami-rust/releases/tags/{encoded_tag}"
        release_list = "repos/metaneutrons/ami-rust/releases?per_page=100&page=1"
        release_by_id = "repos/metaneutrons/ami-rust/releases/52"
        release_state: dict | None = None
        tag_exists = False
        api_calls: list[tuple[str, str, dict | None]] = []
        uploads: list[list[str]] = []
        public_requests: list[tuple[str, int]] = []
        public_content = {"https://fixture.invalid/" + name: raw for name, raw in data.items()}

        def api(path, *, method="GET", data=None, missing=False):
            nonlocal release_state, tag_exists
            api_calls.append((path, method, data))
            if path.endswith("/git/ref/tags/v0.1.0"):
                return {"object": {"type": "commit", "sha": pins["source_commit"]}}
            if path.endswith("/releases/tags/v0.1.0"):
                return sdk
            if path == release_ref:
                return ({"object": {"type": "commit", "sha": self.source_commit}}
                        if tag_exists else None)
            if path == release_endpoint:
                return None
            if path == release_list:
                return []
            if path == "repos/metaneutrons/ami-rust/git/refs" and method == "POST":
                tag_exists = True
                return {"ref": data["ref"]}
            if path == "repos/metaneutrons/ami-rust/releases" and method == "POST":
                release_state = {"id": 52, "tag_name": pins["packaging_tag"],
                                 "draft": True, "prerelease": True, "assets": []}
                return release_state
            if path == release_by_id and method == "GET":
                return release_state
            if path == release_by_id and method == "PATCH":
                release_state = {**release_state, **data}
                return release_state
            if path == "repos/metaneutrons/ami-rust/releases/latest":
                return sdk
            self.fail(f"unexpected API call: {method} {path}")

        def run(command, *, check, timeout):
            command = [str(value) for value in command]
            if command[1:3] == ["release", "upload"]:
                uploaded = command[6:]
                uploads.append([Path(name).name for name in uploaded])
                release_state["assets"] = [
                    {"name": name, "size": len(raw), "digest": "sha256:" + digest(raw),
                     "browser_download_url": "https://fixture.invalid/" + name}
                    for name, raw in sorted(data.items())
                ]
            elif command[1:3] == ["release", "download"]:
                target = Path(command[command.index("--dir") + 1])
                for name, raw in data.items():
                    (target / name).write_bytes(raw)
            else:
                self.fail(f"unexpected GH command: {command}")
            return SimpleNamespace(returncode=0)

        def open_url(url, *, timeout):
            public_requests.append((url, timeout))
            return io.BytesIO(public_content[url])

        with (
            mock.patch.object(stage, "api", side_effect=api),
            mock.patch.object(stage.subprocess, "run", side_effect=run),
            mock.patch.object(stage, "urlopen", side_effect=open_url),
        ):
            stage.run(directory, pins, Path("/fixture/gh"), receipt)

        self.assertEqual(uploads, [sorted(data)])
        readback = self.root / "draft-readback"
        self.assertEqual(readback.stat().st_mode & 0o777, 0o700)
        self.assertEqual({path.name for path in readback.iterdir()}, set(data))
        self.assertEqual({(path.name, path.read_bytes()) for path in readback.iterdir()}, set(data.items()))
        self.assertEqual({url for url, timeout in public_requests}, set(public_content))
        self.assertTrue(all(timeout == 180 for _url, timeout in public_requests))
        receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(receipt_value["status"], "PASS_PUBLIC_PACKAGING_STAGE_NOT_CHANNEL_ACCEPTANCE")
        self.assertEqual(receipt_value["source_commit"], source_commit)
        self.assertTrue(receipt_value["original_sdk_unchanged"])
        writes = [(path, method) for path, method, _data in api_calls if method != "GET"]
        self.assertEqual(writes, [
            ("repos/metaneutrons/ami-rust/git/refs", "POST"),
            ("repos/metaneutrons/ami-rust/releases", "POST"),
            (release_by_id, "PATCH"),
        ])
        self.assertGreaterEqual(sum(path == release_by_id and method == "GET"
                                    for path, method, _data in api_calls), 3)
        self.assertEqual(sum(path == release_endpoint for path, _method, _data in api_calls), 1)
        created = next(data for path, method, data in api_calls
                       if path == "repos/metaneutrons/ami-rust/releases" and method == "POST")
        self.assertEqual(created["tag_name"], "v0.1.0+packaging.2")
        self.assertEqual(created["name"], "ami-rust 0.1.0 — APT and Homebrew packaging 2")

    def test_existing_public_release_uses_its_id_without_reupload_or_patch(self) -> None:
        receipt = self.root / "existing-public-receipt.json"
        sdk = sdk_release(self.pins)
        release_ref = "repos/metaneutrons/ami-rust/git/ref/tags/v0.1.0%2Bpackaging.1"
        release_endpoint = "repos/metaneutrons/ami-rust/releases/tags/v0.1.0%2Bpackaging.1"
        release_by_id = "repos/metaneutrons/ami-rust/releases/52"
        api_calls = []
        gh_commands = []
        public_requests = []
        public_content = {"https://fixture.invalid/" + name: raw for name, raw in self.data.items()}
        public_release = {
            "id": 52,
            "tag_name": self.pins["packaging_tag"],
            "draft": False,
            "prerelease": True,
            "assets": [
                {"name": name, "size": len(raw), "digest": "sha256:" + digest(raw),
                 "browser_download_url": "https://fixture.invalid/" + name}
                for name, raw in sorted(self.data.items())
            ],
        }

        def api(path, *, method="GET", data=None, missing=False):
            api_calls.append((path, method, data))
            if path.endswith("/git/ref/tags/v0.1.0"):
                return {"object": {"type": "commit", "sha": self.pins["source_commit"]}}
            if path.endswith("/releases/tags/v0.1.0"):
                return sdk
            if path == release_ref:
                return {"object": {"type": "commit", "sha": self.source_commit}}
            if path == release_endpoint or path == release_by_id:
                return public_release
            if path == "repos/metaneutrons/ami-rust/releases/latest":
                return sdk
            self.fail(f"unexpected API call: {method} {path}")

        def run(command, *, check, timeout):
            command = [str(value) for value in command]
            gh_commands.append(command)
            if command[1:3] != ["release", "download"]:
                self.fail(f"unexpected GH command: {command}")
            target = Path(command[command.index("--dir") + 1])
            for name, raw in self.data.items():
                (target / name).write_bytes(raw)
            return SimpleNamespace(returncode=0)

        def open_url(url, *, timeout):
            public_requests.append((url, timeout))
            return io.BytesIO(public_content[url])

        with (
            mock.patch.object(stage, "api", side_effect=api),
            mock.patch.object(stage.subprocess, "run", side_effect=run),
            mock.patch.object(stage, "urlopen", side_effect=open_url),
        ):
            stage.run(self.directory, self.pins, Path("/fixture/gh"), receipt)

        self.assertEqual(len(gh_commands), 1)
        self.assertEqual(gh_commands[0][1:3], ["release", "download"])
        self.assertEqual({url for url, _timeout in public_requests}, set(public_content))
        self.assertTrue(all(path != "repos/metaneutrons/ami-rust/releases"
                            or method != "POST" for path, method, _data in api_calls))
        self.assertTrue(all(method != "PATCH" for _path, method, _data in api_calls))
        self.assertFalse(any(path.startswith("repos/metaneutrons/ami-rust/releases?")
                             for path, _method, _data in api_calls))
        self.assertTrue(any(path == release_by_id for path, method, _data in api_calls
                            if method == "GET"))
        self.assertEqual(json.loads(receipt.read_text())["status"],
                         "PASS_PUBLIC_PACKAGING_STAGE_NOT_CHANNEL_ACCEPTANCE")


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Isolated draft/readback probes. No provider requests or public writes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_candidate
import stage_draft

SOURCE = "a" * 40
TAG = "v0.1.0"


class FakeGitHub:
    def __init__(self):
        self.draft = True
        self.source = SOURCE
        self.permissions = True
        self.files = {}
        self.uploads = []
        self.corrupt_download = False
        self.change_draft_after_upload = False

    def json(self, endpoint, *, paginate=False):
        if endpoint == stage_draft.API:
            return {"permissions": {"push": self.permissions}}
        if endpoint == stage_draft.API + "/git/ref/tags/" + TAG:
            return {"object": {"type": "commit", "sha": self.source}}
        if endpoint == stage_draft.API + "/releases/tags/" + TAG:
            return {"id": 42, "tag_name": TAG, "draft": self.draft}
        if endpoint == stage_draft.API + "/releases/42/assets?per_page=100":
            if not paginate:
                raise AssertionError("asset inventory must include all pages")
            return [[{"id": i + 1, "name": name, "state": "uploaded", "size": len(data),
                      "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
                     for i, (name, data) in enumerate(sorted(self.files.items()))]]
        raise AssertionError("unexpected provider request: " + endpoint)

    def upload(self, tag, path):
        if tag != TAG or path.name in self.files:
            raise AssertionError("wrong tag or attempted clobber")
        self.files[path.name] = path.read_bytes()
        self.uploads.append(path.name)
        if self.change_draft_after_upload:
            self.draft = False

    def download(self, asset_id, destination, expected_bytes):
        data = sorted(self.files.items())[asset_id - 1][1]
        if self.corrupt_download:
            data = bytes([data[0] ^ 1]) + data[1:]
        destination.write_bytes(data)


class DraftTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        raw = b'{"spdxVersion":"SPDX-2.3","name":"fixture"}\n'
        (self.bundle / "sbom.spdx.json").write_bytes(raw)
        manifest = {"schema": "ami-rust-release-v1", "version": "0.1.0",
                    "qualification_only": False, "producer": {"source_sha": SOURCE},
                    "assets": [{"path": "sbom.spdx.json", "bytes": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest()}]}
        (self.bundle / "release.json").write_text(json.dumps(manifest))
        self.candidate = self.root / "candidate"
        stage_candidate.prepare(TAG, self.bundle, self.candidate)
        names = stage_candidate.asset_names(TAG)
        for key in ("payload_signature", "transport_signature"):
            (self.candidate / names[key]).write_text('{"fixture":"not a real signature"}\n')
        stage_candidate.finalize(self.candidate, TAG)
        self.github = FakeGitHub()
        self.readback = self.root / "readback"

    def execute(self):
        return stage_draft.stage(self.github, TAG, SOURCE, self.candidate, self.readback)

    def test_upload_and_complete_byte_readback(self):
        result = self.execute()
        self.assertEqual(result["status"], "DRAFT_BYTES_STAGED_NOT_PUBLISHED_NOT_CRYPTO_VERIFIED")
        self.assertEqual(len(self.github.uploads), 6)
        self.assertEqual({p.name: p.read_bytes() for p in self.readback.iterdir()}, self.github.files)

    def test_matching_partial_draft_resumes_without_clobber(self):
        path = self.candidate / stage_candidate.asset_names(TAG)["checksums"]
        self.github.files[path.name] = path.read_bytes()
        self.execute()
        self.assertEqual(len(self.github.uploads), 5)
        self.assertNotIn(path.name, self.github.uploads)

    def test_published_release_refuses_all_uploads(self):
        self.github.draft = False
        with self.assertRaisesRegex(ValueError, "existing draft"):
            self.execute()
        self.assertEqual(self.github.uploads, [])

    def test_wrong_tag_target_refuses_all_uploads(self):
        self.github.source = "b" * 40
        with self.assertRaisesRegex(ValueError, "tag target"):
            self.execute()
        self.assertEqual(self.github.uploads, [])

    def test_candidate_source_must_match_external_source_even_before_provider_access(self):
        with self.assertRaisesRegex(ValueError, "candidate publisher source differs"):
            stage_draft.stage(self.github, TAG, "b" * 40, self.candidate, self.readback)
        self.assertEqual(self.github.uploads, [])

    def test_missing_write_access_refuses_all_uploads(self):
        self.github.permissions = False
        with self.assertRaisesRegex(ValueError, "push permission"):
            self.execute()
        self.assertEqual(self.github.uploads, [])

    def test_extra_remote_asset_refuses_all_uploads(self):
        self.github.files["unreviewed.txt"] = b"extra"
        with self.assertRaisesRegex(ValueError, "asset set"):
            self.execute()
        self.assertEqual(self.github.uploads, [])

    def test_modified_existing_asset_refuses_all_uploads(self):
        self.github.files[stage_candidate.asset_names(TAG)["payload"]] = b"changed"
        with self.assertRaisesRegex(ValueError, "existing draft asset differs"):
            self.execute()
        self.assertEqual(self.github.uploads, [])

    def test_corrupted_actual_download_fails_despite_matching_api_digest(self):
        self.github.corrupt_download = True
        with self.assertRaisesRegex(ValueError, "downloaded draft bytes differ"):
            self.execute()

    def test_draft_identity_rechecked_before_every_upload(self):
        self.github.change_draft_after_upload = True
        with self.assertRaisesRegex(ValueError, "existing draft"):
            self.execute()
        self.assertEqual(len(self.github.uploads), 1)

    def test_altered_local_candidate_never_uploads(self):
        (self.candidate / stage_candidate.asset_names(TAG)["payload"]).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.github.uploads, [])

    def test_existing_readback_refuses_all_uploads(self):
        self.readback.mkdir()
        with self.assertRaisesRegex(ValueError, "fresh independent"):
            self.execute()
        self.assertEqual(self.github.uploads, [])

    def test_receipt_equal_to_readback_is_rejected_before_work(self):
        with self.assertRaisesRegex(ValueError, "outside candidate/readback"):
            stage_draft.receipt_path(self.readback, self.candidate, self.readback)
        receipt = self.root / "receipt.json"
        self.assertEqual(stage_draft.receipt_path(receipt, self.candidate, self.readback), receipt)


class DownloadBoundTests(unittest.TestCase):
    def test_provider_hostname_is_explicit_even_with_ambient_enterprise_host(self):
        github = stage_draft.GitHub.__new__(stage_draft.GitHub)
        github.executable = Path("/trusted/gh")
        with mock.patch.dict("os.environ", {"GH_HOST": "other.example"}), mock.patch.object(
                stage_draft.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}")) as command:
            github.json(stage_draft.API)
            self.assertEqual(command.call_args.args[0][2:4], ["--hostname", "github.com"])
            github.upload(TAG, Path("/candidate/file"))
            self.assertEqual(command.call_args.args[0][-2:], ["--repo", "github.com/" + stage_draft.REPOSITORY])

    def test_pinned_tool_mismatch_fails_before_provider_access(self):
        with self.assertRaisesRegex(ValueError, "GH executable differs"):
            stage_draft.GitHub(Path(sys.executable).resolve(), "macos-aarch64")

    def probe(self, data, size):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fake-gh"
            executable.write_text("#!" + sys.executable + "\nimport sys\nsys.stdout.buffer.write(" + repr(data) + ")\n")
            executable.chmod(0o700)
            github = stage_draft.GitHub.__new__(stage_draft.GitHub)
            github.executable = executable
            output = root / "download"
            try:
                github.download(1, output, size)
            except subprocess.CalledProcessError:
                self.assertLessEqual(output.stat().st_size, size)
                raise
            return output.read_bytes()

    def test_binary_escape_bytes_are_preserved(self):
        self.assertEqual(self.probe(b"\x1babc", 4), b"\x1babc")

    def test_provider_stream_cannot_exceed_exact_asset_size(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.probe(b"12345", 4)


if __name__ == "__main__":
    unittest.main()

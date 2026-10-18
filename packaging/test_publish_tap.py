#!/usr/bin/env python3
"""Offline API-fixture tests for the tap publication guard and merge flow."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from urllib.parse import parse_qs, unquote, urlsplit
from unittest import mock


_PATH = Path(__file__).with_name("publish_tap.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_publish_tap_test", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
publish_tap = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(publish_tap)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class FakeGitHub:
    def __init__(self, formula: bytes, readme: bytes, *, scope: list[str] | None = None,
                 protected: bool = True, failed_check: bool = False,
                 wrong_readback: bool = False, changed_head: bool = False) -> None:
        self.formula = formula
        self.readme = readme
        self.main_sha = "a" * 40
        self.main_tree = "b" * 40
        self.head_sha = "c" * 40
        self.tree_sha = "e" * 40
        self.merge_sha = "d" * 40
        self.branch_name = publish_tap._branch_name(publish_tap._load_pins())
        self.main_files = {"README.md": readme}
        self.branch_files: dict[str, bytes] = {}
        self.branch_exists = False
        self.pr: dict[str, object] | None = None
        self.scope = scope or [publish_tap.TAP_REPOSITORY]
        self.protected = protected
        self.failed_check = failed_check
        self.wrong_readback = wrong_readback
        self.changed_head = changed_head
        self.merge_calls = 0
        self.tree_entries: list[dict[str, object]] = []
        self.commit_message: str | None = None
        self.pull_request_title: str | None = None
        self.merge_title: str | None = None

    def _pull(self, *, head_sha: str | None = None) -> dict[str, object]:
        sha_value = head_sha or self.head_sha
        return {
            "number": 17,
            "html_url": "https://github.com/metaneutrons/homebrew-tap/pull/17",
            "state": "open",
            "merged": False,
            "draft": False,
            "mergeable": True,
            "mergeable_state": "clean",
            "head": {"ref": self.branch_name, "sha": sha_value,
                     "repo": {"full_name": publish_tap.TAP_REPOSITORY}},
            "base": {"ref": "main", "sha": self.main_sha,
                     "repo": {"full_name": publish_tap.TAP_REPOSITORY}},
        }

    def __call__(self, path: str, *, method: str = "GET", data: object | None = None,
                 missing: bool = False) -> object | None:
        route = path.split("?", 1)[0]
        if route == "installation/repositories":
            repositories = [{"full_name": value} for value in self.scope]
            return {"total_count": len(repositories), "repositories": repositories}
        if route == "users/metaneutrons-homebrew%5Bbot%5D":
            return {"login": "metaneutrons-homebrew[bot]", "id": 999, "type": "Bot"}
        if route == f"repos/{publish_tap.TAP_REPOSITORY}/branches/main/protection":
            return {
                "required_status_checks": {
                    "strict": self.protected,
                    "contexts": ["Formula qualification"],
                },
                "enforce_admins": {"enabled": self.protected},
            }
        if route == f"repos/{publish_tap.TAP_REPOSITORY}/branches/main":
            return {"commit": {"sha": self.main_sha}}
        prefix = f"repos/{publish_tap.TAP_REPOSITORY}/contents/"
        if route.startswith(prefix):
            name = unquote(route[len(prefix):])
            query = parse_qs(urlsplit("https://api.invalid/" + path).query)
            ref = query.get("ref", ["main"])[0]
            files = self.main_files if ref == "main" else self.branch_files
            if name == "Formula/ami-rust.rb" and ref == "main" and name not in files:
                if missing:
                    return None
                raise AssertionError("unexpected missing formula lookup")
            if name not in files:
                if missing:
                    return None
                raise AssertionError(f"missing fake content {ref}:{name}")
            return {"type": "file", "encoding": "base64",
                    "content": base64.b64encode(files[name]).decode("ascii")}

        base_prefix = f"repos/{publish_tap.TAP_REPOSITORY}/git/"
        if route == base_prefix + f"ref/heads/{self.branch_name}":
            if not self.branch_exists:
                if missing:
                    return None
                raise AssertionError("unexpected absent branch lookup")
            return {"ref": "refs/heads/" + self.branch_name,
                    "object": {"sha": self.head_sha, "type": "commit"}}
        if route == base_prefix + f"commits/{self.main_sha}" and method == "GET":
            return {"sha": self.main_sha, "tree": {"sha": self.main_tree}}
        if route == base_prefix + "trees" and method == "POST":
            assert type(data) is dict
            self.tree_entries = data["tree"]
            self.branch_files = dict(self.main_files)
            for row in self.tree_entries:
                self.branch_files[row["path"]] = row["content"].encode("utf-8")
            return {"sha": self.tree_sha}
        if route == base_prefix + "commits" and method == "POST":
            self.branch_exists = True
            self.commit_message = data["message"]
            return {"sha": self.head_sha}
        if route == base_prefix + "refs" and method == "POST":
            self.branch_exists = True
            return {"ref": data["ref"], "object": {"sha": self.head_sha}}

        if route == f"repos/{publish_tap.TAP_REPOSITORY}/commits/{self.head_sha}":
            identity = {"name": "metaneutrons-homebrew[bot]",
                        "email": "999+metaneutrons-homebrew[bot]@users.noreply.github.com",
                        "date": "2026-10-18T10:00:00Z"}
            return {
                "sha": self.head_sha,
                "parents": [{"sha": self.main_sha}],
                "commit": {"message": publish_tap._commit_message(publish_tap._load_pins()),
                           "author": identity, "committer": identity},
            }
        compare_prefix = f"repos/{publish_tap.TAP_REPOSITORY}/compare/"
        if route.startswith(compare_prefix):
            base, head = route[len(compare_prefix):].split("...", 1)
            assert base == self.main_sha and head == self.head_sha
            return {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                    "merge_base_commit": {"sha": self.main_sha},
                    "files": [{"filename": "Formula/ami-rust.rb"}, {"filename": "README.md"}]}

        pull_prefix = f"repos/{publish_tap.TAP_REPOSITORY}/pulls"
        if route == pull_prefix and method == "GET":
            return [] if self.pr is None else [self.pr]
        if route == pull_prefix and method == "POST":
            self.pull_request_title = data["title"]
            self.pr = self._pull()
            return self.pr
        if route == pull_prefix + "/17" and method == "GET":
            if self.pr is None:
                raise AssertionError("PR lookup before PR creation")
            if self.changed_head:
                return self._pull(head_sha="f" * 40)
            return self.pr
        if route == f"repos/{publish_tap.TAP_REPOSITORY}/commits/{self.head_sha}/check-runs":
            conclusion = "failure" if self.failed_check else "success"
            return {"total_count": 1,
                    "check_runs": [{"name": "Formula qualification", "status": "completed",
                                    "conclusion": conclusion}]}
        if route == pull_prefix + "/17/merge" and method == "PUT":
            self.merge_calls += 1
            self.merge_title = data["commit_title"]
            if self.pr is None or data["sha"] != self.head_sha:
                return {"merged": False}
            self.pr = self._pull()
            self.pr.update({"state": "closed", "merged": True,
                            "merge_commit_sha": self.merge_sha})
            self.main_sha = self.merge_sha
            self.main_files = dict(self.branch_files)
            if self.wrong_readback:
                self.main_files["Formula/ami-rust.rb"] = b"wrong formula bytes\n"
            return {"merged": True, "sha": self.merge_sha}
        raise AssertionError(f"unhandled fake API request: {method} {path}")


class TapPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        (self.source / "packaging").mkdir(parents=True)
        pins = {"sdk_version": "0.1.0", "packaging_revision": 1,
                "package_version": "0.1.0-1"}
        (self.source / "packaging/pins.json").write_text(json.dumps(pins), encoding="utf-8")
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.formula = (
            'class AmiRust < Formula\n'
            '  desc "Native PC x86-64 AROS ABI-v1 SDK"\n'
            '  homepage "https://github.com/metaneutrons/ami-rust"\n'
            '  version "0.1.0"\n'
            'end\n'
        ).encode("utf-8")
        (self.candidate / "ami-rust.rb").write_bytes(self.formula)
        candidate = {"schema": publish_tap.CANDIDATE_SCHEMA,
                     "assets": [{"path": "ami-rust.rb", "bytes": len(self.formula),
                                 "sha256": sha(self.formula)}]}
        (self.candidate / "candidate.json").write_text(
            json.dumps(candidate, sort_keys=True, indent=2) + "\n", encoding="utf-8")

        self.tap_source = self.root / "tap-source"
        (self.tap_source / "Formula").mkdir(parents=True)
        (self.tap_source / "scripts").mkdir()
        (self.tap_source / "Formula/existing.rb").write_text("class Existing < Formula; end\n")
        (self.tap_source / "README.md").write_bytes(b"# Tap\nexisting.rb\n")
        generator = (
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            "out=\"$1\"\nprintf '# Tap\\n' > \"$out\"\n"
            "for formula in \"$FORMULA_DIR\"/*.rb; do\n"
            "  basename \"$formula\" >> \"$out\"\n"
            "done\n"
        )
        (self.tap_source / "scripts/generate-readme.sh").write_text(generator, encoding="utf-8")
        self.readme = b"# Tap\nami-rust.rb\nexisting.rb\n"
        self.old_source = publish_tap.SOURCE
        publish_tap.SOURCE = self.source
        self.api = FakeGitHub(self.formula, b"# Tap\nexisting.rb\n")
        self.token = mock.patch.dict(os.environ, {"GH_TOKEN": "fake-installation-token"})
        self.token.start()

    def tearDown(self) -> None:
        publish_tap.SOURCE = self.old_source
        self.token.stop()
        self.temp.cleanup()

    def patch_publish(self, fake: FakeGitHub):
        def clone(destination: Path) -> str:
            destination.parent.mkdir(parents=True, exist_ok=True)
            (destination.parent / "empty-home").mkdir(mode=0o700)
            shutil.copytree(self.tap_source, destination)
            return fake.main_sha

        return (
            mock.patch.object(publish_tap, "api", side_effect=fake),
            mock.patch.object(publish_tap, "_anonymous_clone", side_effect=clone),
        )

    def open_pr(self, fake: FakeGitHub | None = None, *, receipt_name: str = "open.json"
                ) -> tuple[FakeGitHub, Path, dict[str, object]]:
        fake = fake or self.api
        receipt_path = self.root / receipt_name
        patches = self.patch_publish(fake)
        with patches[0], patches[1]:
            record = publish_tap.open_publication(self.candidate / "ami-rust.rb", receipt_path)
        return fake, receipt_path, record

    def test_open_creates_api_commit_from_exact_formula_and_generated_readme(self) -> None:
        fake, receipt, record = self.open_pr()
        self.assertEqual(record["status"], "OPEN_PULL_REQUEST")
        self.assertEqual(record["head_sha"], fake.head_sha)
        self.assertEqual(record["base_sha"], fake.main_sha)
        self.assertEqual(record["source_formula_sha256"], sha(self.formula))
        self.assertEqual(record["readme_sha256"], sha(self.readme))
        self.assertEqual(fake.branch_files["Formula/ami-rust.rb"], self.formula)
        self.assertEqual(fake.branch_files["README.md"], self.readme)
        self.assertEqual([row["path"] for row in fake.tree_entries],
                         ["Formula/ami-rust.rb", "README.md"])
        self.assertEqual(json.loads(receipt.read_text()), record)

    def test_revision_two_drives_branch_commit_pr_and_merge_titles(self) -> None:
        pins_path = self.source / "packaging/pins.json"
        pins = json.loads(pins_path.read_text(encoding="utf-8"))
        pins["packaging_revision"] = 2
        pins["package_version"] = "0.1.0-2"
        pins_path.write_text(json.dumps(pins), encoding="utf-8")

        fake = FakeGitHub(self.formula, b"# Tap\nexisting.rb\n")
        expected_message = "feat: distribute ami-rust 0.1.0 packaging 2"
        self.assertEqual(fake.branch_name, "fix/ami-rust-0.1.0-packaging-2")
        fake, opened, record = self.open_pr(fake, receipt_name="open-revision-two.json")
        self.assertEqual(fake.commit_message, expected_message)
        self.assertEqual(fake.pull_request_title, expected_message)

        output = self.root / "merged-revision-two.json"
        with mock.patch.object(publish_tap, "api", side_effect=fake):
            merged = publish_tap.merge_publication(
                self.candidate / "ami-rust.rb", opened, output
            )
        self.assertEqual(fake.merge_title, expected_message)
        self.assertEqual(merged["status"], "MERGED")
        self.assertEqual(record["branch"], "fix/ami-rust-0.1.0-packaging-2")

    def test_open_recovery_reuses_only_exact_branch_and_pull_request(self) -> None:
        fake, _first_receipt, _record = self.open_pr()
        second = self.root / "recovered.json"
        original_api_calls = []

        def capture(path: str, **kwargs):
            original_api_calls.append((path, kwargs.get("method", "GET")))
            return fake(path, **kwargs)

        def clone(destination: Path) -> str:
            destination.parent.mkdir(parents=True, exist_ok=True)
            (destination.parent / "empty-home").mkdir(mode=0o700)
            shutil.copytree(self.tap_source, destination)
            return fake.main_sha

        with mock.patch.object(publish_tap, "api", side_effect=capture), \
                mock.patch.object(publish_tap, "_anonymous_clone", side_effect=clone):
            record = publish_tap.open_publication(self.candidate / "ami-rust.rb", second)
        self.assertEqual(record["status"], "OPEN_PULL_REQUEST")
        self.assertFalse(any(method == "POST" and path.endswith("/git/trees")
                             for path, method in original_api_calls))
        self.assertFalse(any(method == "POST" and path.endswith("/pulls")
                             for path, method in original_api_calls))

    def test_merge_refuses_scope_protection_changed_head_and_failed_check(self) -> None:
        variants = {
            "scope": lambda: FakeGitHub(self.formula, b"# Tap\nexisting.rb\n",
                                         scope=[publish_tap.TAP_REPOSITORY, "another/repo"]),
            "protection": lambda: FakeGitHub(self.formula, b"# Tap\nexisting.rb\n", protected=False),
            "head": lambda: FakeGitHub(self.formula, b"# Tap\nexisting.rb\n", changed_head=True),
            "check": lambda: FakeGitHub(self.formula, b"# Tap\nexisting.rb\n", failed_check=True),
        }
        for name, factory in variants.items():
            with self.subTest(name=name):
                fake = FakeGitHub(self.formula, b"# Tap\nexisting.rb\n")
                _, opened, _ = self.open_pr(fake, receipt_name=f"open-{name}.json")
                changed = factory()
                # Reuse the exact successful open receipt and server-side PR.
                changed.branch_exists = fake.branch_exists
                changed.branch_files = dict(fake.branch_files)
                changed.pr = dict(fake.pr)
                changed.head_sha = fake.head_sha
                changed.main_sha = fake.main_sha
                changed.tree_entries = list(fake.tree_entries)
                output = self.root / f"merge-{name}.json"
                with mock.patch.object(publish_tap, "api", side_effect=changed):
                    with self.assertRaises(publish_tap.TapPublicationError):
                        publish_tap.merge_publication(self.candidate / "ami-rust.rb", opened, output)
                self.assertEqual(changed.merge_calls, 0)
                self.assertFalse(output.exists())

    def test_valid_merge_is_squashed_and_formula_is_read_back_exactly(self) -> None:
        fake, opened, _record = self.open_pr()
        output = self.root / "merged.json"
        with mock.patch.object(publish_tap, "api", side_effect=fake):
            record = publish_tap.merge_publication(self.candidate / "ami-rust.rb", opened, output)
        self.assertEqual(fake.merge_calls, 1)
        self.assertEqual(record["status"], "MERGED")
        self.assertEqual(record["merge_commit_sha"], fake.merge_sha)
        self.assertEqual(fake.main_files["Formula/ami-rust.rb"], self.formula)
        self.assertEqual(json.loads(output.read_text()), record)

    def test_merge_rejects_wrong_formula_readback(self) -> None:
        fake = FakeGitHub(self.formula, b"# Tap\nexisting.rb\n", wrong_readback=True)
        _fake, opened, _record = self.open_pr(fake)
        output = self.root / "wrong-readback.json"
        with mock.patch.object(publish_tap, "api", side_effect=fake):
            with self.assertRaisesRegex(publish_tap.TapPublicationError, "differs from exact attested"):
                publish_tap.merge_publication(self.candidate / "ami-rust.rb", opened, output)
        self.assertEqual(fake.merge_calls, 1)
        self.assertFalse(output.exists())

    def test_formula_inventory_mismatch_fails_before_any_api_request(self) -> None:
        candidate = json.loads((self.candidate / "candidate.json").read_text())
        candidate["assets"][0]["sha256"] = "0" * 64
        (self.candidate / "candidate.json").write_text(json.dumps(candidate), encoding="utf-8")
        api = mock.Mock()
        with mock.patch.object(publish_tap, "api", api):
            with self.assertRaisesRegex(publish_tap.TapPublicationError, "candidate.json inventory"):
                publish_tap.open_publication(self.candidate / "ami-rust.rb", self.root / "never.json")
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()

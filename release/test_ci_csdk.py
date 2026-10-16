#!/usr/bin/env python3
"""No-network counter-probes for the source-patch boundary."""
import copy
import difflib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("portable_csdk", Path(__file__).with_name("ci_csdk.py"))
csdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(csdk)


class PatchRunner:
    def __init__(self):
        self.calls = []
        self.labels = []

    def run(self, command, *, cwd, label, timeout):
        self.calls.append(command)
        if label in self.labels:
            raise ValueError("duplicate process log label")
        self.labels.append(label)
        return subprocess.run(command, cwd=cwd, check=True, capture_output=True, timeout=timeout)


class SourcePatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ami-rust-source-patch-")
        self.root = Path(self.temp.name)
        self.source = self.root / "owned source"
        self.patches = self.root / "patches"
        (self.source / "build").mkdir(parents=True)
        self.patches.mkdir()
        self.before, self.after = b"prefix=/historical/checkout\n", b"prefix=${pcfiledir}/../..\n"
        self.path = self.source / "build/input.pc"
        self.path.write_bytes(self.before)
        patch = "".join(difflib.unified_diff(self.before.decode().splitlines(True),
                       self.after.decode().splitlines(True),
                       fromfile="a/build/input.pc", tofile="b/build/input.pc")).encode()
        (self.patches / "fix.patch").write_bytes(patch)
        self.manifest = {"schema": "ami-rust-portable-csdk-patches-v1", "patches": [{
            "component": "example", "path": "build/input.pc", "patch": "fix.patch",
            "before_sha256": csdk.digest(self.before), "after_sha256": csdk.digest(self.after),
            "patch_sha256": csdk.digest(patch)}]}
        self.runner = PatchRunner()

    def tearDown(self):
        self.temp.cleanup()

    def apply(self):
        (self.patches / "series.json").write_text(json.dumps(self.manifest))
        return csdk.apply_source_patches({"example": self.source}, self.runner,
                                         patch_directory=self.patches)

    def test_valid_patch_applies_to_space_containing_owned_root(self):
        rows = self.apply()
        self.assertEqual(self.path.read_bytes(), self.after)
        self.assertEqual(rows[0]["after_sha256"], csdk.digest(self.after))
        self.assertEqual(len(self.runner.calls), 1)
        self.assertIn("--fuzz=0", self.runner.calls[0])

    def test_changed_source_refused_before_execution(self):
        self.path.write_bytes(self.before + b"changed\n")
        with self.assertRaisesRegex(ValueError, "patch base"):
            self.apply()
        self.assertFalse(self.runner.calls)

    def test_multiple_patches_for_same_component_use_unique_process_logs(self):
        second = copy.deepcopy(self.manifest["patches"][0])
        second["path"], second["patch"] = "build/second.pc", "second.patch"
        (self.source / second["path"]).write_bytes(self.before)
        raw = (self.patches / "fix.patch").read_bytes().replace(b"build/input.pc", b"build/second.pc")
        (self.patches / second["patch"]).write_bytes(raw)
        second["patch_sha256"] = csdk.digest(raw)
        self.manifest["patches"].append(second)
        self.assertEqual(len(self.apply()), 2)
        self.assertEqual((self.source / second["path"]).read_bytes(), self.after)
        self.assertEqual(len(set(self.runner.labels)), 2)

    def test_changed_patch_refused_before_execution(self):
        with (self.patches / "fix.patch").open("ab") as f:
            f.write(b"\n")
        with self.assertRaisesRegex(ValueError, "source patch differs"):
            self.apply()
        self.assertFalse(self.runner.calls)

    def test_extra_file_hunk_refused_even_with_matching_digest(self):
        path = self.patches / "fix.patch"
        patch = path.read_bytes() + b"--- a/other\n+++ b/other\n@@ -1 +1 @@\n-a\n+b\n"
        path.write_bytes(patch)
        self.manifest["patches"][0]["patch_sha256"] = csdk.digest(patch)
        with self.assertRaisesRegex(ValueError, "only its declared file"):
            self.apply()
        self.assertFalse(self.runner.calls)

    def test_symlink_parent_refused(self):
        owned = self.source / "build"
        moved = self.root / "outside"
        owned.rename(moved)
        owned.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.apply()
        self.assertEqual((moved / "input.pc").read_bytes(), self.before)
        self.assertFalse(self.runner.calls)

    def test_wrong_result_identity_fails(self):
        self.manifest["patches"][0]["after_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "patched source differs"):
            self.apply()

    def test_unknown_schema_refused(self):
        self.manifest["schema"] = "unrecognized"
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            self.apply()
        self.assertFalse(self.runner.calls)


if __name__ == "__main__":
    unittest.main()

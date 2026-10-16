import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from release import finalize_cargo_probe as subject


class FinalizerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.source = self.root / "source"
        (self.source / "release").mkdir(parents=True)
        self.temporary = self.root / "temporary"
        self.temporary.mkdir()
        self.output = self.temporary / "ami-rust-context-output"
        self.output.mkdir()
        (self.output / "outcome.json").write_text(json.dumps({"status": "MATCH_NOT_RELEASE_ACCEPTED"}))
        rows = []
        for name in sorted(subject.NAMES | {"licences/upstream.txt"}):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = (name + " original licensed bytes\n").encode()
            path.write_bytes(data)
            rows.append({"path": name, "source": name, "bytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest()})
        self.manifest = self.source / "release/bundle-files.json"
        self.manifest.write_text(json.dumps({"files": rows}))

    def finalize(self, result="success"):
        return subject.finalize(self.temporary, self.output, self.source, result)

    def test_original_materials_and_failure_binary_retained(self):
        (self.output / "cargo").mkdir()
        binary = self.output / "cargo/cargo.tar.xz"
        binary.write_bytes(b"retained original archive bytes")
        bootstrap = self.temporary / subject.probe.BOOTSTRAP_NAME
        bootstrap.mkdir()
        (bootstrap / "bootstrap.json").write_text('{"status":"fixture"}')
        record = self.finalize("failure")
        self.assertFalse(bootstrap.exists())
        self.assertEqual(binary.read_bytes(), b"retained original archive bytes")
        self.assertFalse(record["SDK_release_acceptance"])
        for row in record["accompanying_materials"]:
            self.assertEqual((self.output / "accompanying-materials" / row["path"]).read_bytes(),
                             (self.source / row["path"]).read_bytes())
        self.assertLess(subject.probe.tree_bytes(self.output), subject.LIMIT)

    def test_matching_success_is_diagnostic_only(self):
        self.assertFalse(self.finalize()["SDK_release_acceptance"])

    def test_changed_source_is_rejected_before_copy(self):
        (self.source / "LICENSE-MIT").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bundle pin"):
            self.finalize()
        self.assertFalse((self.output / "accompanying-materials").exists())

    def test_missing_required_notice_is_rejected(self):
        value = json.loads(self.manifest.read_text())
        value["files"] = [r for r in value["files"] if r["path"] != "THIRD_PARTY_NOTICES.md"]
        self.manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.finalize()

    def test_unexpected_export_is_rejected(self):
        (self.output / "surprise.bin").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected diagnostic"):
            self.finalize()

    def test_unowned_work_is_not_deleted(self):
        work = self.temporary / subject.probe.WORK_NAMES[0]
        work.mkdir()
        with self.assertRaisesRegex(ValueError, "unretired"):
            self.finalize()
        self.assertTrue(work.exists())

    def test_false_success_is_rejected(self):
        (self.output / "outcome.json").write_text('{"status":"FAILED_EVIDENCE_RETAINED"}')
        with self.assertRaisesRegex(ValueError, "matching diagnostic"):
            self.finalize()

    def test_linked_source_is_rejected(self):
        path = self.source / "LICENSE-MIT"
        path.unlink()
        path.symlink_to(self.source / "LICENSE-APACHE")
        with self.assertRaisesRegex(ValueError, "canonical source"):
            self.finalize()


if __name__ == "__main__":
    unittest.main()

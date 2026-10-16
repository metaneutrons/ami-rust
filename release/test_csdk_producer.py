"""Focused boundary checks for complete portable C-SDK reproduction."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest


spec = importlib.util.spec_from_file_location("_test_csdk_producer", Path(__file__).with_name("csdk_producer.py"))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


def profiles():
    names = (["include/generated-" + str(i) + ".h" for i in range(530)]
             + ["lib/libdrm_nouveau.a", "lib/pkgconfig/aom.pc"]
             + ["include/unchanged-" + str(i) + ".h" for i in range(2303)])
    before = {"files": [{"path": n, "bytes": 1, "sha256": "a" * 64} for n in names], "symlinks": []}
    after = {"files": [{**r, "sha256": "b" * 64 if i < 532 else r["sha256"]}
                        for i, r in enumerate(before["files"])], "symlinks": []}
    return before, after


class CsdkProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_profile_change_gate_accepts_only_the_complete_declared_change_set(self):
        original, candidate = profiles()
        changed = producer.validate_profiles(original, candidate)
        self.assertEqual(len(changed), 532)
        self.assertIn("lib/pkgconfig/aom.pc", changed)
        for mutate in (
            lambda p: p["files"].pop(),
            lambda p: p["files"].append(p["files"][0]),
            lambda p: p["files"][-1].update(sha256="c" * 64),
            lambda p: p["files"][0].update(bytes=True),
            lambda p: p["files"][0].update(path="../escape"),
            lambda p: p["files"][0].update(sha256="bad"),
            lambda p: p.update(symlinks=[{"path": "link", "target": "outside"}]),
        ):
            original, candidate = profiles()
            mutate(candidate)
            with self.assertRaises(ValueError):
                producer.validate_profiles(original, candidate)

    def make_archive(self, files):
        path = self.root / ("input-" + str(len(list(self.root.glob("*.xz")))) + ".tar.xz")
        rows = []
        with tarfile.open(path, "x:xz") as tar:
            for name, raw in files:
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o755, len(raw)
                tar.addfile(info, io.BytesIO(raw))
                rows.append({"path": name.removeprefix("Developer/"), "bytes": len(raw),
                             "sha256": producer.csdk.digest(raw)})
        return path, {"bytes": path.stat().st_size, "sha256": producer.sdk.sha256(path)}, {"files": rows, "symlinks": []}

    def test_original_extraction_checks_membership_payload_and_archive_digest(self):
        archive, pin, profile = self.make_archive([("Developer/include/example.h", b"header")])
        dest = self.root / "original"
        modes = producer.extract_original(archive, pin, profile, dest)
        self.assertEqual(modes, {"include/example.h": 0o755})
        self.assertEqual((dest / "include/example.h").read_bytes(), b"header")
        with self.assertRaisesRegex(ValueError, "immutable pin"):
            producer.extract_original(archive, {**pin, "sha256": "0" * 64}, profile, self.root / "bad-hash")
        profile["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "member differs"):
            producer.extract_original(archive, pin, profile, self.root / "bad-member")

    def test_traversal_and_duplicate_original_members_are_rejected(self):
        archive, pin, profile = self.make_archive([("Developer/../escape.h", b"bad")])
        with self.assertRaises(ValueError):
            producer.extract_original(archive, pin, profile, self.root / "traversal")
        archive, pin, profile = self.make_archive([("Developer/a.h", b"a"), ("Developer/a.h", b"a")])
        profile["files"] = profile["files"][:1]
        with self.assertRaisesRegex(ValueError, "unexpected original"):
            producer.extract_original(archive, pin, profile, self.root / "duplicate")

    def test_canonical_archive_is_independent_of_root_and_preserves_modes(self):
        archives = []
        for name in ("first root", "unrelated second"):
            root = self.root / name
            (root / "include").mkdir(parents=True)
            (root / "include/a.h").write_bytes(b"const int stable = 1;\n")
            destination = self.root / (str(len(archives)) + ".xz")
            profile = producer.canonical_archive(root, {"include/a.h": 0o755}, destination)
            self.assertEqual(profile["files"][0]["path"], "include/a.h")
            with tarfile.open(destination, "r:xz") as tar:
                member = tar.getmember("Developer/include/a.h")
                self.assertEqual((member.mode, member.uid, member.gid, member.mtime), (0o755, 0, 0, 0))
            archives.append(destination.read_bytes())
        self.assertEqual(archives[0], archives[1])
        root = self.root / "first root"
        (root / "unexpected").write_bytes(b"not in inventory")
        with self.assertRaisesRegex(ValueError, "membership"):
            producer.canonical_archive(root, {"include/a.h": 0o755}, self.root / "extra.xz")

    def test_wrong_native_member_count_or_order_is_rejected_before_reading_outputs(self):
        pin = {"original_sha256": "a" * 64, "original_bytes": 10}
        original = {"sha256": "a" * 64, "bytes": 10, "members": [], "symbols": []}
        with self.assertRaisesRegex(ValueError, "identity, member order"):
            producer.compare_native(original, {"member_basenames": []}, pin)

    def test_native_contract_counts_cannot_be_weakened(self):
        counts = {"objects": 825, "unchanged_members": 616,
                  "path_changed_members": 209, "symbols": 4515}
        producer.validate_native_counts(counts)
        for key in counts:
            for invalid in (0, counts[key] - 1, True, str(counts[key])):
                with self.assertRaisesRegex(ValueError, "native counts"):
                    producer.validate_native_counts({**counts, key: invalid})

    def test_explicit_host_tools_are_all_or_none(self):
        args = SimpleNamespace(cmake=None, pkg_config=None, perl=None, git=None)
        self.assertIsNone(producer.explicit_host_tools(args))
        args.cmake = Path("/fixture/cmake")
        with self.assertRaisesRegex(ValueError, "complete set"):
            producer.explicit_host_tools(args)
        args.pkg_config, args.perl, args.git = (Path("/fixture/" + name)
                                               for name in ("pkg-config", "perl", "git"))
        self.assertEqual(set(producer.explicit_host_tools(args)), {"cmake", "pkg-config", "perl", "git"})


if __name__ == "__main__":
    unittest.main()

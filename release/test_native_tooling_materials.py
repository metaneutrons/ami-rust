"""Focused fixtures for the native SDK publisher input-material extension."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_auth as auth


CAPSULE_URL = (
    "https://github.com/metaneutrons/ami-rust/releases/download/"
    "v0.1.0/ami-rust-0.1.0-release.tar.xz"
)
CONFIG_PATH = "release/native-tooling-inputs.json"
REQUIRED_SOURCES = (
    "tooling/Cargo.lock",
    "tooling/Cargo.toml",
    "tooling/crates/core/build.rs",
    "tooling/crates/core/src/macos_process_snapshot.c",
    "tooling/crates/core/src/macos_process_snapshot.rs",
    "tooling/crates/xtask/src/native_release.rs",
    "tooling/fixtures/accepted-r1-inputs.json",
    "tooling/fixtures/accepted-r1-support-inputs.json",
    "tooling/macos-host-selection.rs",
    "tools/bootstrap-host-rust.sh",
    "tools/build-native-cli.sh",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class NativeToolingMaterialsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ami-rust-native-inputs-test-")
        self.source = Path(self.temporary.name)
        self.base_manifest = {
            "schema": "ami-rust-publisher-inputs-v1",
            "materials": [
                {"uri": "https://example.invalid/bootstrap.tar", "digest": {"sha256": "a" * 64}},
                {"uri": "git+https://example.invalid/source#revision", "digest": {"gitCommit": "b" * 40}},
            ],
        }
        self.input_manifest = patch.object(auth, "input_manifest", return_value=self.base_manifest)
        self.input_manifest.start()
        self.addCleanup(self.input_manifest.stop)
        self.addCleanup(self.temporary.cleanup)
        self._write_native_fixture()

    def _write(self, relative, raw):
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def _write_native_fixture(self):
        self.lock_raw = b"fixture Cargo.lock\n"
        self._write("tooling/Cargo.lock", self.lock_raw)
        self.source_contents = {}
        for path in REQUIRED_SOURCES:
            if path == "tooling/Cargo.lock":
                raw = self.lock_raw
            elif path == "tooling/fixtures/accepted-r1-inputs.json":
                raw = auth.encoded({
                    "accepted_release": {
                        "public_provenance": {
                            "public_release_archive_asset": {
                                "bytes": 1234,
                                "sha256": "c" * 64,
                            },
                        },
                    },
                })
                self.baseline_raw = raw
            else:
                raw = ("fixture " + path + "\n").encode()
            self.source_contents[path] = raw
            self._write(path, raw)

        self.crates = [
            {"name": f"fixture-crate-{index:02d}", "version": "1.2.3",
             "url": f"https://static.crates.io/crates/fixture-crate-{index:02d}/fixture-crate-{index:02d}-1.2.3.crate",
             "sha256": f"{index + 1:064x}"}
            for index in range(29)
        ]
        self.config = {
            "schema": "ami-rust-native-tooling-inputs-v1",
            "sdk_version": "0.2.0",
            "cli_version": "0.2.0-dev",
            "legacy_release": {"url": CAPSULE_URL, "bytes": 1234, "sha256": "c" * 64},
            "cargo_lock": {"path": "tooling/Cargo.lock", "bytes": len(self.lock_raw),
                            "sha256": digest(self.lock_raw)},
            "registry_crates": self.crates,
            "source_files": list(REQUIRED_SOURCES),
        }
        self._write(CONFIG_PATH, auth.encoded(self.config))

    def _set_config(self, update):
        config = copy.deepcopy(self.config)
        update(config)
        self._write(CONFIG_PATH, auth.encoded(config))

    def test_legacy_version_returns_the_unchanged_manifest_without_native_inputs(self):
        (self.source / CONFIG_PATH).unlink()

        result = auth.input_manifest_for_sdk(self.source, "0.1.0")

        self.assertIs(result, self.base_manifest)
        self.assertEqual(auth.encoded(result), auth.encoded(self.base_manifest))

    def test_native_version_adds_pinned_materials_in_sorted_order(self):
        result = auth.input_manifest_for_sdk(self.source, "0.2.0")
        actual = {row["uri"]: row["digest"] for row in result["materials"]}
        expected = {row["uri"]: row["digest"] for row in self.base_manifest["materials"]}
        expected[CAPSULE_URL] = {"sha256": "c" * 64}
        for path, raw in self.source_contents.items():
            expected[f"git+https://github.com/{auth.REPO}#{path}"] = {"sha256": digest(raw)}
        config_raw = (self.source / CONFIG_PATH).read_bytes()
        expected[f"git+https://github.com/{auth.REPO}#{CONFIG_PATH}"] = {"sha256": digest(config_raw)}
        for crate in self.crates:
            expected[crate["url"]] = {"sha256": crate["sha256"]}

        self.assertEqual(result["schema"], "ami-rust-publisher-inputs-v1")
        self.assertEqual(list(actual), sorted(actual))
        self.assertEqual(actual, expected)
        self.assertEqual(result["materials"], [
            {"uri": uri, "digest": expected[uri]} for uri in sorted(expected)
        ])

    def test_shared_macos_host_selector_is_digest_bound(self):
        path = "tooling/macos-host-selection.rs"
        result = auth.input_manifest_for_sdk(self.source, "0.2.0")
        rows = {row["uri"]: row["digest"] for row in result["materials"]}
        uri = f"git+https://github.com/{auth.REPO}#{path}"
        self.assertEqual(rows[uri], {"sha256": digest(self.source_contents[path])})

        changed = self.source_contents[path] + b"changed host selection\n"
        self._write(path, changed)
        result = auth.input_manifest_for_sdk(self.source, "0.2.0")
        rows = {row["uri"]: row["digest"] for row in result["materials"]}
        self.assertEqual(rows[uri], {"sha256": digest(changed)})

    def test_rejects_mismatched_lock_pin_and_capsule(self):
        self._set_config(lambda config: config["cargo_lock"].update(sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "Cargo lock differs"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

        self._write(CONFIG_PATH, auth.encoded(self.config))
        self._set_config(lambda config: config["legacy_release"].update(bytes=1235))
        with self.assertRaisesRegex(ValueError, "capsule differs"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

    def test_rejects_boolean_baseline_byte_count(self):
        baseline = auth.parsed(self.baseline_raw)
        baseline["accepted_release"]["public_provenance"]["public_release_archive_asset"]["bytes"] = True
        self._write("tooling/fixtures/accepted-r1-inputs.json", auth.encoded(baseline))
        self._set_config(lambda config: config["legacy_release"].update(bytes=1))

        with self.assertRaisesRegex(ValueError, "capsule differs"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

    def test_rejects_source_inventory_omissions_and_unsafe_paths(self):
        self._set_config(lambda config: config.update(source_files=list(reversed(REQUIRED_SOURCES))))
        with self.assertRaisesRegex(ValueError, "unordered paths"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

        self._write(CONFIG_PATH, auth.encoded(self.config))
        self._set_config(lambda config: config.update(
            source_files=[path for path in REQUIRED_SOURCES if path != "tooling/Cargo.toml"]))
        with self.assertRaisesRegex(ValueError, "omits a required input"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

        self._write(CONFIG_PATH, auth.encoded(self.config))
        self._set_config(lambda config: config.update(
            source_files=sorted((*REQUIRED_SOURCES, "tooling/../outside"))))
        with self.assertRaisesRegex(ValueError, "unsafe relative publisher path"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

    def test_rejects_incomplete_unordered_and_misidentified_crate_sets(self):
        self._set_config(lambda config: config.update(registry_crates=self.crates[:-1]))
        with self.assertRaisesRegex(ValueError, "29-crate selection"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

        self._write(CONFIG_PATH, auth.encoded(self.config))
        self._set_config(lambda config: config.update(registry_crates=list(reversed(self.crates))))
        with self.assertRaisesRegex(ValueError, "unordered native registry crate"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

        self._write(CONFIG_PATH, auth.encoded(self.config))
        self._set_config(lambda config: config["registry_crates"][0].update(url="https://example.invalid/crate"))
        with self.assertRaisesRegex(ValueError, "invalid or unordered native registry crate"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

    def test_native_process_sampler_sources_are_mandatory_and_digest_bound(self):
        sampler_sources = (
            "tooling/crates/core/build.rs",
            "tooling/crates/core/src/macos_process_snapshot.c",
            "tooling/crates/core/src/macos_process_snapshot.rs",
        )
        for path in sampler_sources:
            with self.subTest(path=path):
                self._write(CONFIG_PATH, auth.encoded(self.config))
                self._set_config(lambda config: config.update(
                    source_files=[entry for entry in REQUIRED_SOURCES if entry != path]))
                with self.assertRaisesRegex(ValueError, "omits a required input"):
                    auth.input_manifest_for_sdk(self.source, "0.2.0")
                self._write(CONFIG_PATH, auth.encoded(self.config))
                altered = self.source_contents[path] + b"changed sampler source\n"
                self._write(path, altered)
                manifest = auth.input_manifest_for_sdk(self.source, "0.2.0")
                rows = {row["uri"]: row["digest"] for row in manifest["materials"]}
                self.assertEqual(rows[f"git+https://github.com/{auth.REPO}#{path}"],
                                 {"sha256": digest(altered)})
                self._write(path, self.source_contents[path])

    def test_rejects_sdk_and_cli_version_disagreement(self):
        self._set_config(lambda config: config.update(sdk_version="0.3.0"))
        with self.assertRaisesRegex(ValueError, "different SDK generation"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")

        self._write(CONFIG_PATH, auth.encoded(self.config))
        self._set_config(lambda config: config.update(cli_version="0.3.0-dev"))
        with self.assertRaisesRegex(ValueError, "version cores differ"):
            auth.input_manifest_for_sdk(self.source, "0.2.0")


if __name__ == "__main__":
    unittest.main()

"""Offline contract tests for project-locked SDK selection and build refusal."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HOST_DIR = ROOT / "host"
if str(HOST_DIR) not in sys.path:
    sys.path.insert(0, str(HOST_DIR))

import build as build_backend  # noqa: E402
import contracts  # noqa: E402


COMPONENT_FILES = {
    "rust": ("bin/rustc", b"rust-toolchain-v1\n"),
    "cargo": ("bin/cargo", b"#!/bin/sh\nexit 0\n"),
    "toolchain": ("bin/clang", b"cross-toolchain-v1\n"),
    "collector": ("bin/aros-collect", b"collector-v1\n"),
    "csdk": ("include/aros/stdc/stdio.h", b"/* sdk header */\n"),
    "vendor": ("serde-1.0.0/src/lib.rs", b"// vendored crate\n"),
}


def inventory_row(root: Path, relative_path: str) -> dict[str, object]:
    path = root / relative_path
    return {
        "path": relative_path,
        "bytes": path.stat().st_size,
        "sha256": contracts.sha256(path),
    }


def fixture_tree_bytes(root: Path) -> int:
    return sum(
        path.stat().st_size
        for path in root.rglob("*")
        if not path.is_symlink() and path.is_file()
    )


class SelectionFixture:
    """A minimal, fully inventoried project lock for the machine running tests."""

    def __init__(self, base: Path):
        self.base = base
        self.project_root = base / "project"
        self.project_root.mkdir()
        self.sdk_root = self.project_root / "sdk"
        self.sdk_root.mkdir()
        self.manifests_root = self.sdk_root / "manifests"
        self.manifests_root.mkdir()
        self.components_root = self.project_root / "components"
        self.components_root.mkdir()
        self.host = contracts.host_key()

        self.sdk_manifest_path = self.sdk_root / "sdk-manifest.json"
        self.lock_path = self.project_root / "ami-rust.lock.json"

        self.sdk_files = {
            "sdk.catalog": b"sdk-catalog-v1\n",
            "bin/ami-helper": b"helper-v1\n",
        }
        for relative_path, content in self.sdk_files.items():
            path = self.sdk_root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        self.component_manifests: dict[str, dict[str, object]] = {}
        profile_components: dict[str, dict[str, str]] = {}
        project_components: dict[str, str] = {}
        for name, (relative_path, content) in COMPONENT_FILES.items():
            component_root = self.components_root / name
            component_root.mkdir(parents=True)
            component_file = component_root / relative_path
            component_file.parent.mkdir(parents=True, exist_ok=True)
            component_file.write_bytes(content)
            if name == "cargo":
                component_file.chmod(0o755)

            component_manifest = {"files": [inventory_row(component_root, relative_path)]}
            manifest_relative = f"manifests/{name}.json"
            manifest_path = self.sdk_root / manifest_relative
            self.write_json(manifest_path, component_manifest)
            self.component_manifests[name] = component_manifest
            profile_components[name] = {
                "manifest": manifest_relative,
                "sha256": contracts.sha256(manifest_path),
            }
            project_components[name] = f"components/{name}"

        host_python = Path(sys.executable).resolve(strict=True)
        self.sdk_manifest: dict[str, object] = {
            "schema": "ami-rust-sdk-v1",
            "files": [
                inventory_row(self.sdk_root, relative_path)
                for relative_path in self.sdk_files
            ],
            "rust_commit": "fixture-rust-commit",
            "rust_llvm": "11.0.0",
            "source_date_epoch": 1_760_000_000,
            "budgets": {
                "build_rss_bytes": 1_000_000_000,
                "build_workspace_bytes": 1_000_000_000,
                "build_seconds": 600,
            },
            "profiles": {
                self.host: {
                    "rust_host": {
                        "macos-aarch64": "aarch64-apple-darwin",
                        "linux-x86_64": "x86_64-unknown-linux-gnu",
                    }[self.host],
                    "collector_binary": "bin/aros-collect",
                    "cargo_binary": "bin/cargo",
                    "cargo_metadata_mode": contracts.CARGO_METADATA_MODE,
                    "components": profile_components,
                }
            },
        }
        self.project: dict[str, object] = {
            "schema": "ami-rust-project-lock-v1",
            "sdk": {
                "root": "sdk",
                "manifest": "sdk-manifest.json",
                "manifest_sha256": "",
            },
            "host": {
                "platform": self.host,
                "python": str(host_python),
                "python_sha256": contracts.sha256(host_python),
            },
            "components": project_components,
        }
        self.write_sdk_manifest()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def write_project_lock(self) -> None:
        self.write_json(self.lock_path, self.project)

    def write_sdk_manifest(self) -> None:
        self.write_json(self.sdk_manifest_path, self.sdk_manifest)
        sdk = self.project["sdk"]
        assert isinstance(sdk, dict)
        sdk["manifest_sha256"] = contracts.sha256(self.sdk_manifest_path)
        self.write_project_lock()

    def replace_component_manifest(self, name: str, manifest: dict[str, object]) -> None:
        self.component_manifests[name] = manifest
        profile = self.sdk_manifest["profiles"][self.host]
        assert isinstance(profile, dict)
        components = profile["components"]
        assert isinstance(components, dict)
        expected = components[name]
        assert isinstance(expected, dict)
        manifest_path = self.sdk_root / str(expected["manifest"])
        self.write_json(manifest_path, manifest)
        expected["sha256"] = contracts.sha256(manifest_path)
        self.write_sdk_manifest()

    def add_sdk_symlink(self, name: str) -> None:
        link = self.sdk_root / name
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("sdk.catalog")
        self.sdk_manifest.setdefault("symlinks", []).append(
            {"path": name, "target": "sdk.catalog"}
        )
        self.write_sdk_manifest()


class ContractSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ami-rust-selector-")
        self.fixture = SelectionFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.assertLessEqual(fixture_tree_bytes(Path(self.temporary.name)), 1_000_000)
        self.temporary.cleanup()

    def test_valid_full_selection_uses_actual_host_and_local_python(self) -> None:
        selected = contracts.select(self.fixture.lock_path)
        lock, project, root, manifest, profile, components, counts = selected

        self.assertEqual(lock, self.fixture.lock_path.absolute())
        self.assertEqual(project["host"]["platform"], contracts.host_key())
        self.assertEqual(profile["rust_host"], {
            "macos-aarch64": "aarch64-apple-darwin",
            "linux-x86_64": "x86_64-unknown-linux-gnu",
        }[contracts.host_key()])
        self.assertEqual(root, self.fixture.sdk_root.resolve())
        self.assertEqual(manifest["schema"], "ami-rust-sdk-v1")
        self.assertEqual(set(components), set(contracts.COMPONENT_NAMES))
        self.assertEqual(counts, {name: 1 for name in components})

        python = Path(project["host"]["python"])
        self.assertEqual(python, Path(sys.executable).resolve(strict=True))
        self.assertTrue(os.access(python, os.X_OK))
        self.assertEqual(contracts.sha256(python), project["host"]["python_sha256"])

    def test_same_length_modified_sdk_file_is_rejected(self) -> None:
        path = self.fixture.sdk_root / "sdk.catalog"
        before = path.read_bytes()
        after = before.replace(b"v1", b"v2")
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)

        with self.assertRaisesRegex(ValueError, "component identity mismatch: sdk.catalog"):
            contracts.select(self.fixture.lock_path)

    def test_same_length_modified_sdk_helper_is_rejected(self) -> None:
        path = self.fixture.sdk_root / "bin/ami-helper"
        before = path.read_bytes()
        after = before.replace(b"v1", b"v2")
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)

        with self.assertRaisesRegex(ValueError, "component identity mismatch: bin/ami-helper"):
            contracts.select(self.fixture.lock_path)

    def test_same_length_modified_local_python_helper_is_rejected(self) -> None:
        helper_copy = self.fixture.project_root / "python-helper"
        helper_copy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper_copy.chmod(0o755)
        self.fixture.project["host"]["python"] = str(helper_copy)
        self.fixture.project["host"]["python_sha256"] = contracts.sha256(helper_copy)
        self.fixture.write_project_lock()
        contracts.select(self.fixture.lock_path)

        size = helper_copy.stat().st_size
        with helper_copy.open("r+b") as stream:
            stream.seek(size // 2)
            byte = stream.read(1)
            stream.seek(size // 2)
            stream.write(bytes([byte[0] ^ 1]))
        self.assertEqual(helper_copy.stat().st_size, size)

        with self.assertRaisesRegex(ValueError, "selected Python identity mismatch"):
            contracts.select(self.fixture.lock_path)

    def test_same_length_modified_prerequisite_is_rejected(self) -> None:
        path = self.fixture.components_root / "toolchain/bin/clang"
        before = path.read_bytes()
        after = before.replace(b"v1", b"v2")
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)

        with self.assertRaisesRegex(ValueError, "component identity mismatch: bin/clang"):
            contracts.select(self.fixture.lock_path)

    def test_missing_profile_component_is_rejected(self) -> None:
        profile = self.fixture.sdk_manifest["profiles"][self.fixture.host]
        components = profile["components"]
        del components["cargo"]
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "SDK profile component keys mismatch: missing=cargo extra=-"):
            contracts.select(self.fixture.lock_path)

    def test_extra_profile_component_is_rejected(self) -> None:
        profile = self.fixture.sdk_manifest["profiles"][self.fixture.host]
        profile["components"]["extra"] = profile["components"]["cargo"]
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "SDK profile component keys mismatch: missing=- extra=extra"):
            contracts.select(self.fixture.lock_path)

    def test_missing_project_component_is_rejected(self) -> None:
        del self.fixture.project["components"]["cargo"]
        self.fixture.write_project_lock()

        with self.assertRaisesRegex(ValueError, "project lock component keys mismatch: missing=cargo extra=-"):
            contracts.select(self.fixture.lock_path)

    def test_extra_project_component_is_rejected(self) -> None:
        self.fixture.project["components"]["extra"] = "components/vendor"
        self.fixture.write_project_lock()

        with self.assertRaisesRegex(ValueError, "project lock component keys mismatch: missing=- extra=extra"):
            contracts.select(self.fixture.lock_path)

    def test_cargo_cannot_reuse_rust_component_root(self) -> None:
        self.fixture.project["components"]["cargo"] = "components/rust"
        self.fixture.write_project_lock()

        with self.assertRaisesRegex(ValueError, "overlapping SDK component roots: rust and cargo"):
            contracts.select(self.fixture.lock_path)

    def test_same_length_modified_cargo_is_rejected(self) -> None:
        path = self.fixture.components_root / "cargo/bin/cargo"
        before = path.read_bytes()
        after = before.replace(b"exit 0", b"exit 1")
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)

        with self.assertRaisesRegex(ValueError, "component identity mismatch: bin/cargo"):
            contracts.select(self.fixture.lock_path)

    def test_missing_cargo_file_is_rejected(self) -> None:
        (self.fixture.components_root / "cargo/bin/cargo").unlink()

        with self.assertRaisesRegex(ValueError, "missing or invalid component: bin/cargo"):
            contracts.select(self.fixture.lock_path)

    def test_non_executable_cargo_is_rejected(self) -> None:
        (self.fixture.components_root / "cargo/bin/cargo").chmod(0o644)

        with self.assertRaisesRegex(ValueError, "SDK Cargo binary is not executable: bin/cargo"):
            contracts.select(self.fixture.lock_path)

    def test_missing_cargo_binary_path_is_rejected(self) -> None:
        profile = self.fixture.sdk_manifest["profiles"][self.fixture.host]
        del profile["cargo_binary"]
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "missing or invalid SDK Cargo binary path"):
            contracts.select(self.fixture.lock_path)

    def test_unsafe_cargo_binary_path_is_rejected(self) -> None:
        profile = self.fixture.sdk_manifest["profiles"][self.fixture.host]
        profile["cargo_binary"] = "../rust/bin/rustc"
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "unsafe SDK Cargo binary path"):
            contracts.select(self.fixture.lock_path)

    def test_missing_cargo_metadata_mode_is_rejected(self) -> None:
        profile = self.fixture.sdk_manifest["profiles"][self.fixture.host]
        del profile["cargo_metadata_mode"]
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "missing or unsupported SDK Cargo metadata mode"):
            contracts.select(self.fixture.lock_path)

    def test_unknown_cargo_metadata_mode_is_rejected(self) -> None:
        profile = self.fixture.sdk_manifest["profiles"][self.fixture.host]
        profile["cargo_metadata_mode"] = "upstream-cargo-defaults"
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "missing or unsupported SDK Cargo metadata mode"):
            contracts.select(self.fixture.lock_path)

    def test_missing_component_file_is_rejected(self) -> None:
        (self.fixture.components_root / "collector/bin/aros-collect").unlink()

        with self.assertRaisesRegex(ValueError, "missing or invalid component: bin/aros-collect"):
            contracts.select(self.fixture.lock_path)

    def test_duplicate_json_key_is_rejected(self) -> None:
        raw = self.fixture.lock_path.read_text(encoding="utf-8")
        needle = '"schema": "ami-rust-project-lock-v1",'
        self.assertIn(needle, raw)
        self.fixture.lock_path.write_text(
            raw.replace(needle, '"schema": "ambiguous", ' + needle, 1),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key: schema"):
            contracts.select(self.fixture.lock_path)

    def test_duplicate_inventory_file_path_is_rejected(self) -> None:
        duplicate = dict(self.fixture.sdk_manifest["files"][0])
        self.fixture.sdk_manifest["files"].append(duplicate)
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "duplicate file or invalid digest in inventory"):
            contracts.select(self.fixture.lock_path)

    def test_unsafe_inventory_path_is_rejected(self) -> None:
        self.fixture.sdk_manifest["files"][0]["path"] = "../outside.bin"
        self.fixture.write_sdk_manifest()

        with self.assertRaisesRegex(ValueError, "unsafe manifest path: ../outside.bin"):
            contracts.select(self.fixture.lock_path)

    def test_dot_segment_sdk_symlink_name_is_rejected(self) -> None:
        self.fixture.add_sdk_symlink("./helper")

        with self.assertRaisesRegex(ValueError, "unsafe manifest path: ./helper"):
            contracts.select(self.fixture.lock_path)

    def test_backslash_sdk_symlink_name_is_rejected(self) -> None:
        self.fixture.add_sdk_symlink("bad\\helper")

        with self.assertRaisesRegex(ValueError, "manifest path must be a portable relative path"):
            contracts.select(self.fixture.lock_path)

    def test_colon_sdk_symlink_name_is_rejected(self) -> None:
        self.fixture.add_sdk_symlink("bad:helper")

        with self.assertRaisesRegex(ValueError, "manifest path must be a portable relative path"):
            contracts.select(self.fixture.lock_path)

    def test_escaping_component_symlink_is_rejected(self) -> None:
        component_root = self.fixture.components_root / "vendor"
        outside = self.fixture.base / "outside.txt"
        outside.write_bytes(b"outside component root\n")
        target = os.path.relpath(outside, component_root)
        (component_root / "escape").symlink_to(target)
        manifest = self.fixture.component_manifests["vendor"]
        manifest["symlinks"] = [{"path": "escape", "target": target}]
        self.fixture.replace_component_manifest("vendor", manifest)

        with self.assertRaisesRegex(ValueError, "escaping/broken component symlink: escape"):
            contracts.select(self.fixture.lock_path)

    def test_unexpected_extra_prerequisite_file_is_rejected(self) -> None:
        extra = self.fixture.components_root / "vendor/unlisted.txt"
        extra.write_bytes(b"not in the locked inventory\n")

        with self.assertRaisesRegex(ValueError, "incomplete prerequisite inventory: extra=1 missing=0"):
            contracts.select(self.fixture.lock_path)

    def test_host_profile_mismatch_is_rejected(self) -> None:
        self.fixture.project["host"]["platform"] = (
            "linux-x86_64" if self.fixture.host == "macos-aarch64" else "macos-aarch64"
        )
        self.fixture.write_project_lock()

        with self.assertRaisesRegex(ValueError, "project host profile does not match this host"):
            contracts.select(self.fixture.lock_path)

    def test_malformed_manifest_hash_is_rejected(self) -> None:
        self.fixture.project["sdk"]["manifest_sha256"] = "z" * 64
        self.fixture.write_project_lock()

        with self.assertRaisesRegex(ValueError, "SDK manifest identity mismatch"):
            contracts.select(self.fixture.lock_path)

    def _assert_build_refusal_has_no_output(self, cargo_arguments: list[str], expected: str) -> None:
        app_root = self.fixture.project_root / "sample-app"
        app_root.mkdir()
        cargo_manifest = app_root / "Cargo.toml"
        cargo_manifest.write_text("[package]\nname = \"sample-app\"\n", encoding="utf-8")
        output_parent = self.fixture.project_root / "outputs"
        output_parent.mkdir()
        output = output_parent / "must-remain-absent"
        argv = [
            "build.py",
            "--project-lock",
            str(self.fixture.lock_path),
            "--output-dir",
            str(output),
            "--",
            *cargo_arguments,
        ]

        with patch.object(sys, "argv", argv), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            with self.assertRaisesRegex(ValueError, expected):
                build_backend.main()
        self.assertFalse(output.exists(), "refused build created its output directory")
        self.assertEqual(list(output_parent.iterdir()), [])

    def test_missing_cargo_lock_is_rejected_before_output(self) -> None:
        self._assert_build_refusal_has_no_output(
            [
                "build", "--manifest-path", str(self.fixture.project_root / "sample-app/Cargo.toml"),
                "--package", "sample-app", "--release", "--locked", "--offline",
            ],
            "missing project Cargo.lock",
        )

    def test_target_override_is_rejected_before_output(self) -> None:
        app_root = self.fixture.project_root / "sample-app"
        app_root.mkdir()
        (app_root / "Cargo.toml").write_text("[package]\nname = \"sample-app\"\n", encoding="utf-8")
        (app_root / "Cargo.lock").write_text("# fixture lock\n", encoding="utf-8")
        output_parent = self.fixture.project_root / "outputs"
        output_parent.mkdir()
        output = output_parent / "must-remain-absent"
        argv = [
            "build.py", "--project-lock", str(self.fixture.lock_path),
            "--output-dir", str(output), "--", "build",
            "--manifest-path", str(app_root / "Cargo.toml"), "--package", "sample-app",
            "--release", "--locked", "--offline", "--target", "x86_64-unknown-linux-gnu",
        ]

        with patch.object(sys, "argv", argv), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            with self.assertRaisesRegex(ValueError, "unsupported or SDK-owned Cargo option: --target"):
                build_backend.main()
        self.assertFalse(output.exists(), "target override refusal created its output directory")
        self.assertEqual(list(output_parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

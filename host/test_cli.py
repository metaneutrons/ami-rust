"""Offline tests for the isolated, project-locked ami-rust CLI boundary."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "host/cli.py"
CONTRACTS = ROOT / "host/contracts.py"
EVIDENCE_DIR = ROOT / "evidence/r1-development/cargo-component-unit"
TEST_PYTHON = Path(os.environ.get("AMI_RUST_TEST_PYTHON", sys.executable))
COMPONENT_FILES = {
    "rust": ("bin/rustc", b"fixture rust compiler identity\n"),
    "cargo": ("bin/cargo", b"#!/bin/sh\nexit 0\n"),
    "toolchain": ("bin/clang", b"fixture native toolchain identity\n"),
    "collector": ("bin/collect-aros", b"fixture collector identity\n"),
    "csdk": ("include/aros/exec.h", b"/* fixture SDK header */\n"),
    "vendor": ("registry/src/pkg/lib.rs", b"// fixture vendored source\n"),
}
HOST_RUST = {
    "macos-aarch64": "aarch64-apple-darwin",
    "linux-x86_64": "x86_64-unknown-linux-gnu",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_row(root, relative):
    path = root / relative
    return {"path": relative, "bytes": path.stat().st_size, "sha256": sha256(path)}


def tree_bytes(root):
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def current_host():
    pair = (platform.system(), platform.machine().lower())
    value = {("Darwin", "arm64"): "macos-aarch64",
             ("Linux", "x86_64"): "linux-x86_64"}.get(pair)
    if value is None:
        raise unittest.SkipTest(f"unsupported test host: {pair[0]}/{pair[1]}")
    return value


class MiniSdk:
    def __init__(self, base):
        self.base = base
        self.project_root = base / "consumer project with spaces"
        self.project_root.mkdir()
        self.sdk_root = base / "SDK copy with spaces"
        self.sdk_root.mkdir()
        self.host_root = self.sdk_root / "host"
        self.host_root.mkdir()
        self.host = current_host()
        self.lock_path = self.project_root / "ami-rust.lock.json"
        self.manifest_path = self.sdk_root / "sdk-manifest.json"
        self.component_roots = self.project_root / "components"
        self.component_roots.mkdir()
        self.marker = self.project_root / "driver effect marker.json"
        self.output_parent = self.project_root / "build outputs with spaces"
        self.output_parent.mkdir()
        (self.host_root / "cli.py").write_bytes(CLI.read_bytes())
        (self.host_root / "contracts.py").write_bytes(CONTRACTS.read_bytes())
        (self.host_root / "build.py").write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "Path(os.environ['AMI_RUST_CLI_TEST_MARKER']).write_text(json.dumps({"
            "'argv': sys.argv[1:], 'isolated': sys.flags.isolated, "
            "'dont_write_bytecode': sys.dont_write_bytecode}))\n"
            "raise SystemExit(int(os.environ.get('AMI_RUST_CLI_TEST_STATUS', '0')))\n",
            encoding="utf-8",
        )

        profiles_root = self.host_root / "profiles" / self.host
        profiles_root.mkdir(parents=True)
        profile_components = {}
        project_components = {}
        for name, (relative, content) in COMPONENT_FILES.items():
            component_root = self.component_roots / name
            component_root.mkdir()
            component_file = component_root / relative
            component_file.parent.mkdir(parents=True, exist_ok=True)
            component_file.write_bytes(content)
            if name == "cargo":
                component_file.chmod(0o755)
            component_manifest = {"files": [inventory_row(component_root, relative)]}
            manifest_relative = f"host/profiles/{self.host}/{name}.json"
            manifest_file = self.sdk_root / manifest_relative
            manifest_file.write_text(json.dumps(component_manifest, sort_keys=True), encoding="utf-8")
            profile_components[name] = {
                "manifest": manifest_relative,
                "sha256": sha256(manifest_file),
            }
            project_components[name] = f"components/{name}"

        host_files = sorted(path.relative_to(self.sdk_root).as_posix()
                            for path in self.host_root.rglob("*") if path.is_file())
        self.manifest = {
            "schema": "ami-rust-sdk-v1",
            "version": "test-fixture",
            "development_only": True,
            "driver": "host/build.py",
            "files": [inventory_row(self.sdk_root, name) for name in host_files],
            "profiles": {
                self.host: {
                    "rust_host": HOST_RUST[self.host],
                    "collector_binary": "bin/collect-aros",
                    "cargo_binary": "bin/cargo",
                    "cargo_metadata_mode": "ami-rust-reproducible-cross-v1",
                    "components": profile_components,
                },
            },
        }
        self.project = {
            "schema": "ami-rust-project-lock-v1",
            "sdk": {
                "root": "../SDK copy with spaces",
                "manifest": "sdk-manifest.json",
                "manifest_sha256": "",
            },
            "host": {
                "platform": self.host,
                "python": str(TEST_PYTHON),
                "python_sha256": sha256(TEST_PYTHON.resolve(strict=True)),
            },
            "components": project_components,
        }
        self.write_manifest_and_lock()
        if tree_bytes(self.base) > 1_000_000:
            raise AssertionError("mini-SDK fixture exceeded the 1 MB temporary-storage cap")

    def write_manifest_and_lock(self):
        self.manifest_path.write_text(json.dumps(self.manifest, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
        self.project["sdk"]["manifest_sha256"] = sha256(self.manifest_path)
        self.write_lock()

    def write_lock(self):
        self.lock_path.write_text(json.dumps(self.project, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8")


class StandaloneCliTests(unittest.TestCase):
    max_fixture_bytes = 0

    @classmethod
    def setUpClass(cls):
        if not CLI.is_file() or not CONTRACTS.is_file():
            raise unittest.SkipTest("ami-rust CLI sources are unavailable")
        if not TEST_PYTHON.is_file() or not os.access(TEST_PYTHON, os.X_OK):
            raise unittest.SkipTest(f"pinned test Python is unavailable: {TEST_PYTHON}")

    def setUp(self):
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="fixture-", dir=EVIDENCE_DIR)
        self.base = Path(self.temporary.name)
        self.fixture = MiniSdk(self.base)
        type(self).max_fixture_bytes = max(type(self).max_fixture_bytes, tree_bytes(self.base))

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments, status=0, marker=True, child_status="0"):
        command = [str(TEST_PYTHON), "-I", "-B", str(CLI), *map(str, arguments)]
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.base / "home"),
            "AMI_RUST_CLI_TEST_MARKER": str(self.fixture.marker),
            "AMI_RUST_CLI_TEST_STATUS": child_status,
        }
        (self.base / "home").mkdir(exist_ok=True)
        result = subprocess.run(command, cwd=self.fixture.project_root, env=environment,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, status, result.stderr or result.stdout)
        if marker:
            self.assertTrue(self.fixture.marker.is_file(), "driver did not create its effect marker")
            record = json.loads(self.fixture.marker.read_text(encoding="utf-8"))
            self.assertEqual(record["isolated"], 1)
            self.assertTrue(record["dont_write_bytecode"])
        else:
            self.assertFalse(self.fixture.marker.exists(), "refused command reached the SDK driver")
            record = None
        self.assertLessEqual(tree_bytes(self.base), 1_000_000)
        type(self).max_fixture_bytes = max(type(self).max_fixture_bytes, tree_bytes(self.base))
        return result, record

    def test_verify_emits_compact_development_status_without_running_driver(self):
        result, _ = self.run_cli("verify", "--sdk-lock", self.fixture.lock_path, marker=False)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        record = json.loads(result.stdout)
        self.assertEqual(record["status"], "verified-development")
        self.assertTrue(record["development_only"])
        self.assertIn("not R1-qualified", record["claim"])
        self.assertIn("not independent release authentication", record["claim"])
        self.assertIn("concurrent mutation", record["claim"])

    def test_version_does_not_require_sdk_imports(self):
        command = [str(TEST_PYTHON), "-I", "-B", str(CLI), "--version"]
        result = subprocess.run(command, cwd=self.fixture.project_root, capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ami-rust 0.1.0-dev")
        self.assertFalse(self.fixture.marker.exists())

    def test_build_preserves_opaque_arguments_and_space_paths(self):
        output = self.fixture.output_parent / "fresh output"
        cargo = ["build", "--manifest-path", "app dir/Cargo.toml", "--unknown-flag",
                 "value with spaces", "--remap-path-prefix=src path=/src", "--"]
        _, record = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", *cargo)
        self.assertEqual(record["argv"], [
            "--project-lock", str(self.fixture.lock_path.absolute()),
            "--output-dir", str(output.absolute()), "--", *cargo,
        ])

    def test_child_status_23_is_returned_exactly(self):
        output = self.fixture.output_parent / "status 23 output"
        _, record = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=23,
                                 child_status="23")
        self.assertEqual(record["argv"][-1], "build")

    def test_missing_lock_refuses_before_driver_effect(self):
        output = self.fixture.output_parent / "missing lock output"
        result, _ = self.run_cli("build", "--output-dir", output, "--", "build",
                                 status=2, marker=False)
        self.assertIn("missing required option: --sdk-lock", result.stderr)

    def test_nonisolated_invocation_refuses_before_driver_effect(self):
        command = [str(TEST_PYTHON), str(CLI), "verify", "--sdk-lock", str(self.fixture.lock_path)]
        result = subprocess.run(command, cwd=self.fixture.project_root, capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires its pinned Python to start with -I -B", result.stderr)
        self.assertFalse(self.fixture.marker.exists())

    def test_same_length_helper_tamper_refuses_before_driver_effect(self):
        path = self.fixture.host_root / "contracts.py"
        before = path.read_bytes()
        after = bytes([before[0] ^ 1]) + before[1:]
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)
        output = self.fixture.output_parent / "tampered helper output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("SDK file identity mismatch: host/contracts.py", result.stderr)

    def test_tampered_contracts_top_level_effect_does_not_execute(self):
        path = self.fixture.host_root / "contracts.py"
        effect_marker = self.fixture.project_root / "contracts top level executed"
        instrumented = (
            "\nfrom pathlib import Path as _EffectPath\n"
            f"_EffectPath({str(effect_marker)!r}).write_text('executed', encoding='utf-8')\n"
        ).encode("utf-8")
        path.write_bytes(path.read_bytes() + instrumented)

        result, _ = self.run_cli("verify", "--sdk-lock", self.fixture.lock_path,
                                 status=2, marker=False)
        self.assertIn("SDK file identity mismatch: host/contracts.py", result.stderr)
        self.assertFalse(effect_marker.exists(), "tampered contracts top-level code executed")

    def test_manifest_pins_the_running_cli_source(self):
        path = self.fixture.host_root / "cli.py"
        before = path.read_bytes()
        after = bytes([before[0] ^ 1]) + before[1:]
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)
        cli_row = next(row for row in self.fixture.manifest["files"] if row["path"] == "host/cli.py")
        cli_row.update(inventory_row(self.fixture.sdk_root, "host/cli.py"))
        self.fixture.write_manifest_and_lock()
        output = self.fixture.output_parent / "mismatched cli output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("running ami-rust CLI does not match", result.stderr)

    def test_same_length_driver_tamper_refuses_before_driver_effect(self):
        path = self.fixture.host_root / "build.py"
        before = path.read_bytes()
        after = before[:-1] + bytes([before[-1] ^ 1])
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)
        output = self.fixture.output_parent / "tampered driver output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("SDK file identity mismatch: host/build.py", result.stderr)

    def test_unlisted_host_helper_refuses_before_driver_effect(self):
        (self.fixture.host_root / "unlisted.py").write_text("marker = True\n", encoding="utf-8")
        output = self.fixture.output_parent / "unlisted helper output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("SDK host source inventory is incomplete", result.stderr)

    def test_manifest_hash_tamper_refuses_before_driver_effect(self):
        path = self.fixture.manifest_path
        before = path.read_bytes()
        after = before.replace(b'"version": "test-fixture"', b'"version": "fake-fixture"', 1)
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)
        output = self.fixture.output_parent / "tampered manifest output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("SDK manifest identity mismatch", result.stderr)

    def test_duplicate_inventory_entry_refuses_before_driver_effect(self):
        self.fixture.manifest["files"].append(dict(self.fixture.manifest["files"][0]))
        self.fixture.write_manifest_and_lock()
        output = self.fixture.output_parent / "duplicate inventory output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("duplicate SDK file inventory path", result.stderr)

    def test_unsafe_inventory_path_refuses_before_driver_effect(self):
        self.fixture.manifest["files"][0]["path"] = "../outside.py"
        self.fixture.write_manifest_and_lock()
        output = self.fixture.output_parent / "unsafe inventory output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("unsafe SDK file path", result.stderr)

    def test_bytecode_cache_refuses_before_driver_effect(self):
        cache = self.fixture.host_root / "__pycache__"
        cache.mkdir()
        (cache / "contracts.cpython-test.pyc").write_bytes(b"compiled marker")
        output = self.fixture.output_parent / "cache output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("Python bytecode cache", result.stderr)

    def test_tampered_python_identity_refuses_before_driver_effect(self):
        self.fixture.project["host"]["python_sha256"] = "0" * 64
        self.fixture.write_lock()
        output = self.fixture.output_parent / "tampered Python output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("selected Python identity mismatch", result.stderr)

    def test_different_correctly_hashed_python_path_refuses(self):
        decoy = self.base / "different pinned Python executable"
        decoy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        decoy.chmod(0o755)
        self.fixture.project["host"]["python"] = str(decoy)
        self.fixture.project["host"]["python_sha256"] = sha256(decoy)
        self.fixture.write_lock()
        self.assertNotEqual(decoy.resolve(strict=True), TEST_PYTHON.resolve(strict=True))

        result, _ = self.run_cli("verify", "--sdk-lock", self.fixture.lock_path,
                                 status=2, marker=False)
        self.assertIn("must run under the Python interpreter pinned", result.stderr)

    def test_duplicate_project_lock_key_refuses_before_driver_effect(self):
        text = self.fixture.lock_path.read_text(encoding="utf-8")
        needle = '"schema": "ami-rust-project-lock-v1",'
        self.assertIn(needle, text)
        self.fixture.lock_path.write_text(text.replace(
            needle, '"schema": "ambiguous",\n  ' + needle, 1), encoding="utf-8")
        output = self.fixture.output_parent / "duplicate lock output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("duplicate JSON key in project lock: schema", result.stderr)

    def test_symlink_in_host_tree_refuses_before_driver_effect(self):
        link = self.fixture.host_root / "linked.py"
        link.symlink_to("build.py")
        output = self.fixture.output_parent / "symlink output"
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("symlink in SDK host source tree", result.stderr)

    def test_existing_output_directory_refuses_before_driver_effect(self):
        output = self.fixture.output_parent / "already exists"
        output.mkdir()
        result, _ = self.run_cli("build", "--sdk-lock", self.fixture.lock_path,
                                 "--output-dir", output, "--", "build", status=2,
                                 marker=False)
        self.assertIn("output directory must be fresh", result.stderr)


if __name__ == "__main__":
    unittest.main()

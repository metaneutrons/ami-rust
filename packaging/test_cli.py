#!/usr/bin/env python3
"""Focused tests for the package-manager adapter and its trust boundaries."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load test module " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cli = load_module(HERE / "cli.py", "ami_rust_package_test_cli")
worker = load_module(HERE / "worker.py", "ami_rust_package_test_worker")


def package_fixture(root: Path) -> dict:
    """Create a tiny complete adapter package with one pinned SDK asset."""
    root.mkdir(parents=True)
    assets = root / "assets"
    assets.mkdir()
    asset_name = "ami-rust-0.1.0-release.tar.xz"
    asset_bytes = b"fixture SDK bytes\n"
    (assets / asset_name).write_bytes(asset_bytes)

    shutil.copyfile(HERE / "cli.py", root / "cli.py")
    shutil.copyfile(HERE / "worker.py", root / "worker.py")
    (root / "proofs.json").write_text('{"subjects":{}}\n', encoding="utf-8")
    (root / "LICENSE-MIT").write_text("MIT fixture notice\n", encoding="utf-8")
    (root / "LICENSE-APACHE").write_text("Apache fixture notice\n", encoding="utf-8")

    asset_row = {
        "path": asset_name,
        "bytes": len(asset_bytes),
        "sha256": hashlib.sha256(asset_bytes).hexdigest(),
    }
    pins = {
        "schema": "ami-rust-package-inputs-v1",
        "sdk_version": "0.1.0",
        "package_version": "0.1.0-1",
        "packaging_revision": 1,
        "sdk_tag": "v0.1.0",
        "repository": "metaneutrons/ami-rust",
        "source_commit": "a" * 40,
        "manifest_sha256": "b" * 64,
        "transport_sha256": "c" * 64,
        "assets": [asset_row],
    }
    (root / "pins.json").write_text(json.dumps(pins, sort_keys=True) + "\n", encoding="utf-8")

    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "inventory.json":
            continue
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        path.chmod(0o644)
        rows.append({
            "path": relative,
            "bytes": len(data),
            "mode": 0o644,
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    inventory = {
        "schema": "ami-rust-package-inventory-v1",
        "sdk_version": pins["sdk_version"],
        "package_version": pins["package_version"],
        "files": rows,
    }
    (root / "inventory.json").write_text(json.dumps(inventory, sort_keys=True) + "\n", encoding="utf-8")
    return pins


def rewrite_inventory(root: Path, mutate) -> None:
    path = root / "inventory.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def strings(arguments) -> list[str]:
    return [str(value) for value in arguments]


class PackageInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fixture(self) -> tuple[Path, dict]:
        root = self.root / "package"
        pins = package_fixture(root)
        return root, pins

    def test_tiny_complete_package_passes(self) -> None:
        root, pins = self.fixture()
        self.assertEqual(cli.verify_package(root), pins)

    def test_changed_bytes_are_rejected(self) -> None:
        root, _pins = self.fixture()
        asset = root / "assets/ami-rust-0.1.0-release.tar.xz"
        asset.write_bytes(b"fixture SDK byteS\n")
        with self.assertRaises(ValueError):
            cli.verify_package(root)

    def test_symlinked_inventory_file_is_rejected(self) -> None:
        root, _pins = self.fixture()
        asset = root / "assets/ami-rust-0.1.0-release.tar.xz"
        target = root / "assets/target"
        asset.unlink()
        target.write_bytes(b"fixture SDK bytes\n")
        asset.symlink_to(target)
        with self.assertRaises(ValueError):
            cli.verify_package(root)

    def test_missing_file_is_rejected(self) -> None:
        root, _pins = self.fixture()
        (root / "assets/ami-rust-0.1.0-release.tar.xz").unlink()
        with self.assertRaises((OSError, ValueError)):
            cli.verify_package(root)

    def test_extra_file_is_rejected(self) -> None:
        root, _pins = self.fixture()
        (root / "unexpected.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            cli.verify_package(root)

    def test_duplicate_inventory_path_is_rejected(self) -> None:
        root, _pins = self.fixture()
        rewrite_inventory(root, lambda inventory: inventory["files"].append(dict(inventory["files"][0])))
        with self.assertRaises(ValueError):
            cli.verify_package(root)

    def test_unsafe_inventory_path_is_rejected(self) -> None:
        root, _pins = self.fixture()
        rewrite_inventory(root, lambda inventory: inventory["files"][0].update({"path": "../outside"}))
        with self.assertRaises(ValueError):
            cli.verify_package(root)

    def test_duplicate_json_key_is_rejected(self) -> None:
        root, _pins = self.fixture()
        (root / "pins.json").write_text('{"schema":"one","schema":"two"}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            cli.verify_package(root)


class HostProfileTests(unittest.TestCase):
    def test_only_macos_26_arm64_and_ubuntu_24_04_x64_are_supported(self) -> None:
        with (
            mock.patch.object(cli.platform, "system", return_value="Darwin"),
            mock.patch.object(cli.platform, "machine", return_value="arm64"),
            mock.patch.object(cli.platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "")),
        ):
            self.assertEqual(cli.host_key(), "macos-aarch64")

        with (
            mock.patch.object(cli.platform, "system", return_value="Linux"),
            mock.patch.object(cli.platform, "machine", return_value="x86_64"),
            mock.patch.object(cli.Path, "read_text", return_value='ID="ubuntu"\nVERSION_ID="24.04"\n'),
        ):
            self.assertEqual(cli.host_key(), "linux-x86_64")

    def test_other_architectures_and_os_releases_are_rejected(self) -> None:
        unsupported = (
            ("Darwin", "x86_64", "26.0.0", None),
            ("Darwin", "arm64", "15.0.0", None),
            ("Linux", "aarch64", "", 'ID="ubuntu"\nVERSION_ID="24.04"\n'),
            ("Linux", "x86_64", "", 'ID="ubuntu"\nVERSION_ID="22.04"\n'),
            ("Linux", "x86_64", "", 'ID="debian"\nVERSION_ID="24.04"\n'),
        )
        for system, machine, version, os_release in unsupported:
            with self.subTest(system=system, machine=machine, version=version, os_release=os_release):
                patches = [
                    mock.patch.object(cli.platform, "system", return_value=system),
                    mock.patch.object(cli.platform, "machine", return_value=machine),
                    mock.patch.object(cli.platform, "mac_ver", return_value=(version, ("", "", ""), "")),
                ]
                if os_release is not None:
                    patches.append(mock.patch.object(cli.Path, "read_text", return_value=os_release))
                with patches[0], patches[1], patches[2]:
                    if os_release is None:
                        context = mock.patch.object(cli.platform, "mac_ver", return_value=(version, ("", "", ""), ""))
                    else:
                        context = patches[3]
                    with context:
                        with self.assertRaises(ValueError):
                            cli.host_key()


NONROOT = not hasattr(os, "getuid") or os.getuid() != 0


@unittest.skipUnless(NONROOT, "production state policy requires a regular non-root user")
class StatePathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_fresh_and_private_existing_states_are_accepted(self) -> None:
        state = self.root / "fresh-state"
        self.assertEqual(cli.state_path(str(state), fresh=True), state)
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        self.assertEqual(cli.state_path(str(state)), state)

    def test_non_private_state_is_rejected(self) -> None:
        state = self.root / "public-state"
        state.mkdir(mode=0o700)
        state.chmod(0o755)
        with self.assertRaises(ValueError):
            cli.state_path(str(state))

    def test_existing_and_non_normalized_fresh_paths_are_rejected(self) -> None:
        existing = self.root / "existing"
        existing.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            cli.state_path(str(existing), fresh=True)
        with self.assertRaises(ValueError):
            cli.state_path(str(self.root / "unused" / ".." / "normalized"), fresh=True)

    def test_symlink_component_is_rejected(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            cli.state_path(str(alias / "state"), fresh=True)

    def test_package_overlap_is_rejected(self) -> None:
        state = self.root / "state"
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        package = state / "ordinary-package"
        package.mkdir()
        package_state = package / "nested-state"
        package_state.mkdir(mode=0o700)
        package_state.chmod(0o700)
        with mock.patch.object(cli, "PACKAGE", package):
            with self.assertRaises(ValueError):
                cli.state_path(str(package_state))

        nested_package = state / "nested" / "package"
        nested_package.mkdir(parents=True)
        with mock.patch.object(cli, "PACKAGE", nested_package):
            with self.assertRaises(ValueError):
                cli.state_path(str(state))

    def test_state_ancestor_of_retained_package_is_allowed_for_recovery(self) -> None:
        state = self.root / "state"
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        retained_package = state / "retained/libexec/ami-rust/0.1.0-1"
        retained_package.mkdir(parents=True)
        with mock.patch.object(cli, "PACKAGE", retained_package):
            self.assertEqual(cli.state_path(str(state)), state)


class AdapterCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "state"
        self.state.mkdir()
        self.pins = {
            "sdk_version": "0.1.0",
            "package_version": "0.1.0-1",
            "sdk_tag": "v0.1.0",
            "repository": "metaneutrons/ami-rust",
            "source_commit": "a" * 40,
            "manifest_sha256": "b" * 64,
            "transport_sha256": "c" * 64,
            "assets": [],
        }
        self.python = self.state / "ami-rust-python-bootstrap/runtime/python/bin/python3.12"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(self, args: list[str], calls: list[list[str]]) -> None:
        with (
            mock.patch.object(cli, "verify_package", return_value=self.pins),
            mock.patch.object(cli, "ready_state", return_value=(self.state, self.python)),
            mock.patch.object(cli, "run", side_effect=lambda command, **_kwargs: calls.append(strings(command))),
        ):
            self.assertEqual(cli.main(args), 0)

    def test_new_calls_both_original_sdk_entrypoints_with_exact_arguments(self) -> None:
        receipt = self.state / "receipt.sha256"
        receipt.write_text("d" * 64 + "\n", encoding="utf-8")
        project = self.root / "project"
        calls: list[list[str]] = []
        self.invoke(["new", "--state", str(self.state), "--project", str(project)], calls)

        prefix = self.state / "sdk-0.1.0"
        bundle = self.state / "ami-rust-public-authenticated-bundle"
        self.assertEqual(calls, [
            [str(self.python), "-I", "-B", str(bundle / "new_project.py"), "--sdk", str(prefix / "sdk"),
             "--output", str(project), "--receipt-sha256", "d" * 64],
            [str(self.python), "-I", "-B", str(bundle / "install_publisher.py"), "lock", "--prefix", str(prefix),
             "--selection", str(self.state / "selection.json"), "--project", str(project),
             "--output", str(project / "ami-rust.lock.json")],
        ])

    def test_build_defaults_package_and_forwards_features_after_separator(self) -> None:
        project = self.root / "project"
        output = self.root / "build-output"
        calls: list[list[str]] = []
        self.invoke(["build", "--state", str(self.state), "--project", str(project), "--output-dir", str(output),
                     "--", "--features", "wire,debug"], calls)
        prefix = self.state / "sdk-0.1.0"
        self.assertEqual(calls, [[
            str(self.python), "-I", "-B", str(prefix / "sdk/host/cli.py"), "build", "--sdk-lock",
            str(project / "ami-rust.lock.json"), "--output-dir", str(output), "--", "build",
            "--manifest-path", str(project / "Cargo.toml"), "--package", "hello-aros", "--release",
            "--locked", "--offline", "--features", "wire,debug",
        ]])

    def test_build_accepts_explicit_package_before_separator(self) -> None:
        project = self.root / "project"
        output = self.root / "build-output"
        calls: list[list[str]] = []
        self.invoke(["build", "--state", str(self.state), "--project", str(project), "--output-dir", str(output),
                     "--package", "custom-aros-app", "--", "--features", "networking"], calls)
        prefix = self.state / "sdk-0.1.0"
        self.assertEqual(calls, [[
            str(self.python), "-I", "-B", str(prefix / "sdk/host/cli.py"), "build", "--sdk-lock",
            str(project / "ami-rust.lock.json"), "--output-dir", str(output), "--", "build",
            "--manifest-path", str(project / "Cargo.toml"), "--package", "custom-aros-app", "--release",
            "--locked", "--offline", "--features", "networking",
        ]])

    def test_check_inputs_calls_the_original_source_verifier(self) -> None:
        calls: list[list[str]] = []
        self.invoke(["check-inputs", "--state", str(self.state)], calls)
        bundle = self.state / "ami-rust-public-authenticated-bundle"
        source = self.state / "source"
        self.assertEqual(calls, [[
            str(self.python), "-I", "-B", str(source / "release/ci_verify.py"), "check-inputs",
            "--bundle", str(bundle), "--work", str(self.state / "preparation"),
            "--output", str(self.state / "preparation-output"), "--python-bootstrap-root",
            str(self.state / "ami-rust-python-bootstrap"), "--source-commit", self.pins["source_commit"],
            "--workflow-commit", self.pins["source_commit"], "--selection", str(self.state / "selection.json"),
        ]])

    @unittest.skipUnless(NONROOT, "production preparation policy requires a regular non-root user")
    def test_prepare_calls_pinned_git_and_original_prerequisite_entrypoints(self) -> None:
        package = self.root / "installed-package"
        package_fixture(package)
        state = self.root / "new-state"
        pins = dict(self.pins)
        pins["package_version"] = "0.1.0-1"
        calls: list[tuple[list[str], dict]] = []

        def fake_run(command, **kwargs):
            command_strings = strings(command)
            calls.append((command_strings, kwargs))
            if len(command_strings) > 3 and command_strings[3].endswith("/worker.py"):
                (state / "ready.json").write_text(json.dumps({
                    "host": "macos-aarch64",
                    "source_commit": pins["source_commit"],
                }) + "\n", encoding="utf-8")

        with (
            mock.patch.object(cli, "PACKAGE", package),
            mock.patch.object(cli, "host_key", return_value="macos-aarch64"),
            mock.patch.object(cli, "run", side_effect=fake_run),
            mock.patch.object(cli.subprocess, "check_output", return_value=pins["source_commit"]),
            mock.patch("sys.stdout", io.StringIO()),
        ):
            cli.prepare(str(state), pins)

        source = state / "source"
        retained = state / "retained/libexec/ami-rust/0.1.0-1"
        python_root = state / "ami-rust-python-bootstrap"
        python = python_root / "runtime/python/bin/python3.12"
        expected = [
            ["/usr/bin/git", "-c", "init.defaultBranch=main", "init", "--template=", str(source)],
            ["/usr/bin/git", "-C", str(source), "remote", "add", "origin",
             "https://github.com/metaneutrons/ami-rust.git"],
            ["/usr/bin/git", "-C", str(source), "-c", "core.hooksPath=/dev/null", "fetch", "--depth=1",
             "origin", pins["source_commit"]],
            ["/usr/bin/git", "-C", str(source), "-c", "core.hooksPath=/dev/null", "checkout", "--detach",
             pins["source_commit"]],
            [sys.executable, "-I", "-B", str(source / "release/ci_python.py"), "--prefix", str(python_root),
             "--inputs", str(source / "release/ci-python-inputs.json")],
            [str(python), "-I", "-B", str(retained / "worker.py"), "--state", str(state)],
        ]
        self.assertEqual([call for call, _kwargs in calls], expected)
        ci_verify = (SOURCE / "release/ci_verify.py").read_text(encoding="utf-8")
        self.assertIn('if python_root.name != "ami-rust-python-bootstrap":', ci_verify)
        actual_python_root = Path(calls[4][0][calls[4][0].index("--prefix") + 1])
        self.assertEqual(actual_python_root.name, "ami-rust-python-bootstrap")
        self.assertEqual(actual_python_root, python_root)
        self.assertEqual(calls[-1][1].get("timeout"), 2400)
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        self.assertTrue((state / "retained/bin/ami-rust").is_file())

    def test_ready_state_failure_precedes_any_sdk_subprocess(self) -> None:
        project = self.root / "project"
        cases = (
            ("missing", None),
            ("wrong-host", "wrong-host"),
            ("wrong-manifest", "wrong-manifest"),
        )
        for name, mismatch in cases:
            with self.subTest(name=name):
                state = self.root / name
                state.mkdir(mode=0o700)
                state.chmod(0o700)
                if mismatch is not None:
                    ready = {
                        "schema": "ami-rust-package-state-v1",
                        "status": "READY",
                        "host": "macos-aarch64",
                        "sdk_version": self.pins["sdk_version"],
                        "source_commit": self.pins["source_commit"],
                        "manifest_sha256": self.pins["manifest_sha256"],
                    }
                    if mismatch == "wrong-host":
                        ready["host"] = "unsupported"
                    else:
                        ready["manifest_sha256"] = "0" * 64
                    (state / "ready.json").write_text(json.dumps(ready) + "\n", encoding="utf-8")
                calls = mock.Mock()
                with (
                    mock.patch.object(cli, "verify_package", return_value=self.pins),
                    mock.patch.object(cli, "state_path", return_value=state),
                    mock.patch.object(cli, "host_key", return_value="macos-aarch64"),
                    mock.patch.object(cli, "run", calls),
                ):
                    with self.assertRaises((OSError, ValueError)):
                        cli.main(["new", "--state", str(state), "--project", str(project)])
                calls.assert_not_called()

    @unittest.skipUnless(NONROOT, "production state policy requires a regular non-root user")
    def test_process_exit_preserves_original_sdk_failure_status(self) -> None:
        package = self.root / "package"
        pins = package_fixture(package)
        state = self.root / "state"
        state.chmod(0o700)
        (state / "receipt.sha256").write_text("d" * 64 + "\n", encoding="utf-8")
        (state / "ready.json").write_text(json.dumps({
            "schema": "ami-rust-package-state-v1",
            "status": "READY",
            "host": "macos-aarch64",
            "sdk_version": pins["sdk_version"],
            "source_commit": pins["source_commit"],
            "manifest_sha256": pins["manifest_sha256"],
        }) + "\n", encoding="utf-8")

        argv = ["ami-rust", "new", "--state", str(state), "--project", str(self.root / "project")]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(cli.platform, "system", return_value="Darwin"),
            mock.patch.object(cli.platform, "machine", return_value="arm64"),
            mock.patch.object(cli.platform, "mac_ver", return_value=("26.0.0", ("", "", ""), "")),
            mock.patch.object(subprocess, "run", side_effect=subprocess.CalledProcessError(37, ["sdk"])),
        ):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(package / "cli.py"), run_name="__main__")
        self.assertEqual(raised.exception.code, 37)


class WorkerProofSetTests(unittest.TestCase):
    def test_incomplete_publisher_subject_set_fails_before_install(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        package = root / "package"
        proofs_dir = package / "proofs"
        proofs_dir.mkdir(parents=True)
        proof_path = proofs_dir / "only-proof.json"
        proof_bytes = b"fixture proof\n"
        proof_path.write_bytes(proof_bytes)

        source_commit = "a" * 40
        pins = {
            "source_commit": source_commit,
            "sdk_version": "0.1.0",
            "package_version": "0.1.0-1",
            "sdk_tag": "v0.1.0",
            "transport_sha256": "c" * 64,
            "manifest_sha256": "b" * 64,
        }
        proof_index = {"subjects": {"unexpected-subject": [{
            "path": proof_path.name,
            "bytes": len(proof_bytes),
            "sha256": hashlib.sha256(proof_bytes).hexdigest(),
        }]}}
        adapter = types.SimpleNamespace(
            verify_package=lambda _package: pins,
            read_json=lambda _path: proof_index,
            digest=lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            run=mock.Mock(),
        )

        trusted = types.SimpleNamespace(
            consumer_source_identity=lambda *_args: object(),
            bootstrap_tools=mock.Mock(),
            host_identity=lambda: "macos-aarch64",
            strict_json=lambda *_args: {},
            _verify_tool_receipt=lambda *_args: {"roots": {}},
            _write_source_policy=lambda *_args: (root / "source-policy.json", {}),
            prepare_consumer_inputs=mock.Mock(),
        )
        candidate = load_module(SOURCE / "release/public_candidate.py", "ami_rust_cli_test_public_candidate")

        class FakeReplay:
            @staticmethod
            def _load_trusted_helpers(_source):
                return trusted

            @staticmethod
            def _authenticate_public_candidate(**kwargs):
                names = kwargs["public_candidate"].stage_candidate.asset_names(kwargs["tag"])
                expected = {names[key] for key in ("payload", "sbom", "transport", "checksums")}
                kwargs["public_candidate"]._proof_inputs(
                    kwargs["gh_bundles"], expected, kwargs["candidate"], kwargs["output"], 0
                )

        modules = {
            "cli.py": adapter,
            "public_replay.py": FakeReplay,
            "public_candidate.py": candidate,
        }
        source = root / "state/source"
        state = root / "state"
        source.mkdir(parents=True)
        with (
            mock.patch.object(worker, "__file__", str(package / "worker.py")),
            mock.patch.object(worker, "load", side_effect=lambda path, _name: modules[Path(path).name]),
        ):
            with self.assertRaisesRegex(ValueError, "exactly the four attested subjects"):
                worker.prepare(state)

        adapter.run.assert_not_called()
        trusted.prepare_consumer_inputs.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)

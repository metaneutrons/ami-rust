#!/usr/bin/env python3
"""Focused tests for the bounded native host-tool preflight proposal."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

DRIVER = Path(__file__).resolve().parents[1] / "tools/supervise-portable-csdk-linux-aarch64.py"


def load_driver():
    spec = importlib.util.spec_from_file_location("csdk_host_tool_resolution_fixture", DRIVER)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load proposed driver")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NativeHostToolPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()

    def write_tool(self, path: Path, body: str = "printf 'fixture\\n'\n", executable=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755 if executable else 0o644)
        return path

    def test_fixed_search_includes_runner_local_tools(self):
        self.assertEqual(self.driver.NATIVE_TOOL_SEARCH_PATH, "/usr/local/bin:/usr/bin:/bin")

    def test_controlled_directory_wins_over_ambient_path(self):
        with tempfile.TemporaryDirectory(prefix="csdk-tool-path-") as temporary:
            root = Path(temporary)
            controlled, ambient, cwd = root / "controlled", root / "ambient", root / "cwd"
            controlled.mkdir(); ambient.mkdir(); cwd.mkdir()
            fixture = self.write_tool(controlled / "cmake", "printf 'controlled cmake\\n'\n")
            self.write_tool(ambient / "cmake", "printf 'ambient cmake\\n'\n")
            original = self.driver.NATIVE_TOOL_SEARCH_PATH
            try:
                self.driver.NATIVE_TOOL_SEARCH_PATH = str(controlled)
                path, record = self.driver.tool_identity(
                    "cmake", "cmake", ["--version"], cwd, {"PATH": str(ambient)})
            finally:
                self.driver.NATIVE_TOOL_SEARCH_PATH = original
            self.assertEqual(path, fixture.resolve())
            self.assertEqual(record["selected_path"], str(fixture))
            self.assertIn("controlled cmake", record["version"]["stdout"])

    def test_nonexecutable_controlled_tool_does_not_fall_back_to_ambient(self):
        with tempfile.TemporaryDirectory(prefix="csdk-tool-nonexec-") as temporary:
            root = Path(temporary)
            controlled, ambient, cwd = root / "controlled", root / "ambient", root / "cwd"
            controlled.mkdir(); ambient.mkdir(); cwd.mkdir()
            self.write_tool(controlled / "cmake", executable=False)
            self.write_tool(ambient / "cmake")
            original = self.driver.NATIVE_TOOL_SEARCH_PATH
            try:
                self.driver.NATIVE_TOOL_SEARCH_PATH = str(controlled)
                with self.assertRaisesRegex(ValueError, "required native host tool is unavailable: cmake"):
                    self.driver.tool_identity("cmake", "cmake", ["--version"], cwd, {"PATH": str(ambient)})
            finally:
                self.driver.NATIVE_TOOL_SEARCH_PATH = original

    def fixture_tools(self, root: Path, cc_target="aarch64-linux-gnu"):
        bindir, cwd = root / "bin", root / "cwd"
        bindir.mkdir(); cwd.mkdir()
        names = ("cc", "cmake", "pkg-config", "perl", "git", "patch")
        paths = {}
        for name in names:
            if name == "cc":
                body = "if [ \"$1\" = \"-dumpmachine\" ]; then printf '" + cc_target + "\\n'; else printf 'fixture cc\\n'; fi\n"
            else:
                body = "printf 'fixture " + name + "\\n'\n"
            paths[name] = self.write_tool(bindir / name, body)
        mapping = {name: (str(paths[name]) if name == "patch" else name, ["--version"])
                   for name in names}
        return bindir, cwd, paths, mapping

    def test_all_six_tools_and_cc_target_are_checked_as_one_preflight(self):
        with tempfile.TemporaryDirectory(prefix="csdk-tool-set-") as temporary:
            root = Path(temporary); bindir, cwd, paths, mapping = self.fixture_tools(root)
            saved_search, saved_tools = self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS
            try:
                self.driver.NATIVE_TOOL_SEARCH_PATH = str(bindir)
                self.driver.NATIVE_TOOLS = mapping
                records, resolved = self.driver.collect_native_host_tools(cwd, {"PATH": "/ambient/ignored"})
            finally:
                self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS = saved_search, saved_tools
            self.assertEqual(set(resolved), set(paths))
            self.assertEqual(set(records), set(paths) | {"cc_target"})
            self.assertIn("aarch64", records["cc_target"]["stdout"])

    def test_wrong_compiler_target_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="csdk-tool-wrong-target-") as temporary:
            root = Path(temporary); bindir, cwd, paths, mapping = self.fixture_tools(root, "x86_64-linux-gnu")
            saved_search, saved_tools = self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS
            try:
                self.driver.NATIVE_TOOL_SEARCH_PATH = str(bindir)
                self.driver.NATIVE_TOOLS = mapping
                with self.assertRaisesRegex(ValueError, "native C compiler does not target the runner's AArch64 host"):
                    self.driver.collect_native_host_tools(cwd, {"PATH": "/ambient/ignored"})
            finally:
                self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS = saved_search, saved_tools

    def test_missing_controlled_tool_is_refused_despite_ambient_executable(self):
        with tempfile.TemporaryDirectory(prefix="csdk-tool-missing-") as temporary:
            root = Path(temporary); bindir, cwd, paths, mapping = self.fixture_tools(root)
            (bindir / "cmake").unlink()
            ambient = root / "ambient"; ambient.mkdir()
            self.write_tool(ambient / "cmake")
            saved_search, saved_tools = self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS
            try:
                self.driver.NATIVE_TOOL_SEARCH_PATH = str(bindir)
                self.driver.NATIVE_TOOLS = mapping
                with self.assertRaisesRegex(ValueError, "required native host tool is unavailable: cmake"):
                    self.driver.collect_native_host_tools(cwd, {"PATH": str(ambient)})
            finally:
                self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS = saved_search, saved_tools

    def test_host_tool_mutation_remains_a_hard_failure(self):
        with tempfile.TemporaryDirectory(prefix="csdk-tool-mutation-") as temporary:
            root = Path(temporary); bindir, cwd, paths, mapping = self.fixture_tools(root)
            saved_search, saved_tools = self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS
            try:
                self.driver.NATIVE_TOOL_SEARCH_PATH = str(bindir)
                self.driver.NATIVE_TOOLS = mapping
                records, _ = self.driver.collect_native_host_tools(cwd, {"PATH": str(root / "unused")})
                self.driver.verify_native_host_tools_unchanged(records)
                paths["cmake"].write_text("#!/bin/sh\nprintf 'mutated cmake\n'\n")
                paths["cmake"].chmod(0o755)
                with self.assertRaisesRegex(ValueError, "native host tool changed during C-SDK production: cmake"):
                    self.driver.verify_native_host_tools_unchanged(records)
            finally:
                self.driver.NATIVE_TOOL_SEARCH_PATH, self.driver.NATIVE_TOOLS = saved_search, saved_tools


if __name__ == "__main__":
    unittest.main(verbosity=2)

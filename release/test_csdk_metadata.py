"""Offline tests for the pinned AOM metadata probe."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import shlex
import tarfile
import tempfile
import unittest
from unittest import mock


_SPEC = importlib.util.spec_from_file_location(
    "_test_csdk_metadata", Path(__file__).with_name("csdk_metadata.py")
)
_METADATA = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_METADATA)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class FakeSupervisor:
    """Filesystem-only runner for the metadata protocol; no tools are executed."""

    def __init__(self, generated_pc: bytes, *, fail_on: str | None = None,
                 escape_prefix_spaces: bool = False):
        self.env = {"PATH": "/test/path", "PKG_CONFIG_PATH": "/host/path"}
        self.commands = []
        self.labels = []
        self.generated_pc = generated_pc
        self.fail_on = fail_on
        self.escape_prefix_spaces = escape_prefix_spaces
        self.peak_rss = 0
        self.peak_workspace = 0

    def _record(self, command, cwd, label, timeout):
        if timeout > 60:
            raise AssertionError("metadata command exceeded the 60-second bound")
        if label in self.labels:
            raise AssertionError("duplicate process label")
        self.labels.append(label)
        row = {"command": list(command), "cwd": str(cwd), "label": label, "timeout": timeout}
        self.commands.append(row)
        if self.fail_on and self.fail_on in label:
            raise RuntimeError("injected supervisor failure")
        return row

    @staticmethod
    def _argument(command, name):
        prefix = "-D" + name + "="
        return next(Path(arg[len(prefix):]) for arg in command if arg.startswith(prefix))

    def run(self, command, *, cwd, label, timeout):
        row = self._record(command, cwd, label, timeout)
        if "-version-" in label:
            config = self._argument(command, "AOM_CONFIG_DIR")
            (config / "config").mkdir(parents=True, exist_ok=True)
            (config / "config/aom_version.h").write_bytes(b"/* generated version */\n")
        elif "-pkgconfig-" in label:
            config = self._argument(command, "AOM_CONFIG_DIR")
            config.mkdir(parents=True, exist_ok=True)
            (config / "aom.pc").write_bytes(self.generated_pc)
        elif "-unpatched-target-counter" in label:
            config = self._argument(command, "AOM_CONFIG_DIR")
            install_prefix = self._argument(command, "CMAKE_INSTALL_PREFIX")
            config.mkdir(parents=True, exist_ok=True)
            raw = (b"prefix=" + str(install_prefix).encode() +
                   b"\nLibs.private: -lm\n")
            (config / "aom.pc").write_bytes(raw)
        return row

    def run_text(self, command, *, cwd, label, timeout):
        self._record(command, cwd, label, timeout)
        pkgdir = Path(self.env["PKG_CONFIG_LIBDIR"])
        pc = (pkgdir / "aom.pc").read_bytes()
        prefix_line = next(line for line in pc.splitlines() if line.startswith(b"prefix="))
        prefix = prefix_line[len(b"prefix="):].decode()
        if "--variable=prefix" in command:
            if prefix == "${pcfiledir}/../..":
                prefix = str(pkgdir.parent.parent)
            if self.escape_prefix_spaces:
                return prefix.replace(" ", "\\ ")
            return prefix
        if prefix == "${pcfiledir}/../..":
            prefix = str(pkgdir.parent.parent)
        return shlex.join(["-I" + prefix + "/include", "-L" + prefix + "/lib", "-laom"])


class AomMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aom metadata ")
        self.root = Path(self.temp.name)
        self.source = self.root / "source with spaces"
        (self.source / "build/cmake").mkdir(parents=True)
        self.patched_script = b"# pinned patched generator fixture\n"
        (self.source / "build/cmake/pkg_config.cmake").write_bytes(self.patched_script)
        self.original_script = b"# pinned upstream generator fixture\n"
        self.archive = self.root / "libaom original.tar.gz"
        self.members = {
            "build/cmake/util.cmake": b"# util\n",
            "build/cmake/version.cmake": b"# version script\n",
            "build/cmake/version.pl": b"# version helper\n",
            "CHANGELOG": b"libaom fixture changelog\n",
            "build/cmake/pkg_config.cmake": self.original_script,
        }
        self._write_archive()
        self.original_pc = (
            b"# libaom pkg-config.\n"
            b"prefix=/legacy SDK/prefix\n"
            b"exec_prefix=${prefix}\n"
            b"includedir=${prefix}/include\n"
            b"libdir=${prefix}/lib\n"
            b"Libs: -L${libdir} -laom\n"
        )
        self.generated_pc = self.original_pc.replace(
            b"prefix=/legacy SDK/prefix\n", b"prefix=${pcfiledir}/../..\n"
        )
        self.tools = {}
        for name in _METADATA._TOOLS:
            path = self.root / (name.replace("/", "-") + " fake tool")
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)
            self.tools[name] = path
        self.supervisor = FakeSupervisor(self.generated_pc)

    def tearDown(self):
        self.temp.cleanup()

    def _write_archive(self, *, duplicate_member: bool = False):
        with tarfile.open(self.archive, "w:gz") as archive:
            for relative, raw in self.members.items():
                member = tarfile.TarInfo("libaom-3.12.1/" + relative)
                member.size = len(raw)
                archive.addfile(member, __import__("io").BytesIO(raw))
                if duplicate_member and relative == "build/cmake/util.cmake":
                    archive.addfile(member, __import__("io").BytesIO(raw))

    def _pinned_constants(self):
        return (
            mock.patch.object(_METADATA, "LIBAOM_ARCHIVE_SHA256", digest(self.archive.read_bytes())),
            mock.patch.object(_METADATA, "PATCHED_PKG_CONFIG_SHA256", digest(self.patched_script)),
            mock.patch.object(_METADATA, "ORIGINAL_PKG_CONFIG_SHA256", digest(self.original_script)),
            mock.patch.object(_METADATA, "GENERATED_PC_SHA256", digest(self.generated_pc)),
        )

    def _call(self, destination=None):
        patches = self._pinned_constants()
        for patcher in patches:
            patcher.start()
        try:
            return _METADATA.generate_aom_metadata(
                self.source, self.archive, self.original_pc,
                destination or (self.root / "destination with spaces"),
                self.supervisor, tools=self.tools,
            )
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    def test_generates_relocatable_metadata_and_both_countercases_in_space_paths(self):
        env_before = self.supervisor.env
        report = self._call()

        self.assertEqual(report["status"], "PASS_AOM_METADATA_ONLY")
        self.assertEqual(report["aom_pc_sha256"], digest(self.generated_pc))
        self.assertTrue(report["two_roots_byte_identical"])
        self.assertEqual(Path(report["generated_pc_path"]).read_bytes(), self.generated_pc)
        self.assertEqual(report["counter_cases"]["unpatched_target"]["standalone_libm_detected"], True)
        self.assertEqual(report["counter_cases"]["original_pc"]["embedded_prefix"], "/legacy SDK/prefix")
        self.assertEqual(len(report["relocation"]), 2)
        self.assertIs(self.supervisor.env, env_before)
        self.assertEqual(self.supervisor.env["PKG_CONFIG_PATH"], "/host/path")
        self.assertEqual(len(self.supervisor.labels), len(set(self.supervisor.labels)))
        self.assertTrue(all(row["timeout"] <= 60 for row in self.supervisor.commands))
        self.assertEqual(set(report["tools"]), set(_METADATA._TOOLS))
        self.assertTrue(all(row["sha256_before"] == row["sha256_after"]
                            for row in report["tools"].values()))
        self.assertEqual((self.source / "build/cmake/version.pl").read_bytes(), b"# version helper\n")
        wrapper = (Path(report["generated_pc_path"]).parents[1] / "target-metadata.cmake").read_text()
        self.assertLess(wrapper.index('set(CMAKE_SYSTEM_NAME "AROS")'), wrapper.index("include("))
        self.assertLess(wrapper.index("set(APPLE FALSE)"), wrapper.index("include("))
        self.assertLess(wrapper.index("set(WIN32 FALSE)"), wrapper.index("include("))

    def test_accepts_absolute_shell_escaped_prefixes_with_spaces(self):
        self.supervisor = FakeSupervisor(self.generated_pc, escape_prefix_spaces=True)
        report = self._call(self.root / "escaped destination with spaces")
        self.assertTrue(report["two_roots_byte_identical"])
        self.assertEqual(len(report["relocation"]), 2)
        self.assertEqual(report["counter_cases"]["original_pc"]["embedded_prefix"], "/legacy SDK/prefix")

    def test_rejects_cmake_injection_in_a_destination_path(self):
        patches = self._pinned_constants()
        for patcher in patches:
            patcher.start()
        try:
            with self.assertRaisesRegex(ValueError, "unsafe CMake syntax"):
                _METADATA.generate_aom_metadata(
                    self.source, self.archive, self.original_pc,
                    self.root / "bad;destination", self.supervisor, tools=self.tools,
                )
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertEqual(self.supervisor.commands, [])

    def test_rejects_nested_source_and_destination_before_mutation(self):
        patches = self._pinned_constants()
        for patcher in patches:
            patcher.start()
        try:
            with self.assertRaisesRegex(ValueError, "must be disjoint"):
                _METADATA.generate_aom_metadata(
                    self.source, self.archive, self.original_pc,
                    self.source / "metadata output", self.supervisor, tools=self.tools,
                )
            with self.assertRaisesRegex(ValueError, "must be disjoint"):
                _METADATA.generate_aom_metadata(
                    self.source, self.archive, self.original_pc,
                    self.root, self.supervisor, tools=self.tools,
                )
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertFalse((self.source / "metadata output").exists())
        self.assertEqual(self.supervisor.commands, [])

    def test_rejects_duplicate_bounded_archive_members_before_commands(self):
        self._write_archive(duplicate_member=True)
        patches = self._pinned_constants()
        for patcher in patches:
            patcher.start()
        try:
            with self.assertRaisesRegex(ValueError, "duplicate pinned libaom archive member"):
                _METADATA.generate_aom_metadata(
                    self.source, self.archive, self.original_pc,
                    self.root / "destination", self.supervisor, tools=self.tools,
                )
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertEqual(self.supervisor.commands, [])

    def test_supervisor_environment_is_restored_when_a_command_fails(self):
        self.supervisor.fail_on = "-pkgconfig-0"
        env_before = self.supervisor.env
        patches = self._pinned_constants()
        for patcher in patches:
            patcher.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "injected supervisor failure"):
                _METADATA.generate_aom_metadata(
                    self.source, self.archive, self.original_pc,
                    self.root / "failing destination", self.supervisor, tools=self.tools,
                )
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        self.assertIs(self.supervisor.env, env_before)
        self.assertEqual(self.supervisor.env["PKG_CONFIG_PATH"], "/host/path")


if __name__ == "__main__":
    unittest.main()

"""Synthetic boundary tests for the bounded Nouveau compile planner."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

_NOUVEAU_PATH = Path(__file__).resolve().with_name("csdk_nouveau.py")
_NOUVEAU_SPEC = importlib.util.spec_from_file_location("_csdk_nouveau_test", _NOUVEAU_PATH)
if _NOUVEAU_SPEC is None or _NOUVEAU_SPEC.loader is None:  # pragma: no cover - filesystem failure
    raise ImportError("cannot load sibling csdk_nouveau.py")
csdk_nouveau = importlib.util.module_from_spec(_NOUVEAU_SPEC)
_NOUVEAU_SPEC.loader.exec_module(csdk_nouveau)
csdk_recipes = csdk_nouveau.csdk_recipes


COUNT = csdk_nouveau.EXPECTED_OBJECTS
TOOLCHAIN_PLACEHOLDER = (
    "${CROSS_TOOLCHAIN_ROOT}/v0.1.4/macos-aarch64/pc-x86_64/"
    + "9" * 64 + "/toolchain/bin/clang"
)
MEMBER_PREFIX = "CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/testsrc/"
SOURCE_PREFIX = "AROS-NX/workbench/hidds/nouveau/testsrc/"


def _object_name(index: int) -> str:
    return f"file{index:04d}.c.obj"


def _object_member(index: int) -> str:
    return MEMBER_PREFIX + _object_name(index)


def _raw_record(index: int) -> dict:
    source = SOURCE_PREFIX + f"file{index:04d}.c"
    object_member = _object_member(index)
    argv = [
        TOOLCHAIN_PLACEHOLDER,
        "--target=x86_64-unknown-aros",
        "-DTEST_DEFINE=1",
        "-IAROS-NX/build/pc-x86_64/SDK/include",
        "-iquoteAROS-NX/workbench/hidds/nouveau/include",
        "--sysroot=AROS-NX/build/pc-x86_64/SYS/Developer",
        "-O2",
        "-o", object_member,
        "-c", source,
    ]
    return {
        "directory": csdk_recipes.BUILD_ROOT,
        "file": source,
        "output": csdk_recipes.BUILD_PREFIX + object_member,
        "command": " ".join(argv),
    }


class NouveauFixture(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="csdk-nouveau-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name).resolve()
        self.source_root = self.root / "source"
        self.build_root = self.root / "build" / "pc-x86_64"
        self.toolchain_root = self.root / "toolchain"
        self.work_dir = self.root / "work"
        for path in (self.source_root, self.build_root, self.toolchain_root / "bin", self.work_dir):
            path.mkdir(parents=True, exist_ok=True)
        self.source_directory = self.source_root / "workbench/hidds/nouveau/testsrc"
        self.include_directory = self.source_root / "workbench/hidds/nouveau/include"
        self.sdk_include = self.build_root / "SDK/include"
        self.sysroot = self.build_root / "SYS/Developer"
        for path in (self.source_directory, self.include_directory, self.sdk_include, self.sysroot):
            path.mkdir(parents=True, exist_ok=True)
        for index in range(COUNT):
            (self.source_directory / f"file{index:04d}.c").write_text("int synthetic;\n")
        self.compiler = self.toolchain_root / "bin/clang-11"
        self.compiler.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n")
        self.compiler.chmod(0o755)
        self.raw_rows = [_raw_record(index) for index in range(COUNT)]
        self.records = csdk_recipes.nouveau_compile_recipes(json.dumps(self.raw_rows))
        self.ninja_text = self._ninja_text(list(range(COUNT)))

    @staticmethod
    def _ninja_text(order: list[int]) -> str:
        dependencies = " ".join(_object_member(index) for index in order)
        return (
            f"build {csdk_nouveau.ARCHIVE_OUTPUT}: {csdk_nouveau.ARCHIVE_RULE} "
            + dependencies + " || aros-genmodule-public-includes\n"
        )

    def plan(self, records: list[dict] | None = None, ninja_text: str | None = None) -> dict:
        return csdk_nouveau.plan_nouveau(
            self.records if records is None else records,
            self.ninja_text if ninja_text is None else ninja_text,
            self.source_root, self.build_root, self.toolchain_root,
        )

    def cli(self, *, compiler_sha256: str, script: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(csdk_nouveau.__file__).resolve()),
                "compile-plan",
                "--compile-commands", str(self.root / "compile_commands.json"),
                "--ninja", str(self.root / "build.ninja"),
                "--source-root", str(self.source_root),
                "--build-root", str(self.build_root),
                "--toolchain-root", str(self.toolchain_root),
                "--compiler-sha256", compiler_sha256,
                "--work-dir", str(self.work_dir),
                "--jobs", "2",
            ],
            capture_output=True,
            text=True,
            env={**os.environ, **({"INVOCATIONS": str(self.root / "invocations.txt"),
                                   "TERMINATED": str(self.root / "terminated.txt")}
                                  if script else {})},
            timeout=60,
            check=False,
        )

    def write_cli_inputs(self, order: list[int] | None = None) -> None:
        (self.root / "compile_commands.json").write_text(json.dumps(self.raw_rows))
        (self.root / "build.ninja").write_text(self._ninja_text(order or list(range(COUNT))))


class TestNouveauPlan(NouveauFixture):
    def test_path_operands_are_mapped_and_flags_keep_order(self) -> None:
        plan = self.plan()
        command = plan["commands"][0]
        raw = command["raw_argv"]
        actual = command["argv"]
        self.assertEqual(actual[0], str(self.compiler))
        self.assertEqual(actual[1:3], raw[1:3])
        self.assertEqual(actual[3], "-I" + str(self.sdk_include))
        self.assertEqual(actual[4], "-iquote" + str(self.include_directory))
        self.assertEqual(actual[5], "--sysroot=" + str(self.sysroot))
        self.assertEqual(actual[6], "-O2")
        self.assertEqual(actual[7], "-o")
        self.assertEqual(actual[8], command["object"])
        self.assertEqual(actual[9], "-c")
        self.assertEqual(actual[10], command["source"])
        self.assertEqual(actual[-1], "-ffile-prefix-map=" + str(self.source_root) + "=.")
        self.assertEqual(command["raw_argv"], raw)
        self.assertEqual(plan["object_count"], COUNT)
        self.assertEqual(len(plan["ordered_object_paths"]), COUNT)

    def test_ninja_selects_archive_member_order_independently_of_database_order(self) -> None:
        order = [1, 0, *range(2, COUNT)]
        plan = self.plan(ninja_text=self._ninja_text(order))
        self.assertEqual(plan["member_basenames"][:3], [_object_name(1), _object_name(0), _object_name(2)])
        self.assertEqual(Path(plan["ordered_object_paths"][0]).name, _object_name(1))
        self.assertEqual(plan["commands"][0]["object"], plan["ordered_object_paths"][0])
        self.assertEqual(len(set(plan["ordered_object_paths"])), COUNT)

    def test_object_path_escape_is_rejected(self) -> None:
        records = [dict(row) for row in self.records]
        records[0]["object"] = "build/pc-x86_64/../../outside.c.obj"
        with self.assertRaisesRegex(csdk_nouveau.NouveauError, "normalized"):
            self.plan(records=records)

    def test_source_symlink_is_rejected(self) -> None:
        link = self.source_directory / "file0000.c"
        original = self.root / "outside-source.c"
        original.write_text("int external;\n")
        link.unlink()
        link.symlink_to(original)
        with self.assertRaisesRegex(csdk_nouveau.NouveauError, "symlink"):
            self.plan()

    def test_output_parent_symlink_is_rejected_before_compilation(self) -> None:
        plan = self.plan()
        output_parent = Path(plan["ordered_object_paths"][0]).parents[5]
        # The common object directory is below build_root/CMakeFiles.
        self.assertEqual(output_parent, self.build_root / "CMakeFiles")
        outside = self.root / "outside-build"
        outside.mkdir()
        output_parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(csdk_nouveau.NouveauError, "symlink"):
            csdk_nouveau._prepare_outputs(plan)
        self.assertEqual(list(outside.iterdir()), [])

    def test_unknown_absolute_or_historical_argument_is_rejected(self) -> None:
        records = [dict(row) for row in self.records]
        records[0] = dict(records[0])
        records[0]["argv"] = list(records[0]["argv"])
        records[0]["argv"].insert(2, "-include=/historical/build/header.h")
        with self.assertRaisesRegex(csdk_nouveau.NouveauError, "unmapped path"):
            self.plan(records=records)


class TestNouveauCompileCli(NouveauFixture):
    def test_isolated_cli_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(Path(csdk_nouveau.__file__).resolve()), "--help"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("compile-plan", result.stdout)

    def test_invalid_compiler_digest_fails_before_any_job(self) -> None:
        self.write_cli_inputs()
        result = self.cli(compiler_sha256="0" * 64)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "invocations.txt").exists())
        plan = json.loads((self.work_dir / "nouveau-compile-plan.json").read_text())
        self.assertEqual(plan["status"], "FAIL_VALIDATION_OR_RUNNER")
        self.assertIn("SHA-256 differs", plan["error"])

    def test_small_compiler_output_completes_all_objects_with_isolated_cli(self) -> None:
        self.compiler.write_text('''#!/bin/sh
out=
want_out=0
for arg do
    if [ "$want_out" = 1 ]; then out=$arg; want_out=0; continue; fi
    if [ "$arg" = -o ]; then want_out=1; fi
done
printf 'synthetic object' > "$out"
printf 'small compiler note\\n'
''')
        self.compiler.chmod(0o755)
        self.write_cli_inputs()
        digest = hashlib.sha256(self.compiler.read_bytes()).hexdigest()
        result = self.cli(compiler_sha256=digest)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        plan = json.loads((self.work_dir / "nouveau-compile-plan.json").read_text())
        self.assertEqual(plan["status"], "NOUVEAU_825_COMPILE_COMMANDS_COMPLETE")
        self.assertEqual(plan["compile"]["started"], COUNT)
        self.assertEqual(plan["compile"]["completed"], COUNT)
        self.assertLessEqual(plan["compile"]["aggregate_saved_log_bytes"],
                             csdk_nouveau.MAX_AGGREGATE_SAVED_LOG_BYTES)
        self.assertIn("small compiler note", (self.work_dir / "nouveau-logs/0000.stdout.log").read_text())

    def test_stdout_spam_fails_even_when_fake_compiler_exits_zero(self) -> None:
        invocations = self.root / "invocations.txt"
        terminated = self.root / "terminated.txt"
        self.compiler.write_text(f'''#!/usr/bin/env python3
import os, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
output = Path(args[args.index("-o") + 1])
source = Path(args[args.index("-c") + 1])
index = int(source.stem[4:])
with open(os.environ["INVOCATIONS"], "a", encoding="ascii") as stream:
    stream.write(str(index) + "\\n")
if index == 0:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            if "1" in Path(os.environ["INVOCATIONS"]).read_text().splitlines():
                break
        except FileNotFoundError:
            pass
        time.sleep(0.01)
    output.write_bytes(b"partial first object")
    sys.stdout.write("X" * ( {csdk_nouveau.MAX_LOG_BYTES_PER_STREAM} + 1024))
    sys.stdout.flush()
    raise SystemExit(0)
def stopped(_signum, _frame):
    Path(os.environ["TERMINATED"]).write_text("terminated\\n")
    raise SystemExit(143)
signal.signal(signal.SIGTERM, stopped)
output.write_bytes(b"partial peer object")
while True:
    time.sleep(1)
''')
        self.compiler.chmod(0o755)
        self.write_cli_inputs()
        digest = hashlib.sha256(self.compiler.read_bytes()).hexdigest()
        result = self.cli(compiler_sha256=digest, script="spam")
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        seen = [int(item) for item in invocations.read_text().splitlines()]
        self.assertEqual(sorted(seen), [0, 1])
        self.assertTrue(terminated.is_file())
        plan = json.loads((self.work_dir / "nouveau-compile-plan.json").read_text())
        self.assertEqual(plan["status"], "FAIL_COMPILE")
        self.assertEqual(plan["compile"]["started"], 2)
        self.assertIn("per-stream capture limit", plan["compile"]["failure"])
        self.assertLessEqual(plan["compile"]["aggregate_saved_log_bytes"],
                             csdk_nouveau.MAX_AGGREGATE_SAVED_LOG_BYTES)
        logs = self.work_dir / "nouveau-logs"
        self.assertIn("truncated: retained bounded output prefix",
                      (logs / "0000.stdout.log").read_text())
        self.assertTrue(Path(plan["ordered_object_paths"][0]).is_file())

    def test_total_warning_capture_limit_fails(self) -> None:
        self.compiler.write_text('''#!/bin/sh
out=
want_out=0
for arg do
    if [ "$want_out" = 1 ]; then out=$arg; want_out=0; continue; fi
    if [ "$arg" = -o ]; then want_out=1; fi
done
printf 'synthetic object' > "$out"
printf 'warning!'
''')
        self.compiler.chmod(0o755)
        plan = self.plan()
        csdk_nouveau._prepare_outputs(plan)
        with patch.object(csdk_nouveau, "MAX_TOTAL_WARNING_BYTES", 12):
            outcome = csdk_nouveau._compile_commands(plan, self.work_dir, jobs=2)
        self.assertEqual(outcome["started"], 2)
        self.assertIn("total compiler warning-byte capture limit", outcome["failure"])
        self.assertLessEqual(outcome["aggregate_saved_log_bytes"],
                             csdk_nouveau.MAX_AGGREGATE_SAVED_LOG_BYTES)

    def test_aggregate_saved_log_overflow_fails_before_next_job(self) -> None:
        self.compiler.write_text('''#!/bin/sh
out=
want_out=0
for arg do
    if [ "$want_out" = 1 ]; then out=$arg; want_out=0; continue; fi
    if [ "$arg" = -o ]; then want_out=1; fi
done
printf 'synthetic object' > "$out"
printf 'warning!'
''')
        self.compiler.chmod(0o755)
        plan = self.plan()
        csdk_nouveau._prepare_outputs(plan)
        with patch.object(csdk_nouveau, "MAX_REGULAR_SAVED_LOG_BYTES", 1):
            outcome = csdk_nouveau._compile_commands(plan, self.work_dir, jobs=2)
        self.assertEqual(outcome["started"], 2)
        self.assertEqual(outcome["failure"], "aggregate saved-log limit exceeded")
        self.assertLessEqual(outcome["aggregate_saved_log_bytes"],
                             csdk_nouveau.MAX_AGGREGATE_SAVED_LOG_BYTES)

    def test_compile_failure_stops_new_jobs_and_terminates_running_peer(self) -> None:
        invocations = self.root / "invocations.txt"
        terminated = self.root / "terminated.txt"
        script = f'''#!/usr/bin/env python3
import os, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
output = Path(args[args.index("-o") + 1])
source = Path(args[args.index("-c") + 1])
index = int(source.stem[4:])
with open(os.environ["INVOCATIONS"], "a", encoding="ascii") as stream:
    stream.write(str(index) + "\\n")
if index == 0:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            if "1" in Path(os.environ["INVOCATIONS"]).read_text().splitlines():
                break
        except FileNotFoundError:
            pass
        time.sleep(0.01)
    print("synthetic first compile failure", file=sys.stderr)
    raise SystemExit(7)
if index == 1:
    def stopped(_signum, _frame):
        Path(os.environ["TERMINATED"]).write_text("terminated\\n")
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, stopped)
    output.write_bytes(b"partial object retained")
    while True:
        time.sleep(1)
output.write_bytes(b"unexpected later object")
'''
        self.compiler.write_text(script)
        self.compiler.chmod(0o755)
        self.write_cli_inputs()
        digest = hashlib.sha256(self.compiler.read_bytes()).hexdigest()
        result = self.cli(compiler_sha256=digest, script=script)
        self.assertEqual(result.returncode, 1, result.stderr)
        seen = [int(item) for item in invocations.read_text().splitlines()]
        self.assertEqual(sorted(seen), [0, 1])
        self.assertTrue(terminated.is_file())
        plan = json.loads((self.work_dir / "nouveau-compile-plan.json").read_text())
        self.assertEqual(plan["status"], "FAIL_COMPILE")
        self.assertEqual(plan["compile"]["started"], 2)
        self.assertEqual(plan["compile"]["failed_index"], 0)
        self.assertEqual(plan["compile"]["completed"], 0)
        self.assertEqual(Path(plan["ordered_object_paths"][1]).read_bytes(), b"partial object retained")
        logs = self.work_dir / "nouveau-logs"
        self.assertIn("synthetic first compile failure", (logs / "0000.stderr.log").read_text())
        self.assertTrue((logs / "0001.stdout.log").is_file())


if __name__ == "__main__":
    unittest.main()

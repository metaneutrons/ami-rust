"""Execute the native SDK's checked allocation arithmetic on the host."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "host/tests/allocation_layout_fixture.c"


class AllocationLayout(unittest.TestCase):
    def test_native_layout_helper(self):
        configured = os.environ.get("CC")
        compiler = shlex.split(configured) if configured else []
        if not compiler:
            executable = shutil.which("cc") or shutil.which("clang")
            if executable is None:
                self.fail("a host C compiler (cc or clang) is required")
            compiler = [executable]

        with tempfile.TemporaryDirectory(prefix="ami-rust-allocation-layout-") as temporary:
            binary = Path(temporary) / "allocation-layout"
            subprocess.run(
                compiler + [
                    "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    str(FIXTURE), "-o", str(binary),
                ],
                check=True,
                cwd=ROOT,
            )
            subprocess.run([str(binary)], check=True, cwd=ROOT)


if __name__ == "__main__":
    unittest.main()

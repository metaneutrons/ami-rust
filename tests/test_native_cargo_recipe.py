from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/native-cargo-recipe.sh"


class NativeCargoRecipeSelection(unittest.TestCase):
    def select(self, *args):
        return subprocess.run([
            "bash", "-euc",
            'source "$1"; shift; native_cargo_select_recipe "$@"; '
            'printf "%s\\n" "$RECIPE_NAME" "$RECIPE" "$RECIPE_SOURCE_SHA" "$SOURCE_PATCH_SHA"',
            "recipe-test", str(HELPER), str(ROOT), *args,
        ], text=True, capture_output=True, check=False)

    def test_default_and_both_exact_source_patch_pairs(self):
        default = self.select()
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(default.stdout, self.select("three-host-v2").stdout)
        for name, count in (("three-host-v2", 2), ("three-host-v3", 4)):
            with self.subTest(name=name):
                result = self.select(name)
                self.assertEqual(result.returncode, 0, result.stderr)
                selected, recipe, source_sha, patch_sha = result.stdout.splitlines()
                self.assertEqual(selected, name)
                directory = ROOT / "host/cargo-repro" / name
                self.assertEqual(Path(recipe), directory)
                raw = (directory / "source.json").read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), source_sha)
                pin = json.loads(raw)
                self.assertEqual(pin["patch_sha256"], patch_sha)
                self.assertEqual(hashlib.sha256((directory / "cargo-metadata.patch").read_bytes()).hexdigest(), patch_sha)
                self.assertEqual(1 + len(pin["additional_files"]), count)

    def test_unknown_empty_and_path_recipe_refused(self):
        for name in ("", "three-host-v4", "../../../unreviewed", "three-host-v3/.."):
            with self.subTest(name=name):
                result = self.select(name)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("unsupported native Cargo recipe", result.stderr)


if __name__ == "__main__":
    unittest.main()

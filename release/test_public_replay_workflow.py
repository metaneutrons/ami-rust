#!/usr/bin/env python3
"""Offline checks for Python and file-name contracts in public-replay.yml."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import importlib.machinery
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "public-replay.yml"
SPEC = importlib.util.spec_from_file_location(
    "r1_public_replay_workflow_public_replay", ROOT / "release" / "public_replay.py"
)
assert SPEC is not None and SPEC.loader is not None
public_replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_replay)


def embedded_python_blocks(source: str) -> list[str]:
    """Return the Python bodies from literal PYCODE heredocs."""
    lines = source.splitlines()
    blocks = []
    for index, line in enumerate(lines):
        if "python3" not in line or "-I -B - <<'PYCODE'" not in line:
            continue
        indentation = len(line) - len(line.lstrip())
        end = next((position for position in range(index + 1, len(lines))
                    if lines[position] == " " * indentation + "PYCODE"), None)
        if end is None:
            raise AssertionError("Python PYCODE heredoc has no matching terminator")
        body = []
        for body_line in lines[index + 1:end]:
            if body_line.strip():
                if not body_line.startswith(" " * indentation):
                    raise AssertionError("Python heredoc body escapes its YAML run block")
                body.append(body_line[indentation:])
            else:
                body.append("")
        blocks.append("\n".join(body) + "\n")
    return blocks


def assignment(tree: ast.Module, name: str) -> ast.Assign:
    matches = [statement for statement in tree.body
               if isinstance(statement, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name
                       for target in statement.targets)]
    if len(matches) != 1:
        raise AssertionError(f"expected one top-level assignment to {name}")
    return matches[0]


class PublicReplayWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocks = embedded_python_blocks(WORKFLOW.read_text(encoding="utf-8"))
        cls.trees = [ast.parse(block, filename=f"public-replay.yml:PYCODE:{index}")
                     for index, block in enumerate(cls.blocks, start=1)]

    def test_all_embedded_python_blocks_compile_and_a_damaged_block_fails(self):
        self.assertEqual(len(self.blocks), 6)
        for index, block in enumerate(self.blocks, start=1):
            with self.subTest(block=index):
                compile(block, f"public-replay.yml:PYCODE:{index}", "exec")

        damaged = self.blocks[0] + "if True print('broken')\n"
        with self.assertRaises(SyntaxError):
            compile(damaged, "public-replay.yml:damaged-PYCODE", "exec")

    def test_freeze_step_names_the_hierarchical_public_replay_controls(self):
        matches = [tree for tree in self.trees
                   if any(isinstance(statement, ast.Assign)
                          and any(isinstance(target, ast.Name)
                                  and target.id == "control_sources"
                                  for target in statement.targets)
                          for statement in tree.body)]
        self.assertEqual(len(matches), 1)
        control_sources = assignment(matches[0], "control_sources")
        control_paths = tuple(element.value for element in control_sources.value.elts
                              if isinstance(element, ast.Constant)
                              and type(element.value) is str)
        self.assertEqual(control_paths, public_replay.PUBLIC_REPLAY_CONTROL_PATHS)
        for relative in control_paths:
            with self.subTest(control=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_download_step_fetches_exact_six_assets_in_order_without_unpacking(self):
        blocks = embedded_python_blocks(WORKFLOW.read_text(encoding="utf-8"))
        block = next(body for body in blocks
                     if '"ami-rust-public-candidate-download-v1"' in body)
        self.assertNotIn("unpack_bundle", block)
        self.assertNotIn("tarfile", block)
        tree = ast.parse(block, filename="public-replay.yml:candidate-download")
        key_loops = [node for node in ast.walk(tree)
                     if isinstance(node, ast.For)
                     and isinstance(node.target, ast.Name)
                     and node.target.id == "key"
                     and isinstance(node.iter, ast.Tuple)]
        self.assertEqual(len(key_loops), 1)
        key_order = tuple(item.value for item in key_loops[0].iter.elts)
        self.assertEqual(key_order, (
            "payload", "sbom", "payload_signature", "transport",
            "transport_signature", "checksums",
        ))

        with tempfile.TemporaryDirectory(prefix="public-replay-download-test-") as temporary:
            root = Path(temporary).resolve(strict=True)
            workspace = root / "workspace"
            controls = workspace / ".git" / "ami-rust-public-controls"
            (controls / "release").mkdir(parents=True)
            (controls / "control-source.json").write_text("{}\n", encoding="utf-8")
            for relative in ("release/stage_candidate.py", "release/ci_sdk.py"):
                path = controls / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
            runtime = root / "runtime"
            runtime.mkdir()
            names = {
                "payload": "ami-rust-1.2.3-release.tar.xz",
                "sbom": "ami-rust-1.2.3-release.tar.xz.spdx.json",
                "payload_signature": "ami-rust-1.2.3-release.tar.xz.sigstore.json",
                "transport": "ami-rust-1.2.3-transport.json",
                "transport_signature": "ami-rust-1.2.3-transport.json.sigstore.json",
                "checksums": "SHA256SUMS",
            }
            transport_bytes = b"fixture transport metadata\n"
            bodies = {names[key]: (transport_bytes if key == "transport"
                                   else ("fixture:" + names[key]).encode())
                      for key in ("payload", "sbom", "payload_signature", "transport",
                                  "transport_signature", "checksums")}
            requested = []

            class Stage:
                @staticmethod
                def asset_names(tag):
                    if tag != "v1.2.3":
                        raise AssertionError("download used an unexpected tag")
                    return names

                @staticmethod
                def _outer_limits(_names):
                    return {name: 1024 * 1024 for name in names.values()}

            class SDK:
                MAX_WORK_BYTES = 12 * 1024**3
                MAX_RSS_BYTES = 4 * 1024**3

                @staticmethod
                def directory_bytes(_path):
                    return 100

            class Loader:
                def create_module(self, _spec):
                    return None

                def exec_module(self, module):
                    if module.__name__.endswith("stage_candidate"):
                        module.asset_names = Stage.asset_names
                        module._outer_limits = Stage._outer_limits
                    else:
                        module.MAX_WORK_BYTES = SDK.MAX_WORK_BYTES
                        module.MAX_RSS_BYTES = SDK.MAX_RSS_BYTES
                        module.directory_bytes = SDK.directory_bytes

            def fake_spec(name, _path):
                return importlib.machinery.ModuleSpec(name, Loader())

            class Response(io.BytesIO):
                def __init__(self, url, content):
                    super().__init__(content)
                    self.headers = {"Content-Length": str(len(content))}
                    self._url = url

                def geturl(self):
                    return self._url

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    self.close()

            def fake_urlopen(request, timeout):
                self.assertEqual(timeout, 30)
                url = request.full_url
                name = urllib.parse.unquote(urllib.parse.urlparse(url).path.rsplit("/", 1)[1])
                requested.append(name)
                return Response(url, bodies[name])

            env = {
                "GITHUB_WORKSPACE": str(workspace),
                "RUNNER_TEMP": str(runtime),
                "RELEASE_TAG": "v1.2.3",
                "PUBLISHER_SOURCE": "a" * 40,
                "RELEASE_MANIFEST_SHA256": "b" * 64,
                "TRANSPORT_INVENTORY_SHA256": hashlib.sha256(transport_bytes).hexdigest(),
                "WORKFLOW_SOURCE_COMMIT": "c" * 40,
                "WORKFLOW_RUN_ID": "123",
                "WORKFLOW_RUN_ATTEMPT": "1",
            }
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch("importlib.util.spec_from_file_location", side_effect=fake_spec), \
                    mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                exec(compile(block, "public-replay.yml:candidate-download", "exec"), {})

            expected_order = tuple(names[key] for key in (
                "payload", "sbom", "payload_signature", "transport",
                "transport_signature", "checksums",
            ))
            self.assertEqual(tuple(requested), expected_order)
            candidate = runtime / "ami-rust-public-bundle"
            self.assertEqual(tuple(sorted(path.name for path in candidate.iterdir())),
                             tuple(sorted(names.values())))
            receipt = json.loads((controls / "transport-receipt.json").read_text())
            self.assertEqual(receipt["status"], "DOWNLOADED_SIX_PUBLIC_ASSETS_NOT_AUTHENTICATED")
            self.assertFalse(receipt["claims"]["assets_authenticated"])
            self.assertEqual(set(receipt["assets"]), set(names.values()))

    def test_production_replay_invocation_requires_candidate_assets_and_external_pins(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            '"$GITHUB_WORKSPACE/.git/ami-rust-public-controls/release/public_replay.py"',
            workflow,
        )
        self.assertIn('--candidate-assets "$RUNNER_TEMP/ami-rust-public-bundle"', workflow)
        self.assertIn('--transport-sha256 "$TRANSPORT_INVENTORY_SHA256"', workflow)
        self.assertIn('--manifest-sha256 "$RELEASE_MANIFEST_SHA256"', workflow)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
        parser = public_replay._parser()
        actions = {action.dest: action for action in parser._actions}
        self.assertTrue(actions["candidate_assets"].required)
        self.assertTrue(actions["transport_sha256"].required)
        self.assertNotIn("bundle", actions)


if __name__ == "__main__":
    unittest.main()

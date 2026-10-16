#!/usr/bin/env python3
"""Offline checks for Python and file-name contracts in public-replay.yml."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "public-replay.yml"
PUBLIC_CONTROLS = ("release/public_replay.py", "release/public_transport.py")

SPEC = importlib.util.spec_from_file_location(
    "r1_public_replay_workflow_transport", ROOT / "release" / "public_transport.py"
)
assert SPEC is not None and SPEC.loader is not None
public_transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_transport)


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


def evaluate_workflow_expression(expression: ast.expr, values: dict[str, object]) -> object:
    """Evaluate only names, string literals, concatenation, and Path joining."""
    if isinstance(expression, ast.Name) and expression.id in values:
        return values[expression.id]
    if isinstance(expression, ast.Constant) and type(expression.value) is str:
        return expression.value
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        left = evaluate_workflow_expression(expression.left, values)
        right = evaluate_workflow_expression(expression.right, values)
        if type(left) is str and type(right) is str:
            return left + right
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
        left = evaluate_workflow_expression(expression.left, values)
        right = evaluate_workflow_expression(expression.right, values)
        if isinstance(left, Path) and type(right) is str:
            return left / right
    raise AssertionError("workflow assignment uses an unsupported expression")


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

    def test_controls_loop_names_the_existing_public_replay_modules(self):
        loops = [node for tree in self.trees for node in ast.walk(tree)
                 if isinstance(node, ast.For)
                 and isinstance(node.target, ast.Name)
                 and node.target.id == "relative"
                 and isinstance(node.iter, ast.Tuple)]
        self.assertEqual(len(loops), 1)
        control_paths = tuple(element.value for element in loops[0].iter.elts
                              if isinstance(element, ast.Constant)
                              and type(element.value) is str)
        self.assertEqual(control_paths, PUBLIC_CONTROLS)
        for relative in control_paths:
            with self.subTest(control=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_workflow_archive_path_round_trips_under_its_inventory_name(self):
        transport_trees = [tree for tree in self.trees
                           if any(isinstance(statement, ast.Assign)
                                  and any(isinstance(target, ast.Name)
                                          and target.id == "archive_path"
                                          for target in statement.targets)
                                  for statement in tree.body)]
        self.assertEqual(len(transport_trees), 1)
        tree = transport_trees[0]
        archive_assignment = assignment(tree, "archive_path")
        inventory_name_assignment = assignment(tree, "expected_archive_name")
        version = "0.7.3"

        with tempfile.TemporaryDirectory(prefix="public-replay-workflow-test-") as temporary:
            root = Path(temporary).resolve(strict=True)
            controls = root / "controls"
            controls.mkdir()
            archive_path = evaluate_workflow_expression(
                archive_assignment.value, {"controls": controls, "version": version}
            )
            inventory_name = evaluate_workflow_expression(
                inventory_name_assignment.value, {"version": version}
            )
            self.assertIsInstance(archive_path, Path)
            self.assertEqual(archive_path.parent, controls)
            self.assertEqual(archive_path.name, inventory_name)

            bundle = root / "candidate"
            bundle.mkdir()
            (bundle / "release.json").write_bytes(b'{"version":"0.7.3"}\n')
            record = public_transport.pack_bundle(bundle, archive_path)
            self.assertEqual(record["archive"]["name"], inventory_name)

            wrong_name = controls / "public-release.tar.xz"
            wrong_name.write_bytes(archive_path.read_bytes())
            rejected_destination = root / "rejected-readback"
            with self.assertRaisesRegex(ValueError, "archive name differs"):
                public_transport.unpack_bundle(wrong_name, record, rejected_destination)
            self.assertFalse(rejected_destination.exists())

            destination = root / "readback"
            receipt = public_transport.unpack_bundle(archive_path, record, destination)
            self.assertEqual(receipt, record)
            self.assertEqual((destination / "release.json").read_bytes(),
                             (bundle / "release.json").read_bytes())


if __name__ == "__main__":
    unittest.main()

"""Offline tests for bounded portable-CSDK recipe parsing."""
from __future__ import annotations

import json
import importlib.util
from pathlib import Path
import unittest

_SPEC = importlib.util.spec_from_file_location("_test_csdk_recipes", Path(__file__).with_name("csdk_recipes.py"))
_RECIPES = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_RECIPES)
RecipeError = _RECIPES.RecipeError
classic_generator_recipe = _RECIPES.classic_generator_recipe
nouveau_compile_recipes = _RECIPES.nouveau_compile_recipes
public_header_recipes = _RECIPES.public_header_recipes


BUILD = "AROS-NX/build/pc-x86_64"
GENMODULE = BUILD + "/hosttools/genmodule"


def header_edge(*, module="sample", config="AROS-NX/config/sample.conf",
                options=(), executable=GENMODULE, copy_override=None):
    output_suffixes = [
        "clib/" + module + "_protos.h",
        "inline/" + module + ".h",
        "defines/" + module + ".h",
        "defines/" + module + "_LVO.h",
        "proto/" + module + ".h",
    ]
    output_dir = BUILD + "/genmodule/sample/include"
    outputs = " ".join("SDK/include/" + suffix for suffix in output_suffixes)
    command = [
        "cd " + BUILD,
        "${CMAKE} -E make_directory " + output_dir,
        " ".join([executable, "-c", config, *options, "-d", output_dir,
                  "writeincludes", module, "library"]),
    ]
    for suffix in output_suffixes:
        destination = copy_override if suffix == output_suffixes[0] and copy_override else suffix
        source = output_dir + "/" + suffix
        target = BUILD + "/SDK/include/" + destination
        command.append("${CMAKE} -E copy_if_different " + source + " " + target)
    return "build " + outputs + ": CUSTOM_COMMAND " + config + "\n  COMMAND = " + " && ".join(command)


def compile_record(*, source="AROS-NX/workbench/hidds/nouveau/drm/foo.c",
                   object_path=None, command_source=None, target="hidd-nouveau-drm"):
    if object_path is None:
        object_path = (BUILD + "/CMakeFiles/" + target + ".dir"
                       + source)
    if command_source is None:
        command_source = source
    object_argument = object_path[len(BUILD + "/"):]
    return {
        "directory": BUILD,
        "file": source,
        "output": object_path,
        "command": ("${CROSS_TOOLCHAIN_ROOT}/toolchain/bin/clang --target=x86_64-unknown-aros "
                    "-O3 -o " + object_argument + " -c " + command_source),
    }


class PublicHeaderRecipeTests(unittest.TestCase):
    def test_parses_outputs_config_options_and_type(self):
        edge = header_edge(options=("-s", "fwl", "-o", BUILD + "/Ports/sample.conf"))
        record, = public_header_recipes(edge)
        self.assertEqual(record["config"], "config/sample.conf")
        self.assertEqual(record["outputs"], [
            "clib/sample_protos.h", "inline/sample.h", "defines/sample.h",
            "defines/sample_LVO.h", "proto/sample.h",
        ])
        self.assertEqual(record["module"], "sample")
        self.assertEqual(record["module_type"], "library")
        self.assertEqual(record["module_suffix"], "fwl")
        self.assertEqual(record["output_override"], {
            "kind": "build", "path": "build/pc-x86_64/Ports/sample.conf",
        })
        self.assertEqual(record["argv"][0], GENMODULE)
        self.assertEqual(record["cwd"], "build/pc-x86_64")

    def test_rejects_missing_config(self):
        edge = header_edge().replace(" -c AROS-NX/config/sample.conf", "")
        with self.assertRaisesRegex(RecipeError, "missing -c config"):
            public_header_recipes(edge)

    def test_rejects_unexpected_generator_and_shell_syntax(self):
        edge = header_edge(executable=BUILD + "/hosttools/other-generator")
        with self.assertRaisesRegex(RecipeError, "classic genmodule"):
            public_header_recipes(edge)
        edge = header_edge() + " ; touch /tmp/not-run"
        with self.assertRaisesRegex(RecipeError, "shell control syntax"):
            public_header_recipes(edge)

    def test_rejects_ambiguous_or_duplicate_outputs(self):
        edge = header_edge().replace("SDK/include/inline/sample.h", "SDK/include/../sample.h")
        with self.assertRaises(RecipeError):
            public_header_recipes(edge)
        repeated = header_edge() + "\n\n" + header_edge(config="AROS-NX/other/sample.conf")
        with self.assertRaisesRegex(RecipeError, "duplicate public SDK header output"):
            public_header_recipes(repeated)

    def test_rejects_copy_set_that_disagrees_with_declared_outputs(self):
        edge = header_edge(copy_override="clib/other.h")
        with self.assertRaisesRegex(RecipeError, "copy exactly"):
            public_header_recipes(edge)


class ClassicGeneratorTests(unittest.TestCase):
    def test_parses_declared_c_inputs_and_original_flags(self):
        sources = ["AROS-NX/tools/genmodule/alpha.c", "AROS-NX/tools/genmodule/beta.c"]
        build_inputs = " ".join(sources + ["AROS-NX/tools/genmodule/config.h"])
        command = ("cd " + BUILD + " && cc -O2 -w -IAROS-NX/tools/genmodule "
                   + " ".join(sources) + " -o " + GENMODULE)
        ninja = ("build hosttools/genmodule | ${cmake_ninja_workdir}hosttools/genmodule: "
                 "CUSTOM_COMMAND " + build_inputs + "\n  COMMAND = " + command)
        record = classic_generator_recipe(ninja)
        self.assertEqual(record["sources"], ["tools/genmodule/alpha.c", "tools/genmodule/beta.c"])
        self.assertEqual(record["flags"], ["-O2", "-w", "-IAROS-NX/tools/genmodule"])
        self.assertEqual(record["output"], "build/pc-x86_64/hosttools/genmodule")

    def test_rejects_command_inputs_that_differ_from_edge(self):
        ninja = ("build hosttools/genmodule: CUSTOM_COMMAND AROS-NX/tools/genmodule/declared.c\n"
                 "  COMMAND = cd " + BUILD + " && cc -O2 "
                 "AROS-NX/tools/genmodule/other.c -o " + GENMODULE)
        with self.assertRaisesRegex(RecipeError, "differ from Ninja build inputs"):
            classic_generator_recipe(ninja)


class NouveauCompileRecipeTests(unittest.TestCase):
    def test_parses_direct_source_object_and_full_argv(self):
        value = json.dumps([compile_record()])
        record, = nouveau_compile_recipes(value)
        self.assertEqual(record["source"], "workbench/hidds/nouveau/drm/foo.c")
        self.assertEqual(record["directory"], "build/pc-x86_64")
        self.assertEqual(record["object"],
                         "build/pc-x86_64/CMakeFiles/hidd-nouveau-drm.dir"
                         "AROS-NX/workbench/hidds/nouveau/drm/foo.c")
        self.assertEqual(record["argv"][-2:], ["-c", "AROS-NX/workbench/hidds/nouveau/drm/foo.c"])

    def test_ignores_other_nouveau_target_records(self):
        self.assertEqual(nouveau_compile_recipes(json.dumps([
            compile_record(target="hidd-nouveau"),
        ])), [])

    def test_rejects_mismatched_source_shell_syntax_and_duplicates(self):
        with self.assertRaisesRegex(RecipeError, "source differs"):
            nouveau_compile_recipes(json.dumps([compile_record(command_source="AROS-NX/other.c")]))
        injected = compile_record()
        injected["command"] += " && touch /tmp/not-run"
        with self.assertRaisesRegex(RecipeError, "shell control syntax"):
            nouveau_compile_recipes(json.dumps([injected]))
        repeated = compile_record()
        with self.assertRaisesRegex(RecipeError, "duplicate Nouveau DRM source"):
            nouveau_compile_recipes(json.dumps([repeated, repeated]))

    def test_rejects_duplicate_json_keys(self):
        with self.assertRaisesRegex(RecipeError, "duplicate JSON key"):
            nouveau_compile_recipes('[{"directory":"x","directory":"y"}]')


if __name__ == "__main__":
    unittest.main()

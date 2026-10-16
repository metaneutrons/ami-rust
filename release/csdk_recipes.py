"""Bounded, non-executing parsers for the frozen portable-CSDK recipes.

These helpers inspect the pinned Ninja file and compilation database. They do
not invoke a shell, compiler, generator, build tool, or other recipe command.
Paths are interpreted against the two prefixes declared by the capsule:
``AROS-NX/`` for source paths and ``AROS-NX/build/pc-x86_64/`` for build paths.
"""
from __future__ import annotations

import json
from pathlib import PurePosixPath
import re
import shlex


SOURCE_PREFIX = "AROS-NX/"
BUILD_PREFIX = "AROS-NX/build/pc-x86_64/"
BUILD_ROOT = "AROS-NX/build/pc-x86_64"
GENMODULE = BUILD_PREFIX + "hosttools/genmodule"
NOUVEAU_SOURCE_PREFIX = SOURCE_PREFIX + "workbench/hidds/nouveau/"
NOUVEAU_OBJECT_PREFIX = (
    BUILD_PREFIX + "CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/"
)


class RecipeError(ValueError):
    """Raised when a frozen recipe is incomplete, ambiguous, or unexpected."""


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RecipeError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _safe_relative(value: str, label: str) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or "\0" in value
            or ":" in value):
        raise RecipeError(label + " is not a portable relative path")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise RecipeError(label + " is not a normalized relative path: " + value)
    return value


def _source_relative(value: str, label: str = "source path") -> str:
    if not isinstance(value, str) or not value.startswith(SOURCE_PREFIX):
        raise RecipeError(label + " is outside the declared AROS-NX source prefix")
    return _safe_relative(value[len(SOURCE_PREFIX):], label)


def _build_relative(value: str, label: str = "build path") -> str:
    if value == BUILD_ROOT:
        return "build/pc-x86_64"
    if not isinstance(value, str) or not value.startswith(BUILD_PREFIX):
        raise RecipeError(label + " is outside the declared pc-x86_64 build prefix")
    return "build/pc-x86_64/" + _safe_relative(value[len(BUILD_PREFIX):], label)


def _build_working_relative(value: str, label: str = "build-relative path") -> str:
    return _safe_relative(value, label)


def _reject_shell_operators(value: str, label: str) -> None:
    # Tokenization below is only a parser. Refuse shell control syntax instead
    # of attempting to interpret or execute it.
    if any(marker in value for marker in ("&&", "||", ";", "|", "<", ">", "`", "$(")):
        raise RecipeError(label + " contains shell control syntax")
    if "\n" in value or "\r" in value or "\0" in value:
        raise RecipeError(label + " contains a control character")


def _literal_argv(value: str, label: str) -> list[str]:
    _reject_shell_operators(value, label)
    try:
        result = shlex.split(value, posix=True)
    except ValueError as exc:
        raise RecipeError(label + " has malformed quoting") from exc
    if not result:
        raise RecipeError(label + " is empty")
    return result


def _ninja_chain(value: str) -> list[list[str]]:
    if not isinstance(value, str) or not value:
        raise RecipeError("Ninja command is missing")
    # The frozen recipes use `&&` only to sequence commands. Split it as data;
    # do not pass any string to a shell.
    parts = value.split(" && ")
    if any(not part.strip() for part in parts):
        raise RecipeError("Ninja command has an empty shell segment")
    result = []
    for part in parts:
        if "&&" in part or "||" in part:
            raise RecipeError("Ninja command contains unexpected shell control syntax")
        result.append(_literal_argv(part, "Ninja command segment"))
    return result


def _ninja_edges(ninja_text: str):
    if not isinstance(ninja_text, str):
        raise RecipeError("Ninja input must be text")
    lines = ninja_text.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("build "):
            continue
        declaration, separator, dependency_text = line.partition(":")
        if not separator:
            raise RecipeError("malformed Ninja build edge at line " + str(index + 1))
        outputs = declaration[len("build "):].split()
        if not outputs:
            raise RecipeError("Ninja build edge has no outputs at line " + str(index + 1))
        dependencies = dependency_text.split()
        command = None
        cursor = index + 1
        while cursor < len(lines) and lines[cursor].strip():
            stripped = lines[cursor].strip()
            if stripped.startswith("COMMAND = "):
                if command is not None:
                    raise RecipeError("Ninja edge has multiple COMMAND assignments")
                command = stripped[len("COMMAND = "):]
            if lines[cursor].startswith("build "):
                break
            cursor += 1
        yield {
            "line": index + 1,
            "outputs": outputs,
            "dependencies": dependencies,
            "command": command,
        }


def _looks_like_public_header_outputs(outputs: list[str]) -> bool:
    sdk = [item for item in outputs if item.startswith("SDK/include/")]
    categories = {item[len("SDK/include/"):].split("/", 1)[0] for item in sdk}
    return len(sdk) == 5 or {"clib", "inline", "defines", "proto"}.issubset(categories)


def _parse_public_generator(argv: list[str]) -> dict:
    if not argv or argv[0] != GENMODULE:
        raise RecipeError("unexpected public-header generator command")
    values = {}
    index = 1
    allowed_options = {"-c", "-d", "-o", "-s"}
    while index < len(argv) and argv[index].startswith("-"):
        option = argv[index]
        if option not in allowed_options or option in values or index + 1 >= len(argv):
            raise RecipeError("unexpected or incomplete genmodule option: " + option)
        values[option] = argv[index + 1]
        index += 2
    if index >= len(argv) or argv[index] != "writeincludes":
        raise RecipeError("public-header generator must use writeincludes")
    if index + 3 != len(argv):
        raise RecipeError("public-header generator has missing or extra arguments")
    if "-c" not in values or "-d" not in values:
        raise RecipeError("public-header generator is missing -c config or -d output")

    config = _source_relative(values["-c"], "genmodule config")
    output_directory = _build_relative(values["-d"], "genmodule output directory")
    override = None
    if "-o" in values:
        override = {"kind": "build", "path": _build_relative(values["-o"], "genmodule -o override")}
    suffix = values.get("-s")
    if suffix is not None and not re.fullmatch(r"[A-Za-z0-9_.-]+", suffix):
        raise RecipeError("genmodule -s suffix is not a simple token")

    module, module_type = argv[index + 1], argv[index + 2]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", module):
        raise RecipeError("genmodule module name is not a simple token")
    if module_type not in {"library", "resource"}:
        raise RecipeError("unexpected genmodule module type: " + module_type)
    return {
        "config": config,
        "output_directory": output_directory,
        "output_override": override,
        "module_suffix": suffix,
        "module": module,
        "module_type": module_type,
    }


def _expected_header_group(module: str) -> set[str]:
    return {
        "clib/" + module + "_protos.h",
        "inline/" + module + ".h",
        "defines/" + module + ".h",
        "defines/" + module + "_LVO.h",
        "proto/" + module + ".h",
    }


def _parse_public_edge(edge: dict, sdk_outputs: list[str]) -> dict:
    if edge["command"] is None:
        raise RecipeError("public-header edge has no COMMAND")
    if len(sdk_outputs) != 5 or len(set(sdk_outputs)) != 5:
        raise RecipeError("public-header edge must declare five unique SDK/include outputs")
    outputs = [
        _safe_relative(item[len("SDK/include/"):], "SDK/include output")
        for item in sdk_outputs
    ]
    chain = _ninja_chain(edge["command"])
    if not chain or chain[0] != ["cd", BUILD_ROOT]:
        raise RecipeError("public-header edge has an unexpected generator working directory")
    generator_positions = [
        position for position, argv in enumerate(chain)
        if argv[0].endswith("/hosttools/genmodule") or argv[0] == "hosttools/genmodule"
    ]
    if len(generator_positions) != 1:
        raise RecipeError("public-header edge must contain exactly one classic genmodule command")
    generator_index = generator_positions[0]

    # Only the known directory preparation and output-copy operations surround
    # genmodule. This catches command substitutions or extra recipe commands.
    for argv in chain[1:generator_index]:
        if (len(argv) < 4 or argv[0] != "${CMAKE}" or argv[1:3] != ["-E", "make_directory"]):
            raise RecipeError("unexpected command before public-header generator")
        for path in argv[3:]:
            _build_relative(path, "genmodule directory operand")
    for argv in chain[generator_index + 1:]:
        if len(argv) < 4 or argv[0] != "${CMAKE}" or argv[1:3] not in (
                ["-E", "make_directory"], ["-E", "copy_if_different"]):
            raise RecipeError("unexpected command after public-header generator")
        operation = argv[2]
        if operation == "make_directory":
            for path in argv[3:]:
                _build_relative(path, "genmodule directory operand")
        else:
            if len(argv) != 5:
                raise RecipeError("copy_if_different must have one source and one destination")
            _build_relative(argv[3], "genmodule copy source")
            _build_relative(argv[4], "genmodule copy destination")

    generator_argv = chain[generator_index]
    parsed = _parse_public_generator(generator_argv)
    if set(outputs) != _expected_header_group(parsed["module"]):
        raise RecipeError("SDK/include outputs do not match the generator module")
    copied_sdk_outputs = []
    for argv in chain[generator_index + 1:]:
        if argv[:3] == ["${CMAKE}", "-E", "copy_if_different"] and len(argv) == 5:
            destination = _build_relative(argv[4], "genmodule copy destination")
            if destination.startswith("build/pc-x86_64/SDK/include/"):
                copied_output = destination[len("build/pc-x86_64/SDK/include/"):]
                if copied_output in copied_sdk_outputs:
                    raise RecipeError("duplicate SDK/include copy destination")
                copied_sdk_outputs.append(copied_output)
    if len(copied_sdk_outputs) != 5 or set(copied_sdk_outputs) != set(outputs):
        raise RecipeError("genmodule command does not copy exactly the five declared SDK headers")

    return {
        **parsed,
        "outputs": outputs,
        "argv": generator_argv,
        "generator_args": generator_argv[1:],
        "cwd": "build/pc-x86_64",
        "original_cwd": BUILD_ROOT,
        "command": edge["command"],
        "line": edge["line"],
    }


def public_header_recipes(ninja_text: str) -> list[dict]:
    """Return the exact five-output classic genmodule recipes for public headers.

    ``outputs`` are suffix paths relative to ``SDK/include``; ``config`` is
    relative to the AROS-NX source root. Command strings are parsed as data and
    shell control syntax outside the frozen ``&&`` separators is rejected.
    """
    records = []
    all_outputs = set()
    for edge in _ninja_edges(ninja_text):
        sdk_outputs = [item for item in edge["outputs"] if item.startswith("SDK/include/")]
        if not sdk_outputs:
            continue
        command = edge["command"] or ""
        has_generator_marker = "writeincludes" in command or GENMODULE in command
        looks_public = _looks_like_public_header_outputs(edge["outputs"])
        if not looks_public:
            if has_generator_marker:
                raise RecipeError("genmodule SDK/include edge does not declare five public headers")
            continue
        record = _parse_public_edge(edge, sdk_outputs)
        for output in record["outputs"]:
            if output in all_outputs:
                raise RecipeError("duplicate public SDK header output: " + output)
            all_outputs.add(output)
        records.append(record)
    return records


def classic_generator_recipe(ninja_text: str) -> dict:
    """Parse the classic C ``tools/genmodule`` host-tool build recipe."""
    matches = []
    for edge in _ninja_edges(ninja_text):
        if "hosttools/genmodule" in edge["outputs"]:
            matches.append(edge)
    if len(matches) != 1:
        raise RecipeError("Ninja file must declare exactly one hosttools/genmodule build edge")
    edge = matches[0]
    if edge["command"] is None:
        raise RecipeError("classic genmodule build edge has no COMMAND")
    chain = _ninja_chain(edge["command"])
    if len(chain) != 2 or chain[0] != ["cd", BUILD_ROOT]:
        raise RecipeError("classic genmodule command has unexpected shell structure")
    argv = chain[1]
    if not argv or argv[0] != "cc":
        raise RecipeError("classic genmodule compiler must be cc")
    source_args = [
        item for item in argv
        if item.startswith(SOURCE_PREFIX + "tools/genmodule/") and item.endswith(".c")
    ]
    if len(source_args) != len(set(source_args)):
        raise RecipeError("classic genmodule command has duplicate C source inputs")
    sources = [_source_relative(item, "classic genmodule source") for item in source_args]
    if (not sources or any(not item.startswith("tools/genmodule/") or not item.endswith(".c")
                           for item in sources)):
        raise RecipeError("classic genmodule command has unexpected source inputs")

    dependency_sources = [
        item for item in edge["dependencies"]
        if item.startswith(SOURCE_PREFIX + "tools/genmodule/") and item.endswith(".c")
    ]
    if dependency_sources != source_args:
        raise RecipeError("classic genmodule command sources differ from Ninja build inputs")
    if len(dependency_sources) != len(set(dependency_sources)):
        raise RecipeError("classic genmodule Ninja edge has duplicate C source inputs")

    try:
        output_index = argv.index("-o")
    except ValueError as exc:
        raise RecipeError("classic genmodule command is missing -o") from exc
    if output_index != len(argv) - 2 or argv.count("-o") != 1:
        raise RecipeError("classic genmodule command has unexpected arguments after -o")
    output = _build_relative(argv[output_index + 1], "classic genmodule output")
    if output != "build/pc-x86_64/hosttools/genmodule":
        raise RecipeError("classic genmodule output differs from declared host tool")
    first_source = argv.index(source_args[0])
    if argv[first_source:first_source + len(source_args)] != source_args or output_index != first_source + len(source_args):
        raise RecipeError("classic genmodule sources or flags are ambiguously ordered")
    flags = argv[1:first_source]
    if flags != ["-O2", "-w", "-IAROS-NX/tools/genmodule"]:
        raise RecipeError("classic genmodule flags differ from the frozen host-tool recipe")
    return {
        "compiler": argv[0],
        "flags": flags,
        "sources": sources,
        "argv": argv,
        "cwd": "build/pc-x86_64",
        "original_cwd": BUILD_ROOT,
        "output": output,
        "line": edge["line"],
    }


def nouveau_compile_recipes(compilation_db_text: str) -> list[dict]:
    """Return direct tracked C compile records for ``hidd-nouveau-drm``.

    Sources are relative to the AROS-NX checkout; directory and object paths
    are relative to that same checkout. ``argv`` preserves every compiler
    argument exactly after shell-like tokenization; it is never executed.
    """
    if not isinstance(compilation_db_text, str):
        raise RecipeError("compilation database input must be text")
    try:
        database = json.loads(compilation_db_text, object_pairs_hook=_unique_json_object,
                              parse_constant=lambda token: (_ for _ in ()).throw(
                                  RecipeError("invalid JSON constant: " + token)))
    except json.JSONDecodeError as exc:
        raise RecipeError("compilation database is malformed JSON") from exc
    if not isinstance(database, list):
        raise RecipeError("compilation database root must be an array")

    records = []
    seen_sources = set()
    seen_objects = set()
    for item in database:
        if not isinstance(item, dict):
            raise RecipeError("compilation database entry must be an object")
        file_value = item.get("file")
        output_value = item.get("output")
        source_candidate = isinstance(file_value, str) and file_value.startswith(NOUVEAU_SOURCE_PREFIX)
        output_candidate = isinstance(output_value, str) and output_value.startswith(NOUVEAU_OBJECT_PREFIX)
        if not output_candidate:
            continue
        if not source_candidate or not output_candidate:
            raise RecipeError("Nouveau DRM record is not a direct source/object pair")
        if file_value.endswith("/") or not file_value.endswith(".c"):
            raise RecipeError("Nouveau DRM source is not a C file")
        source = _source_relative(file_value, "Nouveau DRM source")
        if not source.startswith("workbench/hidds/nouveau/"):
            raise RecipeError("Nouveau DRM source is outside its tracked source subtree")
        if item.get("directory") != BUILD_ROOT:
            raise RecipeError("Nouveau DRM compilation directory is unexpected")
        object_path = _build_relative(output_value, "Nouveau DRM object output")
        if not isinstance(item.get("command"), str):
            raise RecipeError("Nouveau DRM compile command is missing")
        argv = _literal_argv(item["command"], "Nouveau DRM compile command")
        if PurePosixPath(argv[0]).name != "clang":
            raise RecipeError("Nouveau DRM command does not invoke clang")
        if argv.count("-o") != 1 or argv.count("-c") != 1:
            raise RecipeError("Nouveau DRM command must have one -o and one -c")
        output_index, source_index = argv.index("-o"), argv.index("-c")
        if output_index + 1 >= len(argv) or source_index + 1 >= len(argv):
            raise RecipeError("Nouveau DRM command has an incomplete -o or -c option")
        command_object = _build_relative(BUILD_PREFIX + _build_working_relative(
            argv[output_index + 1], "Nouveau DRM object argument"), "Nouveau DRM object argument")
        if command_object != object_path:
            raise RecipeError("Nouveau DRM command object differs from compilation database output")
        if argv[source_index + 1] != file_value:
            raise RecipeError("Nouveau DRM command source differs from compilation database file")
        if source in seen_sources:
            raise RecipeError("duplicate Nouveau DRM source record: " + source)
        if object_path in seen_objects:
            raise RecipeError("duplicate Nouveau DRM object record: " + object_path)
        seen_sources.add(source)
        seen_objects.add(object_path)
        records.append({
            "source": source,
            "directory": "build/pc-x86_64",
            "object": object_path,
            "argv": argv,
        })
    return sorted(records, key=lambda record: record["source"])

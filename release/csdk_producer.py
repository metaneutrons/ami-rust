#!/usr/bin/env python3
"""Reproduce the portable C-SDK candidate from immutable original inputs.

Run this helper under ci_sdk.Supervisor so its entire Python/compiler process
tree, including extraction and archive readback, is resource-accounted.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import lzma
import os
from pathlib import Path
import shutil
import sys
import tarfile


ROOT = Path(__file__).resolve().parent.parent
ARM_TOOLCHAIN_ARCHIVE_URL = "https://github.com/metaneutrons/aros-toolchains/releases/download/v0.1.4/aros-toolchain-v1-llvm11.0.0-linux-aarch64-pc-x86_64.tar.xz"


def load(name):
    spec = importlib.util.spec_from_file_location("_csdk_producer_" + name,
                                                 Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


csdk = load("ci_csdk")
sdk = csdk.sdk
recipes = load("csdk_recipes")
nouveau = load("csdk_nouveau")
ar = load("csdk_archive")
metadata = load("csdk_metadata")


def pinned_file(pin, *, root=ROOT):
    path = root / sdk._safe_relative(pin["path"])
    if (path.is_symlink() or not path.is_file() or type(pin.get("bytes")) is not int
            or path.stat().st_size != pin["bytes"] or sdk.sha256(path) != pin.get("sha256")):
        raise ValueError("portable C-SDK input differs from its pin: " + pin["path"])
    return path


def profile_rows(profile):
    if profile.get("symlinks") != [] or not isinstance(profile.get("files"), list):
        raise ValueError("C-SDK profile requires regular files and no symlinks")
    rows = {}
    for row in profile["files"]:
        name = sdk._safe_relative(row.get("path")).as_posix()
        if (name in rows or type(row.get("bytes")) is not int or row["bytes"] < 0
                or not isinstance(row.get("sha256"), str) or not sdk.DIGEST.fullmatch(row["sha256"])):
            raise ValueError("duplicate or malformed C-SDK profile file")
        rows[name] = (row["bytes"], row["sha256"])
    return rows


def compile_nouveau(plan: dict, work_dir: Path, plan_path: Path, jobs: int) -> dict:
    """Persist an interrupted direct compile before propagating failure."""
    try:
        outcome = nouveau._compile_commands(plan, work_dir, jobs)
    except KeyboardInterrupt as error:
        plan["status"] = "FAIL_COMPILE"
        plan["error"] = str(error)
        signal_state = getattr(error, "signal_state", {})
        plan["compile"] = {
            "failure": str(error),
            "interrupted": True,
            "sigterm_delivery_count": signal_state.get("received", 0),
            "signal_cleanup_attempts": signal_state.get("cleanup_attempts", 1),
            "process_group_cleanup": signal_state.get("process_group_cleanup", []),
            "incomplete_cleanup": signal_state.get("incomplete_cleanup", False),
            "cleanup_status": ("incomplete_cleanup" if signal_state.get("incomplete_cleanup")
                               else "complete"),
            "logs_directory": str(work_dir / "nouveau-logs"),
        }
        nouveau._replace_plan(plan_path, plan)
        raise RuntimeError("full Nouveau compilation interrupted: " + str(error)) from error
    plan["compile"] = outcome
    plan["status"] = ("NOUVEAU_825_COMPILE_COMMANDS_COMPLETE"
                       if outcome["failure"] is None else "FAIL_COMPILE")
    nouveau._replace_plan(plan_path, plan)
    return outcome


def validate_profiles(original, candidate):
    before, after = profile_rows(original), profile_rows(candidate)
    if len(before) != 2835 or before.keys() != after.keys():
        raise ValueError("portable C-SDK must preserve the original 2835-file set")
    changed = {name for name in before if before[name] != after[name]}
    headers = {name for name in changed if name.startswith("include/") and name.endswith(".h")}
    if (len(changed) != 532 or len(headers) != 530
            or changed - headers != {"lib/libdrm_nouveau.a", "lib/pkgconfig/aom.pc"}):
        raise ValueError("portable C-SDK change set is not exactly 530 headers, Nouveau and aom.pc")
    return sorted(changed)


def validate_toolchain_hosts(toolchains):
    if not isinstance(toolchains, dict) or set(toolchains) != set(sdk.PORTABLE_CSDK_HOSTS):
        raise ValueError("portable C-SDK toolchain pins must cover exactly the admitted C-SDK hosts")
    arm = toolchains["linux-aarch64"]
    if not isinstance(arm, dict) or "archive" not in arm:
        raise ValueError("portable C-SDK Linux/AArch64 archive pin is missing")
    archive = arm["archive"]
    if (not isinstance(archive, dict)
            or set(archive) != {"kind", "url", "bytes", "sha256", "archive_root"}
            or archive.get("kind") != "tar" or archive.get("url") != ARM_TOOLCHAIN_ARCHIVE_URL
            or archive.get("archive_root") != "toolchain"
            or type(archive.get("bytes")) is not int or archive["bytes"] <= 0
            or not sdk._is_digest(archive.get("sha256"))):
        raise ValueError("portable C-SDK Linux/AArch64 archive pin is malformed")
    return toolchains


def load_inputs(spec_path):
    spec = sdk.read_json(spec_path)
    if (spec.get("schema") != "ami-rust-portable-csdk-v1"
            or spec.get("status") != "PINNED_CANDIDATE_THREE_HOST_QUALIFICATION_REQUIRED"
            or spec.get("required_counts") != {"regular_files": 2835, "changed_files": 532,
                                               "public_headers": 530}):
        raise ValueError("unrecognized portable C-SDK candidate contract")
    validate_toolchain_hosts(spec.get("toolchains"))
    validate_native_counts(spec.get("nouveau", {}))
    original = sdk.read_json(pinned_file(spec["original"]["profile"]))
    candidate = sdk.read_json(pinned_file(spec["candidate"]["profile"]))
    validate_profiles(original, candidate)
    for name in ("source_capsule", "source_manifest", "patch_series"):
        pinned_file(spec[name])
    return spec, original, candidate


def validate_native_counts(pin):
    expected = {"objects": 825, "unchanged_members": 616,
                "path_changed_members": 209, "symbols": 4515}
    if any(type(pin.get(key)) is not int or pin[key] != value
           for key, value in expected.items()):
        raise ValueError("portable C-SDK native counts differ from the frozen contract")


def explicit_host_tools(args):
    names = ("cmake", "pkg_config", "perl", "git")
    values = {name.replace("_", "-"): getattr(args, name) for name in names}
    if not any(value is not None for value in values.values()):
        return None
    if any(value is None for value in values.values()):
        raise ValueError("explicit C-SDK host tools must be supplied as a complete set")
    return values


def extract_original(archive, pin, profile, destination):
    """Extract exactly the original profile, retaining original file modes."""
    if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size != pin["bytes"]
            or sdk.sha256(archive) != pin["sha256"]):
        raise ValueError("original C-SDK archive differs from its immutable pin")
    expected, seen, modes = profile_rows(profile), set(), {}
    if destination.exists() or destination.is_symlink():
        raise ValueError("fresh original C-SDK staging tree required")
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r:xz") as bundle:
        for member in bundle:
            name = member.name.removeprefix("./")
            relative = sdk._safe_relative(name)
            if relative.parts[0] != "Developer":
                raise ValueError("original C-SDK archive root differs")
            if member.isdir():
                continue
            name = relative.relative_to("Developer").as_posix()
            if not member.isfile() or name in seen or name not in expected:
                raise ValueError("unexpected original C-SDK archive member")
            raw = bundle.extractfile(member).read()
            if (len(raw), csdk.digest(raw)) != expected[name]:
                raise ValueError("original C-SDK member differs from its profile")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(raw)
            target.chmod(member.mode & 0o777)
            modes[name] = member.mode & 0o777
            seen.add(name)
    if seen != set(expected):
        raise ValueError("original C-SDK extraction is incomplete")
    return modes


def compare_native(original, plan, pin):
    if (original["sha256"] != pin["original_sha256"] or original["bytes"] != pin["original_bytes"]
            or len(original["members"]) != 825 or len(original["symbols"]) != 4515
            or plan["member_basenames"] != [m["name"] for m in original["members"]]):
        raise ValueError("original Nouveau archive identity, member order or symbol count differs")
    compared = []
    for index, (old, name) in enumerate(zip(original["members"], plan["ordered_object_paths"])):
        raw = Path(name).read_bytes()
        changed = raw != old["data"]
        path_bearing = (pin["historical_source_prefix"] + "/").encode() in old["data"]
        if changed != path_bearing:
            raise ValueError("unexplained Nouveau object change: " + str(index))
        if any(prefix in raw for prefix in (b"/Volumes/", b"/Users/fabian/", b"/home/runner/", b"/Users/runner/")):
            raise ValueError("local build prefix remains in Nouveau object")
        compared.append({"index": index, "name": old["name"], "original_sha256": old["sha256"],
                         "derived_sha256": csdk.digest(raw), "derived_bytes": len(raw), "changed": changed})
    if sum(row["changed"] for row in compared) != 209:
        raise ValueError("Nouveau path-change coverage differs")
    return compared


def original_prefix_counter(plan, original, replacement, work, compiler_sha):
    """Recompile the same 825 records with only the historical prefix restored."""
    counter = copy.deepcopy(plan)
    objects = work / "objects"
    objects.mkdir(parents=True)
    counter["build_root"] = str(objects)
    counter["ordered_object_paths"] = []
    flag = "-ffile-prefix-map=" + plan["source_root"] + "=."
    for index, command in enumerate(counter["commands"]):
        output = objects / (str(index) + ".obj")
        argv = command["argv"]
        if argv.count(flag) != 1 or argv.count("-o") != 1:
            raise ValueError("ambiguous prefix-map counter-case")
        argv[argv.index(flag)] = "-ffile-prefix-map=" + plan["source_root"] + "=" + replacement
        argv[argv.index("-o") + 1] = str(output)
        command["object"] = str(output)
        counter["ordered_object_paths"].append(str(output))
    nouveau._validate_compiler(counter, compiler_sha)
    nouveau._prepare_outputs(counter)
    result = nouveau._compile_commands(counter, work, 2)
    if result["failure"] is not None or result["completed"] != 825:
        raise ValueError("original-prefix counter-case compilation failed: " + str(result["failure"]))
    rows = []
    for index, (old, path) in enumerate(zip(original["members"], counter["ordered_object_paths"])):
        raw = Path(path).read_bytes()
        if raw != old["data"]:
            raise ValueError("original-prefix counter-case did not reproduce original object " + str(index))
        rows.append({"index": index, "sha256": old["sha256"]})
        Path(path).unlink()  # Exact original bytes remain in the immutable input.
    nouveau._validate_compiler(counter, compiler_sha)
    return {"status": "PASS_ALL_825_ORIGINAL_OBJECTS_REPRODUCED", "members": rows,
            "prefix_replacement": replacement, "compile": result}


def canonical_archive(root, modes, destination):
    inventory = sdk.component_inventory(root)
    if inventory["symlinks"] or {r["path"] for r in inventory["files"]} != set(modes):
        raise ValueError("canonical C-SDK membership differs from original modes")
    with lzma.open(destination, "xb", format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as bundle:
            for name in sorted(modes):
                path = root / name
                info = tarfile.TarInfo("Developer/" + name)
                info.size, info.mode = path.stat().st_size, modes[name]
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                with path.open("rb") as stream:
                    bundle.addfile(info, stream)
    expected = {"Developer/" + r["path"]: (r["bytes"], r["sha256"]) for r in inventory["files"]}
    seen = {}
    with tarfile.open(destination, "r:xz") as bundle:
        for member in bundle:
            if member.name in seen or not member.isfile():
                raise ValueError("noncanonical C-SDK readback member")
            raw = bundle.extractfile(member).read()
            seen[member.name] = (len(raw), csdk.digest(raw))
    if seen != expected:
        raise ValueError("canonical C-SDK archive readback differs")
    return inventory


def produce(spec_path, original_archive, toolchain, native_compiler, work, output, supervisor,
            *, host_tools=None):
    spec, original_profile, candidate_profile = load_inputs(spec_path)
    host = sdk.portable_csdk_host_identity()
    tool_profile = sdk.read_json(pinned_file(spec["toolchains"][host]["profile"]))
    sdk.verify_component(toolchain, tool_profile, "portable C-SDK cross toolchain")
    compiler_pin = spec["toolchains"][host]["compiler"]
    pinned_file(compiler_pin, root=toolchain)
    material = csdk.materialize_capsule(pinned_file(spec["source_capsule"]),
                                       pinned_file(spec["source_manifest"]), work / "capsule", supervisor)
    patches = csdk.apply_source_patches(material["roots"], supervisor)
    source, capsule = material["roots"]["AROS-NX"], work / "capsule"
    text = (capsule / "recipes/build.ninja").read_text()
    header_recipes = recipes.public_header_recipes(text)
    headers_root = work / "headers"
    headers = csdk.generate_public_headers(source, capsule / "generated/sdk-include", header_recipes,
                                          recipes.classic_generator_recipe(text), headers_root,
                                          native_compiler, supervisor)
    prefix = csdk.probe_prefix_mapping(toolchain, work / "prefix-probe", supervisor)
    stage = work / "build"
    modes = extract_original(original_archive, spec["original"]["archive"], original_profile,
                             stage / "SYS/Developer")
    developer = stage / "SYS/Developer"
    for name in ("SDK/include", "GENINCDIR"):
        shutil.copytree(capsule / "generated/sdk-include", stage / name)
    for index, row in enumerate(header_recipes):
        for name in row["outputs"]:
            raw = (headers_root / "headers-0" / str(index) / name).read_bytes()
            if csdk.digest(raw) != headers["headers"][name]["sha256"]:
                raise ValueError("regenerated public header changed after qualification")
            for directory in (developer / "include", stage / "SDK/include", stage / "GENINCDIR"):
                target = directory / sdk._safe_relative(name)
                if not target.is_file():
                    raise ValueError("regenerated header is absent from original staging tree")
                target.write_bytes(raw)
    empty = source / "arch/all-native/include"
    manifest = sdk.read_json(pinned_file(spec["source_manifest"]))
    if any(r["path"].startswith("sources/AROS-NX/arch/all-native/include/") for r in manifest["inventory"]):
        raise ValueError("declared empty source include unexpectedly has frozen files")
    empty.mkdir()
    (stage / "gen/workbench/hidds/nouveau").mkdir(parents=True)
    aom = metadata.generate_aom_metadata(material["roots"]["libaom"],
        capsule / "vendor/libaom/original/libaom-3.12.1.tar.gz",
        (developer / "lib/pkgconfig/aom.pc").read_bytes(), work / "aom-metadata", supervisor,
        tools=host_tools)
    shutil.copyfile(aom["generated_pc_path"], developer / "lib/pkgconfig/aom.pc")
    records = recipes.nouveau_compile_recipes((capsule / "recipes/compile_commands.json").read_text())
    plan = nouveau.plan_nouveau(records, text, source, stage, toolchain)
    plan_path = work / "nouveau-plan.json"
    nouveau._write_plan_fresh(plan_path, plan)
    nouveau._validate_compiler(plan, compiler_pin["sha256"])
    nouveau._prepare_outputs(plan)
    native_work = work / "nouveau-compile"
    native_work.mkdir()
    outcome = compile_nouveau(plan, native_work, plan_path, 2)
    if outcome["failure"] is not None or outcome["completed"] != 825:
        raise ValueError("full Nouveau compilation failed: " + str(outcome["failure"]))
    nouveau._validate_compiler(plan, compiler_pin["sha256"])
    old = ar.read_archive((developer / spec["nouveau"]["archive_path"]).read_bytes())
    compared = compare_native(old, plan, spec["nouveau"])
    counter = original_prefix_counter(plan, old, spec["nouveau"]["historical_source_prefix"],
                                      work / "counter", compiler_pin["sha256"])
    (work / "original-prefix-counter.json").write_bytes(sdk.canonical_json(counter))
    archive_sha = None
    for index in range(2):
        archive = work / ("nouveau-" + str(index) + ".a")
        supervisor.run([str(toolchain / "bin/llvm-ar"), "--format=gnu", "qcD", str(archive),
                        *plan["ordered_object_paths"]], cwd=stage, label="native-archive-" + str(index), timeout=120)
        supervisor.run([str(toolchain / "bin/llvm-ranlib"), "-D", str(archive)], cwd=stage,
                       label="native-ranlib-" + str(index), timeout=120)
        new = ar.read_archive(archive.read_bytes())
        if (new["symbols"] != old["symbols"] or len(new["members"]) != 825
                or new["sha256"] != spec["nouveau"]["derived_sha256"]
                or new["bytes"] != spec["nouveau"]["derived_bytes"]):
            raise ValueError("derived native archive or symbol-to-member index differs")
        if any((a["name"], a["derived_sha256"]) != (b["name"], b["sha256"])
               for a, b in zip(compared, new["members"])):
            raise ValueError("native archive does not contain every exact compiled object")
        if archive_sha is not None and archive_sha != new["sha256"]:
            raise ValueError("native archive is not deterministic")
        archive_sha = new["sha256"]
    shutil.copyfile(work / "nouveau-0.a", developer / "lib/libdrm_nouveau.a")
    sdk.verify_component(toolchain, tool_profile, "cross toolchain after derivation")
    sdk.verify_component(developer, candidate_profile, "complete derived C-SDK")
    for path in developer.rglob("*"):
        if path.is_file() and any(p in path.read_bytes() for p in
                (b"/Volumes/Dev/Source/", b"/Users/fabian/", b"/home/runner/", b"/Users/runner/", str(work).encode())):
            raise ValueError("local build prefix remains in derived C-SDK: " + str(path))
    candidate_pin = spec["candidate"]["archive"]
    target = output / candidate_pin["name"]
    profile = canonical_archive(developer, modes, target)
    if target.stat().st_size != candidate_pin["bytes"] or sdk.sha256(target) != candidate_pin["sha256"]:
        raise ValueError("canonical C-SDK differs from its separate candidate identity")
    (output / "csdk-profile.json").write_bytes(sdk.canonical_json(profile))
    supervisor.check_limits("full portable C-SDK derivation")
    result = {"schema": "ami-rust-portable-csdk-producer-v1", "host": host,
              "status": "PRODUCED_CSDK_COMPONENT_CANDIDATE_NOT_R1_ACCEPTED",
              "spec_sha256": sdk.sha256(spec_path), "patches": patches,
              "source_capsule_sha256": material["source_capsule_sha256"],
              "public_headers": headers, "prefix_probe": prefix, "aom": aom,
              "native_compile": outcome, "native_members": compared,
              "original_prefix_counter": counter, "native_symbol_entries": 4515,
              "candidate_archive": {"path": target.name, "bytes": target.stat().st_size, "sha256": sdk.sha256(target)},
              "profile_sha256": sdk.sha256(output / "csdk-profile.json"),
              "commands": supervisor.commands, "baseline_changed": False, "R1_accepted": False}
    (output / "csdk-producer.json").write_bytes(sdk.canonical_json(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "output", "toolchain", "native-compiler", "original-archive"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--spec", type=Path, default=ROOT / "release/portable-csdk/spec.json")
    for name in ("cmake", "pkg-config", "perl", "git"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args()
    host_tools = explicit_host_tools(args)
    for name in ("work", "output"):
        path = getattr(args, name)
        if not path.is_absolute() or path.exists() or path.is_symlink():
            raise ValueError("fresh absolute portable C-SDK work/output roots required")
    if args.work in args.output.parents or args.output in args.work.parents or args.work == args.output:
        raise ValueError("C-SDK work and output roots overlap")
    for path in (args.work, args.output):
        path.mkdir(parents=True)
    python = args.work / "python"
    python.mkdir()
    supervisor = sdk.Supervisor(args.work, args.output, python, {**os.environ, "LC_ALL": "C", "LANG": "C"})
    sdk.validate_portable_csdk_resource_policy(
        sdk.read_json(ROOT / "release/ci-resources.json"), args.work)
    result = produce(args.spec.resolve(strict=True), args.original_archive.resolve(strict=True),
                     args.toolchain.resolve(strict=True), args.native_compiler.resolve(strict=True),
                     args.work, args.output, supervisor, host_tools=host_tools)
    print(result["status"])


if __name__ == "__main__":
    main()

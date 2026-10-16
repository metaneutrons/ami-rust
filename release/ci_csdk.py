#!/usr/bin/env python3
"""Produce the explicitly derived portable C-SDK from pinned original inputs.

Original SDK/source bytes remain immutable. A source patch is not qualified
until generation, compilation, relocation and the two-host checks pass.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import io
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_portable_csdk_sdk", ROOT / "release/ci_sdk.py")
sdk = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sdk)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def materialize_capsule(capsule, manifest_path, destination, supervisor):
    """Read the immutable capsule once; extract only owned build inputs.

    Every member, including unselected vendors, is read and compared with the
    capsule inventory. No historical absolute build path is used as a live input.
    """
    capsule, destination = Path(capsule), Path(destination)
    series = sdk.read_json(ROOT / "release/patches/portable-csdk/series.json")
    if capsule.is_symlink() or sdk.sha256(capsule) != series["original_source_capsule_sha256"]:
        raise ValueError("original source capsule differs from its pin")
    manifest = sdk.read_json(Path(manifest_path))
    if (manifest.get("schema") != "ami-rust-csdk-corresponding-source-capsule-v1"
            or manifest.get("capsule", {}).get("sha256") != sdk.sha256(capsule)):
        raise ValueError("source capsule manifest has a different identity")
    inventory = {r["path"]: r for r in manifest["inventory"]}
    if len(inventory) != len(manifest["inventory"]) or len(inventory) != manifest["capsule_member_count"]:
        raise ValueError("duplicate or incomplete source capsule inventory")
    selected = lambda n: n.startswith(("sources/", "generated/", "recipes/")) or n == "vendor/libaom/original/libaom-3.12.1.tar.gz"
    selected_bytes = sum(r["bytes"] for n, r in inventory.items() if selected(n))
    if selected_bytes > 352 * 1024**2:
        raise ValueError("selected C-SDK source inputs exceed their explicit ceiling")
    if destination.exists() or destination.is_symlink():
        raise ValueError("fresh C-SDK source destination required")
    supervisor.check_limits("before source capsule extraction")
    destination.mkdir()
    seen, copied = set(), 0
    with tarfile.open(capsule, "r|xz") as archive:
        for member in archive:
            name = sdk._safe_relative(member.name).as_posix()
            row = inventory.get(name)
            if row is None or name in seen:
                raise ValueError("unexpected or duplicate source capsule member")
            seen.add(name)
            if member.isdir():
                if row["type"] != "directory":
                    raise ValueError("source capsule member type differs")
                continue
            if not member.isfile() or row["type"] != "file" or member.size != row["bytes"]:
                raise ValueError("source capsule regular member differs")
            if member.size > 96 * 1024**2:
                raise ValueError("source capsule member exceeds individual ceiling")
            read = archive.extractfile(member)
            target = destination / name
            output = None
            if selected(name):
                target.parent.mkdir(parents=True, exist_ok=True)
                output = target.open("xb")
            h, size = hashlib.sha256(), 0
            try:
                while block := read.read(1024**2):
                    size += len(block)
                    h.update(block)
                    if output is not None:
                        output.write(block)
            finally:
                if output is not None:
                    output.close()
            if size != row["bytes"] or h.hexdigest() != row["sha256"]:
                raise ValueError("source capsule member hash differs: " + name)
            if output is not None:
                target.chmod(row["mode"] & 0o777)
                copied += size
    if seen != set(inventory) or copied != selected_bytes:
        raise ValueError("source capsule extraction is incomplete")
    aom_archive = destination / "vendor/libaom/original/libaom-3.12.1.tar.gz"
    aom_pin = next(r for r in series["patches"] if r["component"] == "libaom")
    if sdk.sha256(aom_archive) != aom_pin["base"]["archive_sha256"]:
        raise ValueError("nested original libaom archive differs")
    aom = destination / "sources/libaom"
    with tarfile.open(aom_archive, "r:gz") as archive:
        name = "libaom-3.12.1/" + aom_pin["path"]
        members = [m for m in archive if m.name == name]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("libaom generator source is absent or ambiguous")
        raw = archive.extractfile(members[0]).read()
    if digest(raw) != aom_pin["before_sha256"]:
        raise ValueError("libaom generator source differs from its pin")
    target = aom / aom_pin["path"]
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    supervisor.check_limits("after source capsule extraction")
    return {"status": "PASS_SOURCE_MATERIALIZATION_ONLY", "all_capsule_members_verified": len(seen),
            "selected_regular_bytes": copied, "source_capsule_sha256": sdk.sha256(capsule),
            "roots": {"AROS-NX": destination / "sources/AROS-NX",
                      "aros-tools": destination / "sources/aros-tools", "libaom": aom}}


def probe_prefix_mapping(toolchain, root, supervisor):
    """Prove source/header mapping, relocation and two effective counter-cases."""
    root = Path(root)
    if root.exists() or root.is_symlink():
        raise ValueError("fresh prefix-map probe root required")
    root.mkdir()
    compiler = Path(toolchain) / "bin/clang-11"
    records, mapped = [], []
    version = supervisor.run_text([str(compiler), "--version"], cwd=root,
                                  label="prefix-map-compiler-version", timeout=30)
    if "clang version 11.0.0" not in version:
        raise ValueError("prefix-map probe requires the pinned LLVM 11 compiler")
    for name, mode in (("root-a", "map"), ("different root b", "map"),
                       ("unmapped-control", "none"), ("incorrect-prefix", "wrong")):
        source = root / name
        (source / "inc").mkdir(parents=True)
        (source / "inc/probe.h").write_text("const char header_origin[] = __FILE__;\n")
        (source / "probe.c").write_text('#include "inc/probe.h"\nconst char source_origin[] = __FILE__;\n')
        target = source / "probe.o"
        command = [str(compiler), "--target=x86_64-unknown-aros", "-ffreestanding", "-O0", "-c",
                   str(source / "probe.c"), "-o", str(target)]
        if mode != "none":
            prefix = source if mode == "map" else root / "nonexistent-source-prefix"
            command.append("-ffile-prefix-map=" + str(prefix) + "=.")
        process = supervisor.run(command, cwd=root, label="prefix-" + name.replace(" ", "-"), timeout=60)
        raw = target.read_bytes()
        has_source_prefix = str(source).encode() in raw
        if raw[:4] != b"\x7fELF" or int.from_bytes(raw[18:20], "little") != 62:
            raise ValueError("prefix-map probe did not produce native x86-64 ELF")
        if mode == "map":
            if has_source_prefix or b"./probe.c" not in raw or b"./inc/probe.h" not in raw:
                raise ValueError("compiler failed to map source/header diagnostic paths")
            mapped.append(raw)
        elif not has_source_prefix:
            raise ValueError("prefix-map counter-probe failed to retain the real source path")
        records.append({"case": name, "mode": mode, "bytes": len(raw), "sha256": digest(raw),
                        "local_source_prefix_present": has_source_prefix, "process": process,
                        "status": "PASS" if mode == "map" else "EXPECTED_LOCAL_PREFIX_DETECTED"})
    if mapped[0] != mapped[1]:
        raise ValueError("prefix-map objects differ across the two absolute roots")
    return {"status": "PASS_PREFIX_MAPPING_ONLY", "compiler_version": version,
            "compiler_sha256": sdk.sha256(compiler), "two_roots_byte_identical": True,
            "cases": records, "RSS_peak_observed_bytes": supervisor.peak_rss,
            "workspace_peak_observed_bytes": supervisor.peak_workspace,
            "limits": supervisor.limits}


def apply_source_patches(roots, supervisor, *, patch_directory=None):
    """Apply exactly declared source hunks, with byte identities before/after."""
    directory = Path(patch_directory) if patch_directory is not None else ROOT / "release/patches/portable-csdk"
    manifest = sdk.read_json(directory / "series.json")
    if manifest.get("schema") != "ami-rust-portable-csdk-patches-v1":
        raise ValueError("unrecognized portable C-SDK patch manifest")
    applied = []
    for index, row in enumerate(manifest["patches"]):
        source = Path(roots[row["component"]]).resolve(strict=True)
        name = sdk._safe_relative(row["path"])
        for part in (source.joinpath(*name.parts[:i]) for i in range(1, len(name.parts) + 1)):
            if part.is_symlink():
                raise ValueError("source patch path traverses a symlink")
        path = source.joinpath(*name.parts)
        if not path.is_file() or sdk.sha256(path) != row["before_sha256"]:
            raise ValueError("patch base differs from the pinned source: " + row["path"])
        patch_name = sdk._safe_relative(row["patch"])
        patch = directory.joinpath(*patch_name.parts)
        if patch.is_symlink() or sdk.sha256(patch) != row["patch_sha256"]:
            raise ValueError("source patch differs from its manifest")
        file_headers = [line for line in patch.read_text().splitlines()
                        if line.startswith(("--- ", "+++ "))]
        if file_headers != ["--- a/" + row["path"], "+++ b/" + row["path"]]:
            raise ValueError("source patch must change only its declared file")
        supervisor.run(["/usr/bin/patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch)],
                       cwd=source, label="patch-" + str(index) + "-" + row["component"], timeout=30)
        if sdk.sha256(path) != row["after_sha256"]:
            raise ValueError("patched source differs from its declared result")
        applied.append({"component": row["component"], "path": row["path"],
                        "before_sha256": row["before_sha256"], "after_sha256": row["after_sha256"],
                        "patch_sha256": row["patch_sha256"]})
    return applied


def _mesa_header_override(source, destination, supervisor):
    """Materialize the complete new config file from the pinned port patch."""
    patch = source / "workbench/libs/mesa/mesa-20.0.8-aros.diff"
    if sdk.sha256(patch) != "16e6df68b64996d880b4fb1eb9275851ee2ab70badff731e2610bd7edca548b6":
        raise ValueError("Mesa header override port patch differs")
    blocks = re.split(r"(?m)(?=^diff -ruN )", patch.read_text())
    blocks = [b for b in blocks if b.startswith(
        "diff -ruN mesa-20.0.8/mesa3dgl.conf mesa-20.0.8.aros/mesa3dgl.conf\n")]
    if len(blocks) != 1 or "@@ -0,0 " not in blocks[0]:
        raise ValueError("Mesa header override is not one complete added file")
    destination.mkdir()
    fragment = destination / "mesa-config.patch"
    fragment.write_text(blocks[0])
    supervisor.run(["/usr/bin/patch", "--batch", "--fuzz=0", "-p1", "-i", str(fragment)],
                   cwd=destination, label="mesa-header-config", timeout=30)
    config = destination / "mesa3dgl.conf"
    if not config.is_file() or config.is_symlink():
        raise ValueError("Mesa header override generation failed")
    return config


def generate_public_headers(source, frozen_include, header_recipes, generator_recipe,
                            destination, compiler, supervisor):
    """Rebuild all 530 public headers in two roots, preserving non-banner bytes.

    This applies the caller patch's argv/cwd change to the complete frozen
    generator records. It does not claim a reconfiguration of the whole OS.
    """
    source, frozen_include, destination = Path(source), Path(frozen_include), Path(destination)
    if len(header_recipes) != 106 or len(generator_recipe["sources"]) != 27:
        raise ValueError("incomplete frozen public-header generator coverage")
    outputs = [name for row in header_recipes for name in row["outputs"]]
    if len(outputs) != 530 or len(set(outputs)) != 530:
        raise ValueError("ambiguous or incomplete public-header output set")
    if destination.exists() or destination.is_symlink():
        raise ValueError("fresh public-header reproduction root required")
    destination.mkdir()
    compiler = Path(compiler).resolve(strict=True)
    version = supervisor.run_text([str(compiler), "--version"], cwd=destination,
                                  label="header-native-compiler-version", timeout=30)
    compiler_sha = sdk.sha256(compiler)
    generator = destination / "genmodule"
    supervisor.run([str(compiler), "-O2", "-w", "-I" + str(source / "tools/genmodule"),
                    *[str(source / sdk._safe_relative(n)) for n in generator_recipe["sources"]],
                    "-o", str(generator)], cwd=destination, label="build-classic-genmodule", timeout=1200)
    if sdk.sha256(compiler) != compiler_sha:
        raise ValueError("native compiler changed during generator production")
    override = _mesa_header_override(source, destination / "mesa-override", supervisor)
    all_roots = []
    for root_number, name in enumerate(("source-a", "different source b")):
        checkout = destination / name
        checkout.mkdir()
        configs = sorted({row["config"] for row in header_recipes})
        for config in configs:
            rel = sdk._safe_relative(config)
            original, copied = source / rel, checkout / rel
            if original.is_symlink() or not original.is_file():
                raise ValueError("frozen generator config is unavailable")
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, copied)
        result = {}
        for index, row in enumerate(header_recipes):
            private = destination / ("headers-" + str(root_number)) / str(index)
            for directory in ("clib", "defines", "inline", "proto", "interface"):
                (private / directory).mkdir(parents=True, exist_ok=True)
            args = list(row["generator_args"])
            if (args.count("-c") != 1 or args.count("-d") != 1
                    or args.count("writeincludes") != 1):
                raise ValueError("frozen generator operands are ambiguous")
            args[args.index("-c") + 1] = row["config"]
            args[args.index("-d") + 1] = str(private)
            if "-o" in args:
                if args.count("-o") != 1 or row["output_override"] != {
                        "kind": "build", "path": "build/pc-x86_64/Ports/mesa/mesa-20.0.8/mesa3dgl.conf"}:
                    raise ValueError("unexpected header config override")
                args[args.index("-o") + 1] = str(override)
            supervisor.run([str(generator), *args], cwd=checkout,
                           label=f"headers-{root_number}-{index}", timeout=60)
            for output in row["outputs"]:
                rel = sdk._safe_relative(output)
                raw = (private / rel).read_bytes()
                original = (frozen_include / rel).read_bytes()
                banner = re.compile(rb"(Automatically generated from ')([^'\n]+)('\.)")
                matches = list(banner.finditer(original))
                if len(matches) != 1 or not matches[0].group(2).endswith(b"/" + row["config"].encode()):
                    raise ValueError("original public-header provenance differs from its config")
                expected = banner.sub(lambda m: m.group(1) + row["config"].encode() + m.group(3), original)
                if raw != expected or any(prefix in raw for prefix in
                        (str(destination).encode(), b"/Volumes/Dev/Source/", b"/Users/fabian/")):
                    raise ValueError("public header differs outside its provenance path: " + output)
                result[output] = {"bytes": len(raw), "sha256": digest(raw)}
        all_roots.append(result)
    if all_roots[0] != all_roots[1]:
        raise ValueError("public headers differ between the two source roots")
    # A positive mapping check needs a counter-case that demonstrably leaks cwd.
    row = header_recipes[0]
    control = destination / "absolute-control"
    for directory in ("clib", "defines", "inline", "proto", "interface"):
        (control / directory).mkdir(parents=True, exist_ok=True)
    args = list(row["generator_args"])
    args[args.index("-c") + 1] = str(source / row["config"])
    args[args.index("-d") + 1] = str(control)
    if "-o" in args:
        args[args.index("-o") + 1] = str(override)
    supervisor.run([str(generator), *args], cwd=destination,
                   label="headers-absolute-counter", timeout=60)
    if not all(str(source).encode() in (control / n).read_bytes() for n in row["outputs"]):
        raise ValueError("absolute config counter-case did not expose its source prefix")
    return {"status": "PASS_MACOS_HEADERS_ONLY" if sdk.host_identity()[0] == "macos-aarch64"
            else "PASS_LINUX_HEADERS_ONLY", "headers": all_roots[0],
            "two_roots_byte_identical": True, "only_provenance_paths_changed": True,
            "absolute_config_counter_case": "EXPECTED_LOCAL_PREFIX_DETECTED",
            "native_compiler": {"sha256": compiler_sha, "version": version},
            "generator_sha256": sdk.sha256(generator), "generator_sources": generator_recipe["sources"],
            "mesa_override_sha256": sdk.sha256(override)}

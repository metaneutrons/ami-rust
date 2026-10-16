"""Generate and check relocatable libaom pkg-config metadata."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import tarfile
import uuid


ROOT = Path(__file__).resolve().parent.parent
_SDK_SPEC = importlib.util.spec_from_file_location("_aom_metadata_ci_sdk", ROOT / "release/ci_sdk.py")
if _SDK_SPEC is None or _SDK_SPEC.loader is None:
    raise RuntimeError("cannot load the C-SDK process supervisor")
_SDK = importlib.util.module_from_spec(_SDK_SPEC)
_SDK_SPEC.loader.exec_module(_SDK)

LIBAOM_ARCHIVE_SHA256 = "9e9775180dec7dfd61a79e00bda3809d43891aee6b2e331ff7f26986207ea22e"
PATCHED_PKG_CONFIG_SHA256 = "8833578cfd9807ade9540afd2680bd32002e655eefc8e5446245a0e784ce2708"
ORIGINAL_PKG_CONFIG_SHA256 = "64cf5b1270215adcca2304a89244adfcd3bda77400b1adc3fc69a8308a59725e"
GENERATED_PC_SHA256 = "44e60ded4d7fa63dceeca042abfca86b841632586aaba5437c45fa96a99f5de7"

_ARCHIVE_LIMIT = 64 * 1024**2
_MEMBER_LIMIT = 1024**2
_ARCHIVE_MEMBERS = (
    "build/cmake/util.cmake",
    "build/cmake/version.cmake",
    "build/cmake/version.pl",
    "CHANGELOG",
    "build/cmake/pkg_config.cmake",
)
_MATERIALIZED_MEMBERS = frozenset(_ARCHIVE_MEMBERS[:-1])
_TOOLS = ("cmake", "pkg-config", "perl", "git")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_cmake_path(value: Path | str, description: str) -> str:
    """Return a path usable in quoted CMake text and -D values.

    Spaces are safe in argv and quoted CMake strings. Reject characters that
    can start CMake expansion, split a CMake list, escape a quote, or inject a
    new command line.
    """
    text = str(value)
    if not text or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"{description} contains control characters")
    if any(char in text for char in ('"', "\\", "$", ";")):
        raise ValueError(f"{description} contains unsafe CMake syntax")
    return text


def _quote_cmake_path(value: Path | str, description: str) -> str:
    return '"' + _safe_cmake_path(value, description) + '"'


def _cmake_argument(name: str, value: Path | str) -> str:
    return "-D" + name + "=" + _safe_cmake_path(value, name)


def _source_root(value: str | os.PathLike[str]) -> Path:
    candidate = Path(value)
    if candidate.is_symlink():
        raise ValueError("libaom source root must not be a symlink")
    root = candidate.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("libaom source root is not a directory")
    _safe_cmake_path(root, "libaom source root")
    return root


def _archive_file(value: str | os.PathLike[str]) -> Path:
    candidate = Path(value)
    if candidate.is_symlink():
        raise ValueError("original libaom archive must not be a symlink")
    archive = candidate.resolve(strict=True)
    if not archive.is_file() or archive.stat().st_size > _ARCHIVE_LIMIT:
        raise ValueError("original libaom archive is missing or exceeds its size bound")
    if _file_digest(archive) != LIBAOM_ARCHIVE_SHA256:
        raise ValueError("original libaom archive differs from its pin")
    return archive


def _destination_root(value: str | os.PathLike[str], source: Path) -> Path:
    requested = Path(value).expanduser()
    if requested.name in ("", ".", ".."):
        raise ValueError("fresh AOM metadata destination required")
    destination = requested.resolve(strict=False)
    if (destination == source or destination.is_relative_to(source)
            or source.is_relative_to(destination)):
        raise ValueError("AOM metadata source and destination must be disjoint")
    if requested.exists() or requested.is_symlink():
        raise ValueError("fresh AOM metadata destination required")
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / requested.name
    if destination.exists() or destination.is_symlink():
        raise ValueError("fresh AOM metadata destination required")
    _safe_cmake_path(destination, "AOM metadata destination")
    destination.mkdir()
    return destination


def _relative_file(root: Path, relative: str, *, create_parents: bool = False) -> Path:
    rel = PurePosixPath(relative)
    if (rel.is_absolute() or rel.as_posix() != relative or
            any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("unsafe pinned libaom archive member")
    target = root
    for part in rel.parts[:-1]:
        target = target / part
        if target.is_symlink():
            raise ValueError("libaom source member traverses a symlink")
        if not target.exists() and create_parents:
            target.mkdir()
        if target.exists() and not target.is_dir():
            raise ValueError("libaom source member parent is not a directory")
    return target / rel.parts[-1]


def _read_pinned_archive_inputs(archive_path: Path) -> tuple[dict[str, bytes], list[dict]]:
    wanted = set(_ARCHIVE_MEMBERS)
    found: dict[str, bytes] = {}
    with tarfile.open(archive_path, mode="r:gz") as archive:
        count = 0
        for member in archive:
            count += 1
            if count > 100_000:
                raise ValueError("libaom archive exceeds the member-count bound")
            prefix = "libaom-3.12.1/"
            if not member.name.startswith(prefix):
                continue
            relative = member.name[len(prefix):]
            if relative not in wanted:
                continue
            if relative in found:
                raise ValueError("duplicate pinned libaom archive member: " + relative)
            if not member.isfile() or member.size < 0 or member.size > _MEMBER_LIMIT:
                raise ValueError("unexpected type or size for pinned libaom member: " + relative)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("cannot read pinned libaom archive member: " + relative)
            raw = stream.read(_MEMBER_LIMIT + 1)
            if len(raw) != member.size or len(raw) > _MEMBER_LIMIT:
                raise ValueError("pinned libaom archive member size differs: " + relative)
            found[relative] = raw
    if set(found) != wanted:
        missing = sorted(wanted - set(found))
        raise ValueError("pinned libaom archive members are incomplete: " + ", ".join(missing))
    if _digest(found["build/cmake/pkg_config.cmake"]) != ORIGINAL_PKG_CONFIG_SHA256:
        raise ValueError("unpatched libaom metadata generator differs from its pin")
    rows = [
        {"path": name, "bytes": len(found[name]), "sha256": _digest(found[name])}
        for name in _ARCHIVE_MEMBERS[:-1]
    ]
    return found, rows


def _materialize_version_inputs(source: Path, members: dict[str, bytes]) -> list[dict]:
    for relative in _ARCHIVE_MEMBERS[:-1]:
        raw = members[relative]
        target = _relative_file(source, relative, create_parents=True)
        if target.is_symlink():
            raise ValueError("libaom source input is a symlink: " + relative)
        if target.exists():
            if not target.is_file() or target.read_bytes() != raw:
                raise ValueError("retained libaom source input differs from original archive: " + relative)
        else:
            with target.open("xb") as stream:
                stream.write(raw)
    pkg_config = _relative_file(source, "build/cmake/pkg_config.cmake")
    if pkg_config.is_symlink() or not pkg_config.is_file():
        raise ValueError("patched libaom metadata generator is missing or linked")
    if _file_digest(pkg_config) != PATCHED_PKG_CONFIG_SHA256:
        raise ValueError("patched libaom metadata generator differs from its pin")
    return [
        {"path": name, "bytes": len(members[name]), "sha256": _digest(members[name])}
        for name in _ARCHIVE_MEMBERS[:-1]
    ]


def _rewrite_prefix(original_pc: bytes) -> tuple[bytes, str]:
    if not isinstance(original_pc, bytes) or not original_pc or len(original_pc) > 1024**2:
        raise ValueError("original aom.pc must be nonempty bounded bytes")
    lines = original_pc.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.startswith(b"prefix=")]
    if len(matches) != 1:
        raise ValueError("original aom.pc must contain exactly one prefix line")
    index = matches[0]
    old_line = lines[index]
    old_value = old_line[len(b"prefix="):].rstrip(b"\r\n")
    try:
        prefix_text = os.fsdecode(old_value)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("original aom.pc prefix is not a filesystem path") from error
    if not Path(prefix_text).is_absolute() or any(char in prefix_text for char in ("\n", "\r", "\0")):
        raise ValueError("original aom.pc must expose an absolute prefix")
    ending = b"\r\n" if old_line.endswith(b"\r\n") else b"\n" if old_line.endswith(b"\n") else b""
    lines[index] = b"prefix=${pcfiledir}/../.." + ending
    rewritten = b"".join(lines)
    return rewritten, prefix_text


def _tool_paths(tools: dict[str, str | os.PathLike[str]] | None) -> dict[str, Path]:
    if tools is None:
        located = {name: shutil.which(name) for name in _TOOLS}
        missing = [name for name, path in located.items() if path is None]
        if missing:
            raise FileNotFoundError("required metadata tools not found: " + ", ".join(missing))
        candidates = {name: Path(path) for name, path in located.items() if path is not None}
    else:
        if not isinstance(tools, dict) or set(tools) != set(_TOOLS):
            raise ValueError("tools must provide exactly cmake, pkg-config, perl and git")
        candidates = {name: Path(tools[name]) for name in _TOOLS}
    resolved = {}
    for name in _TOOLS:
        path = candidates[name].resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("metadata tool is not an executable file: " + name)
        _safe_cmake_path(path, name + " path")
        resolved[name] = path
    return resolved


def _cmake_wrapper(path: Path, include: Path) -> None:
    text = (
        'set(CMAKE_SYSTEM_NAME "AROS")\n'
        "set(APPLE FALSE)\n"
        "set(WIN32 FALSE)\n"
        "include(" + _quote_cmake_path(include, "CMake include path") + ")\n"
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def _pkg_env(supervisor, pkgdir: Path):
    old = supervisor.env
    supervisor.env = {
        **old,
        "PKG_CONFIG_LIBDIR": str(pkgdir),
        "PKG_CONFIG_PATH": "",
        "PKG_CONFIG_SYSROOT_DIR": "",
    }
    return old


def _reported_prefix(output: str, expected: str | os.PathLike[str]) -> str:
    raw = output.strip()
    if not raw:
        raise ValueError("pkg-config returned an empty prefix")
    candidates = [raw]
    try:
        decoded = shlex.split(raw)
    except ValueError:
        decoded = []
    if len(decoded) == 1 and decoded[0] not in candidates:
        candidates.append(decoded[0])
    expected_path = Path(expected).resolve(strict=False)
    # Compare before returning either spelling. This keeps a literal apostrophe
    # in a real path valid while accepting pkgconf's shell-escaped spaces.
    for candidate in candidates:
        path = Path(candidate)
        if path.is_absolute() and path.resolve(strict=False) == expected_path:
            return candidate
    raise ValueError("pkg-config prefix does not resolve to the expected absolute path")


def _run_generation(source: Path, destination: Path, original_pc: bytes,
                    original_prefix: str, original_script: bytes,
                    source_inputs: list[dict], tools: dict[str, Path], supervisor) -> dict:
    label_prefix = "aommeta-" + uuid.uuid4().hex[:12]
    expected_pc, _ = _rewrite_prefix(original_pc)
    if _digest(expected_pc) != GENERATED_PC_SHA256:
        raise ValueError("prefix-only aom.pc result differs from its expected identity")
    if b"Libs.private: -lm\n" in expected_pc:
        raise ValueError("relocatable AROS aom.pc unexpectedly links a standalone libm")

    roots = []
    generated = []
    relocation = []
    for index, name in enumerate(("metadata-a", "different metadata b")):
        root = destination / name
        root.mkdir()
        _safe_cmake_path(root, "metadata root")
        config = root / "config"
        (config / "config").mkdir(parents=True)
        command = [
            str(tools["cmake"]),
            _cmake_argument("AOM_ROOT", source),
            _cmake_argument("AOM_CONFIG_DIR", config),
            _cmake_argument("GIT_EXECUTABLE", tools["git"]),
            _cmake_argument("PERL_EXECUTABLE", tools["perl"]),
            "-P", str(source / "build/cmake/version.cmake"),
        ]
        version_result = supervisor.run(command, cwd=root,
                                         label=f"{label_prefix}-version-{index}", timeout=60)
        version_header = config / "config/aom_version.h"
        if version_header.is_symlink() or not version_header.is_file():
            raise ValueError("libaom version generator did not produce aom_version.h")

        developer = root / "Developer"
        pkgdir = developer / "lib/pkgconfig"
        pkgdir.mkdir(parents=True)
        (developer / "include").mkdir()
        wrapper = root / "target-metadata.cmake"
        _cmake_wrapper(wrapper, source / "build/cmake/pkg_config.cmake")
        pkg_command = [
            str(tools["cmake"]),
            _cmake_argument("AOM_ROOT", source),
            _cmake_argument("AOM_CONFIG_DIR", config),
            _cmake_argument("CMAKE_INSTALL_PREFIX", developer),
            "-DCMAKE_INSTALL_BINDIR=bin",
            "-DCMAKE_INSTALL_INCLUDEDIR=include",
            "-DCMAKE_INSTALL_LIBDIR=lib",
            "-DCMAKE_PROJECT_NAME=AOM",
            "-DCMAKE_SYSTEM_NAME=AROS",
            "-DAPPLE=FALSE",
            "-DWIN32=FALSE",
            "-DCONFIG_MULTITHREAD=0",
            "-DCONFIG_TUNE_VMAF=0",
            "-DCONFIG_TUNE_BUTTERAUGLI=0",
            "-DCONFIG_SALIENCY_MAP=0",
            "-DCONFIG_TFLITE=0",
            "-P", str(wrapper),
        ]
        pkg_result = supervisor.run(pkg_command, cwd=root,
                                     label=f"{label_prefix}-pkgconfig-{index}", timeout=60)
        pc_path = config / "aom.pc"
        if pc_path.is_symlink() or not pc_path.is_file() or pc_path.stat().st_size > 1024**2:
            raise ValueError("libaom metadata generator did not produce a bounded aom.pc")
        raw = pc_path.read_bytes()
        if raw != expected_pc:
            raise ValueError("generated aom.pc changed outside its prefix line")
        if _digest(raw) != GENERATED_PC_SHA256:
            raise ValueError("generated aom.pc differs from its expected identity")
        generated.append(raw)
        (pkgdir / "aom.pc").write_bytes(raw)

        moved = root / "relocated Developer"
        developer.rename(moved)
        previous_env = _pkg_env(supervisor, moved / "lib/pkgconfig")
        try:
            prefix_output = supervisor.run_text(
                [str(tools["pkg-config"]), "--variable=prefix", "aom"], cwd=root,
                label=f"{label_prefix}-relocated-prefix-{index}", timeout=30,
            )
            flags_output = supervisor.run_text(
                [str(tools["pkg-config"]), "--cflags", "--libs", "aom"], cwd=root,
                label=f"{label_prefix}-relocated-flags-{index}", timeout=30,
            )
        finally:
            supervisor.env = previous_env
        prefix = _reported_prefix(prefix_output, moved)
        flag_tokens = shlex.split(flags_output)
        includes = [Path(token[2:]).resolve() for token in flag_tokens if token.startswith("-I")]
        libraries = [Path(token[2:]).resolve() for token in flag_tokens if token.startswith("-L")]
        if (Path(prefix).resolve() != moved.resolve() or len(flag_tokens) != 3
                or includes != [(moved / "include").resolve()]
                or libraries != [(moved / "lib").resolve()] or "-laom" not in flag_tokens):
            raise ValueError("pkg-config failed after relocating the Developer tree")
        relocation.append({
            "prefix_resolves_to_relocated_Developer": True,
            "flags": flags_output.strip(),
        })
        roots.append({"name": name, "version_process": version_result, "pkgconfig_process": pkg_result})

    if generated[0] != generated[1]:
        raise ValueError("aom.pc differs between two separate metadata roots")

    counter = destination / "unpatched-target-counter"
    counter.mkdir()
    counter_config = counter / "config"
    (counter_config / "config").mkdir(parents=True)
    shutil.copyfile(destination / "metadata-a/config/config/aom_version.h",
                    counter_config / "config/aom_version.h")
    counter_developer = counter_config / "Developer"
    counter_command = [
        str(tools["cmake"]),
        _cmake_argument("AOM_ROOT", source),
        _cmake_argument("AOM_CONFIG_DIR", counter_config),
        _cmake_argument("CMAKE_INSTALL_PREFIX", counter_developer),
        "-DCMAKE_INSTALL_BINDIR=bin",
        "-DCMAKE_INSTALL_INCLUDEDIR=include",
        "-DCMAKE_INSTALL_LIBDIR=lib",
        "-DCMAKE_PROJECT_NAME=AOM",
        "-DCMAKE_SYSTEM_NAME=AROS",
        "-DAPPLE=FALSE",
        "-DWIN32=FALSE",
        "-DCONFIG_MULTITHREAD=0",
        "-DCONFIG_TUNE_VMAF=0",
        "-DCONFIG_TUNE_BUTTERAUGLI=0",
        "-DCONFIG_SALIENCY_MAP=0",
        "-DCONFIG_TFLITE=0",
    ]
    counter_script = destination / "original-pkg_config.cmake"
    counter_script.write_bytes(original_script)
    counter_wrapper = destination / "original-target-metadata.cmake"
    _cmake_wrapper(counter_wrapper, counter_script)
    counter_command.extend(["-P", str(counter_wrapper)])
    supervisor.run(counter_command, cwd=counter, label=f"{label_prefix}-unpatched-target-counter", timeout=60)
    counter_pc = counter_config / "aom.pc"
    if counter_pc.is_symlink() or not counter_pc.is_file() or counter_pc.stat().st_size > 1024**2:
        raise ValueError("unpatched metadata generator counter-case produced no aom.pc")
    counter_raw = counter_pc.read_bytes()
    if b"Libs.private: -lm\n" not in counter_raw or str(counter_config).encode() not in counter_raw:
        raise ValueError("unpatched target counter-case did not expose -lm and an absolute prefix")

    original_control = destination / "original-pc-counter"
    original_pkgdir = original_control / "lib/pkgconfig"
    original_pkgdir.mkdir(parents=True)
    original_pc_path = original_pkgdir / "aom.pc"
    original_pc_path.write_bytes(original_pc)
    previous_env = _pkg_env(supervisor, original_pkgdir)
    try:
        original_prefix_output = supervisor.run_text(
            [str(tools["pkg-config"]), "--variable=prefix", "aom"], cwd=destination,
            label=f"{label_prefix}-original-prefix-counter", timeout=30,
        )
    finally:
        supervisor.env = previous_env
    observed_original_prefix = _reported_prefix(original_prefix_output, original_prefix)
    if Path(observed_original_prefix).resolve(strict=False) == original_control.resolve():
        raise ValueError("original aom.pc counter-case did not expose its embedded absolute prefix")

    return {
        "schema": "ami-rust-aom-metadata-v1",
        "status": "PASS_AOM_METADATA_ONLY",
        "source_inputs": source_inputs,
        "patched_script_sha256": _file_digest(source / "build/cmake/pkg_config.cmake"),
        "unpatched_script_sha256": _digest(original_script),
        "two_roots_byte_identical": True,
        "only_prefix_changed": True,
        "generated_pc_path": str(destination / "metadata-a/config/aom.pc"),
        "aom_pc_sha256": _digest(generated[0]),
        "relocation": relocation,
        "counter_cases": {
            "unpatched_target": {
                "status": "EXPECTED_ABSOLUTE_PREFIX_AND_NONEXISTENT_LIBM_DETECTED",
                "absolute_prefix_detected": True,
                "standalone_libm_detected": True,
            },
            "original_pc": {
                "status": "EXPECTED_ORIGINAL_ABSOLUTE_PREFIX_DETECTED",
                "absolute_prefix_detected": True,
                "embedded_prefix": original_prefix,
            },
        },
        "target_metadata_platform": {"CMAKE_SYSTEM_NAME": "AROS", "APPLE": False, "WIN32": False},
        "commands": getattr(supervisor, "commands", []),
        "roots": roots,
        "RSS_peak_observed_bytes": getattr(supervisor, "peak_rss", None),
        "workspace_peak_observed_bytes": getattr(supervisor, "peak_workspace", None),
        "baseline_changed": False,
        "full_CSDK_or_R1_accepted": False,
    }


def generate_aom_metadata(source, original_archive, original_pc: bytes, destination, supervisor,
                          *, tools=None) -> dict:
    """Generate pinned, relocatable AOM metadata and exercise its counter-cases.

    This is a metadata-only probe. Every external process is delegated to the
    caller's Supervisor, and its environment is restored even when a command
    or validation fails. The function accepts explicit tool paths for isolated
    tests; normal use resolves cmake, pkg-config, perl and git from PATH.
    """
    source_root = _source_root(source)
    archive_path = _archive_file(original_archive)
    destination_root = _destination_root(destination, source_root)
    tool_paths = _tool_paths(tools)
    for name, path in tool_paths.items():
        _safe_cmake_path(path, name + " path")
    _safe_cmake_path(source_root, "libaom source root")
    expected_pc, original_prefix = _rewrite_prefix(original_pc)
    before = {name: _file_digest(path) for name, path in tool_paths.items()}
    if not isinstance(supervisor.env, dict):
        raise ValueError("Supervisor.env must be a mapping")
    original_env = supervisor.env
    try:
        members, _ = _read_pinned_archive_inputs(archive_path)
        source_inputs = _materialize_version_inputs(source_root, members)
        result = _run_generation(source_root, destination_root, original_pc, original_prefix,
                                 members["build/cmake/pkg_config.cmake"], source_inputs,
                                 tool_paths, supervisor)
    finally:
        supervisor.env = original_env
    after = {name: _file_digest(path) for name, path in tool_paths.items()}
    changed = [name for name in _TOOLS if before[name] != after[name]]
    if changed:
        raise ValueError("metadata tool changed during generation: " + ", ".join(changed))
    result["tools"] = {
        name: {"path": str(tool_paths[name]), "sha256_before": before[name], "sha256_after": after[name]}
        for name in _TOOLS
    }
    result["aom_pc_sha256"] = _digest(expected_pc)
    return result

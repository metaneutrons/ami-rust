#!/usr/bin/env python3
"""Coordinate protected preparation and verification of the native outer release.

Rust xtask owns outer-asset and package composition and performs the real
publisher verification. This module only binds the protected workflow inputs,
records supervised work, and stages the exact native package inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "release"))
import ci_native
import ci_verify

auth = ci_native.auth
ci_sdk = ci_native.ci_sdk
LINUX = "linux-x86_64"
MACOS = "macos-aarch64"
HOSTS = (LINUX, MACOS)
STATE_NAME = "native-outer-state.json"
POLICY_NAME = "native-publisher-policy.json"
MAX_ASSET_BYTES = 128 * 1024**2
MAX_TREE_BYTES = 512 * 1024**2
MAX_TREE_ENTRIES = 16_384
MAX_PROOF_BYTES = 16 * 1024**2
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_RUNTIME_STATE_KEYS = {
    "manifest", "manifest_raw", "launchers", "tool_receipt", "cli", "xtask",
    "policy_path", "verifier_work", "verifier_output", "python_bootstrap",
    "supervisor", "auxiliary_commands", "auxiliary_insert_at",
}


def _asset_names(sdk_version: str) -> dict[str, str]:
    archive = f"ami-rust-{sdk_version}-release.tar.xz"
    transport = f"ami-rust-{sdk_version}-transport.json"
    return {
        "payload": archive,
        "sbom": archive + ".spdx.json",
        "transport": transport,
        "payload_signature": archive + ".sigstore.json",
        "transport_signature": transport + ".sigstore.json",
        "checksums": "SHA256SUMS",
    }


def _proof_subjects(sdk_version: str) -> tuple[str, ...]:
    names = _asset_names(sdk_version)
    return (names["checksums"], names["payload"], names["sbom"], names["transport"])


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _regular_file(path: Path, cap: int) -> bytes:
    path = Path(path).absolute()
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("required regular file is missing: " + path.name) from error
    if (path.is_symlink() or path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode)
            or info.st_size > cap):
        raise ValueError("input must be a bounded regular file without linked path components: " + path.name)
    raw = path.read_bytes()
    if len(raw) != info.st_size:
        raise ValueError("input changed while being read: " + path.name)
    return raw


def _directory(path: Path, label: str) -> Path:
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError(label + " must be a real directory without linked path components")
    return path


def _fresh_path(path: Path, label: str) -> Path:
    path = Path(path).absolute()
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.resolve() != path.parent:
        raise ValueError(label + " must be a fresh path under an existing real parent")
    if path == ROOT or ROOT in path.parents:
        raise ValueError(label + " must remain outside the source checkout")
    return path


def _tree_files(root: Path, *, maximum: int = MAX_TREE_BYTES) -> dict[str, bytes]:
    root = _directory(root, "tree root")
    pending = [(root, "")]
    files: dict[str, bytes] = {}
    total = 0
    entries = 0
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_TREE_ENTRIES:
                    raise ValueError("input tree exceeds its entry limit")
                name = entry.name if not prefix else prefix + "/" + entry.name
                auth.rel(name)
                info = entry.stat(follow_symlinks=False)
                path = Path(entry.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append((path, name))
                elif stat.S_ISREG(info.st_mode):
                    if info.st_size > MAX_ASSET_BYTES:
                        raise ValueError("input tree file exceeds its member limit: " + name)
                    raw = _regular_file(path, MAX_ASSET_BYTES)
                    total += len(raw)
                    if total > maximum:
                        raise ValueError("input tree exceeds its byte limit")
                    files[name] = raw
                else:
                    raise ValueError("input tree contains a symlink or special file: " + name)
    return files


def _tree_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name, raw in sorted(files.items()):
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha(raw)))
    return digest.hexdigest()


def _candidate_rows(candidate: Path, expected: set[str]) -> list[dict]:
    files = _tree_files(candidate, maximum=MAX_TREE_BYTES)
    if set(files) != expected:
        missing = sorted(expected - set(files))
        extra = sorted(set(files) - expected)
        raise ValueError(f"outer candidate inventory mismatch (missing={missing}, extra={extra})")
    rows = [{"path": name, "bytes": len(raw), "sha256": _sha(raw)}
            for name, raw in sorted(files.items())]
    if any(row["bytes"] > MAX_ASSET_BYTES for row in rows):
        raise ValueError("outer candidate asset exceeds its native package limit")
    if sum(row["bytes"] for row in rows) > 256 * 1024**2:
        raise ValueError("outer candidate assets exceed their native package total limit")
    return rows


def _parse_json(raw: bytes, label: str) -> dict:
    try:
        value = auth.parsed(raw)
    except (UnicodeError, ValueError, TypeError) as error:
        raise ValueError(label + " is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(label + " must be a JSON object")
    return value


def _check_context() -> dict:
    identity = auth.context(ROOT)
    if ci_native.current_host() != LINUX:
        raise ValueError("native outer coordination requires the protected Linux x86-64 host")
    if (not isinstance(identity, dict)
            or not isinstance(identity.get("source_sha"), str)
            or not HEX40.fullmatch(identity["source_sha"])
            or not isinstance(identity.get("workflow_sha"), str)
            or not HEX40.fullmatch(identity["workflow_sha"])
            or type(identity.get("run_id")) is not int or identity["run_id"] <= 0
            or type(identity.get("run_attempt")) is not int or identity["run_attempt"] <= 0):
        raise ValueError("protected workflow identity is incomplete")
    return identity


def _source_env(env: dict[str, str]) -> dict[str, str]:
    env = dict(env)
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    return ci_native._clean_child_env(env)


def _source_identity(supervisor, identity: dict, phase: str) -> tuple[str, str]:
    head = ci_native._supervised_text(
        supervisor, ["/usr/bin/git", "-C", ROOT, "rev-parse", "HEAD"],
        label=f"native-outer-{phase}-source-head", timeout=30).strip()
    tree = ci_native._supervised_text(
        supervisor, ["/usr/bin/git", "-C", ROOT, "rev-parse", "HEAD^{tree}"],
        label=f"native-outer-{phase}-source-tree", timeout=30).strip()
    status = ci_native._supervised_text(
        supervisor, ["/usr/bin/git", "-C", ROOT, "status", "--porcelain=v1", "--untracked-files=all"],
        label=f"native-outer-{phase}-source-status", timeout=30)
    if (head != identity["source_sha"] or not HEX40.fullmatch(tree) or status.strip()):
        raise ValueError("supervised source identity is not the protected clean checkout")
    return head, tree


def _native_policy(identity: dict, tools: dict, config: dict) -> dict:
    manifest = auth.input_manifest_for_sdk(ROOT, config["sdk_version"])
    policy = {
        "schema": "ami-rust-publisher-trust-v2",
        "repository": auth.REPO,
        "workflow": auth.WORKFLOW,
        "workflow_sha": identity["workflow_sha"],
        "source_sha": identity["source_sha"],
        "source_ref": "refs/heads/main",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "cert_identity": f"https://github.com/{auth.REPO}/{auth.WORKFLOW}@refs/heads/main",
        "inputs_manifest_sha256": auth.sha(auth.encoded(manifest)),
        "allowed_host_profiles": list(auth.HOSTS),
        "gh": {"path": tools["tools"]["gh"]["path"],
               "sha256": tools["tools"]["gh"]["sha256"]},
        "cosign": {"path": tools["tools"]["cosign"]["path"],
                   "sha256": tools["tools"]["cosign"]["sha256"]},
        "gh_trusted_roots": {"path": tools["roots"]["gh"]["path"],
                              "sha256": tools["roots"]["gh"]["sha256"]},
        "cosign_trusted_root": {"path": tools["roots"]["cosign"]["path"],
                                "sha256": tools["roots"]["cosign"]["sha256"]},
    }
    return policy


def _validate_tool_bootstrap(verifier_work: Path, verifier_output: Path,
                             identity: dict) -> dict:
    manifest_path = ROOT / "release/ci-auth-tools.json"
    manifest_raw = _regular_file(manifest_path, 1024 * 1024)
    manifest = ci_verify.strict_json(manifest_path, 1024 * 1024)
    pins = ci_verify.validate_tool_manifest(manifest, LINUX)
    receipt_path = verifier_output / "tool-bootstrap.json"
    receipt_raw = _regular_file(receipt_path, 256 * 1024)
    receipt = ci_verify.strict_json(receipt_path, 256 * 1024)
    expected_budgets = {"workspace_bytes": ci_sdk.MAX_WORK_BYTES,
                        "rss_bytes": ci_sdk.MAX_RSS_BYTES,
                        "log_bytes": ci_sdk.MAX_LOG_BYTES,
                        "command_seconds": ci_sdk.MAX_COMMAND_SECONDS}
    if (receipt.get("schema") != ci_verify.TOOL_RECEIPT_SCHEMA
            or receipt.get("status") != "PINNED_VERIFIER_TOOLS_READY"
            or receipt.get("host") != LINUX
            or receipt.get("source_commit") != identity["source_sha"]
            or receipt.get("tools_manifest_sha256") != _sha(manifest_raw)
            or receipt.get("budgets") != expected_budgets
            or not isinstance(receipt.get("commands"), list)):
        raise ValueError("pinned verifier bootstrap receipt differs from the protected source")
    for name in ("gh", "cosign"):
        tool_path = verifier_work / "tools" / name
        row = receipt.get("tools", {}).get(name)
        expected_tool = {"path": str(tool_path), "bytes": pins[name]["binary_bytes"],
                         "sha256": pins[name]["binary_sha256"], "version": pins[name]["version"],
                         "archive_sha256": pins[name]["sha256"], "archive_bytes": pins[name]["bytes"]}
        if (row != expected_tool
                or row.get("bytes") != pins[name]["binary_bytes"]
                or row.get("sha256") != pins[name]["binary_sha256"]
                or tool_path.is_symlink() or not tool_path.is_file()
                or not os.access(tool_path, os.X_OK)
                or tool_path.stat().st_size != pins[name]["binary_bytes"]
                or ci_verify.sha256(tool_path) != pins[name]["binary_sha256"]):
            raise ValueError("pinned verifier executable changed: " + name)
    for name in ("gh", "cosign"):
        pin = pins["roots"][name]
        expected_path = verifier_work / "trust" / Path(pin["path"]).name
        row = receipt.get("roots", {}).get(name)
        expected_root = {"path": str(expected_path), "bytes": pin["bytes"], "sha256": pin["sha256"]}
        if (row != expected_root
                or expected_path.is_symlink() or not expected_path.is_file()
                or expected_path.stat().st_size != pin["bytes"]
                or ci_verify.sha256(expected_path) != pin["sha256"]):
            raise ValueError("pinned verifier trust root changed: " + name)
    if receipt.get("claim") != (
            "Hash-pinned verifier tools and roots are ready; no SDK candidate or publisher evidence has been verified."):
        raise ValueError("pinned verifier bootstrap claim differs from the expected receipt")
    receipt["_receipt_sha256"] = _sha(receipt_raw)
    return receipt


def _rust_paths(host_rust: Path) -> tuple[Path, Path, Path, Path]:
    toolchain = host_rust / "toolchain"
    bindir = toolchain / "bin"
    rustc, cargo, rustdoc = bindir / "rustc", bindir / "cargo", bindir / "rustdoc"
    for name, path in (("rustc", rustc), ("cargo", cargo), ("rustdoc", rustdoc)):
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("pinned host Rust executable is missing or linked: " + name)
    return toolchain, rustc, cargo, rustdoc


def _hash_file(path: Path, cap: int = MAX_ASSET_BYTES) -> dict:
    path = Path(path).absolute()
    if (path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path
            or not os.access(path, os.X_OK)):
        raise ValueError("tool identity must be a regular unlinked file: " + path.name)
    size = path.stat().st_size
    if size <= 0 or size > cap:
        raise ValueError("tool identity file has an invalid size: " + path.name)
    return {"path": str(path), "bytes": size, "sha256": ci_verify.sha256(path)}


def _check_local_linux_launcher(cli: Path, launchers: dict[str, bytes]) -> None:
    if _regular_file(cli, MAX_ASSET_BYTES) != launchers.get(LINUX):
        raise ValueError("native outer local CLI differs byte-for-byte from the inner Linux launcher")


def _supervisor_env(work: Path, host_rust: Path) -> dict[str, str]:
    toolchain, rustc, cargo, rustdoc = _rust_paths(host_rust)
    env = {"PATH": str(rustc.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
           "HOME": str(work / "home"), "TMPDIR": str(work / "tmp"), "LC_ALL": "C",
           "CARGO_BUILD_JOBS": "2", "CARGO_HOME": str(work / "cargo-home"),
           "CLI_CARGO": str(cargo), "RUSTC": str(rustc), "RUSTDOC": str(rustdoc),
           "CARGO_ENCODED_RUSTFLAGS": "\x1f".join([
               f"--remap-path-prefix={ROOT}=/ami-rust",
               f"--remap-path-prefix={work / 'cargo-home'}=/cargo"])}
    if ci_native.current_host() == "macos-aarch64":
        env["DYLD_LIBRARY_PATH"] = str(toolchain / "lib")
    return _source_env(env)


def _private_root(path: Path, label: str) -> Path:
    path = _directory(path, label)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(label + " must be a private directory owned by the current user")
    return path


def _bundle_identity(bundle: Path, identity: dict, config: dict) -> tuple[dict, bytes, dict[str, bytes], str]:
    files = _tree_files(bundle)
    manifest_raw = files.get("release.json")
    inputs_raw = files.get(".auth/inputs.json")
    if manifest_raw is None or inputs_raw is None:
        raise ValueError("native inner candidate is missing its manifest or inputs")
    manifest = _parse_json(manifest_raw, "native inner release manifest")
    if (manifest.get("schema") != "ami-rust-release-v2"
            or manifest.get("qualification_only") is not False
            or manifest.get("version") != config["sdk_version"]):
        raise ValueError("inner bundle is not the configured production native release")
    producer = manifest.get("producer")
    expected_producer = {"kind": "protected-github-actions", "repository": auth.REPO,
                         "workflow": auth.WORKFLOW, "source_sha": identity["source_sha"],
                         "workflow_sha": identity["workflow_sha"], "run_id": identity["run_id"],
                         "run_attempt": identity["run_attempt"],
                         "acceptance": "R1 acceptance and publication are separate gates"}
    if producer != expected_producer:
        raise ValueError("inner release producer identity differs from this protected run")
    expected_inputs = auth.encoded(auth.input_manifest_for_sdk(ROOT, config["sdk_version"]))
    if inputs_raw != expected_inputs:
        raise ValueError("inner publisher inputs differ from the exact native source manifest")
    rows = manifest.get("assets")
    if not isinstance(rows, list):
        raise ValueError("native release manifest asset inventory is missing")
    assets = {}
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}
                or not isinstance(row["path"], str) or type(row["bytes"]) is not int
                or row["bytes"] < 0 or not isinstance(row["sha256"], str)
                or not HEX64.fullmatch(row["sha256"])
                or row["path"] in assets):
            raise ValueError("native release asset inventory is malformed")
        assets[row["path"]] = row
        raw = files.get(row["path"])
        if raw is None or len(raw) != row["bytes"] or _sha(raw) != row["sha256"]:
            raise ValueError("native release asset differs from its manifest pin: " + row["path"])
    host_rows = manifest.get("host_launchers")
    if not isinstance(host_rows, dict) or set(host_rows) != set(HOSTS):
        raise ValueError("native release manifest must pin both host launchers")
    launcher_bytes = {}
    launcher_rows = {}
    for host in HOSTS:
        row = host_rows[host]
        if (not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}
                or not isinstance(row.get("path"), str) or type(row.get("bytes")) is not int
                or row["bytes"] <= 0 or not isinstance(row.get("sha256"), str)
                or not HEX64.fullmatch(row["sha256"])):
            raise ValueError("native host launcher record is malformed: " + host)
        path = auth.rel(row["path"])
        raw = files.get(path)
        asset = assets.get(path)
        if (raw is None or asset is None or len(raw) != row["bytes"] or _sha(raw) != row["sha256"]
                or asset["bytes"] != row["bytes"] or asset["sha256"] != row["sha256"]):
            raise ValueError("native host launcher differs from its declared asset bytes: " + host)
        launcher_bytes[host] = raw
        launcher_rows[host] = {"path": path, "bytes": len(raw), "sha256": _sha(raw)}
    return manifest, manifest_raw, launcher_bytes, _tree_digest(files)


def _protected_package_maintainer() -> str:
    raw = _regular_file(ROOT / "packaging/pins.json", 2 * 1024 * 1024)
    pins = _parse_json(raw, "maintainer source")
    maintainer = pins.get("maintainer")
    if (not isinstance(maintainer, str) or not maintainer or maintainer.strip() != maintainer
            or any(character in maintainer for character in "\r\n\0")):
        raise ValueError("packaging pins do not contain a valid maintainer identity")
    return maintainer


def _package_inputs(identity: dict, source_tree: str, manifest_raw: bytes, manifest: dict,
                    config: dict, rows: list[dict], proof_rows: dict,
                    launcher_rows: dict, host: str, maintainer: str) -> dict:
    names = _asset_names(config["sdk_version"])
    asset_map = {row["path"]: row for row in rows}
    if set(asset_map) != set(names.values()):
        raise ValueError("native package requires the exact six finalized outer assets")
    launcher = launcher_rows[host]
    publisher_proofs = {
        subject: [{"bytes": proof_rows[subject]["bytes"], "sha256": proof_rows[subject]["sha256"]}]
        for subject in _proof_subjects(config["sdk_version"])
    }
    version = config["sdk_version"]
    revision = 1
    return {
        "schema": "ami-rust-package-inputs-v2",
        "cli_version": config["cli_version"],
        "sdk_version": version,
        "packaging_revision": revision,
        "package_version": f"{version}-{revision}",
        "packaging_tag": f"v{version}+packaging.{revision}",
        "sdk_tag": f"v{version}",
        "repository": auth.REPO,
        "source_commit": identity["source_sha"],
        "source_tree": source_tree,
        "sdk_run_id": identity["run_id"],
        "sdk_run_attempt": identity["run_attempt"],
        "manifest_sha256": _sha(manifest_raw),
        "transport_sha256": asset_map[names["transport"]]["sha256"],
        "assets": rows,
        "hosts": {"apt": LINUX, "homebrew": MACOS},
        "maintainer": maintainer,
        "publisher_proofs": publisher_proofs,
        "host": host,
        "launchers": {
            "ami-rust": {"path": "bin/ami-rust", "bytes": launcher["bytes"],
                         "sha256": launcher["sha256"]},
            "cargo-ami": {"path": "bin/cargo-ami", "bytes": launcher["bytes"],
                          "sha256": launcher["sha256"]},
        },
        "core_sha256": launcher["sha256"],
    }


def _proof_mapping(values: list[str], sdk_version: str) -> dict[str, Path]:
    expected = set(_proof_subjects(sdk_version))
    result = {}
    for value in values:
        if not isinstance(value, str) or "=" not in value:
            raise ValueError("each --gh value must be SUBJECT=PATH")
        subject, raw_path = value.split("=", 1)
        if not subject or not raw_path or subject not in expected or subject in result:
            raise ValueError("GitHub proofs must name each exact outer subject once")
        result[subject] = Path(raw_path)
    if set(result) != expected:
        raise ValueError("verify requires exactly four GitHub provenance proofs")
    return result


def _proof_filename(subject: str) -> str:
    auth.rel(subject)
    if "/" in subject:
        raise ValueError("outer proof subject must be a flat asset name")
    return subject + ".json"


def _write_outputs(values: dict[str, str]) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    path = Path(destination).absolute()
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("GITHUB_OUTPUT must be an existing absolute regular file")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("GITHUB_OUTPUT must be an existing regular file")
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or any(c in value for c in "\r\n"):
                raise ValueError("invalid GitHub output field")
            stream.write(key + "=" + value + "\n")


def _github_values(rows: list[dict], sdk_version: str, checksums_sha256: str | None = None) -> dict[str, str]:
    names = _asset_names(sdk_version)
    digests = {row["path"]: row["sha256"] for row in rows}
    values = {"tag": "v" + sdk_version}
    for key in ("payload", "sbom", "transport", "payload_signature", "transport_signature", "checksums"):
        values[key + "_name"] = names[key]
        if key in ("payload", "sbom", "transport") and names[key] in digests:
            values[key + "_sha256"] = digests[names[key]]
    if checksums_sha256 is not None:
        values["checksums_sha256"] = checksums_sha256
    return values


def _state_file(work: Path) -> Path:
    return work / STATE_NAME


def _save_state(work: Path, state: dict) -> None:
    path = _state_file(work)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("native outer state temporary path is not fresh")
    raw = auth.encoded({key: value for key, value in state.items()
                        if key not in _RUNTIME_STATE_KEYS})
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _load_state(work: Path) -> dict:
    raw = _regular_file(_state_file(work), 4 * 1024 * 1024)
    state = _parse_json(raw, "native outer resume receipt")
    if state.get("schema") != "ami-rust-native-outer-state-v1":
        raise ValueError("native outer resume receipt has an unsupported schema")
    return state


def _history(supervisor, auxiliary_commands: list[dict], insertion_index: int) -> dict:
    return {
        "main_commands": list(supervisor.commands),
        "auxiliary_commands": list(auxiliary_commands),
        "auxiliary_insert_at": insertion_index,
        "peak_rss_observed_bytes": supervisor.peak_rss,
        "peak_workspace_observed_bytes": supervisor.peak_workspace,
        "peak_log_observed_bytes": supervisor.native_peak_logs,
    }


def _restore_history(supervisor, history: dict) -> tuple[list[dict], int]:
    commands = history.get("main_commands")
    auxiliary = history.get("auxiliary_commands")
    insert_at = history.get("auxiliary_insert_at")
    if (not isinstance(commands, list) or not isinstance(auxiliary, list)
            or type(insert_at) is not int or not 0 <= insert_at <= len(commands)):
        raise ValueError("native outer supervised command history is malformed")
    supervisor.commands = list(commands)
    supervisor.peak_rss = max(supervisor.peak_rss, history.get("peak_rss_observed_bytes", 0))
    supervisor.peak_workspace = max(supervisor.peak_workspace,
                                    history.get("peak_workspace_observed_bytes", 0))
    supervisor.native_peak_logs = max(supervisor.native_peak_logs,
                                      history.get("peak_log_observed_bytes", 0))
    return list(auxiliary), insert_at


def _summary(supervisor, state: dict) -> dict:
    history = state["supervision_state"]
    return ci_native._supervision_summary(supervisor, history["auxiliary_commands"],
                                          history["auxiliary_insert_at"])


def _paths(args) -> dict[str, Path]:
    return {"bundle": _directory(args.bundle, "inner bundle"),
            "work": _private_root(args.work, "native outer work"),
            "output": _private_root(args.output, "native outer output"),
            "host_rust": _directory(args.host_rust, "pinned host Rust root"),
            "python_root": _directory(args.python_bootstrap_root, "pinned Python bootstrap root")}


def _assert_disjoint(paths: dict[str, Path], verifier_work: Path | None = None,
                     verifier_output: Path | None = None) -> None:
    roots = [(key, path.resolve(strict=True)) for key, path in paths.items()]
    if verifier_work is not None:
        roots.extend([("verifier_work", _directory(verifier_work, "verifier work").resolve(strict=True)),
                      ("verifier_output", _directory(verifier_output, "verifier metadata").resolve(strict=True))])
    for index, (name, left) in enumerate(roots):
        for other_name, right in roots[index + 1:]:
            if ci_native._overlap(left, right):
                raise ValueError(f"native outer roots overlap: {name} and {other_name}")


def _verifier_siblings(work: Path) -> tuple[Path, Path]:
    return work.parent / "ami-rust-release-work", work.parent / "ami-rust-release-bootstrap"


def _expected_policy_path(work: Path) -> Path:
    return work / POLICY_NAME


def _tool_paths(work: Path) -> tuple[Path, Path]:
    target = work / "target" / "release"
    return target / "ami-rust", target / "ami-rust-xtask"


def _check_tool_bytes(work: Path, state: dict) -> tuple[Path, Path]:
    cli, xtask = _tool_paths(work)
    for label, path, field in (("native CLI", cli, "cli"), ("native xtask", xtask, "xtask")):
        row = state["tool_hashes"].get(field)
        actual = _hash_file(path, MAX_ASSET_BYTES)
        if not isinstance(row, dict) or actual != row:
            raise ValueError(label + " bytes changed since outer preparation")
    return cli, xtask


def _resume(paths: dict[str, Path], identity: dict, config: dict, *, phase: str):
    work, output = paths["work"], paths["output"]
    state = _load_state(work)
    expected_paths = {key: str(value) for key, value in paths.items()}
    if state.get("paths") != expected_paths or state.get("identity") != identity:
        raise ValueError("native outer resume roots or protected run identity changed")
    if state.get("native_inputs_sha256") != _sha(_regular_file(ROOT / "release/native-tooling-inputs.json", 1024 * 1024)):
        raise ValueError("native tooling input configuration changed since preparation")
    if state.get("sdk_version") != config["sdk_version"] or state.get("cli_version") != config["cli_version"]:
        raise ValueError("native release versions changed since preparation")
    if state.get("phase") not in ({"prepared"} if phase == "finalize" else {"finalized"}):
        raise ValueError("native outer command is out of sequence")
    verifier_work, verifier_output = _verifier_siblings(work)
    verifier_work = _private_root(verifier_work, "pinned verifier work")
    verifier_output = _private_root(verifier_output, "pinned verifier metadata")
    _assert_disjoint(paths, verifier_work, verifier_output)
    if state.get("verifier_paths") != {"work": str(verifier_work), "output": str(verifier_output)}:
        raise ValueError("pinned verifier roots changed since preparation")
    manifest, manifest_raw, launchers, bundle_digest = _bundle_identity(paths["bundle"], identity, config)
    if (bundle_digest != state.get("bundle_tree_sha256")
            or _sha(manifest_raw) != state.get("inner_manifest_sha256")):
        raise ValueError("inner bundle bytes changed since outer preparation")
    tool_receipt = _validate_tool_bootstrap(verifier_work, verifier_output, identity)
    if tool_receipt.get("_receipt_sha256") != state.get("verifier_receipt_sha256"):
        raise ValueError("pinned verifier receipt changed since outer preparation")
    policy = _native_policy(identity, tool_receipt, config)
    policy_raw = auth.encoded(policy)
    policy_path = _expected_policy_path(work)
    if (_regular_file(policy_path, 2 * 1024 * 1024) != policy_raw
            or _sha(policy_raw) != state.get("policy_sha256")):
        raise ValueError("source-derived native publisher policy changed")
    cli, xtask = _check_tool_bytes(work, state)
    _toolchain, rustc, cargo, rustdoc = _rust_paths(paths["host_rust"])
    rust_hashes = {name: _hash_file(path) for name, path in
                   (("rustc", rustc), ("cargo", cargo), ("rustdoc", rustdoc))}
    if rust_hashes != state.get("host_rust_tools"):
        raise ValueError("pinned host Rust executable bytes changed since preparation")
    python_bootstrap = ci_sdk.verify_python_bootstrap(paths["python_root"], LINUX)[1]
    if (python_bootstrap != state.get("python_bootstrap_receipt")
            or tool_receipt.get("python_bootstrap") != python_bootstrap):
        raise ValueError("pinned Python bootstrap receipt changed since preparation")
    native_static = [("host-rust", paths["host_rust"]), ("inner-bundle", paths["bundle"]),
                     ("verifier-work", verifier_work), ("verifier-metadata", verifier_output)]
    supervisor = ci_native._make_supervisor(work, output, paths["python_root"],
                                            _supervisor_env(work, paths["host_rust"]),
                                            static_roots=native_static)
    auxiliary, insertion_index = _restore_history(supervisor, state["supervision_state"])
    state["manifest"] = manifest
    state["manifest_raw"] = manifest_raw
    state["launchers"] = launchers
    state["tool_receipt"] = tool_receipt
    state["cli"] = cli
    state["xtask"] = xtask
    state["policy_path"] = policy_path
    state["verifier_work"] = verifier_work
    state["verifier_output"] = verifier_output
    state["python_bootstrap"] = python_bootstrap
    state["supervisor"] = supervisor
    state["auxiliary_commands"] = auxiliary
    state["auxiliary_insert_at"] = insertion_index
    return state


def _git_source_check(supervisor, identity: dict, expected_tree: str, phase: str) -> None:
    head, tree = _source_identity(supervisor, identity, phase)
    if head != identity["source_sha"] or tree != expected_tree:
        raise ValueError("source checkout tree changed since native outer preparation")


def _candidate_paths(output: Path) -> tuple[Path, Path]:
    candidate = output / "candidate"
    metadata = output / "metadata"
    return candidate, metadata


def _copy_notice_tree(work: Path) -> Path:
    destination = work / "native-notices"
    if destination.exists() or destination.is_symlink():
        raise ValueError("native notice staging directory must be fresh")
    destination.mkdir(mode=0o700)
    licenses = destination / "licenses"
    licenses.mkdir(mode=0o700)
    for source, name in ((ROOT / "LICENSE-MIT", "LICENSE-MIT"),
                         (ROOT / "LICENSE-APACHE", "LICENSE-APACHE"),
                         (ROOT / "tooling/third-party/THIRD-PARTY-NOTICES.md", "THIRD-PARTY-NOTICES.md")):
        ci_native.write(destination / name, _regular_file(source, 2 * 1024 * 1024))
    source_licenses = _directory(ROOT / "tooling/third-party/licenses", "third-party license directory")
    license_files = _tree_files(source_licenses, maximum=MAX_TREE_BYTES)
    if not license_files:
        raise ValueError("native package requires reviewed third-party license texts")
    for relative, raw in sorted(license_files.items()):
        if "/" in relative:
            raise ValueError("reviewed third-party licenses must be flat files")
        ci_native.write(licenses / relative, raw)
    return destination


def _expected_checksums(rows: list[dict]) -> bytes:
    checksummed = [row for row in rows if row["path"] != "SHA256SUMS"]
    return "".join(f"{row['sha256']}  {row['path']}\n" for row in checksummed).encode("ascii")


def prepare(bundle: Path, work: Path, output: Path, host_rust: Path,
            python_bootstrap_root: Path) -> dict:
    identity = _check_context()
    config = ci_native.native_inputs()
    paths = {"bundle": _directory(bundle, "inner bundle"),
             "work": _fresh_path(work, "native outer work"),
             "output": _fresh_path(output, "native outer output"),
             "host_rust": _directory(host_rust, "pinned host Rust root"),
             "python_root": _directory(python_bootstrap_root, "pinned Python bootstrap root")}
    verifier_work, verifier_output = _verifier_siblings(paths["work"])
    _fresh_path(verifier_work, "pinned verifier work")
    _fresh_path(verifier_output, "pinned verifier metadata")
    planned = [(key, value.resolve(strict=False)) for key, value in paths.items()]
    planned.extend([("verifier_work", verifier_work.resolve(strict=False)),
                    ("verifier_output", verifier_output.resolve(strict=False))])
    for index, (name, path) in enumerate(planned):
        if path == ROOT or ROOT in path.parents:
            raise ValueError(name + " must remain outside the source checkout")
        for other_name, other in planned[index + 1:]:
            if ci_native._overlap(path, other):
                raise ValueError(f"native outer roots overlap: {name} and {other_name}")
    manifest, manifest_raw, launchers, bundle_digest = _bundle_identity(paths["bundle"], identity, config)

    work = ci_native.fresh(paths["work"])
    output = ci_native.fresh(paths["output"])
    paths["work"], paths["output"] = work, output
    cli, xtask, _env, supervisor = ci_native.build_tools(
        work, paths["host_rust"], output, paths["python_root"],
        static_roots=[("inner-bundle", paths["bundle"])])
    _check_local_linux_launcher(cli, launchers)
    supervisor.env = _source_env(supervisor.env)
    head, source_tree = _source_identity(supervisor, identity, "prepare")
    rustc_identity = ci_native._supervised_text(
        supervisor, [paths["host_rust"] / "toolchain/bin/rustc", "-Vv"],
        label="native-outer-prepare-rustc-identity", timeout=30)
    if ("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" not in rustc_identity
            or "host: " + ci_native.HOST_TRIPLES[LINUX] not in rustc_identity):
        raise ValueError("pinned host compiler identity changed during native outer preparation")

    verifier_work.mkdir(mode=0o700)
    verifier_output.mkdir(mode=0o700)
    live_roots = (work, output, paths["host_rust"], paths["bundle"])
    samples = [ci_sdk.directory_accounting(path) for path in live_roots]
    additional_bytes = sum(size for size, _logs in samples)
    additional_logs = sum(logs for _size, logs in samples)
    if additional_bytes > ci_sdk.MAX_WORK_BYTES or additional_logs > ci_sdk.MAX_LOG_BYTES:
        raise RuntimeError("live native outer roots exceed verifier bootstrap resource limits")
    bootstrap_insert_at = len(supervisor.commands)
    tool_receipt = ci_verify.bootstrap_tools(
        verifier_work, verifier_output, paths["python_root"],
        source_commit=identity["source_sha"], additional_input_bytes=additional_bytes,
        additional_log_bytes=additional_logs)
    ci_native._add_static_roots(supervisor, [("verifier-work", verifier_work),
                                             ("verifier-metadata", verifier_output)])
    ci_native._check_limits(supervisor, "native outer pinned verifier bootstrap")
    tool_receipt = _validate_tool_bootstrap(verifier_work, verifier_output, identity)
    policy = _native_policy(identity, tool_receipt, config)
    policy_raw = auth.encoded(policy)
    policy_path = _expected_policy_path(work)
    ci_native.write(policy_path, policy_raw, 0o600)

    candidate, metadata = _candidate_paths(output)
    metadata.mkdir(mode=0o700)
    outer_raw = ci_native._supervised_text(
        supervisor, [xtask, "native-outer", "--bundle", paths["bundle"], "--policy", policy_path,
                     "--output", candidate], label="native-outer-prepare", timeout=1200)
    outer_result = _parse_json(outer_raw.encode(), "native outer preparation result")
    if (outer_result.get("schema") != "ami-rust-native-outer-draft-v1"
            or outer_result.get("status") != "INNER_AUTHENTICATED_OUTER_UNSIGNED"
            or outer_result.get("sdk_version") != config["sdk_version"]):
        raise ValueError("Rust native outer preparation returned an unexpected result")
    names = _asset_names(config["sdk_version"])
    initial_rows = _candidate_rows(candidate, {names["payload"], names["sbom"], names["transport"]})
    predicate_raw = auth.encoded(auth.predicate(paths["bundle"], LINUX, ROOT))
    if not predicate_raw or len(predicate_raw) > 2 * 1024 * 1024:
        raise ValueError("native outer predicate exceeds its bounded metadata profile")
    ci_native.write(metadata / "outer-predicate.json", predicate_raw, 0o600)
    prepared = {
        "schema": "ami-rust-native-outer-prepared-v1",
        "status": "OUTER_CANDIDATE_PREPARED_SIGNING_REQUIRED_NOT_R1_ACCEPTED",
        "source_commit": identity["source_sha"], "workflow_commit": identity["workflow_sha"],
        "run_id": identity["run_id"], "run_attempt": identity["run_attempt"],
        "host_profile": LINUX, "inner_manifest_sha256": _sha(manifest_raw),
        "tag": "v" + config["sdk_version"], "predicate_sha256": _sha(predicate_raw),
        "candidate": {"tag": "v" + config["sdk_version"], "assets": initial_rows},
        "native_outer_result": outer_result,
        "r1_accepted": False, "publication_authorized": False,
    }
    ci_native.write(metadata / "outer-prepared.json", auth.encoded(prepared), 0o600)
    rustc, cargo, rustdoc = _rust_paths(paths["host_rust"])[1:]
    tool_hashes = {"cli": _hash_file(cli), "xtask": _hash_file(xtask)}
    rust_hashes = {name: _hash_file(path) for name, path in
                   (("rustc", rustc), ("cargo", cargo), ("rustdoc", rustdoc))}
    python_receipt = ci_sdk.verify_python_bootstrap(paths["python_root"], LINUX)[1]
    native_inputs_sha = _sha(_regular_file(ROOT / "release/native-tooling-inputs.json", 1024 * 1024))
    state = {
        "schema": "ami-rust-native-outer-state-v1", "phase": "prepared",
        "identity": identity, "paths": {key: str(value) for key, value in paths.items()},
        "verifier_paths": {"work": str(verifier_work), "output": str(verifier_output)},
        "sdk_version": config["sdk_version"], "cli_version": config["cli_version"],
        "native_inputs_sha256": native_inputs_sha,
        "source_tree": source_tree, "inner_manifest_sha256": _sha(manifest_raw),
        "bundle_tree_sha256": bundle_digest,
        "verifier_receipt_sha256": tool_receipt["_receipt_sha256"],
        "policy_sha256": _sha(policy_raw),
        "tool_hashes": tool_hashes, "host_rust_tools": rust_hashes,
        "rustc_identity_sha256": _sha(rustc_identity.encode()),
        "python_bootstrap_receipt": python_receipt,
        "initial_assets": initial_rows,
        "supervision_state": _history(supervisor, tool_receipt["commands"], bootstrap_insert_at),
    }
    state["supervision"] = _summary(supervisor, state)
    ci_native._check_limits(supervisor, "native outer prepared evidence")
    _save_state(work, state)
    state["supervision_state"] = _history(supervisor, tool_receipt["commands"], bootstrap_insert_at)
    state["supervision"] = _summary(supervisor, state)
    _save_state(work, state)
    ci_native._check_limits(supervisor, "native outer resume receipt")
    outputs = _github_values(initial_rows, config["sdk_version"])
    _write_outputs(outputs)
    return prepared


def finalize(bundle: Path, work: Path, output: Path, host_rust: Path,
             python_bootstrap_root: Path) -> dict:
    identity = _check_context()
    config = ci_native.native_inputs()
    paths = _paths(argparse.Namespace(bundle=bundle, work=work, output=output,
                                      host_rust=host_rust,
                                      python_bootstrap_root=python_bootstrap_root))
    state = _resume(paths, identity, config, phase="finalize")
    supervisor = state["supervisor"]
    _git_source_check(supervisor, identity, state["source_tree"], "finalize")
    rustc_identity = ci_native._supervised_text(
        supervisor, [paths["host_rust"] / "toolchain/bin/rustc", "-Vv"],
        label="native-outer-finalize-rustc-identity", timeout=30)
    if _sha(rustc_identity.encode()) != state["rustc_identity_sha256"]:
        raise ValueError("pinned host compiler identity changed since outer preparation")
    candidate, metadata = _candidate_paths(paths["output"])
    names = _asset_names(config["sdk_version"])
    _candidate_rows(candidate, {names["payload"], names["sbom"], names["transport"],
                                names["payload_signature"], names["transport_signature"]})
    for key in ("payload_signature", "transport_signature"):
        raw = _regular_file(candidate / names[key], MAX_PROOF_BYTES)
        if not _parse_json(raw, "Cosign signature bundle"):  # Rust finalizer also checks this.
            raise ValueError("outer Cosign signature bundle is empty")
    finalized_raw = ci_native._supervised_text(
        supervisor, [state["xtask"], "native-outer-finalize", "--output", candidate,
                     "--sdk-version", config["sdk_version"]], label="native-outer-finalize", timeout=1200)
    result = _parse_json(finalized_raw.encode(), "native outer finalizer result")
    if (result.get("schema") != "ami-rust-native-outer-finalized-v1"
            or result.get("status") != "CHECKSUMS_BOUND_SIGNATURES_UNVERIFIED"
            or result.get("sdk_version") != config["sdk_version"]
            or not HEX64.fullmatch(result.get("checksums_sha256", ""))):
        raise ValueError("Rust native outer finalizer returned an unexpected result")
    rows = _candidate_rows(candidate, set(names.values()))
    sums = _regular_file(candidate / "SHA256SUMS", MAX_ASSET_BYTES)
    if _sha(sums) != result["checksums_sha256"] or sums != _expected_checksums(rows):
        raise ValueError("native outer SHA256SUMS differs from its exact six-asset inventory")
    state["phase"] = "finalized"
    state["final_assets"] = rows
    state["checksums_sha256"] = result["checksums_sha256"]
    state["supervision_state"] = _history(supervisor, state["supervision_state"]["auxiliary_commands"],
                                           state["supervision_state"]["auxiliary_insert_at"])
    state["supervision"] = _summary(supervisor, state)
    finalized = {
        "schema": "ami-rust-native-outer-finalized-v1",
        "status": result["status"], "tag": "v" + config["sdk_version"],
        "sdk_version": config["sdk_version"], "assets": rows,
        "checksums_sha256": result["checksums_sha256"], "native_finalizer": result,
        "supervision": state["supervision"],
        "r1_accepted": False, "publication_authorized": False,
    }
    target = metadata / "outer-finalized.json"
    if target.exists() or target.is_symlink():
        raise ValueError("native outer finalized metadata must be fresh")
    ci_native.write(target, auth.encoded(finalized), 0o600)
    ci_native._check_limits(supervisor, "native outer finalized candidate")
    _save_state(paths["work"], state)
    ci_native._check_limits(supervisor, "native outer finalization receipt")
    _write_outputs(_github_values(rows, config["sdk_version"], result["checksums_sha256"]))
    return finalized


def verify(bundle: Path, work: Path, output: Path, host_rust: Path,
           python_bootstrap_root: Path, gh_values: list[str]) -> dict:
    identity = _check_context()
    config = ci_native.native_inputs()
    gh_sources = _proof_mapping(gh_values, config["sdk_version"])
    proof_bytes = {subject: _regular_file(path, MAX_PROOF_BYTES)
                   for subject, path in gh_sources.items()}
    paths = _paths(argparse.Namespace(bundle=bundle, work=work, output=output,
                                      host_rust=host_rust,
                                      python_bootstrap_root=python_bootstrap_root))
    state = _resume(paths, identity, config, phase="verify")
    supervisor = state["supervisor"]
    _git_source_check(supervisor, identity, state["source_tree"], "verify")
    rustc_identity = ci_native._supervised_text(
        supervisor, [paths["host_rust"] / "toolchain/bin/rustc", "-Vv"],
        label="native-outer-verify-rustc-identity", timeout=30)
    if _sha(rustc_identity.encode()) != state["rustc_identity_sha256"]:
        raise ValueError("pinned host compiler identity changed since outer preparation")

    candidate, metadata = _candidate_paths(paths["output"])
    names = _asset_names(config["sdk_version"])
    rows = _candidate_rows(candidate, set(names.values()))
    finalized_raw = _regular_file(metadata / "outer-finalized.json", 2 * 1024 * 1024)
    finalized = _parse_json(finalized_raw, "native outer finalized metadata")
    if (finalized.get("status") != "CHECKSUMS_BOUND_SIGNATURES_UNVERIFIED"
            or finalized.get("assets") != rows or finalized.get("checksums_sha256") != _sha(
                _regular_file(candidate / "SHA256SUMS", MAX_ASSET_BYTES))):
        raise ValueError("finalized metadata differs from the current six-asset candidate")
    predicate = auth.encoded(auth.predicate(paths["bundle"], LINUX, ROOT))
    if _regular_file(metadata / "outer-predicate.json", 2 * 1024 * 1024) != predicate:
        raise ValueError("saved native outer predicate differs from the protected source")
    report_path = metadata / "outer-verification.json"
    if report_path.exists() or report_path.is_symlink():
        raise ValueError("native outer verification report destination must be fresh")
    gh_dir = metadata / "gh"
    if gh_dir.exists() or gh_dir.is_symlink():
        raise ValueError("native GitHub proof snapshot directory must be fresh")
    gh_dir.mkdir(mode=0o700)
    proof_rows: dict[str, dict] = {}
    proof_index_subjects = {}
    for subject in _proof_subjects(config["sdk_version"]):
        raw = proof_bytes[subject]
        filename = _proof_filename(subject)
        ci_native.write(gh_dir / filename, raw, 0o600)
        row = {"path": filename, "bytes": len(raw), "sha256": _sha(raw)}
        proof_rows[subject] = {"bytes": len(raw), "sha256": row["sha256"]}
        proof_index_subjects[subject] = [row]
    proof_index = {"schema": "ami-rust-package-proofs-v2", "subjects": proof_index_subjects}
    proof_index_path = metadata / "native-package-proofs.json"
    ci_native.write(proof_index_path, auth.encoded(proof_index), 0o600)

    maintainer = _protected_package_maintainer()
    launcher_rows = state["manifest"].get("host_launchers")
    if not isinstance(launcher_rows, dict):
        raise ValueError("native release host launcher records disappeared")
    manifest_assets = {row["path"]: row for row in state["manifest"]["assets"]}
    pinned_launchers = {}
    for host in HOSTS:
        row = launcher_rows[host]
        launcher = _regular_file(paths["bundle"] / row["path"], MAX_ASSET_BYTES)
        expected = manifest_assets[row["path"]]
        if (len(launcher) != row["bytes"] or _sha(launcher) != row["sha256"]
                or expected["bytes"] != row["bytes"] or expected["sha256"] != row["sha256"]):
            raise ValueError("actual host launcher differs from the native release manifest: " + host)
        pinned_launchers[host] = {"path": row["path"], "bytes": len(launcher), "sha256": _sha(launcher)}
    for host in HOSTS:
        package_inputs = _package_inputs(identity, state["source_tree"], state["manifest_raw"],
                                         state["manifest"], config, rows, proof_rows,
                                         pinned_launchers, host, maintainer)
        ci_native.write(metadata / f"native-package-inputs-{host}.json",
                        auth.encoded(package_inputs), 0o600)

    notices = _copy_notice_tree(paths["work"])
    package = paths["work"] / "native-package"
    check_work = paths["work"] / "outer-binding-check"
    if package.exists() or package.is_symlink() or check_work.exists() or check_work.is_symlink():
        raise ValueError("native package verification work paths must be fresh")
    linux_launcher = paths["bundle"] / pinned_launchers[LINUX]["path"]
    try:
        package_raw = ci_native._supervised_text(
            supervisor, [state["xtask"], "native-package", "--pins",
                         metadata / f"native-package-inputs-{LINUX}.json", "--proof-index", proof_index_path,
                         "--launcher", linux_launcher, "--assets", candidate, "--proofs", gh_dir,
                         "--notices", notices, "--output", package],
            cwd=paths["work"], label="native-package-compose", timeout=1200)
        package_result = _parse_json(package_raw.encode(), "native package composition result")
        if (package_result.get("schema") != "ami-rust-native-package-draft-v1"
                or package_result.get("status") != "BYTE_CONSISTENT_PACKAGE_DRAFT"
                or package_result.get("host") != LINUX
                or package_result.get("package_version") != config["sdk_version"] + "-1"):
            raise ValueError("Rust native package composer returned an unexpected package")
        verify_raw = ci_native._supervised_text(
            supervisor, [state["xtask"], "native-package-verify", "--package", package,
                         "--policy", state["policy_path"], "--inputs",
                         paths["bundle"] / ".auth/inputs.json", "--work", check_work],
            cwd=paths["work"], label="native-package-verify", timeout=1200)
    except Exception as error:
        failed = {
            "schema": "ami-rust-native-outer-verification-v1",
            "status": "OUTER_VERIFICATION_FAILED",
            "source_commit": identity["source_sha"], "workflow_commit": identity["workflow_sha"],
            "run_id": identity["run_id"], "run_attempt": identity["run_attempt"],
            "host_profile": LINUX, "r1_accepted": False, "publication_authorized": False,
            "error_type": type(error).__name__,
            "supervision": ci_native._supervision_summary(
                supervisor, state["supervision_state"]["auxiliary_commands"],
                state["supervision_state"]["auxiliary_insert_at"]),
            "claim": "Native outer verification failed; no R1 acceptance or publication authorization was produced.",
        }
        try:
            state["supervision_state"] = _history(
                supervisor, state["supervision_state"]["auxiliary_commands"],
                state["supervision_state"]["auxiliary_insert_at"])
            state["supervision"] = failed["supervision"]
            ci_native.write(report_path, auth.encoded(failed), 0o600)
            _save_state(paths["work"], state)
            ci_native._check_limits(supervisor, "native outer verification failure report")
        except Exception as report_error:
            raise RuntimeError(
                "native outer verification failed and its failure report could not be preserved"
            ) from report_error
        raise
    native_result = _parse_json(verify_raw.encode(), "native package verification result")
    if (native_result.get("schema") != "ami-rust-native-package-publisher-verification-v1"
            or native_result.get("status") != "OUTER_AND_INNER_AUTHENTICATED"
            or native_result.get("host") != LINUX
            or native_result.get("sdk_version") != config["sdk_version"]):
        raise ValueError("Rust native package verifier did not authenticate the outer and inner release")
    package_inventory = _regular_file(package / "inventory.json", 2 * 1024 * 1024)
    report = {
        "schema": "ami-rust-native-outer-verification-v1",
        "status": "OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED",
        "source_commit": identity["source_sha"], "workflow_commit": identity["workflow_sha"],
        "run_id": identity["run_id"], "run_attempt": identity["run_attempt"],
        "host_profile": LINUX, "tag": "v" + config["sdk_version"],
        "inner_manifest_sha256": state["inner_manifest_sha256"],
        "assets": rows,
        "gh_bundles": {subject: {"path": _proof_filename(subject),
                                  "bytes": proof_rows[subject]["bytes"],
                                  "sha256": proof_rows[subject]["sha256"]}
                       for subject in _proof_subjects(config["sdk_version"])},
        "predicate_sha256": _sha(predicate),
        "native_package_inputs_sha256": {
            host: _sha(_regular_file(metadata / f"native-package-inputs-{host}.json", 2 * 1024 * 1024))
            for host in HOSTS},
        "proof_index_sha256": _sha(auth.encoded(proof_index)),
        "native_package_inventory_sha256": _sha(package_inventory),
        "publisher_verification": native_result,
        "supervision": None,
        "r1_accepted": False, "publication_authorized": False,
        "claim": "Native outer and inner cryptographic verification only; full release qualification and R1 acceptance remain separate.",
    }
    state["phase"] = "verified"
    state["proof_index_sha256"] = report["proof_index_sha256"]
    state["package_inventory_sha256"] = report["native_package_inventory_sha256"]
    state["supervision_state"] = _history(supervisor, state["supervision_state"]["auxiliary_commands"],
                                           state["supervision_state"]["auxiliary_insert_at"])
    state["supervision"] = _summary(supervisor, state)
    report["supervision"] = state["supervision"]
    ci_native.write(report_path, auth.encoded(report), 0o600)
    _save_state(paths["work"], state)
    ci_native._check_limits(supervisor, "native outer verification report")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "finalize", "verify"):
        sub = subs.add_parser(name)
        sub.add_argument("--bundle", type=Path, required=True)
        sub.add_argument("--work", type=Path, required=True)
        sub.add_argument("--output", type=Path, required=True)
        sub.add_argument("--host-rust", type=Path, required=True)
        sub.add_argument("--python-bootstrap-root", type=Path, required=True)
        if name == "verify":
            sub.add_argument("--gh", action="append", default=[], metavar="SUBJECT=PATH")
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.bundle, args.work, args.output, args.host_rust,
                         args.python_bootstrap_root)
    elif args.command == "finalize":
        result = finalize(args.bundle, args.work, args.output, args.host_rust,
                          args.python_bootstrap_root)
    else:
        result = verify(args.bundle, args.work, args.output, args.host_rust,
                        args.python_bootstrap_root, args.gh)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

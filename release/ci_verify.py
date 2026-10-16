#!/usr/bin/env python3
"""Verify and exercise one protected hosted SDK candidate as a consumer.

The helper never signs, publishes, or grants R1 acceptance.  It authenticates
the candidate with the production GH/Cosign verifier, probes tamper boundaries
before installation, then runs the exact signed QUICKSTART recipe in two
independent absolute working roots under the admitted hosted resource limits.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import zipfile

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
TOOLS_SCHEMA = "ami-rust-ci-auth-tools-v1"
TOOL_RECEIPT_SCHEMA = "ami-rust-ci-auth-tool-bootstrap-v1"
RESULT_SCHEMA = "ami-rust-hosted-consumer-qualification-v1"
MAX_BUNDLE_BYTES = 32 * 1024**2
MAX_BUNDLE_FILES = 512
MAX_ASSET_BYTES = 16 * 1024**2
MAX_OUTPUT_BYTES = 32 * 1024**2
MAX_ARCHIVE_EXPANDED = 512 * 1024**2
MAX_PROBES = 5
HOSTS = ("macos-aarch64", "linux-x86_64")
TARGETS = {"macos-aarch64": "aarch64-apple-darwin",
           "linux-x86_64": "x86_64-unknown-linux-gnu"}
VARIANTS = {
    "sha256sum": ("ami-rust-sha256sum", ()),
    "minimal-noalloc": ("ami-rust-minimal", ("--no-default-features",)),
    "minimal-alloc": ("ami-rust-minimal", ("--features", "alloc")),
    "qualification": ("ami-rust-qualification", ()),
    "dependencies": ("ami-rust-dependencies", ()),
}
RECIPE_PREFIX = '"$PYTHON" -I -B '
EXPECTED_RECIPE = (
    '"$PYTHON" -I -B "$BUNDLE/install_publisher.py" verify --bundle "$BUNDLE" --policy "$POLICY"',
    '"$PYTHON" -I -B "$BUNDLE/install_publisher.py" install --bundle "$BUNDLE" --policy "$POLICY" --prefix "$WORK/sdk-0.1.0" --receipt-pin "$WORK/receipt.sha256"',
    '"$PYTHON" -I -B "$BUNDLE/install_publisher.py" lock --prefix "$WORK/sdk-0.1.0" --selection "$WORK/selection.json" --project "$WORK/sdk-0.1.0/sdk" --output "$WORK/utility.lock.json"',
    '"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/utility-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-sha256sum --release --locked --offline',
    '"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/minimal-noalloc-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-minimal --release --locked --offline',
    '"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/minimal-alloc-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-minimal --release --locked --offline --features alloc',
    '"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/qualification-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-qualification --release --locked --offline',
    '"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/utility.lock.json" --output-dir "$WORK/dependencies-build" -- build --manifest-path "$WORK/sdk-0.1.0/sdk/Cargo.toml" --package ami-rust-dependencies --release --locked --offline',
    '"$PYTHON" -I -B "$BUNDLE/new_project.py" --sdk "$WORK/sdk-0.1.0/sdk" --output "$WORK/hello-aros" --receipt-sha256 "$(cat "$WORK/receipt.sha256")"',
    '"$PYTHON" -I -B "$BUNDLE/install_publisher.py" lock --prefix "$WORK/sdk-0.1.0" --selection "$WORK/selection.json" --project "$WORK/hello-aros" --output "$WORK/hello.lock.json"',
    '"$PYTHON" -I -B "$WORK/sdk-0.1.0/sdk/host/cli.py" build --sdk-lock "$WORK/hello.lock.json" --output-dir "$WORK/hello-build" -- build --manifest-path "$WORK/hello-aros/Cargo.toml" --package hello-aros --release --locked --offline',
    '"$PYTHON" -I -B "$BUNDLE/install_publisher.py" uninstall --prefix "$WORK/sdk-0.1.0" --receipt-sha256 "$(cat "$WORK/receipt.sha256")"',
)


def load_helper(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load trusted consumer helper: " + relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ci_sdk = load_helper("_ami_rust_ci_sdk_for_verify", "release/ci_sdk.py")
ci_auth = load_helper("_ami_rust_ci_auth_for_verify", "release/ci_auth.py")
ci_cargo = ci_sdk.ci_cargo


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def strict_json(path: Path, maximum: int = 1024 * 1024) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("missing, linked or oversized JSON input: " + path.name)
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise ValueError("duplicate JSON key: " + key)
            value[key] = item
        return value
    def reject(token):
        raise ValueError("non-finite JSON number: " + token)
    def finite(raw):
        number = float(raw)
        if number != number or number in (float("inf"), float("-inf")):
            raise ValueError("non-finite JSON exponent")
        return number
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                       parse_constant=reject, parse_float=finite)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object: " + path.name)
    return value


def host_identity() -> str:
    pair = (platform.system(), platform.machine().lower())
    host = {("Darwin", "arm64"): "macos-aarch64",
            ("Linux", "x86_64"): "linux-x86_64"}.get(pair)
    if host is None:
        raise ValueError("consumer qualification supports only macOS ARM64 and Ubuntu x86-64")
    return host


def validate_tool_manifest(manifest: dict, host: str) -> dict:
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "trust_boundary", "hosts", "roots"}
            or manifest.get("schema") != TOOLS_SCHEMA or host not in HOSTS
            or set(manifest.get("hosts", {})) != set(HOSTS)
            or not isinstance(manifest.get("roots"), dict)
            or set(manifest["roots"]) != {"gh", "cosign"}):
        raise ValueError("pinned GH/Cosign tool manifest has an incompatible schema")
    rows = manifest["hosts"][host]
    if not isinstance(rows, dict) or set(rows) != {"gh", "cosign"}:
        raise ValueError("host GH/Cosign tool pins are incomplete")
    for name, version, expected_origin in (("gh", "2.102.0", "github.com"),
                                          ("cosign", "3.1.3", "github.com")):
        row = rows[name]
        required = {"version", "url", "bytes", "sha256", "binary_bytes", "binary_sha256"}
        if name == "gh":
            required.add("archive_member")
        if (not isinstance(row, dict) or set(row) != required or row.get("version") != version
                or type(row.get("bytes")) is not int or row["bytes"] <= 0
                or type(row.get("binary_bytes")) is not int or row["binary_bytes"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", ""))
                or not re.fullmatch(r"[0-9a-f]{64}", row.get("binary_sha256", ""))):
            raise ValueError("invalid pinned " + name + " tool identity")
        parsed = urllib.parse.urlparse(row["url"])
        if parsed.scheme != "https" or parsed.hostname != expected_origin or not parsed.path.startswith("/"):
            raise ValueError("pinned " + name + " URL must use HTTPS on github.com")
    gh = rows["gh"]
    expected_gh = {"macos-aarch64": "gh_2.102.0_macOS_arm64/bin/gh",
                   "linux-x86_64": "gh_2.102.0_linux_amd64/bin/gh"}[host]
    if gh["archive_member"] != expected_gh:
        raise ValueError("pinned GH archive member does not match this host")
    roots = manifest["roots"]
    expected_roots = {
        "gh": ("release/trust/github-trusted-root.jsonl", 34634,
               "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"),
        "cosign": ("release/trust/sigstore-trusted-root.json", 5748,
                   "05a094edfa2e8eb7d1b4b37244e28ffb6d86b8b86ce3eb122b644b4335ae4dc1"),
    }
    for name, expected in expected_roots.items():
        row = roots[name]
        if (not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}
                or (row.get("path"), row.get("bytes"), row.get("sha256")) != expected):
            raise ValueError("pinned " + name + " trust root differs from the reviewed bytes")
    return {"host": host, "gh": dict(gh), "cosign": dict(rows["cosign"]),
            "roots": {key: dict(value) for key, value in roots.items()}}


def _copy_pinned_root(source: Path, destination: Path, pin: dict) -> dict:
    if source.is_symlink() or not source.is_file() or destination.exists() or destination.is_symlink():
        raise ValueError("trusted-root source or destination is not a fresh regular file")
    if source.stat().st_size != pin["bytes"] or sha256(source) != pin["sha256"]:
        raise ValueError("trusted-root source differs from its tracked pin: " + pin["path"])
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o600)
    if destination.stat().st_size != pin["bytes"] or sha256(destination) != pin["sha256"]:
        raise ValueError("external trusted-root copy failed readback: " + pin["path"])
    return {"path": str(destination), "bytes": pin["bytes"], "sha256": pin["sha256"]}


def _write_archive_member(archive_path: Path, host: str, pin: dict, destination: Path) -> dict:
    """Extract exactly the hash-pinned GH executable; never unpack other members."""
    member_name = pin["archive_member"]
    expected_size, expected_sha = pin["binary_bytes"], pin["binary_sha256"]
    if destination.exists() or destination.is_symlink():
        raise ValueError("GH executable destination must be fresh")
    digest = hashlib.sha256()
    written = 0
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        if host == "linux-x86_64":
            with tarfile.open(archive_path, mode="r:gz") as bundle:
                members = bundle.getmembers()
                if len(members) > 1000 or sum(max(0, item.size) for item in members) > MAX_ARCHIVE_EXPANDED:
                    raise ValueError("GH tar archive exceeds its member or expanded-size bound")
                names = set()
                selected = None
                for item in members:
                    name = item.name.rstrip("/")
                    if not name or "\\" in name or "\0" in name or name.startswith("/"):
                        raise ValueError("unsafe member name in GH archive")
                    pure = PurePosixPath(name)
                    if any(part in ("", ".", "..") for part in pure.parts) or pure.is_absolute():
                        raise ValueError("unsafe member path in GH archive")
                    if name in names:
                        raise ValueError("duplicate member in GH archive")
                    names.add(name)
                    if item.issym() or item.islnk() or not (item.isfile() or item.isdir()):
                        raise ValueError("GH archive contains a link or special member")
                    if name == member_name:
                        selected = item
                if selected is None or not selected.isfile() or selected.size != expected_size:
                    raise ValueError("pinned GH executable is missing or has the wrong size")
                stream = bundle.extractfile(selected)
                if stream is None:
                    raise ValueError("cannot read pinned GH executable member")
                with stream, destination.open("xb") as output:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        written += len(block)
                        if written > expected_size:
                            raise ValueError("pinned GH executable expanded past its size")
                        output.write(block)
                        digest.update(block)
        else:
            with zipfile.ZipFile(archive_path) as bundle:
                infos = bundle.infolist()
                if len(infos) > 1000 or sum(item.file_size for item in infos) > MAX_ARCHIVE_EXPANDED:
                    raise ValueError("GH ZIP archive exceeds its member or expanded-size bound")
                names = set()
                selected = None
                for item in infos:
                    name = item.filename.rstrip("/")
                    if not name or "\\" in name or "\0" in name or name.startswith("/"):
                        raise ValueError("unsafe member name in GH ZIP")
                    pure = PurePosixPath(name)
                    if any(part in ("", ".", "..") for part in pure.parts) or pure.is_absolute():
                        raise ValueError("unsafe member path in GH ZIP")
                    if name in names:
                        raise ValueError("duplicate member in GH ZIP")
                    names.add(name)
                    mode = (item.external_attr >> 16) & 0xFFFF
                    if stat.S_ISLNK(mode) or (not item.is_dir() and mode and not stat.S_ISREG(mode)):
                        raise ValueError("GH ZIP archive contains a link or special member")
                    if name == member_name:
                        selected = item
                if selected is None or selected.is_dir() or selected.file_size != expected_size:
                    raise ValueError("pinned GH executable is missing or has the wrong size")
                with bundle.open(selected) as stream, destination.open("xb") as output:
                    while True:
                        block = stream.read(1024 * 1024)
                        if not block:
                            break
                        written += len(block)
                        if written > expected_size:
                            raise ValueError("pinned GH executable expanded past its size")
                        output.write(block)
                        digest.update(block)
        if written != expected_size or digest.hexdigest() != expected_sha:
            raise ValueError("GH executable bytes differ from the binary pin")
        destination.chmod(0o700)
        return {"path": str(destination), "bytes": written, "sha256": digest.hexdigest()}
    except BaseException:
        if destination.exists():
            try:
                destination.unlink()
            except OSError as cleanup_error:
                raise RuntimeError("invalid GH executable could not be retired") from cleanup_error
        raise


def _managed_roots(work: Path, output: Path, python_root: Path) -> None:
    if any(not path.is_absolute() for path in (work, output, python_root)):
        raise ValueError("work, output and Python bootstrap roots must be absolute")
    for path in (work, output, python_root):
        if path.is_symlink():
            raise ValueError("managed root must not be a symlink: " + path.name)
    if work.resolve().parent != output.resolve().parent or work.resolve().parent != python_root.resolve().parent:
        raise ValueError("work, output and Python bootstrap must be siblings on one managed volume")
    if (len({work.resolve(), output.resolve(), python_root.resolve()}) != 3
            or work.resolve().is_relative_to(ROOT.resolve())
            or output.resolve().is_relative_to(ROOT.resolve())):
        raise ValueError("managed roots must be distinct and outside the source checkout")
    if python_root.name != "ami-rust-python-bootstrap":
        raise ValueError("pinned Python bootstrap root has the wrong name")
    if not work.parent.is_dir() or not output.parent.is_dir() or not python_root.is_dir():
        raise ValueError("managed roots require existing parent and pinned Python directories")
    for path in (work, output):
        if not path.exists():
            path.mkdir(mode=0o700)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("managed roots must be real, private, current-user directories")


def _source_commit() -> str:
    commit = subprocess.check_output(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                     stderr=subprocess.DEVNULL, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("trusted source checkout has no exact Git commit")
    return commit


def _assert_source_clean(expected_commit: str) -> None:
    if _source_commit() != expected_commit:
        raise ValueError("protected source checkout HEAD differs from its external policy identity")
    status = subprocess.check_output(
        ["/usr/bin/git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=all"],
        stderr=subprocess.DEVNULL, text=True)
    if status:
        raise ValueError("protected source checkout has tracked or untracked modifications")


def _trust_paths(manifest: dict, work: Path) -> dict:
    trust_dir = work / "trust"
    trust_dir.mkdir(mode=0o700, exist_ok=True)
    roots = {}
    for name in ("gh", "cosign"):
        pin = manifest["roots"][name]
        source = ROOT / pin["path"]
        roots[name] = _copy_pinned_root(source, trust_dir / Path(pin["path"]).name, pin)
    return roots


def _tool_env(work: Path, python: Path) -> dict[str, str]:
    home = work / "task-env"
    for name in ("home", "tmp", "cargo-home"):
        (home / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    tools = work / "tools"
    return {"PATH": str(tools) + ":" + str(python.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(home / "home"), "TMPDIR": str(home / "tmp"),
            "TMP": str(home / "tmp"), "TEMP": str(home / "tmp"),
            "CARGO_HOME": str(home / "cargo-home"), "LC_ALL": "C", "LANG": "C",
            "TZ": "UTC", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_OPTIONAL_LOCKS": "0",
            "CARGO_INCREMENTAL": "0", "SOURCE_DATE_EPOCH": "1791936000"}


def _tools_receipt(output: Path) -> Path:
    return output / "tool-bootstrap.json"


def _version_text(supervisor, path: Path, args: list[str], label: str) -> str:
    supervisor.run([str(path), *args], cwd=supervisor.work, label=label, timeout=60)
    row = supervisor.commands[-1]
    return ((supervisor.work / row["stdout_log"]).read_text(errors="replace") + "\n" +
            (supervisor.work / row["stderr_log"]).read_text(errors="replace"))


def _verify_tool_receipt(work: Path, output: Path, host: str, manifest: dict) -> dict:
    receipt_path = _tools_receipt(output)
    receipt = strict_json(receipt_path, 256 * 1024)
    expected_manifest_sha = sha256(ROOT / "release/ci-auth-tools.json")
    if (receipt.get("schema") != TOOL_RECEIPT_SCHEMA or receipt.get("host") != host
            or receipt.get("tools_manifest_sha256") != expected_manifest_sha
            or receipt.get("source_commit") != _source_commit()):
        raise ValueError("pinned verifier tool bootstrap receipt differs from trusted source")
    pins = validate_tool_manifest(manifest, host)
    for name in ("gh", "cosign"):
        path = work / "tools" / name
        row = receipt.get("tools", {}).get(name)
        if (not isinstance(row, dict) or row.get("path") != str(path)
                or row.get("bytes") != pins[name]["binary_bytes"]
                or row.get("sha256") != pins[name]["binary_sha256"]
                or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK)
                or path.stat().st_size != pins[name]["binary_bytes"]
                or sha256(path) != pins[name]["binary_sha256"]):
            raise ValueError("installed verifier executable differs from its trusted pin: " + name)
    for name in ("gh", "cosign"):
        row = receipt.get("roots", {}).get(name)
        pin = pins["roots"][name]
        path = Path(row.get("path", "")) if isinstance(row, dict) else Path("/")
        expected_path = work / "trust" / Path(pin["path"]).name
        if (path != expected_path or row.get("bytes") != pin["bytes"]
                or row.get("sha256") != pin["sha256"] or path.is_symlink()
                or not path.is_file() or path.stat().st_size != pin["bytes"]
                or sha256(path) != pin["sha256"]
                or path.resolve().is_relative_to(work / "candidate")):
            raise ValueError("external verifier root differs from its trusted pin: " + name)
    return receipt


def bootstrap_tools(work: Path, output: Path, python_root: Path, *, source_commit: str | None = None) -> dict:
    """Fetch hash-pinned GH/Cosign tools and trust roots outside any candidate."""
    _managed_roots(work, output, python_root)
    identity = ci_auth.context(ROOT)
    _assert_source_clean(identity["source_sha"])
    if source_commit is not None and source_commit != identity["source_sha"]:
        raise ValueError("tool bootstrap source commit differs from the protected workflow identity")
    if any(output.iterdir()):
        raise ValueError("verifier tool bootstrap output directory must be empty")
    host = host_identity()
    python, bootstrap = ci_sdk.verify_python_bootstrap(python_root, host)
    manifest_path = ROOT / "release/ci-auth-tools.json"
    manifest = strict_json(manifest_path, 1024 * 1024)
    pins = validate_tool_manifest(manifest, host)
    receipt_path = _tools_receipt(output)
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError("verifier tool bootstrap output already exists")
    tools_dir = work / "tools"
    tools_dir.mkdir(mode=0o700, exist_ok=True)
    downloads = work / "tool-downloads"
    downloads.mkdir(mode=0o700, exist_ok=True)
    roots = _trust_paths(manifest, work)
    env = _tool_env(work, python)
    supervisor = ci_sdk.Supervisor(work, output, python_root, env)
    tool_rows = {}
    for name in ("cosign", "gh"):
        pin = pins[name]
        url_path = urllib.parse.urlparse(pin["url"]).path
        suffix = ".zip" if url_path.endswith(".zip") else ".tar.gz" if url_path.endswith(".tar.gz") else ""
        archive_path = downloads / (name + suffix) if name == "gh" else tools_dir / name
        if supervisor.managed_bytes() + pin["bytes"] > ci_sdk.MAX_WORK_BYTES:
            raise ValueError("pinned verifier tool download exceeds managed workspace ceiling")
        downloaded = ci_cargo.download_verified(pin["url"], pin["bytes"], pin["sha256"], archive_path,
                                                expected_origin="github.com",
                                                redirect_hosts=ci_sdk.REDIRECT_HOSTS,
                                                total_timeout=600)
        if name == "gh":
            extracted = _write_archive_member(archive_path, host, pin, tools_dir / "gh")
            archive_path.unlink()
            if archive_path.exists():
                raise RuntimeError("verified GH archive could not be retired")
            tool_rows[name] = {**downloaded, "binary": extracted}
        else:
            executable = tools_dir / "cosign"
            executable.chmod(0o700)
            if (executable.stat().st_size != pin["binary_bytes"]
                    or sha256(executable) != pin["binary_sha256"]):
                raise ValueError("pinned Cosign executable differs from its binary hash")
            tool_rows[name] = {**downloaded, "binary": {"path": str(executable),
                    "bytes": executable.stat().st_size, "sha256": sha256(executable)}}
        supervisor.check_limits("pinned " + name + " bootstrap")
    gh_path, cosign_path = tools_dir / "gh", tools_dir / "cosign"
    gh_version = _version_text(supervisor, gh_path, ["--version"], "verify-gh-version")
    cosign_version = _version_text(supervisor, cosign_path, ["version"], "verify-cosign-version")
    if "gh version 2.102.0" not in gh_version or not re.search(r"\bv?3\.1\.3\b", cosign_version):
        raise ValueError("pinned verifier executables reported an unexpected version")
    current = identity["source_sha"]
    receipt = {
        "schema": TOOL_RECEIPT_SCHEMA, "status": "PINNED_VERIFIER_TOOLS_READY",
        "host": host, "source_commit": current,
        "tools_manifest_sha256": sha256(manifest_path), "python_bootstrap": bootstrap,
        "tools": {name: {"path": str(tools_dir / name),
                         "bytes": pins[name]["binary_bytes"],
                         "sha256": pins[name]["binary_sha256"],
                         "version": pins[name]["version"],
                         "archive_sha256": pins[name]["sha256"],
                         "archive_bytes": pins[name]["bytes"]} for name in ("gh", "cosign")},
        "roots": roots,
        "commands": supervisor.commands,
        "budgets": {"workspace_bytes": ci_sdk.MAX_WORK_BYTES,
                    "rss_bytes": ci_sdk.MAX_RSS_BYTES, "log_bytes": ci_sdk.MAX_LOG_BYTES,
                    "command_seconds": ci_sdk.MAX_COMMAND_SECONDS},
        "claim": "Hash-pinned verifier tools and roots are ready; no SDK candidate or publisher evidence has been verified.",
    }
    receipt_path.write_bytes(canonical_json(receipt))
    receipt_path.chmod(0o600)
    if ci_sdk.directory_bytes(output) > MAX_OUTPUT_BYTES:
        raise ValueError("tool bootstrap receipt exceeds the output ceiling")
    # The workflow can use these fixed, absolute paths without parsing logs.
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        path = Path(github_output)
        if path.is_symlink() or not path.is_file():
            raise ValueError("GITHUB_OUTPUT must be an existing regular file")
        with path.open("a", encoding="utf-8") as stream:
            stream.write("gh=" + str(gh_path) + "\n")
            stream.write("cosign=" + str(cosign_path) + "\n")
    return receipt


def _policy_from_source(source_commit: str, workflow_env: dict[str, str], roots: dict,
                        work: Path) -> tuple[Path, dict]:
    identity = ci_auth.context(ROOT)
    _assert_source_clean(identity["source_sha"])
    if identity["source_sha"] != source_commit:
        raise ValueError("source commit changed while establishing external verifier policy")
    materials = ci_auth.input_manifest(ROOT)
    inputs_sha = hashlib.sha256(ci_auth.encoded(materials)).hexdigest()
    tools_manifest = strict_json(ROOT / "release/ci-auth-tools.json", 1024 * 1024)
    pins = validate_tool_manifest(tools_manifest, host_identity())
    policy = {
        "schema": "ami-rust-publisher-trust-v2",
        "repository": ci_auth.REPO, "workflow": ci_auth.WORKFLOW,
        "workflow_sha": identity["workflow_sha"], "source_sha": identity["source_sha"],
        "source_ref": "refs/heads/main", "oidc_issuer": "https://token.actions.githubusercontent.com",
        "cert_identity": f"https://github.com/{ci_auth.REPO}/{ci_auth.WORKFLOW}@refs/heads/main",
        "inputs_manifest_sha256": inputs_sha, "allowed_host_profiles": list(ci_auth.HOSTS),
        "gh": {"path": str(work / "tools/gh"), "sha256": pins["gh"]["binary_sha256"]},
        "cosign": {"path": str(work / "tools/cosign"), "sha256": pins["cosign"]["binary_sha256"]},
        "gh_trusted_roots": {"path": roots["gh"]["path"], "sha256": roots["gh"]["sha256"]},
        "cosign_trusted_root": {"path": roots["cosign"]["path"], "sha256": roots["cosign"]["sha256"]},
    }
    policy_path = work / "trust/publisher-policy.json"
    if policy_path.exists() or policy_path.is_symlink():
        raise ValueError("external publisher policy destination must be fresh")
    policy_path.write_bytes(canonical_json(policy))
    policy_path.chmod(0o600)
    return policy_path, policy


def _candidate_inventory(bundle: Path) -> tuple[list[tuple[str, Path]], int]:
    if bundle.is_symlink() or bundle.resolve(strict=True) != bundle.absolute():
        raise ValueError("candidate bundle path must be absolute and contain no symlink components")
    if not bundle.is_dir():
        raise ValueError("candidate bundle must be a directory")
    rows = []
    total = 0
    for base, dirs, files in os.walk(bundle, followlinks=False):
        current = Path(base)
        for name in list(dirs):
            child = current / name
            if not stat.S_ISDIR(child.lstat().st_mode):
                raise ValueError("candidate bundle contains a linked or non-directory path")
        for name in files:
            path = current / name
            info = path.lstat()
            rel = path.relative_to(bundle).as_posix()
            ci_auth.rel(rel)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("candidate bundle contains a linked or special file")
            if info.st_size > MAX_ASSET_BYTES:
                raise ValueError("candidate bundle file exceeds its 16 MiB asset bound: " + rel)
            total += info.st_size
            rows.append((rel, path))
            if len(rows) > MAX_BUNDLE_FILES or total > MAX_BUNDLE_BYTES:
                raise ValueError("candidate bundle exceeds the 512-file/32-MiB boundary")
    rows.sort(key=lambda row: row[0])
    required = {"release.json", ".auth/inputs.json", ".auth/authentication.json",
                "sdk.tar.xz", "SHAUTIL", "install.py", "install_publisher.py",
                "verify_publisher.py", "new_project.py", "QUICKSTART.md"}
    names = {name for name, _ in rows}
    if not required <= names:
        raise ValueError("candidate bundle omits required authenticated consumer files: " +
                         ", ".join(sorted(required - names)))
    return rows, total


def _copy_candidate(source: Path, destination: Path) -> dict:
    rows, total = _candidate_inventory(source)
    if destination.exists() or destination.is_symlink():
        raise ValueError("candidate copy destination must be fresh")
    destination.mkdir(mode=0o700, parents=True)
    try:
        for relative, src in rows:
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            before = src.stat()
            shutil.copyfile(src, target)
            if target.stat().st_size != before.st_size or sha256(target) != sha256(src):
                raise ValueError("candidate copy readback differs: " + relative)
            target.chmod(0o600 if relative.startswith(".auth/") else 0o644)
        if ci_sdk.directory_bytes(destination) != total:
            raise ValueError("candidate copy total differs from its bounded inventory")
        return {"file_count": len(rows), "bytes": total,
                "inventory_sha256": hashlib.sha256(b"".join(
                    ci_auth.encoded({"path": name, "bytes": path.stat().st_size,
                                    "sha256": sha256(path)}) for name, path in rows)).hexdigest()}
    except BaseException:
        try:
            shutil.rmtree(destination)
        except OSError as cleanup_error:
            raise RuntimeError("candidate copy failed and partial tree could not be retired") from cleanup_error
        raise


def _mutate_byte(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise ValueError("negative probe requires a nonempty regular file")
    with path.open("r+b") as stream:
        original = stream.read(1)
        stream.seek(0)
        stream.write(bytes([original[0] ^ 1]))
        stream.flush()
        os.fsync(stream.fileno())


def _negative_copy(base: Path, destination: Path) -> dict:
    return _copy_candidate(base, destination)


def run_negative_probes(bundle: Path, policy_path: Path, work: Path, install_prefix: Path,
                        verify_callback) -> list[dict]:
    """Require every tamper fixture to fail verification before installation.

    `verify_callback` is the production CLI adapter in real CI. Unit tests use a
    visibly synthetic callback and do not claim cryptographic verification.
    """
    if install_prefix.exists() or install_prefix.is_symlink():
        raise ValueError("negative verification probes must precede every installation")
    manifest = strict_json(bundle / "release.json", 1024 * 1024)
    assets = {row["path"] for row in manifest.get("assets", []) if isinstance(row, dict)}
    if not {"sdk.tar.xz", "SHAUTIL"} <= assets:
        raise ValueError("negative probes require authenticated SDK and SHAUTIL assets")
    cases = (
        ("mutated-sdk", "sdk.tar.xz"),
        ("mutated-shautil", "SHAUTIL"),
        ("missing-asset", "sdk.tar.xz"),
        ("manifest-mismatch", "release.json"),
        ("wrong-source-policy", None),
    )
    results = []
    for label, relative in cases:
        candidate = work / ("negative-" + label)
        inventory = _negative_copy(bundle, candidate)
        alternate_policy = policy_path
        if label == "mutated-sdk" or label == "mutated-shautil":
            _mutate_byte(candidate / relative)
        elif label == "missing-asset":
            (candidate / relative).unlink()
        elif label == "manifest-mismatch":
            raw = strict_json(candidate / "release.json", 1024 * 1024)
            raw["version"] = raw.get("version", "0.1.0") + "-tampered"
            (candidate / "release.json").write_bytes(canonical_json(raw))
        else:
            policy = strict_json(policy_path, 1024 * 1024)
            source_sha = policy["source_sha"]
            policy["source_sha"] = "1" * 40 if source_sha != "1" * 40 else "2" * 40
            alternate_policy = work / "trust/wrong-source-policy.json"
            if alternate_policy.exists() or alternate_policy.is_symlink():
                raise ValueError("wrong-source policy probe destination already exists")
            alternate_policy.write_bytes(canonical_json(policy))
            alternate_policy.chmod(0o600)
        outcome = verify_callback(candidate, alternate_policy, "negative-" + label)
        if outcome.get("accepted") is not False or type(outcome.get("exit_code")) is not int or outcome["exit_code"] == 0:
            raise RuntimeError("tamper probe did not fail closed: " + label)
        if install_prefix.exists() or install_prefix.is_symlink():
            raise RuntimeError("negative verifier probe created an installation: " + label)
        results.append({"case": label, "status": "REJECTED_BEFORE_INSTALL",
                        "mutated_path": relative, "candidate_inventory": inventory,
                        "exit_code": outcome["exit_code"],
                        "stop_reason": outcome.get("stop_reason"),
                        "stderr_sha256": outcome.get("stderr_sha256")})
    if len(results) != MAX_PROBES:
        raise RuntimeError("not all required negative verifier probes ran")
    return results


def _run_supervised(supervisor, python: Path, script: Path, argv: list[str], *,
                    cwd: Path, label: str, timeout: int = 300) -> tuple[dict, str, str]:
    supervisor.run([str(python), "-I", "-B", str(script), *argv], cwd=cwd,
                    label=label, timeout=timeout)
    row = supervisor.commands[-1]
    stdout = (supervisor.work / row["stdout_log"]).read_text(errors="replace")
    stderr = (supervisor.work / row["stderr_log"]).read_text(errors="replace")
    return row, stdout, stderr


def _expect_verify_rejection(supervisor, python: Path, bundle: Path, policy: Path,
                             label: str) -> dict:
    # Untrusted candidates never supply the verifier used for their first review.
    script = ROOT / "release/install_publisher.py"
    try:
        row, _, stderr = _run_supervised(supervisor, python, script,
            ["verify", "--bundle", str(bundle), "--policy", str(policy)],
            cwd=supervisor.work, label=label, timeout=300)
        return {"accepted": True, "exit_code": row["exit_code"],
                "stop_reason": row["stop_reason"], "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest()}
    except RuntimeError:
        row = supervisor.commands[-1]
        stderr_path = supervisor.work / row["stderr_log"]
        stderr_sha = sha256(stderr_path) if stderr_path.exists() else hashlib.sha256(b"").hexdigest()
        if row["stop_reason"] is not None or row["exit_code"] in (None, 0):
            raise RuntimeError("negative verifier command stopped unexpectedly instead of refusing")
        return {"accepted": False, "exit_code": row["exit_code"],
                "stop_reason": row["stop_reason"], "stderr_sha256": stderr_sha}


def _extract_flat_cargo(archive: Path, component_root: Path, cargo_manifest: dict) -> dict:
    if component_root.exists() or component_root.is_symlink():
        raise ValueError("Cargo extraction root must be fresh")
    expected = {row["path"]: row for row in cargo_manifest.get("files", [])}
    if set(expected) != {"bin/cargo", "producer.json"} or len(expected) != len(cargo_manifest.get("files", [])):
        raise ValueError("candidate Cargo manifest must declare only binary and producer receipt")
    component_root.mkdir(parents=True)
    found = {}
    expanded = 0
    try:
        with tarfile.open(archive, mode="r:xz") as tar:
            members = tar.getmembers()
            if [member.name for member in members] != ["bin/cargo", "producer.json"]:
                raise ValueError("candidate Cargo archive has unexpected member set/order")
            for member in members:
                if (not member.isfile() or member.issym() or member.islnk() or member.pax_headers
                        or member.uid != 0 or member.gid != 0 or member.mtime != 1791936000
                        or member.uname != "" or member.gname != ""
                        or member.mode != (0o755 if member.name == "bin/cargo" else 0o644)):
                    raise ValueError("candidate Cargo archive contains noncanonical metadata")
                row = expected[member.name]
                if member.size != row["bytes"]:
                    raise ValueError("candidate Cargo archive size differs from its profile")
                expanded += member.size
                if expanded > 256 * 1024**2:
                    raise ValueError("candidate Cargo archive exceeds its expanded-size ceiling")
                target = component_root / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError("candidate Cargo archive member has no stream")
                digest = hashlib.sha256()
                size = 0
                with stream, target.open("xb") as output:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        size += len(block)
                        if size > row["bytes"]:
                            raise ValueError("Cargo archive member exceeded its profile size")
                        output.write(block)
                        digest.update(block)
                if size != row["bytes"] or digest.hexdigest() != row["sha256"]:
                    raise ValueError("candidate Cargo bytes differ from the SDK manifest")
                found[member.name] = {"path": member.name, "bytes": size, "sha256": digest.hexdigest()}
                target.chmod(0o755 if member.name == "bin/cargo" else 0o644)
        if found != expected:
            raise ValueError("candidate Cargo archive inventory is incomplete")
        return ci_sdk.verify_component(component_root, cargo_manifest, "cargo")
    except BaseException:
        try:
            shutil.rmtree(component_root)
        except OSError as cleanup_error:
            raise RuntimeError("Cargo extraction failed and partial component could not be retired") from cleanup_error
        raise


def _write_selection(path: Path, python: Path, components: dict[str, Path]) -> dict:
    if path.exists() or path.is_symlink():
        raise ValueError("consumer selection file must be fresh")
    expected = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")
    if set(components) != set(expected):
        raise ValueError("consumer selection must contain exactly the six SDK components")
    value = {"python": str(python.resolve(strict=True)),
             "components": {name: str(components[name].resolve(strict=True)) for name in expected}}
    path.write_bytes(canonical_json(value))
    path.chmod(0o600)
    return value


def _copy_components_to_consumers(staging: dict[str, Path], consumers: list[Path],
                                  component_info: dict, supervisor) -> list[dict[str, Path]]:
    copied = []
    for consumer in consumers:
        destination_root = consumer / "components"
        destination_root.mkdir(mode=0o700)
        rows = {}
        for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor"):
            destination = destination_root / name
            ci_sdk._copy_tree(staging[name], destination)
            ci_sdk.verify_component(destination, component_info[name]["manifest"], name)
            rows[name] = destination
        copied.append(rows)
        supervisor.check_limits("complete consumer prerequisite copy")
    return copied


def _run_recipe_line(supervisor, env: dict[str, str], cwd: Path, line: str, label: str) -> tuple[dict, str, str]:
    if line not in EXPECTED_RECIPE:
        raise ValueError("consumer command differs from the reviewed signed QUICKSTART recipe")
    command = "/bin/sh"
    # Run the authenticated command as written; only the explicit recipe variables differ per root.
    old_env = supervisor.env
    supervisor.env = env
    try:
        row = supervisor.run([command, "-c", "set -eu\n" + line], cwd=cwd, label=label,
                             timeout=ci_sdk.MAX_COMMAND_SECONDS)
    finally:
        supervisor.env = old_env
    record = supervisor.commands[-1]
    stdout = (supervisor.work / record["stdout_log"]).read_text(errors="replace")
    stderr = (supervisor.work / record["stderr_log"]).read_text(errors="replace")
    if record["exit_code"] != 0 or record["stop_reason"] is not None:
        raise RuntimeError("signed QUICKSTART command failed: " + label)
    return record, stdout, stderr


def _recipe_commands(bundle: Path) -> tuple[list[str], str]:
    path = bundle / "QUICKSTART.md"
    raw = path.read_bytes()
    if len(raw) > MAX_ASSET_BYTES:
        raise ValueError("signed QUICKSTART exceeds the asset size limit")
    text = raw.decode("utf-8")
    blocks = re.findall(r"```sh\n(.*?)\n```", text, re.S)
    commands = [line for block in blocks for line in block.splitlines() if line.startswith(RECIPE_PREFIX)]
    if tuple(commands) != EXPECTED_RECIPE:
        raise ValueError("signed QUICKSTART does not contain the exact reviewed 12-command recipe")
    return commands, hashlib.sha256(raw).hexdigest()


def _validate_trusted_consumer_assets(bundle: Path, verifier_result: dict, policy: dict,
                                      trusted_source: Path = ROOT) -> None:
    """Bind executed docs/helpers to the protected source's static asset map."""
    static = strict_json(trusted_source / "release/bundle-files.json", 2 * 1024**2)
    if static.get("schema") != "ami-rust-bundle-files-v1" or not isinstance(static.get("files"), list):
        raise ValueError("trusted static bundle file map is malformed")
    rows = {row.get("path"): row for row in static["files"] if isinstance(row, dict)}
    if len(rows) != len(static["files"]):
        raise ValueError("trusted static bundle file map contains duplicate or malformed paths")
    release = strict_json(bundle / "release.json", 1024 * 1024)
    assets = {row["path"]: row for row in release.get("assets", []) if isinstance(row, dict)}
    if (len(assets) != len(release.get("assets", []))
            or verifier_result.get("release_manifest_sha256") != sha256(bundle / "release.json")
            or verifier_result.get("version") != release.get("version")):
        raise ValueError("protected verifier result does not bind the candidate release manifest")
    authentication = verifier_result.get("authentication")
    direct_subjects = sorted(("release.json", "sdk.tar.xz", "SHAUTIL"))
    workflow_runs = authentication.get("workflowRuns") if isinstance(authentication, dict) else None
    if (not isinstance(authentication, dict)
            or authentication.get("schema") != "ami-rust-publisher-verification-v2"
            or authentication.get("verified") is not True
            or authentication.get("repository") != ci_auth.REPO
            or authentication.get("workflow") != ci_auth.WORKFLOW
            or authentication.get("workflowSha") != policy.get("workflow_sha")
            or authentication.get("sourceSha") != policy.get("source_sha")
            or authentication.get("sourceRef") != "refs/heads/main"
            or authentication.get("manifestSha256") != verifier_result.get("release_manifest_sha256")
            or authentication.get("attestedSubjects") != direct_subjects
            or authentication.get("cosignSubjects") != direct_subjects
            or not isinstance(authentication.get("manifestBoundAssets"), list)
            or not set(["sdk.tar.xz", "SHAUTIL", "install.py", "install_publisher.py",
                        "verify_publisher.py", "new_project.py", "QUICKSTART.md"]) <=
               set(authentication.get("manifestBoundAssets", []))
            or not isinstance(workflow_runs, list)
            or verifier_result.get("host") not in HOSTS
            or len(workflow_runs) != 1
            or not isinstance(workflow_runs[0], dict)
            or workflow_runs[0].get("hostProfile") != verifier_result["host"]):
        raise ValueError("protected verifier authentication report differs from external source policy")
    for name in ("install.py", "install_publisher.py", "verify_publisher.py", "new_project.py", "QUICKSTART.md"):
        pin = rows.get(name)
        asset = assets.get(name)
        if not isinstance(pin, dict) or set(pin) != {"path", "source", "bytes", "sha256"}:
            raise ValueError("trusted source has no static bundle pin for " + name)
        source = trusted_source / ci_auth.rel(pin["source"])
        candidate_file = bundle / name
        if (asset != {"path": name, "bytes": pin["bytes"], "sha256": pin["sha256"]}
                or source.is_symlink() or not source.is_file()
                or source.stat().st_size != pin["bytes"] or sha256(source) != pin["sha256"]
                or candidate_file.is_symlink() or not candidate_file.is_file()
                or candidate_file.stat().st_size != pin["bytes"]
                or sha256(candidate_file) != pin["sha256"]):
            raise ValueError("authenticated consumer asset differs from protected source pin: " + name)
    if verifier_result.get("status") != "verified":
        raise ValueError("protected-source verifier did not establish candidate verification")


def _parse_command_result(stdout: str, expected_status: str, label: str) -> dict:
    try:
        value = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("signed consumer command did not return JSON: " + label) from error
    if not isinstance(value, dict) or value.get("status") != expected_status:
        raise ValueError("signed consumer command returned an unexpected result: " + label)
    return value


def _build_receipt(path: Path, host: str, reference: dict | None, supervisor,
                   label: str) -> dict:
    receipt_path = path / "build-receipt.json"
    receipt = ci_sdk.read_json(receipt_path, 4 * 1024**2)
    if receipt.get("host") != host or not isinstance(receipt.get("canonical_artifacts"), dict):
        raise ValueError("consumer build receipt is malformed or from another host: " + label)
    if reference is not None:
        summary, artifact = ci_sdk._verify_native_receipt(path, reference, supervisor, label)
        return {**summary, "canonical_artifacts": reference,
                "AMIRUST_path": str(artifact), "reference_match": True}
    artifact_rows = receipt["canonical_artifacts"]
    artifact_root = path / "artifacts"
    found = {}
    for name, row in artifact_rows.items():
        rel = ci_sdk._safe_relative(name)
        target = artifact_root.joinpath(*rel.parts)
        info = target.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size != row.get("bytes")
                or sha256(target) != row.get("sha256")):
            raise ValueError("new-project artifact differs from its build receipt: " + name)
        found[name] = {"bytes": info.st_size, "sha256": row["sha256"]}
    if not found or "AMIRUST" not in found:
        raise ValueError("new-project build did not produce AMIRUST")
    supervisor.check_limits("completed new-project native build")
    return {"receipt_sha256": sha256(receipt_path), "canonical_artifacts": found,
            "AMIRUST_path": str(artifact_root / "AMIRUST"), "reference_match": False}


def _run_recipe_builds(supervisor, python: Path, host: str, reference: dict,
                       consumers: list[Path], commands: list[str], output: Path) -> dict:
    names = ("sha256sum", "minimal-noalloc", "minimal-alloc", "qualification", "dependencies")
    output_native = output / "native"
    output_native.mkdir(mode=0o700)
    rows_by_root = {}
    first_native = {}
    for consumer_index, consumer in enumerate(consumers):
        root_name = "absolute-a" if consumer_index == 0 else "absolute-b"
        env = dict(supervisor.env)
        env.update({"PYTHON": str(python), "BUNDLE": str(supervisor.work / "candidate"),
                    "POLICY": str(supervisor.work / "trust/publisher-policy.json"),
                    "WORK": str(consumer)})
        # The twelve authenticated lines are executed verbatim for each root.
        root_rows = []
        if consumer_index == 0:
            indices = range(3, 8)
        else:
            indices = range(3, 8)
        for index in indices:
            line = commands[index]
            build_name = ("utility-build", "minimal-noalloc-build", "minimal-alloc-build",
                          "qualification-build", "dependencies-build")[index - 3]
            record, _, _ = _run_recipe_line(supervisor, env, consumer, line,
                                               f"consumer-{root_name}-{build_name}")
            variant = names[index - 3]
            build_path = consumer / build_name
            expected = reference["hosts"][host][variant]
            verified = _build_receipt(build_path, host, expected, supervisor,
                                      root_name + "/" + variant)
            if consumer_index == 0:
                preserved = ci_sdk._preserve_native_payload(Path(verified["AMIRUST_path"]),
                                                              supervisor.work, variant)
                first_native[variant] = {"path": preserved, "canonical_artifacts": verified["canonical_artifacts"],
                                         "amirst_sha256": sha256(preserved),
                                         "amirst_bytes": preserved.stat().st_size}
            else:
                original = first_native.get(variant)
                if (not original or original["canonical_artifacts"] != verified["canonical_artifacts"]
                        or original["amirst_sha256"] != sha256(Path(verified["AMIRUST_path"]))
                        or original["amirst_bytes"] != Path(verified["AMIRUST_path"]).stat().st_size):
                    raise ValueError("two clean consumer roots produced different native bytes: " + variant)
                destination = output_native / (variant + ".AMIRUST")
                if destination.exists() or destination.is_symlink():
                    raise ValueError("native qualification output already exists: " + variant)
                shutil.copyfile(verified["AMIRUST_path"], destination)
                destination.chmod(0o755)
                if sha256(destination) != original["amirst_sha256"]:
                    raise ValueError("retained native payload differs after second-root comparison")
            root_rows.append({"recipe_index": index, "command": line,
                              "process": record, "build_receipt_sha256": verified["receipt_sha256"],
                              "canonical_artifacts": verified["canonical_artifacts"],
                              "reference_match": True})
            ci_sdk._retire_successful_build(build_path, supervisor.work)
            supervisor.check_limits("retired consumer build " + variant)
        # The project creation/lock/build lines are the final three commands before uninstall.
        for index, label in ((8, "new-project"), (9, "hello-project-lock"), (10, "hello-build")):
            record, stdout, _ = _run_recipe_line(supervisor, env, consumer, commands[index],
                                                   f"consumer-{root_name}-{label}")
            if index == 8:
                try:
                    result = json.loads(stdout)
                except json.JSONDecodeError as error:
                    raise ValueError("signed new-project command did not return JSON") from error
                if (not isinstance(result, dict) or result.get("package") != "hello-aros"
                        or result.get("project") != str(consumer / "hello-aros")
                        or result.get("sdk_manifest_sha256") != sdk["manifest_sha256"]):
                    raise ValueError("signed new-project command created an unexpected package")
                if not (consumer / "hello-aros/Cargo.toml").is_file():
                    raise ValueError("signed new-project command did not create Cargo.toml")
                root_rows.append({"recipe_index": index, "command": commands[index],
                                  "process": record, "result": result})
            elif index == 9:
                result = _parse_command_result(stdout, "locked", label)
                if (result.get("host") != host
                        or result.get("sdk_manifest_sha256") != sdk["manifest_sha256"]
                        or result.get("receipt_sha256") != receipt_pins[root_name]):
                    raise ValueError("new-project lock does not bind the installed SDK and receipt")
                root_rows.append({"recipe_index": index, "command": commands[index],
                                  "process": record, "result": result})
            else:
                build_path = consumer / "hello-build"
                verified = _build_receipt(build_path, host, None, supervisor, label)
                root_rows.append({"recipe_index": index, "command": commands[index],
                                  "process": record, "build_receipt_sha256": verified["receipt_sha256"],
                                  "canonical_artifacts": verified["canonical_artifacts"],
                                  "reference_match": False})
                ci_sdk._retire_successful_build(build_path, supervisor.work)
                supervisor.check_limits("retired new-project build")
        rows_by_root[root_name] = root_rows
    return {"roots": rows_by_root, "retained_native": [
        {"path": "native/" + variant + ".AMIRUST", "bytes": (output_native / (variant + ".AMIRUST")).stat().st_size,
         "sha256": sha256(output_native / (variant + ".AMIRUST"))}
        for variant in VARIANTS]}


def _install_and_run_recipe(bundle: Path, work: Path, output: Path, python: Path,
                            supervisor, host: str, sdk: dict, components: dict,
                            reference: dict, commands: list[str]) -> dict:
    consumers_root = work / "consumers"
    consumers_root.mkdir(mode=0o700, exist_ok=True)
    marker = consumers_root / "unrelated-sibling-marker.txt"
    marker.write_bytes(b"preserved-sibling-marker-v1\n")
    marker.chmod(0o600)
    consumers = [consumers_root / "absolute-a", consumers_root / "absolute-b"]
    for consumer in consumers:
        consumer.mkdir(mode=0o700)
    component_copies = _copy_components_to_consumers(components, consumers, sdk["component_info"], supervisor)
    selections = [_write_selection(root / "selection.json", python, rows)
                  for root, rows in zip(consumers, component_copies, strict=True)]
    envs = []
    receipt_pins = {}
    for consumer in consumers:
        env = dict(supervisor.env)
        env.update({"PYTHON": str(python), "BUNDLE": str(bundle),
                    "POLICY": str(work / "trust/publisher-policy.json"), "WORK": str(consumer)})
        envs.append(env)

    command_rows = {"absolute-a": [], "absolute-b": []}
    # First two documented commands are executed for both independent roots.
    for index in (0, 1):
        for consumer, name, env in zip(consumers, ("absolute-a", "absolute-b"), envs, strict=True):
            row, stdout, _ = _run_recipe_line(supervisor, env, consumer, commands[index],
                                               f"consumer-{name}-recipe-{index:02d}")
            result = _parse_command_result(stdout, "verified" if index == 0 else "installed", commands[index])
            if index == 0 and (result.get("host") != host or result.get("qualification_only") is not False):
                raise ValueError("production verifier output differs from this host or candidate route")
            if index == 1:
                receipt = consumer / "receipt.sha256"
                digest = receipt.read_text(encoding="ascii").strip()
                if not re.fullmatch(r"[0-9a-f]{64}", digest) or result.get("receipt_sha256") != digest:
                    raise ValueError("production install did not return its external receipt pin")
                if (result.get("host") != host or result.get("version") != sdk["manifest"].get("version")
                        or result.get("qualification_only") is not False
                        or result.get("release_manifest_sha256") != sha256(bundle / "release.json")):
                    raise ValueError("production installation result differs from the authenticated candidate")
                receipt_pins[name] = digest
            command_rows[name].append({"recipe_index": index, "command": commands[index],
                                       "process": row, "result": result})

    # Run the six-component lock command for both installed SDKs before building.
    for consumer, name, env in zip(consumers, ("absolute-a", "absolute-b"), envs, strict=True):
        row, stdout, _ = _run_recipe_line(supervisor, env, consumer, commands[2],
                                           f"consumer-{name}-recipe-02")
        result = _parse_command_result(stdout, "locked", commands[2])
        if (result.get("host") != host
                or result.get("sdk_manifest_sha256") != sdk["manifest_sha256"]
                or result.get("receipt_sha256") != receipt_pins[name]):
            raise ValueError("utility project lock does not bind the installed SDK and receipt")
        command_rows[name].append({"recipe_index": 2, "command": commands[2],
                                   "process": row, "result": result})

    build_records = _run_recipe_builds(supervisor, python, host, reference, consumers,
                                       commands, output)
    for consumer, name, env in zip(consumers, ("absolute-a", "absolute-b"), envs, strict=True):
        # _run_recipe_builds has already run indices 3-10; retain their command and
        # result records alongside the install/lock records.
        command_rows[name].extend(build_records["roots"][name])

    uninstall_rows = {}
    for consumer, name, env, other in zip(consumers, ("absolute-a", "absolute-b"), envs,
                                         (consumers[1], consumers[0]), strict=True):
        row, stdout, _ = _run_recipe_line(supervisor, env, consumer, commands[11],
                                           f"consumer-{name}-recipe-11")
        result = _parse_command_result(stdout, "uninstalled", commands[11])
        if (result.get("receipt_sha256") != receipt_pins[name]
                or result.get("version") != sdk["manifest"].get("version")):
            raise ValueError("production uninstall result differs from the selected installation receipt")
        prefix = consumer / "sdk-0.1.0"
        if prefix.exists() or prefix.is_symlink():
            raise ValueError("production uninstall left the selected prefix behind")
        if not marker.is_file() or marker.read_bytes() != b"preserved-sibling-marker-v1\n":
            raise ValueError("production uninstall removed or changed its sibling marker")
        if not (consumer / "hello-aros/Cargo.toml").is_file():
            raise ValueError("production uninstall removed the consumer project")
        other_prefix = other / "sdk-0.1.0"
        if name == "absolute-a" and (not other_prefix.is_dir() or other_prefix.is_symlink()):
            raise ValueError("uninstall of A removed the installed sibling B")
        uninstall_rows[name] = {"command": commands[11], "process": row, "result": result,
                                "selected_prefix_absent": True, "sibling_prefix_preserved":
                                    other_prefix.is_dir() if name == "absolute-a" else True,
                                "project_preserved": True, "marker_preserved": True}
        command_rows[name].append({"recipe_index": 11, "command": commands[11],
                                   "process": row, "result": result})
        for root, component_map in zip(consumers, component_copies, strict=True):
            for component, path in component_map.items():
                ci_sdk.verify_component(path, sdk["component_info"][component]["manifest"], component)
        supervisor.check_limits("post-uninstall prerequisite inventory")
    for variant, expected in VARIANTS.items():
        payload = output / "native" / (variant + ".AMIRUST")
        reference_row = reference["hosts"][host][variant]["AMIRUST"]
        if (payload.stat().st_size != reference_row["bytes"]
                or sha256(payload) != reference_row["sha256"]):
            raise ValueError("retained native payload does not match the host reference: " + variant)
    return {"commands": command_rows, "uninstall": uninstall_rows,
            "prerequisite_inventories_after_uninstall": {
                name: {component: ci_sdk.verify_component(path, sdk["component_info"][component]["manifest"], component)
                       for component, path in rows.items()}
                for name, rows in zip(("absolute-a", "absolute-b"), component_copies, strict=True)},
            "retained_native": build_records["retained_native"],
            "unrelated_sibling_marker_sha256": sha256(marker)}


def qualify(bundle_path: Path, work: Path, output: Path, python_root: Path) -> dict:
    host = host_identity()
    workflow_keys = ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REF", "SOURCE_IS_PROTECTED",
                     "PUBLISHER_ENVIRONMENT", "RUNNER_ENVIRONMENT", "GITHUB_SHA",
                     "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    workflow_env = {key: os.environ.get(key, "") for key in workflow_keys}
    # This must happen before subprocesses receive the stripped environment.
    identity = ci_auth.context(ROOT)
    python, python_bootstrap = ci_sdk.verify_python_bootstrap(python_root, host)
    _managed_roots(work, output, python_root)
    manifest_path = ROOT / "release/ci-auth-tools.json"
    tool_manifest = strict_json(manifest_path, 1024 * 1024)
    tool_pins = validate_tool_manifest(tool_manifest, host)
    receipt_path = _tools_receipt(output)
    if not receipt_path.exists():
        bootstrap_tools(work, output, python_root, source_commit=identity["source_sha"])
    tool_receipt = _verify_tool_receipt(work, output, host, tool_manifest)
    if {path.name for path in output.iterdir()} != {"tool-bootstrap.json"}:
        raise ValueError("consumer output directory contains unexpected preexisting entries")
    roots = tool_receipt["roots"]
    policy_path, policy = _policy_from_source(identity["source_sha"], workflow_env, roots, work)
    env = _tool_env(work, python)
    # Do not pass workflow credentials or ambient proxy settings into verifier/build subprocesses.
    supervisor = ci_sdk.Supervisor(work, output, python_root, env)
    gh_text = _version_text(supervisor, work / "tools/gh", ["--version"], "recheck-gh-version")
    cosign_text = _version_text(supervisor, work / "tools/cosign", ["version"], "recheck-cosign-version")
    if "gh version 2.102.0" not in gh_text or not re.search(r"\bv?3\.1\.3\b", cosign_text):
        raise ValueError("pinned verifier tool version changed before candidate verification")
    if (sha256(work / "tools/gh") != tool_pins["gh"]["binary_sha256"]
            or sha256(work / "tools/cosign") != tool_pins["cosign"]["binary_sha256"]):
        raise ValueError("pinned verifier tool changed while checking its version")
    candidate_original = bundle_path.absolute()
    if (candidate_original == work or candidate_original in work.parents
            or work in candidate_original.parents or candidate_original == output
            or candidate_original in output.parents or output in candidate_original.parents):
        raise ValueError("candidate bundle must not overlap managed work or output")
    bundle = work / "candidate"
    bundle_copy = _copy_candidate(candidate_original, bundle)
    commands, quickstart_sha = _recipe_commands(bundle)

    # Validate policy, capacity, and the native reference from the protected source.
    reference_inputs, resources, host_rows, capacity = ci_sdk.load_normative(
        ROOT / "release/ci-sdk-inputs.json", ROOT / "release/ci-resources.json", host)
    capacity = ci_sdk.validate_resource_policy(resources, work.parent)
    reference = ci_sdk.validate_native_reference(
        ci_sdk.read_json(ROOT / "release/native-reference.json", 2 * 1024**2),
        reference_inputs, reference_inputs["native_reference"]["sha256"])

    # Authenticate the candidate with the verifier in the protected checkout
    # before reading its manifest as an extraction/download authority.
    initial_row, initial_stdout, _ = _run_supervised(
        supervisor, python, ROOT / "release/install_publisher.py",
        ["verify", "--bundle", str(bundle), "--policy", str(policy_path)],
        cwd=work, label="publisher-verify-protected-source", timeout=300)
    initial_verify = _parse_command_result(initial_stdout, "verified", "protected-source verifier")
    if initial_verify.get("host") != host or initial_verify.get("qualification_only") is not False:
        raise ValueError("protected-source verifier returned a different host or release route")
    _validate_trusted_consumer_assets(bundle, initial_verify, policy)

    candidate_manifest = strict_json(bundle / "release.json", 1024 * 1024)
    asset_rows = {row["path"]: row for row in candidate_manifest["assets"]}
    if candidate_manifest.get("qualification_only") is not False:
        raise ValueError("consumer route requires production qualification_only=false")
    for name in ("sdk.tar.xz", "SHAUTIL", f"cargo-{host}.tar.xz", "install.py",
                 "install_publisher.py", "verify_publisher.py", "new_project.py", "QUICKSTART.md"):
        if name not in asset_rows:
            raise ValueError("authenticated candidate omits a required production consumer asset: " + name)

    # Build a fresh external policy, then establish positive proof before any installer side effect.
    consumers_root = work / "consumers"
    install_prefix = consumers_root / "absolute-a/sdk-0.1.0"
    probe_rows = run_negative_probes(
        bundle, policy_path, work, install_prefix,
        lambda candidate, policy_value, label: _expect_verify_rejection(
            supervisor, python, candidate, policy_value, label))

    sdk_root = work / "verified-source-sdk"
    sdk_info_raw = ci_sdk._extract_sdk_archive(
        bundle / "sdk.tar.xz", sdk_root, asset_rows["sdk.tar.xz"]["sha256"],
        asset_rows["sdk.tar.xz"]["bytes"], 94)
    sdk_info = {**sdk_info_raw, "component_info": ci_sdk._component_rows_from_sdk(sdk_info_raw, host)}
    component_info = sdk_info["component_info"]
    sdk_manifest = sdk_info["manifest"]
    if sdk_manifest.get("source_identity") != identity["source_sha"]:
        raise ValueError("candidate SDK source commit differs from the external protected source policy")
    component_staging = work / "component-staging"
    component_staging.mkdir(mode=0o700)
    rust_root, rust_archives, rust_extracts = ci_sdk._install_rust(
        host_rows, reference_inputs, work, work / "component-staging", supervisor)
    version = supervisor.run_text([str(rust_root / "bin/rustc"), "-Vv"], cwd=work,
                                  label="verify-consumer-rust-identity", timeout=30)
    if ("commit-hash: " + reference_inputs["rust_commit"] not in version
            or "LLVM version: " + reference_inputs["rust_llvm"] not in version
            or "host: " + TARGETS[host] not in version):
        raise ValueError("installed Rust prerequisite differs from the pinned release profile")
    staging = {"rust": rust_root}
    component_staging = work / "component-staging"
    for name in ("toolchain", "collector", "csdk", "vendor"):
        (component_staging / name).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    toolchain, toolchain_pin, toolchain_extract = ci_sdk._extract_pinned_component(
        host_rows["toolchain"], "toolchain", work, component_staging / "toolchain", supervisor)
    collector, collector_pin, collector_extract = ci_sdk._extract_pinned_component(
        host_rows["collector"], "collector", work, component_staging / "collector", supervisor,
        component_info["collector"]["manifest"])
    staging.update({"toolchain": toolchain, "collector": collector})
    shared_inputs = reference_inputs["shared"]
    shared_receipts = {}
    for name in ("csdk", "vendor"):
        pin = (ci_sdk.portable_csdk_prerequisite(reference_inputs)
               if name == "csdk" else shared_inputs[name])
        root, row = ci_sdk._extract_local_component(
            pin, name, component_staging / name, supervisor)
        staging[name] = root
        shared_receipts[name] = row
    cargo_manifest = component_info["cargo"]["manifest"]
    ci_auth.cargo_matches((bundle / f"cargo-{host}.tar.xz").read_bytes(), cargo_manifest)
    cargo_root = component_staging / "cargo"
    cargo_inventory = _extract_flat_cargo(bundle / f"cargo-{host}.tar.xz", cargo_root, cargo_manifest)
    staging["cargo"] = cargo_root
    ordered_components = {name: staging[name] for name in
                          ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")}
    component_inventories = {name: ci_sdk.verify_component(root, component_info[name]["manifest"], name)
                             for name, root in ordered_components.items()}
    supervisor.check_limits("all six verified consumer prerequisites")

    commands, quickstart_sha = _recipe_commands(bundle)
    consumer_report = _install_and_run_recipe(
        bundle, work, output, python, supervisor, host, sdk_info, ordered_components,
        reference, commands)
    if len(consumer_report["retained_native"]) != 5:
        raise ValueError("consumer output must retain exactly the five matched native variants")
    _assert_source_clean(identity["source_sha"])
    supervisor.check_limits("completed consumer qualification")
    result = {
        "schema": RESULT_SCHEMA, "status": "PASS_HOSTED_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE",
        "host": host, "source_policy": {
            "source_sha": identity["source_sha"], "workflow_sha": identity["workflow_sha"],
            "source_ref": "refs/heads/main", "inputs_manifest_sha256": policy["inputs_manifest_sha256"],
            "external_policy_sha256": sha256(policy_path),
            "tool_manifest_sha256": sha256(manifest_path),
        },
        "python_bootstrap": {"archive_sha256": python_bootstrap["archive_sha256"],
                              "runtime_sha256": python_bootstrap["runtime_sha256"]},
        "tools": tool_receipt["tools"], "roots": tool_receipt["roots"],
        "candidate": {"release_manifest_sha256": sha256(bundle / "release.json"),
                      "bundle_copy": bundle_copy, "version": candidate_manifest["version"],
                      "sdk_manifest_sha256": sdk_info["manifest_sha256"],
                      "sdk_archive_sha256": asset_rows["sdk.tar.xz"]["sha256"],
                      "qualification_only": False},
        "negative_verification": probe_rows,
        "protected_source_positive_verification": {
            "process": initial_row, "status": initial_verify["status"],
            "release_manifest_sha256": initial_verify["release_manifest_sha256"],
            "authentication": initial_verify["authentication"]},
        "provisioning": {"components": component_inventories,
                         "rust_archives": rust_archives, "rust_installer": rust_extracts,
                         "toolchain": {"pin": toolchain_pin, "extraction": toolchain_extract},
                         "collector": {"pin": collector_pin, "extraction": collector_extract},
                         "shared": shared_receipts,
                         "cargo_archive_sha256": asset_rows[f"cargo-{host}.tar.xz"]["sha256"],
                         "cargo_inventory": cargo_inventory},
        "consumer_recipe": {"quickstart_sha256": quickstart_sha,
                            "commands_per_root": list(commands),
                            "roots": consumer_report["commands"],
                            "uninstall": consumer_report["uninstall"],
                            "prerequisite_inventories_after_uninstall":
                                consumer_report["prerequisite_inventories_after_uninstall"],
                            "unrelated_sibling_marker_sha256":
                                consumer_report["unrelated_sibling_marker_sha256"]},
        "retained_native": consumer_report["retained_native"],
        "budgets": {"workspace_bytes": ci_sdk.MAX_WORK_BYTES,
                    "rss_bytes": ci_sdk.MAX_RSS_BYTES, "log_bytes": ci_sdk.MAX_LOG_BYTES,
                    "command_seconds": ci_sdk.MAX_COMMAND_SECONDS,
                    "output_bytes_limit": MAX_OUTPUT_BYTES},
        "capacity_preflight": capacity,
        "peaks": {"checkout_bytes": supervisor.checkout_bytes,
                  "workspace_bytes": supervisor.peak_workspace,
                  "rss_bytes": supervisor.peak_rss, "logs_bytes": supervisor.peak_logs,
                  "commands": supervisor.commands},
        "claims": {"publisher_evidence_verified": True,
                    "publisher_release_acceptance": False,
                    "r1_accepted": False, "signed": False, "published": False,
                    "aros_guest_run": False},
    }
    result_path = output / "consumer-qualification.json"
    if result_path.exists() or result_path.is_symlink():
        raise ValueError("consumer qualification output already exists")
    base_output_bytes = ci_sdk.directory_bytes(output)
    result["output_bytes"] = 0
    for _ in range(3):
        result_raw = canonical_json(result)
        expected_output_bytes = base_output_bytes + len(result_raw)
        if result["output_bytes"] == expected_output_bytes:
            break
        result["output_bytes"] = expected_output_bytes
    result_raw = canonical_json(result)
    output_bytes = base_output_bytes + len(result_raw)
    if output_bytes > MAX_OUTPUT_BYTES:
        raise ValueError("consumer metadata and native payloads exceed the 32 MiB output limit")
    result["output_bytes"] = output_bytes
    result_raw = canonical_json(result)
    if base_output_bytes + len(result_raw) != output_bytes:
        raise RuntimeError("consumer output receipt size calculation did not converge")
    # This is the final operation: a successfully written PASS receipt cannot
    # be followed by a later validation error and survive as a false pass.
    with result_path.open("xb") as stream:
        stream.write(result_raw)
        stream.flush()
        os.fsync(stream.fileno())
    result_path.chmod(0o600)
    return result


def _write_failure(output: Path, error: BaseException, stage: str) -> dict | None:
    if not output.is_dir() or output.is_symlink():
        return None
    path = output / "consumer-qualification.json"
    if path.exists() or path.is_symlink():
        return None
    value = {"schema": RESULT_SCHEMA, "status": "FAILED",
             "failed_stage": stage, "error_type": type(error).__name__,
             "error": str(error)[:2000],
             "claims": {"publisher_release_acceptance": False, "r1_accepted": False,
                        "signed": False, "published": False},
             "preserved_work": True}
    try:
        path.write_bytes(canonical_json(value))
        path.chmod(0o600)
        return value
    except OSError:
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("bootstrap-tools", "qualify"):
        child = commands.add_parser(command)
        child.add_argument("--work", type=Path, required=True)
        child.add_argument("--output", type=Path, required=True)
        child.add_argument("--python-bootstrap-root", type=Path, required=True)
        if command == "qualify":
            child.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    stage = args.command
    output = args.output
    try:
        if not sys.flags.isolated or not sys.dont_write_bytecode:
            raise ValueError("run ci_verify.py under the pinned Python with -I -B")
        if args.command == "bootstrap-tools":
            result = bootstrap_tools(args.work, args.output, args.python_bootstrap_root)
        else:
            result = qualify(args.bundle, args.work, args.output, args.python_bootstrap_root)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except BaseException as error:
        failure = _write_failure(output, error, stage)
        if failure:
            print(json.dumps(failure, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        else:
            print(f"ami-rust hosted consumer qualification failed: {type(error).__name__}: {str(error)[:2000]}",
                  file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

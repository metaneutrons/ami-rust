#!/usr/bin/env python3
"""Transitional internal coordination for the Rust SDK-v2 producer.

The Rust xtask owns SDK/release composition. This helper reuses immutable
component archives and the existing protected signing workflow. It neither
publishes nor accepts RC1; retiring this internal Python is RC4 work.
"""
from __future__ import annotations

import argparse
import io
import itertools
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import sys
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "release"))
import ci_auth as auth
import ci_sdk

NATIVE_LIMIT = 64 * 1024**2
HOST_TRIPLES = {"linux-x86_64": "x86_64-unknown-linux-gnu", "macos-aarch64": "aarch64-apple-darwin"}


def native_inputs():
    value = auth.parsed(auth.read(ROOT / "release/native-tooling-inputs.json"))
    lock_raw = auth.read(ROOT / "tooling/Cargo.lock")
    workspace = tomllib.loads(auth.read(ROOT / "tooling/Cargo.toml").decode())
    if workspace["workspace"]["package"]["version"] != value["cli_version"]:
        raise ValueError("native CLI version differs from the source workspace")
    lock = value["cargo_lock"]
    if (lock["path"] != "tooling/Cargo.lock" or len(lock_raw) != lock["bytes"]
            or auth.sha(lock_raw) != lock["sha256"]):
        raise ValueError("native Cargo lock differs from the producer pin")
    packages = tomllib.loads(lock_raw.decode())["package"]
    expected = sorted((p["name"], p["version"], p["checksum"]) for p in packages if "source" in p)
    observed = [(p["name"], p["version"], p["sha256"]) for p in value["registry_crates"]]
    if (observed != expected or len(expected) != 29
            or any(p["source"] != "registry+https://github.com/rust-lang/crates.io-index"
                   for p in packages if "source" in p)):
        raise ValueError("native archive selection differs from the reviewed Cargo lock")
    # Reuse the consumer-compatible validation before running any build.
    auth.input_manifest_for_sdk(ROOT, value["sdk_version"])
    return value


def current_host():
    host = {("Linux", "x86_64"): "linux-x86_64", ("Darwin", "arm64"): "macos-aarch64"}.get(
        (platform.system(), platform.machine()))
    if host is None:
        raise ValueError("unsupported native producer host")
    return host


def fresh(path):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("fresh native producer directory required")
    if path == ROOT or ROOT in path.resolve().parents:
        raise ValueError("native producer work must be outside source")
    path.mkdir(mode=0o700)
    return path.resolve(strict=True)


def _python_root_for(work, explicit=None):
    if explicit is not None:
        return Path(explicit).absolute()
    return Path(work).absolute().parent / "ami-rust-python-bootstrap"


def write(path, raw, mode=0o644):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(mode)


def _clean_child_env(env):
    """Keep subprocess environments explicit and remove registry credentials."""
    env = dict(env)
    env.pop("CARGO_REGISTRY_TOKEN", None)
    env.pop("CARGO_REGISTRIES_CRATES_IO_TOKEN", None)
    return env


def _overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def _static_directory(path, label):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_dir():
        raise ValueError("native static input must be a real directory: " + label)
    path = path.resolve(strict=True)
    size, logs = ci_sdk.directory_accounting(path)
    return path, {"label": label, "path": path.name,
                  "regular_file_bytes": size, "log_bytes": logs}


def _add_static_roots(supervisor, roots):
    """Charge immutable external roots once; directory accounting never follows links."""
    rows = getattr(supervisor, "native_static_roots", [])
    paths = {Path(row["resolved_path"]) for row in rows}
    managed = [ROOT.resolve(strict=True), supervisor.work.resolve(strict=True),
               supervisor.output.resolve(strict=False), supervisor.python_root.resolve(strict=True)]
    for label, value in roots:
        path, row = _static_directory(value, label)
        if any(_overlap(path, root) for root in managed):
            raise ValueError("native static input overlaps a managed root: " + label)
        if any(_overlap(path, prior) for prior in paths):
            raise ValueError("native static input roots overlap: " + label)
        paths.add(path)
        row["resolved_path"] = str(path)
        rows.append(row)
        supervisor.checkout_bytes += row["regular_file_bytes"]
        supervisor.native_static_log_bytes = getattr(supervisor, "native_static_log_bytes", 0) + row["log_bytes"]
    supervisor.native_static_roots = rows
    if not hasattr(supervisor, "native_log_ceiling"):
        supervisor.native_log_ceiling = supervisor.limits["log_bytes"]
    supervisor.limits["log_bytes"] = supervisor.native_log_ceiling - supervisor.native_static_log_bytes
    if supervisor.limits["log_bytes"] < 0:
        raise RuntimeError("static native inputs already exceed the aggregate log ceiling")
    if not hasattr(supervisor, "native_peak_logs"):
        supervisor.native_peak_logs = 0
    return rows


def _make_supervisor(work, output, python_root, env, *, static_roots=()):
    work, output = Path(work).absolute(), Path(output).absolute()
    python_root = Path(python_root).absolute()
    if work.is_symlink() or output.is_symlink() or python_root.is_symlink():
        raise ValueError("native supervisor roots must not be symlinks")
    if not work.is_dir() or (output.exists() and not output.is_dir()):
        raise ValueError("native supervisor work and output roots must be directories")
    ci_sdk.verify_python_bootstrap(python_root, current_host())
    roots = [ROOT.resolve(strict=True), work.resolve(strict=True),
             output.resolve(strict=False), python_root.resolve(strict=True)]
    if len(set(roots)) != len(roots) or any(_overlap(a, b) for i, a in enumerate(roots) for b in roots[i + 1:]):
        raise ValueError("native supervisor managed roots must be distinct and nonoverlapping")
    if any(root == ROOT.resolve(strict=True) or ROOT.resolve(strict=True) in root.parents
           for root in roots[1:]):
        raise ValueError("native supervisor roots must remain outside the source checkout")
    supervisor = ci_sdk.Supervisor(work, output, python_root, _clean_child_env(env))
    supervisor.native_static_roots = []
    supervisor.native_static_log_bytes = 0
    supervisor.native_peak_logs = 0
    supervisor.native_log_ceiling = supervisor.limits["log_bytes"]
    _add_static_roots(supervisor, static_roots)
    _check_limits(supervisor, "initial native inputs")
    return supervisor


def _record_new_logs(supervisor, before):
    rows = supervisor.commands[before:]
    static_logs = getattr(supervisor, "native_static_log_bytes", 0)
    for row in rows:
        row["log_peak_observed_bytes"] += static_logs
        supervisor.native_peak_logs = max(supervisor.native_peak_logs,
                                          row["log_peak_observed_bytes"])
    return rows


def _supervised_run(supervisor, command, *, label, cwd=ROOT, timeout=1200, expected=0):
    before = len(supervisor.commands)
    try:
        row = supervisor.run([str(part) for part in command], cwd=Path(cwd), label=label, timeout=timeout)
    except RuntimeError:
        rows = _record_new_logs(supervisor, before)
        if (expected != 0 and len(rows) == 1 and rows[0].get("label") == label
                and rows[0].get("exit_code") == expected and rows[0].get("stop_reason") is None):
            return rows[0]
        raise
    rows = _record_new_logs(supervisor, before)
    if expected != 0:
        raise RuntimeError(f"supervisor returned without rejecting expected-failure command {label}")
    if row.get("exit_code") != expected:
        raise ValueError(f"native command {label} returned {row.get('exit_code')}, expected {expected}")
    return row


def _supervised_text(supervisor, command, *, label, cwd=ROOT, timeout=60):
    row = _supervised_run(supervisor, command, label=label, cwd=cwd, timeout=timeout)
    return (supervisor.work / row["stdout_log"]).read_text(errors="replace")


def _check_limits(supervisor, label):
    supervisor.check_limits(label)
    current_logs = supervisor.logs_bytes() + getattr(supervisor, "native_static_log_bytes", 0)
    supervisor.native_peak_logs = max(getattr(supervisor, "native_peak_logs", 0), current_logs)


def _supervision_summary(supervisor, auxiliary_commands=(), auxiliary_insert_at=None):
    commands = list(supervisor.commands)
    if auxiliary_commands:
        index = len(commands) if auxiliary_insert_at is None else auxiliary_insert_at
        commands[index:index] = list(auxiliary_commands)
    limits = {"rss_bytes": ci_sdk.MAX_RSS_BYTES,
              "workspace_bytes": ci_sdk.MAX_WORK_BYTES,
              "log_bytes": ci_sdk.MAX_LOG_BYTES,
              "seconds": ci_sdk.MAX_COMMAND_SECONDS}
    return {
        "schema": "ami-rust-native-supervision-v1",
        "limits": limits,
        "static_input_root_count": len(supervisor.native_static_roots),
        "static_input_roots": [{key: value for key, value in row.items() if key != "resolved_path"}
                                for row in supervisor.native_static_roots],
        "peak_rss_observed_bytes": max([0, supervisor.peak_rss] +
                                        [row.get("rss_peak_observed_bytes", 0) for row in commands]),
        "peak_workspace_observed_bytes": max([0, supervisor.peak_workspace] +
                                             [row.get("managed_peak_observed_bytes", 0) for row in commands]),
        "peak_log_observed_bytes": max([0, supervisor.native_peak_logs] +
                                       [row.get("log_peak_observed_bytes", 0) for row in commands]),
        "commands": commands,
    }


def build_tools(work, host_rust, output, python_root, *, static_roots=()):
    native_inputs()
    host_rust = Path(host_rust).absolute()
    if host_rust.is_symlink() or not host_rust.is_dir():
        raise ValueError("native host Rust root must be a real directory")
    toolchain = host_rust.resolve(strict=True) / "toolchain"
    rust = toolchain / "bin"
    for name in ("rustc", "cargo", "rustdoc"):
        if (rust / name).is_symlink() or not (rust / name).is_file():
            raise ValueError("pinned native host Rust executable is missing: " + name)
    for name in ("home", "cargo-home", "tmp"):
        (work / name).mkdir(mode=0o700)
    env = {"PATH": str(rust) + ":/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work / "home"),
           "TMPDIR": str(work / "tmp"), "LC_ALL": "C", "CARGO_BUILD_JOBS": "2",
           "CARGO_HOME": str(work / "cargo-home"), "CLI_CARGO": str(rust / "cargo"),
           "RUSTC": str(rust / "rustc"), "RUSTDOC": str(rust / "rustdoc")}
    supervisor = _make_supervisor(work, output, python_root, env,
                                  static_roots=[("host-rust", host_rust), *static_roots])
    compiler = _supervised_text(supervisor, [str(rust / "rustc"), "-Vv"], cwd=ROOT,
                                label="native-rustc-identity", timeout=30)
    if ("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" not in compiler
            or "host: " + HOST_TRIPLES[current_host()] not in compiler):
        raise ValueError("native producer host compiler differs from the pinned bootstrap")
    _supervised_run(supervisor, [rust / "cargo", "fetch", "--locked", "--manifest-path", ROOT / "tooling/Cargo.toml"],
                    label="native-cargo-fetch")
    _supervised_run(supervisor, ["/bin/bash", ROOT / "tools/build-native-cli.sh", work / "target"],
                    label="native-build-cli")
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
        f"--remap-path-prefix={ROOT}=/ami-rust", f"--remap-path-prefix={work / 'cargo-home'}=/cargo"])
    if current_host() == "macos-aarch64":
        env["DYLD_LIBRARY_PATH"] = str(toolchain / "lib")
    supervisor.env = _clean_child_env(env)
    _supervised_run(supervisor, [rust / "cargo", "build", "--release", "--locked", "--offline", "--package",
                                 "ami-rust-xtask", "--manifest-path", ROOT / "tooling/Cargo.toml",
                                 "--target-dir", work / "target"], label="native-build-xtask")
    cli = work / "target/release/ami-rust"
    cli_identity_raw = _supervised_text(supervisor, [str(cli), "--version"], cwd=ROOT,
                                        label="native-cli-identity", timeout=60)
    write(work / "cli-identity.json", cli_identity_raw.encode())
    cli_identity = auth.parsed(auth.read(work / "cli-identity.json"))
    if cli_identity.get("schema") != "ami-rust-version-v1" or cli_identity.get("cli_version") != native_inputs()["cli_version"]:
        raise ValueError("built native CLI reports a different version")
    _check_limits(supervisor, "native build tools")
    return cli, work / "target/release/ami-rust-xtask", env, supervisor


def obtain_legacy(work, pin):
    """Read the hash-pinned immutable capsule; never execute its Python files."""
    with urllib.request.urlopen(pin["url"], timeout=120) as response:
        raw = response.read(pin["bytes"] + 1)
    if len(raw) != pin["bytes"] or auth.sha(raw) != pin["sha256"]:
        raise ValueError("immutable component capsule differs from its pin")
    plain = auth.bounded_xz(raw, NATIVE_LIMIT)
    members = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
        for member in archive:
            path = member.name.rstrip("/") if member.isdir() else member.name
            auth.rel(path)
            if member.isdir():
                continue
            if (not member.isfile() or path in members or member.size > auth.FILE_LIMIT
                    or len(members) >= 512):
                raise ValueError("unsupported immutable capsule member")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("immutable capsule member unreadable")
            members[path] = stream.read(member.size + 1)
            if len(members[path]) != member.size:
                raise ValueError("immutable capsule member truncated")
    if "release.json" not in members or sum(map(len, members.values())) > NATIVE_LIMIT:
        raise ValueError("immutable capsule has an unsupported layout")
    import public_transport
    public_transport._validate_path_set(list(members))
    root = work / "accepted-legacy"
    root.mkdir(mode=0o700)
    for name, raw in members.items():
        write(root / name, raw)
    return root


def producer(identity):
    return {"kind": "protected-github-actions", "repository": auth.REPO, "workflow": auth.WORKFLOW,
            **identity, "acceptance": "R1 acceptance and publication are separate gates"}


def host_build(work, output, host_rust, host, python_root=None):
    identity = auth.context(ROOT)
    if host != current_host():
        raise ValueError("producer host selection differs from the actual runner")
    config = native_inputs()
    python_root = _python_root_for(work, python_root)
    work = fresh(work)
    output = fresh(output)
    cli, xtask, env, supervisor = build_tools(work, host_rust, output, python_root)
    legacy = obtain_legacy(work, config["legacy_release"])
    _check_limits(supervisor, "native source capsule")
    draft = work / "sdk-draft"
    _supervised_run(supervisor, [xtask, "native-sdk", "--source-sdk", legacy / "sdk.tar.xz",
                                 "--source-commit", identity["source_sha"], "--version", config["sdk_version"],
                                 "--output", draft], label="native-compose-sdk")
    for name, source in (("ami-rust", cli), ("sdk.tar.xz", draft / "sdk.tar.xz"),
                         ("sdk-manifest.json", draft / "sdk-manifest.json")):
        write(output / name, auth.read(source), 0o755 if name == "ami-rust" else 0o644)
    _check_limits(supervisor, "native host output")
    report = {"schema": "ami-rust-native-host-producer-v1", "status": "UNSIGNED_HOST_OUTPUT",
              "host": host, "source": identity, "sdk_version": config["sdk_version"],
              "cli_version": config["cli_version"], "cargo_lock": config["cargo_lock"],
              "cli_identity": auth.parsed(auth.read(work / "cli-identity.json")),
              "supervision": _supervision_summary(supervisor),
              "files": [{"path": p.name, "bytes": p.stat().st_size, "sha256": auth.sha(auth.read(p))}
                        for p in sorted(output.iterdir())],
              "claim": "Native host output only; signatures, consumer qualification and release acceptance remain separate"}
    write(output / "native-host-producer.json", auth.encoded(report))
    _check_limits(supervisor, "native host producer receipt")
    report["supervision"] = _supervision_summary(supervisor)
    (output / "native-host-producer.json").write_bytes(auth.encoded(report))
    _check_limits(supervisor, "native host producer receipt")
    return report


def validate_host_payload(payload, host, identity, config):
    payload = Path(payload).absolute()
    if payload.is_symlink() or not payload.is_dir():
        raise ValueError("native host output root must be a real directory")
    payload = payload.resolve(strict=True)
    report = auth.parsed(auth.read(auth.below(payload, "native-host-producer.json")))
    if (report.get("schema") != "ami-rust-native-host-producer-v1"
            or report.get("status") != "UNSIGNED_HOST_OUTPUT" or report.get("source") != identity
            or report.get("host") != host or report.get("sdk_version") != config["sdk_version"]
            or report.get("cli_version") != config["cli_version"] or report.get("cargo_lock") != config["cargo_lock"]
            or report.get("cli_identity", {}).get("cli_version") != config["cli_version"]):
        raise ValueError("native host output selects a different source, run, host or lock")
    rows = report.get("files")
    if (not isinstance(rows, list) or len(rows) != 3
            or {r.get("path") for r in rows} != {"ami-rust", "sdk.tar.xz", "sdk-manifest.json"}):
        raise ValueError("native host output inventory is incomplete")
    for row in rows:
        raw = auth.read(auth.below(payload, row["path"]))
        if len(raw) != row["bytes"] or auth.sha(raw) != row["sha256"]:
            raise ValueError("native host output bytes differ from their build report")
    return payload


def _check_local_launcher(cli, payloads, host=None):
    host = current_host() if host is None else host
    if host not in payloads or auth.read(cli) != auth.read(payloads[host] / "ami-rust"):
        raise ValueError("native local CLI differs byte-for-byte from the selected host launcher")


def compose(work, output, host_rust, payloads, python_root=None, *, static_roots=()):
    identity = auth.context(ROOT)
    config = native_inputs()
    python_root = _python_root_for(work, python_root)
    work = fresh(work)
    output = Path(output).absolute()
    payloads = {host: validate_host_payload(payloads[host], host, identity, config) for host in auth.HOSTS}
    external_roots = [("native-host-" + host, payloads[host]) for host in auth.HOSTS]
    external_roots.extend(static_roots)
    cli, xtask, env, supervisor = build_tools(work, host_rust, output, python_root,
                                              static_roots=external_roots)
    _check_local_launcher(cli, payloads)
    if auth.read(payloads[auth.HOSTS[0]] / "sdk.tar.xz") != auth.read(payloads[auth.HOSTS[1]] / "sdk.tar.xz"):
        raise ValueError("native host SDK archives are not byte identical")
    legacy = obtain_legacy(work, config["legacy_release"])
    _check_limits(supervisor, "native release source capsule")
    producer_path = work / "declared-producer.json"
    write(producer_path, auth.encoded(producer(identity)))
    _supervised_run(supervisor, [xtask, "native-release", "--source-bundle", legacy,
                                 "--source-commit", identity["source_sha"], "--version", config["sdk_version"],
                                 "--linux-cli", payloads["linux-x86_64"] / "ami-rust",
                                 "--macos-cli", payloads["macos-aarch64"] / "ami-rust",
                                 "--producer-file", producer_path, "--native-notices", ROOT / "tooling/third-party",
                                 "--output", output],
                    label="native-compose-release")
    output = Path(output)
    if auth.read(output / "sdk.tar.xz") != auth.read(payloads[auth.HOSTS[0]] / "sdk.tar.xz"):
        raise ValueError("assembled SDK differs from both host producer outputs")
    write(output / ".auth/inputs.json", auth.encoded(auth.input_manifest_for_sdk(ROOT, config["sdk_version"])))
    if sum(p.stat().st_size for p in output.rglob("*") if p.is_file()) > NATIVE_LIMIT - 1024**2:
        raise ValueError("native candidate exceeds its prospective authentication profile")
    _check_limits(supervisor, "native assembled candidate")
    return {"schema": "ami-rust-native-publisher-candidate-v1", "status": "UNSIGNED_CANDIDATE",
            "source": identity, "manifest_sha256": auth.sha(auth.read(output / "release.json")),
            "supervision": _supervision_summary(supervisor)}


def audit(work, bundle, host_rust, payloads, python_root=None):
    work = Path(work)
    expected = work.parent / (work.name + "-expected")
    bundle = Path(bundle).absolute()
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("native signer candidate must be a real directory")
    bundle = bundle.resolve(strict=True)
    report = compose(work, expected, host_rust, payloads, python_root,
                     static_roots=[("signed-candidate", bundle)])
    required = {p.relative_to(expected).as_posix() for p in expected.rglob("*") if p.is_file()}
    observed = set()
    for path in bundle.rglob("*"):
        if stat.S_ISDIR(path.lstat().st_mode):
            continue
        name = path.relative_to(bundle).as_posix()
        if name not in required or auth.read(auth.below(bundle, name)) != auth.read(auth.below(expected, name)):
            raise ValueError("native signer candidate differs from independent composition: " + name)
        observed.add(name)
    if required != observed:
        raise ValueError("native signer candidate inventory is incomplete")
    digests = {name: auth.sha(auth.read(bundle / name)) for name in auth.SUBJECTS}
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a") as stream:
            for key, name in (("manifest", "release.json"), ("sdk", "sdk.tar.xz"), ("utility", "SHAUTIL")):
                stream.write(f"{key}={digests[name]}\n")
    return {"schema": "ami-rust-native-signer-audit-v1", "status": "PASS_UNSIGNED_CANDIDATE_ONLY",
            "source": report["source"], "subjects": digests,
            "supervision": report["supervision"]}


def verify_lifecycle(work, output, bundle, host_rust, python_root, outer):
    """Real native verification/install/removal, with an independently built CLI.

    Internal Python coordinates this test. The Rust observer admits each
    consumer result only after its adapter evidence is complete and valid.
    Complete RC1 parity, migration and release acceptance remain separate gates.
    """
    import ci_verify
    identity = auth.context(ROOT)
    config = native_inputs()
    python_root = _python_root_for(work, python_root)
    work = fresh(work)
    output = fresh(output)
    bundle = Path(bundle).absolute()
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("native lifecycle candidate must be a real directory")
    bundle = bundle.resolve(strict=True)
    outer = Path(outer).absolute()
    if outer.is_symlink() or not outer.is_dir():
        raise ValueError("native outer candidate must be a real directory")
    outer = outer.resolve(strict=True)
    cli, xtask, env, supervisor = build_tools(work, host_rust, output, python_root,
                                          static_roots=[("signed-candidate", bundle), ("outer-candidate", outer)])
    _supervised_run(supervisor, [Path(host_rust) / "toolchain/bin/cargo", "build", "--release", "--locked", "--offline",
        "--manifest-path", ROOT / "tools/consumer-enforcement-adapter/Cargo.toml",
        "--target-dir", work / "consumer-adapter-target"], label="native-build-consumer-adapter")
    adapter = work / "consumer-adapter-target/release/consumer-enforcement-adapter"
    verifier_work = work.parent / "ami-rust-native-verifier-work"
    verifier_metadata = work.parent / "ami-rust-native-verifier-metadata"
    bootstrap_insert_at = len(supervisor.commands)
    # These roots remain live but unchanged while the separate verifier
    # supervisor downloads and probes its tools. Its source/Python roots are
    # already counted there; charge each other root once, including live logs.
    live_samples = [ci_sdk.directory_accounting(root) for root in (work, output)]
    extra_bytes = sum(sample[0] for sample in live_samples)
    extra_bytes += sum(row["regular_file_bytes"] for row in supervisor.native_static_roots)
    extra_logs = sum(sample[1] for sample in live_samples) + supervisor.native_static_log_bytes
    tools = ci_verify.bootstrap_tools(verifier_work, verifier_metadata, python_root,
                                      additional_input_bytes=extra_bytes, additional_log_bytes=extra_logs)
    _add_static_roots(supervisor, [("verifier-work", verifier_work),
                                   ("verifier-metadata", verifier_metadata)])
    _check_limits(supervisor, "native verifier bootstrap")
    policy = {"schema": "ami-rust-publisher-trust-v2", "repository": auth.REPO, "workflow": auth.WORKFLOW,
              "workflow_sha": identity["workflow_sha"], "source_sha": identity["source_sha"],
              "source_ref": "refs/heads/main", "oidc_issuer": "https://token.actions.githubusercontent.com",
              "cert_identity": f"https://github.com/{auth.REPO}/{auth.WORKFLOW}@refs/heads/main",
              "inputs_manifest_sha256": auth.sha(auth.encoded(auth.input_manifest_for_sdk(ROOT, config["sdk_version"]))),
              "allowed_host_profiles": list(auth.HOSTS),
              **{name: {"path": tools["tools"][name]["path"], "sha256": tools["tools"][name]["sha256"]}
                 for name in ("gh", "cosign")},
              "gh_trusted_roots": tools["roots"]["gh"], "cosign_trusted_root": tools["roots"]["cosign"]}
    # Tool receipts may additionally describe roots' sizes. The public policy
    # deliberately admits only path and digest, as its Rust parser requires.
    for name in ("gh_trusted_roots", "cosign_trusted_root"):
        policy[name] = {key: policy[name][key] for key in ("path", "sha256")}
    policy_path = output / "native-publisher-policy.json"
    write(policy_path, auth.encoded(policy), 0o600)
    closure_path = output / "reviewed-consumer-inputs.json"
    write(closure_path, auth.encoded({"schema": "ami-rust-reviewed-consumer-inputs-v1", "source": identity,
        "publisher_inputs": auth.input_manifest_for_sdk(ROOT, config["sdk_version"]),
        "candidate_manifest_sha256": auth.sha(auth.read(bundle / "release.json")),
        "scope": "Reviewed source/component/vendor/package identities; each Rust observer additionally records exact runtime tools and phase policy."}), 0o600)
    for directory in (output / "observation-specs", output / "observations"):
        directory.mkdir(mode=0o700)
    commands = []

    def command(label, arguments, expected=0, *, executable=cli, disposable_refusal_state=None):
        stdout = output / (label + ".stdout.json")
        stderr = output / (label + ".stderr.log")
        spec = _consumer_observation_spec(work, python_root, executable, arguments, expected,
            policy_path, closure_path, [ROOT, *[row["resolved_path"] for row in supervisor.native_static_roots]],
            disposable_refusal_state=disposable_refusal_state)
        spec_path = output / "observation-specs" / (label + ".json")
        write(spec_path, auth.encoded(spec), 0o600)
        observed = output / "observations" / label
        record = _supervised_run(supervisor, [xtask, "native-consumer-observe", "--spec", spec_path,
            "--adapter", adapter, "--output", observed], cwd=work, label=label, timeout=1200)
        observation = auth.parsed(auth.read(observed / "observation.json"))
        if (observation.get("status") != "PASS_EXPECTED_CONSUMER_RESULT_AND_ADAPTER_EVIDENCE"
                or observation.get("expected_exit") != expected
                or observation.get("adapter_evidence", {}).get("child_exit_code") != expected):
            raise ValueError("native consumer result omitted complete admitted adapter evidence: " + label)
        shutil.copyfile(work / record["stdout_log"], stdout)
        shutil.copyfile(work / record["stderr_log"], stderr)
        commands.append({"label": label, "exit": expected, "expected_exit": expected,
                         "stdout_sha256": auth.sha(auth.read(stdout)),
                         "stderr_sha256": auth.sha(auth.read(stderr)),
                         "observation": observation,
                         "supervision_record": dict(record)})
        write(output / (label + ".result.json"), auth.encoded(commands[-1]))
        _check_limits(supervisor, "native lifecycle command " + label)
        return auth.read(stdout)

    command("01-real-native-verify", ["verify", "--bundle", bundle, "--policy", policy_path])
    for index, kind in enumerate(("gh", "cosign"), start=2):
        altered = work / ("altered-" + kind)
        shutil.copytree(bundle, altered)
        proof = altered / ".auth" / kind / "release.json.json"
        value = auth.parsed(auth.read(proof))
        row, key = ((value["dsseEnvelope"]["signatures"][0], "sig") if kind == "gh"
                    else (value["messageSignature"], "signature"))
        original = row[key]
        row[key] = ("A" if original[0] != "A" else "B") + original[1:]
        proof.write_bytes(auth.encoded(value))
        command(f"0{index}-altered-{kind}-signature", ["verify", "--bundle", altered, "--policy", policy_path], 2)
        diagnostic = (output / f"0{index}-altered-{kind}-signature.stderr.log").read_text()
        if "publisher verifier " not in diagnostic or f"/{kind} failed with" not in diagnostic:
            raise ValueError(f"altered {kind} signature did not reach the actual pinned verifier failure")
        shutil.rmtree(altered)
    altered = work / "altered-sdk"
    shutil.copytree(bundle, altered)
    with (altered / "sdk.tar.xz").open("ab") as stream:
        stream.write(b"isolated corruption counterprobe")
    command("04-altered-sdk", ["verify", "--bundle", altered, "--policy", policy_path], 2)
    shutil.rmtree(altered)
    install_area = work / "native-direct-install-area"
    install_area.mkdir(mode=0o700)
    prefix, pin = install_area / "native-install", install_area / "external-receipt.sha256"
    result = auth.parsed(command("05-native-install", ["install", "--bundle", bundle, "--policy", policy_path,
                                                        "--prefix", prefix, "--receipt-pin", pin]))
    receipt = result["receipt_sha256"]
    if (result["status"] != "installed" or auth.sha(auth.read(prefix / "install-receipt.json")) != receipt
            or pin.read_text().strip() != receipt):
        raise ValueError("native installation does not match its external receipt pin")
    installed_before = {p.relative_to(prefix).as_posix(): auth.sha(auth.read(p)) for p in prefix.rglob("*") if p.is_file()}
    command("06-occupied-install", ["install", "--bundle", bundle, "--policy", policy_path, "--prefix", prefix], 2)
    command("07-wrong-removal-pin", ["uninstall", "--prefix", prefix, "--receipt-sha256", "0" * 64], 2)
    installed_after = {p.relative_to(prefix).as_posix(): auth.sha(auth.read(p)) for p in prefix.rglob("*") if p.is_file()}
    if installed_before != installed_after:
        raise ValueError("refused native lifecycle operation changed installed user data")
    removed = auth.parsed(command("08-native-uninstall", ["uninstall", "--prefix", prefix, "--receipt-sha256", receipt]))
    if removed["status"] != "uninstalled" or prefix.exists() or pin.read_text().strip() != receipt:
        raise ValueError("native uninstall did not preserve the external pin and remove only its installation")
    package_lifecycle = _qualify_native_package(
        work, output, outer, bundle, cli, xtask, supervisor, policy_path, identity, config, command)
    report = {"schema": "ami-rust-native-direct-lifecycle-v1", "status": "PASS_NATIVE_LIFECYCLE_NOT_RC1_ACCEPTANCE",
              "package_lifecycle": package_lifecycle,
              "native_matrix": package_lifecycle["native_matrix"],
              "source": identity, "host": current_host(), "commands": commands,
              "supervision": _supervision_summary(supervisor, tools.get("commands", []),
                                                   bootstrap_insert_at),
              "manifest_sha256": auth.sha(auth.read(bundle / "release.json")),
              "cli_sha256": auth.sha(auth.read(cli)), "receipt_sha256": receipt,
              "remaining_gates": ["complete both-host no-Python observation", "complete cold/warm and negative lifecycle matrix",
                                  "complete cross-host R1-A2 native output and raw-metadata comparison",
                                  "complete migration, upgrade and retained replay R1-A4 matrix"],
              "claim": "Real inner/outer signatures, native direct and package preparation/build/removal/retained replay, plus the current-host two-root five-variant matrix; internal Python coordination is outside consumer scope. No-Python observation, cross-host R1-A2/A4 and RC1 acceptance remain open"}
    report_path = output / "native-direct-lifecycle.json"
    initial_report = auth.encoded(report)
    if ci_sdk.directory_bytes(output) + len(initial_report) > ci_sdk.MAX_OUTPUT_BYTES:
        raise ValueError("native lifecycle report would exceed the 32 MiB consumer artifact ceiling")
    write(report_path, initial_report)
    _check_limits(supervisor, "native direct lifecycle report")
    report["supervision"] = _supervision_summary(supervisor, tools.get("commands", []),
                                                  bootstrap_insert_at)
    final_report = auth.encoded(report)
    if (ci_sdk.directory_bytes(output) - report_path.stat().st_size + len(final_report)
            > ci_sdk.MAX_OUTPUT_BYTES):
        raise ValueError("native lifecycle report would exceed the 32 MiB consumer artifact ceiling")
    report_path.write_bytes(final_report)
    if ci_sdk.directory_bytes(output) > ci_sdk.MAX_OUTPUT_BYTES:
        raise ValueError("native lifecycle output exceeded the 32 MiB consumer artifact ceiling")
    _check_limits(supervisor, "native direct lifecycle report")
    return report


def _consumer_observation_spec(work, python_root, executable, arguments, expected,
                               policy_path, closure_path, readonly_roots, *, disposable_refusal_state=None):
    """Select each command's owned writes; Rust owns policy/runtime/report logic."""
    work = Path(work).resolve(strict=True)
    arguments = list(map(str, arguments))
    verb = arguments[0]
    phase = {"verify-package": "package-consistency", "native-package-verify": "package-authentication",
             "prepare": "prepare-refusal" if expected else "cold-prepare",
             "native-prepare-interruption": "cold-prepare",
             "new": "new-project", "migrate": "lock"}.get(verb, verb)
    if phase not in {"verify", "install", "uninstall", "package-consistency", "package-authentication",
                     "cold-prepare", "prepare-refusal", "check-inputs", "new-project", "lock", "build"}:
        raise ValueError("unsupported observed consumer command")

    def option(name):
        if name not in arguments:
            return None
        return Path(arguments[arguments.index(name) + 1]).absolute()

    writes = {work / "home", work / "tmp"}
    derived = None
    record = None
    state = option("--state")
    if state is not None and (state / "selection.json").is_file():
        record = state / "selection.json"
    for key in ("--selection", "--sdk-lock"):
        if option(key) is not None:
            record = option(key)
    legacy_python = None
    if verb == "migrate":
        record = option("--from-lock")
        if record is None or option("--output") is None:
            raise ValueError("observed migration requires an explicit legacy lock and output")
        legacy = auth.parsed(auth.read(record))
        if legacy.get("schema") != "ami-rust-project-lock-v1":
            raise ValueError("observed migration requires the inert legacy v1 record")
        legacy_python = Path(legacy["host"]["python"]).resolve(strict=True)
        if not legacy_python.is_file():
            raise ValueError("legacy Python identity is not a regular file")
    if phase == "cold-prepare":
        derived = {"role": "consumer-state-parent", "path": str(state.parent)}
        writes.add(state.parent.parent)
    elif phase == "build":
        target = option("--output-dir")
        derived = {"role": "consumer-build-parent", "path": str(target.parent)}
        writes.add(target.parent.parent)
    elif phase == "new-project":
        writes.add(option("--project").parent)
    elif phase == "lock":
        writes.add(option("--output").parent)
    elif phase == "package-authentication":
        writes.add(option("--work").parent)
    elif phase == "install" and not expected:
        writes.add(option("--prefix").parent)
        if option("--receipt-pin") is not None:
            writes.add(option("--receipt-pin").parent)
    elif phase == "uninstall" and not expected:
        writes.add(option("--prefix").parent)
    if disposable_refusal_state is not None:
        disposable = Path(disposable_refusal_state)
        if (phase != "prepare-refusal" or expected != 2 or state != disposable or record is not None
                or disposable == work or work not in disposable.parents
                or disposable.resolve(strict=True) != disposable):
            raise ValueError("disposable retry grant requires its exact existing partial private state")
        info = disposable.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("disposable retry state must be a private current-user directory")
        # Permit effects on this disposable partial state so an attempted write
        # cannot be hidden by a sandbox denial and mistaken for a refusal.
        writes.add(disposable)
    # Keep distinct native operation areas and remove duplicate/nested grants.
    writes = {root for root in writes if not any(root != other and other in root.parents for other in writes)}
    policy = auth.parsed(auth.read(policy_path))
    pin = auth.parsed(auth.read(ROOT / "release/ci-python-inputs.json"))["hosts"][current_host()]
    interpreter = Path(python_root) / "runtime" / pin["runtime_relative_path"]
    library_name = "libpython3.12.dylib" if current_host() == "macos-aarch64" else "libpython3.12.so.1.0"
    library = Path(python_root) / "runtime/python/lib" / library_name
    bindings = [Path(closure_path), Path(policy_path)] + ([record] if record else [])
    return {"schema": "ami-rust-consumer-observation-spec-v1", "phase": phase,
            "command": [str(Path(executable).resolve(strict=True)), *arguments], "expected_exit": expected,
            "cwd": str(work), "home": str(work / "home"), "tmp": str(work / "tmp"),
            "read_trees": [{"role": "work", "path": str(root)} for root in sorted({work, *map(Path, readonly_roots)})],
            "write_trees": [{"role": "work", "path": str(root)} for root in sorted(writes)],
            "read_files": [str(legacy_python)] if legacy_python else [],
            # The CLI checks account-home ownership independently of sandbox HOME.
            # Grant this directory literally, without reading its contents recursively.
            "read_directories": [str(Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True))],
            "executables": [policy[name]["path"] for name in ("gh", "cosign")]
                + ([str(option("--frontend").resolve(strict=True))]
                   if verb == "native-prepare-interruption" else []),
            "libraries": [], "deny_exec": sorted({str(interpreter), *([str(legacy_python)] if legacy_python else [])}),
            "deny_library": [str(library)],
            "component_record": str(record) if record else None, "derived": derived,
            "bindings": [{"path": str(path), "sha256": auth.sha(auth.read(path))} for path in bindings]}


def _publish_cold_root_diagnostics(work, output):
    diagnostics = Path(work) / "cold-root-diagnostics"
    output = Path(output)
    destination = output / "cold-root-diagnostics"
    if (diagnostics.is_symlink() or not diagnostics.is_dir()
            or output.is_symlink() or not output.is_dir()
            or destination.exists() or destination.is_symlink()):
        raise ValueError("cold-root diagnostics are not available at a fresh consumer destination")
    report = diagnostics / "report.json"
    raw = diagnostics / "raw"
    if (report.is_symlink() or not report.is_file() or raw.is_symlink() or not raw.is_dir()
            or report.stat().st_size > ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_REPORT_BYTES
            or ci_sdk.directory_bytes(raw) > ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_RAW_BYTES):
        raise ValueError("cold-root diagnostics exceed their bounded evidence profile")
    for path in diagnostics.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("cold-root diagnostics contain a nonregular entry")
    diagnostic_bytes = ci_sdk.directory_bytes(diagnostics)
    if ci_sdk.directory_bytes(output) + diagnostic_bytes > ci_sdk.MAX_OUTPUT_BYTES:
        raise ValueError("cold-root diagnostics would exceed the 32 MiB consumer artifact ceiling")
    inventory = ci_sdk.component_inventory(diagnostics)
    # Both roots share the runner filesystem. Rename the evidence so preserving
    # a failure does not duplicate up to 26 MiB of managed workspace.
    diagnostics.rename(destination)
    if (ci_sdk.component_inventory(destination) != inventory
            or ci_sdk.directory_bytes(output) > ci_sdk.MAX_OUTPUT_BYTES):
        raise ValueError("cold-root diagnostics changed or exceeded the consumer artifact ceiling")


def _preserve_matrix_metadata(artifacts, rows, work):
    """Keep only the three exact dependency archives until the matrix passes."""
    destination = Path(work) / "pending-native-metadata"
    if destination.exists() or destination.is_symlink():
        raise ValueError("native matrix metadata staging directory must be fresh")
    destination.mkdir(mode=0o700)
    retained = {}
    for crate in ci_sdk.METADATA_CRATES:
        names = [name for name in rows
                 if name.startswith("target/release/deps/")
                 and re.fullmatch("lib" + crate + r"-[0-9a-f]+\.rlib", Path(name).name)]
        if len(names) != 1:
            raise ValueError("expected exactly one raw metadata archive for " + crate)
        name = names[0]
        source = Path(artifacts).joinpath(*ci_sdk._safe_relative(name).parts)
        row = rows[name]
        if (source.is_symlink() or not source.is_file()
                or source.stat().st_size != row["bytes"] or ci_sdk.sha256(source) != row["sha256"]):
            raise ValueError("native matrix metadata archive differs from its canonical row: " + crate)
        target = destination.joinpath(*ci_sdk._safe_relative(name).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if target.stat().st_size != row["bytes"] or ci_sdk.sha256(target) != row["sha256"]:
            raise ValueError("preserved native matrix metadata archive differs: " + crate)
        retained[name] = row
    return destination, retained


def _matrix_diagnostic_allowance(supervisor, output):
    # Reserve the complete structured mismatch report even when raw evidence
    # must be omitted. Moving it to output adds no second workspace copy.
    available = min(ci_sdk.MAX_OUTPUT_BYTES - ci_sdk.directory_bytes(output),
                    ci_sdk.MAX_WORK_BYTES - supervisor.managed_bytes())
    if available < ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_REPORT_BYTES:
        raise ValueError("insufficient managed headroom for the native matrix diagnostic report")
    return min(ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_RAW_BYTES,
               available - ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_REPORT_BYTES)


def _qualify_native_build_matrix(work, state, frontend, output, supervisor, config, command):
    """Build the frozen five-variant set in two private roots through the signed frontend."""
    work, state, output = Path(work).absolute(), Path(state).absolute(), Path(output).absolute()
    host = current_host()
    inputs_path = ROOT / "release/ci-sdk-inputs.json"
    inputs = ci_sdk.read_json(inputs_path)
    reference_pin = inputs["native_reference"]
    reference = ci_sdk.validate_native_reference(
        ci_sdk.read_json(ROOT / reference_pin["path"], 2 * 1024**2),
        inputs, reference_pin["sha256"])

    prefix = state / ("sdk-" + config["sdk_version"])
    selection = state / "selection.json"
    receipt_path = prefix / "install-receipt.json"
    sdk_source = prefix / "sdk"
    if (state.is_symlink() or not state.is_dir() or prefix.is_symlink() or not prefix.is_dir()
            or selection.is_symlink() or not selection.is_file()
            or receipt_path.is_symlink() or not receipt_path.is_file()
            or sdk_source.is_symlink() or not sdk_source.is_dir()):
        raise ValueError("native matrix requires the cold-prepared installed SDK and selection")
    selection_bytes = auth.read(selection)
    selection_value = auth.parsed(selection_bytes)
    install_receipt_sha256 = auth.sha(auth.read(receipt_path))
    if selection_value.get("install_receipt_sha256") != install_receipt_sha256:
        raise ValueError("native matrix selection differs from the installed SDK receipt")
    sdk_inventory = ci_sdk.component_inventory(sdk_source)
    if (not (sdk_source / "Cargo.toml").is_file()
            or (sdk_source / "Cargo.toml").is_symlink()
            or not (sdk_source / "Cargo.lock").is_file()
            or (sdk_source / "Cargo.lock").is_symlink()):
        raise ValueError("installed native SDK source workspace is incomplete")
    sdk_inventory_sha256 = auth.sha(auth.encoded(sdk_inventory))
    sdk_source_bytes = sum(row["bytes"] for row in sdk_inventory["files"])

    matrix_root = work / "native matrix with spaces"
    if matrix_root.exists() or matrix_root.is_symlink():
        raise ValueError("native matrix private root must be fresh")
    matrix_root.mkdir(mode=0o700)
    layouts = []
    for name in ("sdk-layout-a", "sdk-layout-b-with-spaces"):
        root = matrix_root / name
        root.mkdir(mode=0o700)
        project = root / "sdk"
        shutil.copytree(sdk_source, project, symlinks=True, copy_function=shutil.copy2)
        copied_inventory = ci_sdk.component_inventory(project)
        if copied_inventory != sdk_inventory:
            raise ValueError("native matrix SDK project copy differs from the verified installation")
        lock_path = root / "project-lock.json"
        lock_label = "17-matrix-lock-" + name
        lock_output = auth.parsed(command(lock_label, ["lock", "--prefix", prefix,
            "--selection", selection, "--project", project, "--output", lock_path], executable=frontend))
        if (lock_output.get("status") != "locked" or lock_output.get("output") != str(lock_path)
                or lock_output.get("receipt_sha256") != install_receipt_sha256
                or lock_output.get("sdk_manifest_sha256") != auth.sha(auth.read(project / "contract/sdk.json"))
                or lock_path.is_symlink() or not lock_path.is_file()):
            raise ValueError("native matrix direct lock did not bind the prepared SDK and project")
        layouts.append({"name": name, "root": root, "project": project,
                        "lock": lock_path, "lock_sha256": ci_sdk.sha256(lock_path),
                        "receipt_sha256": lock_output["receipt_sha256"],
                        "sdk_manifest_sha256": lock_output["sdk_manifest_sha256"]})
        _check_limits(supervisor, "created native matrix direct lock " + name)

    first_by_variant = {}
    build_records = []
    metadata_stage = None
    metadata_rows = None
    for layout in layouts:
        build_parent = layout["root"] / "build outputs"
        build_parent.mkdir(mode=0o700)
        for variant, (package, feature_args) in ci_sdk.VARIANTS.items():
            # Each command starts with its own empty derived-executable parent.
            # Reusing build_parent would include the preceding variant's tools.
            derived_parent = build_parent / (variant + "-derived")
            derived_parent.mkdir(mode=0o700)
            build_output = derived_parent / "build"
            label = f"{layout['name']}/{variant}"
            build_label = "19-matrix-build-" + layout["name"] + "-" + variant
            arguments = ["build", "--sdk-lock", layout["lock"], "--output-dir", build_output,
                         "--", "build", "--manifest-path", layout["project"] / "Cargo.toml",
                         "--package", package, "--release", "--locked", "--offline", *feature_args]
            build_output_value = auth.parsed(command(build_label, arguments, executable=frontend))
            if (build_output_value.get("status") != "PASS"
                    or build_output_value.get("native_executable") != str(build_output / "artifacts/AMIRUST")
                    or build_output_value.get("receipt") != str(build_output / "build-receipt.json")):
                raise ValueError("native matrix frontend build did not report PASS: " + label)
            build_receipt = ci_sdk.read_json(build_output / "build-receipt.json", 4 * 1024**2)
            if (build_receipt.get("project_lock_sha256") != layout["lock_sha256"]
                    or build_receipt.get("sdk_manifest_sha256") != layout["sdk_manifest_sha256"]):
                raise ValueError("native matrix build receipt differs from its selected project lock: " + label)
            expected_rows = ci_sdk._expected_native_rows(reference, host, variant)
            try:
                result, native_file = ci_sdk._verify_native_receipt(
                    build_output, expected_rows, supervisor, label)
            except ValueError as error:
                if "canonical outputs differ from the accepted host reference" not in str(error):
                    raise
                observed, observed_native = ci_sdk._verify_native_receipt(
                    build_output, None, supervisor, label + "/reference-diagnostic")
                if layout is layouts[0]:
                    diagnostic_first_layout = "accepted-host-reference"
                    diagnostic_first_rows = expected_rows
                    diagnostic_first_snapshot = {}
                    diagnostic_first_native = expected_rows["AMIRUST"]
                else:
                    first = first_by_variant[variant]
                    diagnostic_first_layout = layouts[0]["name"]
                    diagnostic_first_rows = first["artifacts"]
                    diagnostic_first_snapshot = first["snapshot"]
                    diagnostic_first_native = {
                        "bytes": first["bytes"], "sha256": first["sha256"]}
                ci_sdk._write_cold_root_diagnostics(
                    work, variant, diagnostic_first_layout, layout["name"],
                    diagnostic_first_rows, observed["artifacts"], diagnostic_first_snapshot,
                    build_output / "artifacts", diagnostic_first_native, {
                        "bytes": observed_native.stat().st_size,
                        "sha256": ci_sdk.sha256(observed_native)},
                    raw_limit_bytes=_matrix_diagnostic_allowance(supervisor, output))
                _publish_cold_root_diagnostics(work, output)
                raise

            native_row = {"bytes": native_file.stat().st_size, "sha256": ci_sdk.sha256(native_file)}
            if layout is layouts[0]:
                preserved = ci_sdk._preserve_native_payload(native_file, work, variant)
                snapshot = ci_sdk._preserve_canonical_snapshot(
                    build_output / "artifacts", result["artifacts"], work, variant,
                    supervisor.managed_bytes)
                first_by_variant[variant] = {
                    "path": preserved, "bytes": native_row["bytes"],
                    "sha256": native_row["sha256"], "artifacts": result["artifacts"],
                    "snapshot": snapshot}
                _check_limits(supervisor, "preserved first native matrix root " + variant)
            else:
                first = first_by_variant[variant]
                try:
                    ci_sdk._assert_cold_roots_match(
                        work, variant, layouts[0]["name"], layout["name"], first,
                        result["artifacts"], build_output / "artifacts", native_row,
                        diagnostic_raw_limit_bytes=_matrix_diagnostic_allowance(supervisor, output))
                except ValueError:
                    _publish_cold_root_diagnostics(work, output)
                    raise
                if variant == "dependencies":
                    metadata_stage, metadata_rows = _preserve_matrix_metadata(
                        build_output / "artifacts", result["artifacts"], work)
                    _check_limits(supervisor, "preserved native matrix metadata archives")
                snapshot_root = work / "cold-root-first" / variant
                if snapshot_root.exists():
                    shutil.rmtree(snapshot_root)
                if snapshot_root.exists() or snapshot_root.is_symlink():
                    raise RuntimeError("matched native matrix snapshot could not be retired")

            build_records.append({
                "identity": {"layout": layout["name"], "variant": variant,
                             "package": package, "feature_arguments": list(feature_args)},
                "command_label": build_label,
                "build_receipt_sha256": result["receipt_sha256"],
                "canonical_artifact_count": len(result["artifacts"]),
                "canonical_artifacts": result["artifacts"],
                "build_byproducts": result["build_byproducts"],
                "AMIRUST": native_row,
                "reference_match": result["artifacts"] == expected_rows})
            ci_sdk._retire_successful_build(build_output, work)
            _check_limits(supervisor, "retired successful native matrix build " + label)

    if (metadata_stage is None or metadata_rows is None
            or set(first_by_variant) != set(ci_sdk.VARIANTS)
            or len(build_records) != 2 * len(ci_sdk.VARIANTS)):
        raise RuntimeError("native matrix did not complete all five variants in both roots")
    if (auth.read(selection) != selection_bytes
            or auth.sha(auth.read(receipt_path)) != install_receipt_sha256):
        raise ValueError("native matrix changed the prepared selection or installed receipt")

    retained_native = [{"variant": variant, "path": "native/" + variant + ".AMIRUST",
                        "bytes": first_by_variant[variant]["bytes"],
                        "sha256": first_by_variant[variant]["sha256"]}
                       for variant in ci_sdk.VARIANTS]
    retained_metadata = [{"crate": crate, "path": "metadata/" + crate + ".rlib",
                          "canonical_path": name, **metadata_rows[name]}
                         for crate in ci_sdk.METADATA_CRATES
                         for name in metadata_rows
                         if name.startswith("target/release/deps/")
                         and re.fullmatch("lib" + crate + r"-[0-9a-f]+\.rlib", Path(name).name)]
    if (len(retained_native) != len(ci_sdk.VARIANTS)
            or len(retained_metadata) != len(ci_sdk.METADATA_CRATES)):
        raise ValueError("native matrix success payload inventory is incomplete")
    matrix = {
        "schema": "ami-rust-native-two-root-five-variant-matrix-v1",
        "status": "PASS_CURRENT_HOST_MATRIX_NOT_RC1_ACCEPTANCE",
        "host": host,
        "sdk_version": config["sdk_version"],
        "reference_sha256": reference_pin["sha256"],
        "root_count": len(layouts),
        "variant_count": len(ci_sdk.VARIANTS),
        "build_count": len(build_records),
        "canonical_artifact_count": sum(row["canonical_artifact_count"] for row in build_records),
        "canonical_artifact_count_by_layout": {
            layout["name"]: sum(row["canonical_artifact_count"] for row in build_records
                                if row["identity"]["layout"] == layout["name"])
            for layout in layouts},
        "layouts": [{"name": layout["name"],
                     "project": layout["project"].relative_to(work).as_posix(),
                     "lock_sha256": layout["lock_sha256"],
                     "receipt_sha256": layout["receipt_sha256"],
                     "sdk_manifest_sha256": layout["sdk_manifest_sha256"],
                     "sdk_source_file_count": len(sdk_inventory["files"]),
                     "sdk_source_symlink_count": len(sdk_inventory["symlinks"]),
                     "sdk_source_bytes": sdk_source_bytes,
                     "sdk_source_inventory_sha256": sdk_inventory_sha256}
                    for layout in layouts],
        "builds": build_records,
        "retained_native_payloads": retained_native,
        "retained_dependency_metadata": retained_metadata,
        "claim": "The five frozen native variants match the exact host reference in two fresh SDK project and build roots. This is current-host evidence only; cross-host R1-A2/A4, no-Python observation, and RC1 acceptance remain open.",
    }
    output_bytes = ci_sdk.directory_bytes(output)
    retained_bytes = sum(row["bytes"] for row in retained_native + retained_metadata)
    report_reserve = 2 * 1024**2
    if (output_bytes + retained_bytes + len(auth.encoded(matrix)) + report_reserve
            > ci_sdk.MAX_OUTPUT_BYTES):
        raise ValueError("native matrix outputs would exceed the 32 MiB consumer artifact ceiling")
    if ((output / "native").exists() or (output / "native").is_symlink()
            or (output / "metadata").exists() or (output / "metadata").is_symlink()):
        raise ValueError("native matrix output destinations must be fresh")
    published_native = [ci_sdk._copy_native_payload(
        first_by_variant[variant]["path"], output, variant) | {"variant": variant}
        for variant in ci_sdk.VARIANTS]
    published_metadata = ci_sdk._copy_metadata_archives(
        metadata_stage, metadata_rows, output)
    if published_native != retained_native or published_metadata != retained_metadata:
        raise ValueError("published native matrix outputs differ from their verified staging rows")
    if ci_sdk.directory_bytes(output) > ci_sdk.MAX_OUTPUT_BYTES:
        raise ValueError("native matrix outputs exceeded the 32 MiB consumer artifact ceiling")

    for layout in layouts:
        shutil.rmtree(layout["root"])
        if layout["root"].exists() or layout["root"].is_symlink():
            raise RuntimeError("successful native matrix project root could not be retired")
    if matrix_root.exists():
        matrix_root.rmdir()
    for temporary in (work / "pending-native", metadata_stage):
        if temporary.exists():
            shutil.rmtree(temporary)
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeError("successful native matrix staging could not be retired")
    _check_limits(supervisor, "completed native two-root five-variant matrix")
    return matrix


def _retained_state_snapshot(root, *, entry_limit=100_000):
    """Include empty directories, ownership and modes as well as file/link bytes."""
    root = Path(root)
    metadata = []
    for path in itertools.chain((root,), root.rglob("*")):
        if len(metadata) >= entry_limit:
            raise ValueError("retained-state snapshot exceeds its entry limit")
        info = path.lstat()
        metadata.append({"path": path.relative_to(root).as_posix(), "uid": info.st_uid,
                         "gid": info.st_gid, "mode": info.st_mode,
                         "device": info.st_dev, "inode": info.st_ino,
                         "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns})
    return {"inventory": ci_sdk.component_inventory(root),
            "metadata": sorted(metadata, key=lambda row: row["path"])}


def _preservation_snapshot(roots):
    """Hash complete byte/link/metadata inventories without duplicating them in artifacts."""
    result = {}
    for label, root in sorted(roots.items()):
        # Six independently bounded component trees plus the state wrapper.
        snapshot = _retained_state_snapshot(root, entry_limit=7 * 100_000)
        result[label] = {"root": str(root), "sha256": auth.sha(auth.encoded(snapshot)),
                         "entries": len(snapshot["metadata"]),
                         "file_bytes": sum(row["bytes"] for row in snapshot["inventory"]["files"])}
    return result


def _retained_preservation_guards(work):
    """Populate only isolated qualification HOME and disposable unrelated data."""
    roots = {"global_cargo_config": work / "home/.cargo",
             "global_rustup_config": work / "home/.rustup",
             "unrelated_sdk": work / "unrelated-sdk",
             "user_data": work / "unrelated-user-data"}
    payloads = {"global_cargo_config": ("config.toml", b"[net]\noffline = true\n"),
                "global_rustup_config": ("settings.toml", b'version = "12"\n'),
                "unrelated_sdk": ("owner.txt", b"unrelated SDK, preserve all files and modes\n"),
                "user_data": ("notes.txt", b"unrelated user data, preserve all files and modes\n")}
    for label, root in roots.items():
        root.mkdir(mode=0o700)
        name, raw = payloads[label]
        write(root / name, raw, 0o600)
        (root / "empty-preservation-canary").mkdir(mode=0o700)
    return roots


def _qualify_native_migration(work, output, state, project, frontend, xtask, supervisor, command, original_elf, guards):
    """Exercise public migration with real installed inputs and explicit synthetic v1 data."""
    ready = auth.parsed(auth.read(state / "ready.json"))
    prefix = state / ("sdk-" + ready["sdk_version"])
    pin = auth.sha(auth.read(prefix / "install-receipt.json"))
    python_pin = auth.parsed(auth.read(ROOT / "release/ci-python-inputs.json"))["hosts"][current_host()]
    interpreter = supervisor.python_root / "runtime" / python_pin["runtime_relative_path"]
    original_protected = {"ready_state": state, "original_project": project, **guards}
    original_before = _preservation_snapshot(original_protected)
    area = work / "native-legacy-migration-fixture"
    generated = _supervised_run(supervisor, [xtask, "native-legacy-migration-fixture",
        "--install-prefix", prefix, "--selection", state / "selection.json", "--python", interpreter,
        "--project", project, "--output", area], cwd=work, label="20-compose-compatible-legacy-data")
    if _preservation_snapshot(original_protected) != original_before:
        raise ValueError("migration fixture generation changed existing inputs or retained data")
    fixture = auth.parsed(auth.read(work / generated["stdout_log"]))
    legacy_project, legacy_sdk = area / "project", area / "legacy-sdk"
    old_lock, migrated = legacy_project / "ami-rust.lock.json", area / "output/migrated-v2-lock.json"
    if (fixture.get("status") != "SYNTHETIC_BASELINE_COMPATIBLE_FIXTURE_NOT_HISTORICAL_EVIDENCE"
            or fixture.get("project") != str(legacy_project)
            or fixture.get("from_lock") != str(old_lock)
            or fixture.get("migration_output") != str(migrated)
            or fixture.get("receipt_pin", {}).get("sha256") != pin):
        raise ValueError("native migration fixture omitted its exact synthetic input identity")
    legacy_protected = {"legacy_project": legacy_project, "legacy_sdk": legacy_sdk}
    protected = {**original_protected, **legacy_protected}
    before = {**original_before, **_preservation_snapshot(legacy_protected)}
    arguments = ["migrate", "--project", legacy_project, "--from-lock", old_lock,
                 "--install-prefix", prefix, "--receipt-sha256", pin, "--output", migrated]
    wrong = list(arguments)
    wrong[wrong.index("--receipt-sha256") + 1] = "0" * 64
    refused_before = _preservation_snapshot({"refused_output": migrated.parent})
    command("21-migration-wrong-receipt", wrong, 2, executable=frontend)
    if (_preservation_snapshot({"refused_output": migrated.parent}) != refused_before
            or migrated.exists() or migrated.is_symlink()
            or auth.read(output / "21-migration-wrong-receipt.stderr.log")
                != b"ami-rust: installed receipt differs from the external pin\n"):
        raise ValueError("refused migration changed its output area or missed the receipt-pin refusal")
    result = auth.parsed(command("22-public-legacy-migration", arguments, executable=frontend))
    lock_bytes = auth.read(migrated)
    if (result.get("status") != "migrated" or result.get("legacy_lock_sha256") != auth.sha(auth.read(old_lock))
            or result.get("receipt_sha256") != pin
            or auth.parsed(lock_bytes).get("schema") != "ami-rust-project-lock-v2"):
        raise ValueError("public migration did not publish the selected separate native v2 lock")
    occupied_before = _preservation_snapshot({"existing_output": migrated.parent})
    command("23-migration-occupied-output", arguments, 2, executable=frontend)
    if (_preservation_snapshot({"existing_output": migrated.parent}) != occupied_before
            or auth.read(migrated) != lock_bytes
            or auth.read(output / "23-migration-occupied-output.stderr.log")
                != b"ami-rust: output JSON path must be fresh\n"):
        raise ValueError("refused migration changed the existing native lock")
    command("24-verify-migrated-lock", ["verify", "--sdk-lock", migrated], executable=frontend)
    build_area = work / "native-migration-build"
    build_area.mkdir(mode=0o700)
    build_parent = build_area / "derived"
    build_parent.mkdir(mode=0o700)
    build = build_parent / "build"
    built = auth.parsed(command("25-build-migrated-project", ["build", "--sdk-lock", migrated,
        "--output-dir", build, "--", "build", "--manifest-path", legacy_project / "Cargo.toml",
        "--package", "hello-aros", "--release", "--locked", "--offline"], executable=frontend))
    if (built.get("status") != "PASS" or not (build / "build-receipt.json").is_file()
            or auth.read(build / "artifacts/AMIRUST") != original_elf):
        raise ValueError("migrated project did not reproduce the original native executable")
    after = _preservation_snapshot(protected)
    if before != after:
        raise ValueError("migration or migrated build changed old inputs or the current ready installation")
    report = {"schema": "ami-rust-public-native-migration-effects-v1",
              "status": "PASS_PUBLIC_MIGRATION_AND_EQUIVALENT_BUILD",
              "fixture": fixture, "before": before, "after": after,
              "migrated_lock_sha256": auth.sha(lock_bytes), "native_executable_sha256": auth.sha(original_elf),
              "scope": "Actual public Rust commands under observation; legacy metadata is synthetic compatibility data against real installed baseline inputs. Historical release migration remains separate."}
    write(output / "native-public-migration.json", auth.encoded(report))
    return report


def _qualify_prepare_interruption(work, output, frontend, xtask, command):
    """Observe an actual public prepare SIGTERM, then verify retained effects."""
    area = work / "native-interrupted-prepare-area"
    area.mkdir(mode=0o700)
    parent = area / "derived"
    parent.mkdir(mode=0o700)
    state, driver = parent / "state", area / "driver-output"
    sibling = area / "unrelated-user-data.bin"
    sentinel = b"preserve interrupted-prepare sibling\n"
    write(sibling, sentinel)
    result = auth.parsed(command("09-public-prepare-sigterm", ["native-prepare-interruption",
        "--frontend", frontend, "--state", state, "--home", work / "home",
        "--tmp", work / "tmp", "--output", driver], executable=xtask))
    report = auth.parsed(auth.read(driver / "report.json"))
    if (result.get("actual_child_exit_code") != 143 or result.get("helper_exit_code") != 0
            or report.get("status") != "OBSERVED_EXPECTED_PREPARE_INTERRUPTION"
            or report.get("capture", {}).get("actual_child_exit_code") != 143
            or report.get("launcher", {}).get("sha256") != auth.sha(auth.read(frontend))
            or report.get("signal", {}).get("sent") is not True
            or (state / "ready.json").exists()):
        raise ValueError("public prepare interruption omitted its actual status or retained effects")
    for stream in ("stdout", "stderr"):
        raw = auth.read(driver / (stream + ".raw"))
        row = report["capture"][stream]
        if len(raw) != row["bytes"] or auth.sha(raw) != row["sha256"]:
            raise ValueError("prepare interruption capture differs from its actual bytes")
    retained = state / "retained/bin/ami-rust"
    command("09-interrupted-retained-package-consistency", ["verify-package"], executable=retained)
    before = _retained_state_snapshot(state)
    command("09-interrupted-state-retry-refusal", ["prepare", "--state", state], 2,
        executable=frontend, disposable_refusal_state=state)
    refusal = auth.read(output / "09-interrupted-state-retry-refusal.stderr.log")
    if refusal != b"ami-rust: state path must be fresh\n":
        raise ValueError("interrupted-state retry did not reach the native fresh-state refusal")
    if _retained_state_snapshot(state) != before or auth.read(sibling) != sentinel:
        raise ValueError("interrupted prepare retry changed retained ownership, bytes or sibling data")
    result = {"schema": "ami-rust-public-prepare-interruption-effects-v1",
        "status": "PASS_ACTUAL_CLI_SIGTERM_RETAINED_STATE_AND_UNCHANGED_RETRY",
        "driver": report, "state_snapshot": before,
        "state_snapshot_sha256": auth.sha(auth.encoded(before)),
        "retry_exit_code": 2, "retained_package_consistent": True,
        "retry_state_write_authority": "exact disposable partial state; no derived execution",
        "retry_refusal_sha256": auth.sha(refusal),
        "unrelated_sibling_sha256": auth.sha(sentinel),
        "scope": "Source-checkout interruption only; installation publication recovery is a separate case."}
    write(output / "native-prepare-interruption.json", auth.encoded(result))
    shutil.copytree(driver, output / "native-prepare-interruption-captures")
    return result


def _qualify_native_package(work, output, outer, bundle, cli, xtask, supervisor, policy_path, identity, config, command):
    """Exercise the actual packaged frontend and retained replay on signed inputs."""
    metadata = outer / "metadata"
    outer_report = auth.parsed(auth.read(metadata / "outer-verification.json"))
    if (outer_report.get("status") != "OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED"
            or outer_report.get("source_commit") != identity["source_sha"]
            or type(outer_report.get("run_id")) is not int
            or type(outer_report.get("run_attempt")) is not int
            or outer_report.get("run_id") != identity["run_id"]
            or outer_report.get("run_attempt") != identity["run_attempt"]):
        raise ValueError("outer producer receipt differs from the protected source/run")
    pins_path = metadata / ("native-package-inputs-" + current_host() + ".json")
    pins = auth.parsed(auth.read(pins_path))
    if (pins.get("source_commit") != identity["source_sha"]
            or type(pins.get("sdk_run_id")) is not int
            or type(pins.get("sdk_run_attempt")) is not int
            or pins.get("sdk_run_id") != identity["run_id"]
            or pins.get("sdk_run_attempt") != identity["run_attempt"]
            or pins.get("host") != current_host()
            or pins.get("cli_version") != config["cli_version"]
            or pins.get("sdk_version") != config["sdk_version"]):
        raise ValueError("native package inputs differ from source/run/host/version")
    notices = work / "native-package-notices"
    notices.mkdir(mode=0o700)
    for name in ("LICENSE-MIT", "LICENSE-APACHE"):
        write(notices / name, auth.read(ROOT / name))
    write(notices / "THIRD-PARTY-NOTICES.md", auth.read(ROOT / "tooling/third-party/THIRD-PARTY-NOTICES.md"))
    shutil.copytree(ROOT / "tooling/third-party/licenses", notices / "licenses")
    package = work / "native-package"
    _supervised_run(supervisor, [xtask, "native-package", "--pins", pins_path,
        "--proof-index", metadata / "native-package-proofs.json", "--launcher", cli,
        "--assets", outer / "candidate", "--proofs", metadata / "gh",
        "--notices", notices, "--output", package], label="native-consumer-compose-package")
    frontend = package / "bin/ami-rust"
    command("09-package-consistency", ["verify-package"], executable=frontend)
    authentication_area = work / "native-package-authentication-area"
    authentication_area.mkdir(mode=0o700)
    authentication = auth.parsed(command("09-package-publisher-authentication", ["native-package-verify", "--package", package,
        "--policy", policy_path, "--inputs", bundle / ".auth/inputs.json",
        "--work", authentication_area / "work"], executable=xtask))
    if authentication.get("status") != "OUTER_AND_INNER_AUTHENTICATED":
        raise ValueError("native package outer/inner authentication did not complete")
    interruption = _qualify_prepare_interruption(work, output, frontend, xtask, command)
    state_write_area = work / "native-state-write-area"
    state_write_area.mkdir(mode=0o700)
    state_parent = state_write_area / "derived"
    state_parent.mkdir(mode=0o700)
    state = state_parent / "native-ready-state"
    prepared = auth.parsed(command("10-package-cold-prepare", ["prepare", "--state", state], executable=frontend))
    if prepared.get("status") != "READY":
        raise ValueError("native package preparation did not produce READY")
    ready = auth.read(state / "ready.json")
    command("11-package-warm-recheck", ["check-inputs", "--state", state], executable=frontend)
    command("12-occupied-state-refusal", ["prepare", "--state", state], 2, executable=frontend)
    if auth.read(state / "ready.json") != ready:
        raise ValueError("occupied-state preparation changed the accepted READY record")
    project_area = work / "native-project-write-area"
    project_area.mkdir(mode=0o700)
    project = project_area / "native-client-project"
    command("13-new-client-project", ["new", "--state", state, "--project", project], executable=frontend)
    first_write_area = work / "native-client-build"
    first_write_area.mkdir(mode=0o700)
    first_parent = first_write_area / "derived"
    first_parent.mkdir(mode=0o700)
    first = first_parent / "build"
    built = auth.parsed(command("14-package-offline-build", ["build", "--state", state,
        "--project", project, "--output-dir", first], executable=frontend))
    if built.get("status") != "PASS" or not (first / "build-receipt.json").is_file():
        raise ValueError("native packaged build omitted its PASS receipt")
    native_matrix = _qualify_native_build_matrix(
        work, state, frontend, output, supervisor, config, command)
    # A later retained-launcher failure must not discard the completed matrix.
    write(output / "native-build-matrix.json", auth.encoded(native_matrix))
    _check_limits(supervisor, "preserved completed native build matrix")
    original_elf = auth.read(first / "artifacts/AMIRUST")
    guards = _retained_preservation_guards(work)
    migration = _qualify_native_migration(
        work, output, state, project, frontend, xtask, supervisor, command, original_elf, guards)
    marker = work / "unrelated-user-file.txt"
    write(marker, b"preserve across package removal\n")
    protected = {"ready_state_and_retained_tooling": state, "old_project": project,
                 **guards}
    migration_area = work / "native-legacy-migration-fixture"
    for name in ("project", "legacy-sdk", "output"):
        protected["migration_" + name] = migration_area / name
    before_removal = _preservation_snapshot(protected)
    shutil.rmtree(package)
    retained = state / "retained/bin/ami-rust"
    if not retained.is_file() or auth.read(state / "ready.json") != ready:
        raise ValueError("native package removal did not preserve retained tooling and state")
    command("15-retained-input-recheck", ["check-inputs", "--state", state], executable=retained)
    replay_write_area = work / "native-retained-build"
    replay_write_area.mkdir(mode=0o700)
    replay_parent = replay_write_area / "derived"
    replay_parent.mkdir(mode=0o700)
    replay = replay_parent / "build"
    repeated = auth.parsed(command("16-retained-offline-replay", ["build", "--state", state,
        "--project", project, "--output-dir", replay], executable=retained))
    if (repeated.get("status") != "PASS" or auth.read(replay / "artifacts/AMIRUST") != original_elf
            or auth.read(marker) != b"preserve across package removal\n"):
        raise ValueError("retained replay changed native output or unrelated user data")
    after_removal = _preservation_snapshot(protected)
    if after_removal != before_removal:
        raise ValueError("package removal or retained replay changed protected state/project/global config/SDK/user data")
    preservation = {"schema": "ami-rust-retained-removal-preservation-v1",
                    "status": "PASS_COMPLETE_RETAINED_REMOVAL_PRESERVATION",
                    "before": before_removal, "after": after_removal,
                    "scope": "Owned package directory removal plus actual retained input recheck/offline build. This is not a cross-version upgrade or package-manager transaction."}
    write(output / "native-retained-removal-preservation.json", auth.encoded(preservation))
    return {"status": "PASS_SIGNED_PACKAGE_PREPARE_BUILD_AND_RETAINED_REPLAY",
        "package_core_sha256": pins["core_sha256"], "authentication": authentication,
        "prepare_interruption": interruption,
        "public_migration": migration,
        "native_executable_sha256": auth.sha(original_elf),
        "native_matrix": native_matrix,
        "retained_removal_preservation": preservation,
        "ready_sha256": auth.sha(ready),
        "removal": "private owned package root removed; state, project and unrelated marker preserved",
        "limitation": "Cargo offline mode exercised; OS network denial and complete no-Python observation remain unqualified"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    host = subs.add_parser("host")
    host.add_argument("--host", choices=auth.HOSTS, required=True)
    host.add_argument("--output", type=Path, required=True)
    host.add_argument("--python-bootstrap-root", type=Path)
    for name in ("assemble", "audit"):
        sub = subs.add_parser(name)
        sub.add_argument("--linux", type=Path, required=True)
        sub.add_argument("--macos", type=Path, required=True)
        sub.add_argument("--output" if name == "assemble" else "--bundle", type=Path, required=True)
        sub.add_argument("--python-bootstrap-root", type=Path)
    verify = subs.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--outer", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument("--python-bootstrap-root", type=Path, required=True)
    for sub in subs.choices.values():
        sub.add_argument("--work", type=Path, required=True)
        sub.add_argument("--host-rust", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "host":
        result = host_build(args.work, args.output, args.host_rust, args.host, args.python_bootstrap_root)
    elif args.command == "verify":
        result = verify_lifecycle(args.work, args.output, args.bundle, args.host_rust, args.python_bootstrap_root, args.outer)
    else:
        payloads = {"linux-x86_64": args.linux, "macos-aarch64": args.macos}
        result = (compose(args.work, args.output, args.host_rust, payloads, args.python_bootstrap_root)
                  if args.command == "assemble" else
                  audit(args.work, args.bundle, args.host_rust, payloads, args.python_bootstrap_root))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

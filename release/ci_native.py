#!/usr/bin/env python3
"""Transitional internal coordination for the Rust SDK-v2 producer.

The Rust xtask owns SDK/release composition. This helper reuses immutable
component archives and the existing protected signing workflow. It neither
publishes nor accepts RC1; retiring this internal Python is RC4 work.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import platform
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

    Internal Python coordinates this test. The complete consumer observer,
    package preparation and RC1 lifecycle matrix remain separate open gates.
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
    policy_path = work / "native-publisher-policy.json"
    write(policy_path, auth.encoded(policy), 0o600)
    commands = []

    def command(label, arguments, expected=0, *, executable=cli):
        stdout = output / (label + ".stdout.json")
        stderr = output / (label + ".stderr.log")
        record = _supervised_run(supervisor, [executable, *map(str, arguments)], cwd=work,
                                 label=label, timeout=1200, expected=expected)
        shutil.copyfile(work / record["stdout_log"], stdout)
        shutil.copyfile(work / record["stderr_log"], stderr)
        commands.append({"label": label, "exit": record["exit_code"], "expected_exit": expected,
                         "stdout_sha256": auth.sha(auth.read(stdout)),
                         "stderr_sha256": auth.sha(auth.read(stderr)),
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
    prefix, pin = work / "native-install", work / "external-receipt.sha256"
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
        work, outer, bundle, cli, xtask, supervisor, policy_path, identity, config, command)
    report = {"schema": "ami-rust-native-direct-lifecycle-v1", "status": "PASS_NATIVE_LIFECYCLE_NOT_RC1_ACCEPTANCE",
              "package_lifecycle": package_lifecycle,
              "source": identity, "host": current_host(), "commands": commands,
              "supervision": _supervision_summary(supervisor, tools.get("commands", []),
                                                   bootstrap_insert_at),
              "manifest_sha256": auth.sha(auth.read(bundle / "release.json")),
              "cli_sha256": auth.sha(auth.read(cli)), "receipt_sha256": receipt,
              "remaining_gates": ["complete both-host no-Python observation", "complete cold/warm and negative lifecycle matrix",
                                  "two-root five-variant builds", "migration, upgrade and retained replay matrix"],
              "claim": "Real inner/outer signatures, native direct and package preparation/build/removal/retained replay; internal Python coordination is outside consumer scope. Complete observed no-Python and RC1 matrix remain open"}
    write(output / "native-direct-lifecycle.json", auth.encoded(report))
    _check_limits(supervisor, "native direct lifecycle report")
    report["supervision"] = _supervision_summary(supervisor, tools.get("commands", []),
                                                  bootstrap_insert_at)
    (output / "native-direct-lifecycle.json").write_bytes(auth.encoded(report))
    _check_limits(supervisor, "native direct lifecycle report")
    return report


def _qualify_native_package(work, outer, bundle, cli, xtask, supervisor, policy_path, identity, config, command):
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
    authentication = auth.parsed(_supervised_text(supervisor, [xtask, "native-package-verify", "--package", package,
        "--policy", policy_path, "--inputs", bundle / ".auth/inputs.json",
        "--work", work / "native-package-authentication"], label="native-consumer-package-authentication", timeout=1200).encode())
    if authentication.get("status") != "OUTER_AND_INNER_AUTHENTICATED":
        raise ValueError("native package outer/inner authentication did not complete")
    state = work / "native-ready-state"
    prepared = auth.parsed(command("10-package-cold-prepare", ["prepare", "--state", state], executable=frontend))
    if prepared.get("status") != "READY":
        raise ValueError("native package preparation did not produce READY")
    ready = auth.read(state / "ready.json")
    command("11-package-warm-recheck", ["check-inputs", "--state", state], executable=frontend)
    command("12-occupied-state-refusal", ["prepare", "--state", state], 2, executable=frontend)
    if auth.read(state / "ready.json") != ready:
        raise ValueError("occupied-state preparation changed the accepted READY record")
    project = work / "native-client-project"
    command("13-new-client-project", ["new", "--state", state, "--project", project], executable=frontend)
    first = work / "native-client-build"
    built = auth.parsed(command("14-package-offline-build", ["build", "--state", state,
        "--project", project, "--output-dir", first], executable=frontend))
    if built.get("status") != "PASS" or not (first / "build-receipt.json").is_file():
        raise ValueError("native packaged build omitted its PASS receipt")
    original_elf = auth.read(first / "artifacts/AMIRUST")
    marker = work / "unrelated-user-file.txt"
    write(marker, b"preserve across package removal\n")
    shutil.rmtree(package)
    retained = state / "retained/bin/ami-rust"
    if not retained.is_file() or auth.read(state / "ready.json") != ready:
        raise ValueError("native package removal did not preserve retained tooling and state")
    command("15-retained-input-recheck", ["check-inputs", "--state", state], executable=retained)
    replay = work / "native-retained-build"
    repeated = auth.parsed(command("16-retained-offline-replay", ["build", "--state", state,
        "--project", project, "--output-dir", replay], executable=retained))
    if (repeated.get("status") != "PASS" or auth.read(replay / "artifacts/AMIRUST") != original_elf
            or auth.read(marker) != b"preserve across package removal\n"):
        raise ValueError("retained replay changed native output or unrelated user data")
    return {"status": "PASS_SIGNED_PACKAGE_PREPARE_BUILD_AND_RETAINED_REPLAY",
        "package_core_sha256": pins["core_sha256"], "authentication": authentication,
        "native_executable_sha256": auth.sha(original_elf),
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

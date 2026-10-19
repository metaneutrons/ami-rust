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
import subprocess
import sys
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "release"))
import ci_auth as auth

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


def write(path, raw, mode=0o644):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(mode)


def run(command, env, *, log, timeout=1200):
    # Never forward registry publication credentials, including from a caller
    # using this helper outside GitHub Actions.
    env = dict(env)
    env.pop("CARGO_REGISTRY_TOKEN", None)
    env.pop("CARGO_REGISTRIES_CRATES_IO_TOKEN", None)
    with log.open("xb") as stream:
        result = subprocess.run([str(p) for p in command], cwd=ROOT, env=env,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise ValueError(f"native producer command failed ({result.returncode}); retained log: {log.name}")


def build_tools(work, host_rust):
    native_inputs()
    toolchain = Path(host_rust).resolve(strict=True) / "toolchain"
    rust = toolchain / "bin"
    probe_env = dict(os.environ)
    probe_env.pop("CARGO_REGISTRY_TOKEN", None)
    probe_env.pop("CARGO_REGISTRIES_CRATES_IO_TOKEN", None)
    compiler = subprocess.check_output([str(rust / "rustc"), "-Vv"], text=True, env=probe_env)
    if ("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" not in compiler
            or "host: " + HOST_TRIPLES[current_host()] not in compiler):
        raise ValueError("native producer host compiler differs from the pinned bootstrap")
    for name in ("home", "cargo-home", "tmp"):
        (work / name).mkdir(mode=0o700)
    env = {"PATH": str(rust) + ":/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work / "home"),
           "TMPDIR": str(work / "tmp"), "LC_ALL": "C", "CARGO_BUILD_JOBS": "2",
           "CARGO_HOME": str(work / "cargo-home"), "CLI_CARGO": str(rust / "cargo"),
           "RUSTC": str(rust / "rustc"), "RUSTDOC": str(rust / "rustdoc")}
    run([rust / "cargo", "fetch", "--locked", "--manifest-path", ROOT / "tooling/Cargo.toml"],
        env, log=work / "fetch.log")
    run(["/bin/bash", ROOT / "tools/build-native-cli.sh", work / "target"],
        env, log=work / "build-cli.log")
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
        f"--remap-path-prefix={ROOT}=/ami-rust", f"--remap-path-prefix={work / 'cargo-home'}=/cargo"])
    if current_host() == "macos-aarch64":
        env["DYLD_LIBRARY_PATH"] = str(toolchain / "lib")
    run([rust / "cargo", "build", "--release", "--locked", "--offline", "--package", "ami-rust-xtask",
         "--manifest-path", ROOT / "tooling/Cargo.toml", "--target-dir", work / "target"],
        env, log=work / "build-xtask.log")
    cli = work / "target/release/ami-rust"
    run([cli, "--version"], env, log=work / "cli-identity.json")
    cli_identity = auth.parsed(auth.read(work / "cli-identity.json"))
    if cli_identity.get("schema") != "ami-rust-version-v1" or cli_identity.get("cli_version") != native_inputs()["cli_version"]:
        raise ValueError("built native CLI reports a different version")
    return cli, work / "target/release/ami-rust-xtask", env


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


def host_build(work, output, host_rust, host):
    identity = auth.context(ROOT)
    if host != current_host():
        raise ValueError("producer host selection differs from the actual runner")
    config = native_inputs()
    work = fresh(work)
    output = fresh(output)
    cli, xtask, env = build_tools(work, host_rust)
    legacy = obtain_legacy(work, config["legacy_release"])
    draft = work / "sdk-draft"
    run([xtask, "native-sdk", "--source-sdk", legacy / "sdk.tar.xz", "--source-commit", identity["source_sha"],
         "--version", config["sdk_version"], "--output", draft], env, log=work / "compose-sdk.log")
    for name, source in (("ami-rust", cli), ("sdk.tar.xz", draft / "sdk.tar.xz"),
                         ("sdk-manifest.json", draft / "sdk-manifest.json")):
        write(output / name, auth.read(source), 0o755 if name == "ami-rust" else 0o644)
    report = {"schema": "ami-rust-native-host-producer-v1", "status": "UNSIGNED_HOST_OUTPUT",
              "host": host, "source": identity, "sdk_version": config["sdk_version"],
              "cli_version": config["cli_version"], "cargo_lock": config["cargo_lock"],
              "cli_identity": auth.parsed(auth.read(work / "cli-identity.json")),
              "files": [{"path": p.name, "bytes": p.stat().st_size, "sha256": auth.sha(auth.read(p))}
                        for p in sorted(output.iterdir())],
              "claim": "Native host output only; signatures, consumer qualification and release acceptance remain separate"}
    write(output / "native-host-producer.json", auth.encoded(report))
    return report


def validate_host_payload(payload, host, identity, config):
    payload = Path(payload).resolve(strict=True)
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


def compose(work, output, host_rust, payloads):
    identity = auth.context(ROOT)
    config = native_inputs()
    work = fresh(work)
    _, xtask, env = build_tools(work, host_rust)
    payloads = {host: validate_host_payload(payloads[host], host, identity, config) for host in auth.HOSTS}
    if auth.read(payloads[auth.HOSTS[0]] / "sdk.tar.xz") != auth.read(payloads[auth.HOSTS[1]] / "sdk.tar.xz"):
        raise ValueError("native host SDK archives are not byte identical")
    legacy = obtain_legacy(work, config["legacy_release"])
    producer_path = work / "declared-producer.json"
    write(producer_path, auth.encoded(producer(identity)))
    run([xtask, "native-release", "--source-bundle", legacy, "--source-commit", identity["source_sha"],
         "--version", config["sdk_version"], "--linux-cli", payloads["linux-x86_64"] / "ami-rust",
         "--macos-cli", payloads["macos-aarch64"] / "ami-rust", "--producer-file", producer_path,
         "--output", output], env, log=work / "compose-release.log")
    output = Path(output)
    if auth.read(output / "sdk.tar.xz") != auth.read(payloads[auth.HOSTS[0]] / "sdk.tar.xz"):
        raise ValueError("assembled SDK differs from both host producer outputs")
    write(output / ".auth/inputs.json", auth.encoded(auth.input_manifest_for_sdk(ROOT, config["sdk_version"])))
    if sum(p.stat().st_size for p in output.rglob("*") if p.is_file()) > NATIVE_LIMIT - 1024**2:
        raise ValueError("native candidate exceeds its prospective authentication profile")
    return {"schema": "ami-rust-native-publisher-candidate-v1", "status": "UNSIGNED_CANDIDATE",
            "source": identity, "manifest_sha256": auth.sha(auth.read(output / "release.json"))}


def audit(work, bundle, host_rust, payloads):
    work = Path(work)
    expected = work.parent / (work.name + "-expected")
    report = compose(work, expected, host_rust, payloads)
    bundle = Path(bundle).resolve(strict=True)
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
            "source": report["source"], "subjects": digests}


def verify_lifecycle(work, output, bundle, host_rust, python_root):
    """Real native verification/install/removal, with an independently built CLI.

    Internal Python coordinates this test. The complete consumer observer,
    package preparation and RC1 lifecycle matrix remain separate open gates.
    """
    import ci_verify
    identity = auth.context(ROOT)
    config = native_inputs()
    work = fresh(work)
    output = fresh(output)
    cli, _, env = build_tools(work, host_rust)
    verifier_work = work.parent / "ami-rust-native-verifier-work"
    verifier_metadata = work.parent / "ami-rust-native-verifier-metadata"
    tools = ci_verify.bootstrap_tools(verifier_work, verifier_metadata, python_root)
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
    bundle = Path(bundle).resolve(strict=True)
    commands = []

    def command(label, arguments, expected=0):
        stdout = output / (label + ".stdout.json")
        stderr = output / (label + ".stderr.log")
        with stdout.open("xb") as out, stderr.open("xb") as err:
            result = subprocess.run([str(cli), *map(str, arguments)], cwd=work, env=env,
                                    stdout=out, stderr=err, timeout=1200)
        commands.append({"label": label, "exit": result.returncode, "expected_exit": expected,
                         "stdout_sha256": auth.sha(auth.read(stdout)), "stderr_sha256": auth.sha(auth.read(stderr))})
        write(output / (label + ".result.json"), auth.encoded(commands[-1]))
        if result.returncode != expected:
            raise ValueError(f"native consumer {label} returned {result.returncode}, expected {expected}")
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
    report = {"schema": "ami-rust-native-direct-lifecycle-v1", "status": "PASS_DIRECT_LIFECYCLE_NOT_RC1_ACCEPTANCE",
              "source": identity, "host": current_host(), "commands": commands,
              "manifest_sha256": auth.sha(auth.read(bundle / "release.json")),
              "cli_sha256": auth.sha(auth.read(cli)), "receipt_sha256": receipt,
              "remaining_gates": ["complete both-host no-Python observation", "cold/warm package preparation",
                                  "two-root five-variant builds", "migration, upgrade and retained replay matrix"],
              "claim": "Real signatures and direct native installation/removal only; internal Python test coordination remains"}
    write(output / "native-direct-lifecycle.json", auth.encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    host = subs.add_parser("host")
    host.add_argument("--host", choices=auth.HOSTS, required=True)
    host.add_argument("--output", type=Path, required=True)
    for name in ("assemble", "audit"):
        sub = subs.add_parser(name)
        sub.add_argument("--linux", type=Path, required=True)
        sub.add_argument("--macos", type=Path, required=True)
        sub.add_argument("--output" if name == "assemble" else "--bundle", type=Path, required=True)
    verify = subs.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument("--python-bootstrap-root", type=Path, required=True)
    for sub in subs.choices.values():
        sub.add_argument("--work", type=Path, required=True)
        sub.add_argument("--host-rust", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "host":
        result = host_build(args.work, args.output, args.host_rust, args.host)
    elif args.command == "verify":
        result = verify_lifecycle(args.work, args.output, args.bundle, args.host_rust, args.python_bootstrap_root)
    else:
        payloads = {"linux-x86_64": args.linux, "macos-aarch64": args.macos}
        result = (compose(args.work, args.output, args.host_rust, payloads) if args.command == "assemble"
                  else audit(args.work, args.bundle, args.host_rust, payloads))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

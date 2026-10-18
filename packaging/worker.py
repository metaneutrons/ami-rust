#!/usr/bin/env python3
"""Run the original qualified SDK preparation and installer with packaged proofs."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def prepare(state: Path) -> None:
    package = Path(__file__).resolve().parent
    adapter = load(package / "cli.py", "ami_rust_package_cli")
    pins = adapter.verify_package(package)
    source = state / "source"
    replay = load(source / "release/public_replay.py", "ami_rust_packaged_replay")
    trusted = replay._load_trusted_helpers(source)
    identity = trusted.consumer_source_identity(pins["source_commit"], pins["source_commit"])
    work = state / "preparation"
    output = state / "preparation-output"
    python_root = state / "ami-rust-python-bootstrap"
    work.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    trusted.bootstrap_tools(work, output, python_root, source_commit=pins["source_commit"])
    host = trusted.host_identity()
    tool_manifest = trusted.strict_json(source / "release/ci-auth-tools.json", 1024 * 1024)
    tools = trusted._verify_tool_receipt(work, output, host, tool_manifest)
    policy_path, policy = trusted._write_source_policy(identity, tools["roots"], work)
    public_candidate = load(source / "release/public_candidate.py", "ami_rust_packaged_candidate")
    index = adapter.read_json(package / "proofs.json")
    proofs = {}
    for subject, rows in index["subjects"].items():
        proofs[subject] = []
        for row in rows:
            path = package / "proofs" / row["path"]
            if path.stat().st_size != row["bytes"] or adapter.digest(path) != row["sha256"]:
                raise ValueError("packaged publisher proof differs from its inventory")
            proofs[subject].append(path)
    bundle, receipt, _retained_proofs = replay._authenticate_public_candidate(
        candidate=package / "assets", tag=pins["sdk_tag"], source=source,
        source_commit=pins["source_commit"], transport_sha256=pins["transport_sha256"],
        manifest_sha256=pins["manifest_sha256"], policy=policy, trusted=trusted,
        public_candidate=public_candidate, controls_root=None, work=work, output=output,
        gh_path=work / "tools/gh", gh_bundles=proofs, retrieval_token=None)
    if receipt.get("authenticated") is not True:
        raise ValueError("original publisher authentication did not pass")
    result = trusted.prepare_consumer_inputs(bundle, work, output, python_root,
        pins["source_commit"], pins["source_commit"], state / "selection.json")
    if result.get("status") != "PREPARED_VERIFIED_INPUTS_NOT_INSTALLED":
        raise ValueError("original prerequisite preparation did not pass")
    prefix = state / ("sdk-" + pins["sdk_version"])
    adapter.run([sys.executable, "-I", "-B", bundle / "install_publisher.py", "install",
                 "--bundle", bundle, "--policy", policy_path, "--prefix", prefix,
                 "--receipt-pin", state / "receipt.sha256"])
    record = {"schema": "ami-rust-package-state-v1", "status": "READY", "host": host,
              "sdk_version": pins["sdk_version"], "package_version": pins["package_version"],
              "source_commit": pins["source_commit"], "manifest_sha256": pins["manifest_sha256"]}
    with (state / "ready.json").open("x") as stream:
        stream.write(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    prepare(parser.parse_args().state)

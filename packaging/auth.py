#!/usr/bin/env python3
"""Use the SDK's pinned verifier binaries and roots for package provenance."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen
import zipfile

SOURCE = Path(__file__).resolve().parents[1]
REPOSITORY = "metaneutrons/ami-rust"
WORKFLOW = REPOSITORY + "/.github/workflows/packages.yml"
IDENTITY = "https://github.com/" + WORKFLOW + "@refs/heads/main"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bootstrap(destination):
    manifest = json.loads((SOURCE / "release/ci-auth-tools.json").read_text())
    host = {("Darwin", "arm64"): "macos-aarch64", ("Linux", "x86_64"): "linux-x86_64"}[
        platform.system(), platform.machine()]
    destination.mkdir(mode=0o700)
    for name, row in manifest["roots"].items():
        raw = (SOURCE / row["path"]).read_bytes()
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
            raise ValueError(name + " trust root differs from source pin")
    for name, row in manifest["hosts"][host].items():
        with urlopen(row["url"], timeout=120) as response:
            raw = response.read(row["bytes"] + 1)
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
            raise ValueError(name + " download differs from source pin")
        if "archive_member" in row:
            if row["url"].endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    if archive.namelist().count(row["archive_member"]) != 1:
                        raise ValueError("ambiguous verifier archive member")
                    raw = archive.read(row["archive_member"])
            else:
                with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                    members = [item for item in archive if item.name == row["archive_member"]]
                    if len(members) != 1 or not members[0].isfile():
                        raise ValueError("ambiguous verifier archive member")
                    raw = archive.extractfile(members[0]).read(row["binary_bytes"] + 1)
        if len(raw) != row["binary_bytes"] or sha(raw) != row["binary_sha256"]:
            raise ValueError(name + " executable differs from source pin")
        path = destination / name
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o700)


def commands(tools, path, commit, *, bundle=None):
    gh = [str(tools / "gh"), "attestation", "verify", str(path), "--repo", REPOSITORY,
          "--custom-trusted-root", str(SOURCE / "release/trust/github-trusted-root.jsonl"),
          "--cert-identity", IDENTITY, "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
          "--signer-digest", commit, "--source-digest", commit,
          "--source-ref", "refs/heads/main", "--deny-self-hosted-runners",
          "--predicate-type", "https://slsa.dev/provenance/v1"]
    cosign = [str(tools / "cosign"), "verify-blob", str(path), "--bundle", str(bundle),
              "--trusted-root", str(SOURCE / "release/trust/sigstore-trusted-root.json"),
              "--certificate-identity", IDENTITY,
              "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
              "--certificate-github-workflow-repository", REPOSITORY,
              "--certificate-github-workflow-ref", "refs/heads/main",
              "--certificate-github-workflow-sha", commit,
              "--certificate-github-workflow-trigger", "workflow_dispatch"]
    return gh, cosign


def verify(directory, tools, commit, *, probes=True):
    pins = json.loads((SOURCE / "packaging/pins.json").read_text())
    signed = [f"ami-rust-{pins['sdk_version']}-packaging.{pins['packaging_revision']}.tar.xz",
              f"ami-rust_{pins['package_version']}_amd64.deb", "ami-rust.rb"]
    candidate = json.loads((directory / "candidate.json").read_text())
    for name in [row["path"] for row in candidate["assets"]] + ["candidate.json", "SHA256SUMS"]:
        subprocess.run(commands(tools, directory / name, commit)[0], check=True, timeout=180)
    for name in signed:
        bundle = directory / (name + ".sigstore.json")
        subprocess.run(commands(tools, directory / name, commit, bundle=bundle)[1], check=True, timeout=180)
    if probes:
        # Exercise each cryptographic verifier on a corrupted copy independently
        # of the candidate-inventory gate. Never modify accepted package bytes.
        name = f"ami-rust_{pins['package_version']}_amd64.deb"
        with tempfile.TemporaryDirectory(prefix="ami-rust-auth-counter-") as temporary:
            altered = Path(temporary) / name
            altered.write_bytes((directory / name).read_bytes() + b"counter-probe")
            for command in commands(tools, altered, commit,
                                    bundle=directory / (name + ".sigstore.json")):
                result = subprocess.run(command, timeout=180)
                if result.returncode != 1:
                    raise ValueError("corrupted-package verifier probe did not fail with exit 1")
    print(json.dumps({"status": "PASS_PACKAGE_AUTHENTICATION", "source_commit": commit,
                      "corruption_counter_probes": probes}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("bootstrap", "verify"))
    parser.add_argument("--tools", required=True, type=Path)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--source-commit")
    args = parser.parse_args()
    if args.mode == "bootstrap":
        bootstrap(args.tools)
    else:
        if not args.directory or not args.source_commit:
            parser.error("verify requires --directory and --source-commit")
        verify(args.directory, args.tools, args.source_commit)


if __name__ == "__main__":
    main()

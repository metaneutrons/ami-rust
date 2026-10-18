#!/usr/bin/env python3
"""Offline tests for the package provenance verifier's trust boundaries."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


_AUTH_PATH = Path(__file__).with_name("auth.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_package_auth_test", _AUTH_PATH)
assert _SPEC is not None and _SPEC.loader is not None
auth = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(auth)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def package_names(pins: dict) -> list[str]:
    archive = f"ami-rust-{pins['sdk_version']}-packaging.{pins['packaging_revision']}.tar.xz"
    deb = f"ami-rust_{pins['package_version']}_amd64.deb"
    payloads = (archive, deb)
    return sorted([
        *payloads,
        *(name + ".spdx.json" for name in payloads),
        "ami-rust.rb", "packaging-report.json", "metadata-report.json",
        *(name + ".sigstore.json" for name in payloads),
        "ami-rust.rb.sigstore.json",
    ])


def _tar_gz(member_name: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(member_name)
        member.size = len(content)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _bootstrap_fixture(root: Path, *, wrong_binary_digest: bool = False) -> tuple[Path, dict[str, bytes]]:
    source = root / "source"
    trust = source / "release/trust"
    trust.mkdir(parents=True)
    root_bytes = {
        "gh": b"fixture github trust root\n",
        "cosign": b"fixture sigstore trust root\n",
    }
    root_paths = {
        "gh": "release/trust/github-trusted-root.jsonl",
        "cosign": "release/trust/sigstore-trusted-root.json",
    }
    for name, relative in root_paths.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(root_bytes[name])

    binaries = {"gh": b"gh fixture executable\n", "cosign": b"cosign fixture executable\n"}
    archive_name = "gh_0.0.0_linux_amd64/bin/gh"
    archive_bytes = _tar_gz(archive_name, binaries["gh"])
    rows = {
        "gh": {
            "url": "https://fixture.invalid/gh.tar.gz",
            "bytes": len(archive_bytes), "sha256": digest(archive_bytes),
            "archive_member": archive_name,
            "binary_bytes": len(binaries["gh"]),
            "binary_sha256": "0" * 64 if wrong_binary_digest else digest(binaries["gh"]),
        },
        "cosign": {
            "url": "https://fixture.invalid/cosign",
            "bytes": len(binaries["cosign"]), "sha256": digest(binaries["cosign"]),
            "binary_bytes": len(binaries["cosign"]),
            "binary_sha256": digest(binaries["cosign"]),
        },
    }
    manifest = {
        "schema": "ami-rust-ci-auth-tools-v1",
        "roots": {
            name: {"path": root_paths[name], "bytes": len(root_bytes[name]), "sha256": digest(root_bytes[name])}
            for name in root_paths
        },
        "hosts": {"linux-x86_64": rows},
    }
    (source / "release").mkdir(parents=True, exist_ok=True)
    (source / "release/ci-auth-tools.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
    )
    return source, {rows["gh"]["url"]: archive_bytes, rows["cosign"]["url"]: binaries["cosign"]}


class AuthBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_pinned_tools_and_trust_roots_bootstrap_successfully(self) -> None:
        source, responses = _bootstrap_fixture(self.root)
        output = self.root / "tools"
        requests: list[tuple[str, int]] = []

        def open_url(url, *, timeout):
            requests.append((url, timeout))
            return io.BytesIO(responses[url])

        with (
            mock.patch.object(auth, "SOURCE", source),
            mock.patch.object(auth.platform, "system", return_value="Linux"),
            mock.patch.object(auth.platform, "machine", return_value="x86_64"),
            mock.patch.object(auth, "urlopen", side_effect=open_url),
        ):
            auth.bootstrap(output)

        self.assertEqual(set(requests), {(url, 120) for url in responses})
        self.assertEqual((output / "gh").read_bytes(), b"gh fixture executable\n")
        self.assertEqual((output / "cosign").read_bytes(), b"cosign fixture executable\n")
        self.assertEqual((output / "gh").stat().st_mode & 0o777, 0o700)
        self.assertEqual((output / "cosign").stat().st_mode & 0o777, 0o700)

    def test_root_and_extracted_binary_tampering_are_rejected_before_use(self) -> None:
        source, _responses = _bootstrap_fixture(self.root)
        (source / "release/trust/github-trusted-root.jsonl").write_bytes(b"tampered root\n")
        opener = mock.Mock()
        with (
            mock.patch.object(auth, "SOURCE", source),
            mock.patch.object(auth.platform, "system", return_value="Linux"),
            mock.patch.object(auth.platform, "machine", return_value="x86_64"),
            mock.patch.object(auth, "urlopen", opener),
        ):
            with self.assertRaisesRegex(ValueError, "trust root differs"):
                auth.bootstrap(self.root / "root-tamper-tools")
        opener.assert_not_called()

        source, responses = _bootstrap_fixture(self.root / "binary-case", wrong_binary_digest=True)
        with (
            mock.patch.object(auth, "SOURCE", source),
            mock.patch.object(auth.platform, "system", return_value="Linux"),
            mock.patch.object(auth.platform, "machine", return_value="x86_64"),
            mock.patch.object(auth, "urlopen", side_effect=lambda url, timeout: io.BytesIO(responses[url])),
        ):
            with self.assertRaisesRegex(ValueError, "executable differs"):
                auth.bootstrap(self.root / "binary-tamper-tools")


class AuthCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_verifier_vectors_pin_the_packaging_workflow_and_exact_source(self) -> None:
        source = Path("/tmp/ami-rust-source")
        path = Path("/tmp/candidate.deb")
        tools = Path("/tmp/tools")
        bundle = Path("/tmp/candidate.deb.sigstore.json")
        commit = "a" * 40
        with mock.patch.object(auth, "SOURCE", source):
            gh, cosign = auth.commands(tools, path, commit, bundle=bundle)

        identity = "https://github.com/metaneutrons/ami-rust/.github/workflows/packages.yml@refs/heads/main"
        self.assertEqual(gh, [
            "/tmp/tools/gh", "attestation", "verify", "/tmp/candidate.deb",
            "--repo", "metaneutrons/ami-rust",
            "--custom-trusted-root", "/tmp/ami-rust-source/release/trust/github-trusted-root.jsonl",
            "--cert-identity", identity,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--signer-digest", commit, "--source-digest", commit,
            "--source-ref", "refs/heads/main", "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1",
        ])
        self.assertEqual(cosign, [
            "/tmp/tools/cosign", "verify-blob", "/tmp/candidate.deb",
            "--bundle", "/tmp/candidate.deb.sigstore.json",
            "--trusted-root", "/tmp/ami-rust-source/release/trust/sigstore-trusted-root.json",
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-repository", "metaneutrons/ami-rust",
            "--certificate-github-workflow-ref", "refs/heads/main",
            "--certificate-github-workflow-sha", commit,
            "--certificate-github-workflow-trigger", "workflow_dispatch",
        ])

    def _verification_fixture(self, root: Path) -> tuple[Path, Path, dict[str, bytes]]:
        source = root / "source"
        (source / "release/trust").mkdir(parents=True)
        pins = {
            "sdk_version": "0.1.0",
            "packaging_revision": 1,
            "package_version": "0.1.0-1",
        }
        directory = root / "candidate"
        directory.mkdir()
        data = {name: ("asset:" + name + "\n").encode() for name in package_names(pins)}
        rows = [{"path": name, "bytes": len(raw), "sha256": digest(raw)}
                for name, raw in sorted(data.items())]
        data["candidate.json"] = json.dumps({"assets": rows}, sort_keys=True).encode() + b"\n"
        data["SHA256SUMS"] = b"synthetic checksum fixture\n"
        for name, raw in data.items():
            (directory / name).write_bytes(raw)
        (source / "packaging/pins.json").parent.mkdir(parents=True)
        (source / "packaging/pins.json").write_text(json.dumps(pins), encoding="utf-8")
        return source, directory, data

    def test_verify_authenticates_every_candidate_file_and_signed_payload(self) -> None:
        source, directory, data = self._verification_fixture(self.root)
        tools = self.root / "tools"
        commit = "c" * 40
        calls: list[tuple[list[str], dict]] = []

        def run(command, **kwargs):
            command = [str(value) for value in command]
            calls.append((command, kwargs))
            if kwargs.get("check") is True:
                return SimpleNamespace(returncode=0)
            self.assertTrue(Path(command[3] if command[1] == "attestation" else command[2])
                            .read_bytes().endswith(b"counter-probe"))
            return SimpleNamespace(returncode=1)

        with (
            mock.patch.object(auth, "SOURCE", source),
            mock.patch.object(auth.subprocess, "run", side_effect=run),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            auth.verify(directory, tools, commit)

        gh_calls = [command for command, _kwargs in calls if command[1:3] == ["attestation", "verify"]]
        cosign_calls = [command for command, _kwargs in calls if command[1:2] == ["verify-blob"]]
        self.assertEqual(
            {Path(command[3]).name for command in gh_calls}, set(data)
        )
        self.assertEqual(
            {Path(command[2]).name for command in cosign_calls},
            {"ami-rust-0.1.0-packaging.1.tar.xz", "ami-rust_0.1.0-1_amd64.deb", "ami-rust.rb"},
        )
        self.assertEqual(len(gh_calls), len(data) + 1)  # one extra GH corruption probe
        self.assertEqual(len(cosign_calls), 4)  # three signatures plus the Cosign corruption probe
        self.assertEqual(len(calls[-2:]), 2)
        self.assertTrue(all(kwargs.get("timeout") == 180 for _command, kwargs in calls))

    def test_zero_exit_from_mutated_asset_counter_probe_is_rejected(self) -> None:
        source, directory, _data = self._verification_fixture(self.root)
        calls = []

        def run(command, **kwargs):
            calls.append(([str(value) for value in command], kwargs))
            return SimpleNamespace(returncode=0)

        with (
            mock.patch.object(auth, "SOURCE", source),
            mock.patch.object(auth.subprocess, "run", side_effect=run),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(ValueError, "corrupted-package verifier probe did not fail with exit 1"):
                auth.verify(directory, self.root / "tools", "c" * 40)
        self.assertEqual(len(calls), len(package_names({
            "sdk_version": "0.1.0", "packaging_revision": 1, "package_version": "0.1.0-1",
        })) + 2 + 3 + 1)
        self.assertTrue(all(kwargs.get("check") is True for _command, kwargs in calls[:-1]))


if __name__ == "__main__":
    unittest.main(verbosity=2)

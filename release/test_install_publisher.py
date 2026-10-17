"""Production installer adapter tests.

The adapter substitutes a synthetic verifier report. It never exercises real
cryptography and makes no publisher-authentication or R1-acceptance claim.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve(strict=True).parents[1]
sys.path.insert(0, str(ROOT / "release"))
import install as installer
import install_publisher as production
import verify_publisher as verifier


def digest(data):
    return hashlib.sha256(data).hexdigest()


def row(name, data):
    return {"path": name, "bytes": len(data), "sha256": digest(data)}


def compact(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("ascii")


def tar_xz(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.mode = 0o644
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


class ProductionInstallerAdapterTests(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix="ami-rust-prod-installer-")
        self.root = Path(self.owner.name).resolve(strict=True)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.prefix = self.root / "installed"
        self.pin = self.root / "receipt.sha256"
        self.policy_path = self.root / "policy.json"
        self._fixture_bundle()
        self.policy = self._policy()
        self.policy_path.write_bytes(compact(self.policy))

    def tearDown(self):
        self.owner.cleanup()

    def _fixture_bundle(self):
        marker = b"synthetic production SDK file\n"
        inner = compact({"schema": "ami-rust-sdk-v1", "version": "0.2.0",
                        "qualification_only": False,
                        "files": [row("fixture/marker.txt", marker)]})
        sdk_entries = {"contract/sdk.json": inner, "fixture/marker.txt": marker}
        sdk_archive = tar_xz(sdk_entries)
        assets = {"sdk.tar.xz": sdk_archive, "docs/readme.txt": b"synthetic release asset\n"}
        manifest = {
            "schema": "ami-rust-release-v1", "version": "0.2.0",
            "qualification_only": False, "sdk_archive": "sdk.tar.xz",
            "sdk_manifest_sha256": digest(inner),
            "assets": [row(name, data) for name, data in sorted(assets.items())],
            "sdk_files": [row(name, data) for name, data in sorted(sdk_entries.items())],
            "producer": {"repository": "metaneutrons/ami-rust"},
            "host_interpreters": {host: {"sha256": "a" * 64}
                                  for host in sorted(installer.HOSTS)},
        }
        raw = compact(manifest)
        auth = {
            "schema": "ami-rust-authentication-v2", "manifest_sha256": digest(raw),
            "workflow_runs": [{"run_id": 123456789, "run_attempt": 2,
                               "host_profile": "macos-aarch64"}],
            "gh_attestations": [{"path": name, "host_profile": "macos-aarch64",
                                 "bundle": f".auth/gh/{name.replace('/', '_')}.json"}
                                for name in sorted(("release.json", "sdk.tar.xz", "SHAUTIL"))],
            "cosign_bundles": [{"path": name,
                                "bundle": f".auth/cosign/{name.replace('/', '_')}.json"}
                               for name in sorted(("release.json", "sdk.tar.xz", "SHAUTIL"))],
        }
        inputs = compact({"schema": "ami-rust-publisher-inputs-v1", "materials": [
            {"uri": "https://example.invalid/sdk.tar.xz", "digest": {"sha256": "b" * 64}}
        ]})
        self.bundle.joinpath("release.json").write_bytes(raw)
        for name, data in assets.items():
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self._write_bundle_file(".auth/authentication.json", compact(auth))
        self._write_bundle_file(".auth/inputs.json", inputs)
        for row_value in auth["gh_attestations"] + auth["cosign_bundles"]:
            self._write_bundle_file(row_value["bundle"], b'{"synthetic":true}\n')
        self.manifest = manifest
        self.manifest_raw = raw
        self.assets = assets

    def _write_bundle_file(self, relative, data):
        path = self.bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def _policy(self):
        # These regular external files are only schema fixtures. The adapter
        # report is mocked; the bytes do not act as real trust anchors.
        pins = {}
        for name, content, executable in (
                ("gh", b"synthetic gh", True), ("cosign", b"synthetic cosign", True),
                ("gh-roots", b'{"synthetic":true}\n', False),
                ("cosign-root", b'{"synthetic":true}\n', False)):
            path = self.root / name
            path.write_bytes(content)
            if executable:
                path.chmod(0o700)
            pins[name] = {"path": str(path), "sha256": digest(content)}
        return {
            "schema": "ami-rust-publisher-trust-v2", "repository": "metaneutrons/ami-rust",
            "workflow": ".github/workflows/sdk-qualify.yml", "workflow_sha": "1" * 40,
            "source_sha": "2" * 40, "source_ref": "refs/heads/main",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "cert_identity": "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
            "inputs_manifest_sha256": digest((self.bundle / ".auth/inputs.json").read_bytes()),
            "allowed_host_profiles": ["macos-aarch64", "linux-x86_64"],
            "gh": pins["gh"], "cosign": pins["cosign"],
            "gh_trusted_roots": pins["gh-roots"], "cosign_trusted_root": pins["cosign-root"],
        }

    def _report(self):
        subjects = ["SHAUTIL", "release.json", "sdk.tar.xz"]
        return {
            "schema": "ami-rust-publisher-verification-v2", "verified": True,
            "repository": "metaneutrons/ami-rust", "workflow": ".github/workflows/sdk-qualify.yml",
            "workflowSha": "1" * 40, "sourceSha": "2" * 40, "sourceRef": "refs/heads/main",
            "manifestSha256": digest(self.manifest_raw),
            "workflowRuns": [{"runId": 123456789, "runAttempt": 2,
                              "hostProfile": "macos-aarch64"}],
            "attestedSubjects": subjects,
            "manifestBoundAssets": sorted(self.assets), "cosignSubjects": subjects,
            "publisherPolicyEvidence": (
                "environment and runnerEnvironment are signed SLSA predicate claims verified under the exact pinned workflow SHA; "
                "they are not independent Fulcio certificate fields"),
            "verificationMode": "offline pinned GH bundle/custom root and Cosign bundle/trusted root",
            "elapsedSeconds": 0.25,
        }

    def _verified(self):
        return production._verified_production_bundle(str(self.bundle), str(self.policy_path))

    def test_synthetic_adapter_installs_retains_report_and_uninstalls_atomically(self):
        report = self._report()
        with patch.object(production.publisher_verifier, "verify", return_value=report) as verify:
            verified = self._verified()
            self.assertEqual(verify.call_count, 1)
            result = installer._install_verified(verified, str(self.prefix), str(self.pin))
        self.assertEqual(result["status"], "installed")
        self.assertEqual(result["host"], verified["host"])
        self.assertIs(result["qualification_only"], False)
        self.assertEqual(self.pin.read_text().strip(), result["receipt_sha256"])
        receipt = json.loads((self.prefix / "install-receipt.json").read_text())
        self.assertEqual(receipt["schema"], "ami-rust-install-receipt-v2")
        self.assertEqual(receipt["publisher"], "metaneutrons.ami-rust.github")
        self.assertEqual(receipt["authentication"]["report"], report)
        self.assertEqual((self.prefix / "payload/release.json.sig").read_bytes(),
                         (self.bundle / ".auth/cosign/release.json.json").read_bytes())
        self.assertEqual(installer._installed(self.prefix, result["receipt_sha256"])[1]["schema"],
                         "ami-rust-install-receipt-v2")
        removed = installer._uninstall(self.prefix, result["receipt_sha256"])
        self.assertEqual(removed["status"], "uninstalled")
        self.assertFalse(self.prefix.exists())

    def test_production_install_cli_returns_the_verified_host(self):
        report = self._report()
        stdout = io.StringIO()
        isolated_sys = SimpleNamespace(
            flags=SimpleNamespace(isolated=True), dont_write_bytecode=True)
        with patch.object(production.publisher_verifier, "verify", return_value=report), \
                patch.object(production, "sys", isolated_sys), \
                redirect_stdout(stdout):
            exit_code = production.main([
                "install", "--bundle", str(self.bundle), "--policy", str(self.policy_path),
                "--prefix", str(self.prefix), "--receipt-pin", str(self.pin),
            ])
        self.assertEqual(exit_code, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["status"], "installed")
        self.assertEqual(result["host"], installer._host_key())
        self.assertIs(result["qualification_only"], False)
        self.assertEqual(result["receipt_sha256"], self.pin.read_text().strip())

    def test_modified_asset_is_rejected_after_synthetic_verifier(self):
        report = self._report()
        (self.bundle / "docs/readme.txt").write_bytes(b"modified\n")
        with patch.object(production.publisher_verifier, "verify", return_value=report):
            with self.assertRaisesRegex(installer.Refusal, "asset identity mismatch"):
                self._verified()
        self.assertFalse(self.prefix.exists())

    def test_legacy_manifest_path_rejects_nonqualification_candidate(self):
        with self.assertRaisesRegex(installer.Refusal, "qualification_only"):
            installer._release_manifest(self.manifest_raw)

    def test_policy_and_pinned_trust_must_be_external_to_bundle(self):
        bundled_policy = self.bundle / "publisher-policy.json"
        bundled_policy.write_bytes(compact(self.policy))
        with self.assertRaisesRegex(installer.Refusal, "policy must be outside"):
            production._load_policy(str(bundled_policy), self.bundle)
        self.policy["schema"] = "wrong-schema"
        self.policy_path.write_bytes(compact(self.policy))
        with self.assertRaises(verifier.PublisherVerificationError):
            self._verified()
        self.policy["schema"] = "ami-rust-publisher-trust-v2"
        self.policy["cosign_trusted_root"]["path"] = str(self.bundle / "release.json")
        self.policy["cosign_trusted_root"]["sha256"] = digest((self.bundle / "release.json").read_bytes())
        self.policy_path.write_bytes(compact(self.policy))
        with self.assertRaisesRegex(installer.Refusal, "outside the release bundle"):
            self._verified()

    def test_receipt_rejects_report_manifest_or_source_identity_drift(self):
        with patch.object(production.publisher_verifier, "verify", return_value=self._report()):
            verified = self._verified()
        authentication = verified["authentication"]
        authentication["report"]["sourceRef"] = "refs/tags/untrusted"
        with self.assertRaisesRegex(installer.Refusal, "identity mismatch"):
            installer._validate_authentication(authentication, digest(self.manifest_raw))


if __name__ == "__main__":
    unittest.main()

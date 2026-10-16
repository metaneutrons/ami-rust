"""Synthetic adapter tests for verifier policy and rejection mechanics only.

These tests mock gh/cosign outputs. They are not real signature or provenance
qualification and must never be reported as such.
"""
import hashlib
import json
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_publisher as verifier


WORKFLOW_SHA = "1" * 40
SOURCE_SHA = "2" * 40
HOST = "macos-aarch64"
RUN_ID = 123456789
ATTEMPT = 2


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class PublisherVerificationAdapterTests(unittest.TestCase):
    def test_nonfinite_json_constants_and_overflow_refused(self):
        for value in ("1e999", "-1e999", "NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), self.assertRaises(verifier.PublisherVerificationError):
                verifier._strict_json(('{"x":' + value + '}').encode(), "fixture")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "bundle"
        self.root.mkdir()
        self.gh_tool = self._file("tools/gh", b"fake-gh-binary")
        self.cosign_tool = self._file("tools/cosign", b"fake-cosign-binary")
        self.gh_tool.chmod(0o755)
        self.cosign_tool.chmod(0o755)
        self.gh_roots = self._file("roots/gh-roots.jsonl", b'{"trustedRoot":true}\n')
        self.cosign_root = self._file("roots/cosign-root.json", b'{"trustedRoot":true}')
        self.asset_bytes = {
            "sdk.tar.xz": b"sdk archive fixture",
            "SHAUTIL": b"sha utility fixture",
            "docs/readme.txt": b"transitively bound documentation",
        }
        rows = [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in sorted(self.asset_bytes.items())]
        self.manifest = {"schema": "ami-rust-release-v1", "qualification_only": False,
                         "assets": rows}
        raw_manifest = (canonical(self.manifest) + "\n").encode()
        self._write("release.json", raw_manifest)
        for name, data in self.asset_bytes.items():
            self._write(name, data)
        self.manifest_raw = raw_manifest
        self.input_materials = [
            {"uri": "https://example.invalid/toolchain.tar.xz",
             "digest": {"sha256": "a" * 64}},
            {"uri": "git+https://github.com/example/tool@main",
             "digest": {"gitCommit": "b" * 40}},
        ]
        self.inputs_manifest = {"schema": "ami-rust-publisher-inputs-v1",
                                "materials": self.input_materials}
        inputs_raw = (canonical(self.inputs_manifest) + "\n").encode()
        self._write(".auth/inputs.json", inputs_raw)
        self.inputs_sha = hashlib.sha256(inputs_raw).hexdigest()
        auth = {
            "schema": "ami-rust-authentication-v2",
            "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
            "workflow_runs": [{"run_id": RUN_ID, "run_attempt": ATTEMPT,
                               "host_profile": HOST}],
            "gh_attestations": [
                {"path": name, "host_profile": HOST,
                 "bundle": f".auth/gh/{name.replace('/', '_')}.json"}
                for name in sorted(verifier.DIRECT_SUBJECTS)
            ],
            "cosign_bundles": [
                {"path": name, "bundle": f".auth/cosign/{name.replace('/', '_')}.json"}
                for name in sorted(verifier.DIRECT_SUBJECTS)
            ],
        }
        self._write(".auth/authentication.json", (json.dumps(auth, sort_keys=True) + "\n").encode())
        for row in auth["gh_attestations"]:
            self._write(row["bundle"], b'{"synthetic":true}')
        for row in auth["cosign_bundles"]:
            self._write(row["bundle"], b'{"synthetic":true}')
        self.policy = {
            "schema": "ami-rust-publisher-trust-v2",
            "repository": "metaneutrons/ami-rust",
            "workflow": ".github/workflows/sdk-qualify.yml",
            "workflow_sha": WORKFLOW_SHA,
            "source_sha": SOURCE_SHA,
            "source_ref": "refs/heads/main",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "cert_identity": "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
            "inputs_manifest_sha256": self.inputs_sha,
            "allowed_host_profiles": [HOST, "linux-x86_64"],
            "gh": self._pin(self.gh_tool),
            "cosign": self._pin(self.cosign_tool),
            "gh_trusted_roots": self._pin(self.gh_roots),
            "cosign_trusted_root": self._pin(self.cosign_root),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def _file(self, relative, data):
        path = Path(self.tmp.name) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def _write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def _pin(self, path):
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def _subject_digest(self, subject):
        if subject == "release.json":
            data = self.manifest_raw
        else:
            data = self.asset_bytes[subject]
        return hashlib.sha256(data).hexdigest()

    def _gh_output(self, command):
        subject = Path(command[3]).name
        statement = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": subject, "digest": {"sha256": self._subject_digest(subject)}}],
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {"workflow": {
                        "repository": "https://github.com/metaneutrons/ami-rust",
                        "path": ".github/workflows/sdk-qualify.yml",
                        "ref": "refs/heads/main",
                    }},
                    "resolvedDependencies": [
                        {"uri": "git+https://github.com/metaneutrons/ami-rust@refs/heads/main",
                         "digest": {"gitCommit": SOURCE_SHA}},
                        *self.input_materials,
                    ],
                },
                "runDetails": {"metadata": {
                    "invocationId": f"https://github.com/metaneutrons/ami-rust/actions/runs/{RUN_ID}/attempts/{ATTEMPT}",
                    "publisherPolicy": {
                        "environment": "release", "runnerEnvironment": "github-hosted",
                        "repository": "metaneutrons/ami-rust",
                        "workflow": ".github/workflows/sdk-qualify.yml",
                        "workflowSha": WORKFLOW_SHA, "sourceSha": SOURCE_SHA,
                        "sourceRef": "refs/heads/main",
                        "inputsManifestSha256": self.inputs_sha,
                        "hostProfile": HOST,
                    },
                }},
            },
        }
        result = {"attestation": {"synthetic": True},
                  "verificationResult": {"signature": {"certificate": {"synthetic": True}},
                                         "statement": statement}}
        return (json.dumps([result]) + "\n").encode()

    def _adapter(self, command, *, deadline, env):
        if command[1:3] == ["attestation", "verify"]:
            self.assertIn("--deny-self-hosted-runners", command)
            self.assertIn("--custom-trusted-root", command)
            self.assertIn(str(self.gh_roots.resolve()), command)
            for option, value in (
                ("--cert-identity", self.policy["cert_identity"]),
                ("--cert-oidc-issuer", "https://token.actions.githubusercontent.com"),
                ("--signer-workflow", "metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml"),
                ("--signer-digest", WORKFLOW_SHA),
                ("--source-digest", SOURCE_SHA),
                ("--source-ref", "refs/heads/main"),
                ("--predicate-type", "https://slsa.dev/provenance/v1"),
            ):
                self.assertIn(option, command)
                self.assertEqual(command[command.index(option) + 1], value)
            return self._gh_output(command)
        if command[1] == "verify-blob":
            self.assertIn("--trusted-root", command)
            self.assertIn(str(self.cosign_root.resolve()), command)
            self.assertIn(self.policy["cert_identity"], command)
            self.assertIn("https://token.actions.githubusercontent.com", command)
            self.assertIn("refs/heads/main", command)
            self.assertIn(WORKFLOW_SHA, command)
            return b""
        self.fail(f"unexpected verifier command: {command}")

    def _verify_with_adapter(self, adapter=None):
        adapter = adapter or self._adapter
        with patch.object(verifier, "_run_command", side_effect=adapter):
            return verifier.verify(self.root, self.manifest, self.policy)

    def test_accepts_exact_synthetic_policy_and_separates_direct_subjects(self):
        calls = []

        def adapter(command, **kwargs):
            calls.append(command)
            return self._adapter(command, **kwargs)

        result = self._verify_with_adapter(adapter)
        self.assertTrue(result["verified"])
        self.assertEqual(result["workflowRuns"], [{"runId": RUN_ID, "runAttempt": ATTEMPT,
                                                    "hostProfile": HOST}])
        self.assertEqual(set(result["attestedSubjects"]), verifier.DIRECT_SUBJECTS)
        self.assertEqual(set(result["cosignSubjects"]), verifier.DIRECT_SUBJECTS)
        self.assertEqual(set(result["manifestBoundAssets"]), set(self.asset_bytes))
        self.assertEqual(sum(call[1:3] == ["attestation", "verify"] for call in calls), 3)
        self.assertEqual(sum(call[1] == "verify-blob" for call in calls), 3)

    def test_rejects_old_private_input_commit_policy(self):
        self.policy["schema"] = "ami-rust-publisher-trust-v1"
        self.policy["input_commit"] = "3" * 40
        self.policy.pop("inputs_manifest_sha256")
        with patch.object(verifier, "_run_command") as run:
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)
        run.assert_not_called()

    def test_rejects_wrong_signed_source_dependency(self):
        def wrong_source(command, **kwargs):
            if command[1:3] == ["attestation", "verify"]:
                output = self._gh_output(command).decode().replace(SOURCE_SHA, "4" * 40).encode()
                return output
            return b""

        with patch.object(verifier, "_run_command", side_effect=wrong_source):
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)

    def test_rejects_changed_input_manifest_before_tool_use(self):
        (self.root / ".auth/inputs.json").write_bytes(b'{"schema":"ami-rust-publisher-inputs-v1","materials":[]}')
        with patch.object(verifier, "_run_command") as run:
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)
        run.assert_not_called()

    def test_rejects_signed_material_set_mismatch(self):
        def wrong_materials(command, **kwargs):
            if command[1:3] == ["attestation", "verify"]:
                output = self._gh_output(command).decode().replace("a" * 64, "c" * 64).encode()
                return output
            return b""

        with patch.object(verifier, "_run_command", side_effect=wrong_materials):
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)

    def test_rejects_non_hosted_runner_claim(self):
        def self_hosted(command, **kwargs):
            if command[1:3] == ["attestation", "verify"]:
                output = self._gh_output(command).decode().replace("github-hosted", "self-hosted").encode()
                return output
            return b""

        with patch.object(verifier, "_run_command", side_effect=self_hosted):
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)

    def test_rejects_wrong_signed_release_environment_claim(self):
        def wrong_environment(command, **kwargs):
            if command[1:3] == ["attestation", "verify"]:
                output = self._gh_output(command).decode().replace('"environment": "release"',
                                                                    '"environment": "test"').encode()
                return output
            return b""

        with patch.object(verifier, "_run_command", side_effect=wrong_environment):
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)

    def test_rejects_extra_payload_even_when_unlisted(self):
        self._write("extra.bin", b"unbound")
        with patch.object(verifier, "_run_command") as run:
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)
        run.assert_not_called()

    def test_rejects_payload_digest_change_before_tool_use(self):
        (self.root / "SHAUTIL").write_bytes(b"changed")
        with patch.object(verifier, "_run_command") as run:
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)
        run.assert_not_called()

    def test_rejects_duplicate_authentication_json_keys(self):
        auth = self.root / ".auth/authentication.json"
        auth.write_text('{"schema":"ami-rust-authentication-v2","schema":"x"}')
        with patch.object(verifier, "_run_command") as run:
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)
        run.assert_not_called()

    def test_rejects_qualification_only_manifest(self):
        qualification_manifest = dict(self.manifest, qualification_only=True)
        with patch.object(verifier, "_run_command") as run:
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, qualification_manifest, self.policy)
        run.assert_not_called()

    def test_rejects_wrong_tool_pin(self):
        self.policy["gh"]["sha256"] = "0" * 64
        with patch.object(verifier, "_run_command") as run:
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier.verify(self.root, self.manifest, self.policy)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

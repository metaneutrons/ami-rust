#!/usr/bin/env python3
"""Synthetic adapter tests only; mocked verifier output is not crypto evidence."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("candidate_auth.py")
SPEC = importlib.util.spec_from_file_location("outer_candidate_auth_test_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
candidate_auth = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = candidate_auth
SPEC.loader.exec_module(candidate_auth)

verifier = candidate_auth.verifier
stage_candidate = candidate_auth.stage_candidate

WORKFLOW_SHA = "1" * 40
SOURCE_SHA = "2" * 40
INPUTS_SHA = "3" * 64
RUN_ID = 123456789
RUN_ATTEMPT = 3
HOST = "linux-x86_64"


class OuterCandidateAuthAdapterTests(unittest.TestCase):
    """These tests exercise policy parsing with synthetic CLI responses only."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="outer-candidate-auth-test-")
        self.root = Path(self.temp.name).resolve()
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.policy = {
            "schema": verifier.POLICY_SCHEMA,
            "repository": verifier.REPOSITORY,
            "workflow": verifier.WORKFLOW,
            "workflow_sha": WORKFLOW_SHA,
            "source_sha": SOURCE_SHA,
            "source_ref": verifier.SOURCE_REF,
            "oidc_issuer": verifier.OIDC_ISSUER,
            "cert_identity": f"https://github.com/{verifier.REPOSITORY}/{verifier.WORKFLOW}@{verifier.SOURCE_REF}",
            "inputs_manifest_sha256": INPUTS_SHA,
            "allowed_host_profiles": [HOST],
            "gh": {"path": "/pinned/tools/gh", "sha256": "a" * 64},
            "cosign": {"path": "/pinned/tools/cosign", "sha256": "b" * 64},
            "gh_trusted_roots": {"path": "/pinned/roots/gh.jsonl", "sha256": "c" * 64},
            "cosign_trusted_root": {"path": "/pinned/roots/cosign.json", "sha256": "d" * 64},
        }
        self.identity = {"source_sha": SOURCE_SHA, "workflow_sha": WORKFLOW_SHA,
                         "run_id": RUN_ID, "run_attempt": RUN_ATTEMPT}
        self.materials = [{"uri": "https://example.invalid/tool.tar.xz",
                           "digest": {"sha256": "e" * 64}}]
        self.tag = "v1.2.3"
        self.names = stage_candidate.asset_names(self.tag)
        self.subjects = {self.names[key] for key in ("payload", "sbom", "transport", "checksums")}
        self.asset_rows = {}
        for subject in sorted({self.names[key] for key in self.names}):
            raw = ("fixture asset " + subject).encode()
            self.asset_rows[subject] = (len(raw), hashlib.sha256(raw).hexdigest())
            if subject != self.names["checksums"]:
                (self.candidate / subject).write_bytes(raw)
        # This helper-level test does not call the structural candidate verifier;
        # the report subject digest is the only input used below.
        self.asset_rows[self.names["checksums"]] = (12, hashlib.sha256(b"fixture sums").hexdigest())
        self.expected_predicate = self._predicate()
        self.gh_bundles = {}
        for subject in self.subjects:
            path = self.root / (subject.replace("/", "_") + ".gh.json")
            path.write_text(json.dumps({"fixture_only": True}, sort_keys=True), encoding="utf-8")
            self.gh_bundles[subject] = path

    def tearDown(self):
        self.temp.cleanup()

    def _predicate(self):
        return {
            "buildDefinition": {
                "buildType": verifier.BUILD_TYPE,
                "externalParameters": {"workflow": {
                    "repository": f"https://github.com/{verifier.REPOSITORY}",
                    "path": verifier.WORKFLOW, "ref": verifier.SOURCE_REF}},
                "resolvedDependencies": [
                    {"uri": f"git+https://github.com/{verifier.REPOSITORY}@{verifier.SOURCE_REF}",
                     "digest": {"gitCommit": SOURCE_SHA}}, *self.materials],
                "internalParameters": {"github": dict(verifier.GITHUB_BUILD_PARAMETERS),
                    "publisherPolicy": {
                    "environment": "release", "runnerEnvironment": "github-hosted",
                    "repository": verifier.REPOSITORY, "workflow": verifier.WORKFLOW,
                    "workflowSha": WORKFLOW_SHA, "sourceSha": SOURCE_SHA,
                    "sourceRef": verifier.SOURCE_REF,
                    "inputsManifestSha256": INPUTS_SHA, "hostProfile": HOST,
                }},
            },
            "runDetails": {
                "builder": {"id": f"https://github.com/{verifier.REPOSITORY}/{verifier.WORKFLOW}@{verifier.SOURCE_REF}"},
                "metadata": {
                    "invocationId": f"https://github.com/{verifier.REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}",
                },
            },
        }

    def _write_statement(self, subject, *, predicate=None):
        row = self.asset_rows[subject]
        statement = {
            "predicateType": verifier.PREDICATE_TYPE,
            "subject": [{"name": subject, "digest": {"sha256": row[1]}}],
            "predicate": self.expected_predicate if predicate is None else predicate,
        }
        self.gh_bundles[subject].write_text(
            json.dumps({"statement": statement}, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _mock_gh_runner(argv, *, deadline, env):
        bundle_path = Path(argv[argv.index("--bundle") + 1])
        fixture = json.loads(bundle_path.read_text(encoding="utf-8"))
        result = [{"attestation": {"fixture_only": True},
                   "verificationResult": {
                       "statement": fixture["statement"],
                       "signature": {"certificate": {"fixture_only": True}},
                   }}]
        return json.dumps(result, sort_keys=True).encode()

    @staticmethod
    def _build_candidate(root):
        bundle = root / "inner"
        bundle.mkdir()
        sbom = b'{"spdxVersion":"SPDX-2.3","packages":[]}\n'
        (bundle / "sbom.spdx.json").write_bytes(sbom)
        manifest = {
            "schema": "ami-rust-release-v1", "version": "1.2.3",
            "qualification_only": False,
            "assets": [{"path": "sbom.spdx.json", "bytes": len(sbom),
                        "sha256": hashlib.sha256(sbom).hexdigest()}],
            "producer": {"source_sha": SOURCE_SHA},
        }
        (bundle / "release.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        candidate = root / "candidate"
        stage_candidate.prepare("v1.2.3", bundle, candidate)
        names = stage_candidate.asset_names("v1.2.3")
        (candidate / names["payload_signature"]).write_text('{"fixture":true}\n', encoding="utf-8")
        (candidate / names["transport_signature"]).write_text('{"fixture":true}\n', encoding="utf-8")
        stage_candidate.finalize(candidate, "v1.2.3")
        return candidate

    def test_full_prepare_finalize_verify_adapter_roundtrip_with_mock_crypto(self):
        # Real packing, structural readback, metadata binding and proof snapshots;
        # only trusted tool bootstrap and cryptographic command execution are mocks.
        base = self.root / "full-adapter"
        base.mkdir()
        bundle = base / "inner"
        bundle.mkdir()
        (bundle / ".auth").mkdir()
        inputs_raw = candidate_auth._canonical_json({"schema":verifier.INPUTS_SCHEMA,
                                                     "materials":self.materials})
        (bundle / ".auth/inputs.json").write_bytes(inputs_raw)
        self.policy["inputs_manifest_sha256"] = hashlib.sha256(inputs_raw).hexdigest()
        payload = b'{"spdxVersion":"SPDX-2.3","packages":[]}\n'
        (bundle / "sbom.spdx.json").write_bytes(payload)
        manifest = {"schema":"ami-rust-release-v1", "version":"1.2.3",
                    "qualification_only":False,
                    "assets":[{"path":"sbom.spdx.json", "bytes":len(payload),
                               "sha256":hashlib.sha256(payload).hexdigest()}],
                    "producer":{"kind":"protected-github-actions", "repository":verifier.REPOSITORY,
                                "workflow":verifier.WORKFLOW, "source_sha":SOURCE_SHA,
                                "workflow_sha":WORKFLOW_SHA, "run_id":RUN_ID,
                                "run_attempt":RUN_ATTEMPT,
                                "acceptance":"R1 acceptance and publication are separate gates"}}
        raw_manifest = candidate_auth._canonical_json(manifest)
        (bundle / "release.json").write_bytes(raw_manifest)
        candidate = base / "candidate"
        work, metadata, python = (base / name for name in ("work", "metadata", "python"))
        for path in (work, metadata, python):
            path.mkdir(mode=0o700)
        (metadata / "tool-bootstrap.json").write_bytes(b"{}")
        inner_result = {"verified":True,"sourceSha":SOURCE_SHA,"workflowSha":WORKFLOW_SHA,
                        "sourceRef":verifier.SOURCE_REF,
                        "manifestSha256":hashlib.sha256(raw_manifest).hexdigest(),
                        "workflowRuns":[{"runId":RUN_ID,"runAttempt":RUN_ATTEMPT,"hostProfile":HOST}]}
        with patch.object(candidate_auth, "_trusted_context", return_value=(self.identity, {}, self.policy, python)), \
             patch.object(verifier, "verify", return_value=inner_result):
            prepared = candidate_auth.prepare(bundle, candidate, work, metadata, python)
            self.assertEqual(prepared["github_outputs"]["payload_name"], self.names["payload"])
            for key in ("payload_signature", "transport_signature"):
                (candidate / self.names[key]).write_text('{"fixture":true}\n')
            finalized = stage_candidate.finalize(candidate, self.tag)
            (metadata / "outer-finalized.json").write_bytes(candidate_auth._canonical_json(finalized))
            digests = {row["path"]:row["sha256"] for row in finalized["assets"]}
            predicate = json.loads((metadata / "outer-predicate.json").read_bytes())
            proofs = []
            for subject in sorted(self.subjects):
                proof = base / (subject + ".json")
                statement = {"predicateType":verifier.PREDICATE_TYPE,
                             "subject":[{"name":subject,"digest":{"sha256":digests[subject]}}],
                             "predicate":predicate}
                proof.write_bytes(candidate_auth._canonical_json({"statement":statement}))
                proofs.append(subject + "=" + str(proof))

            def command(argv, *, deadline, env):
                is_gh = argv[1:3] == ["attestation", "verify"]
                target = Path(argv[3] if is_gh else argv[2])
                if hashlib.sha256(target.read_bytes()).hexdigest() != digests[target.name]:
                    raise verifier.PublisherVerificationError(
                        "pinned verifier rejected evidence (1): mocked digest mismatch")
                return self._mock_gh_runner(argv, deadline=deadline, env=env) if is_gh else b""

            result = candidate_auth.verify(candidate, bundle, work, metadata, python, proofs, runner=command)
        self.assertEqual(result["status"], candidate_auth.VERIFIED_STATUS)
        self.assertIs(result["r1_accepted"], False)
        self.assertEqual(len(result["commands"]), 8)
        self.assertEqual(len(result["gh_bundles"]), 4)
        self.assertEqual(json.loads((metadata / "outer-verification.json").read_bytes()), result)
        for subject, row in result["gh_bundles"].items():
            saved = metadata / row["path"]
            self.assertEqual(hashlib.sha256(saved.read_bytes()).hexdigest(), row["sha256"])

    def test_four_singleton_predicates_are_checked_against_exact_source_and_run(self):
        for subject in self.subjects:
            self._write_statement(subject)
        commands = []
        candidate_auth._verify_gh_attestations(
            self.candidate, self.tag, self.asset_rows, self.gh_bundles, self.policy,
            self.identity, self.expected_predicate, self.materials,
            {"PATH": "/usr/bin"}, time.monotonic() + 30, commands,
            runner=self._mock_gh_runner)
        self.assertEqual(len(commands), 4)
        self.assertTrue(all(row["exit_code"] == 0 for row in commands))
        self.assertEqual({row["label"].split(":", 1)[1] for row in commands}, self.subjects)
        for row in commands:
            argv = row["argv"]
            self.assertIn("--deny-self-hosted-runners", argv)
            self.assertEqual(argv[argv.index("--source-digest") + 1], SOURCE_SHA)
            self.assertEqual(argv[argv.index("--signer-digest") + 1], WORKFLOW_SHA)

    def test_wrong_signed_source_claim_is_rejected_after_command_success(self):
        wrong = json.loads(json.dumps(self.expected_predicate))
        wrong["buildDefinition"]["internalParameters"]["publisherPolicy"]["sourceSha"] = "4" * 40
        subject = sorted(self.subjects)[0]
        self._write_statement(subject, predicate=wrong)
        with self.assertRaisesRegex(verifier.PublisherVerificationError, "publisherPolicy"):
            candidate_auth._verify_gh_attestations(
                self.candidate, self.tag, self.asset_rows, self.gh_bundles, self.policy,
                self.identity, self.expected_predicate, self.materials,
                {"PATH": "/usr/bin"}, time.monotonic() + 30, [],
                runner=self._mock_gh_runner)

    def test_wrong_invocation_run_is_rejected_even_when_source_matches(self):
        wrong = json.loads(json.dumps(self.expected_predicate))
        wrong["runDetails"]["metadata"]["invocationId"] = (
            f"https://github.com/{verifier.REPOSITORY}/actions/runs/{RUN_ID + 1}/attempts/{RUN_ATTEMPT}")
        subject = sorted(self.subjects)[0]
        self._write_statement(subject, predicate=wrong)
        with self.assertRaisesRegex(verifier.PublisherVerificationError, "invocationId"):
            candidate_auth._verify_gh_attestations(
                self.candidate, self.tag, self.asset_rows, self.gh_bundles, self.policy,
                self.identity, self.expected_predicate, self.materials,
                {"PATH": "/usr/bin"}, time.monotonic() + 30, [],
                runner=self._mock_gh_runner)

    def test_incomplete_attestation_set_fails_before_invoking_tools(self):
        called = False

        def runner(argv, *, deadline, env):
            nonlocal called
            called = True
            return b"[]"

        incomplete = dict(self.gh_bundles)
        incomplete.pop(sorted(self.subjects)[0])
        with self.assertRaisesRegex(candidate_auth.CandidateAuthenticationError, "exactly four"):
            candidate_auth._verify_gh_attestations(
                self.candidate, self.tag, self.asset_rows, incomplete, self.policy,
                self.identity, self.expected_predicate, self.materials,
                {"PATH": "/usr/bin"}, time.monotonic() + 30, [], runner=runner)
        self.assertFalse(called)

    def test_real_verifier_command_failure_is_preserved_with_its_exit_code(self):
        subject = sorted(self.subjects)[0]
        self._write_statement(subject)
        commands = []

        def failed_command(argv, *, deadline, env):
            raise verifier.PublisherVerificationError(
                "pinned verifier rejected evidence (17): fixture rejection")

        with self.assertRaisesRegex(verifier.PublisherVerificationError, "17"):
            candidate_auth._verify_gh_attestations(
                self.candidate, self.tag, self.asset_rows, self.gh_bundles, self.policy,
                self.identity, self.expected_predicate, self.materials,
                {"PATH": "/usr/bin"}, time.monotonic() + 30, commands,
                runner=failed_command)
        self.assertEqual(commands[0]["exit_code"], 17)
        self.assertEqual(commands[0]["status"], "rejected")

    def test_mutated_payload_probe_requires_both_crypto_commands_to_reject(self):
        fixture_root = self.root / "counterprobe-fixture"
        fixture_root.mkdir()
        candidate = self._build_candidate(fixture_root)
        work = self.root / "work"
        work.mkdir()
        names = stage_candidate.asset_names("v1.2.3")
        gh_payload_bundle = fixture_root / "payload.gh.json"
        gh_payload_bundle.write_text('{"fixture_only":true}\n', encoding="utf-8")
        commands = []

        def reject_mutation(argv, *, deadline, env):
            raise verifier.PublisherVerificationError(
                "pinned verifier rejected evidence (1): mutated subject digest mismatch")

        result = candidate_auth._counterprobes(
            candidate, "v1.2.3", self.policy, gh_payload_bundle, work,
            {"PATH": "/usr/bin"}, time.monotonic() + 30, commands,
            runner=reject_mutation)
        self.assertTrue(result["missing_asset"]["rejected"])
        self.assertTrue(result["mutated_payload"]["github"]["rejected"])
        self.assertTrue(result["mutated_payload"]["cosign"]["rejected"])
        self.assertNotEqual(result["mutated_payload"]["original_sha256"],
                            result["mutated_payload"]["mutated_sha256"])
        self.assertEqual([row["exit_code"] for row in commands], [1, 1])
        self.assertEqual({row["label"] for row in commands}, {
            "counterprobe:github-mutated-payload",
            "counterprobe:cosign-mutated-payload",
        })
        self.assertEqual(list(work.iterdir()), [])

    def test_corrupt_asset_fails_real_candidate_checksum_validation(self):
        with tempfile.TemporaryDirectory(prefix="outer-candidate-corrupt-") as temporary:
            root = Path(temporary).resolve()
            candidate = self._build_candidate(root)
            names = stage_candidate.asset_names("v1.2.3")
            payload = candidate / names["payload"]
            with payload.open("r+b") as stream:
                stream.write(b"x")
            with self.assertRaisesRegex(ValueError, "SHA256SUMS"):
                stage_candidate.verify_candidate(candidate, "v1.2.3")


if __name__ == "__main__":
    unittest.main()

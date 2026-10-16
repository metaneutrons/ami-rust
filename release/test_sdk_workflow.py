"""Execute the actual SDK workflow cleanup and proposal gates on tiny payloads."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/sdk-qualify.yml"
SOURCE = WORKFLOW.read_text()
CLEANUP = textwrap.dedent(SOURCE.split("python3 -I -B - <<'PYCODE'\n", 1)[1].split("          PYCODE", 1)[0])
OUTER = SOURCE.split("\n  release-candidate:\n", 1)[1].split("\n  assemble:\n", 1)[0]
OUTER_CLEANUP = textwrap.dedent(OUTER.split("name: Retire release work and preserve bounded candidate evidence", 1)[1]
                              .split("python3 -I -B - <<'PYCODE'\n", 1)[1].split("          PYCODE", 1)[0])


class WorkflowProposalTests(unittest.TestCase):
    def run_cleanup(self, proposal, *, selected=None, different_roots=False):
        with tempfile.TemporaryDirectory(prefix="sdk-proposal-gates-") as directory:
            root = Path(directory)
            output = root / "ami-rust-sdk-output"
            output.mkdir()
            (root / "ami-rust-sdk-work").mkdir()
            python_root = root / "ami-rust-python-bootstrap"
            python_root.mkdir()
            (python_root / "bootstrap.json").write_text("{}")
            def write(name, value):
                (output / name).write_text(json.dumps(value))
            variants = ("minimal-noalloc", "minimal-alloc", "qualification", "dependencies", "sha256sum")
            payloads = {}
            names = ["sdk.tar.xz", "cargo-component.tar.xz", *["native/" + v + ".AMIRUST" for v in variants]]
            if proposal:
                names += ["metadata/" + crate + ".rlib" for crate in ("serde", "curve25519_dalek", "ed25519_dalek")]
            for name in names:
                p = output / name
                p.parent.mkdir(exist_ok=True)
                p.write_bytes(name.encode())
                payloads[name] = {"path": name, "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            csdk = {"schema": "ami-rust-portable-csdk-producer-v1", "status": "PRODUCED_CSDK_COMPONENT_CANDIDATE_NOT_R1_ACCEPTED", "host": "linux-x86_64", "spec_sha256": "a" * 64}
            write("csdk-producer.json", csdk)
            csdk_sha = hashlib.sha256((output / "csdk-producer.json").read_bytes()).hexdigest()
            builds = []
            for layout in ("sdk-layout-a", "sdk-layout-b"):
                for variant in variants:
                    builds.append({"layout": layout, "variant": variant, "reference_match": not proposal,
                                   "canonical_artifacts": {"AMIRUST": {"bytes": 1, "sha256": "b" * 64}}})
            if different_roots:
                builds[-1]["canonical_artifacts"] = {"AMIRUST": {"bytes": 2, "sha256": "c" * 64}}
            sdk = {"schema": "ami-rust-hosted-sdk-producer-v1", "host": "linux-x86_64",
                   "status": "PRODUCED_NATIVE_REFERENCE_PROPOSAL_NOT_FOR_AUTHENTICATION" if proposal else "PRODUCED_HOSTED_SDK_CANDIDATE_NOT_R1_ACCEPTED",
                   "reference_proposal": proposal, "source": {"qualification_only": False, "sdk_archive": payloads["sdk.tar.xz"]},
                   "cargo_component": {"archive": payloads["cargo-component.tar.xz"]},
                   "native_payloads": [payloads["native/" + v + ".AMIRUST"] for v in variants], "native_builds": builds, "metadata_archives": [row for name, row in payloads.items() if name.startswith("metadata/")],
                   "inputs": {"portable_csdk": {"producer_receipt_sha256": csdk_sha, "spec": {"sha256": "a" * 64}}}}
            write("sdk-producer.json", sdk)
            write("producer.json", {"schema": "ami-rust-hosted-custom-cargo-producer-v1", "host": "linux-x86_64", "status": "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION"})
            environment = {**os.environ, "RUNNER_TEMP": str(root), "REFERENCE_PROPOSAL": str(proposal if selected is None else selected).lower(),
                           "EXPECTED_HOST": "linux-x86_64", "PRODUCER_RESULT": "success", "PYTHON_RESULT": "success",
                           "WORKFLOW_SOURCE_COMMIT": "d" * 40, "WORKFLOW_RUN_ID": "1", "WORKFLOW_RUN_ATTEMPT": "1"}
            result = subprocess.run([sys.executable, "-I", "-B", "-c", CLEANUP], env=environment, capture_output=True, text=True)
            retained = all((output / p).is_file() for p in payloads)
            return result, retained

    def test_actual_cleanup_preserves_proposals_and_verified_normal_outputs(self):
        compile(CLEANUP, str(WORKFLOW), "exec")
        for proposal in (False, True):
            with self.subTest(proposal=proposal):
                result, retained = self.run_cleanup(proposal)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(retained)
                self.assertIs(json.loads(result.stdout)["R1_accepted"], False)

    def test_proposal_cannot_be_accepted_under_normal_workflow_selection(self):
        result, _ = self.run_cleanup(True, selected=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unrecognized SDK producer receipt", result.stderr)

    def test_proposal_cold_roots_must_really_match(self):
        result, _ = self.run_cleanup(True, different_roots=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("matching cold roots", result.stderr)

    def test_assembly_is_explicitly_skipped_for_proposals(self):
        self.assertIn("  assemble:\n    if: ${{ !inputs.reference_proposal }}", SOURCE)
        self.assertIn("needs: assemble", SOURCE)
        self.assertIn("needs: authenticate", SOURCE)


class WorkflowAdmissionTests(unittest.TestCase):
    def test_reserves_complete_dag_once_before_both_producers(self):
        admission = SOURCE.split("\n  admission:\n", 1)[1].split("\n  producer:\n", 1)[0]
        producer = SOURCE.split("\n  producer:\n", 1)[1].split("\n  release-candidate:\n", 1)[0]
        command = "release/ci_artifact_admission.py --sdk-candidate"
        self.assertEqual(SOURCE.count(command), 1)
        self.assertIn(command, admission)
        self.assertIn("environment: release", admission)
        self.assertIn("test \"$SOURCE_IS_PROTECTED\" = true", admission)
        self.assertIn("needs: admission", producer)
        self.assertIn("needs.admission.result == 'success'", producer)
        self.assertNotIn("steps.admission", producer)

    def test_bootstrap_uses_siblings_and_preserves_receipt_for_outer_verifier(self):
        bootstrap = OUTER.split("name: Bootstrap pinned verifier tools and roots", 1)[1].split(
            "      - name: Verify inner publisher", 1)[0]
        self.assertIn('--output "$RUNNER_TEMP/ami-rust-release-bootstrap"', bootstrap)
        self.assertNotIn('--output "$RUNNER_TEMP/ami-rust-release-output/metadata"', bootstrap)
        self.assertIn('install -d -m 700 "$RUNNER_TEMP/ami-rust-release-output/metadata"', bootstrap)
        self.assertIn('"$RUNNER_TEMP/ami-rust-release-bootstrap/tool-bootstrap.json"', bootstrap)
        self.assertIn('"$RUNNER_TEMP/ami-rust-release-output/metadata/tool-bootstrap.json"', bootstrap)


    def test_each_attestation_is_copied_before_the_action_can_reuse_its_path(self):
        with tempfile.TemporaryDirectory(prefix="outer-attest-copy-") as directory:
            root = Path(directory).resolve()
            original = root / "reused-action-bundle.json"
            for key, following in (("payload", "payload SBOM"), ("sbom", "transport inventory"),
                                   ("transport", "complete checksums"), ("checksums", None)):
                position = OUTER.index("id: attest-" + key + "\n")
                preserve = OUTER.index("ami-rust-release-attestations/" + key + ".json", position)
                if following:
                    self.assertLess(preserve, OUTER.index("name: Attest " + following))
                # Execute the actual workflow's copy commands using a reused
                # action output path. Earlier proofs must remain unchanged.
                block = OUTER[position:].split("        run: |\n", 1)[1].split("      - name:", 1)[0]
                script = textwrap.dedent(block)
                original.write_text(key)
                subprocess.run(["/bin/bash", "-e", "-c", script], check=True,
                               env={**os.environ, "RUNNER_TEMP":str(root), "BUNDLE_PATH":str(original)})
            original.write_text("overwritten action output")
            for key in ("payload", "sbom", "transport", "checksums"):
                self.assertEqual((root / "ami-rust-release-attestations" / (key + ".json")).read_text(), key)


class OuterWorkflowTests(unittest.TestCase):
    def run_cleanup(self, *, receipt=True, wrong_source=False, outcome="success", oversized=False):
        with tempfile.TemporaryDirectory(prefix="outer-cleanup-") as directory:
            root = Path(directory).resolve()
            for name in ('ami-rust-release-inner', 'ami-rust-release-work', 'ami-rust-release-bootstrap', 'ami-rust-release-attestations', 'ami-rust-python-bootstrap'):
                (root / name).mkdir()
            output = root / 'ami-rust-release-output'
            metadata = output / 'metadata'
            metadata.mkdir(parents=True)
            candidate = output / 'candidate'
            candidate.mkdir()
            (candidate / 'fixture').write_bytes(b'unchanged fixture')
            if oversized:
                with (candidate / 'sparse').open('wb') as stream:
                    stream.truncate(97 * 1024**2)
            if receipt:
                (metadata / 'outer-verification.json').write_text(json.dumps({
                    'status':'OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED',
                    'source_commit':('b' if wrong_source else 'a') * 40,
                    'run_id':123, 'run_attempt':1}))
            env = {**os.environ, 'RUNNER_TEMP':str(root), 'VERIFY_RESULT':outcome,
                   'GITHUB_SHA':'a' * 40, 'GITHUB_RUN_ID':'123', 'GITHUB_RUN_ATTEMPT':'1'}
            result = subprocess.run([sys.executable, '-I', '-B', '-c', OUTER_CLEANUP],
                                    capture_output=True, text=True, env=env)
            self.assertFalse((root / 'ami-rust-release-work').exists())
            self.assertFalse((root / 'ami-rust-release-bootstrap').exists())
            self.assertEqual((candidate / 'fixture').read_bytes(), b'unchanged fixture')
            cleanup = metadata / 'cleanup.json'
            return result, json.loads(cleanup.read_bytes()) if cleanup.exists() else None

    def test_success_requires_real_bound_receipt_and_retires_work(self):
        result, receipt = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(receipt['verification_outcome'], 'success')
        self.assertIs(receipt['SDK_published'], False)
        self.assertEqual(receipt['remaining_work_bytes'], 0)

    def test_success_without_receipt_or_with_other_source_fails(self):
        for options in ({'receipt':False}, {'wrong_source':True}):
            with self.subTest(options=options):
                result, receipt = self.run_cleanup(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(receipt)

    def test_failed_verification_preserves_partial_candidate_without_success_claim(self):
        result, receipt = self.run_cleanup(receipt=False, outcome='failure')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(receipt['verification_outcome'], 'failure')
        self.assertIs(receipt['SDK_published'], False)

    def test_actual_retained_output_bound_is_enforced(self):
        result, receipt = self.run_cleanup(oversized=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('96 MiB output', result.stderr)
        self.assertIsNone(receipt)

    def test_outer_signer_depends_on_consumers_and_excludes_proposals(self):
        self.assertIn('if: ${{ !inputs.reference_proposal }}', OUTER)
        self.assertIn('needs: [consumer]', OUTER)
        self.assertNotIn('release upload', OUTER)
        self.assertNotIn('release edit', OUTER)


if __name__ == "__main__":
    unittest.main()

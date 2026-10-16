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


if __name__ == "__main__":
    unittest.main()

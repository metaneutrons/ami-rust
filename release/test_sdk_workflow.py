"""Execute the actual SDK workflow cleanup and proposal gates on tiny payloads."""
import hashlib
import json
import os
import re
from types import SimpleNamespace
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
    def run_cleanup(self, proposal, *, selected=None, different_roots=False,
                    producer_success=True, diagnostics=False, diagnostic_link=False):
        with tempfile.TemporaryDirectory(prefix="sdk-proposal-gates-") as directory:
            root = Path(directory)
            output = root / "ami-rust-sdk-output"
            output.mkdir()
            (root / "ami-rust-sdk-work").mkdir()
            work = root / "ami-rust-sdk-work"
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
            if not producer_success:
                sdk.update(status="FAILED", error="fixture failure")
                write("sdk-producer.json", sdk)
            if diagnostics:
                diag = work / "cold-root-diagnostics"
                raw = diag / "raw"
                raw.mkdir(parents=True)
                first_bytes = b"first rlib bytes"
                second_bytes = b"second rlib bytes"
                first_sha = hashlib.sha256(first_bytes).hexdigest()
                second_sha = hashlib.sha256(second_bytes).hexdigest()
                member = "target/release/deps/libserde-abc123.rlib"
                first_map = {"AMIRUST": {"bytes": 1, "sha256": "b" * 64},
                             member: {"bytes": len(first_bytes), "sha256": first_sha}}
                second_map = {"AMIRUST": {"bytes": 1, "sha256": "b" * 64},
                              member: {"bytes": len(second_bytes), "sha256": second_sha}}
                for name, content in (("member-000-first.bin", first_bytes),
                                      ("member-000-second.bin", second_bytes)):
                    (raw / name).write_bytes(content)
                if diagnostic_link:
                    (raw / "member-000-first.bin").unlink()
                    (raw / "member-000-first.bin").symlink_to(raw / "member-000-second.bin")
                report = {"schema": "ami-rust-cold-root-diagnostics-v1",
                          "status": "COLD_ROOT_NATIVE_MISMATCH", "variant": "dependencies",
                          "first_layout": "sdk-layout-a", "second_layout": "sdk-layout-b",
                          "first_canonical_artifacts": first_map,
                          "second_canonical_artifacts": second_map,
                          "first_native": {"bytes": 1, "sha256": "b" * 64},
                          "second_native": {"bytes": 1, "sha256": "b" * 64},
                          "differing_members": [{"member": member,
                              "first": {"present": True, "bytes": len(first_bytes), "sha256": first_sha,
                                        "retained": True, "path": "raw/member-000-first.bin"},
                              "second": {"present": True, "bytes": len(second_bytes), "sha256": second_sha,
                                         "retained": True, "path": "raw/member-000-second.bin"}}],
                          "raw_retention_limit_bytes": 24 * 1024 * 1024,
                          "raw_retained_bytes": len(first_bytes) + len(second_bytes),
                          "raw_omitted_bytes": 0,
                          "host_artifact_retention_limit_bytes": 32 * 1024 * 1024}
                (diag / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
            environment = {**os.environ, "RUNNER_TEMP": str(root), "REFERENCE_PROPOSAL": str(proposal if selected is None else selected).lower(),
                           "EXPECTED_HOST": "linux-x86_64", "PRODUCER_RESULT": "success" if producer_success else "failure", "PYTHON_RESULT": "success",
                           "WORKFLOW_SOURCE_COMMIT": "d" * 40, "WORKFLOW_RUN_ID": "1", "WORKFLOW_RUN_ATTEMPT": "1"}
            result = subprocess.run([sys.executable, "-I", "-B", "-c", CLEANUP], env=environment, capture_output=True, text=True)
            retained = all((output / p).is_file() for p in payloads)
            retained_diagnostics = None
            report_path = output / "cold-root-diagnostics/report.json"
            if report_path.is_file():
                report_value = json.loads(report_path.read_text())
                raw_files = {path.relative_to(output / "cold-root-diagnostics").as_posix(): path.read_bytes()
                             for path in (output / "cold-root-diagnostics/raw").glob("*")}
                retained_diagnostics = {"report": report_value, "raw": raw_files}
            return result, retained, retained_diagnostics

    def test_actual_cleanup_preserves_proposals_and_verified_normal_outputs(self):
        compile(CLEANUP, str(WORKFLOW), "exec")
        for proposal in (False, True):
            with self.subTest(proposal=proposal):
                result, retained, _ = self.run_cleanup(proposal)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(retained)
                self.assertIs(json.loads(result.stdout)["R1_accepted"], False)

    def test_proposal_cannot_be_accepted_under_normal_workflow_selection(self):
        result, _, _ = self.run_cleanup(True, selected=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unrecognized SDK producer receipt", result.stderr)

    def test_proposal_cold_roots_must_really_match(self):
        result, _, _ = self.run_cleanup(True, different_roots=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("matching cold roots", result.stderr)

    def test_failed_cleanup_retains_validated_cold_root_diagnostics(self):
        result, payloads_retained, evidence = self.run_cleanup(
            False, producer_success=False, diagnostics=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(payloads_retained)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["report"]["status"], "COLD_ROOT_NATIVE_MISMATCH")
        self.assertIn("artifact_raw_retained_bytes", evidence["report"])
        self.assertEqual(evidence["raw"]["raw/member-000-first.bin"], b"first rlib bytes")
        self.assertEqual(evidence["raw"]["raw/member-000-second.bin"], b"second rlib bytes")

    def test_failed_cleanup_rejects_linked_cold_root_diagnostic_bytes(self):
        result, _, _ = self.run_cleanup(False, producer_success=False,
                                        diagnostics=True, diagnostic_link=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular file", result.stderr)

    def test_assembly_is_explicitly_skipped_for_proposals(self):
        self.assertIn("  assemble:\n    if: ${{ !inputs.reference_proposal && !inputs.native_tooling }}", SOURCE)
        self.assertIn("needs: [assemble, native-assemble]", SOURCE)
        self.assertIn("needs: authenticate", SOURCE)


class NativeWorkflowTests(unittest.TestCase):
    @staticmethod
    def assert_native_contract(source):
        def job(name, following):
            return source.split("\n  " + name + ":\n", 1)[1].split("\n  " + following + ":\n", 1)[0]
        producer = job("native-producer", "release-candidate")
        assembler = job("native-assemble", "authenticate")
        signer = job("authenticate", "native-consumer")
        consumer = job("native-consumer", "consumer")
        for block in (producer, assembler):
            if "if: ${{ inputs.native_tooling && !inputs.reference_proposal }}" not in block:
                raise AssertionError("native production must exclude reference proposals")
        if "needs: admission" not in producer or "needs: native-producer" not in assembler:
            raise AssertionError("native producer dependencies bypass admission")
        if ("needs: [assemble, native-assemble]" not in signer
                or "needs['native-assemble'].result == 'success'" not in signer):
            raise AssertionError("native signing lacks its selected assembly dependency")
        for block in (producer, signer, consumer):
            if "profile: linux-x86_64" not in block or "profile: macos-aarch64" not in block:
                raise AssertionError("native delivery must preserve both supported hosts")
        for block, command in ((producer, "host"), (assembler, "assemble"), (signer, "audit"), (consumer, "verify")):
            if ('"$RUNNER_TEMP/ami-rust-python-bootstrap/runtime/python/bin/python3.12" -I -B release/ci_native.py ' + command) not in block:
                raise AssertionError("native producer command must use the pinned internal runtime")
            if "environment: release" not in block or "SOURCE_IS_PROTECTED: ${{ github.ref_protected }}" not in block:
                raise AssertionError("native delivery must retain its protected environment")
        if "--native-tooling" not in source or "Native tooling and reference proposal modes cannot be combined" not in source:
            raise AssertionError("native workflow lacks mode admission")
        if "name: sdk-authenticated-linux-x86_64-${{ github.run_id }}-${{ github.run_attempt }}" not in consumer:
            raise AssertionError("native consumers must share the exact authenticated candidate")
        if "gh release" in producer + assembler + signer + consumer:
            raise AssertionError("native qualification must not publish an SDK")

    def test_native_branch_preserves_protected_signing_and_both_hosts(self):
        self.assert_native_contract(SOURCE)

    def test_native_counterprobes_refuse_missing_dependency_or_host(self):
        broken = SOURCE.replace("needs: native-producer", "needs: admission", 1)
        with self.assertRaisesRegex(AssertionError, "dependencies"):
            self.assert_native_contract(broken)
        before, after = SOURCE.split("\n  native-consumer:\n", 1)
        broken = before + "\n  native-consumer:\n" + after.replace("profile: macos-aarch64", "profile: unsupported-host", 1)
        with self.assertRaisesRegex(AssertionError, "both supported hosts"):
            self.assert_native_contract(broken)


class WorkflowAdmissionTests(unittest.TestCase):
    @staticmethod
    def assert_admission_probe_contract(source):
        admission = source.split("\n  admission:\n", 1)[1].split("\n  producer:\n", 1)[0]
        producer = source.split("\n  producer:\n", 1)[1].split("\n  release-candidate:\n", 1)[0]
        required = (
            "    permissions:\n      contents: read\n      actions: read\n      id-token: write\n      attestations: write",
            "release/ci_artifact_admission.py --sdk-candidate",
            "release/ci_auth.py preflight",
            "release/ci_auth.py verify-preflight",
            "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
            "subject-name: ami-rust-github-provenance-probe.txt",
            "predicate-type: https://slsa.dev/provenance/v1",
            "outputs.bundle-path",
            "outputs.attestation-id",
            "outputs.attestation-url",
            "outputs.subject_sha256",
            "outputs.predicate_sha256",
            "needs: admission",
        )
        for item in required:
            if item == "needs: admission":
                if item not in producer:
                    raise AssertionError("producer jobs must depend on admission")
            elif item not in admission:
                raise AssertionError("admission provenance gate is missing " + item)
        probe_steps = admission.split("\n      - name: ")
        names = [step.split("\n", 1)[0] for step in probe_steps]
        for name in ("Prepare non-SDK provenance ingestion probe",
                     "Ingest non-SDK provenance probe before producer jobs",
                     "Require persisted admission provenance proof"):
            matching = [step for step in probe_steps if step.startswith(name + "\n")]
            if len(matching) != 1 or "if: ${{ !inputs.reference_proposal }}" not in matching[0]:
                raise AssertionError("probe step must be normal-run-only: " + name)
        if not (admission.index("release/ci_artifact_admission.py --sdk-candidate")
                < admission.index("release/ci_auth.py preflight")
                < admission.index("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6")
                < admission.index("release/ci_auth.py verify-preflight")):
            raise AssertionError("probe must follow retention admission and verify provider persistence")
        if "actions/upload-artifact" in admission:
            raise AssertionError("admission probe must not add an Actions artifact upload")

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

    def test_normal_runs_require_real_non_sdk_attestation_before_producers(self):
        self.assert_admission_probe_contract(SOURCE)

    def test_admission_counterprobes_reject_missing_or_bypassed_persistence_gate(self):
        missing_verify = SOURCE.replace("release/ci_auth.py verify-preflight", "removed verify invocation")
        with self.assertRaisesRegex(AssertionError, "verify-preflight"):
            self.assert_admission_probe_contract(missing_verify)
        bypass = SOURCE.replace("if: ${{ !inputs.reference_proposal }}\n        uses: actions/attest@",
                                "if: ${{ always() }}\n        uses: actions/attest@", 1)
        with self.assertRaisesRegex(AssertionError, "normal-run-only"):
            self.assert_admission_probe_contract(bypass)

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


class ConsumerInputSelectionTests(unittest.TestCase):
    @staticmethod
    def assert_shared_linux_candidate(source):
        authenticate = source.split("\n  authenticate:\n", 1)[1].split("\n  consumer:\n", 1)[0]
        consumer = source.split("\n  consumer:\n", 1)[1]
        release_candidate = source.split("\n  release-candidate:\n", 1)[1].split("\n  assemble:\n", 1)[0]
        linux_candidate = "sdk-authenticated-linux-x86_64-${{ github.run_id }}-${{ github.run_attempt }}"
        matrix_candidate = "sdk-authenticated-${{ matrix.profile }}-${{ github.run_id }}-${{ github.run_attempt }}"

        # Both authentication jobs stay available as producer evidence, while
        # both consumer hosts and the outer publisher use the same Linux-built
        # authenticated release candidate.
        if "profile: macos-aarch64" not in authenticate or "profile: linux-x86_64" not in authenticate:
            raise AssertionError("both authenticated producer profiles must remain")
        if authenticate.count("name: " + matrix_candidate) != 1:
            raise AssertionError("authenticated producer artifacts must remain host-specific")
        if "profile: macos-aarch64" not in consumer or "profile: linux-x86_64" not in consumer:
            raise AssertionError("both consumer hosts must remain in the matrix")
        if consumer.count("name: " + linux_candidate) != 1 or matrix_candidate in consumer:
            raise AssertionError("each consumer must download the shared Linux candidate")
        if consumer.count("name: sdk-consumer-${{ matrix.profile }}-${{ github.run_id }}-${{ github.run_attempt }}") != 1:
            raise AssertionError("consumer output artifact labels must remain host-specific")
        if release_candidate.count("name: " + linux_candidate) != 1:
            raise AssertionError("release candidate must use the same Linux authenticated artifact")

    def test_both_consumers_and_release_candidate_share_linux_authenticated_input(self):
        self.assert_shared_linux_candidate(SOURCE)

    def test_wrong_consumer_or_release_candidate_selection_is_rejected(self):
        consumer_prefix, after_consumer = SOURCE.split("\n  consumer:\n", 1)
        consumer = after_consumer
        linux_candidate = "sdk-authenticated-linux-x86_64-${{ github.run_id }}-${{ github.run_attempt }}"
        matrix_candidate = "sdk-authenticated-${{ matrix.profile }}-${{ github.run_id }}-${{ github.run_attempt }}"
        wrong_consumer = consumer_prefix + "\n  consumer:\n" + consumer.replace(linux_candidate, matrix_candidate, 1)
        with self.assertRaisesRegex(AssertionError, "shared Linux candidate"):
            self.assert_shared_linux_candidate(wrong_consumer)

        outer_prefix, after_release_candidate = SOURCE.split("\n  release-candidate:\n", 1)
        release_candidate, outer_suffix = after_release_candidate.split("\n  assemble:\n", 1)
        wrong_outer = outer_prefix + "\n  release-candidate:\n" + release_candidate.replace(
            linux_candidate, matrix_candidate, 1) + "\n  assemble:\n" + outer_suffix
        with self.assertRaisesRegex(AssertionError, "same Linux authenticated artifact"):
            self.assert_shared_linux_candidate(wrong_outer)

    def test_host_specific_producer_and_consumer_artifacts_are_preserved(self):
        broken = SOURCE.replace(
            "name: sdk-authenticated-${{ matrix.profile }}-${{ github.run_id }}-${{ github.run_attempt }}",
            "name: sdk-authenticated-linux-x86_64-${{ github.run_id }}-${{ github.run_attempt }}", 1)
        with self.assertRaisesRegex(AssertionError, "producer artifacts must remain host-specific"):
            self.assert_shared_linux_candidate(broken)
        broken = SOURCE.replace(
            "name: sdk-consumer-${{ matrix.profile }}-${{ github.run_id }}-${{ github.run_attempt }}",
            "name: sdk-consumer-linux-x86_64-${{ github.run_id }}-${{ github.run_attempt }}", 1)
        with self.assertRaisesRegex(AssertionError, "consumer output artifact labels must remain host-specific"):
            self.assert_shared_linux_candidate(broken)


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

    def assert_outer_gate(self, source):
        outer = source.split("\n  release-candidate:\n", 1)[1].split("\n  assemble:\n", 1)[0]
        self.assertIn('needs: [consumer, authenticate]', outer)
        match = re.search(r"^    if: \$\{\{ (.+) \}\}$", outer, re.MULTILINE)
        self.assertIsNotNone(match)
        expression = match.group(1).replace('&&', ' and ').replace('||', ' or ').replace('!', ' not ')
        for native, proposal, auth, consumer, cancelled, expected in (
            (True, False, 'success', 'skipped', False, True),
            (True, False, 'failure', 'skipped', False, False),
            (True, False, 'skipped', 'skipped', False, False),
            (True, True, 'success', 'skipped', False, False),
            (False, False, 'success', 'success', False, True),
            (False, False, 'success', 'failure', False, False),
            (True, False, 'success', 'skipped', True, False),
        ):
            inputs = SimpleNamespace(native_tooling=native, reference_proposal=proposal)
            needs = SimpleNamespace(authenticate=SimpleNamespace(result=auth), consumer=SimpleNamespace(result=consumer))
            actual = eval(expression, {'__builtins__': {}}, {'inputs':inputs, 'needs':needs,
                'always':lambda:True, 'cancelled':lambda:cancelled, 'true':True})
            self.assertEqual(actual, expected, (native, proposal, auth, consumer, cancelled))
        native_consumer = source.split("\n  native-consumer:\n", 1)[1].split("\n  consumer:\n", 1)[0]
        self.assertIn('needs: [authenticate, release-candidate]', native_consumer)
        self.assertIn('--outer "$RUNNER_TEMP/ami-rust-native-outer-candidate"', native_consumer)
        match = re.search(r"^    if: \$\{\{ (.+) \}\}$", native_consumer, re.MULTILINE)
        self.assertIsNotNone(match)
        # A selected branch can have skipped ancestors even when both direct
        # dependencies succeeded. Without a status function GitHub adds
        # success(), and the real run silently skips the entire host matrix.
        self.assertIn('always()', match.group(1))
        expression = (match.group(1).replace("needs['release-candidate']", 'needs.release_candidate')
                      .replace('&&', ' and ').replace('||', ' or ').replace('!', ' not '))
        for native, proposal, auth, outer, cancelled, expected in (
            (True, False, 'success', 'success', False, True),
            (True, False, 'failure', 'success', False, False),
            (True, False, 'success', 'failure', False, False),
            (True, False, 'success', 'skipped', False, False),
            (True, False, 'skipped', 'success', False, False),
            (True, True, 'success', 'success', False, False),
            (False, False, 'success', 'success', False, False),
            (True, False, 'success', 'success', True, False),
        ):
            inputs = SimpleNamespace(native_tooling=native, reference_proposal=proposal)
            needs = SimpleNamespace(authenticate=SimpleNamespace(result=auth),
                                    release_candidate=SimpleNamespace(result=outer))
            actual = eval(expression, {'__builtins__': {}}, {'inputs':inputs, 'needs':needs,
                'always':lambda:True, 'cancelled':lambda:cancelled, 'true':True})
            self.assertEqual(actual, expected, (native, proposal, auth, outer, cancelled))

    def test_outer_signer_depends_on_the_selected_successful_path(self):
        self.assert_outer_gate(SOURCE)
        self.assertNotIn('release upload', OUTER)
        self.assertNotIn('release edit', OUTER)

    def test_failed_authentication_cannot_reach_native_outer_signing(self):
        broken = SOURCE.replace("needs.authenticate.result == 'success') ||", "true) ||", 1)
        self.assertNotEqual(broken, SOURCE)
        with self.assertRaises(AssertionError):
            self.assert_outer_gate(broken)

    def test_native_consumers_reject_implicit_skip_and_failed_outer_counterprobes(self):
        before, after = SOURCE.split("\n  native-consumer:\n", 1)
        for replacement in (
            "${{ inputs.native_tooling }}",
            "${{ always() && !cancelled() && inputs.native_tooling && !inputs.reference_proposal && needs.authenticate.result == 'success' }}",
        ):
            broken_after, count = re.subn(r"^    if: .+$", '    if: ' + replacement,
                                         after, count=1, flags=re.MULTILINE)
            self.assertEqual(count, 1)
            with self.assertRaises(AssertionError):
                self.assert_outer_gate(before + "\n  native-consumer:\n" + broken_after)


if __name__ == "__main__":
    unittest.main()

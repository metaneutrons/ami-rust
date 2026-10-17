#!/usr/bin/env python3
"""Synthetic fixtures for public-candidate authentication; no real crypto claims."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("public_candidate.py")
SPEC = importlib.util.spec_from_file_location("r1_public_candidate_fixture_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
public_candidate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = public_candidate
SPEC.loader.exec_module(public_candidate)

verifier = public_candidate.verifier
stage_candidate = public_candidate.stage_candidate
transport = public_candidate.transport
HOST = public_candidate.HOST
SOURCE_SHA = "2" * 40
WORKFLOW_SHA = SOURCE_SHA
INPUT_MATERIALS = [{"uri": "https://example.invalid/tool.tar.xz",
                    "digest": {"sha256": "e" * 64}}]
RUN_ID = 123456789
RUN_ATTEMPT = 3


class PublicCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-candidate-test-")
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        self.trusted_inputs = self.root / "trusted-inputs"
        (self.trusted_inputs / ".auth").mkdir(parents=True)
        self.inputs_raw = public_candidate._canonical_json({
            "schema": verifier.INPUTS_SCHEMA,
            "materials": INPUT_MATERIALS,
        })
        (self.trusted_inputs / ".auth/inputs.json").write_bytes(self.inputs_raw)
        self.policy = self._make_policy()
        self.tag = "v1.2.3-rc.4+public"
        self.version = "1.2.3"
        self.producer = self._producer()
        self.good_predicate = self._predicate(self.producer)
        self.candidate, self.inner, self.names = self._build_candidate()
        self.transport_sha256 = hashlib.sha256((self.candidate / self.names["transport"]).read_bytes()).hexdigest()
        self.manifest_sha256 = hashlib.sha256((self.inner / "release.json").read_bytes()).hexdigest()
        self.gh_bundles = self._make_gh_bundles(self.candidate, self.names, self.good_predicate)

    def tearDown(self):
        self.temp.cleanup()

    def _make_policy(self):
        policy_dir = self.root / "policy-files"
        policy_dir.mkdir()
        gh = policy_dir / "gh"
        cosign = policy_dir / "cosign"
        gh.write_bytes(b"synthetic gh verifier fixture\n")
        cosign.write_bytes(b"synthetic cosign verifier fixture\n")
        gh.chmod(0o755)
        cosign.chmod(0o755)
        gh_roots = policy_dir / "gh-roots.jsonl"
        gh_roots.write_text('{"fixture_only":true}\n', encoding="utf-8")
        cosign_root = policy_dir / "cosign-root.json"
        cosign_root.write_text('{"fixture_only":true}\n', encoding="utf-8")
        return {
            "schema": verifier.POLICY_SCHEMA,
            "repository": verifier.REPOSITORY,
            "workflow": verifier.WORKFLOW,
            "workflow_sha": WORKFLOW_SHA,
            "source_sha": SOURCE_SHA,
            "source_ref": verifier.SOURCE_REF,
            "oidc_issuer": verifier.OIDC_ISSUER,
            "cert_identity": f"https://github.com/{verifier.REPOSITORY}/{verifier.WORKFLOW}@{verifier.SOURCE_REF}",
            "inputs_manifest_sha256": hashlib.sha256(self.inputs_raw).hexdigest(),
            "allowed_host_profiles": [HOST],
            "gh": {"path": str(gh), "sha256": hashlib.sha256(gh.read_bytes()).hexdigest()},
            "cosign": {"path": str(cosign), "sha256": hashlib.sha256(cosign.read_bytes()).hexdigest()},
            "gh_trusted_roots": {"path": str(gh_roots), "sha256": hashlib.sha256(gh_roots.read_bytes()).hexdigest()},
            "cosign_trusted_root": {"path": str(cosign_root), "sha256": hashlib.sha256(cosign_root.read_bytes()).hexdigest()},
        }

    @staticmethod
    def _producer(**changes):
        result = {
            "kind": "protected-github-actions",
            "repository": verifier.REPOSITORY,
            "workflow": verifier.WORKFLOW,
            "source_sha": SOURCE_SHA,
            "workflow_sha": WORKFLOW_SHA,
            "run_id": RUN_ID,
            "run_attempt": RUN_ATTEMPT,
            "acceptance": "R1 acceptance and publication are separate gates",
        }
        result.update(changes)
        return result

    def _predicate(self, producer, *, source_sha=None, workflow_sha=None,
                   run_id=None, run_attempt=None, host=HOST, material_rows=None):
        source = source_sha or producer["source_sha"]
        workflow = workflow_sha or producer["workflow_sha"]
        selected_run = producer["run_id"] if run_id is None else run_id
        selected_attempt = producer["run_attempt"] if run_attempt is None else run_attempt
        materials = copy.deepcopy(INPUT_MATERIALS if material_rows is None else material_rows)
        return {
            "buildDefinition": {
                "buildType": verifier.BUILD_TYPE,
                "externalParameters": {"workflow": {
                    "repository": f"https://github.com/{verifier.REPOSITORY}",
                    "path": verifier.WORKFLOW,
                    "ref": verifier.SOURCE_REF,
                }},
                "resolvedDependencies": [
                    {"uri": f"git+https://github.com/{verifier.REPOSITORY}@{verifier.SOURCE_REF}",
                     "digest": {"gitCommit": source}},
                    *materials,
                ],
                "internalParameters": {"publisherPolicy": {
                    "environment": "release",
                    "runnerEnvironment": "github-hosted",
                    "repository": verifier.REPOSITORY,
                    "workflow": verifier.WORKFLOW,
                    "workflowSha": workflow,
                    "sourceSha": source,
                    "sourceRef": verifier.SOURCE_REF,
                    "inputsManifestSha256": self.policy["inputs_manifest_sha256"],
                    "hostProfile": host,
                }},
            },
            "runDetails": {
                "builder": {"id": f"https://github.com/{verifier.REPOSITORY}/{verifier.WORKFLOW}@{verifier.SOURCE_REF}"},
                "metadata": {
                    "invocationId": f"https://github.com/{verifier.REPOSITORY}/actions/runs/{selected_run}/attempts/{selected_attempt}",
                },
            },
        }

    def _build_candidate(self, *, candidate_name="candidate", producer=None, version=None):
        inner = self.root / (candidate_name + "-inner")
        inner.mkdir()
        (inner / ".auth").mkdir()
        (inner / ".auth/inputs.json").write_bytes(self.inputs_raw)
        (inner / ".auth/authentication.json").write_bytes(b'{"fixture_only":true}\n')
        sbom = b'{"spdxVersion":"SPDX-2.3","packages":[]}\n'
        sdk = b"synthetic SDK archive\x00\xff"
        (inner / "sbom.spdx.json").write_bytes(sbom)
        (inner / "sdk.tar.xz").write_bytes(sdk)
        manifest = {
            "schema": "ami-rust-release-v1",
            "version": version or self.version,
            "qualification_only": False,
            "assets": [
                {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in sorted({"sbom.spdx.json": sbom, "sdk.tar.xz": sdk}.items())
            ],
            "producer": copy.deepcopy(producer or self._producer()),
        }
        manifest_raw = public_candidate._canonical_json(manifest)
        (inner / "release.json").write_bytes(manifest_raw)
        candidate = self.root / candidate_name
        stage_candidate.prepare(self.tag, inner, candidate)
        names = stage_candidate.asset_names(self.tag)
        for key in ("payload_signature", "transport_signature"):
            subject_key = "payload" if key == "payload_signature" else "transport"
            subject_raw = (candidate / names[subject_key]).read_bytes()
            signature = {"fixture_only": True,
                         "subject_sha256": hashlib.sha256(subject_raw).hexdigest()}
            (candidate / names[key]).write_bytes(public_candidate._canonical_json(signature))
        stage_candidate.finalize(candidate, self.tag)
        return candidate, inner, names

    def _make_gh_bundles(self, candidate, names, predicate, *, run_id=None,
                         run_attempt=None, directory="gh-inputs", claim_changes=None):
        proof_root = self.root / directory
        proof_root.mkdir(exist_ok=True)
        files = stage_candidate._scan_candidate_files(candidate, set(names.values()), names)
        rows = stage_candidate._asset_inventory(files)
        digests = {row["path"]: row["sha256"] for row in rows}
        result = {}
        for key in ("payload", "sbom", "transport", "checksums"):
            subject = names[key]
            claim = copy.deepcopy(predicate)
            if claim_changes and subject in claim_changes:
                claim_changes[subject](claim)
            subject_rows = [{"name": subject, "digest": {"sha256": digests[subject]}}]
            if claim_changes and subject in claim_changes and "combined" in claim_changes[subject].__name__:
                subject_rows.append({"name": names["sbom"], "digest": {"sha256": digests[names["sbom"]]}})
            statement = {
                "predicateType": verifier.PREDICATE_TYPE,
                "subject": subject_rows,
                "predicate": claim,
            }
            raw = public_candidate._canonical_json({"statement": statement})
            proof = proof_root / (key + "-" + str(run_id or RUN_ID) + "-" + str(run_attempt or RUN_ATTEMPT) + ".json")
            proof.write_bytes(raw)
            result[subject] = [proof]
        return result

    @staticmethod
    def _mock_inner_verification(inner, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                                 source_sha=SOURCE_SHA, workflow_sha=WORKFLOW_SHA):
        raw = (inner / "release.json").read_bytes()
        return {
            "verified": True,
            "sourceSha": source_sha,
            "workflowSha": workflow_sha,
            "sourceRef": verifier.SOURCE_REF,
            "manifestSha256": hashlib.sha256(raw).hexdigest(),
            "workflowRuns": [{"runId": run_id, "runAttempt": run_attempt, "hostProfile": HOST}],
        }

    def _runner(self, candidate, destination, *, events=None, cosign_reject=None):
        def runner(argv, *, deadline, env):
            if destination.exists():
                raise AssertionError("candidate was unpacked before outer cryptographic verification finished")
            if events is not None:
                events.append(argv[1:3])
            if argv[1:3] == ["attestation", "verify"]:
                subject_path = Path(argv[3])
                proof_raw = Path(argv[argv.index("--bundle") + 1]).read_bytes()
                fixture = json.loads(proof_raw.decode("utf-8"))
                statement = fixture["statement"]
                subject_digest = hashlib.sha256(subject_path.read_bytes()).hexdigest()
                if not any(row.get("name") == subject_path.name
                           and row.get("digest", {}).get("sha256") == subject_digest
                           for row in statement.get("subject", [])):
                    raise verifier.PublisherVerificationError(
                        "pinned verifier rejected evidence (1): synthetic subject digest mismatch"
                    )
                result = [{"attestation": {"fixture_only": True},
                           "verificationResult": {
                               "statement": statement,
                               "signature": {"certificate": {"fixture_only": True}},
                           }}]
                return public_candidate._canonical_json(result)
            if argv[1] == "verify-blob":
                subject_path = Path(argv[2])
                bundle = Path(argv[argv.index("--bundle") + 1])
                signature = json.loads(bundle.read_text(encoding="utf-8"))
                actual = hashlib.sha256(subject_path.read_bytes()).hexdigest()
                if (cosign_reject == subject_path.name
                        or signature.get("subject_sha256") != actual):
                    raise verifier.PublisherVerificationError(
                        "pinned verifier rejected evidence (1): synthetic signature mismatch"
                    )
                return b""
            raise AssertionError("unexpected verifier command: " + repr(argv))
        return runner

    def _verify(self, *, candidate=None, inner=None, proofs=None, tag=None,
                manifest_sha256=None, source_commit=SOURCE_SHA, destination_name="unpacked",
                runner=None, verifier_result=None):
        candidate = candidate or self.candidate
        inner = inner or self.inner
        destination = self.root / destination_name
        verify_runner = runner or self._runner(candidate, destination)
        inner_result = verifier_result or self._mock_inner_verification(inner)
        with patch.object(verifier, "verify", return_value=inner_result):
            return public_candidate.verify_and_unpack(
                candidate=candidate,
                tag=tag or self.tag,
                source_commit=source_commit,
                transport_sha256=hashlib.sha256(
                    (candidate / stage_candidate.asset_names(tag or self.tag)["transport"]).read_bytes()
                ).hexdigest(),
                manifest_sha256=manifest_sha256 or hashlib.sha256((inner / "release.json").read_bytes()).hexdigest(),
                policy=self.policy,
                trusted_inputs_root=self.trusted_inputs,
                gh_bundles=proofs or self.gh_bundles,
                destination=destination,
                work=self.work,
                runner=verify_runner,
            )

    def _policy_with_resource_under(self, root, label, field):
        policy = copy.deepcopy(self.policy)
        resource_dir = root / ("policy-resource-" + label + "-" + field)
        resource_dir.mkdir()
        if field in {"gh", "cosign"}:
            raw = ("synthetic " + field + " verifier fixture\n").encode("ascii")
            mode = 0o755
            filename = field
        else:
            raw = b'{"fixture_only":true}\n'
            mode = 0o644
            filename = "roots.json"
        resource = resource_dir / filename
        resource.write_bytes(raw)
        resource.chmod(mode)
        policy[field] = {"path": str(resource), "sha256": hashlib.sha256(raw).hexdigest()}
        return policy

    def _saved_receipt(self):
        paths = sorted(self.work.glob("public-candidate-*/receipt.json"))
        self.assertTrue(paths, "verification should preserve a receipt")
        latest = max(paths, key=lambda path: path.stat().st_mtime_ns)
        return json.loads(latest.read_text(encoding="utf-8"))

    def test_public_roundtrip_selects_matching_history_and_verifies_before_unpack(self):
        payload = self.names["payload"]
        old_predicate = self._predicate(
            self.producer, source_sha="4" * 40, workflow_sha="4" * 40,
            run_id=RUN_ID - 1, run_attempt=1,
        )
        historical = self.root / "historical-payload.json"
        payload_digest = hashlib.sha256((self.candidate / payload).read_bytes()).hexdigest()
        statement = {"predicateType": verifier.PREDICATE_TYPE,
                     "subject": [{"name": payload, "digest": {"sha256": payload_digest}}],
                     "predicate": old_predicate}
        historical.write_bytes(public_candidate._canonical_json({"statement": statement}))
        proofs = {subject: list(items) for subject, items in self.gh_bundles.items()}
        proofs[payload] = [historical, proofs[payload][0], proofs[payload][0]]
        events = []
        destination = self.root / "unpacked"
        runner = self._runner(self.candidate, destination, events=events)
        real_unpack = transport.unpack_bundle
        ordering = []

        def checked_unpack(*args, **kwargs):
            self.assertEqual(len(events), 7)
            self.assertFalse(destination.exists())
            ordering.append("unpack")
            return real_unpack(*args, **kwargs)

        inner_result = self._mock_inner_verification(self.inner)
        with patch.object(verifier, "verify", return_value=inner_result), \
             patch.object(transport, "unpack_bundle", side_effect=checked_unpack):
            receipt = public_candidate.verify_and_unpack(
                self.candidate, self.tag, SOURCE_SHA, self.transport_sha256,
                self.manifest_sha256, self.policy, self.trusted_inputs, proofs,
                destination, self.work, runner=runner,
            )
        self.assertEqual(ordering, ["unpack"])
        self.assertEqual(receipt["status"], public_candidate.RECEIPT_STATUS)
        self.assertTrue(receipt["authenticated"])
        self.assertTrue(receipt["unpacked"])
        self.assertFalse(receipt["installed"])
        self.assertFalse(receipt["r1_accepted"])
        self.assertEqual((receipt["run_id"], receipt["run_attempt"]), (RUN_ID, RUN_ATTEMPT))
        self.assertEqual(len(receipt["commands"]), 7)
        self.assertEqual(receipt["ignored_gh_proofs"][0]["proof_sha256"], hashlib.sha256(historical.read_bytes()).hexdigest())
        self.assertEqual(len(receipt["selected_gh_proofs"][payload]), 1)
        self.assertTrue(destination.is_dir())
        self.assertTrue(Path(receipt["receipt_path"]).is_file())
        self.assertTrue((Path(receipt["evidence_directory"]) / "gh").is_dir())

    def test_hash_pinned_policy_resources_under_forbidden_roots_fail_before_verification(self):
        fields = ("gh", "cosign", "gh_trusted_roots", "cosign_trusted_root")
        for root_label in ("downloaded candidate", "trusted inputs", "verification work",
                           "unpacked destination"):
            for field in fields:
                with self.subTest(root=root_label, resource=field):
                    destination = self.root / (
                        "contained-" + root_label.replace(" ", "-") + "-" + field
                    )
                    if root_label == "downloaded candidate":
                        forbidden_root = self.candidate
                    elif root_label == "trusted inputs":
                        forbidden_root = self.trusted_inputs
                    elif root_label == "verification work":
                        forbidden_root = self.work
                    else:
                        destination.mkdir(mode=0o700)
                        forbidden_root = destination
                    policy = self._policy_with_resource_under(forbidden_root, root_label, field)
                    verifier_calls = []

                    def must_not_run(argv, *, deadline, env):
                        verifier_calls.append(argv)
                        raise AssertionError("external verifier ran before policy-resource containment")

                    def invoke():
                        return public_candidate.verify_and_unpack(
                            candidate=self.candidate,
                            tag=self.tag,
                            source_commit=SOURCE_SHA,
                            transport_sha256=self.transport_sha256,
                            manifest_sha256=self.manifest_sha256,
                            policy=policy,
                            trusted_inputs_root=self.trusted_inputs,
                            gh_bundles=self.gh_bundles,
                            destination=destination,
                            work=self.work,
                            runner=must_not_run,
                        )

                    if root_label == "unpacked destination":
                        # A destination containing policy material is normally rejected by
                        # the freshness preflight. Bypass only that preflight here so this
                        # regression exercises the independent containment guard itself.
                        with patch.object(
                            transport, "_fresh_directory_path",
                            return_value=(destination, destination.parent),
                        ):
                            with self.assertRaisesRegex(
                                public_candidate.PublicCandidateVerificationError,
                                field + " must be outside " + root_label,
                            ):
                                invoke()
                    else:
                        with self.assertRaisesRegex(
                            public_candidate.PublicCandidateVerificationError,
                            field + " must be outside " + root_label,
                        ):
                            invoke()
                    self.assertEqual(verifier_calls, [])

    def test_actual_verifier_rejection_can_be_skipped_but_infrastructure_errors_abort(self):
        payload = self.names["payload"]
        valid = self.gh_bundles[payload][0]
        rejected = self.root / "rejected-signature.json"
        rejected.write_bytes(public_candidate._canonical_json({
            "fixture_reject": True,
            "statement": json.loads(valid.read_text(encoding="utf-8"))["statement"],
        }))
        proofs = {subject: list(items) for subject, items in self.gh_bundles.items()}
        proofs[payload] = [rejected, valid]
        destination = self.root / "rejected-proof-then-valid"
        base_runner = self._runner(self.candidate, destination)

        def rejecting_runner(argv, *, deadline, env):
            if argv[1:3] == ["attestation", "verify"]:
                bundle = Path(argv[argv.index("--bundle") + 1])
                if json.loads(bundle.read_text(encoding="utf-8")).get("fixture_reject"):
                    raise verifier.PublisherVerificationError(
                        "pinned verifier rejected evidence (2): synthetic invalid signature"
                    )
            return base_runner(argv, deadline=deadline, env=env)

        receipt = self._verify(proofs=proofs, destination_name="rejected-proof-then-valid",
                               runner=rejecting_runner)
        self.assertTrue(any("exit 2" in row["reason"] for row in receipt["ignored_gh_proofs"]))
        self.assertEqual(len(receipt["commands"]), 7)

        for index, failure in enumerate((
            OSError("synthetic verifier launch failure"),
            verifier.PublisherVerificationError("pinned verifier output exceeded its limit"),
        )):
            with self.subTest(infrastructure=type(failure).__name__):
                target = self.root / ("infrastructure-failure-" + str(index))

                def failing_runner(argv, *, deadline, env, error=failure):
                    raise error

                with self.assertRaises(type(failure)):
                    self._verify(destination_name=target.name, runner=failing_runner)
                self.assertFalse(target.exists())

    def test_wrong_source_material_host_and_combined_subject_proofs_are_ignored(self):
        payload = self.names["payload"]
        cases = {
            "source": lambda predicate: predicate["buildDefinition"]["internalParameters"]["publisherPolicy"].update(
                {"sourceSha": "4" * 40}),
            "material": lambda predicate: predicate["buildDefinition"]["resolvedDependencies"].append(
                {"uri": "https://example.invalid/other.tar.xz", "digest": {"sha256": "f" * 64}}),
            "host": lambda predicate: predicate["buildDefinition"]["internalParameters"]["publisherPolicy"].update(
                {"hostProfile": "macos-aarch64"}),
            "combined": lambda predicate: predicate["runDetails"].update({"untrustedExtra": True}),
        }
        for index, (label, change) in enumerate(cases.items()):
            with self.subTest(claim=label):
                old = self.gh_bundles[payload][0]
                proof_dir = self.root / ("wrong-" + label)
                proof_dir.mkdir()
                source_fixture = json.loads(old.read_text(encoding="utf-8"))
                changed_statement = source_fixture["statement"]
                changed_predicate = copy.deepcopy(changed_statement["predicate"])
                change(changed_predicate)
                changed_statement["predicate"] = changed_predicate
                if label == "combined":
                    changed_statement["subject"].append({
                        "name": self.names["sbom"],
                        "digest": {"sha256": hashlib.sha256((self.candidate / self.names["sbom"]).read_bytes()).hexdigest()},
                    })
                bad = proof_dir / "payload.json"
                bad.write_bytes(public_candidate._canonical_json({"statement": changed_statement}))
                proofs = {subject: list(items) for subject, items in self.gh_bundles.items()}
                proofs[payload] = [bad]
                destination_name = "unpacked-" + str(index)
                with self.assertRaises(public_candidate.PublicCandidateVerificationError):
                    self._verify(proofs=proofs, destination_name=destination_name)
                self.assertFalse((self.root / destination_name).exists())
                report = self._saved_receipt()
                self.assertEqual(report["status"], public_candidate.FAILED_STATUS)
                self.assertTrue(report["ignored_gh_proofs"])

    def test_wrong_publisher_run_is_rejected_by_inner_producer_after_unpack(self):
        wrong_run = RUN_ID + 100
        wrong_predicate = self._predicate(self.producer, run_id=wrong_run, run_attempt=2)
        proofs = self._make_gh_bundles(
            self.candidate, self.names, wrong_predicate, run_id=wrong_run, run_attempt=2,
            directory="wrong-run-gh",
        )
        with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "source or run"):
            self._verify(proofs=proofs, destination_name="wrong-run-unpacked")
        self.assertTrue((self.root / "wrong-run-unpacked").is_dir())
        self.assertEqual(self._saved_receipt()["status"], public_candidate.FAILED_STATUS)

    def test_duplicate_proofs_are_deduplicated_and_multiple_matching_runs_are_ambiguous(self):
        payload = self.names["payload"]
        duplicate = {subject: list(items) for subject, items in self.gh_bundles.items()}
        duplicate[payload] = [duplicate[payload][0], duplicate[payload][0]]
        receipt = self._verify(proofs=duplicate, destination_name="deduplicated")
        self.assertEqual(len(receipt["commands"]), 6)
        self.assertEqual(len(receipt["selected_gh_proofs"][payload]), 1)

        alternate = self._make_gh_bundles(
            self.candidate, self.names,
            self._predicate(self.producer, run_id=RUN_ID + 1, run_attempt=1),
            run_id=RUN_ID + 1, run_attempt=1, directory="alternate-run-gh",
        )[payload][0]
        ambiguous = {subject: list(items) for subject, items in self.gh_bundles.items()}
        ambiguous[payload] = [ambiguous[payload][0], alternate]
        with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "multiple matching publisher runs"):
            self._verify(proofs=ambiguous, destination_name="ambiguous")
        self.assertFalse((self.root / "ambiguous").exists())

    def test_missing_proof_and_contradictory_same_run_claim_fail_closed(self):
        payload = self.names["payload"]
        missing = {subject: list(items) for subject, items in self.gh_bundles.items()}
        missing[payload] = []
        with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "at least one"):
            self._verify(proofs=missing, destination_name="missing-proof")
        self.assertFalse((self.root / "missing-proof").exists())

        changed = copy.deepcopy(self.good_predicate)
        changed["runDetails"]["auditMarker"] = "second signed claim"
        conflict = self._make_gh_bundles(
            self.candidate, self.names, changed, directory="same-run-conflict-gh"
        )[payload][0]
        contradictory = {subject: list(items) for subject, items in self.gh_bundles.items()}
        contradictory[payload].append(conflict)
        with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "contradictory"):
            self._verify(proofs=contradictory, destination_name="contradictory")
        self.assertFalse((self.root / "contradictory").exists())

    def test_transport_checksum_asset_and_signature_mutations_are_rejected(self):
        with self.subTest("payload asset mutation"):
            payload_path = self.candidate / self.names["payload"]
            original = payload_path.read_bytes()
            payload_path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            self._refinalize_checksums()
            with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "transport archive pin"):
                self._verify(destination_name="mutated-asset")
            payload_path.write_bytes(original)
            self._refinalize_checksums()

        with self.subTest("checksum mutation"):
            checksums = self.candidate / self.names["checksums"]
            original = checksums.read_bytes()
            checksums.write_bytes(original[:-1] + (b"0\n" if original[-1:] == b"\n" else b"0"))
            with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "SHA256SUMS"):
                self._verify(destination_name="mutated-checksum")
            checksums.write_bytes(original)

        with self.subTest("signature mutation"):
            signature_path = self.candidate / self.names["payload_signature"]
            original_signature = signature_path.read_bytes()
            signature_path.write_bytes(public_candidate._canonical_json({
                "fixture_only": True, "subject_sha256": "0" * 64,
            }))
            self._refinalize_checksums()
            changed_proofs = self._make_gh_bundles(
                self.candidate, self.names, self.good_predicate, directory="changed-signature-gh"
            )
            runner = self._runner(self.candidate, self.root / "mutated-signature", cosign_reject=self.names["payload"])
            with self.assertRaisesRegex(verifier.PublisherVerificationError, "rejected evidence"):
                self._verify(proofs=changed_proofs, destination_name="mutated-signature", runner=runner)
            signature_path.write_bytes(original_signature)
            self._refinalize_checksums()

        with self.subTest("candidate changes during cryptographic checks"):
            transport_path = self.candidate / self.names["transport"]
            original_transport = transport_path.read_bytes()
            destination = self.root / "changed-during-checks"
            base_runner = self._runner(self.candidate, destination)

            def mutating_runner(argv, *, deadline, env):
                result = base_runner(argv, deadline=deadline, env=env)
                if argv[1] == "verify-blob" and Path(argv[2]).name == self.names["transport"]:
                    transport_path.write_bytes(original_transport + b" ")
                return result

            with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "SHA256SUMS"):
                self._verify(destination_name=destination.name, runner=mutating_runner)
            self.assertFalse(destination.exists())
            transport_path.write_bytes(original_transport)

    def _refinalize_checksums(self):
        names = self.names
        files = {
            names[key]: (self.candidate / names[key]).read_bytes()
            for key in ("payload", "sbom", "transport", "payload_signature", "transport_signature")
        }
        (self.candidate / names["checksums"]).write_bytes(stage_candidate._checksum_bytes(files, names))

    def test_malformed_symlink_and_extra_candidate_entries_are_rejected(self):
        candidate = self.root / "extra-candidate"
        files = {name: (self.candidate / name).read_bytes() for name in self.names.values()}
        candidate.mkdir()
        for name, raw in files.items():
            (candidate / name).write_bytes(raw)
        (candidate / "unexpected.txt").write_bytes(b"extra")
        with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "wrong file set"):
            self._verify(candidate=candidate, destination_name="extra-destination")

        symlink_candidate = self.root / "symlink-candidate"
        symlink_candidate.mkdir()
        for name, raw in files.items():
            (symlink_candidate / name).write_bytes(raw)
        (symlink_candidate / self.names["payload_signature"]).unlink()
        (symlink_candidate / self.names["payload_signature"]).symlink_to(self.root / "outside-signature")
        (self.root / "outside-signature").write_text('{"fixture_only":true}\n', encoding="utf-8")
        with self.assertRaises(public_candidate.PublicCandidateVerificationError):
            self._verify(candidate=symlink_candidate, destination_name="symlink-destination")

        malformed_candidate = self.root / "malformed-candidate"
        malformed_candidate.mkdir()
        for name, raw in files.items():
            (malformed_candidate / name).write_bytes(raw)
        transport_path = malformed_candidate / self.names["transport"]
        transport_path.write_bytes(b"not json\n")
        altered = stage_candidate._scan_candidate_files(malformed_candidate, set(self.names.values()), self.names)
        (malformed_candidate / self.names["checksums"]).write_bytes(
            stage_candidate._checksum_bytes(altered, self.names)
        )
        with self.assertRaises(public_candidate.PublicCandidateVerificationError):
            self._verify(candidate=malformed_candidate, destination_name="malformed-destination")

    def test_inner_manifest_pin_wrong_producer_and_outer_predicate_fail_after_unpack(self):
        with self.subTest("external manifest pin"):
            with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "external manifest SHA"):
                self._verify(manifest_sha256="f" * 64, destination_name="wrong-manifest-pin")
            self.assertTrue((self.root / "wrong-manifest-pin").is_dir())

        with self.subTest("producer run"):
            wrong_producer = self._producer(run_id=RUN_ID + 9)
            candidate, inner, names = self._build_candidate(
                candidate_name="wrong-producer", producer=wrong_producer
            )
            predicates = self._make_gh_bundles(
                candidate, names, self.good_predicate, directory="wrong-producer-gh"
            )
            with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "source or run"):
                self._verify(candidate=candidate, inner=inner, proofs=predicates,
                             destination_name="wrong-producer-unpacked")
            self.assertTrue((self.root / "wrong-producer-unpacked").is_dir())

        with self.subTest("extra publisher predicate claim"):
            predicate = copy.deepcopy(self.good_predicate)
            predicate["runDetails"]["auditMarker"] = "outside publisher predicate"
            altered_proofs = self._make_gh_bundles(
                self.candidate, self.names, predicate, directory="outer-predicate-extra-gh"
            )
            with self.assertRaisesRegex(public_candidate.PublicCandidateVerificationError, "differs from the authenticated inner publisher predicate"):
                self._verify(proofs=altered_proofs, destination_name="wrong-outer-predicate")
            self.assertTrue((self.root / "wrong-outer-predicate").is_dir())


if __name__ == "__main__":
    unittest.main()

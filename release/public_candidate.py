#!/usr/bin/env python3
"""Authenticate and safely unpack a downloaded public release candidate.

This reader is deliberately separate from the protected CI candidate verifier.
Publisher identity and materials come from explicit external pins; candidate
bytes cannot supply trust roots, verifier tools, or the expected source.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from types import ModuleType
from typing import Any, Callable


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
HOST = "linux-x86_64"
RECEIPT_SCHEMA = "ami-rust-public-candidate-authentication-v1"
RECEIPT_STATUS = "PUBLIC_CANDIDATE_AUTHENTICATED_AND_UNPACKED_NOT_INSTALLED_NOT_R1_ACCEPTED"
FAILED_STATUS = "PUBLIC_CANDIDATE_AUTHENTICATION_FAILED"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_RUN_INVOCATION = re.compile(
    r"https://github\.com/metaneutrons/ami-rust/actions/runs/([1-9][0-9]*)/attempts/([1-9][0-9]*)\Z"
)


def _load_sibling(filename: str, module_name: str) -> ModuleType:
    path = SCRIPT.with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load trusted release helper " + filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


candidate_auth = _load_sibling("candidate_auth.py", "_ami_rust_public_candidate_auth")
stage_candidate = candidate_auth.stage_candidate
verifier = candidate_auth.verifier
transport = stage_candidate._TRANSPORT
ci_auth = candidate_auth.ci_auth


class PublicCandidateVerificationError(ValueError):
    """A public candidate or its publisher evidence failed authentication."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _assert_external_policy_resources(policy: dict[str, Any], paths: dict[str, Path]) -> None:
    for field in ("gh", "cosign", "gh_trusted_roots", "cosign_trusted_root"):
        resource = Path(policy[field]["path"]).resolve(strict=True)
        for label, root in paths.items():
            if resource == root or root in resource.parents:
                raise PublicCandidateVerificationError(
                    field + " must be outside " + label
                )


def _assert_separated_roots(candidate: Path, trusted_inputs_root: Path, work: Path,
                            destination: Path) -> None:
    candidate_auth._require_disjoint({
        "downloaded candidate": candidate,
        "trusted inputs": trusted_inputs_root,
        "verification work": work,
        "unpacked destination": destination,
    })
    if work.resolve().is_relative_to(ROOT.resolve()):
        raise PublicCandidateVerificationError("verification work must be outside the public reader checkout")


def _candidate_files(candidate: Path, tag: str, transport_sha256: str
                     ) -> tuple[dict[str, str], dict[str, bytes], dict[str, tuple[int, str]], dict[str, Any]]:
    names = stage_candidate.asset_names(tag)
    expected = set(names.values())
    try:
        files = stage_candidate._scan_candidate_files(candidate, expected, names)
        if files[names["checksums"]] != stage_candidate._checksum_bytes(files, names):
            raise ValueError("SHA256SUMS does not match the exact five candidate assets")
        transport_raw = files[names["transport"]]
        if _sha256(transport_raw) != transport_sha256:
            raise ValueError("transport metadata does not match the externally pinned SHA-256")
        record = stage_candidate._load_transport(files, names)
        archive_name, archive_bytes, archive_digest, _inventory = transport._validate_record(record)
        payload = files[names["payload"]]
        if (archive_name != names["payload"] or archive_bytes != len(payload)
                or archive_digest != _sha256(payload)):
            raise ValueError("transport archive pin does not match the payload asset")
        for key in ("payload_signature", "transport_signature"):
            stage_candidate._json_object(files[names[key]], names[key])
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise PublicCandidateVerificationError(str(error)) from error
    rows = {name: (len(raw), _sha256(raw)) for name, raw in files.items()}
    return names, files, rows, record


def _proof_inputs(gh_bundles: dict[str, list[Path]], expected_subjects: set[str],
                  candidate: Path, evidence_root: Path, candidate_bytes: int
                  ) -> tuple[dict[str, list[dict[str, Any]]], int]:
    if type(gh_bundles) is not dict or set(gh_bundles) != expected_subjects:
        raise PublicCandidateVerificationError("GH proof inputs must cover exactly the four attested subjects")
    count = 0
    total_bytes = 0
    snapshots: dict[str, list[dict[str, Any]]] = {}
    seen_contents: dict[str, Path] = {}
    gh_dir = evidence_root / "gh"
    gh_dir.mkdir(mode=0o700)
    for subject in sorted(expected_subjects):
        paths = gh_bundles[subject]
        if type(paths) is not list or not paths:
            raise PublicCandidateVerificationError("each GH subject must have at least one proof bundle")
        snapshots[subject] = []
        subject_seen: set[str] = set()
        for raw_path in paths:
            count += 1
            if count > verifier._MAX_FILES:
                raise PublicCandidateVerificationError("GH proof set exceeds the existing file count limit")
            source = Path(raw_path)
            try:
                raw = candidate_auth._safe_regular(
                    source, "GH proof bundle for " + subject, verifier._MAX_GH_BUNDLE
                )
                info = source.stat()
                if info.st_nlink != 1:
                    raise PublicCandidateVerificationError("GH proof bundle must not be hard-linked")
                parsed = verifier._strict_json(raw, "GH proof bundle")
                if not isinstance(parsed, dict):
                    raise PublicCandidateVerificationError("GH proof bundle must be a JSON object")
                resolved_source = source.resolve(strict=True)
            except (OSError, TypeError, ValueError) as error:
                raise PublicCandidateVerificationError(str(error)) from error
            if resolved_source == candidate or candidate in resolved_source.parents:
                raise PublicCandidateVerificationError("GH proof bundles must be outside the downloaded candidate")
            digest = _sha256(raw)
            if digest in subject_seen:
                continue
            subject_seen.add(digest)
            if digest not in seen_contents:
                total_bytes += len(raw)
                if total_bytes > verifier._MAX_TREE:
                    raise PublicCandidateVerificationError("GH proof set exceeds the existing byte limit")
                if 2 * candidate_bytes + total_bytes > candidate_auth.MAX_CANDIDATE_PROOF_BYTES:
                    raise PublicCandidateVerificationError("candidate, command snapshot, and GH proof set exceeds the existing 96 MiB limit")
                snapshot = gh_dir / (digest + ".json")
                try:
                    candidate_auth._write_new_file(gh_dir, snapshot.name, raw)
                except (OSError, ValueError) as error:
                    raise PublicCandidateVerificationError(str(error)) from error
                seen_contents[digest] = snapshot
            snapshots[subject].append({"sha256": digest, "path": seen_contents[digest]})
    return snapshots, total_bytes


def _snapshot_candidate(evidence_root: Path, files: dict[str, bytes]) -> Path:
    """Create the exact scanned candidate bytes used by cryptographic commands."""
    snapshot = evidence_root / "candidate-assets"
    try:
        snapshot.mkdir(mode=0o700)
        for name, raw in sorted(files.items()):
            candidate_auth._write_new_file(snapshot, name, raw)
    except (OSError, ValueError) as error:
        raise PublicCandidateVerificationError("could not snapshot the scanned candidate assets") from error
    return snapshot


def _statement_run(statement: dict[str, Any]) -> tuple[int, int]:
    try:
        invocation = statement["predicate"]["runDetails"]["metadata"]["invocationId"]
    except (KeyError, TypeError) as error:
        raise verifier.PublisherVerificationError("SLSA invocationId is missing") from error
    if not isinstance(invocation, str):
        raise verifier.PublisherVerificationError("SLSA invocationId is invalid")
    match = _RUN_INVOCATION.fullmatch(invocation)
    if match is None:
        raise verifier.PublisherVerificationError("SLSA invocationId is not a canonical publisher run")
    try:
        return int(match.group(1)), int(match.group(2))
    except ValueError as error:
        raise verifier.PublisherVerificationError("SLSA invocationId is outside the supported integer range") from error


def _proof_claim(statement: dict[str, Any]) -> str:
    return _sha256(_canonical_json(statement))


def _verify_gh_bundle(subject: str, proof: dict[str, Any], *, candidate: Path,
                      policy: dict[str, Any], asset_rows: dict[str, tuple[int, str]],
                      input_materials: list[dict[str, Any]], run: dict[str, int] | None,
                      deadline: float, env: dict[str, str], commands: list[dict[str, Any]],
                      runner: Callable[..., bytes] | None) -> tuple[dict[str, Any] | None, tuple[int, int] | None, str | None]:
    snapshot = proof["path"]
    command = candidate_auth._gh_command(candidate / subject, snapshot, policy)
    try:
        output = candidate_auth._run_logged(
            command, deadline=deadline, env=env,
            label="github-attestation:" + subject,
            commands=commands, runner=runner,
        )
    except verifier.PublisherVerificationError as error:
        code = candidate_auth._exit_code(error)
        if code is not None and code != 0:
            return None, None, "verifier rejected proof (exit " + str(code) + "): " + str(error)[:500]
        raise
    statement = verifier._statement_result(output, "public GH attestation verification JSON")
    if run is None:
        try:
            run_pair = _statement_run(statement)
            statement_run = {"run_id": run_pair[0], "run_attempt": run_pair[1]}
            verifier._check_predicate(
                statement, policy=policy, run=statement_run, host=HOST,
                subject_paths={subject}, manifest={subject: asset_rows[subject]},
                input_materials=input_materials,
            )
        except verifier.PublisherVerificationError as error:
            return None, None, str(error)[:1000]
        return statement, run_pair, None
    try:
        verifier._check_predicate(
            statement, policy=policy, run=run, host=HOST,
            subject_paths={subject}, manifest={subject: asset_rows[subject]},
            input_materials=input_materials,
        )
    except verifier.PublisherVerificationError as error:
        return None, None, str(error)[:1000]
    return statement, (run["run_id"], run["run_attempt"]), None


def _select_payload_run(candidate: Path, subject: str, proofs: list[dict[str, Any]],
                        policy: dict[str, Any], asset_rows: dict[str, tuple[int, str]],
                        input_materials: list[dict[str, Any]], deadline: float,
                        env: dict[str, str], commands: list[dict[str, Any]],
                        ignored: list[dict[str, Any]], runner: Callable[..., bytes] | None
                        ) -> tuple[dict[str, int], dict[str, Any], list[dict[str, str]]]:
    accepted: dict[tuple[int, int], dict[str, Any]] = {}
    accepted_proofs: dict[tuple[int, int], dict[str, str]] = {}
    executed: dict[str, tuple[dict[str, Any] | None, tuple[int, int] | None, str | None]] = {}
    for proof in proofs:
        digest = proof["sha256"]
        if digest not in executed:
            executed[digest] = _verify_gh_bundle(
                subject, proof, candidate=candidate, policy=policy, asset_rows=asset_rows,
                input_materials=input_materials, run=None, deadline=deadline, env=env,
                commands=commands, runner=runner,
            )
        statement, run_pair, rejection = executed[digest]
        if rejection is not None:
            ignored.append({"subject": subject, "proof_sha256": digest, "reason": rejection})
            continue
        assert statement is not None and run_pair is not None
        claim_digest = _proof_claim(statement)
        previous = accepted.setdefault(run_pair, {"claim": claim_digest, "statement": statement})
        if previous["claim"] != claim_digest:
            previous["conflicting_claim"] = True
        accepted_proofs.setdefault(run_pair, {})[digest] = claim_digest
    if not accepted:
        raise PublicCandidateVerificationError("no cryptographically verified payload statement matches the external source, materials, and host")
    if len(accepted) != 1:
        raise PublicCandidateVerificationError("payload attestations contain multiple matching publisher runs")
    run_pair, selected = next(iter(accepted.items()))
    if selected.get("conflicting_claim"):
        raise PublicCandidateVerificationError("payload run has contradictory accepted attestation statements")
    run = {"run_id": run_pair[0], "run_attempt": run_pair[1]}
    proof_rows = [
        {"sha256": digest, "statement_sha256": claim}
        for digest, claim in sorted(accepted_proofs[run_pair].items())
    ]
    return run, selected["statement"], proof_rows


def _select_subject_statement(subject: str, proofs: list[dict[str, Any]], *,
                              candidate: Path, policy: dict[str, Any],
                              asset_rows: dict[str, tuple[int, str]],
                              input_materials: list[dict[str, Any]], run: dict[str, int],
                              deadline: float, env: dict[str, str],
                              commands: list[dict[str, Any]], ignored: list[dict[str, Any]],
                              runner: Callable[..., bytes] | None
                              ) -> tuple[dict[str, Any], list[dict[str, str]]]:
    accepted: dict[str, dict[str, Any]] = {}
    accepted_proofs: dict[str, dict[str, str]] = {}
    executed: dict[str, tuple[dict[str, Any] | None, tuple[int, int] | None, str | None]] = {}
    for proof in proofs:
        digest = proof["sha256"]
        if digest not in executed:
            executed[digest] = _verify_gh_bundle(
                subject, proof, candidate=candidate, policy=policy, asset_rows=asset_rows,
                input_materials=input_materials, run=run, deadline=deadline, env=env,
                commands=commands, runner=runner,
            )
        statement, _run_pair, rejection = executed[digest]
        if rejection is not None:
            ignored.append({"subject": subject, "proof_sha256": digest, "reason": rejection})
            continue
        assert statement is not None
        claim_digest = _proof_claim(statement)
        accepted.setdefault(claim_digest, statement)
        accepted_proofs.setdefault(claim_digest, {})[digest] = claim_digest
    if not accepted:
        raise PublicCandidateVerificationError("no GH proof for " + subject + " matches the selected publisher run")
    if len(accepted) != 1:
        raise PublicCandidateVerificationError("subject " + subject + " has contradictory accepted attestations")
    claim_digest, statement = next(iter(accepted.items()))
    proof_rows = [
        {"sha256": digest, "statement_sha256": proof_claim}
        for digest, proof_claim in sorted(accepted_proofs[claim_digest].items())
    ]
    return statement, proof_rows


def _write_receipt(evidence_root: Path, receipt: dict[str, Any]) -> Path:
    raw = _canonical_json(receipt)
    if len(raw) > candidate_auth.MAX_PREDICATE_BYTES:
        raise PublicCandidateVerificationError("public candidate receipt exceeds the existing report size limit")
    try:
        return candidate_auth._write_new_file(evidence_root, "receipt.json", raw)
    except (OSError, ValueError) as error:
        raise PublicCandidateVerificationError("could not preserve the public candidate receipt: " + str(error)) from error


def verify_and_unpack(candidate: Path, tag: str, source_commit: str,
                      transport_sha256: str, manifest_sha256: str, policy: dict[str, Any],
                      trusted_inputs_root: Path, gh_bundles: dict[str, list[Path]],
                      destination: Path, work: Path,
                      runner: Callable[..., bytes] | None = None) -> dict[str, Any]:
    """Authenticate the six public assets, then unpack and authenticate the inner bundle.

    `source_commit`, `transport_sha256`, and `manifest_sha256` must be supplied
    by an independent trusted release source. `runner` has the same bounded
    `(argv, deadline, env) -> bytes` contract as the existing candidate verifier.
    """
    if not isinstance(source_commit, str) or _HEX40.fullmatch(source_commit) is None:
        raise PublicCandidateVerificationError("external source commit must be a canonical lowercase commit")
    if not isinstance(transport_sha256, str) or _HEX64.fullmatch(transport_sha256) is None:
        raise PublicCandidateVerificationError("external transport SHA-256 pin is invalid")
    if not isinstance(manifest_sha256, str) or _HEX64.fullmatch(manifest_sha256) is None:
        raise PublicCandidateVerificationError("external release manifest SHA-256 pin is invalid")
    if not isinstance(tag, str):
        raise PublicCandidateVerificationError("release tag must be text")

    try:
        policy = verifier._policy(policy)
    except verifier.PublisherVerificationError as error:
        raise PublicCandidateVerificationError(str(error)) from error
    if policy["source_sha"] != source_commit or policy["workflow_sha"] != source_commit:
        raise PublicCandidateVerificationError("external publisher source and workflow pins must both equal source_commit")
    if HOST not in policy["allowed_host_profiles"]:
        raise PublicCandidateVerificationError("external publisher policy does not authorize the Linux x86-64 host")

    try:
        candidate = candidate_auth._safe_directory(Path(candidate), "downloaded public candidate")
        trusted_inputs_root = candidate_auth._safe_directory(Path(trusted_inputs_root), "trusted publisher inputs")
        work = candidate_auth._safe_directory(Path(work), "public verification work")
        work_info = work.stat()
        if work_info.st_uid != os.getuid() or stat.S_IMODE(work_info.st_mode) & 0o077:
            raise PublicCandidateVerificationError("public verification work must be private and owned by the current user")
        destination, _destination_parent = transport._fresh_directory_path(
            Path(destination), "unpacked destination"
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        if isinstance(error, PublicCandidateVerificationError):
            raise
        raise PublicCandidateVerificationError(str(error)) from error
    _assert_separated_roots(candidate, trusted_inputs_root, work, destination)
    try:
        release_core = stage_candidate._REPLAY.release_core(tag)
    except (TypeError, ValueError) as error:
        raise PublicCandidateVerificationError("release tag is not a canonical public release tag") from error
    _assert_external_policy_resources(policy, {
        "downloaded candidate": candidate,
        "trusted inputs": trusted_inputs_root,
        "verification work": work,
        "unpacked destination": destination,
    })

    try:
        _inputs_raw, input_materials = verifier._inputs_manifest(trusted_inputs_root, policy)
    except verifier.PublisherVerificationError as error:
        raise PublicCandidateVerificationError("external trusted input manifest failed: " + str(error)) from error

    names, initial_files, asset_rows, record = _candidate_files(candidate, tag, transport_sha256)
    initial_candidate_bytes = sum(len(raw) for raw in initial_files.values())
    evidence_root = Path(tempfile.mkdtemp(prefix="public-candidate-", dir=work))
    try:
        os.chmod(evidence_root, 0o700)
    except OSError as error:
        raise PublicCandidateVerificationError("could not secure public proof snapshot directory") from error
    gh_proofs, _proof_bytes = _proof_inputs(
        gh_bundles,
        {names[key] for key in ("payload", "sbom", "transport", "checksums")},
        candidate, evidence_root, initial_candidate_bytes,
    )
    crypto_candidate = _snapshot_candidate(evidence_root, initial_files)

    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "status": FAILED_STATUS,
        "authenticated": False,
        "unpacked": False,
        "installed": False,
        "r1_accepted": False,
        "publication_authorized": False,
        "tag": tag,
        "release_core": release_core,
        "source_commit": source_commit,
        "workflow_commit": source_commit,
        "host_profile": HOST,
        "transport_sha256": transport_sha256,
        "manifest_sha256": manifest_sha256,
        "candidate_assets": stage_candidate._asset_inventory(initial_files),
        "selected_gh_proofs": {},
        "cosign_proofs": {},
        "ignored_gh_proofs": [],
        "commands": [],
        "evidence_directory": str(evidence_root),
        "destination": str(destination),
    }
    try:
        expected_subjects = {names[key] for key in ("payload", "sbom", "transport", "checksums")}
        if set(gh_proofs) != expected_subjects:
            raise PublicCandidateVerificationError("GH proof subject map is incomplete")
        deadline = time.monotonic() + verifier._TOTAL_SECONDS
        with tempfile.TemporaryDirectory(prefix="verifier-home-", dir=evidence_root) as home_name:
            env = candidate_auth._command_env(Path(home_name))
            payload_name = names["payload"]
            run, payload_statement, payload_proofs = _select_payload_run(
                crypto_candidate, payload_name, gh_proofs[payload_name], policy, asset_rows,
                input_materials, deadline, env, receipt["commands"],
                receipt["ignored_gh_proofs"], runner,
            )
            selected_statements: dict[str, dict[str, Any]] = {payload_name: payload_statement}
            receipt["selected_gh_proofs"][payload_name] = payload_proofs
            for subject in sorted(expected_subjects - {payload_name}):
                statement, proof_rows = _select_subject_statement(
                    subject, gh_proofs[subject], candidate=crypto_candidate, policy=policy,
                    asset_rows=asset_rows, input_materials=input_materials, run=run,
                    deadline=deadline, env=env, commands=receipt["commands"],
                    ignored=receipt["ignored_gh_proofs"], runner=runner,
                )
                selected_statements[subject] = statement
                receipt["selected_gh_proofs"][subject] = proof_rows
            candidate_auth._verify_cosign(
                crypto_candidate, tag, policy, env, deadline, receipt["commands"], runner=runner
            )
            for key in ("payload", "transport"):
                subject = names[key]
                bundle_bytes = initial_files[names[key + "_signature"]]
                receipt["cosign_proofs"][subject] = {
                    "bundle_sha256": _sha256(bundle_bytes),
                    "bundle_bytes": len(bundle_bytes),
                }

        # No archive extraction or inner-bundle inspection happens before this point.
        names_after, final_files, final_rows, final_record = _candidate_files(
            candidate, tag, transport_sha256
        )
        if (names_after != names or final_files != initial_files or final_rows != asset_rows
                or final_record != record):
            raise PublicCandidateVerificationError("six candidate assets changed during cryptographic verification")

        unpack_receipt = transport.unpack_bundle(candidate / names["payload"], record, destination)
        if unpack_receipt != record:
            raise PublicCandidateVerificationError("unpack receipt differs from the externally checked transport record")
        # Catch changes spanning the final scan and unpack, including changes to signed metadata.
        _names_after_unpack, files_after_unpack, _rows_after_unpack, _record_after_unpack = _candidate_files(
            candidate, tag, transport_sha256
        )
        if files_after_unpack != initial_files:
            raise PublicCandidateVerificationError("six candidate assets changed while the payload was unpacked")

        raw_manifest = verifier._read_regular(
            destination / "release.json", 4 * 1024 * 1024, "unpacked inner release manifest"
        )
        if _sha256(raw_manifest) != manifest_sha256:
            raise PublicCandidateVerificationError("unpacked release.json does not match the external manifest SHA-256 pin")
        try:
            inner_root, manifest, authenticated_manifest, inner_tag, inner_result = candidate_auth._load_inner_bundle(
                destination, policy, {
                    "source_sha": source_commit,
                    "workflow_sha": source_commit,
                    "run_id": run["run_id"],
                    "run_attempt": run["run_attempt"],
                }
            )
        except candidate_auth.CandidateAuthenticationError as error:
            raise PublicCandidateVerificationError(str(error)) from error
        if _sha256(authenticated_manifest) != manifest_sha256:
            raise PublicCandidateVerificationError("authenticated release.json changed from the external manifest pin")
        if inner_tag != "v" + release_core or manifest.get("version") != release_core:
            raise PublicCandidateVerificationError("outer tag core does not match the authenticated inner release version")
        try:
            _manifest_check, manifest_source = stage_candidate._validate_release_manifest(
                authenticated_manifest, record, release_core, stage_candidate._INNER_SBOM_NAME
            )
        except (TypeError, ValueError) as error:
            raise PublicCandidateVerificationError("inner release manifest does not match the public transport inventory") from error
        if manifest_source != source_commit:
            raise PublicCandidateVerificationError("inner release manifest source differs from the external source pin")
        outer_sbom = final_files[names["sbom"]]
        inner_sbom = verifier._read_regular(
            inner_root / stage_candidate._INNER_SBOM_NAME, len(outer_sbom),
            "unpacked inner SBOM",
        )
        if inner_sbom != outer_sbom:
            raise PublicCandidateVerificationError("outer SBOM differs from the authenticated inner bundle SBOM")
        expected_predicate = ci_auth.predicate(inner_root, HOST)
        for subject in sorted(expected_subjects):
            if selected_statements[subject].get("predicate") != expected_predicate:
                raise PublicCandidateVerificationError(
                    "outer GH predicate for " + subject + " differs from the authenticated inner publisher predicate"
                )

        receipt.update({
            "status": RECEIPT_STATUS,
            "authenticated": True,
            "unpacked": True,
            "run_id": run["run_id"],
            "run_attempt": run["run_attempt"],
            "version": manifest["version"],
            "inner_manifest_sha256": _sha256(authenticated_manifest),
            "inner_verification": {
                "verified": inner_result.get("verified"),
                "manifest_sha256": inner_result.get("manifestSha256"),
                "source_sha": inner_result.get("sourceSha"),
                "workflow_sha": inner_result.get("workflowSha"),
                "workflow_runs": inner_result.get("workflowRuns"),
            },
            "unpacked_inventory": record["files"],
            "claim": "The selected public candidate and its inner publisher bundle authenticated and were safely unpacked; installation and R1 acceptance remain separate decisions.",
        })
        receipt["receipt_path"] = str(evidence_root / "receipt.json")
        _write_receipt(evidence_root, receipt)
        return receipt
    except Exception as error:
        receipt["status"] = FAILED_STATUS
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)[:2000]}
        try:
            _write_receipt(evidence_root, receipt)
        except Exception as receipt_error:
            raise PublicCandidateVerificationError(
                "public candidate verification failed and its evidence receipt could not be saved: " + str(receipt_error)
            ) from error
        raise

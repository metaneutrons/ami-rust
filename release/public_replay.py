#!/usr/bin/env python3
"""Replay one publicly retrieved SDK bundle through the documented consumer flow.

This client records publisher evidence verification and a hosted consumer replay.
It does not publish a release, accept R1, or run an AROS guest. Run this driver
with the pinned Python interpreter in isolated, no-bytecode mode.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any


RESULT_SCHEMA = "ami-rust-public-consumer-replay-v1"
RESULT_STATUS = "PASS_PUBLIC_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE"
FAILURE_SCHEMA = "ami-rust-public-consumer-replay-failure-v1"
FAILURE_NAME = "public-replay-failure.json"
RESULT_NAME = "public-replay.json"
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
SEMVER_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
RELEASE_TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:" + SEMVER_IDENTIFIER + r")(?:\." + SEMVER_IDENTIFIER + r")*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
APPROVED_REPOSITORY = "metaneutrons/ami-rust"
REQUIRED_CONSUMER_ASSETS = (
    "sdk.tar.xz", "SHAUTIL", "install.py", "install_publisher.py",
    "verify_publisher.py", "new_project.py", "QUICKSTART.md",
)


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _absolute_real_directory(label: str, value: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(label + " must be an absolute path")
    resolved = path.resolve(strict=True)
    if path != resolved or not resolved.is_dir():
        raise ValueError(label + " must be an existing real directory without symlink components")
    return resolved


def release_core(release_tag: str) -> str:
    """Return the SemVer release core from a canonical v-prefixed tag."""
    if not isinstance(release_tag, str) or RELEASE_TAG_RE.fullmatch(release_tag) is None:
        raise ValueError("release tag must be a canonical v-prefixed SemVer value")
    return release_tag[1:].split("-", 1)[0].split("+", 1)[0]


def _load_trusted_helpers(source: Path) -> ModuleType:
    script = source / "release" / "ci_verify.py"
    if script.is_symlink() or not script.is_file():
        raise ValueError("selected source has no regular release/ci_verify.py")
    name = "_ami_rust_public_replay_ci_verify"
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load hosted consumer helpers from selected source")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    if Path(module.ROOT).resolve(strict=True) != source:
        raise ValueError("loaded consumer helpers are not bound to the selected source checkout")
    return module


def _git_preflight(source: Path, expected_commit: str) -> None:
    """Validate the selected checkout with read-only Git commands before import."""
    git_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(source),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["/usr/bin/git", "-C", str(source), "-c", "core.fsmonitor=false", *arguments],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=30,
                env=git_env, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("selected source Git preflight could not complete") from error
        if result.returncode != 0:
            raise ValueError("selected source Git preflight failed")
        return result.stdout.strip()

    top_level = Path(git("rev-parse", "--show-toplevel")).resolve(strict=True)
    if top_level != source:
        raise ValueError("--source must name the selected Git checkout root")
    if git("rev-parse", "HEAD") != expected_commit:
        raise ValueError("selected source HEAD differs from the external source commit")
    if git("status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"):
        raise ValueError("selected source checkout has tracked, untracked, or submodule modifications")

    raw_origins = git("config", "--local", "--get-all", "remote.origin.url").splitlines()
    if len(raw_origins) != 1:
        raise ValueError("selected source must have exactly one configured origin URL")
    configured_origin = raw_origins[0].removesuffix(".git")
    effective_origin = git("remote", "get-url", "origin").removesuffix(".git")
    approved = {
        "https://github.com/" + APPROVED_REPOSITORY,
        "git@github.com:" + APPROVED_REPOSITORY,
    }
    if configured_origin not in approved or effective_origin not in approved:
        raise ValueError("selected source origin is not the approved publisher repository")


def _verify_release_tag_target(source: Path, release_tag: str,
                              expected_commit: str) -> str:
    """Peel one exact release tag and bind it and HEAD to the external source pin."""
    if RELEASE_TAG_RE.fullmatch(release_tag) is None:
        raise ValueError("release tag must be a canonical v-prefixed SemVer value")
    if not COMMIT_RE.fullmatch(expected_commit):
        raise ValueError("publisher source must be an exact lowercase 40-character Git commit")

    git_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(source),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["/usr/bin/git", "-C", str(source), "-c", "core.fsmonitor=false", *arguments],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=30,
                env=git_env, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("selected release tag Git verification could not complete") from error
        if result.returncode != 0:
            raise ValueError("selected release tag Git verification failed")
        return result.stdout.strip()

    head = git("rev-parse", "--verify", "HEAD")
    if head != expected_commit:
        raise ValueError("selected source HEAD differs from the external source commit")

    # A fully qualified tag ref avoids DWIM and abbreviated-ref selection.
    # ^{commit} peels annotated tags and accepts lightweight tags while
    # rejecting tags that do not ultimately name a commit.
    target = git("rev-parse", "--verify", "--quiet",
                 "refs/tags/" + release_tag + "^{commit}")
    if COMMIT_RE.fullmatch(target) is None:
        raise ValueError("selected release tag did not resolve to one exact commit")
    if target != expected_commit:
        raise ValueError("selected release tag target differs from the external source commit")
    return target


def _load_selected_trusted_helpers(source: Path, expected_commit: str) -> ModuleType:
    """Run the clean checkout preflight before importing its trusted helpers."""
    _git_preflight(source, expected_commit)
    return _load_trusted_helpers(source)


def _empty_managed_roots(work: Path, output: Path) -> None:
    for label, root in (("work", work), ("output", output)):
        if root.is_symlink() or not root.is_dir():
            raise ValueError(label + " must be a real managed directory")
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError(label + " must be private and owned by the current user")
        if next(root.iterdir(), None) is not None:
            raise ValueError(label + " must be fresh and empty")


def _write_failure(output: Path, phase: str, error: Exception,
                   release_tag: str, source_commit: str, manifest_sha256: str,
                   supervisor: Any | None,
                   release_tag_target_commit: str | None = None) -> None:
    """Keep a bounded, environment-free failure receipt when output is safe."""
    try:
        if output.is_symlink() or not output.is_dir():
            return
        info = output.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            return
        destination = output / FAILURE_NAME
        if destination.exists() or destination.is_symlink():
            return
        record = {
            "schema": FAILURE_SCHEMA,
            "status": "FAIL_PUBLIC_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE",
            "phase": phase,
            "release_tag": release_tag,
            "source_commit": source_commit,
            "expected_release_manifest_sha256": manifest_sha256,
            "error_type": type(error).__name__,
            "error": str(error)[:2000],
            "commands": list(getattr(supervisor, "commands", ()))[:256],
            "claims": {"R1_accepted": False, "published_by_harness": False,
                       "aros_guest_run": False},
        }
        if release_tag_target_commit is not None:
            record["release_tag_target_commit"] = release_tag_target_commit
        raw = _canonical_json(record)
        if len(raw) > 256 * 1024:
            record["commands"] = []
            record["error"] = str(error)[:512]
            raw = _canonical_json(record)
        with destination.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        destination.chmod(0o600)
    except OSError:
        # Preserve the originating exception; never mask it with report I/O.
        return


def _write_success(output: Path, helpers: ModuleType, report: dict) -> None:
    destination = output / RESULT_NAME
    if destination.exists() or destination.is_symlink():
        raise ValueError("public replay result destination must be fresh")
    max_output = helpers.MAX_OUTPUT_BYTES
    base_bytes = helpers.ci_sdk.directory_bytes(output)
    report["output_bytes"] = 0
    for _ in range(3):
        raw = helpers.canonical_json(report)
        expected = base_bytes + len(raw)
        if report["output_bytes"] == expected:
            break
        report["output_bytes"] = expected
    raw = helpers.canonical_json(report)
    output_bytes = base_bytes + len(raw)
    if output_bytes > max_output:
        raise ValueError("replay metadata and native payloads exceed the existing output bound")
    report["output_bytes"] = output_bytes
    raw = helpers.canonical_json(report)
    if base_bytes + len(raw) != output_bytes:
        raise RuntimeError("public replay result size calculation did not converge")
    with destination.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    destination.chmod(0o600)


def replay_public_candidate(*, source: Path, source_commit: str, bundle: Path,
                            manifest_sha256: str, release_tag: str,
                            work: Path, output: Path,
                            python_bootstrap_root: Path,
                            helpers: ModuleType | None = None) -> dict:
    """Verify and replay a safe-extracted public bundle using selected source helpers."""
    phase = "input-validation"
    supervisor = None
    release_tag_target_commit = None
    source_commit = str(source_commit)
    manifest_sha256 = str(manifest_sha256)
    release_tag = str(release_tag)
    output_path = Path(output).absolute()
    try:
        if RELEASE_TAG_RE.fullmatch(release_tag) is None:
            raise ValueError("--release-tag must be a v-prefixed SemVer value")
        if not COMMIT_RE.fullmatch(source_commit):
            raise ValueError("--source-commit must be an exact lowercase 40-character Git commit")
        if not DIGEST_RE.fullmatch(manifest_sha256):
            raise ValueError("--manifest-sha256 must be an exact lowercase 64-character digest")

        source_path = _absolute_real_directory("--source", Path(source))
        bundle_path = Path(bundle)
        if not bundle_path.is_absolute():
            raise ValueError("--bundle must be an absolute path")
        if source_path == bundle_path or source_path in bundle_path.parents or bundle_path in source_path.parents:
            raise ValueError("public bundle must be outside the selected source checkout")

        # Load only from the explicit checkout, then require its actual clean
        # Git identity. This helper does not consult or fabricate CI identity.
        phase = "source-identity"
        trusted = (helpers if helpers is not None
                   else _load_selected_trusted_helpers(source_path, source_commit))
        if hasattr(trusted, "ROOT") and Path(trusted.ROOT).resolve(strict=True) != source_path:
            raise ValueError("consumer helper root differs from the selected source checkout")
        identity = trusted.consumer_source_identity(source_commit, source_commit)
        expected_identity = {"source_sha": source_commit, "workflow_sha": source_commit}
        if identity != expected_identity:
            raise ValueError("consumer source identity differs from the externally selected source commit")
        if trusted.ci_auth.REPO != APPROVED_REPOSITORY:
            raise ValueError("selected source helper repository identity differs from the approved origin")

        phase = "release-tag-source-binding"
        release_tag_target_commit = _verify_release_tag_target(
            source_path, release_tag, source_commit)

        phase = "external-manifest-pin"
        original_bundle = bundle_path.absolute()
        _, external_bundle_bytes = trusted._candidate_inventory(original_bundle)
        manifest_path = original_bundle / "release.json"
        observed_manifest_sha = sha256(manifest_path)
        if observed_manifest_sha != manifest_sha256:
            raise ValueError("public release.json differs from the externally supplied manifest SHA-256")

        work_path = Path(work)
        output_path = Path(output)
        python_root = Path(python_bootstrap_root)
        trusted._managed_roots(work_path, output_path, python_root)
        _empty_managed_roots(work_path, output_path)
        if any(path.resolve(strict=True) == original_bundle
               or path.resolve(strict=True) in original_bundle.parents
               or original_bundle in path.resolve(strict=True).parents
               for path in (work_path, output_path, python_root)):
            raise ValueError("public bundle must be separate from every managed root")

        phase = "pinned-runtime-and-tools"
        host = trusted.host_identity()
        python, python_bootstrap = trusted.ci_sdk.verify_python_bootstrap(python_root, host)
        tool_manifest_path = source_path / "release" / "ci-auth-tools.json"
        tool_manifest = trusted.strict_json(tool_manifest_path, 1024 * 1024)
        tool_pins = trusted.validate_tool_manifest(tool_manifest, host)

        # bootstrap_tools uses consumer_source_identity when source_commit is
        # explicit, and charges the external bundle bytes to its Supervisor.
        trusted.bootstrap_tools(work_path, output_path, python_root,
                                source_commit=identity["source_sha"],
                                additional_input_bytes=external_bundle_bytes)
        tool_receipt = trusted._verify_tool_receipt(work_path, output_path, host, tool_manifest)
        if {entry.name for entry in output_path.iterdir()} != {"tool-bootstrap.json"}:
            raise ValueError("fresh replay output contains unexpected verifier bootstrap entries")

        roots = tool_receipt["roots"]
        policy_path, policy = trusted._write_source_policy(identity, roots, work_path)
        env = trusted._tool_env(work_path, python)
        supervisor = trusted.ci_sdk.Supervisor(work_path, output_path, python_root, env)
        supervisor.checkout_bytes += external_bundle_bytes

        gh_text = trusted._version_text(supervisor, work_path / "tools/gh",
                                        ["--version"], "public-replay-verify-gh-version")
        cosign_text = trusted._version_text(supervisor, work_path / "tools/cosign",
                                            ["version"], "public-replay-verify-cosign-version")
        if ("gh version 2.102.0" not in gh_text
                or not re.search(r"\bv?3\.1\.3\b", cosign_text)):
            raise ValueError("pinned verifier tool version changed before public bundle verification")
        if (trusted.sha256(work_path / "tools/gh") != tool_pins["gh"]["binary_sha256"]
                or trusted.sha256(work_path / "tools/cosign") != tool_pins["cosign"]["binary_sha256"]):
            raise ValueError("pinned verifier tool changed before public bundle verification")

        # Copy and pin one private snapshot. Check the external release manifest
        # both before and after copying; do not parse it before protected verify.
        phase = "candidate-snapshot"
        if original_bundle == work_path or original_bundle in work_path.parents or work_path in original_bundle.parents:
            raise ValueError("public bundle must not overlap managed work")
        if original_bundle == output_path or original_bundle in output_path.parents or output_path in original_bundle.parents:
            raise ValueError("public bundle must not overlap managed output")
        candidate = work_path / "candidate"
        bundle_copy = trusted._copy_candidate(original_bundle, candidate)
        if (bundle_copy["bytes"] != external_bundle_bytes
                or sha256(manifest_path) != manifest_sha256
                or trusted.sha256(candidate / "release.json") != manifest_sha256):
            raise ValueError("public bundle changed after external manifest pinning")

        # This is the first command that parses the candidate release manifest.
        # The verifier program itself comes only from the selected clean source.
        phase = "protected-source-verification"
        verify_row, verify_stdout, _ = trusted._run_supervised(
            supervisor, python, source_path / "release" / "install_publisher.py",
            ["verify", "--bundle", str(candidate), "--policy", str(policy_path)],
            cwd=work_path, label="public-replay-protected-source-verify", timeout=300)
        verified = trusted._parse_command_result(
            verify_stdout, "verified", "selected-source public bundle verifier")
        if verified.get("host") != host or verified.get("qualification_only") is not False:
            raise ValueError("protected-source verifier returned a different host or release route")
        if verified.get("release_manifest_sha256") != manifest_sha256:
            raise ValueError("protected-source verifier did not bind the externally pinned release manifest")
        trusted._validate_trusted_consumer_assets(candidate, verified, policy)

        # Read candidate metadata and documentation only after protected verify.
        candidate_manifest = trusted.strict_json(candidate / "release.json", 1024 * 1024)
        if (not isinstance(candidate_manifest, dict)
                or candidate_manifest.get("version") != release_core(release_tag)):
            raise ValueError("authenticated release manifest version differs from selected release tag")
        asset_rows = {row["path"]: row for row in candidate_manifest.get("assets", [])
                      if isinstance(row, dict) and isinstance(row.get("path"), str)}
        if (len(asset_rows) != len(candidate_manifest.get("assets", []))
                or candidate_manifest.get("qualification_only") is not False):
            raise ValueError("consumer route requires an unambiguous production manifest")
        for name in ("sdk.tar.xz", "SHAUTIL", f"cargo-{host}.tar.xz", *REQUIRED_CONSUMER_ASSETS[2:]):
            if name not in asset_rows:
                raise ValueError("authenticated candidate omits a required consumer asset: " + name)

        phase = "reference-and-replay-preparation"
        reference_inputs, resources, _ = trusted.ci_sdk.read_normative(
            source_path / "release/ci-sdk-inputs.json",
            source_path / "release/ci-resources.json", host)
        capacity = trusted.ci_sdk.validate_resource_policy(resources, work_path.parent)
        reference = trusted.ci_sdk.validate_native_reference(
            trusted.ci_sdk.read_json(source_path / "release/native-reference.json", 2 * 1024**2),
            reference_inputs, reference_inputs["native_reference"]["sha256"])

        probe_rows = trusted.run_negative_probes(
            candidate, policy_path, work_path,
            work_path / "consumers" / "absolute-a" / "sdk-0.1.0",
            lambda probe, probe_policy, label: trusted._expect_verify_rejection(
                supervisor, python, probe, probe_policy, label))

        prepare_command, check_command = trusted._preparation_commands(candidate)
        first_consumer = trusted._create_consumer_roots(work_path)
        preparation_env = dict(supervisor.env)
        preparation_env.update({
            "SOURCE": str(source_path), "SOURCE_COMMIT": identity["source_sha"],
            "WORKFLOW_COMMIT": identity["workflow_sha"], "PREP_PYTHON": str(python),
            "PYTHON_BOOTSTRAP": str(python_root), "PREP": str(work_path),
            "PREP_OUTPUT": str(output_path), "BUNDLE": str(original_bundle),
            "WORK": str(first_consumer),
        })
        prepare_row, prepare_stdout, _ = trusted._run_recipe_line(
            supervisor, preparation_env, first_consumer, prepare_command,
            "public-replay-document-prepare-inputs")
        preparation = trusted._parse_command_result(
            prepare_stdout, "PREPARED_VERIFIED_INPUTS_NOT_INSTALLED",
            "documented consumer preparation")
        if (preparation.get("source_policy") != identity
                or preparation.get("release_manifest_sha256") != manifest_sha256):
            raise ValueError("documented preparation differs from the selected source or public manifest")

        sdk_root = work_path / "verified-source-sdk"
        sdk_manifest_path = sdk_root / "contract" / "sdk.json"
        sdk_info = {
            "root": sdk_root,
            "manifest": trusted.ci_sdk.read_json(sdk_manifest_path, 2 * 1024**2),
            "manifest_sha256": trusted.sha256(sdk_manifest_path),
        }
        sdk_info["component_info"] = trusted.ci_sdk._component_rows_from_sdk(sdk_info, host)
        if (sdk_info["manifest_sha256"] != preparation.get("sdk_manifest_sha256")
                or sdk_info["manifest"].get("source_identity") != identity["source_sha"]):
            raise ValueError("prepared SDK differs from the selected source preparation receipt")
        ordered_components = {name: work_path / "component-staging" / name
                              for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")}
        component_inventories = {
            name: trusted.ci_sdk.verify_component(
                component_root, sdk_info["component_info"][name]["manifest"], name)
            for name, component_root in ordered_components.items()
        }

        commands, quickstart_sha = trusted._recipe_commands(candidate)
        consumer_report = trusted._install_and_run_recipe(
            candidate, work_path, output_path, python, supervisor, host, sdk_info,
            ordered_components, reference, commands)
        if len(consumer_report["retained_native"]) != 5:
            raise ValueError("consumer replay must retain all five native variants")

        phase = "post-uninstall-input-recheck"
        check_row, check_stdout, _ = trusted._run_recipe_line(
            supervisor, preparation_env, first_consumer, check_command,
            "public-replay-document-check-inputs-after-uninstall")
        recheck = trusted._parse_command_result(
            check_stdout, "VERIFIED_RETAINED_INPUTS", "documented retained input check")
        if (recheck.get("components") != component_inventories
                or recheck.get("selection_sha256") != preparation.get("selection_sha256")
                or recheck.get("policy_sha256") != preparation.get("policy_sha256")):
            raise ValueError("post-uninstall input recheck differs from the verified preparation")

        trusted._assert_source_clean(identity["source_sha"])
        supervisor.check_limits("completed public consumer replay")
        report = {
            "schema": RESULT_SCHEMA,
            "status": RESULT_STATUS,
            "release_tag": release_tag,
            "release_tag_target_commit": release_tag_target_commit,
            "host": host,
            "source_policy": {
                "source_sha": identity["source_sha"],
                "workflow_sha": identity["workflow_sha"],
                "source_ref": "refs/heads/main",
                "repository": trusted.ci_auth.REPO,
                "inputs_manifest_sha256": policy["inputs_manifest_sha256"],
                "external_policy_sha256": trusted.sha256(policy_path),
                "tool_manifest_sha256": trusted.sha256(tool_manifest_path),
            },
            "python_bootstrap": {
                "archive_sha256": python_bootstrap["archive_sha256"],
                "runtime_sha256": python_bootstrap["runtime_sha256"],
            },
            "tools": tool_receipt["tools"],
            "roots": tool_receipt["roots"],
            "candidate": {
                "release_manifest_sha256": manifest_sha256,
                "bundle_copy": bundle_copy,
                "external_bundle_bytes": external_bundle_bytes,
                "version": candidate_manifest["version"],
                "sdk_manifest_sha256": sdk_info["manifest_sha256"],
                "sdk_archive_sha256": asset_rows["sdk.tar.xz"]["sha256"],
                "qualification_only": False,
            },
            "protected_source_verification": {
                "process": verify_row,
                "status": verified["status"],
                "release_manifest_sha256": verified["release_manifest_sha256"],
                "authentication": verified["authentication"],
            },
            "negative_verification": probe_rows,
            "provisioning": {"components": component_inventories,
                             **preparation.get("provisioning", {})},
            "documented_preparation": {
                "command": prepare_command,
                "process": prepare_row,
                "receipt_sha256": trusted.sha256(output_path / "consumer-preparation.json"),
                "after_uninstall": {"command": check_command, "process": check_row,
                                    "result": recheck},
            },
            "consumer_recipe": {
                "quickstart_sha256": quickstart_sha,
                "commands_per_root": list(commands),
                "roots": consumer_report["commands"],
                "uninstall": consumer_report["uninstall"],
                "prerequisite_inventories_after_uninstall":
                    consumer_report["prerequisite_inventories_after_uninstall"],
                "unrelated_sibling_marker_sha256":
                    consumer_report["unrelated_sibling_marker_sha256"],
            },
            "retained_native": consumer_report["retained_native"],
            "budgets": {"workspace_bytes": trusted.ci_sdk.MAX_WORK_BYTES,
                        "rss_bytes": trusted.ci_sdk.MAX_RSS_BYTES,
                        "log_bytes": trusted.ci_sdk.MAX_LOG_BYTES,
                        "command_seconds": trusted.ci_sdk.MAX_COMMAND_SECONDS,
                        "output_bytes_limit": trusted.MAX_OUTPUT_BYTES},
            "capacity_preflight": capacity,
            "peaks": {"checkout_bytes": supervisor.checkout_bytes,
                      "workspace_bytes": supervisor.peak_workspace,
                      "rss_bytes": supervisor.peak_rss,
                      "logs_bytes": supervisor.peak_logs,
                      "commands": supervisor.commands},
            "claims": {
                "publisher_evidence_verified": True,
                "public_transport_verified_by_harness": False,
                "publisher_release_acceptance": False,
                "r1_accepted": False,
                "published_by_harness": False,
                "aros_guest_run": False,
                "two_host_replay_complete": False,
            },
        }
        phase = "write-replay-result"
        _write_success(output_path, trusted, report)
        return report
    except Exception as error:
        _write_failure(output_path, phase, error, release_tag, source_commit,
                       manifest_sha256, supervisor, release_tag_target_commit)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True,
                        help="clean public publisher source checkout")
    parser.add_argument("--source-commit", required=True,
                        help="externally selected exact publisher source commit")
    parser.add_argument("--bundle", type=Path, required=True,
                        help="already downloaded and safe-extracted public release bundle")
    parser.add_argument("--manifest-sha256", required=True,
                        help="externally recorded release.json SHA-256")
    parser.add_argument("--release-tag", required=True,
                        help="externally selected v-prefixed semantic-version release tag")
    parser.add_argument("--work", type=Path, required=True,
                        help="fresh private work directory")
    parser.add_argument("--output", type=Path, required=True,
                        help="fresh private output directory")
    parser.add_argument("--python-bootstrap-root", type=Path, required=True,
                        help="pinned ami-rust-python-bootstrap directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not sys.flags.isolated or not sys.dont_write_bytecode:
            raise ValueError("run public_replay.py under the pinned Python with -I -B")
        replay_public_candidate(
            source=args.source, source_commit=args.source_commit, bundle=args.bundle,
            manifest_sha256=args.manifest_sha256, release_tag=args.release_tag,
            work=args.work, output=args.output,
            python_bootstrap_root=args.python_bootstrap_root,
        )
        return 0
    except Exception as error:
        print(json.dumps({"status": "FAIL_PUBLIC_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE",
                          "error_type": type(error).__name__,
                          "error": str(error)[:2000]}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

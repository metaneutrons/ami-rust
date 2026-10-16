#!/usr/bin/env python3
"""Production publisher-evidence verifier and user-owned SDK installer.

Run with the intended Python as ``python -I -B release/install_publisher.py``.
This verifies GH/Cosign evidence against an owner-protected external policy.
It does not establish R1 guest qualification or acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile

# Python's isolated mode excludes the script directory from import search.
# Import only the adjacent installer/verifier modules shipped at this entrypoint.
_SCRIPT_DIR = Path(__file__).resolve(strict=True).parent
sys.path.insert(0, str(_SCRIPT_DIR))

import install as installer
import verify_publisher as publisher_verifier


def _load_policy(path_value, bundle):
    path = installer._canonical_absolute(path_value, "external publisher policy")
    installer._real_regular(path, "external publisher policy")
    installer._protected_input(path, "external publisher policy")
    bundle = Path(bundle).resolve(strict=True)
    if path == bundle or bundle in path.parents:
        raise installer.Refusal("publisher policy must be outside the release bundle")
    raw = installer._read_fd(path, 1024 * 1024, "external publisher policy")
    policy = installer._json(raw, "external publisher policy")
    for field in ("gh", "cosign", "gh_trusted_roots", "cosign_trusted_root"):
        entry = policy.get(field) if isinstance(policy, dict) else None
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            # The publisher verifier will produce the detailed schema refusal;
            # this boundary must still reject any ambiguous trust input now.
            continue
        trust_path = installer._canonical_absolute(entry["path"], f"external {field}")
        installer._real_regular(trust_path, f"external {field}",
                                executable=field in ("gh", "cosign"))
        installer._protected_input(trust_path, f"external {field}")
        if trust_path == bundle or bundle in trust_path.parents:
            raise installer.Refusal(f"{field} trust input must be outside the release bundle")
    return policy, hashlib.sha256(raw).hexdigest()


def _verified_production_bundle(bundle_value, policy_value):
    if not isinstance(bundle_value, str) or not bundle_value:
        raise installer.Refusal("bundle directory path is required")
    bundle = Path(os.path.abspath(bundle_value))
    try:
        if bundle.resolve(strict=True) != bundle:
            raise installer.Refusal("bundle path must not contain symlink components")
    except OSError as error:
        raise installer.Refusal(f"missing release bundle: {error}") from error
    policy, policy_digest = _load_policy(policy_value, bundle)

    # The real fail-closed cryptographic verifier runs before archive parsing or
    # any installation side effect. Adapter tests replace only its subprocess boundary.
    manifest_raw = installer._read_relative(bundle, "release.json", installer.MANIFEST_LIMIT,
                                            "release manifest")
    manifest = installer._json(manifest_raw, "release manifest")
    report = publisher_verifier.verify(bundle, manifest, policy)
    if (not isinstance(report, dict)
            or report.get("workflowSha") != policy.get("workflow_sha")
            or report.get("sourceSha") != policy.get("source_sha")
            or report.get("sourceRef") != policy.get("source_ref")
            or report.get("repository") != policy.get("repository")
            or report.get("workflow") != policy.get("workflow")):
        raise installer.Refusal("publisher verification report differs from the external policy")
    auth_evidence = {"report": report, "external_policy_sha256": policy_digest}
    installer._validate_authentication(auth_evidence, installer._sha(manifest_raw))

    try:
        manifest, assets, sdk_files = installer._release_manifest(manifest_raw, production=True)
        if manifest["qualification_only"] is not False:
            raise installer.Refusal("production publisher route requires qualification_only=false")
        if report["manifestBoundAssets"] != sorted(assets):
            raise installer.Refusal("publisher report assets do not match the release manifest")
        asset_data = {}
        for name, (size, digest) in assets.items():
            data = installer._read_relative(bundle, name, installer.ASSET_LIMIT, f"asset {name}")
            if len(data) != size or installer._sha(data) != digest:
                raise installer.Refusal(f"asset identity mismatch: {name}")
            asset_data[name] = data
        sdk_files_data, sdk_modes = installer._verify_archive(asset_data["sdk.tar.xz"], sdk_files)
        sdk_manifest_raw = sdk_files_data["contract/sdk.json"]
        if installer._sha(sdk_manifest_raw) != manifest["sdk_manifest_sha256"]:
            raise installer.Refusal("SDK manifest digest mismatch")
        sdk_manifest = installer._json(sdk_manifest_raw, "SDK manifest")
        if (sdk_manifest.get("schema") != "ami-rust-sdk-v1"
                or sdk_manifest.get("version") != manifest["version"]
                or sdk_manifest.get("qualification_only") is not False):
            raise installer.Refusal("inner SDK manifest must match the non-qualification release")
        declared_sdk = installer._inventory(
            sdk_manifest.get("files"), "inner SDK file", count_limit=installer.ARCHIVE_MEMBERS_LIMIT,
            total_limit=installer.ARCHIVE_LIMIT, file_limit=installer.ARCHIVE_LIMIT)
        if any(sdk_files.get(name) != value for name, value in declared_sdk.items()):
            raise installer.Refusal("inner SDK inventory differs from signed archive inventory")
        executable_files = {name for name in sdk_files if name.startswith(
            ("host/", "crates/", "native/", "targets/", "tests/", "examples/"))}
        if not executable_files <= set(declared_sdk):
            raise installer.Refusal("inner SDK inventory omits an executable/host source file")

        # The authenticated mapping has one exact Cosign bundle for release.json.
        auth_raw = installer._read_relative(bundle, ".auth/authentication.json", 1024 * 1024,
                                            "publisher authentication metadata")
        auth = installer._json(auth_raw, "publisher authentication metadata")
        mappings = auth.get("cosign_bundles") if isinstance(auth, dict) else None
        rows = [row for row in mappings if isinstance(row, dict) and row.get("path") == "release.json"] \
            if isinstance(mappings, list) else []
        if len(rows) != 1 or set(rows[0]) != {"path", "bundle"}:
            raise installer.Refusal("authentication metadata must map one release.json Cosign bundle")
        cosign_path = rows[0]["bundle"]
        installer._portable_path(cosign_path, "release.json Cosign bundle")
        signature = installer._read_relative(bundle, cosign_path, 1024 * 1024,
                                             "release.json Cosign bundle")
        installer._json(signature, "release.json Cosign bundle")
    except (installer.Refusal, OSError, tarfile.TarError, lzma.LZMAError):
        raise
    except publisher_verifier.PublisherVerificationError as error:
        raise installer.Refusal(str(error)) from error

    return {"host": installer._host_key(), "bundle": bundle, "manifest": manifest,
            "manifest_raw": manifest_raw, "manifest_sha256": installer._sha(manifest_raw),
            "signature": signature, "assets": asset_data,
            "sdk_files": sdk_files_data, "sdk_modes": sdk_modes,
            "authentication": auth_evidence, "publisher_report": report}


def _verify_command(args):
    result = _verified_production_bundle(args.bundle, args.policy)
    return {"status": "verified", "publisher": "metaneutrons.ami-rust.github",
            "release_manifest_sha256": result["manifest_sha256"],
            "version": result["manifest"]["version"], "host": result["host"],
            "qualification_only": False, "authentication": result["publisher_report"],
            "claim": "publisher evidence and candidate bytes verified; R1 qualification and acceptance are not established"}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify publisher evidence and install a production ami-rust release. "
                    "Does not establish R1 guest qualification or acceptance.")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify publisher evidence under an external policy")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--policy", required=True)
    install = commands.add_parser("install", help="verify and install a production release")
    install.add_argument("--bundle", required=True)
    install.add_argument("--policy", required=True)
    install.add_argument("--prefix", required=True)
    install.add_argument("--receipt-pin", help="fresh external file for the receipt SHA-256")
    uninstall = commands.add_parser("uninstall", help="remove an installation with its external receipt pin")
    uninstall.add_argument("--prefix", required=True)
    uninstall.add_argument("--receipt-sha256", required=True)
    lock = commands.add_parser("lock", help="bind an explicit selection to an existing project")
    lock.add_argument("--prefix", required=True)
    lock.add_argument("--selection", required=True)
    lock.add_argument("--project", required=True)
    lock.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        parser.error("run with the intended Python using -I -B")
    try:
        if args.command == "verify":
            result = _verify_command(args)
        elif args.command == "install":
            verified = _verified_production_bundle(args.bundle, args.policy)
            result = installer._install_verified(verified, args.prefix, args.receipt_pin)
        elif args.command == "uninstall":
            result = installer._uninstall(args.prefix, args.receipt_sha256)
        else:
            result = installer._lock(args.prefix, args.selection, args.project, args.output)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except installer.PinWriteFailure as error:
        print(json.dumps({"status": "installed_receipt_pin_failed", "prefix": error.prefix,
                          "receipt_sha256": error.receipt_sha256, "error": str(error)},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 1
    except installer.PublishedInterruption as error:
        print(json.dumps({"status": "installed_interrupted", "prefix": error.prefix,
                          "receipt_sha256": error.receipt_sha256, "error": str(error)},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 1
    except (installer.Refusal, publisher_verifier.PublisherVerificationError, OSError,
            InterruptedError, tarfile.TarError, lzma.LZMAError, subprocess.SubprocessError) as error:
        print(f"ami-rust production installer: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

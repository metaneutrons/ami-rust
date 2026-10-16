"""Synthetic bounded fixtures for hosted consumer verification.

These tests exercise routing and fail-closed control flow only. They do not
fabricate or claim GH attestation, Cosign, Fulcio, or publisher signatures.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().with_name("ci_verify.py")
SPEC = importlib.util.spec_from_file_location("_test_ci_verify", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load adjacent ci_verify.py fixture target")
ci_verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ci_verify
SPEC.loader.exec_module(ci_verify)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: object) -> bytes:
    raw = ci_verify.canonical_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


class HostedConsumerVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ci-verify-fixture-")
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / "work"
        self.work.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_tracked_tool_pins_route_to_both_supported_hosts(self):
        manifest = ci_verify.strict_json(ci_verify.ROOT / "release/ci-auth-tools.json")
        mac = ci_verify.validate_tool_manifest(manifest, "macos-aarch64")
        linux = ci_verify.validate_tool_manifest(manifest, "linux-x86_64")
        self.assertEqual(mac["gh"]["archive_member"], "gh_2.102.0_macOS_arm64/bin/gh")
        self.assertEqual(linux["gh"]["archive_member"], "gh_2.102.0_linux_amd64/bin/gh")
        self.assertEqual(mac["cosign"]["url"].rsplit("/", 1)[-1], "cosign-darwin-arm64")
        self.assertEqual(linux["cosign"]["url"].rsplit("/", 1)[-1], "cosign-linux-amd64")
        self.assertNotEqual(mac["gh"]["binary_sha256"], linux["gh"]["binary_sha256"])

    def test_tool_manifest_rejects_cross_host_or_root_substitution(self):
        manifest = ci_verify.strict_json(ci_verify.ROOT / "release/ci-auth-tools.json")
        broken = json.loads(json.dumps(manifest))
        broken["hosts"]["macos-aarch64"]["gh"]["archive_member"] = "gh_2.102.0_linux_amd64/bin/gh"
        with self.assertRaisesRegex(ValueError, "archive member"):
            ci_verify.validate_tool_manifest(broken, "macos-aarch64")
        broken = json.loads(json.dumps(manifest))
        broken["roots"]["cosign"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "trust root"):
            ci_verify.validate_tool_manifest(broken, "linux-x86_64")

    def test_linux_gh_extractor_reads_only_the_pinned_regular_member(self):
        payload = b"synthetic-gh-executable"
        pin = {"archive_member": "gh_2.102.0_linux_amd64/bin/gh",
               "binary_bytes": len(payload), "binary_sha256": sha(payload)}
        archive = self.work / "gh.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name in ("gh_2.102.0_linux_amd64/", "gh_2.102.0_linux_amd64/bin/"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            info = tarfile.TarInfo(pin["archive_member"])
            info.size = len(payload)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(payload))
        target = self.work / "tools/gh"
        result = ci_verify._write_archive_member(archive, "linux-x86_64", pin, target)
        self.assertEqual(target.read_bytes(), payload)
        self.assertTrue(target.stat().st_mode & stat.S_IXUSR)
        self.assertEqual(result["sha256"], pin["binary_sha256"])

    def test_macos_gh_extractor_rejects_linked_archive_member(self):
        payload = b"synthetic-gh-executable"
        pin = {"archive_member": "gh_2.102.0_macOS_arm64/bin/gh",
               "binary_bytes": len(payload), "binary_sha256": sha(payload)}
        archive = self.work / "gh.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            info = zipfile.ZipInfo(pin["archive_member"])
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(info, "../outside")
        target = self.work / "tools/gh"
        with self.assertRaisesRegex(ValueError, "link or special"):
            ci_verify._write_archive_member(archive, "macos-aarch64", pin, target)
        self.assertFalse(target.exists())

    def _candidate(self, root: Path) -> Path:
        root.mkdir()
        payloads = {
            "sdk.tar.xz": b"sdk-fixture",
            "SHAUTIL": b"shautil-fixture",
            "install.py": b"fixture installer",
            "install_publisher.py": b"fixture publisher installer",
            "verify_publisher.py": b"fixture verifier",
            "new_project.py": b"fixture project helper",
            "QUICKSTART.md": b"# Fixture\n",
            ".auth/inputs.json": b"{}\n",
            ".auth/authentication.json": b"{}\n",
        }
        manifest = {"version": "0.1.0", "assets": [
            {"path": name, "bytes": len(payloads[name]), "sha256": sha(payloads[name])}
            for name in ("sdk.tar.xz", "SHAUTIL")], "qualification_only": False}
        payloads["release.json"] = ci_verify.canonical_json(manifest)
        for name, raw in payloads.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        return root

    def test_all_five_tamper_probes_fail_before_any_install(self):
        bundle = self._candidate(self.root / "candidate")
        policy = write_json(self.work / "trust/policy.json", {"source_sha": "a" * 40})
        install_prefix = self.work / "consumers/absolute-a/sdk-0.1.0"
        calls = []

        def synthetic_verifier(candidate, policy_path, label):
            calls.append(label)
            sdk = candidate / "sdk.tar.xz"
            shautil = candidate / "SHAUTIL"
            accepted = (sdk.is_file() and shautil.is_file()
                        and sdk.read_bytes() == b"sdk-fixture"
                        and shautil.read_bytes() == b"shautil-fixture"
                        and json.loads((candidate / "release.json").read_text())["version"] == "0.1.0"
                        and json.loads(policy_path.read_text())["source_sha"] == "a" * 40)
            return {"accepted": accepted, "exit_code": 0 if accepted else 2,
                    "stop_reason": None, "stderr_sha256": sha(b"synthetic rejection")}

        rows = ci_verify.run_negative_probes(bundle, self.work / "trust/policy.json", self.work,
                                             install_prefix, synthetic_verifier)
        self.assertEqual([row["case"] for row in rows], [
            "mutated-sdk", "mutated-shautil", "missing-asset", "manifest-mismatch", "wrong-source-policy"])
        self.assertEqual(calls, ["negative-" + row["case"] for row in rows])
        self.assertFalse(install_prefix.exists())
        self.assertTrue(all(row["status"] == "REJECTED_BEFORE_INSTALL" for row in rows))

    def test_negative_probes_refuse_to_start_after_install_exists(self):
        bundle = self._candidate(self.root / "candidate")
        policy = write_json(self.work / "trust/policy.json", {"source_sha": "a" * 40})
        prefix = self.work / "consumers/installed"
        prefix.mkdir(parents=True)
        called = []
        with self.assertRaisesRegex(ValueError, "precede every installation"):
            ci_verify.run_negative_probes(bundle, policy, self.work, prefix,
                                          lambda *args: called.append(args))
        self.assertEqual(called, [])

    def test_signed_quickstart_must_be_the_exact_twelve_command_recipe(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        text = "# Recipe\n\n```sh\n" + "\n".join(ci_verify.EXPECTED_RECIPE) + "\n```\n"
        (bundle / "QUICKSTART.md").write_text(text)
        commands, digest = ci_verify._recipe_commands(bundle)
        self.assertEqual(tuple(commands), ci_verify.EXPECTED_RECIPE)
        self.assertEqual(digest, sha(text.encode()))
        (bundle / "QUICKSTART.md").write_text(text.replace("--offline", "--locked", 1))
        with self.assertRaisesRegex(ValueError, "exact reviewed 12-command"):
            ci_verify._recipe_commands(bundle)

    def test_positive_verifier_report_binds_exact_protected_consumer_assets(self):
        wanted = {"install.py", "install_publisher.py", "verify_publisher.py",
                  "new_project.py", "QUICKSTART.md"}
        trusted_source = self.root / "trusted-source"
        static_rows = []
        source_payloads = {}
        for name in sorted(wanted):
            relative = "fixture-assets/" + name
            raw = ("synthetic trusted source: " + name + "\n").encode()
            source_payloads[name] = raw
            target = trusted_source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            static_rows.append({"path": name, "source": relative, "bytes": len(raw),
                                "sha256": sha(raw)})
        write_json(trusted_source / "release/bundle-files.json",
                   {"schema": "ami-rust-bundle-files-v1", "files": static_rows})
        pins = {row["path"]: row for row in static_rows}
        bundle = self.root / "authenticated-candidate"
        bundle.mkdir()
        asset_rows = []
        for name in sorted(wanted):
            pin = pins[name]
            target = bundle / name
            target.write_bytes(source_payloads[name])
            asset_rows.append({"path": name, "bytes": pin["bytes"], "sha256": pin["sha256"]})
        manifest = {"version": "0.1.0", "assets": asset_rows}
        write_json(bundle / "release.json", manifest)
        manifest_sha = ci_verify.sha256(bundle / "release.json")
        policy = {"workflow_sha": "b" * 40, "source_sha": "a" * 40}
        subjects = sorted(("release.json", "sdk.tar.xz", "SHAUTIL"))
        auth = {"schema": "ami-rust-publisher-verification-v2", "verified": True,
                "repository": "metaneutrons/ami-rust", "workflow": ".github/workflows/sdk-qualify.yml",
                "workflowSha": policy["workflow_sha"], "sourceSha": policy["source_sha"],
                "sourceRef": "refs/heads/main", "manifestSha256": manifest_sha,
                "attestedSubjects": subjects, "cosignSubjects": subjects,
                "manifestBoundAssets": sorted(wanted | set(subjects)),
                "workflowRuns": [{"hostProfile": "linux-x86_64"}]}
        result = {"status": "verified", "release_manifest_sha256": manifest_sha,
                  "version": "0.1.0", "host": "linux-x86_64", "authentication": auth}
        ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
        for host in ci_verify.HOSTS:
            result["host"] = host
            auth["workflowRuns"] = [{"hostProfile": host}]
            ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
            other = next(h for h in ci_verify.HOSTS if h != host)
            auth["workflowRuns"] = [{"hostProfile": other}]
            with self.assertRaisesRegex(ValueError, "authentication report differs"):
                ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
        auth["workflowRuns"] = [{"hostProfile": host} for host in ci_verify.HOSTS]
        with self.assertRaisesRegex(ValueError, "authentication report differs"):
            ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
        auth["workflowRuns"] = [{"hostProfile": result["host"]}]
        (bundle / "new_project.py").write_bytes(b"changed after authentication")
        with self.assertRaisesRegex(ValueError, "differs from protected source pin"):
            ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)

    def test_cargo_extractor_verifies_exact_profile_and_archive_metadata(self):
        files = {"bin/cargo": b"cargo-binary", "producer.json": b'{"schema":"fixture"}\n'}
        profile = {"files": [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
                             for name, raw in sorted(files.items())], "symlinks": []}
        archive = self.work / "cargo.tar.xz"
        with tarfile.open(archive, "w:xz", format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                info.mode = 0o755 if name == "bin/cargo" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 1791936000
                tar.addfile(info, io.BytesIO(raw))
        result = ci_verify._extract_flat_cargo(archive, self.work / "cargo-root", profile)
        self.assertEqual(result["entry_count"], 2)
        self.assertEqual((self.work / "cargo-root/bin/cargo").read_bytes(), files["bin/cargo"])

    def test_cargo_extractor_rejects_noncanonical_permissions(self):
        files = {"bin/cargo": b"cargo-binary", "producer.json": b'{"schema":"fixture"}\n'}
        profile = {"files": [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
                             for name, raw in sorted(files.items())], "symlinks": []}
        archive = self.work / "cargo-noncanonical.tar.xz"
        with tarfile.open(archive, "w:xz", format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                info.mode = 0o700 if name == "bin/cargo" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 1791936000
                tar.addfile(info, io.BytesIO(raw))
        with self.assertRaisesRegex(ValueError, "noncanonical metadata"):
            ci_verify._extract_flat_cargo(archive, self.work / "cargo-rejected", profile)
        self.assertFalse((self.work / "cargo-rejected").exists())


if __name__ == "__main__":
    unittest.main()

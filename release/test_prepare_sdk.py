"""Fixtures for deterministic hosted source-SDK packaging."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

_MODULE_SPEC = importlib.util.spec_from_file_location(
    "prepare_sdk", Path(__file__).resolve().with_name("prepare_sdk.py"))
if _MODULE_SPEC is None or _MODULE_SPEC.loader is None:
    raise RuntimeError("cannot load adjacent prepare_sdk.py fixture target")
prepare_sdk = importlib.util.module_from_spec(_MODULE_SPEC)
sys.modules[_MODULE_SPEC.name] = prepare_sdk
_MODULE_SPEC.loader.exec_module(prepare_sdk)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> bytes:
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


class PrepareSdkTests(unittest.TestCase):
    def test_portable_path_contract(self):
        for name in ("bad\nname", "é.txt", "a" * 241, "a" * 121, "CON.txt", "LPT1", "a.", "a b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                prepare_sdk.safe_path(name)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="prepare-sdk-")
        self.root = Path(self.temp.name)
        self.source = self.root / "public"
        self.source.mkdir()
        self.resources_path = self.source / "release/ci-resources.json"
        self.reports = {}
        self._make_source()
        self._commit_source()
        for host in prepare_sdk.HOSTS:
            report = self.root / f"{host}.json"
            write_json(report, self._report(host))
            self.reports[host] = report

    def tearDown(self):
        self.temp.cleanup()

    def _git(self, *args):
        return subprocess.run(["git", "-C", str(self.source), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def _make_source(self):
        self.source_files = {}
        self.csdk_original_profile_bytes, self.csdk_candidate_profile_bytes = self._make_csdk_profiles()
        paths = [
            "Cargo.lock", "Cargo.toml", "host/build.py", "host/cargo-repro/produce.py",
            "host/cargo-repro/prepare-overlay.py", "host/cargo-repro/source.json",
            "host/cargo-repro/cargo-metadata.patch", "host/cargo-repro/openssl-overlay.json",
            "host/cargo-repro/openssl-paths.patch", "host/profiles/macos-aarch64/cargo.json",
            "host/profiles/linux-x86_64/cargo.json", "host/profiles/macos-aarch64/rust.json",
            "host/profiles/linux-x86_64/rust.json", "host/profiles/macos-aarch64/csdk.json",
            "host/profiles/linux-x86_64/csdk.json", "native/sdk.c", "crates/example/src/lib.rs",
        ]
        paths.extend(f"fixture/payload-{index:02d}.bin" for index in range(71))
        self.assertEqual(len(paths), 88)
        for index, name in enumerate(paths):
            if name.endswith("/csdk.json"):
                data = self.csdk_original_profile_bytes
            elif name.endswith("cargo.json"):
                data = b'{"files":[],"symlinks":[]}\n'
            elif name.endswith("rust.json"):
                host = name.split("/")[2]
                target = prepare_sdk.HOSTS[host]
                paths = ["bin/rustc", "lib/rustlib/install.log", "lib/rustlib/manifest-cargo",
                         "lib/rustlib/manifest-rust-src", "lib/rustlib/manifest-rustc",
                         f"lib/rustlib/manifest-rust-std-{target}"]
                data = prepare_sdk.canonical_json({"files": [
                    {"path": path, "bytes": 7, "sha256": "c" * 64} for path in paths], "symlinks": []})
            else:
                data = f"fixture-{index}:{name}\n".encode()
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.source_files[name] = data
        self.template_files = dict(self.source_files)
        # Model the merged public checkout: these two helper files changed after
        # the source archive template was frozen and are now bound by CI pins.
        for name in ("host/build.py", "host/cargo-repro/produce.py"):
            data = f"# current pinned hosted helper: {name}\n".encode()
            (self.source / name).write_bytes(data)
            self.source_files[name] = data
        (self.source / "release").mkdir(parents=True, exist_ok=True)
        (self.source / "release/ci_cargo.py").write_text("# fixture hosted producer driver\n")
        portable_csdk = self.source / "release/portable-csdk"
        portable_csdk.mkdir(parents=True, exist_ok=True)
        (portable_csdk / "original-profile.json").write_bytes(self.csdk_original_profile_bytes)
        (portable_csdk / "profile.json").write_bytes(self.csdk_candidate_profile_bytes)
        self.csdk_spec = self._make_csdk_spec()
        self.csdk_spec_bytes = write_json(portable_csdk / "spec.json", self.csdk_spec)

        readme = (
            "# ami-rust\n\n"
            "The CI workflow runs isolated installer regression fixtures on Linux and macOS.\n"
            "It does not build or qualify the SDK, run AROS, validate a publisher identity,\n"
            "or create release artifacts. An offline test signature is not a publisher\n"
            "signature. No SDK publication is authorized by this repository workflow.\n"
        )
        (self.source / "README.md").write_text(readme)
        (self.source / "inputs/budgets.json").parent.mkdir(parents=True, exist_ok=True)
        self.sealed_budgets = {"build_rss_bytes": 8 * 1024**3, "jobs": 2,
                               "build_seconds": 1200, "build_workspace_bytes": 12 * 1024**3,
                               "runtime_limit": 100}
        sealed_budget_bytes = write_json(self.source / "inputs/budgets.json", self.sealed_budgets)
        source_record = {"source_commit": "1" * 40, "scope": "old scope",
                         "packaging": {"base_archive_sha256": "a" * 64}}
        write_json(self.source / "contract/source.json", source_record)

        resources = {
            "schema": "ami-rust-hosted-resources-v1",
            "basis": {"old_runtime_budget_sha256": sha(sealed_budget_bytes)},
            "build": {"jobs": 2, "rss_bytes": 4 * 1024**3, "seconds": 1200,
                      "workspace_bytes": 12 * 1024**3, "log_bytes": 16 * 1024**2},
            "host_capacity": {"schema": "ami-rust-host-capacity-v1",
                              "ram_minimum_bytes": 6 * 1024**3,
                              "disk_free_minimum_bytes": 24 * 1024**3},
        }
        resources_bytes = write_json(self.resources_path, resources)
        self.resources = resources
        self.inputs = self._inputs()
        inputs_bytes = write_json(self.source / "release/ci-bootstrap-inputs.json", self.inputs)
        self.inputs_sha = sha(inputs_bytes)
        self.resources_sha = sha(resources_bytes)

        profiles = {}
        for host, target in prepare_sdk.HOSTS.items():
            profiles[host] = {
                "rust_host": target, "collector_binary": "bin/aros-collect",
                "cargo_binary": "bin/cargo", "cargo_metadata_mode": "ami-rust-reproducible-cross-v1",
                "components": {
                    "cargo": {"manifest": f"host/profiles/{host}/cargo.json",
                              "sha256": sha(self.source_files[f"host/profiles/{host}/cargo.json"])},
                    "csdk": {"manifest": f"host/profiles/{host}/csdk.json",
                             "sha256": sha(self.csdk_original_profile_bytes)},
                    "rust": {"manifest": f"host/profiles/{host}/rust.json",
                             "sha256": sha(self.source_files[f"host/profiles/{host}/rust.json"])},
                },
            }
            write_json(self.source / f"contract/{host}-profile.json", profiles[host])
        template = {
            "schema": "ami-rust-sdk-v1", "version": "0.1.0-rc.3-local",
            "source_identity": "1" * 40, "source_date_epoch": prepare_sdk.EPOCH,
            "qualification_only": True, "rust_commit": "2" * 40, "rust_llvm": "23.1.1",
            "driver": "host/build.py",
            "budgets": dict(self.sealed_budgets),
            "profiles": profiles,
            "files": [{"path": name, "bytes": len(data), "sha256": sha(data)}
                      for name, data in sorted(self.template_files.items())],
        }
        write_json(self.source / "contract/sdk.json", template)

    def _make_csdk_profiles(self):
        original = []
        candidate = []
        for index in range(530):
            name = f"include/fixture/header-{index:04d}.h"
            original_data = f"original header {index}\n".encode()
            candidate_data = f"candidate header {index}\n".encode()
            original.append({"path": name, "bytes": len(original_data), "sha256": sha(original_data)})
            candidate.append({"path": name, "bytes": len(candidate_data), "sha256": sha(candidate_data)})
        for index in range(2303):
            name = f"share/fixture/payload-{index:04d}.bin"
            data = f"unchanged payload {index}\n".encode()
            row = {"path": name, "bytes": len(data), "sha256": sha(data)}
            original.append(row)
            candidate.append(dict(row))
        for name in ("lib/libdrm_nouveau.a", "lib/pkgconfig/aom.pc"):
            old = f"old {name}\n".encode()
            new = f"portable {name}\n".encode()
            original.append({"path": name, "bytes": len(old), "sha256": sha(old)})
            candidate.append({"path": name, "bytes": len(new), "sha256": sha(new)})
        original.sort(key=lambda row: row["path"])
        candidate.sort(key=lambda row: row["path"])
        return (prepare_sdk.canonical_json({"files": original, "symlinks": []}),
                prepare_sdk.canonical_json({"files": candidate, "symlinks": []}))

    def _make_csdk_spec(self):
        original_sha = sha(self.csdk_original_profile_bytes)
        candidate_sha = sha(self.csdk_candidate_profile_bytes)
        return {
            "schema": "ami-rust-portable-csdk-v1",
            "status": "PINNED_CANDIDATE_TWO_HOST_QUALIFICATION_REQUIRED",
            "original": {
                "profile": {"path": "release/portable-csdk/original-profile.json",
                            "bytes": len(self.csdk_original_profile_bytes), "sha256": original_sha},
                "archive": {"path": "release/inputs/csdk.tar.xz", "bytes": 100,
                            "sha256": sha(b"fixture original archive")},
            },
            "candidate": {
                "profile": {"path": "release/portable-csdk/profile.json",
                            "bytes": len(self.csdk_candidate_profile_bytes), "sha256": candidate_sha},
                "archive": {"path": "release/inputs/portable-csdk.tar.xz",
                            "name": "csdk-component.tar.xz", "bytes": 200,
                            "sha256": sha(b"fixture candidate archive")},
            },
            "nouveau": {
                "archive_path": "lib/libdrm_nouveau.a", "derived_bytes": 20,
                "derived_sha256": sha(b"derived nouveau"),
                "historical_source_prefix": "/fixture/historical/source",
                "objects": 2, "original_bytes": 20,
                "original_sha256": sha(b"original nouveau"),
                "path_changed_members": 1, "symbols": 4, "unchanged_members": 1,
            },
            "patch_series": {"path": "release/patches/portable-csdk/series.json", "bytes": 300,
                             "sha256": sha(b"fixture patch series")},
            "required_counts": dict(prepare_sdk.PORTABLE_CSDK_REQUIRED_COUNTS),
            "source_capsule": {"path": "release/csdk-source/source.tar.xz", "bytes": 400,
                               "sha256": sha(b"fixture source capsule")},
            "source_manifest": {"path": "release/csdk-source/manifest.json", "bytes": 500,
                                "sha256": sha(b"fixture source manifest")},
            "toolchains": {
                host: {
                    "compiler": {"bytes": 10, "path": "bin/clang-11",
                                 "sha256": sha(f"{host} compiler".encode())},
                    "profile": {"bytes": 20,
                                "path": f"host/profiles/{host}/toolchain.json",
                                "sha256": sha(f"{host} profile".encode())},
                }
                for host in prepare_sdk.HOSTS
            },
        }

    def _inputs(self):
        targets = [
            {"path": "src/compiler/build_runner/compilation_files.rs",
             "upstream_sha256": "3" * 64, "patched_sha256": "4" * 64},
            {"path": "src/workspace/features.rs",
             "upstream_sha256": "5" * 64, "patched_sha256": "6" * 64},
        ]
        rust = {"release": "1.98.1", "commit": prepare_sdk.PINNED_RUST_COMMIT,
                "cargo_commit": "7" * 40,
                "manifest": {"url": "https://static.rust-lang.org/dist/channel-rust-1.98.1.toml",
                             "sha256": "8" * 64, "bytes": 1000}}
        rust["components"] = {}
        for target in prepare_sdk.HOSTS.values():
            components = {}
            total = 0
            for name in ("rustc", "rust-std", "cargo"):
                size = {"rustc": 101, "rust-std": 102, "cargo": 103}[name]
                components[name] = {
                    "url": f"https://static.rust-lang.org/dist/2026-09-03/{name}-1.98.1-{target}.tar.xz",
                    "http_content_length": size, "sha256": sha(f"{name}-{target}".encode()),
                }
                total += size
            components["total_archive_bytes"] = total
            rust["components"][target] = components
        return {
            "schema": "ami-rust-ci-cargo-inputs-v1",
            "rust": rust,
            "python": {host: {"sha256": sha(host.encode())} for host in prepare_sdk.HOSTS},
            "custom_cargo": {
                "upstream": "https://github.com/rust-lang/cargo.git",
                "commit": prepare_sdk.PINNED_CARGO_COMMIT,
                "cargo_lock": {"sha256": "9" * 64, "bytes": 10},
                "patch_path": "host/cargo-repro/cargo-metadata.patch",
                "patch_sha256": prepare_sdk.PINNED_CARGO_PATCH,
                "patch_targets": targets,
            },
            "openssl_overlay": {
                "recipe_sha256": "a" * 64, "patch_sha256": "b" * 64,
                "source_sha256": "c" * 64, "patched_sha256": "d" * 64,
                "exact_changed_paths": ["openssl-src/src/lib.rs", "openssl-src/.cargo-checksum.json"],
            },
            "producer_helpers": {
                "producer_path": "host/cargo-repro/produce.py",
                "producer_sha256": sha(self.source_files["host/cargo-repro/produce.py"]),
                "overlay_helper_sha256": sha(self.source_files["host/cargo-repro/prepare-overlay.py"]),
                "host_supervisor_path": "host/build.py",
                "host_supervisor_sha256": sha(self.source_files["host/build.py"]),
            },
        }

    def _report(self, host):
        target = prepare_sdk.HOSTS[host]
        custom = self.inputs["custom_cargo"]
        rust = self.inputs["rust"]
        target_rows = [{"path": row["path"], "upstream_sha256": row["upstream_sha256"],
                        "patched_sha256": row["patched_sha256"]} for row in custom["patch_targets"]]
        archives = []
        for row in prepare_sdk._archive_pins(self.inputs, target):
            archives.append({**row, "relative_file": f"rust-archives/{row['component']}.tar.xz",
                             "archive_member_count": 10, "expanded_bytes": 1000})
        helper_actual = {
            "produce.py": self.inputs["producer_helpers"]["producer_sha256"],
            "prepare-overlay.py": self.inputs["producer_helpers"]["overlay_helper_sha256"],
            "build.py": self.inputs["producer_helpers"]["host_supervisor_sha256"],
            "ci_cargo.py": sha((self.source / "release/ci_cargo.py").read_bytes()),
        }
        version = ("cargo 1.98.1 (fixture 2026-09-03)\nrelease: 1.98.1\n"
                   f"commit-hash: {custom['commit']}\nhost: {target}")
        return {
            "schema": "ami-rust-hosted-custom-cargo-producer-v1",
            "status": "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION",
            "host": host, "rust_target": target, "build_profile": "release",
            "budgets": self.resources["build"],
            "capacity_preflight": {
                key: {"physical_ram_bytes": 8 * 1024**3, "free_disk_bytes": 30 * 1024**3,
                      "ram_minimum_bytes": 6 * 1024**3,
                      "disk_free_minimum_bytes": 24 * 1024**3}
                for key in ("work", "output")
            },
            "input_materials": {
                "inputs_sha256": self.inputs_sha,
                "resource_policy_sha256": self.resources_sha,
                "rust_release": rust["release"], "rust_commit": rust["commit"],
                "bootstrap_cargo_commit": rust["cargo_commit"],
                "rust_channel_manifest": rust["manifest"],
                "rust_archives": archives,
                "python": {"sha256": self.inputs["python"][host]["sha256"],
                           "pinned_sha256": self.inputs["python"][host]["sha256"]},
                "cargo_upstream": {
                    "upstream": custom["upstream"], "commit": custom["commit"],
                    "cargo_lock_sha256": custom["cargo_lock"]["sha256"],
                    "patch_sha256": custom["patch_sha256"], "patch_targets": target_rows,
                },
                "cargo_patch": {"path": custom["patch_path"], "sha256": custom["patch_sha256"],
                                "targets": target_rows},
                "openssl_overlay_recipe_sha256": self.inputs["openssl_overlay"]["recipe_sha256"],
                "openssl_overlay_patch_sha256": self.inputs["openssl_overlay"]["patch_sha256"],
                "producer_helpers": {"ci_input_pins": self.inputs["producer_helpers"],
                                     "actual_sha256": helper_actual,
                                     "driver_sha256": helper_actual["ci_cargo.py"]},
            },
            "vendor": {"overlay_identity": {
                "overlay_pin_sha256": self.inputs["openssl_overlay"]["recipe_sha256"],
                "patch_sha256": self.inputs["openssl_overlay"]["patch_sha256"],
                "changed_files": sorted(self.inputs["openssl_overlay"]["exact_changed_paths"]),
                "original_vendor_recheck": "PASS",
            }},
            "custom_cargo_artifact": {"relative_path": "build-work/target/release/cargo",
                                      "bytes": 4096, "sha256": sha(host.encode()), "version": version},
            "peaks": {
                "rss_observed_bytes": 2 * 1024**3,
                "work_plus_output_observed_bytes": 6 * 1024**3,
                "checkout_initial_bytes": 1024,
                "elapsed_seconds": 180,
                "commands": [
                    {"label": "cargo-vendor", "exit_code": 0, "stop_reason": None,
                     "elapsed_seconds": 30, "rss_peak_observed_bytes": 1024,
                     "managed_peak_observed_bytes": 4096,
                     "stdout_log": "logs/vendor.out", "stderr_log": "logs/vendor.err"},
                    {"label": "cargo-vendor-overlay", "exit_code": 0, "stop_reason": None,
                     "elapsed_seconds": 10, "rss_peak_observed_bytes": 1024,
                     "managed_peak_observed_bytes": 4096,
                     "stdout_log": "logs/overlay.out", "stderr_log": "logs/overlay.err"},
                    {"label": "cargo-build", "exit_code": 0, "stop_reason": None,
                     "elapsed_seconds": 90, "rss_peak_observed_bytes": 2048,
                     "managed_peak_observed_bytes": 8192,
                     "stdout_log": "logs/build.out", "stderr_log": "logs/build.err"},
                ],
            },
            "relative_files": [{"path": "/private/tmp/fixture"}],
        }

    def _commit_source(self):
        subprocess.run(["git", "-C", str(self.source), "init", "-q"], check=True)
        self._git("config", "user.name", "Fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        subprocess.run(["git", "-C", str(self.source), "remote", "add", "origin",
                        "https://github.com/metaneutrons/ami-rust.git"], check=True)
        subprocess.run(["git", "-C", str(self.source), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)

    def _prepare(self, suffix):
        output = self.root / suffix
        result = prepare_sdk.prepare(self.source, output, self.resources_path, self.reports)
        return result, output / result["archive"]

    def _commit_fixture_changes(self, message):
        self._git("add", "-A")
        self._git("commit", "-m", message)

    def _install_candidate_profile(self, profile, message):
        candidate_bytes = prepare_sdk.canonical_json(profile)
        candidate_path = self.source / prepare_sdk.PORTABLE_CSDK_CANDIDATE_PROFILE
        candidate_path.write_bytes(candidate_bytes)
        spec_path = self.source / prepare_sdk.PORTABLE_CSDK_SPEC
        spec = json.loads(spec_path.read_bytes())
        spec["candidate"]["profile"]["bytes"] = len(candidate_bytes)
        spec["candidate"]["profile"]["sha256"] = sha(candidate_bytes)
        write_json(spec_path, spec)
        self._commit_fixture_changes(message)

    def test_production_candidate_removes_only_path_dependent_installer_records(self):
        result = prepare_sdk.prepare(self.source, self.root / "production", self.resources_path,
                                     self.reports, production_candidate=True)
        self.assertFalse(result["qualification_only"])
        with tarfile.open(self.root / "production" / result["archive"], "r:xz") as tar:
            manifest = json.load(tar.extractfile("contract/sdk.json"))
            self.assertEqual(manifest["version"], "0.1.0")
            self.assertFalse(manifest["qualification_only"])
            self.assertIn("not an R1 acceptance", manifest["packaging"]["release_acceptance"])
            portable_csdk = manifest["packaging"]["portable_csdk"]
            self.assertEqual(portable_csdk["spec_path"], prepare_sdk.PORTABLE_CSDK_SPEC)
            self.assertEqual(portable_csdk["spec_bytes"], len(self.csdk_spec_bytes))
            self.assertEqual(portable_csdk["spec_sha256"], sha(self.csdk_spec_bytes))
            distribution_spec = copy.deepcopy(self.csdk_spec)
            distribution_spec["nouveau"].pop("historical_source_prefix")
            self.assertEqual(portable_csdk["distribution_spec"], distribution_spec)
            self.assertNotIn("historical_source_prefix", portable_csdk["distribution_spec"]["nouveau"])
            self.assertNotIn("/fixture/historical/source", json.dumps(manifest, sort_keys=True))
            self.assertEqual(portable_csdk["candidate_archive"], self.csdk_spec["candidate"]["archive"])
            self.assertEqual(portable_csdk["distribution_spec"]["status"],
                             "PINNED_CANDIDATE_TWO_HOST_QUALIFICATION_REQUIRED")
            self.assertEqual(portable_csdk["changed_profile_rows"], 532)
            self.assertEqual(len(manifest["files"]), 93)
            self.assertEqual(len(tar.getmembers()), 94)
            for host in prepare_sdk.HOSTS:
                name = f"host/profiles/{host}/rust.json"
                profile_bytes = tar.extractfile(name).read()
                profile = json.loads(profile_bytes)
                self.assertEqual(profile["files"], [
                    {"path": "bin/rustc", "bytes": 7, "sha256": "c" * 64}])
                self.assertEqual(manifest["profiles"][host]["components"]["rust"]["sha256"],
                                 sha(profile_bytes))
                self.assertEqual(len(manifest["packaging"]["rust_provisioning"]
                                     ["omitted_installer_administrative_files"][host]), 5)
                csdk_name = f"host/profiles/{host}/csdk.json"
                csdk_bytes = tar.extractfile(csdk_name).read()
                self.assertEqual(csdk_bytes, self.csdk_candidate_profile_bytes)
                self.assertEqual(manifest["profiles"][host]["components"]["csdk"]["manifest"],
                                 csdk_name)
                self.assertEqual(manifest["profiles"][host]["components"]["csdk"]["sha256"],
                                 sha(self.csdk_candidate_profile_bytes))

    def test_counterfeit_portable_csdk_candidate_pin_is_rejected(self):
        spec_path = self.source / prepare_sdk.PORTABLE_CSDK_SPEC
        spec = json.loads(spec_path.read_bytes())
        spec["candidate"]["profile"]["sha256"] = "0" * 64
        write_json(spec_path, spec)
        self._commit_fixture_changes("counterfeit candidate profile pin")
        with self.assertRaisesRegex(ValueError, "candidate profile differs from its exact normative pin"):
            prepare_sdk.prepare(self.source, self.root / "bad-candidate-pin", self.resources_path,
                                self.reports, production_candidate=True)

    def test_portable_csdk_original_must_match_both_frozen_template_profiles(self):
        original_path = self.source / prepare_sdk.PORTABLE_CSDK_ORIGINAL_PROFILE
        changed_original = self.csdk_original_profile_bytes + b"\n"
        original_path.write_bytes(changed_original)
        spec_path = self.source / prepare_sdk.PORTABLE_CSDK_SPEC
        spec = json.loads(spec_path.read_bytes())
        spec["original"]["profile"]["bytes"] = len(changed_original)
        spec["original"]["profile"]["sha256"] = sha(changed_original)
        write_json(spec_path, spec)
        self._commit_fixture_changes("change original profile fixture")
        with self.assertRaisesRegex(ValueError, "does not match the frozen template profile"):
            prepare_sdk.prepare(self.source, self.root / "bad-original-profile", self.resources_path,
                                self.reports, production_candidate=True)

    def test_portable_csdk_rejects_malformed_candidate_profile_inventories(self):
        baseline = json.loads(self.csdk_candidate_profile_bytes)
        extra = json.loads(self.csdk_candidate_profile_bytes)
        extra["files"].append({"path": "share/fixture/extra.bin", "bytes": 1,
                               "sha256": sha(b"extra")})
        removed = json.loads(self.csdk_candidate_profile_bytes)
        removed["files"].pop()
        duplicate = json.loads(self.csdk_candidate_profile_bytes)
        duplicate["files"][-1]["path"] = duplicate["files"][0]["path"]
        bad_hash = json.loads(self.csdk_candidate_profile_bytes)
        bad_hash["files"][0]["sha256"] = "not-a-sha256"
        linked = json.loads(self.csdk_candidate_profile_bytes)
        linked["symlinks"] = ["share/fixture/link"]
        cases = (
            ("extra", extra, "wrong regular-file count"),
            ("removed", removed, "wrong regular-file count"),
            ("duplicate", duplicate, "duplicate paths"),
            ("bad-hash", bad_hash, "SHA-256 pin is malformed"),
            ("symlink", linked, "must contain files and no symlinks"),
        )
        for label, profile, error in cases:
            with self.subTest(case=label):
                self._install_candidate_profile(profile, f"malformed candidate profile {label}")
                with self.assertRaisesRegex(ValueError, error):
                    prepare_sdk.prepare(self.source, self.root / f"bad-profile-{label}",
                                        self.resources_path, self.reports,
                                        production_candidate=True)

    def test_portable_rust_profile_refuses_missing_or_duplicate_admin_records(self):
        host = "macos-aarch64"
        original = json.loads(self.source_files[f"host/profiles/{host}/rust.json"])
        original["files"].pop()
        with self.assertRaisesRegex(ValueError, "reviewed five"):
            prepare_sdk.portable_rust_profile(prepare_sdk.canonical_json(original), host)
        original["files"].append(original["files"][0])
        with self.assertRaisesRegex(ValueError, "duplicated"):
            prepare_sdk.portable_rust_profile(prepare_sdk.canonical_json(original), host)

    def test_deterministic_complete_94_member_archive_and_metadata_only_cargo(self):
        first, archive1 = self._prepare("out-one")
        second, archive2 = self._prepare("out-two")
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        self.assertEqual(archive1.read_bytes(), archive2.read_bytes())
        self.assertEqual(first["member_count"], 94)
        with tarfile.open(archive1, "r:xz") as tar:
            names = {item.name for item in tar.getmembers()}
            self.assertEqual(len(names), 94)
            self.assertTrue(prepare_sdk.REQUIRED_EXTRAS <= names)
            self.assertIn("contract/sdk.json", names)
            self.assertNotIn("bin/cargo", names)
            manifest = json.load(tar.extractfile("contract/sdk.json"))
            self.assertEqual(manifest["version"], "0.1.0-rc.4-hosted")
            self.assertTrue(manifest["qualification_only"])
            self.assertFalse(manifest["hosted_cargo"]["binary_payload_included"])
            self.assertEqual(len(manifest["files"]), 93)
            self.assertNotIn("portable_csdk", manifest.get("packaging", {}))
            packaged = {row["path"]: row for row in manifest["files"]}
            for helper in ("host/build.py", "host/cargo-repro/produce.py"):
                self.assertNotEqual(sha(self.template_files[helper]), sha(self.source_files[helper]))
                self.assertEqual(packaged[helper]["sha256"], sha(self.source_files[helper]))
                self.assertEqual(tar.extractfile(helper).read(), self.source_files[helper])
            for host in prepare_sdk.HOSTS:
                cargo = json.load(tar.extractfile(f"host/profiles/{host}/cargo.json"))
                csdk_name = f"host/profiles/{host}/csdk.json"
                self.assertEqual(tar.extractfile(csdk_name).read(), self.csdk_original_profile_bytes)
                self.assertEqual(manifest["profiles"][host]["components"]["csdk"]["sha256"],
                                 sha(self.csdk_original_profile_bytes))
                self.assertEqual([row["path"] for row in cargo["files"]], ["bin/cargo", "producer.json"])
                spec = cargo["producer_identity_spec"]
                producer_bytes = prepare_sdk.canonical_json(spec["record"])
                self.assertEqual(len(producer_bytes), spec["bytes"])
                self.assertEqual(prepare_sdk.digest(producer_bytes), spec["sha256"])
                self.assertNotIn("peaks", spec["record"])
                self.assertNotIn("relative_files", spec["record"])
                self.assertEqual(cargo["files"][1]["sha256"], spec["sha256"])
                self.assertEqual(manifest["profiles"][host]["components"]["cargo"]["sha256"],
                                 prepare_sdk.digest(tar.extractfile(f"host/profiles/{host}/cargo.json").read()))
            source_record = json.load(tar.extractfile("contract/source.json"))
            self.assertEqual(source_record["source_commit"], first["source_commit"])
            self.assertIn("packaging", source_record["previous_template"])
            self.assertEqual(tar.extractfile("inputs/budgets.json").read(),
                             (self.source / "inputs/budgets.json").read_bytes())

    def test_committed_source_byte_change_outside_inventory_is_rejected(self):
        path = self.source / "native/sdk.c"
        path.write_bytes(path.read_bytes() + b"altered\n")
        subprocess.run(["git", "-C", str(self.source), "add", "native/sdk.c"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "altered"], check=True)
        with self.assertRaisesRegex(ValueError, "differs from the pinned template inventory"):
            self._prepare("bad-source")

    def test_malformed_host_receipt_is_rejected(self):
        report_path = self.reports["linux-x86_64"]
        report = json.loads(report_path.read_text())
        report["rust_target"] = "aarch64-apple-darwin"
        write_json(report_path, report)
        with self.assertRaisesRegex(ValueError, "unsuccessful or for the wrong host/profile"):
            self._prepare("bad-receipt")

    def test_malformed_duplicate_profile_is_rejected(self):
        path = self.source / "contract/macos-aarch64-profile.json"
        path.write_text("{\"broken\":true}\n")
        subprocess.run(["git", "-C", str(self.source), "add", str(path)], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "profile"], check=True)
        with self.assertRaisesRegex(ValueError, "profile does not agree"):
            self._prepare("bad-profile")

    def test_sealed_runtime_budgets_cannot_drift_in_extra_or_template(self):
        budget_path = self.source / "inputs/budgets.json"
        original = budget_path.read_bytes()
        changed = json.loads(original)
        changed["runtime_limit"] += 1
        write_json(budget_path, changed)
        self._git("add", ".")
        self._git("commit", "-m", "test: change runtime budget extra")
        with self.assertRaisesRegex(ValueError, "sealed policy hash"):
            prepare_sdk.prepare(self.source, self.root / "bad-extra", self.resources_path, self.reports)
        self.assertFalse((self.root / "bad-extra").exists())
        budget_path.write_bytes(original)
        template_path = self.source / "contract/sdk.json"
        template = json.loads(template_path.read_bytes())
        template["budgets"]["runtime_limit"] += 1
        write_json(template_path, template)
        self._git("add", ".")
        self._git("commit", "-m", "test: change template runtime budget")
        with self.assertRaisesRegex(ValueError, "template runtime budgets"):
            prepare_sdk.prepare(self.source, self.root / "bad-template", self.resources_path, self.reports)
        self.assertFalse((self.root / "bad-template").exists())

    def test_helper_change_without_updated_normative_pin_is_rejected(self):
        path = self.source / "host/build.py"
        path.write_text("# unpinned helper change\n")
        subprocess.run(["git", "-C", str(self.source), "add", "host/build.py"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "unpinned helper"], check=True)
        with self.assertRaisesRegex(ValueError, "host/build.py differs from its normative producer pin"):
            self._prepare("bad-helper-pin")

    def test_success_receipt_cannot_hide_overbudget_or_failed_command(self):
        report_path = self.reports["macos-aarch64"]
        report = json.loads(report_path.read_text())
        report["peaks"]["rss_observed_bytes"] = 4 * 1024**3 + 1
        write_json(report_path, report)
        with self.assertRaisesRegex(ValueError, "exceeded its hosted RSS or workspace ceiling"):
            self._prepare("over-rss")

        report = self._report("macos-aarch64")
        report["peaks"]["commands"][0]["exit_code"] = 1
        write_json(report_path, report)
        with self.assertRaisesRegex(ValueError, "did not complete cleanly"):
            self._prepare("failed-command")

        report = self._report("macos-aarch64")
        report["peaks"]["elapsed_seconds"] = float("nan")
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "non-finite JSON number"):
            self._prepare("nonfinite-receipt")


if __name__ == "__main__":
    unittest.main()

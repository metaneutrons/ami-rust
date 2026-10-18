#!/usr/bin/env python3
"""Bounded tests for the package-manager lifecycle campaign."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ami_rust_package_lifecycle_tests", HERE / "lifecycle.py")
assert SPEC is not None and SPEC.loader is not None
lifecycle = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = lifecycle
SPEC.loader.exec_module(lifecycle)


def control_tar(control: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=1) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("control")
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 1
            info.size = len(control)
            archive.addfile(info, io.BytesIO(control))
    return output.getvalue()


def ar_member(name: str, data: bytes) -> bytes:
    encoded = (name + "/").encode("ascii")
    header = (encoded.ljust(16, b" ") + b"0".ljust(12, b" ") + b"0".ljust(6, b" ")
              + b"0".ljust(6, b" ") + b"100644".ljust(8, b" ")
              + str(len(data)).encode().ljust(10, b" ") + b"`\n")
    return header + data + (b"\n" if len(data) % 2 else b"")


def digest_row(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {"path": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def package_fixture(directory: Path) -> dict:
    """Build the exact seven-file output contract with tiny synthetic payloads."""
    directory.mkdir(parents=True)
    pins = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
    sdk = pins["sdk_version"]
    package_version = pins["package_version"]
    revision = pins["packaging_revision"]
    tag = pins["packaging_tag"]
    archive_name = f"ami-rust-{sdk}-packaging.{revision}.tar.xz"
    deb_name = f"ami-rust_{package_version}_amd64.deb"
    archive_raw = b"tiny immutable release archive fixture\n"
    data_raw = b"tiny immutable Debian data payload\n"
    control = (f"Package: ami-rust\nVersion: {package_version}\nArchitecture: amd64\n"
               "Maintainer: fixture\nDescription: fixture\n").encode("utf-8")
    deb_raw = (b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
               + ar_member("control.tar.gz", control_tar(control))
               + ar_member("data.tar.xz", data_raw))
    (directory / archive_name).write_bytes(archive_raw)
    (directory / deb_name).write_bytes(deb_raw)
    archive_sha = hashlib.sha256(archive_raw).hexdigest()
    deb_sha = hashlib.sha256(deb_raw).hexdigest()
    public_url = (f"https://github.com/{pins['repository']}/releases/download/"
                  f"{lifecycle.quote(tag, safe='')}/{lifecycle.quote(archive_name, safe='')}")
    formula_raw = ("require \"json\"\n\nclass AmiRust < Formula\n"
                   f"  url \"{public_url}\"\n  version \"{sdk}\"\n"
                   f"  sha256 \"{archive_sha}\"\n  revision {revision}\nend\n").encode()
    (directory / "ami-rust.rb").write_bytes(formula_raw)
    archive_sbom = b"archive sbom fixture\n"
    deb_sbom = b"debian sbom fixture\n"
    (directory / (archive_name + ".spdx.json")).write_bytes(archive_sbom)
    (directory / (deb_name + ".spdx.json")).write_bytes(deb_sbom)
    build_report = {
        "schema": "ami-rust-packaging-report-v1", "sdk_version": sdk,
        "package_version": package_version, "packaging_tag": tag, "epoch": 0,
        "outputs": {archive_name: {"bytes": len(archive_raw), "sha256": archive_sha},
                    deb_name: {"bytes": len(deb_raw), "sha256": deb_sha}},
    }
    (directory / "packaging-report.json").write_text(json.dumps(build_report) + "\n", encoding="utf-8")
    generated = {name: digest_row(directory / name) for name in
                 ("ami-rust.rb", archive_name + ".spdx.json", deb_name + ".spdx.json")}
    metadata_report = {
        "schema": "ami-rust-packaging-metadata-report-v1",
        "sdk": {"version": sdk, "package_version": package_version,
                "packaging_revision": revision, "packaging_tag": tag},
        "generated_files": generated,
        "payloads": {
            archive_name: {"bytes": len(archive_raw), "sha256": archive_sha,
                           "spdx": {"path": archive_name + ".spdx.json",
                                    "bytes": len(archive_sbom),
                                    "sha256": hashlib.sha256(archive_sbom).hexdigest()}},
            deb_name: {"bytes": len(deb_raw), "sha256": deb_sha,
                       "spdx": {"path": deb_name + ".spdx.json",
                                "bytes": len(deb_sbom),
                                "sha256": hashlib.sha256(deb_sbom).hexdigest()}},
        },
    }
    (directory / "metadata-report.json").write_text(json.dumps(metadata_report) + "\n", encoding="utf-8")
    return pins


class FakeRunner:
    def __init__(self, root: Path, profile: str, *, fail_label: str | None = None,
                 installed: str | None = None):
        self.root = root
        self.profile = profile
        self.fail_label = fail_label
        self.installed = installed
        self.calls: list[tuple[str, list[str], float]] = []
        self.tap_root = root / "fake-homebrew-tap"
        self.tap_created = False
        self.tap_removed = False
        self.tap_name: str | None = None
        self.final_formula_seen_during_upgrade: bytes | None = None

    def run(self, label, argv, *, timeout, cwd=None):
        argv = [str(item) for item in argv]
        self.calls.append((label, argv, timeout))
        if timeout <= 0:
            raise AssertionError("runner received an expired shared budget")
        if label == self.fail_label:
            return lifecycle.CommandResult(37, b"", b"injected command failure")
        if label == "brew-prefix":
            prefix = self.root / "fake-brew-prefix"
            (prefix / "bin").mkdir(parents=True, exist_ok=True)
            return lifecycle.CommandResult(0, str(prefix).encode() + b"\n")
        if label == "brew-tap-list":
            return lifecycle.CommandResult(0, b"")
        if label == "brew-tap-list-cleanup":
            return lifecycle.CommandResult(0, ((self.tap_name or "") + "\n").encode())
        if label == "brew-tap-new":
            self.tap_name = argv[-1]
            (self.tap_root / "Formula").mkdir(parents=True, exist_ok=True)
            self.tap_created = True
            return lifecycle.CommandResult(0)
        if label == "brew-tap-repository":
            return lifecycle.CommandResult(0, str(self.tap_root).encode() + b"\n")
        if argv[:2] == ["dpkg-query", "-W"] or argv[:3] == ["brew", "list", "--versions"]:
            if self.installed is None:
                return lifecycle.CommandResult(1)
            if self.profile == "ubuntu-24.04-x86_64":
                return lifecycle.CommandResult(0, f"installed\t{self.installed}\n".encode())
            return lifecycle.CommandResult(0, f"ami-rust {self.installed}\n".encode())
        if label.startswith("install-") or label == "reinstall-final":
            if self.profile == "ubuntu-24.04-x86_64":
                filename = Path(argv[-1]).name
                self.installed = filename.removeprefix("ami-rust_").removesuffix("_amd64.deb")
            else:
                self.installed = self._formula_version()
            return lifecycle.CommandResult(0)
        if label == "upgrade-to-final":
            if self.profile == "ubuntu-24.04-x86_64":
                filename = Path(argv[-1]).name
                self.installed = filename.removeprefix("ami-rust_").removesuffix("_amd64.deb")
            else:
                self.installed = self._formula_version()
            return lifecycle.CommandResult(0)
        if label.startswith("uninstall-") or label == "cleanup-owned-package":
            self.installed = None
            return lifecycle.CommandResult(0)
        if label == "brew-untap-owned":
            self.tap_removed = True
            return lifecycle.CommandResult(0)
        if label == "qualify-exercise":
            root_index = argv.index("--root") + 1
            qualification_root = Path(argv[root_index])
            state_root = qualification_root / "user-home/ami-rust-0.1.0-state"
            state = state_root / "retained/bin/ami-rust"
            state.parent.mkdir(parents=True, exist_ok=True)
            state_root.chmod(0o700)
            state.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            state.chmod(0o700)
            pins = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
            ready = {"status": "READY", "sdk_version": pins["sdk_version"],
                     "source_commit": pins["source_commit"], "host": pins["hosts"][
                         "apt" if self.profile == "ubuntu-24.04-x86_64" else "homebrew"]}
            (state_root / "ready.json").write_text(json.dumps(ready), encoding="utf-8")
            (qualification_root / "persistent.json").write_text(json.dumps({"state": str(state_root)}),
                                                                 encoding="utf-8")
            return lifecycle.CommandResult(0)
        return lifecycle.CommandResult(0)

    def _formula_version(self) -> str:
        formula_path = self.tap_root / "Formula/ami-rust.rb"
        raw = formula_path.read_text(encoding="utf-8")
        if self.installed == "0.1.0":
            self.final_formula_seen_during_upgrade = formula_path.read_bytes()
        version = re.search(r'^  version "([^\"]+)"$', raw, re.M).group(1)
        revision = re.search(r"^  revision ([0-9]+)$", raw, re.M)
        suffix = int(revision.group(1)) if revision else 0
        return version + (f"_{suffix}" if suffix else "")


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.packages = self.root / "packages"
        self.pins = package_fixture(self.packages)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_supported_profiles_are_explicit_and_unsupported_profiles_refuse(self) -> None:
        self.assertEqual(lifecycle.detect_host("Darwin", "arm64", "26.0.0"), "macos-26-arm64")
        self.assertEqual(lifecycle.detect_host("Linux", "x86_64", os_release={"ID": "ubuntu", "VERSION_ID": "24.04"}),
                         "ubuntu-24.04-x86_64")
        for system, machine, version, release in (
                ("Darwin", "x86_64", "26.0.0", None),
                ("Darwin", "arm64", "25.0.0", None),
                ("Linux", "x86_64", None, {"ID": "ubuntu", "VERSION_ID": "22.04"}),
                ("Linux", "aarch64", None, {"ID": "ubuntu", "VERSION_ID": "24.04"}),
                ("Linux", "x86_64", None, {"ID": "debian", "VERSION_ID": "12"})):
            with self.subTest(system=system, machine=machine, release=release):
                with self.assertRaises(lifecycle.LifecycleError):
                    lifecycle.detect_host(system, machine, version, release)

    def test_exact_output_contract_rejects_extra_files_and_symlinks(self) -> None:
        package = lifecycle.load_package_set(self.packages)
        self.assertEqual(set(package.files), {path.name for path in self.packages.iterdir()})
        extra = self.packages / "unreported.txt"
        extra.write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(lifecycle.LifecycleError, "exact output inventory"):
            lifecycle.load_package_set(self.packages)
        extra.unlink()
        link = self.packages / "linked.txt"
        link.symlink_to(self.packages / "ami-rust.rb")
        with self.assertRaisesRegex(lifecycle.LifecycleError, "regular, non-linked"):
            lifecycle.load_package_set(self.packages)

    def test_lifecycle_root_cannot_overlap_immutable_package_output(self) -> None:
        runner = FakeRunner(self.root, "ubuntu-24.04-x86_64")
        overlapping = self.packages / "campaign"
        with mock.patch.object(lifecycle.os, "getuid", return_value=self.root.stat().st_uid):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "must be disjoint"):
                lifecycle.Lifecycle(self.packages, overlapping, runner=runner,
                                    host_profile="ubuntu-24.04-x86_64").run()
        self.assertFalse(overlapping.exists())

    def test_debian_fixture_changes_only_version_and_reuses_exact_final_data_payload(self) -> None:
        package = lifecycle.load_package_set(self.packages)
        final_inventory = lifecycle.file_inventory(self.packages)
        fixture = lifecycle.make_debian_upgrade_fixture(package, self.root / "fixture")
        self.assertEqual(fixture["kind"], "local-unsigned-upgrade-fixture")
        self.assertEqual(fixture["version"], f"{self.pins['sdk_version']}-{self.pins['packaging_revision'] - 1}")
        self.assertEqual(fixture["revision"], package.pins["packaging_revision"] - 1)
        fixture_path = Path(str(fixture["path"]))
        members = lifecycle.parse_ar(fixture_path.read_bytes())
        final_members = lifecycle.parse_ar(package.deb.read_bytes())
        self.assertEqual(members["data.tar.xz"], final_members["data.tar.xz"])
        self.assertEqual(fixture["data_sha256"], fixture["final_data_sha256"])
        final_control = lifecycle.deb_control(final_members["control.tar.gz"])
        fixture_control = lifecycle.deb_control(members["control.tar.gz"])
        self.assertEqual(fixture_control.replace(f"Version: {fixture['version']}\n".encode(), f"Version: {package.pins['package_version']}\n".encode(), 1), final_control)
        self.assertEqual(lifecycle.file_inventory(self.packages), final_inventory)

    def test_homebrew_revision_zero_fixture_keeps_url_and_does_not_edit_final_formula(self) -> None:
        package = lifecycle.load_package_set(self.packages)
        final_inventory = lifecycle.file_inventory(self.packages)
        fixture = lifecycle.make_homebrew_upgrade_fixture(package, self.root / "fixture")
        fixture_raw = Path(str(fixture["path"])).read_bytes()
        final_raw = package.formula.read_bytes()
        self.assertEqual(fixture["revision"], 0)
        self.assertNotIn(b"  revision ", fixture_raw)
        self.assertIn(b"url \"https://github.com/metaneutrons/ami-rust/releases/download/", fixture_raw)
        self.assertIn(b"sha256 \"" + hashlib.sha256(package.archive.read_bytes()).hexdigest().encode() + b"\"", fixture_raw)
        self.assertEqual(final_raw.replace(f"  revision {package.pins['packaging_revision']}\n".encode(), b"", 1), fixture_raw)
        self.assertEqual(lifecycle.file_inventory(self.packages), final_inventory)

    def test_ubuntu_lifecycle_uses_campaign_owned_installs_and_retains_user_state(self) -> None:
        runner = FakeRunner(self.root, "ubuntu-24.04-x86_64")
        campaign_root = self.root / "campaign-apt"
        with mock.patch.object(lifecycle.os, "getuid", return_value=self.root.stat().st_uid):
            result = lifecycle.Lifecycle(self.packages, campaign_root, runner=runner,
                                         host_profile="ubuntu-24.04-x86_64", budget_seconds=5400).run()
        labels = [label for label, _argv, _timeout in runner.calls]
        expected_order = ["initial-installed-query", "install-final-initial", "qualify-exercise",
                          "uninstall-current-query", "uninstall-current", "qualify-replay-retained",
                          "reinstall-final", "qualify-replay-current", "install-lower-revision-fixture",
                          "upgrade-to-final", "qualify-replay-upgraded", "cleanup-owned-package"]
        indexes = [labels.index(label) for label in expected_order]
        self.assertEqual(indexes, sorted(indexes))
        apt_install = next(argv for label, argv, _timeout in runner.calls if label == "install-final-initial")
        self.assertEqual(apt_install[:3], ["sudo", "dpkg", "-i"])
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["states_and_evidence_retained"])
        self.assertEqual(result["execution_cutoff_seconds"], 5100)
        self.assertIsNone(runner.installed)
        self.assertEqual(stat.S_IMODE(campaign_root.stat().st_mode), 0o700)
        state = campaign_root / "qualification/user-home/ami-rust-0.1.0-state"
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        retained_replay = next(argv for label, argv, _timeout in runner.calls if label == "qualify-replay-retained")
        self.assertEqual(Path(retained_replay[retained_replay.index("--executable") + 1]),
                         state / "retained/bin/ami-rust")
        self.assertTrue((campaign_root / "qualification/persistent.json").is_file())
        fixture = result["upgrade_fixture"]
        self.assertEqual(fixture["version"], f"{self.pins['sdk_version']}-{self.pins['packaging_revision'] - 1}")
        self.assertEqual(lifecycle.file_inventory(self.packages), result["package_output_inventory"])
        phases = list((campaign_root / "evidence").glob("*.json"))
        self.assertTrue(any(json.loads(path.read_text())["status"] == "PASS" for path in phases))

    def test_homebrew_lifecycle_installs_revision_zero_then_brews_upgrade_to_exact_final_formula(self) -> None:
        runner = FakeRunner(self.root, "macos-26-arm64")
        campaign_root = self.root / "campaign-brew"
        with mock.patch.object(lifecycle.os, "getuid", return_value=self.root.stat().st_uid):
            result = lifecycle.Lifecycle(self.packages, campaign_root, runner=runner,
                                         host_profile="macos-26-arm64", budget_seconds=5400,
                                         tap_suffix="test123").run()
        labels = [label for label, _argv, _timeout in runner.calls]
        self.assertLess(labels.index("install-lower-revision-fixture"), labels.index("upgrade-to-final"))
        upgrade = next(argv for label, argv, _timeout in runner.calls if label == "upgrade-to-final")
        self.assertEqual(upgrade[:2], ["brew", "upgrade"])
        uninstall = next(argv for label, argv, _timeout in runner.calls if label == "uninstall-current")
        self.assertEqual(uninstall, ["brew", "uninstall", "local/ami-rust-lifecycle-test123/ami-rust"])
        self.assertEqual(result["upgrade_fixture"]["revision"], 0)
        self.assertEqual(result["upgrade_fixture"]["version"], "0.1.0")
        self.assertIn("https://github.com/metaneutrons/ami-rust/releases/download/",
                      (runner.tap_root / "Formula/ami-rust.rb").read_text(encoding="utf-8"))
        self.assertTrue(runner.tap_removed)
        self.assertIsNone(runner.installed)
        self.assertTrue(result["temporary_tap_removed"])
        self.assertEqual(runner.final_formula_seen_during_upgrade, (self.packages / "ami-rust.rb").read_bytes())
        self.assertEqual(lifecycle.file_inventory(self.packages), result["package_output_inventory"])

    def test_failure_propagates_and_cleans_only_owned_package_while_evidence_survives(self) -> None:
        runner = FakeRunner(self.root, "ubuntu-24.04-x86_64", fail_label="qualify-replay-retained")
        campaign_root = self.root / "campaign-fail"
        with mock.patch.object(lifecycle.os, "getuid", return_value=self.root.stat().st_uid):
            with self.assertRaisesRegex(lifecycle.CommandFailure, "qualify-replay-retained failed with exit 37"):
                lifecycle.Lifecycle(self.packages, campaign_root, runner=runner,
                                     host_profile="ubuntu-24.04-x86_64").run()
        self.assertIsNone(runner.installed)
        report = json.loads((campaign_root / "evidence/result.json").read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "FAIL")
        self.assertFalse(report["owned_package_may_remain"])
        self.assertTrue((campaign_root / "evidence/replay-retained-after-uninstall.json").is_file())
        self.assertTrue((campaign_root / "qualification").is_dir())
        self.assertEqual(len([label for label, _argv, _timeout in runner.calls if label == "initial-installed-query"]), 1)

    def test_existing_package_is_refused_without_adoption_or_uninstall(self) -> None:
        runner = FakeRunner(self.root, "ubuntu-24.04-x86_64", installed="0.1.0-9")
        campaign_root = self.root / "campaign-collision"
        with mock.patch.object(lifecycle.os, "getuid", return_value=self.root.stat().st_uid):
            with self.assertRaisesRegex(lifecycle.LifecycleError, "already has a dpkg record"):
                lifecycle.Lifecycle(self.packages, campaign_root, runner=runner,
                                     host_profile="ubuntu-24.04-x86_64").run()
        self.assertEqual(runner.installed, "0.1.0-9")
        self.assertFalse(any(label.startswith("uninstall") for label, _argv, _timeout in runner.calls))


if __name__ == "__main__":
    unittest.main()

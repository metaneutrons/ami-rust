#!/usr/bin/env python3
"""Black-box security regressions for the unpublished installer candidate.

Run explicitly with: python3 -I -B release/test_install.py
Fixtures use only a disposable OpenSSH test signer. They do not test or imply
publisher identity, protected Actions provenance, or R1 qualification.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import signal
import time
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve(strict=True).parents[1]
INSTALLER = ROOT / "release" / "install.py"
SSH_KEYGEN = Path("/usr/bin/ssh-keygen")
PUBLISHER = "test-publisher"
VERSION = "0.1.0-rc.3-local"
MAX_SCRATCH_BYTES = 12 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("ascii")


def inventory_row(name: str, data: bytes) -> dict:
    return {"path": name, "bytes": len(data), "sha256": sha256(data)}


def tar_xz(entries) -> bytes:
    """Build a tiny deterministic xz/tar fixture; entries may include bad types."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz", format=tarfile.USTAR_FORMAT) as archive:
        for entry in entries:
            name, kind, value = entry
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.mode = 0o644
            if kind == "file":
                data = value
                info.type = tarfile.REGTYPE
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = value
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = value
                archive.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            else:
                raise AssertionError(f"unknown fixture member kind: {kind}")
    return output.getvalue()


def parse_json_stdout(result: subprocess.CompletedProcess) -> dict:
    """Accept a single JSON object or a JSON object on one output line."""
    candidates = [result.stdout.strip()]
    candidates.extend(reversed([line.strip() for line in result.stdout.splitlines()]))
    for candidate in candidates:
        if candidate:
            try:
                value = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    raise AssertionError(f"installer returned no JSON object: {result.stdout!r}")


def tree_bytes(root: Path) -> int:
    total = 0
    if root.exists():
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
    return total


def snapshot(paths) -> dict:
    result = {}
    for root in paths:
        root = Path(root)
        if not root.exists():
            result[str(root)] = None
            continue
        rows = {}
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                rows[relative] = ("symlink", os.readlink(path))
            elif path.is_file():
                rows[relative] = ("file", path.read_bytes(), path.stat().st_mode & 0o777)
            elif path.is_dir():
                rows[relative] = ("directory", path.stat().st_mode & 0o777)
        result[str(root)] = rows
    return result


class InstallerFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SSH_KEYGEN.is_file() or not os.access(SSH_KEYGEN, os.X_OK):
            raise unittest.SkipTest("fixture requires /usr/bin/ssh-keygen")
        if not INSTALLER.is_file():
            raise AssertionError(f"installer CLI is missing: {INSTALLER}")
        cls.scratch_owner = tempfile.TemporaryDirectory(
            prefix="ami-rust-installer-fixtures-", dir=tempfile.gettempdir())
        cls.scratch = Path(cls.scratch_owner.name).resolve(strict=True)
        cls.private_key = cls.scratch / "disposable-test-ed25519"
        cls.public_key = cls.scratch / "disposable-test-ed25519.pub"
        result = subprocess.run(
            [str(SSH_KEYGEN), "-q", "-t", "ed25519", "-N", "", "-C",
             PUBLISHER, "-f", str(cls.private_key)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
            env={"PATH": os.defpath, "HOME": str(cls.scratch), "LC_ALL": "C", "LANG": "C"},
        )
        if result.returncode != 0:
            cls.scratch_owner.cleanup()
            raise AssertionError(f"could not create disposable fixture signer: {result.stderr!r}")
        if cls.private_key.parent.resolve(strict=True) != cls.scratch:
            raise AssertionError("fixture private key escaped its temporary directory")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "scratch_owner"):
            cls.scratch_owner.cleanup()

    def setUp(self):
        self.case = self.scratch / self._testMethodName
        self.case.mkdir()
        self.bundle = self.case / "bundle"
        self.trust_path = self.case / "trust.json"
        self.home_owner = tempfile.TemporaryDirectory(
            prefix=".ami-rust-install-test-", dir=str(self.case))
        self.home_root = Path(self.home_owner.name).resolve(strict=True)
        # The candidate's versioned prefix is fresh and remains under this
        # private, user-owned counted fixture directory for ownership checks.
        self.prefix = self.home_root / f"sdk-{VERSION}"
        self.receipt_pin = self.home_root / "receipt.sha256"
        self._write_trust(self.trust_path, self.public_key)
        self._write_bundle()

    def tearDown(self):
        scratch_bytes = tree_bytes(self.scratch)
        home_bytes = tree_bytes(self.home_root)
        self.assertLessEqual(scratch_bytes + home_bytes, MAX_SCRATCH_BYTES,
                             "fixture scratch exceeded its 12 MiB bound")
        self.home_owner.cleanup()

    def _write_trust(self, path: Path, public_key: Path):
        public_key = public_key.resolve(strict=True)
        trust = {
            "schema": "ami-rust-offline-trust-v1",
            "publisher": PUBLISHER,
            "public_key": str(public_key),
            "public_key_sha256": sha256(public_key.read_bytes()),
            "verifier": str(SSH_KEYGEN.resolve(strict=True)),
            "verifier_sha256": sha256_file(SSH_KEYGEN.resolve(strict=True)),
        }
        path.write_bytes(json_bytes(trust))
        return path.resolve(strict=True)

    def _sign(self, manifest_path: Path):
        signature = Path(str(manifest_path) + ".sig")
        try:
            signature.unlink()
        except FileNotFoundError:
            pass
        result = subprocess.run(
            [str(SSH_KEYGEN), "-q", "-Y", "sign", "-f", str(self.private_key),
             "-n", "ami-rust-release", str(manifest_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
            env={"PATH": os.defpath, "HOME": str(self.scratch), "LC_ALL": "C", "LANG": "C"},
        )
        if result.returncode != 0 or not signature.is_file():
            raise AssertionError(f"fixture signing failed: {result.stderr!r}")

    def _base_entries(self):
        inner_manifest = json_bytes({
            "schema": "ami-rust-sdk-v1",
            "version": VERSION,
            "qualification_only": True,
            "driver": "host/build.py",
            "files": [inventory_row("fixture/marker.txt", b"harmless SDK marker\n")],
        })
        return [
            ("contract/sdk.json", "file", inner_manifest),
            ("fixture/marker.txt", "file", b"harmless SDK marker\n"),
        ], inner_manifest

    def _write_bundle(self, *, archive_entries=None, sdk_files=None,
                      manifest_changes=None, sdk_manifest_sha256=None,
                      raw_manifest=None, sign=True):
        if self.bundle.exists():
            shutil.rmtree(self.bundle)
        self.bundle.mkdir()
        base_entries, inner_manifest = self._base_entries()
        if archive_entries is None:
            archive_entries = list(base_entries)
        archive_data = tar_xz(archive_entries)
        archive_path = self.bundle / "sdk.tar.xz"
        archive_path.write_bytes(archive_data)
        native = b"\x7fELFoffline integrity fixture\n"
        (self.bundle / "SHAUTIL").write_bytes(native)
        if sdk_files is None:
            sdk_files = [inventory_row(name, data) for name, kind, data in base_entries
                         if kind == "file"]
        if sdk_manifest_sha256 is None:
            sdk_manifest_sha256 = sha256(inner_manifest)
        python_sha = sha256_file(Path(sys.executable).resolve(strict=True))
        manifest = {
            "schema": "ami-rust-release-v1",
            "version": VERSION,
            "qualification_only": True,
            "sdk_archive": "sdk.tar.xz",
            "sdk_manifest_sha256": sdk_manifest_sha256,
            "assets": [inventory_row("sdk.tar.xz", archive_data), inventory_row("SHAUTIL", native)],
            "sdk_files": sdk_files,
            "host_interpreters": {
                "macos-aarch64": {"sha256": python_sha},
                "linux-x86_64": {"sha256": python_sha},
            },
            "producer": {"kind": "local-unpublished-candidate",
                         "release_qualified": False},
        }
        if manifest_changes:
            manifest.update(manifest_changes)
        manifest_path = self.bundle / "release.json"
        if raw_manifest is None:
            raw_manifest = json_bytes(manifest)
        manifest_path.write_bytes(raw_manifest)
        if sign:
            self._sign(manifest_path)
        return manifest, raw_manifest, archive_data

    def _run(self, *arguments, env_updates=None):
        env = {
            "PATH": os.defpath,
            "HOME": str(Path.home().resolve(strict=True)),
            "LC_ALL": "C",
            "LANG": "C",
            "TMPDIR": str(self.scratch),
        }
        if env_updates:
            env.update(env_updates)
        return subprocess.run(
            [sys.executable, "-I", "-B", str(INSTALLER), *map(str, arguments)],
            cwd=str(self.case), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", check=False, timeout=45,
        )

    def _verify(self, bundle=None, trust=None, env_updates=None):
        return self._run("verify", "--bundle", bundle or self.bundle,
                         "--trust", trust or self.trust_path, env_updates=env_updates)

    def _install(self, prefix=None, pin=None, bundle=None, trust=None):
        arguments = ["install", "--bundle", bundle or self.bundle,
                     "--trust", trust or self.trust_path,
                     "--prefix", prefix or self.prefix]
        if pin is not False:
            arguments.extend(["--receipt-pin", pin or self.receipt_pin])
        return self._run(*arguments)

    def _uninstall(self, prefix=None, receipt_sha256=None):
        if receipt_sha256 is None:
            receipt_sha256 = self.receipt_pin.read_text().strip()
        return self._run("uninstall", "--prefix", prefix or self.prefix,
                         "--receipt-sha256", receipt_sha256)

    def _expect_success(self, result, status):
        self.assertEqual(result.returncode, 0,
                         f"expected {status}; stderr={result.stderr!r}; stdout={result.stdout!r}")
        payload = parse_json_stdout(result)
        self.assertEqual(payload.get("status"), status, payload)
        return payload

    def _expect_refusal(self, result):
        self.assertNotEqual(result.returncode, 0,
                            f"expected refusal, got stdout={result.stdout!r}")
        self.assertNotIn("Traceback", result.stderr,
                         f"unexpected uncaught exception: {result.stderr!r}")
        return result.stderr + result.stdout

    def _install_ok(self):
        result = self._install()
        payload = self._expect_success(result, "installed")
        return payload

    def _no_stage(self, prefix=None):
        prefix = prefix or self.prefix
        stages = list(prefix.parent.glob(f".{prefix.name}.stage-*"))
        self.assertEqual(stages, [], f"failed install left staging directories: {stages}")

    def test_valid_signature_verifies_without_installing_and_disclaims_provenance(self):
        result = self._verify()
        payload = self._expect_success(result, "verified")
        self.assertEqual(payload.get("publisher"), PUBLISHER)
        self.assertEqual(payload.get("version"), VERSION)
        self.assertTrue(payload.get("qualification_only"))
        self.assertIn("not verified", payload.get("provenance", ""))
        self.assertFalse(self.prefix.exists())

    def test_install_then_uninstall_removes_only_owned_tree(self):
        sibling = self.home_root / "sibling-sdk"
        shared = self.home_root / "shared-prerequisites"
        project = self.home_root / "project-data"
        for directory in (sibling, shared, project):
            directory.mkdir()
        (sibling / "keep.bin").write_bytes(b"sibling version")
        (shared / "toolchain.bin").write_bytes(b"shared prerequisite")
        (project / "Cargo.toml").write_bytes(b"consumer project")
        before = snapshot((sibling, shared, project))

        payload = self._install_ok()
        self.assertEqual(payload.get("version"), VERSION)
        self.assertTrue(payload.get("qualification_only"))
        self.assertIn("not verified", payload.get("provenance", ""))
        marker = self.prefix / "sdk" / "fixture" / "marker.txt"
        self.assertEqual(marker.read_bytes(), b"harmless SDK marker\n")
        self.assertEqual((self.prefix / "payload" / "sdk.tar.xz").read_bytes(),
                         (self.bundle / "sdk.tar.xz").read_bytes())
        receipt = self.prefix / "install-receipt.json"
        self.assertEqual(self.receipt_pin.read_text().strip(), sha256_file(receipt))
        receipt_json = json.loads(receipt.read_text())
        self.assertEqual(receipt_json["version"], VERSION)

        removed = self._expect_success(self._uninstall(), "uninstalled")
        self.assertEqual(removed.get("receipt_sha256"), self.receipt_pin.read_text().strip())
        self.assertFalse(self.prefix.exists())
        self.assertEqual(snapshot((sibling, shared, project)), before)
        self.assertEqual(self.receipt_pin.read_text().strip(), removed["receipt_sha256"])

    def test_wrong_trusted_public_key_is_rejected(self):
        wrong_private = self.case / "wrong-disposable-key"
        result = subprocess.run(
            [str(SSH_KEYGEN), "-q", "-t", "ed25519", "-N", "", "-C",
             "wrong-test-publisher", "-f", str(wrong_private)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
            env={"PATH": os.defpath, "HOME": str(self.scratch), "LC_ALL": "C", "LANG": "C"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        wrong_trust = self._write_trust(self.case / "wrong-trust.json",
                                        Path(str(wrong_private) + ".pub"))
        message = self._expect_refusal(self._verify(trust=wrong_trust))
        self.assertIn("signature verification failed", message)
        self.assertFalse(self.prefix.exists())

    def test_changed_manifest_without_resigning_is_rejected_before_install(self):
        raw = (self.bundle / "release.json").read_bytes()
        self.assertIn(b"rc.3-local", raw)
        (self.bundle / "release.json").write_bytes(raw.replace(b"rc.3-local", b"rc.4-local"))
        message = self._expect_refusal(self._install())
        self.assertIn("signature verification failed", message)
        self.assertFalse(self.prefix.exists())
        self._no_stage()

    def test_changed_archive_asset_is_rejected_before_extraction(self):
        archive = self.bundle / "sdk.tar.xz"
        data = bytearray(archive.read_bytes())
        data[-1] ^= 0x01
        archive.write_bytes(data)
        message = self._expect_refusal(self._install())
        self.assertIn("asset", message)
        self.assertFalse(self.prefix.exists())
        self._no_stage()

    def test_missing_or_unlisted_bundle_asset_is_rejected(self):
        archive = self.bundle / "sdk.tar.xz"
        original = archive.read_bytes()
        archive.unlink()
        self._expect_refusal(self._verify())
        self.assertFalse(self.prefix.exists())
        archive.write_bytes(original)
        (self.bundle / "unexpected.bin").write_bytes(b"unlisted")
        message = self._expect_refusal(self._verify())
        self.assertIn("bundle file set mismatch", message)
        self.assertFalse(self.prefix.exists())

    def test_duplicate_manifest_json_key_is_rejected_even_when_signed(self):
        manifest, _, _ = self._write_bundle()
        suffix = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("ascii")
        raw = b'{"schema":"ami-rust-release-v1",' + suffix[1:] + b"\n"
        self._write_bundle(raw_manifest=raw)
        self.assertNotEqual((self.bundle / "release.json.sig").stat().st_size, 0)
        message = self._expect_refusal(self._verify())
        self.assertIn("duplicate JSON key", message)
        self.assertFalse(self.prefix.exists())

    def test_archive_rejects_unsafe_paths_and_nonregular_members(self):
        base, _ = self._base_entries()
        cases = [
            ("parent traversal", ("../escape", "file", b"x")),
            ("absolute path", ("/tmp/ami-rust-escape", "file", b"x")),
            ("backslash path", ("fixture\\escape", "file", b"x")),
            ("unlisted extra", ("fixture/extra.txt", "file", b"x")),
            ("duplicate name", ("fixture/marker.txt", "file", b"second")),
            ("symlink", ("fixture/link", "symlink", "marker.txt")),
            ("hardlink", ("fixture/hardlink", "hardlink", "fixture/marker.txt")),
            ("fifo", ("fixture/fifo", "fifo", "")),
        ]
        for label, bad_member in cases:
            with self.subTest(member=label):
                entries = list(base)
                entries.append(bad_member)
                self._write_bundle(archive_entries=entries)
                message = self._expect_refusal(self._install())
                self.assertFalse(self.prefix.exists(), label)
                self._no_stage()
                if label in ("symlink", "hardlink", "fifo"):
                    self.assertIn("plain regular file", message)
                elif label in ("parent traversal", "absolute path", "backslash path"):
                    self.assertTrue("unsafe" in message or "portable" in message, message)
                elif label == "duplicate name":
                    self.assertIn("duplicate", message)
                else:
                    self.assertTrue("inventory mismatch" in message or "plain regular" in message,
                                    message)

        # Omission is an independent archive-inventory failure.
        entries = [entry for entry in base if entry[0] != "fixture/marker.txt"]
        self._write_bundle(archive_entries=entries)
        message = self._expect_refusal(self._install())
        self.assertIn("inventory mismatch", message)
        self.assertFalse(self.prefix.exists())
        self._no_stage()

    def test_archive_rejects_sdk_manifest_hash_and_member_identity_mismatch(self):
        _, inner = self._base_entries()
        wrong_sdk_digest = "0" * 64
        self._write_bundle(sdk_manifest_sha256=wrong_sdk_digest)
        message = self._expect_refusal(self._verify())
        self.assertIn("sdk_files must pin contract/sdk.json", message)

        base, _ = self._base_entries()
        expected = [inventory_row(name, data) for name, kind, data in base if kind == "file"]
        wrong_size = [dict(row) for row in expected]
        marker_row = next(row for row in wrong_size if row["path"] == "fixture/marker.txt")
        marker_row["bytes"] += 1
        self._write_bundle(sdk_files=wrong_size)
        message = self._expect_refusal(self._verify())
        self.assertIn("file identity mismatch", message)

        wrong_hash = [dict(row) for row in expected]
        marker_row = next(row for row in wrong_hash if row["path"] == "fixture/marker.txt")
        marker_row["sha256"] = "0" * 64
        self._write_bundle(sdk_files=wrong_hash)
        message = self._expect_refusal(self._verify())
        self.assertIn("file identity mismatch", message)

    def test_failed_candidate_install_leaves_prior_version_unchanged(self):
        old_prefix = self.home_root / "sdk-old"
        self._expect_success(self._install(prefix=old_prefix, pin=self.home_root / "old.pin"),
                             "installed")
        before = snapshot((old_prefix, self.home_root / "old.pin"))
        archive = self.bundle / "sdk.tar.xz"
        archive.write_bytes(archive.read_bytes() + b"tampered")
        new_prefix = self.home_root / "sdk-new"
        message = self._expect_refusal(self._install(prefix=new_prefix,
                                                      pin=self.home_root / "new.pin"))
        self.assertIn("asset", message)
        self.assertFalse(new_prefix.exists())
        self.assertFalse((self.home_root / "new.pin").exists())
        self.assertEqual(snapshot((old_prefix, self.home_root / "old.pin")), before)
        self._no_stage(new_prefix)

    def test_modified_native_executable_is_rejected_before_install(self):
        native = self.bundle / "SHAUTIL"
        raw = native.read_bytes()
        native.write_bytes(raw[:-1] + b"!")
        message = self._expect_refusal(self._install())
        self.assertIn("asset identity mismatch", message)
        self.assertFalse(self.prefix.exists())
        self._no_stage()

    def test_unsafe_trust_permissions_are_rejected(self):
        self.trust_path.chmod(0o666)
        self.assertIn("unsafe ownership/write permissions", self._expect_refusal(self._verify()))

    def test_signed_inner_and_outer_manifest_inconsistency_is_rejected(self):
        self._write_bundle(manifest_changes={"version": "0.1.0-rc.4-local"})
        self.assertIn("SDK and outer release", self._expect_refusal(self._verify()))
        entries, inner = self._base_entries()
        value = json.loads(inner)
        value["files"][0]["sha256"] = "0" * 64
        changed = json_bytes(value)
        entries[0] = ("contract/sdk.json", "file", changed)
        rows = [inventory_row(name, data) for name, kind, data in entries if kind == "file"]
        self._write_bundle(archive_entries=entries, sdk_files=rows,
                           sdk_manifest_sha256=sha256(changed))
        self.assertIn("inner SDK inventory", self._expect_refusal(self._verify()))

    def test_unsafe_verifier_permissions_are_rejected(self):
        self.trust_path.chmod(0o600)
        tool = self.case / "copied-ssh-keygen"
        tool.write_bytes(SSH_KEYGEN.read_bytes())
        tool.chmod(0o777)
        trust = json.loads(self.trust_path.read_text())
        trust.update(verifier=str(tool), verifier_sha256=sha256(tool.read_bytes()))
        self.trust_path.write_bytes(json_bytes(trust))
        self.assertIn("unsafe ownership/write permissions", self._expect_refusal(self._verify()))

    def test_real_signal_during_staging_preserves_previous_installation(self):
        old = self.home_root / "prior-sdk"
        old_pin = self.home_root / "prior.pin"
        self._expect_success(self._install(prefix=old, pin=old_pin), "installed")
        previous = snapshot((old, old_pin))
        entries, _ = self._base_entries()
        entries += [(f"many/item-{i:04d}.txt", "file", b"x" * 4096) for i in range(900)]
        expected = [inventory_row(name, data) for name, kind, data in entries if kind == "file"]
        self._write_bundle(archive_entries=entries, sdk_files=expected)
        for chosen_signal in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=chosen_signal):
                target = self.home_root / ("interrupted-" + str(chosen_signal))
                env = {"PATH": os.defpath, "HOME": str(self.scratch), "TMPDIR": str(self.scratch), "LC_ALL": "C"}
                process = subprocess.Popen([sys.executable, "-I", "-B", str(INSTALLER), "install",
                    "--bundle", str(self.bundle), "--trust", str(self.trust_path), "--prefix", str(target)],
                    cwd=self.case, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                deadline = time.monotonic() + 20
                observed = False
                while process.poll() is None and time.monotonic() < deadline:
                    stages = list(target.parent.glob(f".{target.name}.stage-*"))
                    if stages:
                        observed = True
                        process.send_signal(chosen_signal)
                        break
                    time.sleep(0.001)
                if not observed and process.poll() is None:
                    process.kill()
                out, err = process.communicate(timeout=20)
                self.assertTrue(observed, "failed to observe an actual install stage")
                self.assertNotEqual(process.returncode, 0, (out, err))
                self.assertFalse(target.exists())
                self.assertEqual(snapshot((old, old_pin)), previous)
                stages = list(target.parent.glob(f".{target.name}.stage-*"))
                if chosen_signal == signal.SIGTERM:
                    self.assertEqual(stages, [], "SIGTERM must clean incomplete staging")
                else:
                    for stage in stages:
                        self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
                        shutil.rmtree(stage)

    def test_existing_prefix_is_refused_without_mutation(self):
        self.prefix.mkdir(mode=0o700)
        sentinel = self.prefix / "consumer-data.txt"
        sentinel.write_bytes(b"must remain untouched")
        before = snapshot((self.prefix,))
        message = self._expect_refusal(self._install())
        self.assertIn("fresh", message)
        self.assertEqual(snapshot((self.prefix,)), before)
        self.assertFalse(self.receipt_pin.exists())
        self._no_stage()

    def test_modified_installed_file_refuses_uninstall(self):
        self._install_ok()
        marker = self.prefix / "sdk" / "fixture" / "marker.txt"
        marker.write_bytes(b"modified")
        message = self._expect_refusal(self._uninstall())
        self.assertIn("identity mismatch", message)
        self.assertTrue(self.prefix.exists())
        self.assertEqual(marker.read_bytes(), b"modified")

    def test_extra_user_file_refuses_uninstall(self):
        self._install_ok()
        extra = self.prefix / "sdk" / "user-data.txt"
        extra.write_bytes(b"user data")
        message = self._expect_refusal(self._uninstall())
        self.assertIn("file set mismatch", message)
        self.assertTrue(self.prefix.exists())
        self.assertEqual(extra.read_bytes(), b"user data")

    def test_symlink_in_installation_refuses_uninstall(self):
        self._install_ok()
        outside = self.home_root / "outside.txt"
        outside.write_bytes(b"outside")
        link = self.prefix / "sdk" / "user-link"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"host does not permit symlink fixture: {error}")
        message = self._expect_refusal(self._uninstall())
        self.assertIn("symlink", message)
        self.assertTrue(self.prefix.exists())
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_wrong_external_receipt_pin_refuses_uninstall(self):
        self._install_ok()
        installed_before = snapshot((self.prefix,))
        wrong = "0" * 64
        self.assertNotEqual(wrong, self.receipt_pin.read_text().strip())
        message = self._expect_refusal(self._uninstall(receipt_sha256=wrong))
        self.assertIn("external receipt pin", message)
        self.assertEqual(snapshot((self.prefix,)), installed_before)

    def test_receipt_pin_must_be_fresh_and_outside_prefix(self):
        occupied = self.home_root / "occupied.pin"
        occupied.write_text("old pin\n")
        message = self._expect_refusal(self._install(pin=occupied))
        self.assertIn("fresh", message)
        self.assertFalse(self.prefix.exists())
        self.assertEqual(occupied.read_text(), "old pin\n")

        inside = self.prefix / "receipt.sha256"
        message = self._expect_refusal(self._install(pin=inside))
        self.assertIn("outside the installation prefix", message)
        self.assertFalse(self.prefix.exists())

    def test_isolated_python_ignores_ambient_sitecustomize(self):
        injected = self.case / "injected-site"
        injected.mkdir()
        marker = self.case / "ambient-python-ran"
        sitecustomize = injected / "sitecustomize.py"
        sitecustomize.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        result = self._verify(env_updates={"PYTHONPATH": str(injected)})
        self._expect_success(result, "verified")
        self.assertFalse(marker.exists(), "ambient sitecustomize executed despite -I -B")


if __name__ == "__main__":
    unittest.main(verbosity=2)

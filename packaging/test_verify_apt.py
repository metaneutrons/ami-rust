#!/usr/bin/env python3
"""Offline tests for the public APT signature, index, and payload verifier."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


_VERIFY_PATH = Path(__file__).with_name("verify_apt.py")
_FIXTURE_DIR = Path(__file__).with_name("testdata")
_PUBLIC_INRELEASE = _FIXTURE_DIR / "apt-archive-inrelease"
_PUBLIC_KEY = _FIXTURE_DIR / "apt-archive-public-key.pgp"
_PUBLIC_RELEASE_SHA256 = "f962e6d376ba9fbd60f4b92ec92d36abf7201cfc671d5d1d165947b8fc7ae1fe"
_SPEC = importlib.util.spec_from_file_location("ami_rust_verify_apt_test", _VERIFY_PATH)
assert _SPEC is not None and _SPEC.loader is not None
verify_apt = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verify_apt)


def sha(raw: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, raw).hexdigest()


def stanza(filename: str, version: str, payload: bytes) -> bytes:
    return (
        "Package: ami-rust\n"
        f"Version: {version}\n"
        "Architecture: amd64\n"
        f"Filename: {filename}\n"
        f"Size: {len(payload)}\n"
        f"SHA256: {sha(payload)}\n"
    ).encode("ascii")


class AptFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.packages_dir = root / "packages"
        self.packages_dir.mkdir()
        self.pins = json.loads(Path(__file__).with_name("pins.json").read_text())
        self.version = self.pins["package_version"]
        self.filename = f"ami-rust_{self.version}_amd64.deb"
        self.pool_path = f"pool/main/a/ami-rust/{self.filename}"
        self.payload = b"synthetic Debian payload for verifier tests\n"
        (self.packages_dir / self.filename).write_bytes(self.payload)
        self.plain_index = stanza(self.pool_path, self.version, self.payload)
        self.gzip_index = gzip.compress(self.plain_index, mtime=0)
        self.index_path = "dists/rolling/main/binary-amd64/by-hash/SHA512/" + sha(
            self.gzip_index, "sha512"
        )
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.release = self.release_text(self.gzip_index)
        self.assets = {
            verify_apt.KEY: b"K" * 609,
            "dists/rolling/InRelease": b"synthetic signed InRelease placeholder\n",
            self.index_path: self.gzip_index,
            self.pool_path: self.payload,
        }
        self.status = (
            f"[GNUPG:] VALIDSIG {verify_apt.SIGNER} 20261018 1792300000 0 4 0 1 10 00 "
            f"{verify_apt.PRIMARY}\n"
        )
        self.runs = 0
        self.last_output: Path | None = None
        self.last_fetched: list[str] = []

    def release_text(self, compressed: bytes) -> str:
        yesterday = self.now - timedelta(days=1)
        next_month = self.now + timedelta(days=30)
        return (
            "Origin: metaneutrons\n"
            "Suite: rolling\n"
            "Acquire-By-Hash: yes\n"
            f"Date: {format_datetime(yesterday)}\n"
            f"Valid-Until: {format_datetime(next_month)}\n"
            "SHA256:\n"
            f" {sha(compressed)} {len(compressed)} main/binary-amd64/Packages.gz\n"
            "SHA512:\n"
            f" {sha(compressed, 'sha512')} {len(compressed)} main/binary-amd64/Packages.gz\n"
        )

    def run(self, *, release: str | None = None, status: str | None = None,
            assets: dict[str, bytes] | None = None, gpgv_returncode: int = 0,
            gpg_returncode: int = 0, gpg_creates_output: bool = True,
            gpg_output: str | None = None) -> tuple[dict, list[str], Path]:
        self.runs += 1
        output = self.root / f"verified-{self.runs}"
        self.last_output = output
        requested = self.assets if assets is None else assets
        fetched: list[str] = []
        self.last_fetched = fetched

        def fake_fetch(relative: str, target: Path, limit: int) -> bytes:
            fetched.append(relative)
            raw = requested[relative]
            if len(raw) > limit:
                raise AssertionError(f"fixture {relative} unexpectedly exceeds {limit} bytes")
            target.write_bytes(raw)
            return raw

        signed_release = self.release if release is None else release
        signer_status = self.status if status is None else status

        def fake_subprocess(command, **kwargs):
            if command[0] == "gpgv":
                self.assert_gpgv_command(command, kwargs)
                return SimpleNamespace(stdout=signer_status, stderr="gpgv diagnostic\n",
                                       returncode=gpgv_returncode)
            if command[0] == "gpg":
                self.assert_gpg_command(command, kwargs)
                if gpg_creates_output:
                    release_path = Path(command[command.index("--output") + 1])
                    release_path.write_text(signed_release if gpg_output is None else gpg_output,
                                            encoding="utf-8")
                return SimpleNamespace(stdout="gpg output\n", stderr="gpg diagnostic\n",
                                       returncode=gpg_returncode)
            raise AssertionError(f"unexpected subprocess: {command[0]}")

        with (
            mock.patch.object(verify_apt, "KEY_SHA256", sha(self.assets[verify_apt.KEY])),
            mock.patch.object(verify_apt, "fetch", side_effect=fake_fetch),
            mock.patch.object(verify_apt.subprocess, "run", side_effect=fake_subprocess),
        ):
            verify_apt.verify(self.packages_dir, output)
        report = json.loads((output / "result.json").read_text(encoding="utf-8"))
        return report, fetched, output

    def assert_gpgv_command(self, command: list[str], kwargs: dict) -> None:
        if command[0] != "gpgv":
            raise AssertionError(f"unexpected subprocess: {command[0]}")
        for required in ("--homedir", "--keyring", "--status-fd"):
            if required not in command:
                raise AssertionError(f"gpgv command lacks {required}")
        if "--output" in command:
            raise AssertionError("gpgv must authenticate only; it does not extract cleartext")
        if command[command.index("--status-fd") + 1] != "1":
            raise AssertionError("gpgv must emit machine-readable status on stdout")
        expected = {"capture_output": True, "text": True, "check": False, "timeout": 60}
        if kwargs != expected:
            raise AssertionError(f"unexpected gpgv invocation options: {kwargs}")

    def assert_gpg_command(self, command: list[str], kwargs: dict) -> None:
        if command[0] != "gpg":
            raise AssertionError(f"unexpected subprocess: {command[0]}")
        for required in ("--batch", "--no-default-keyring", "--keyring", "--homedir",
                         "--no-auto-key-retrieve", "--output", "--decrypt"):
            if required not in command:
                raise AssertionError(f"gpg command lacks {required}")
        if command[-1] != str(self.last_output / "InRelease"):
            raise AssertionError("gpg must decrypt the exact authenticated InRelease file")
        expected = {"capture_output": True, "text": True, "check": False, "timeout": 60}
        if kwargs != expected:
            raise AssertionError(f"unexpected gpg invocation options: {kwargs}")


class VerifyAptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.fixture = AptFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @unittest.skipUnless(shutil.which("gpgv") and shutil.which("gpg"),
                         "real gpgv and gpg are required for this interface regression")
    def test_real_gnupg_extracts_and_authenticates_public_archive_cleartext(self) -> None:
        key_bytes = _PUBLIC_KEY.read_bytes()
        self.assertEqual(sha(key_bytes), verify_apt.KEY_SHA256)
        home = self.root / "real-gnupg"
        home.mkdir(mode=0o700)
        plaintext = verify_apt.authenticated_plaintext(
            _PUBLIC_INRELEASE, _PUBLIC_KEY, home, self.root
        )
        self.assertEqual(sha(plaintext), _PUBLIC_RELEASE_SHA256)
        self.assertIn(b"Suite: rolling\n", plaintext)
        status = (self.root / "gpgv.stdout.log").read_text(encoding="utf-8")
        self.assertIn("[GNUPG:] VALIDSIG " + verify_apt.SIGNER, status)
        self.assertTrue(status.rstrip().endswith(verify_apt.PRIMARY))
        self.assertIn("Good signature", (self.root / "gpgv.stderr.log").read_text(encoding="utf-8"))
        self.assertIn("Good signature", (self.root / "gpg.stderr.log").read_text(encoding="utf-8"))

    @unittest.skipUnless(shutil.which("gpgv") and shutil.which("gpg"),
                         "real gpgv and gpg are required for this interface regression")
    def test_real_gnupg_rejects_modified_signed_plaintext_before_decryption(self) -> None:
        original = _PUBLIC_INRELEASE.read_bytes()
        needle = b"Origin: metaneutrons"
        self.assertIn(needle, original)
        altered = original.replace(needle, b"Origin: Metaneutrons", 1)
        inrelease = self.root / "modified-InRelease"
        inrelease.write_bytes(altered)
        home = self.root / "tampered-gnupg"
        home.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "gpgv failed with exit code"):
            verify_apt.authenticated_plaintext(inrelease, _PUBLIC_KEY, home, self.root)
        self.assertIn("BAD signature", (self.root / "gpgv.stderr.log").read_text(encoding="utf-8"))
        self.assertFalse((self.root / "gpg.stdout.log").exists())
        self.assertFalse((self.root / "Release").exists())

    def rejected(self, *, release: str | None = None, status: str | None = None,
                 assets: dict[str, bytes] | None = None, message: str | None = None,
                 gpgv_returncode: int = 0, gpg_returncode: int = 0,
                 gpg_creates_output: bool = True, gpg_output: str | None = None) -> None:
        with self.assertRaises(ValueError) as raised:
            self.fixture.run(release=release, status=status, assets=assets,
                             gpgv_returncode=gpgv_returncode, gpg_returncode=gpg_returncode,
                             gpg_creates_output=gpg_creates_output, gpg_output=gpg_output)
        if message is not None:
            self.assertIn(message, str(raised.exception))
        assert self.fixture.last_output is not None
        self.assertFalse((self.fixture.last_output / "result.json").exists())

    def test_valid_signature_by_hash_index_and_exact_deb(self) -> None:
        report, fetched, output = self.fixture.run()
        self.assertEqual(report["status"], "PASS_PUBLIC_APT_SIGNATURE_BY_HASH_AND_PAYLOAD")
        self.assertEqual(report["index_algorithm"], "SHA512")
        self.assertEqual(report["index_path"], self.fixture.index_path)
        self.assertEqual(report["package"]["Filename"], self.fixture.pool_path)
        self.assertEqual(fetched, [
            verify_apt.KEY,
            "dists/rolling/InRelease",
            self.fixture.index_path,
            self.fixture.pool_path,
        ])
        self.assertEqual(json.loads((output / "result.json").read_text()), report)
        self.assertEqual(report["verification_logs"], {
            "gpgv_stdout": "gpgv.stdout.log", "gpgv_stderr": "gpgv.stderr.log",
            "gpg_stdout": "gpg.stdout.log", "gpg_stderr": "gpg.stderr.log",
        })
        self.assertEqual((output / "gpgv.stderr.log").read_text(), "gpgv diagnostic\n")
        self.assertEqual((output / "gpg.stderr.log").read_text(), "gpg diagnostic\n")

    def test_gpgv_success_without_release_output_uses_gpg_cleartext_extraction(self) -> None:
        # AptFixture's gpgv mock deliberately creates no Release file; only its
        # subsequent authenticated gpg decrypt step creates the plaintext.
        report, _, output = self.fixture.run()
        self.assertEqual(report["status"], "PASS_PUBLIC_APT_SIGNATURE_BY_HASH_AND_PAYLOAD")
        self.assertTrue((output / "Release").is_file())
        self.assertEqual((output / "Release").read_text(), self.fixture.release)

    def test_changed_by_hash_index_and_changed_deb_are_rejected(self) -> None:
        altered_index = bytearray(self.fixture.gzip_index)
        altered_index[-1] ^= 1
        assets = dict(self.fixture.assets)
        assets[self.fixture.index_path] = bytes(altered_index)
        self.rejected(assets=assets, message="signed size/hash")

        altered_payload = bytearray(self.fixture.payload)
        altered_payload[0] ^= 1
        assets = dict(self.fixture.assets)
        assets[self.fixture.pool_path] = bytes(altered_payload)
        self.rejected(assets=assets, message="signed size/hash")

        (self.fixture.packages_dir / self.fixture.filename).write_bytes(
            b"qualified candidate bytes have changed\n"
        )
        self.rejected(message="differs from the qualified release")

    def test_wrong_signer_and_expired_release_are_rejected(self) -> None:
        wrong_status = self.fixture.status.replace(verify_apt.SIGNER, "9" * 40)
        self.rejected(status=wrong_status, message="unexpected primary or signing subkey")

        last_week = format_datetime(self.fixture.now - timedelta(days=7))
        expired = self.fixture.release.replace(
            f"Valid-Until: {format_datetime(self.fixture.now + timedelta(days=30))}",
            f"Valid-Until: {last_week}",
        )
        self.rejected(release=expired, message="not currently valid")

    def test_invalid_envelope_and_rejected_gpg_extraction_are_durable_failures(self) -> None:
        self.rejected(gpgv_returncode=2, status="", message="gpgv failed with exit code 2")
        assert self.fixture.last_output is not None
        self.assertEqual((self.fixture.last_output / "gpgv.stderr.log").read_text(),
                         "gpgv diagnostic\n")
        self.assertFalse((self.fixture.last_output / "gpg.stdout.log").exists())

        self.rejected(gpg_returncode=2, message="gpg failed with exit code 2")
        assert self.fixture.last_output is not None
        self.assertEqual((self.fixture.last_output / "gpg.stdout.log").read_text(), "gpg output\n")
        self.assertEqual((self.fixture.last_output / "gpg.stderr.log").read_text(),
                         "gpg diagnostic\n")

        self.rejected(gpg_creates_output=False,
                      message="GPG did not create the authenticated InRelease plaintext")
        assert self.fixture.last_output is not None
        self.assertTrue((self.fixture.last_output / "gpgv.stdout.log").is_file())
        self.assertTrue((self.fixture.last_output / "gpg.stderr.log").is_file())

    def test_gpg_plaintext_is_bounded(self) -> None:
        self.rejected(gpg_output="X" * (verify_apt.MAX_INRELEASE_BYTES + 1),
                      message="exceeds its bound")

    def test_signed_release_without_sha512_is_rejected_before_index_fetch(self) -> None:
        sha256_only = self.fixture.release.split("SHA512:\n", 1)[0]
        self.rejected(release=sha256_only, message="missing the promised SHA256/SHA512")
        self.assertEqual(self.fixture.last_fetched, [verify_apt.KEY, "dists/rolling/InRelease"])

    def test_duplicate_release_paragraph_and_package_stanza_are_rejected(self) -> None:
        duplicate_release = self.fixture.release + "\nOrigin: duplicate\nSuite: rolling\n"
        self.rejected(release=duplicate_release, message="Release paragraph is absent or ambiguous")

        duplicate_index = self.fixture.plain_index + b"\n" + self.fixture.plain_index
        compressed = gzip.compress(duplicate_index, mtime=0)
        path = "dists/rolling/main/binary-amd64/by-hash/SHA512/" + sha(compressed, "sha512")
        assets = dict(self.fixture.assets)
        assets.pop(self.fixture.index_path)
        assets[path] = compressed
        release = self.fixture.release_text(compressed)
        self.rejected(release=release, assets=assets, message="ami-rust package is absent or ambiguous")

    def test_corruption_counter_must_reject_a_changed_payload(self) -> None:
        original = verify_apt.check_hash

        def broken_hash_check(raw, size, digest, algorithm):
            if raw.endswith(b"counter-probe"):
                return None
            return original(raw, size, digest, algorithm)

        with mock.patch.object(verify_apt, "check_hash", side_effect=broken_hash_check):
            with self.assertRaisesRegex(ValueError, "counter-probe did not fail"):
                self.fixture.run()
        assert self.fixture.last_output is not None
        self.assertFalse((self.fixture.last_output / "result.json").exists())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Verify the public signed APT index and the exact released Debian payload."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess

BASE = "https://deb.metaneutrons.cc"
KEY = "metaneutrons-archive-keyring.pgp"
KEY_SHA256 = "e663577e0e5769a6b1a83f1cd44751dfc60bd0820ae0724df5cb6a60fb3a2b74"
PRIMARY = "1B7B79417383648BBFBE282E01AB8296EF0FCD76"
SIGNER = "A0C21782FC507CCBD666F3ED242072FEC8BE54A4"
MAX_INRELEASE_BYTES = 2 * 1024**2


def run_logged(command, root, label, timeout):
    """Run a verifier and retain its diagnostics, including on rejection."""
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        (root / f"{label}.stdout.log").write_text(stdout, encoding="utf-8")
        (root / f"{label}.stderr.log").write_text(stderr, encoding="utf-8")
        raise ValueError(f"{label} timed out") from error
    (root / f"{label}.stdout.log").write_text(result.stdout or "", encoding="utf-8")
    (root / f"{label}.stderr.log").write_text(result.stderr or "", encoding="utf-8")
    if result.returncode != 0:
        raise ValueError(f"{label} failed with exit code {result.returncode}")
    return result


def authenticated_plaintext(inrelease, key, home, diagnostics_root):
    """Authenticate exact archive fingerprints, then extract bounded cleartext."""
    inrelease = Path(inrelease)
    key = Path(key)
    home = Path(home)
    diagnostics_root = Path(diagnostics_root)
    command = ["gpgv", "--homedir", str(home), "--keyring", str(key), "--status-fd", "1",
               str(inrelease)]
    result = run_logged(command, diagnostics_root, "gpgv", timeout=60)
    signatures = [line.split() for line in result.stdout.splitlines()
                  if line.startswith("[GNUPG:] VALIDSIG ")]
    signature = one(signatures, "archive signature")
    if signature[2] != SIGNER or signature[-1] != PRIMARY:
        raise ValueError("archive signature uses an unexpected primary or signing subkey")

    release_file = diagnostics_root / "Release"
    if release_file.exists() or release_file.is_symlink():
        raise ValueError("authenticated InRelease plaintext destination already exists")
    decrypt = ["gpg", "--batch", "--no-tty", "--no-default-keyring", "--keyring", str(key),
               "--homedir", str(home), "--no-auto-key-retrieve", "--output", str(release_file),
               "--decrypt", str(inrelease)]
    run_logged(decrypt, diagnostics_root, "gpg", timeout=60)
    try:
        info = release_file.lstat()
    except OSError as error:
        raise ValueError("GPG did not create the authenticated InRelease plaintext") from error
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0
            or info.st_size > MAX_INRELEASE_BYTES):
        raise ValueError("GPG plaintext is linked, empty, non-regular or exceeds its bound")
    with release_file.open("rb") as stream:
        raw = stream.read(MAX_INRELEASE_BYTES + 1)
    if len(raw) != info.st_size or len(raw) > MAX_INRELEASE_BYTES:
        raise ValueError("GPG plaintext changed or exceeds its bound")
    return raw


def fetch(relative, target, limit):
    subprocess.run(["curl", "--fail", "--silent", "--show-error", "--proto", "=https",
                    "--connect-timeout", "20", "--max-time", "180", "--max-filesize", str(limit),
                    "--output", str(target), BASE + "/" + relative], check=True, timeout=190)
    if target.stat().st_size > limit:
        raise ValueError("public APT object exceeds its bound")
    return target.read_bytes()


def paragraphs(text):
    result = []
    current = {}
    field = None
    for line in text.splitlines() + [""]:
        if not line:
            if current:
                result.append(current)
            current, field = {}, None
        elif line[0].isspace():
            if field is None:
                raise ValueError("APT continuation has no field")
            current[field] += "\n" + line.strip()
        else:
            field, separator, value = line.partition(":")
            if not separator or field in current:
                raise ValueError("duplicate or malformed APT field")
            current[field] = value.strip()
    return result


def one(rows, label):
    if len(rows) != 1:
        raise ValueError(label + " is absent or ambiguous")
    return rows[0]


def check_hash(raw, size, digest, algorithm):
    if len(raw) != int(size) or hashlib.new(algorithm, raw).hexdigest() != digest:
        raise ValueError("public APT object differs from signed size/hash")


def verify(packages, root):
    root.mkdir(mode=0o700)
    key = root / KEY
    raw = fetch(KEY, key, 65536)
    check_hash(raw, 609, KEY_SHA256, "sha256")
    inrelease = root / "InRelease"
    fetch("dists/rolling/InRelease", inrelease, MAX_INRELEASE_BYTES)
    home = root / "gnupg"
    home.mkdir(mode=0o700)
    release_raw = authenticated_plaintext(inrelease, key, home, root)
    release = one(paragraphs(release_raw.decode("utf-8")), "Release paragraph")
    now = datetime.now(timezone.utc)
    if not (parsedate_to_datetime(release["Date"]) <= now < parsedate_to_datetime(release["Valid-Until"])):
        raise ValueError("signed archive metadata is not currently valid")
    if release.get("Acquire-By-Hash") != "yes" or release.get("Suite") != "rolling":
        raise ValueError("archive suite/by-hash contract differs")
    if not {"SHA256", "SHA512"} <= release.keys():
        raise ValueError("archive is missing the promised SHA256/SHA512 index records")
    algorithm = "SHA512"
    records = [line.split() for line in release[algorithm].splitlines() if line.strip()]
    digest, size, name = one([row for row in records if len(row) == 3
                              and row[2] == "main/binary-amd64/Packages.gz"], "strongest package index")
    relative = "dists/rolling/main/binary-amd64/by-hash/" + algorithm + "/" + digest
    raw = fetch(relative, root / "Packages.gz", min(int(size), 32 * 1024**2))
    check_hash(raw, size, digest, algorithm.lower())
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        plain = stream.read(32 * 1024**2 + 1)
    if len(plain) > 32 * 1024**2:
        raise ValueError("APT index expansion exceeds the parser bound")
    pins = json.loads((Path(__file__).with_name("pins.json")).read_text())
    package = one([row for row in paragraphs(plain.decode()) if row.get("Package") == "ami-rust"
                   and row.get("Version") == pins["package_version"] and row.get("Architecture") == "amd64"],
                  "ami-rust package")
    path = PurePosixPath(package["Filename"])
    filename = f"ami-rust_{pins['package_version']}_amd64.deb"
    if (path.is_absolute() or ".." in path.parts or path.as_posix() != package["Filename"]
            or path.as_posix() != "pool/main/a/ami-rust/" + filename):
        raise ValueError("unexpected APT pool location")
    raw = fetch(str(path), root / filename, int(package["Size"]))
    check_hash(raw, package["Size"], package["SHA256"], "sha256")
    expected = (packages / filename).read_bytes()
    if raw != expected:
        raise ValueError("public APT package differs from the qualified release")
    # Prove the size/hash measurement rejects a changed isolated payload.
    try:
        check_hash(raw + b"counter-probe", package["Size"], package["SHA256"], "sha256")
    except ValueError:
        pass
    else:
        raise ValueError("APT payload corruption counter-probe did not fail")
    report = {"status": "PASS_PUBLIC_APT_SIGNATURE_BY_HASH_AND_PAYLOAD", "base_url": BASE,
              "primary_fingerprint": PRIMARY, "signing_subkey": SIGNER,
              "index_algorithm": algorithm, "index_path": relative, "package": package,
              "verification_logs": {"gpgv_stdout": "gpgv.stdout.log", "gpgv_stderr": "gpgv.stderr.log",
                                    "gpg_stdout": "gpg.stdout.log", "gpg_stderr": "gpg.stderr.log"},
              "corruption_counter_probe": "PASS", "real_client_installation": "SEPARATE_GATE"}
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages-dir", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    verify(args.packages_dir, args.root)

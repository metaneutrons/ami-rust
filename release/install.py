#!/usr/bin/env python3
"""Offline ami-rust candidate verification and user-owned installation.

Run with the intended Python as ``python -I -B release/install.py``. This
verifies an OpenSSH signature over release.json against an external trust file
and checks the declared bytes. It does not verify Cosign/GitHub Actions
provenance, establish the publisher's real-world identity, or qualify an R1
release. Checksums and a signature under an unanchored key are not provenance.
"""
import argparse
import ctypes
import errno
import hashlib
import io
import json
import lzma
import os
import platform
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import secrets
from pathlib import Path


MANIFEST_LIMIT = 4 * 1024 * 1024
SIGNATURE_LIMIT = 16 * 1024
ASSET_LIMIT = 16 * 1024 * 1024
ASSET_TOTAL_LIMIT = 32 * 1024 * 1024
ARCHIVE_LIMIT = 16 * 1024 * 1024
ARCHIVE_MEMBERS_LIMIT = 1000
INSTALLED_LIMIT = 64 * 1024 * 1024
RECEIPT_LIMIT = 4 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")
PRINCIPAL = re.compile(r"[A-Za-z0-9._@+-]{1,200}\Z")
SEGMENT = re.compile(r"[A-Za-z0-9._+-]{1,120}\Z")
COMPONENTS = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")
HOSTS = {"macos-aarch64", "linux-x86_64"}
SSH_NAMESPACE = "ami-rust-release"


class Refusal(ValueError):
    pass


class PinWriteFailure(Exception):
    def __init__(self, prefix, receipt_sha256, detail):
        super().__init__(detail)
        self.prefix = str(prefix)
        self.receipt_sha256 = receipt_sha256


class PublishedInterruption(Exception):
    def __init__(self, prefix, receipt_sha256):
        super().__init__("SIGTERM arrived after installation publication")
        self.prefix = str(prefix)
        self.receipt_sha256 = receipt_sha256


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(raw, label):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refusal(f"duplicate JSON key in {label}: {key}")
            value[key] = item
        return value

    def constant(value):
        raise Refusal(f"invalid JSON constant in {label}: {value}")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                            parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"invalid UTF-8 JSON in {label}: {error}") from error
    if not isinstance(result, dict):
        raise Refusal(f"{label} must be a JSON object")
    return result


def _read_fd(path, limit, label):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as error:
        raise Refusal(f"cannot open {label}: {error}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refusal(f"{label} must be a regular file")
        if info.st_size > limit:
            raise Refusal(f"oversized {label}")
        chunks = []
        total = 0
        while True:
            block = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > limit:
                raise Refusal(f"oversized {label}")
        if total != info.st_size:
            raise Refusal(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _canonical_absolute(value, label):
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise Refusal(f"{label} must be an absolute path")
    if os.path.normpath(value) != value:
        raise Refusal(f"{label} must be a normalized absolute path")
    return Path(value)


def _real_regular(value, label, executable=False):
    path = _canonical_absolute(value, label)
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError as error:
        raise Refusal(f"missing {label}: {error}") from error
    if resolved != path or not stat.S_ISREG(info.st_mode):
        raise Refusal(f"{label} must be a regular file without symlink components")
    if executable and (not info.st_mode & 0o111 or not os.access(path, os.X_OK)):
        raise Refusal(f"{label} is not executable")
    return path


def _digest_text(value, label):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise Refusal(f"invalid {label} SHA-256")
    return value


def _portable_path(value, label):
    if (not isinstance(value, str) or not value or len(value) > 240
            or value.startswith("/") or "\\" in value or ":" in value
            or any(ord(char) < 32 or ord(char) >= 127 for char in value)):
        raise Refusal(f"{label} must be a portable relative path")
    parts = value.split("/")
    if len(parts) > 24:
        raise Refusal(f"too many path components in {label}")
    for part in parts:
        stem = part.split(".", 1)[0].upper()
        if (not SEGMENT.fullmatch(part) or part in (".", "..")
                or part.endswith(".")
                or stem in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)):
            raise Refusal(f"nonportable or unsafe {label}: {value}")
    return parts


def _inventory(rows, label, *, count_limit, total_limit, file_limit):
    if not isinstance(rows, list) or not rows or len(rows) > count_limit:
        raise Refusal(f"invalid {label} inventory length")
    result = {}
    folded = {}
    total = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise Refusal(f"invalid {label} inventory entry")
        path = row["path"]
        _portable_path(path, f"{label} path")
        if path in result or path.casefold() in folded:
            raise Refusal(f"duplicate {label} path: {path}")
        size = row["bytes"]
        digest = _digest_text(row["sha256"], f"{label} file")
        if type(size) is not int or size < 0 or size > file_limit:
            raise Refusal(f"invalid {label} byte length: {path}")
        total += size
        if total > total_limit:
            raise Refusal(f"{label} exceeds its total byte limit")
        result[path] = (size, digest)
        folded[path.casefold()] = path
    for path in result:
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            folded_parent = folded.get(parent.casefold())
            if folded_parent is not None:
                raise Refusal(f"file/directory or case-insensitive path conflict: {path}")
    return result


def _ancestors(paths):
    result = set()
    for value in paths:
        parts = value.split("/")
        for index in range(1, len(parts)):
            result.add("/".join(parts[:index]))
    return result


def _scan_tree(root, *, max_files, max_total):
    try:
        root_info = root.lstat()
    except OSError as error:
        raise Refusal(f"missing directory: {root}") from error
    if not stat.S_ISDIR(root_info.st_mode):
        raise Refusal(f"path must be a real directory: {root}")
    files, directories = {}, set()

    def visit(directory, prefix):
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise Refusal(f"cannot inspect directory {directory}: {error}") from error
        for entry in entries:
            _portable_path(entry.name, "bundle or installation entry")
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise Refusal(f"cannot inspect {relative}: {error}") from error
            if stat.S_ISLNK(info.st_mode):
                raise Refusal(f"symlink is forbidden: {relative}")
            _portable_path(relative, "bundle or installation path")
            if stat.S_ISDIR(info.st_mode):
                directories.add(relative)
                if len(directories) > max_files:
                    raise Refusal("too many directories")
                visit(Path(entry.path), relative)
            elif stat.S_ISREG(info.st_mode):
                files[relative] = info
                if len(files) > max_files:
                    raise Refusal("too many files")
                if info.st_size < 0 or info.st_size > max_total:
                    raise Refusal(f"oversized file: {relative}")
            else:
                raise Refusal(f"non-regular entry is forbidden: {relative}")

    visit(root, "")
    nodes = {name: "file" for name in files}
    nodes.update({name: "directory" for name in directories})
    folded = {}
    for name, kind in nodes.items():
        key = name.casefold()
        if key in folded and folded[key] != name:
            raise Refusal(f"case-insensitive path collision: {name}")
        folded[key] = name
        parts = name.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            existing = nodes.get(parent)
            folded_parent = folded.get(parent.casefold())
            if existing == "file" or (folded_parent is not None
                                       and folded_parent.casefold() == parent.casefold()
                                       and nodes.get(folded_parent) == "file"):
                raise Refusal(f"file/directory path conflict: {name}")
    total = sum(info.st_size for info in files.values())
    if total > max_total:
        raise Refusal("directory exceeds its total byte limit")
    return files, directories


def _read_relative(root, relative, limit, label):
    parts = _portable_path(relative, label)
    current = root
    for part in parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise Refusal(f"missing {label}: {relative}") from error
        if not stat.S_ISDIR(info.st_mode):
            raise Refusal(f"unsafe parent in {label}: {relative}")
    path = current / parts[-1]
    try:
        info = path.lstat()
    except OSError as error:
        raise Refusal(f"missing {label}: {relative}") from error
    if not stat.S_ISREG(info.st_mode):
        raise Refusal(f"{label} must be a regular non-symlink file: {relative}")
    return _read_fd(path, limit, label)


def _host_key():
    key = {("Darwin", "arm64"): "macos-aarch64",
           ("Linux", "x86_64"): "linux-x86_64"}.get(
               (platform.system(), platform.machine().lower()))
    if key is None:
        raise Refusal("supported hosts are macOS Apple Silicon and Linux x86-64")
    return key


def _load_trust(path_value, bundle_root):
    if not isinstance(path_value, str) or not path_value:
        raise Refusal("trust file path is required")
    path = Path(os.path.abspath(path_value))
    try:
        if path.resolve(strict=True) != path:
            raise Refusal("trust file path may not contain symlinks")
        trust_info = path.lstat()
    except OSError as error:
        raise Refusal(f"missing trust file: {error}") from error
    if not stat.S_ISREG(trust_info.st_mode):
        raise Refusal("trust file must be a regular file")
    _protected_input(path, "trust file")
    if path == bundle_root or bundle_root in path.parents:
        raise Refusal("trust file must be outside the bundle")
    if trust_info.st_size > 1024 * 1024:
        raise Refusal("oversized trust file")
    raw = _read_fd(path, 1024 * 1024, "trust file")
    trust = _json(raw, "trust file")
    required = {"schema", "publisher", "public_key", "public_key_sha256",
                "verifier", "verifier_sha256"}
    if set(trust) != required or trust.get("schema") != "ami-rust-offline-trust-v1":
        raise Refusal("incompatible offline trust file schema")
    publisher = trust.get("publisher")
    if not isinstance(publisher, str) or not PRINCIPAL.fullmatch(publisher):
        raise Refusal("invalid publisher principal in trust file")
    key_path = _real_regular(trust.get("public_key"), "trusted public key")
    verifier = _real_regular(trust.get("verifier"), "pinned ssh-keygen", executable=True)
    _protected_input(key_path, "trusted public key")
    _protected_input(verifier, "pinned ssh-keygen")
    for candidate, label in ((key_path, "public key"), (verifier, "verifier")):
        if candidate == bundle_root or bundle_root in candidate.parents:
            raise Refusal(f"{label} must be outside the bundle")
    key_raw = _read_fd(key_path, 4096, "trusted public key")
    key_digest = _digest_text(trust.get("public_key_sha256"), "public key")
    verifier_digest = _digest_text(trust.get("verifier_sha256"), "ssh-keygen")
    if _sha(key_raw) != key_digest:
        raise Refusal("trusted public key digest mismatch")
    if _sha_file(verifier) != verifier_digest:
        raise Refusal("pinned ssh-keygen digest mismatch")
    try:
        lines = key_raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise Refusal("trusted public key must be ASCII OpenSSH format") from error
    if len(lines) != 1 or "\r" in lines[0]:
        raise Refusal("trusted public key must contain one OpenSSH key line")
    fields = lines[0].split()
    allowed_types = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                     "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                     "sk-ssh-ed25519@openssh.com",
                     "sk-ecdsa-sha2-nistp256@openssh.com"}
    if len(fields) < 2 or fields[0] not in allowed_types:
        raise Refusal("unsupported OpenSSH public-key format")
    key_line = f"{fields[0]} {fields[1]}"
    return {"publisher": publisher, "key_line": key_line,
            "key_raw": key_raw, "public_key_sha256": key_digest,
            "verifier": verifier, "verifier_sha256": verifier_digest}


def _verify_signature(raw_manifest, signature, trust, bundle_root):
    if not signature or len(signature) > SIGNATURE_LIMIT:
        raise Refusal("missing or oversized release signature")
    allowed = (f'{trust["publisher"]} namespaces="{SSH_NAMESPACE}" '
               f'{trust["key_line"]}\n').encode("ascii")
    try:
        with tempfile.TemporaryDirectory(prefix="ami-rust-verify-",
                                         dir=str(_private_temp_root(
                                             forbidden=(bundle_root,)))) as temp:
            temp_path = Path(temp)
            allowed_path = temp_path / "allowed_signers"
            signature_path = temp_path / "release.sig"
            for path, data in ((allowed_path, allowed), (signature_path, signature)):
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            command = [str(trust["verifier"]), "-Y", "verify", "-f",
                       str(allowed_path), "-I", trust["publisher"], "-n",
                       SSH_NAMESPACE, "-s", str(signature_path)]
            result = subprocess.run(command, input=raw_manifest, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=30, check=False,
                                    env={"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"})
    except subprocess.TimeoutExpired as error:
        raise Refusal("ssh-keygen signature verification timed out") from error
    except OSError as error:
        raise Refusal(f"cannot execute pinned ssh-keygen: {error}") from error
    if result.returncode != 0:
        raise Refusal("release manifest OpenSSH signature verification failed")
    if _sha_file(trust["verifier"]) != trust["verifier_sha256"]:
        raise Refusal("pinned ssh-keygen changed during verification")


def _release_manifest(raw, *, production=False):
    if len(raw) > MANIFEST_LIMIT:
        raise Refusal("oversized release manifest")
    manifest = _json(raw, "release manifest")
    required = {"schema", "version", "qualification_only", "sdk_archive",
                "sdk_manifest_sha256", "assets", "sdk_files", "producer",
                "host_interpreters"}
    if set(manifest) != required or manifest.get("schema") != "ami-rust-release-v1":
        raise Refusal("incompatible release manifest schema")
    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise Refusal("invalid release version")
    qualification = manifest.get("qualification_only")
    if qualification is not True and not (production and qualification is False):
        raise Refusal("release qualification_only value is incompatible with this installer route")
    if manifest.get("sdk_archive") != "sdk.tar.xz":
        raise Refusal("release sdk_archive must be sdk.tar.xz")
    sdk_digest = _digest_text(manifest.get("sdk_manifest_sha256"), "SDK manifest")
    if not isinstance(manifest.get("producer"), dict) or not manifest["producer"]:
        raise Refusal("release producer identity must be a non-empty object")
    host_pythons = manifest.get("host_interpreters")
    if not isinstance(host_pythons, dict) or set(host_pythons) != HOSTS:
        raise Refusal("release must pin Python hashes for both supported hosts")
    for host in HOSTS:
        entry = host_pythons[host]
        if not isinstance(entry, dict) or set(entry) != {"sha256"}:
            raise Refusal(f"invalid host_interpreters entry: {host}")
        _digest_text(entry.get("sha256"), f"{host} Python")

    assets = _inventory(manifest.get("assets"), "asset", count_limit=1000,
                        total_limit=ASSET_TOTAL_LIMIT, file_limit=ASSET_LIMIT)
    if "sdk.tar.xz" not in assets:
        raise Refusal("release asset inventory is missing sdk.tar.xz")
    if any(path.casefold() in ("release.json", "release.json.sig")
           or path.casefold().startswith(("release.json/", "release.json.sig/"))
           for path in assets):
        raise Refusal("release manifest and signature paths are reserved")
    sdk_files = _inventory(manifest.get("sdk_files"), "SDK file", count_limit=ARCHIVE_MEMBERS_LIMIT,
                           total_limit=ARCHIVE_LIMIT, file_limit=ARCHIVE_LIMIT)
    contract = sdk_files.get("contract/sdk.json")
    if contract is None or contract[1] != sdk_digest:
        raise Refusal("sdk_files must pin contract/sdk.json to sdk_manifest_sha256")
    return manifest, assets, sdk_files


def _decompress_xz(data):
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,
                                       memlimit=64 * 1024 * 1024)
        output = bytearray()
        pending = data
        while True:
            room = ARCHIVE_LIMIT + 1 - len(output)
            if room <= 0:
                raise Refusal("uncompressed SDK archive exceeds 16 MiB")
            output.extend(decoder.decompress(pending, max_length=room))
            pending = b""
            if len(output) > ARCHIVE_LIMIT:
                raise Refusal("uncompressed SDK archive exceeds 16 MiB")
            if decoder.eof:
                if decoder.unused_data:
                    raise Refusal("trailing or concatenated data after XZ stream")
                return bytes(output)
            if decoder.needs_input:
                raise Refusal("truncated XZ SDK archive")
    except lzma.LZMAError as error:
        raise Refusal(f"invalid XZ SDK archive: {error}") from error


def _verify_archive(data, expected):
    raw = _decompress_xz(data)
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        members = archive.getmembers()
    except (tarfile.TarError, OSError) as error:
        raise Refusal(f"invalid SDK tar archive: {error}") from error
    if not members or len(members) > ARCHIVE_MEMBERS_LIMIT:
        raise Refusal("SDK archive has an invalid member count")
    found, modes = {}, {}
    last_end = 0
    for member in members:
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not member.isreg():
            raise Refusal(f"SDK archive member is not a plain regular file: {member.name}")
        if getattr(member, "pax_headers", None):
            raise Refusal(f"SDK archive extended headers are not accepted: {member.name}")
        name = member.name
        _portable_path(name, "SDK archive member")
        if name in found or name.casefold() in {item.casefold() for item in found}:
            raise Refusal(f"duplicate SDK archive member: {name}")
        if type(member.size) is not int or member.size < 0 or member.size > ARCHIVE_LIMIT:
            raise Refusal(f"invalid SDK archive member size: {name}")
        stream = archive.extractfile(member)
        if stream is None:
            raise Refusal(f"cannot read SDK archive member: {name}")
        content = stream.read(member.size + 1)
        if len(content) != member.size:
            raise Refusal(f"truncated SDK archive member: {name}")
        found[name] = content
        modes[name] = member.mode & 0o777
        last_end = max(last_end, member.offset_data + ((member.size + 511) // 512) * 512)
    if set(found) != set(expected):
        extras, missing = sorted(set(found) - set(expected)), sorted(set(expected) - set(found))
        raise Refusal(f"SDK archive inventory mismatch: extra={extras[:3]} missing={missing[:3]}")
    for name, content in found.items():
        size, digest = expected[name]
        if len(content) != size or _sha(content) != digest:
            raise Refusal(f"SDK archive file identity mismatch: {name}")
    tail = raw[last_end:]
    if len(tail) < 1024 or any(tail):
        raise Refusal("SDK tar must end with zero padding and two end-of-archive blocks")
    return found, modes


def verify_bundle(bundle_value, trust_value):
    host = _host_key()
    if not isinstance(bundle_value, str) or not bundle_value:
        raise Refusal("bundle directory path is required")
    bundle = Path(os.path.abspath(bundle_value))
    try:
        resolved = bundle.resolve(strict=True)
    except OSError as error:
        raise Refusal(f"missing bundle directory: {error}") from error
    if resolved != bundle:
        raise Refusal("bundle path must not contain symlink components")
    files, directories = _scan_tree(bundle, max_files=1100,
                                    max_total=ASSET_TOTAL_LIMIT + MANIFEST_LIMIT + SIGNATURE_LIMIT)
    manifest_raw = _read_relative(bundle, "release.json", MANIFEST_LIMIT, "release manifest")
    signature = _read_relative(bundle, "release.json.sig", SIGNATURE_LIMIT, "release signature")
    manifest, assets, sdk_files = _release_manifest(manifest_raw)
    expected_paths = set(assets) | {"release.json", "release.json.sig"}
    if set(files) != expected_paths:
        extras, missing = sorted(set(files) - expected_paths), sorted(expected_paths - set(files))
        raise Refusal(f"bundle file set mismatch: extra={extras[:3]} missing={missing[:3]}")
    if directories != _ancestors(expected_paths):
        raise Refusal("bundle contains an unlisted or missing directory")

    trust = _load_trust(trust_value, bundle)
    trust_digest = _sha(trust["key_raw"])
    bundled_digests = ({entry[1] for entry in assets.values()}
                       | {entry[1] for entry in sdk_files.values()}
                       | {_sha(manifest_raw), _sha(signature)})
    if trust_digest in bundled_digests:
        raise Refusal("trusted public key is also bundled; self-trust is forbidden")
    _verify_signature(manifest_raw, signature, trust, bundle)

    asset_data = {}
    for name, (size, digest) in assets.items():
        if files[name].st_size != size:
            raise Refusal(f"asset byte length mismatch: {name}")
        content = _read_relative(bundle, name, ASSET_LIMIT, f"asset {name}")
        if len(content) != size or _sha(content) != digest:
            raise Refusal(f"asset identity mismatch: {name}")
        asset_data[name] = content
    sdk_files_data, sdk_modes = _verify_archive(asset_data["sdk.tar.xz"], sdk_files)
    sdk_manifest_raw = sdk_files_data["contract/sdk.json"]
    if _sha(sdk_manifest_raw) != manifest["sdk_manifest_sha256"]:
        raise Refusal("SDK manifest digest mismatch")
    sdk_manifest = _json(sdk_manifest_raw, "SDK manifest")
    if sdk_manifest.get("schema") != "ami-rust-sdk-v1":
        raise Refusal("incompatible SDK manifest in archive")
    if sdk_manifest.get("version") != manifest["version"] or sdk_manifest.get("qualification_only") is not True:
        raise Refusal("SDK and outer release version/qualification fields differ")
    declared_sdk = _inventory(sdk_manifest.get("files"), "inner SDK file", count_limit=ARCHIVE_MEMBERS_LIMIT,
                              total_limit=ARCHIVE_LIMIT, file_limit=ARCHIVE_LIMIT)
    for name, value in declared_sdk.items():
        if sdk_files.get(name) != value:
            raise Refusal("inner SDK inventory differs from the signed archive inventory")
    executable_files = {name for name in sdk_files if name.startswith(("host/", "crates/", "native/", "targets/", "tests/", "examples/"))}
    if not executable_files <= set(declared_sdk):
        raise Refusal("inner SDK inventory omits an executable/host source file")
    return {"host": host, "bundle": bundle, "manifest": manifest,
            "manifest_raw": manifest_raw, "manifest_sha256": _sha(manifest_raw),
            "signature": signature, "assets": asset_data,
            "sdk_files": sdk_files_data, "sdk_modes": sdk_modes,
            "trust": trust}


def _home():
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)


def _secure_user_directory(directory, label):
    if not directory.is_absolute():
        raise Refusal(f"{label} must be absolute")
    try:
        resolved = directory.resolve(strict=True)
    except OSError as error:
        raise Refusal(f"missing {label}: {error}") from error
    if resolved != directory or not directory.is_dir():
        raise Refusal(f"{label} must have no symlink components")
    _validate_directory_ancestors(directory, label, user_owned_leaf=True)
    return directory


def _validate_directory_ancestors(directory, label, *, user_owned_leaf,
                                   allow_root_sticky_leaf=False):
    uid = os.getuid()
    for index, path in enumerate([directory, *directory.parents]):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise Refusal(f"{label} ancestor must be a real directory: {path}")
        if info.st_uid not in (0, uid):
            raise Refusal(f"{label} ancestor has an unexpected owner: {path}")
        if index == 0:
            root_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if user_owned_leaf and info.st_uid != uid:
                raise Refusal(f"{label} must be owned by the current user: {path}")
            if user_owned_leaf and info.st_mode & 0o022:
                raise Refusal(f"{label} must not be group/world writable: {path}")
            if allow_root_sticky_leaf and root_sticky:
                continue
        else:
            if info.st_uid not in (0, uid):
                raise Refusal(f"{label} ancestor has an unexpected owner: {path}")
        writable = bool(info.st_mode & 0o022)
        root_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if writable and not root_sticky:
            raise Refusal(f"{label} ancestor is group/world writable: {path}")


def _protected_input(path, label):
    info = path.lstat()
    if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise Refusal(f"unsafe ownership/write permissions for {label}")
    _validate_directory_ancestors(path.parent, label, user_owned_leaf=False)


def _fsync_dir(path):
    """Best-effort directory fsync where the host filesystem supports it."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(str(path), flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Some filesystems do not support fsync on directories. File contents
        # are still individually fsynced before their directory is published.
        return False
    return True


def _fsync_tree_dirs(root):
    directories = []
    for current, names, _ in os.walk(root, topdown=False, followlinks=False):
        directories.append(Path(current))
    for directory in directories:
        _fsync_dir(directory)


def _private_temp_root(*, forbidden=()):
    explicit = os.environ.get("TMPDIR")
    if explicit:
        if not Path(explicit).is_absolute():
            raise Refusal("TMPDIR must be an absolute path")
        candidate = Path(os.path.abspath(explicit))
        try:
            candidate = candidate.resolve(strict=True)
            info = candidate.lstat()
        except OSError as error:
            raise Refusal(f"cannot validate TMPDIR: {error}") from error
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise Refusal("explicit TMPDIR must be a current-user-owned directory")
        if info.st_mode & 0o077:
            raise Refusal("explicit TMPDIR must be private to the current user")
        _secure_user_directory(candidate, "TMPDIR")
    else:
        candidate = Path(tempfile.gettempdir())
        try:
            candidate = candidate.resolve(strict=True)
            info = candidate.lstat()
        except OSError as error:
            raise Refusal(f"cannot validate system temporary directory: {error}") from error
        if not stat.S_ISDIR(info.st_mode):
            raise Refusal("system temporary directory must be a real directory")
        uid = os.getuid()
        private_user_dir = info.st_uid == uid and not (info.st_mode & 0o077)
        root_sticky_dir = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if not (private_user_dir or root_sticky_dir):
            raise Refusal("system temporary directory is neither private nor root-owned sticky")
        _validate_directory_ancestors(candidate, "system temporary directory",
                                      user_owned_leaf=private_user_dir,
                                      allow_root_sticky_leaf=root_sticky_dir)
    for item in forbidden:
        reserved = Path(item).resolve(strict=True)
        if candidate == reserved or reserved in candidate.parents:
            raise Refusal("temporary directory must be outside the protected tree")
    return candidate


def _install_target(value):
    path = _canonical_absolute(value, "installation prefix")
    if path == Path("/") or path == _home():
        raise Refusal("installation prefix may not be root or the home directory")
    cwd = Path.cwd().resolve(strict=True)
    if path == cwd or path in cwd.parents:
        raise Refusal("installation prefix may not replace the current working directory or an ancestor")
    parent = path.parent
    _secure_user_directory(parent, "installation parent")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise Refusal("installation prefix must be fresh")
    if path.name in ("", ".", ".."):
        raise Refusal("invalid installation prefix")
    return path


def _pin_target(value, prefix):
    if not isinstance(value, str) or not value:
        raise Refusal("receipt pin path is required")
    path = Path(os.path.abspath(value))
    if path == Path("/") or path == _home() or path == prefix or path in prefix.parents or prefix in path.parents:
        raise Refusal("receipt pin must be a fresh file outside the installation prefix")
    parent = path.parent
    _secure_user_directory(parent, "receipt pin parent")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise Refusal("receipt pin path must be fresh")
    if path.name in ("", ".", ".."):
        raise Refusal("invalid receipt pin path")
    return path


def _fresh_output(value):
    if not isinstance(value, str) or not value:
        raise Refusal("output JSON path is required")
    path = Path(os.path.abspath(value))
    _secure_user_directory(path.parent, "output parent")
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    raise Refusal("output JSON path must be fresh")


def rename_exclusive(source, destination):
    """Atomically rename without replacing an existing destination."""
    source = Path(os.path.abspath(os.fspath(source)))
    destination = Path(os.path.abspath(os.fspath(destination)))
    if source.parent != destination.parent:
        raise Refusal("exclusive rename requires source and destination siblings")
    try:
        if source.parent.resolve(strict=True) != destination.parent.resolve(strict=True):
            raise Refusal("exclusive rename parents must resolve to the same directory")
        source_info = source.lstat()
    except OSError as error:
        raise Refusal(f"exclusive rename source is unavailable: {error}") from error
    if stat.S_ISLNK(source_info.st_mode) or not (
            stat.S_ISDIR(source_info.st_mode) or stat.S_ISREG(source_info.st_mode)):
        raise Refusal("exclusive rename source must be a regular file or directory")
    if os.name != "posix":
        raise Refusal("exclusive atomic rename is supported only on macOS and Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    encoded_source, encoded_destination = os.fsencode(source), os.fsencode(destination)
    if platform.system() == "Darwin":
        try:
            function = libc.renamex_np
        except AttributeError as error:
            raise Refusal("renamex_np is unavailable; refusing nonexclusive rename") from error
        function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        result = function(encoded_source, encoded_destination, 0x00000004)  # RENAME_EXCL
    elif platform.system() == "Linux":
        try:
            function = libc.renameat2
        except AttributeError as error:
            raise Refusal("renameat2 is unavailable; refusing nonexclusive rename") from error
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        result = function(-100, encoded_source, -100, encoded_destination, 1)  # NOREPLACE
    else:
        raise Refusal("exclusive atomic rename is supported only on macOS and Linux")
    if result != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise Refusal("destination already exists")
        raise Refusal(f"exclusive atomic rename failed: {os.strerror(number)}")


def _write_new(path, data, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags, mode)
    except OSError as error:
        raise Refusal(f"cannot create fresh file {path}: {error}") from error
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _write_fresh_atomic(path, data):
    temp = path.parent / f".{path.name}.ami-rust-{secrets.token_hex(12)}.tmp"
    try:
        _write_new(temp, data)
        rename_exclusive(temp, path)
        _fsync_dir(path.parent)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _mkdirs(root, relative):
    parts = _portable_path(relative, "installed path")
    current = root
    for part in parts:
        current = current / part
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise Refusal(f"installation path conflict: {current}")
        os.chmod(current, 0o755)


def _write_tree_file(root, relative, data, mode):
    parts = _portable_path(relative, "installed file path")
    if len(parts) > 1:
        _mkdirs(root, "/".join(parts[:-1]))
    path = root.joinpath(*parts)
    _write_new(path, data, mode & 0o777)


def _tree_inventory(root):
    files, _ = _scan_tree(root, max_files=2002, max_total=INSTALLED_LIMIT)
    result = []
    for name in sorted(files):
        data = _read_relative(root, name, INSTALLED_LIMIT, f"installed file {name}")
        result.append({"path": name, "bytes": len(data), "sha256": _sha(data)})
    return result


def _signal_cleanup_handler():
    previous = signal.getsignal(signal.SIGTERM)

    def stop(signum, frame):
        raise SigtermRequested("installation interrupted by SIGTERM")

    signal.signal(signal.SIGTERM, stop)
    return previous


class SigtermRequested(Exception):
    pass


def _install(bundle, trust, prefix, receipt_pin=None):
    """Install only the legacy offline-signature qualification candidate."""
    return _install_verified(verify_bundle(bundle, trust), prefix, receipt_pin)


def _install_verified(verified, prefix, receipt_pin=None):
    """Publish an already-verified result using the shared atomic installer."""
    prefix = _install_target(prefix)
    pin = _pin_target(receipt_pin, prefix) if receipt_pin is not None else None
    bundle_root = verified["bundle"]
    if (prefix == bundle_root or prefix in bundle_root.parents
            or bundle_root in prefix.parents):
        raise Refusal("installation prefix must be outside the release bundle")
    if pin is not None and bundle_root in pin.parents:
        raise Refusal("receipt pin must be outside the release bundle")
    stage = prefix.parent / f".{prefix.name}.stage-{secrets.token_hex(12)}"
    previous = _signal_cleanup_handler()
    published = False
    stage_created = False
    try:
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        try:
            stage.mkdir(mode=0o700)
            stage_created = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        os.chmod(stage, 0o700)
        (stage / "sdk").mkdir(mode=0o755)
        (stage / "payload").mkdir(mode=0o755)
        for name, content in verified["sdk_files"].items():
            archive_mode = verified["sdk_modes"].get(name, 0o644)
            safe_mode = 0o755 if archive_mode & 0o111 else 0o644
            _write_tree_file(stage / "sdk", name, content, safe_mode)
        for name, content in verified["assets"].items():
            _write_tree_file(stage / "payload", name, content, 0o644)
        _write_tree_file(stage, "payload/release.json", verified["manifest_raw"], 0o644)
        _write_tree_file(stage, "payload/release.json.sig", verified["signature"], 0o644)
        inventory = _tree_inventory(stage)
        production = verified.get("authentication") is not None
        receipt = {
            "schema": "ami-rust-install-receipt-v2" if production else "ami-rust-install-receipt-v1",
            "publisher": ("metaneutrons.ami-rust.github" if production
                          else verified["trust"]["publisher"]),
            "release_manifest_sha256": verified["manifest_sha256"],
            "sdk_manifest_sha256": verified["manifest"]["sdk_manifest_sha256"],
            "version": verified["manifest"]["version"],
            "inventory": inventory,
        }
        if production:
            receipt["authentication"] = verified["authentication"]
        receipt_raw = (json.dumps(receipt, sort_keys=True, indent=2,
                                  ensure_ascii=True) + "\n").encode("ascii")
        _write_new(stage / "install-receipt.json", receipt_raw)
        receipt_digest = _sha(receipt_raw)
        _fsync_tree_dirs(stage)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        try:
            rename_exclusive(stage, prefix)
            published = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        _fsync_dir(prefix.parent)
        if pin is not None:
            try:
                _write_fresh_atomic(pin, (receipt_digest + "\n").encode("ascii"))
            except Exception as error:
                raise PinWriteFailure(prefix, receipt_digest, str(error)) from error
    except SigtermRequested as error:
        if published:
            if pin is not None:
                raise PinWriteFailure(prefix, receipt_digest, str(error)) from error
            raise PublishedInterruption(prefix, receipt_digest) from error
        raise
    finally:
        signal.signal(signal.SIGTERM, previous)
        if stage_created and not published:
            try:
                shutil.rmtree(stage)
            except FileNotFoundError:
                pass
    return {"status": "installed", "prefix": str(prefix),
            "receipt_sha256": receipt_digest,
            "receipt_pin": str(pin) if pin else None,
            "publisher": receipt["publisher"],
            "release_manifest_sha256": verified["manifest_sha256"],
            "version": verified["manifest"]["version"],
            "qualification_only": verified["manifest"]["qualification_only"],
            "provenance": ("GitHub Actions and Cosign publisher evidence verified under external policy"
                           if production else
                           "OpenSSH manifest signature verified; Cosign/GitHub Actions provenance not verified"),
            "claim": ("publisher evidence and candidate bytes verified; this does not establish R1 qualification"
                      if production else
                      "candidate bytes verified; this does not establish R1 qualification")}


def _validate_authentication(authentication, manifest_sha256):
    if not isinstance(authentication, dict) or set(authentication) != {"report", "external_policy_sha256"}:
        raise Refusal("invalid receipt authentication evidence")
    _digest_text(authentication.get("external_policy_sha256"), "external publisher policy")
    report = authentication.get("report")
    fields = {"schema", "verified", "repository", "workflow", "workflowSha", "sourceSha",
              "sourceRef", "manifestSha256", "workflowRuns", "attestedSubjects",
              "manifestBoundAssets", "cosignSubjects", "publisherPolicyEvidence",
              "verificationMode", "elapsedSeconds"}
    if not isinstance(report, dict) or set(report) != fields:
        raise Refusal("invalid publisher verification report fields")
    if (report.get("schema") != "ami-rust-publisher-verification-v2"
            or report.get("verified") is not True
            or report.get("repository") != "metaneutrons/ami-rust"
            or report.get("workflow") != ".github/workflows/sdk-qualify.yml"
            or report.get("sourceRef") != "refs/heads/main"):
        raise Refusal("publisher verification report identity mismatch")
    for name in ("workflowSha", "sourceSha"):
        value = report.get(name)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise Refusal(f"invalid publisher report {name}")
    if report.get("manifestSha256") != manifest_sha256:
        raise Refusal("publisher report does not bind the installed release manifest")
    direct = ["SHAUTIL", "release.json", "sdk.tar.xz"]
    if report.get("attestedSubjects") != direct or report.get("cosignSubjects") != direct:
        raise Refusal("publisher report subject identity mismatch")
    assets = report.get("manifestBoundAssets")
    if (not isinstance(assets, list) or not assets
            or any(not isinstance(item, str) for item in assets)
            or assets != sorted(set(assets))):
        raise Refusal("invalid publisher report manifest-bound asset list")
    runs = report.get("workflowRuns")
    if not isinstance(runs, list) or len(runs) != 1:
        raise Refusal("publisher report must identify exactly one workflow run")
    run = runs[0]
    if (not isinstance(run, dict) or set(run) != {"runId", "runAttempt", "hostProfile"}
            or type(run.get("runId")) is not int or run["runId"] <= 0
            or type(run.get("runAttempt")) is not int or run["runAttempt"] <= 0
            or run.get("hostProfile") not in HOSTS):
        raise Refusal("invalid publisher report workflow run")
    if (report.get("publisherPolicyEvidence") != (
            "environment and runnerEnvironment are signed SLSA predicate claims verified under the exact pinned workflow SHA; "
            "they are not independent Fulcio certificate fields")
            or report.get("verificationMode") != "offline pinned GH bundle/custom root and Cosign bundle/trusted root"):
        raise Refusal("publisher report verification description mismatch")
    elapsed = report.get("elapsedSeconds")
    if type(elapsed) not in (int, float) or elapsed < 0 or elapsed > 300:
        raise Refusal("invalid publisher report elapsed time")
    return report


def _validate_receipt(raw):
    if len(raw) > RECEIPT_LIMIT:
        raise Refusal("oversized installation receipt")
    receipt = _json(raw, "installation receipt")
    common = {"publisher", "release_manifest_sha256", "sdk_manifest_sha256", "version", "inventory"}
    schema = receipt.get("schema")
    required = common | ({"authentication"} if schema == "ami-rust-install-receipt-v2" else set()) | {"schema"}
    if set(receipt) != required or schema not in ("ami-rust-install-receipt-v1", "ami-rust-install-receipt-v2"):
        raise Refusal("incompatible installation receipt")
    if schema == "ami-rust-install-receipt-v2":
        if receipt.get("publisher") != "metaneutrons.ami-rust.github":
            raise Refusal("invalid production receipt publisher")
        _validate_authentication(receipt.get("authentication"), receipt.get("release_manifest_sha256"))
    elif not isinstance(receipt.get("publisher"), str) or not PRINCIPAL.fullmatch(receipt["publisher"]):
        raise Refusal("invalid receipt publisher")
    _digest_text(receipt.get("release_manifest_sha256"), "receipt release manifest")
    _digest_text(receipt.get("sdk_manifest_sha256"), "receipt SDK manifest")
    if not isinstance(receipt.get("version"), str) or not VERSION.fullmatch(receipt["version"]):
        raise Refusal("invalid receipt version")
    inventory = _inventory(receipt.get("inventory"), "receipt file", count_limit=2002,
                           total_limit=INSTALLED_LIMIT, file_limit=INSTALLED_LIMIT)
    if any(not (name.startswith("sdk/") or name.startswith("payload/")) for name in inventory):
        raise Refusal("receipt inventory contains a path outside sdk/ and payload/")
    if {"payload/release.json", "payload/release.json.sig", "sdk/contract/sdk.json"} - set(inventory):
        raise Refusal("receipt inventory is missing required installation metadata")
    return receipt, inventory


def _installed(prefix, expected_receipt_sha=None):
    prefix = _canonical_absolute(prefix, "installation prefix")
    _secure_user_directory(prefix.parent, "installation parent")
    try:
        resolved = prefix.resolve(strict=True)
        info = prefix.lstat()
    except OSError as error:
        raise Refusal(f"missing installation prefix: {error}") from error
    if resolved != prefix or not stat.S_ISDIR(info.st_mode):
        raise Refusal("installation prefix must be a real directory without symlinks")
    uid = os.getuid()
    if info.st_uid != uid or info.st_mode & 0o022:
        raise Refusal("installation prefix must be user-owned and not group/world writable")
    receipt_path = prefix / "install-receipt.json"
    try:
        receipt_info = receipt_path.lstat()
    except OSError as error:
        raise Refusal(f"missing installation receipt: {error}") from error
    if (not stat.S_ISREG(receipt_info.st_mode) or receipt_info.st_uid != uid
            or receipt_info.st_mode & 0o022):
        raise Refusal("installation receipt must be a safely user-owned regular file")
    raw = _read_relative(prefix, "install-receipt.json", RECEIPT_LIMIT,
                         "installation receipt")
    receipt_sha = _sha(raw)
    if expected_receipt_sha is not None:
        _digest_text(expected_receipt_sha, "external receipt pin")
        if receipt_sha != expected_receipt_sha:
            raise Refusal("installation receipt does not match the external receipt pin")
    receipt, inventory = _validate_receipt(raw)
    actual, directories = _scan_tree(prefix, max_files=2003, max_total=INSTALLED_LIMIT)
    actual_paths = set(actual) - {"install-receipt.json"}
    if actual_paths != set(inventory):
        extras, missing = sorted(actual_paths - set(inventory)), sorted(set(inventory) - actual_paths)
        raise Refusal(f"installed file set mismatch: extra={extras[:3]} missing={missing[:3]}")
    expected_dirs = _ancestors(set(inventory) | {"install-receipt.json"})
    if directories != expected_dirs:
        raise Refusal("installation contains an unexpected or missing directory")
    for name, (size, digest) in inventory.items():
        path = prefix.joinpath(*name.split("/"))
        info = actual[name]
        if info.st_uid != uid or info.st_mode & 0o022:
            raise Refusal(f"installed file is not safely user-owned: {name}")
        content = _read_relative(prefix, name, INSTALLED_LIMIT, f"installed file {name}")
        if len(content) != size or _sha(content) != digest:
            raise Refusal(f"installed file identity mismatch: {name}")
    manifest_raw = _read_relative(prefix, "payload/release.json", MANIFEST_LIMIT,
                                  "installed release manifest")
    if _sha(manifest_raw) != receipt["release_manifest_sha256"]:
        raise Refusal("installed release manifest identity mismatch")
    production_receipt = receipt["schema"] == "ami-rust-install-receipt-v2"
    manifest, assets, sdk_files = _release_manifest(manifest_raw, production=production_receipt)
    if production_receipt and manifest["qualification_only"] is not False:
        raise Refusal("production receipt requires a non-qualification release manifest")
    if not production_receipt and manifest["qualification_only"] is not True:
        raise Refusal("legacy receipt requires a qualification-only release manifest")
    if (production_receipt
            and receipt["authentication"]["report"]["manifestBoundAssets"] != sorted(assets)):
        raise Refusal("publisher report assets do not match the installed release manifest")
    if manifest["version"] != receipt["version"] or manifest["sdk_manifest_sha256"] != receipt["sdk_manifest_sha256"]:
        raise Refusal("receipt and release manifest metadata differ")
    expected = {"payload/release.json", "payload/release.json.sig"}
    expected.update("payload/" + name for name in assets)
    expected.update("sdk/" + name for name in sdk_files)
    if expected != set(inventory):
        raise Refusal("receipt inventory does not match the release and SDK manifests")
    for name, (size, digest) in assets.items():
        if inventory["payload/" + name] != (size, digest):
            raise Refusal(f"receipt does not preserve release asset identity: {name}")
    for name, (size, digest) in sdk_files.items():
        if inventory["sdk/" + name] != (size, digest):
            raise Refusal(f"receipt does not preserve SDK archive identity: {name}")
    if _sha(_read_relative(prefix, "sdk/contract/sdk.json", MANIFEST_LIMIT,
                           "installed SDK manifest")) != receipt["sdk_manifest_sha256"]:
        raise Refusal("installed SDK manifest identity mismatch")
    return prefix, receipt, receipt_sha, manifest


def _uninstall(prefix, receipt_sha256):
    prefix = _canonical_absolute(prefix, "installation prefix")
    if prefix == Path("/") or prefix == _home():
        raise Refusal("refusing to uninstall root or the home directory")
    cwd = Path.cwd().resolve(strict=True)
    if prefix == cwd or prefix in cwd.parents:
        raise Refusal("refusing to uninstall the current working directory or an ancestor")
    prefix, receipt, digest, _ = _installed(prefix, receipt_sha256)
    tombstone = prefix.parent / f".{prefix.name}.remove-{secrets.token_hex(12)}"
    rename_exclusive(prefix, tombstone)
    _fsync_dir(prefix.parent)
    try:
        # Recheck after the atomic move. shutil.rmtree does not follow symlinks.
        _installed(tombstone, receipt_sha256)
    except Exception:
        if tombstone.exists() and not prefix.exists():
            rename_exclusive(tombstone, prefix)
            _fsync_dir(prefix.parent)
        raise
    # If recursive removal is interrupted, leave the hidden tombstone for
    # recovery instead of restoring a partially deleted tree at its old name.
    shutil.rmtree(tombstone)
    _fsync_dir(prefix.parent)
    return {"status": "uninstalled", "prefix": str(prefix),
            "receipt_sha256": digest, "version": receipt["version"]}


def _selection(path_value):
    path = Path(path_value)
    if not path.is_absolute():
        path = Path(os.path.abspath(path))
    try:
        if path.resolve(strict=True) != path:
            raise Refusal("selection path may not contain symlinks")
    except OSError as error:
        raise Refusal(f"missing selection JSON: {error}") from error
    selection = _json(_read_fd(path, 1024 * 1024, "selection JSON"), "selection JSON")
    if not all(key in selection for key in ("python", "components")):
        raise Refusal("selection JSON requires python and components")
    components = selection.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise Refusal("selection components must name exactly the six SDK components")
    canonical = {}
    for name in COMPONENTS:
        value = components[name]
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise Refusal(f"selection component must be an absolute path: {name}")
        try:
            path = Path(value)
            resolved = path.resolve(strict=True)
            info = path.lstat()
        except OSError as error:
            raise Refusal(f"missing selection component {name}: {error}") from error
        if resolved != path or not stat.S_ISDIR(info.st_mode):
            raise Refusal(f"selection component must be a real directory: {name}")
        canonical[name] = str(path)
    python_value = selection.get("python")
    if not isinstance(python_value, str):
        raise Refusal("selection python must be an absolute executable path")
    python = _real_regular(python_value, "selected Python", executable=True)
    return selection, python, canonical


def _minimal_env():
    return {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}


def _lock(prefix, selection_value, project_value, output_value):
    output = _fresh_output(output_value)
    prefix, receipt, receipt_sha, manifest = _installed(prefix)
    if prefix in output.parents:
        raise Refusal("project lock output must be outside the installed SDK prefix")
    project = _canonical_absolute(project_value, "project directory")
    try:
        if project.resolve(strict=True) != project or not project.is_dir():
            raise Refusal("project directory must be a real directory without symlinks")
    except OSError as error:
        raise Refusal(f"missing project directory: {error}") from error
    selection, python, components = _selection(selection_value)
    binding_path = project / "ami-rust-sdk.json"
    if binding_path.exists() or binding_path.is_symlink():
        binding = _json(_read_fd(binding_path, 4096, "project SDK binding"), "project SDK binding")
        expected = {"schema": "ami-rust-project-sdk-binding-v1", "version": manifest["version"],
                    "sdk_manifest_sha256": manifest["sdk_manifest_sha256"]}
        if binding != expected:
            raise Refusal("project SDK binding differs from selected installation")
    host = _host_key()
    python_sha = _sha_file(python)
    if python_sha != manifest["host_interpreters"][host]["sha256"]:
        raise Refusal("selected Python does not match the release host_interpreters pin")
    for name in ("Cargo.toml", "Cargo.lock"):
        path = project / name
        try:
            if path.resolve(strict=True) != path or not stat.S_ISREG(path.lstat().st_mode):
                raise Refusal(f"project {name} must be a regular non-symlink file")
        except OSError as error:
            raise Refusal(f"project requires {name}: {error}") from error
    lock = {
        "schema": "ami-rust-project-lock-v1",
        "sdk": {"root": str(prefix / "sdk"), "manifest": "contract/sdk.json",
                "manifest_sha256": receipt["sdk_manifest_sha256"]},
        "host": {"platform": host, "python": str(python), "python_sha256": python_sha},
        "components": components,
        "cargo": {"manifest_sha256": _sha_file(project / "Cargo.toml"),
                  "lock_sha256": _sha_file(project / "Cargo.lock")},
    }
    temp_parent = _private_temp_root(forbidden=(prefix, project))
    with tempfile.TemporaryDirectory(prefix="ami-rust-lock-", dir=str(temp_parent)) as temp:
        lock_path = Path(temp) / "project-lock.json"
        lock_raw = (json.dumps(lock, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _write_new(lock_path, lock_raw)
        cli = prefix / "sdk" / "host" / "cli.py"
        try:
            result = subprocess.run([str(python), "-I", "-B", str(cli), "verify",
                                     "--sdk-lock", str(lock_path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=30, check=False, env=_minimal_env())
        except subprocess.TimeoutExpired as error:
            raise Refusal("installed ami-rust CLI verification timed out") from error
        except OSError as error:
            raise Refusal(f"cannot execute pinned Python/ami-rust CLI: {error}") from error
        if result.returncode != 0:
            raise Refusal("installed ami-rust CLI rejected the generated project lock")
        response = _json(result.stdout, "ami-rust CLI verification response")
        if (response.get("host") != host
                or response.get("sdk_manifest_sha256") != receipt["sdk_manifest_sha256"]):
            raise Refusal("installed ami-rust CLI verification response does not match this SDK")
    if _sha_file(python) != python_sha:
        raise Refusal("selected Python changed during lock verification")
    _installed(prefix)
    for name in ("Cargo.toml", "Cargo.lock"):
        if _sha_file(project / name) != lock["cargo"]["manifest_sha256" if name == "Cargo.toml" else "lock_sha256"]:
            raise Refusal(f"project {name} changed during lock verification")
    raw = (json.dumps(lock, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _write_fresh_atomic(output, raw)
    return {"status": "locked", "output": str(output),
            "sdk_manifest_sha256": receipt["sdk_manifest_sha256"],
            "receipt_sha256": receipt_sha, "host": host,
            "claim": "project pins verified by the installed CLI; this does not re-establish release publisher trust or R1 qualification"}


def _verify_command(args):
    result = verify_bundle(args.bundle, args.trust)
    return {"status": "verified", "publisher": result["trust"]["publisher"],
            "public_key_sha256": result["trust"]["public_key_sha256"],
            "release_manifest_sha256": result["manifest_sha256"],
            "version": result["manifest"]["version"], "host": result["host"],
            "qualification_only": True,
            "provenance": "OpenSSH manifest signature verified; Cosign/GitHub Actions provenance not verified",
            "claim": "candidate bytes verified against the supplied offline trust file; publisher identity binding and R1 qualification are not established"}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline ami-rust candidate verifier and user-owned installer. "
                    "Does not verify Cosign/GitHub Actions provenance or qualify R1.")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify a bundle against external offline trust")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--trust", required=True)
    install = commands.add_parser("install", help="verify and install a candidate into a fresh prefix")
    install.add_argument("--bundle", required=True)
    install.add_argument("--trust", required=True)
    install.add_argument("--prefix", required=True)
    install.add_argument("--receipt-pin", help="fresh external file for the receipt SHA-256")
    uninstall = commands.add_parser("uninstall", help="remove only an installation with its externally pinned receipt")
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
            result = _install(args.bundle, args.trust, args.prefix, args.receipt_pin)
        elif args.command == "uninstall":
            result = _uninstall(args.prefix, args.receipt_sha256)
        else:
            result = _lock(args.prefix, args.selection, args.project, args.output)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except PinWriteFailure as error:
        print(json.dumps({"status": "installed_receipt_pin_failed",
                          "prefix": error.prefix,
                          "receipt_sha256": error.receipt_sha256,
                          "error": str(error)}, sort_keys=True, separators=(",", ":")),
              file=sys.stderr)
        return 1
    except PublishedInterruption as error:
        print(json.dumps({"status": "installed_interrupted",
                          "prefix": error.prefix,
                          "receipt_sha256": error.receipt_sha256,
                          "error": str(error)}, sort_keys=True, separators=(",", ":")),
              file=sys.stderr)
        return 1
    except (Refusal, OSError, InterruptedError, tarfile.TarError, lzma.LZMAError,
            subprocess.SubprocessError) as error:
        print(f"ami-rust installer: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

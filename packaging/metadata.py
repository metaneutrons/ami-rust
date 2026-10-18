#!/usr/bin/env python3
"""Generate Homebrew and SPDX metadata for a verified ami-rust package build."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any
from urllib.parse import quote, urlparse
import uuid


PINS_SCHEMA = "ami-rust-package-inputs-v1"
BUILD_REPORT_SCHEMA = "ami-rust-packaging-report-v1"
INVENTORY_SCHEMA = "ami-rust-package-inventory-v1"
REPORT_SCHEMA = "ami-rust-packaging-metadata-report-v1"
REPOSITORY = "metaneutrons/ami-rust"
MAX_EPOCH = (1 << 33) - 1
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_ASSET_BYTES = 128 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_MEMBERS = 20_000
CHUNK_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
STABLE_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z"
)


class MetadataError(ValueError):
    """Raised when package outputs or source pins violate the metadata contract."""


def _canonical_json(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise MetadataError("metadata is not a valid JSON value") from error


def _parse_json(raw: bytes, label: str) -> Any:
    def unique_pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise MetadataError(f"{label} contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise MetadataError(f"{label} contains a nonstandard JSON constant: {value}")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise MetadataError(f"{label} is not valid bounded UTF-8 JSON") from error


def _read_regular(path: Path, label: str, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise MetadataError(f"cannot open {label}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise MetadataError(f"{label} must be a regular, non-linked file")
        if info.st_size <= 0 or info.st_size > limit:
            raise MetadataError(f"{label} is empty or exceeds its byte bound")
        pieces: list[bytes] = []
        remaining = limit + 1
        while remaining:
            block = os.read(fd, min(CHUNK_BYTES, remaining))
            if not block:
                break
            pieces.append(block)
            remaining -= len(block)
        raw = b"".join(pieces)
        if len(raw) > limit or len(raw) != info.st_size:
            raise MetadataError(f"{label} changed or exceeds its byte bound")
        return raw
    finally:
        os.close(fd)


def _read_json(path: Path, label: str, limit: int) -> tuple[Any, bytes]:
    raw = _read_regular(path, label, limit)
    value = _parse_json(raw, label)
    if type(value) is not dict:
        raise MetadataError(f"{label} must contain a JSON object")
    return value, raw


def _safe_file_name(value: Any, label: str) -> str:
    if (type(value) is not str or not value or value in {".", ".."}
            or "/" in value or "\\" in value or "\x00" in value
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", value) is None):
        raise MetadataError(f"{label} must be a safe flat filename")
    return value


def _safe_relative(value: Any, label: str) -> str:
    if (type(value) is not str or not value or value.startswith("/")
            or "\\" in value or "\x00" in value):
        raise MetadataError(f"{label} must be a safe relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise MetadataError(f"{label} must not contain traversal components")
    if PurePosixPath(value).as_posix() != value:
        raise MetadataError(f"{label} is not a canonical relative path")
    return value


def _validate_pins(pins: Any) -> dict[str, dict[str, Any]]:
    if type(pins) is not dict or pins.get("schema") != PINS_SCHEMA:
        raise MetadataError(f"pins must use schema {PINS_SCHEMA}")
    sdk_version = pins.get("sdk_version")
    revision = pins.get("packaging_revision")
    if type(sdk_version) is not str or STABLE_VERSION_RE.fullmatch(sdk_version) is None:
        raise MetadataError("pins sdk_version must be a canonical numeric stable SemVer")
    if type(revision) is not int or revision < 1:
        raise MetadataError("pins packaging_revision must be a positive integer")
    if (pins.get("repository") != REPOSITORY
            or pins.get("sdk_tag") != "v" + sdk_version
            or pins.get("package_version") != f"{sdk_version}-{revision}"
            or pins.get("packaging_tag") != f"v{sdk_version}+packaging.{revision}"):
        raise MetadataError("pins repository, tags or package version are inconsistent")
    for key in ("source_commit", "source_tree"):
        value = pins.get(key)
        if type(value) is not str or COMMIT_RE.fullmatch(value) is None:
            raise MetadataError(f"pins {key} is invalid")
    for key in ("manifest_sha256", "transport_sha256"):
        value = pins.get(key)
        if type(value) is not str or SHA256_RE.fullmatch(value) is None:
            raise MetadataError(f"pins {key} is invalid")
    if (type(pins.get("sdk_run_id")) is not int or pins["sdk_run_id"] <= 0
            or type(pins.get("sdk_run_attempt")) is not int or pins["sdk_run_attempt"] <= 0):
        raise MetadataError("pins SDK workflow run identity is invalid")

    records = pins.get("assets")
    if type(records) is not list or len(records) != 6:
        raise MetadataError("pins must contain exactly six SDK assets")
    release_archive = f"ami-rust-{sdk_version}-release.tar.xz"
    transport_name = f"ami-rust-{sdk_version}-transport.json"
    expected_names = {
        "SHA256SUMS",
        release_archive,
        release_archive + ".sigstore.json",
        release_archive + ".spdx.json",
        transport_name,
        transport_name + ".sigstore.json",
    }
    assets: dict[str, dict[str, Any]] = {}
    total = 0
    for record in records:
        if type(record) is not dict or set(record) != {"path", "bytes", "sha256"}:
            raise MetadataError("each SDK asset pin must contain only path, bytes and sha256")
        name = _safe_file_name(record["path"], "SDK asset path")
        size = record["bytes"]
        digest = record["sha256"]
        if name in assets:
            raise MetadataError("pins contain a duplicate SDK asset path")
        if type(size) is not int or not 1 <= size <= MAX_ASSET_BYTES:
            raise MetadataError(f"SDK asset pin size is invalid or oversized: {name}")
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise MetadataError(f"SDK asset pin SHA-256 is invalid: {name}")
        assets[name] = {"path": name, "bytes": size, "sha256": digest}
        total += size
    if set(assets) != expected_names:
        raise MetadataError("pins do not contain the exact six SDK assets for sdk_version")
    if total > MAX_TOTAL_ASSET_BYTES:
        raise MetadataError("pinned SDK assets exceed the total size bound")
    if pins["transport_sha256"] != assets[transport_name]["sha256"]:
        raise MetadataError("pins transport SHA-256 disagrees with its asset pin")
    try:
        if len(json.dumps(pins, ensure_ascii=False, allow_nan=False).encode("utf-8")) > MAX_SOURCE_BYTES:
            raise MetadataError("pins exceed the source metadata bound")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise MetadataError("pins contain values outside the JSON data model") from error
    return assets


def _file_digest(path: Path, label: str, limit: int = MAX_PACKAGE_BYTES) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise MetadataError(f"cannot open {label}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise MetadataError(f"{label} must be a regular, non-linked file")
        if info.st_size <= 0 or info.st_size > limit:
            raise MetadataError(f"{label} is empty or exceeds its byte bound")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, CHUNK_BYTES)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise MetadataError(f"{label} exceeds its byte bound")
            digest.update(block)
        if size != info.st_size:
            raise MetadataError(f"{label} changed while being hashed")
        return {"bytes": size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def _load_pins(source: Path) -> tuple[dict[str, Any], bytes, dict[str, dict[str, Any]]]:
    pins, raw = _read_json(source / "packaging" / "pins.json", "packaging/pins.json",
                           MAX_SOURCE_BYTES)
    return pins, raw, _validate_pins(pins)


def _expected_names(pins: dict[str, Any]) -> tuple[str, str]:
    archive = f"ami-rust-{pins['sdk_version']}-packaging.{pins['packaging_revision']}.tar.xz"
    deb = f"ami-rust_{pins['package_version']}_amd64.deb"
    return archive, deb


def _validate_build_report(package_output: Path, pins: dict[str, Any], epoch: int
                           ) -> tuple[dict[str, Any], bytes, dict[str, dict[str, Any]]]:
    report, raw = _read_json(package_output / "packaging-report.json",
                             "packaging-report.json", MAX_REPORT_BYTES)
    if (report.get("schema") != BUILD_REPORT_SCHEMA
            or report.get("sdk_version") != pins["sdk_version"]
            or report.get("package_version") != pins["package_version"]
            or report.get("packaging_tag") != pins["packaging_tag"]
            or type(report.get("epoch")) is not int or report["epoch"] != epoch):
        raise MetadataError("packaging-report.json identity differs from pins or requested epoch")
    archive_name, deb_name = _expected_names(pins)
    outputs = report.get("outputs")
    if type(outputs) is not dict or set(outputs) != {archive_name, deb_name}:
        raise MetadataError("packaging-report.json must identify the exact archive and Debian package")
    expected: dict[str, dict[str, Any]] = {}
    for name, row in outputs.items():
        _safe_file_name(name, "build output name")
        if type(row) is not dict or set(row) != {"bytes", "sha256"}:
            raise MetadataError(f"build output report row is malformed: {name}")
        if (type(row["bytes"]) is not int or not 1 <= row["bytes"] <= MAX_PACKAGE_BYTES
                or type(row["sha256"]) is not str or SHA256_RE.fullmatch(row["sha256"]) is None):
            raise MetadataError(f"build output report row is invalid: {name}")
        actual = _file_digest(package_output / name, name)
        if actual != row:
            raise MetadataError(f"package output differs from packaging-report.json: {name}")
        expected[name] = actual
    entries = list(package_output.iterdir())
    if ({path.name for path in entries} != set(expected) | {"packaging-report.json"}
            or any(not stat.S_ISREG(path.lstat().st_mode) for path in entries)):
        raise MetadataError("package output directory has unexpected or linked entries")
    inventory_sha = report.get("inventory_sha256")
    inventory_files = report.get("inventory_files")
    if (type(inventory_sha) is not str or SHA256_RE.fullmatch(inventory_sha) is None
            or type(inventory_files) is not int or inventory_files <= 0):
        raise MetadataError("packaging-report.json inventory identity is malformed")
    return report, raw, expected


def _read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo,
                     label: str, limit: int) -> bytes:
    if not member.isfile() or member.size <= 0 or member.size > limit:
        raise MetadataError(f"{label} is not a bounded regular archive file")
    stream = archive.extractfile(member)
    if stream is None:
        raise MetadataError(f"cannot read {label} from the package archive")
    with stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit or len(raw) != member.size:
        raise MetadataError(f"{label} changed or exceeds its archive bound")
    return raw


def _load_original_sdk_sbom(archive_path: Path, pins: dict[str, Any], assets: dict[str, dict[str, Any]],
                            report: dict[str, Any]) -> tuple[dict[str, Any], bytes, str]:
    package_version = pins["package_version"]
    archive_root = f"ami-rust-{package_version}"
    libexec = f"{archive_root}/usr/libexec/ami-rust/{package_version}"
    inventory_path = libexec + "/inventory.json"
    source_sbom_name = f"ami-rust-{pins['sdk_version']}-release.tar.xz.spdx.json"
    sbom_path = libexec + "/assets/" + source_sbom_name
    member_by_name: dict[str, tarfile.TarInfo] = {}
    total_size = 0
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_PACKAGE_MEMBERS:
                    raise MetadataError("package archive contains too many members")
                name = member.name
                normalized = name[:-1] if member.isdir() and name.endswith("/") else name
                if (not normalized or normalized.startswith("/") or "\\" in normalized
                        or "\x00" in normalized
                        or any(part in {"", ".", ".."} for part in normalized.split("/"))):
                    raise MetadataError("package archive contains an unsafe member path")
                if normalized != archive_root and not normalized.startswith(archive_root + "/"):
                    raise MetadataError("package archive contains a path outside its version root")
                if not (member.isdir() or member.isfile()):
                    raise MetadataError("package archive contains a link or unsupported member")
                if member.size < 0 or member.size > MAX_PACKAGE_MEMBER_BYTES:
                    raise MetadataError("package archive member exceeds its byte bound")
                if member.isfile():
                    total_size += member.size
                    if total_size > MAX_PACKAGE_BYTES:
                        raise MetadataError("package archive expands beyond its total byte bound")
                if normalized in member_by_name:
                    raise MetadataError("package archive contains a duplicate member path")
                member_by_name[normalized] = member
            inventory_member = member_by_name.get(inventory_path)
            sbom_member = member_by_name.get(sbom_path)
            if inventory_member is None or sbom_member is None:
                raise MetadataError("package archive lacks its inventory or original SDK SPDX asset")
            inventory_raw = _read_tar_member(
                archive, inventory_member, "package inventory", MAX_SOURCE_BYTES
            )
            if hashlib.sha256(inventory_raw).hexdigest() != report["inventory_sha256"]:
                raise MetadataError("packaged inventory SHA-256 differs from build report")
            inventory = _parse_json(inventory_raw, "packaged inventory")
            if type(inventory) is not dict or (
                inventory.get("schema") != INVENTORY_SCHEMA
                or inventory.get("sdk_version") != pins["sdk_version"]
                or inventory.get("package_version") != package_version
            ):
                raise MetadataError("packaged inventory identity differs from pins")
            rows = inventory.get("files")
            if (type(rows) is not list or len(rows) != report["inventory_files"]
                    or not rows or len(rows) > MAX_PACKAGE_MEMBERS):
                raise MetadataError("packaged inventory file count differs from build report")
            inventory_rows: dict[str, dict[str, Any]] = {}
            for row in rows:
                if type(row) is not dict or set(row) != {"path", "bytes", "sha256", "mode"}:
                    raise MetadataError("packaged inventory row is malformed")
                relative = _safe_relative(row["path"], "inventory path")
                if relative in inventory_rows:
                    raise MetadataError("packaged inventory repeats a path")
                if (type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_PACKAGE_MEMBER_BYTES
                        or type(row["sha256"]) is not str
                        or SHA256_RE.fullmatch(row["sha256"]) is None
                        or type(row["mode"]) is not int or row["mode"] < 0):
                    raise MetadataError("packaged inventory row has invalid file metadata")
                member = member_by_name.get(libexec + "/" + relative)
                if member is None or not member.isfile() or member.size != row["bytes"]:
                    raise MetadataError("packaged inventory differs from archive member sizes")
                inventory_rows[relative] = row
            for asset_name, pin in assets.items():
                row = inventory_rows.get("assets/" + asset_name)
                if (row is None or row["bytes"] != pin["bytes"]
                        or row["sha256"] != pin["sha256"]):
                    raise MetadataError(f"packaged SDK asset differs from its pin: {asset_name}")
            sbom_pin = assets[source_sbom_name]
            if sbom_member.size != sbom_pin["bytes"]:
                raise MetadataError("original SDK SPDX asset size differs from its pin")
            sbom_raw = _read_tar_member(
                archive, sbom_member, "original SDK SPDX asset", sbom_pin["bytes"]
            )
            sbom_sha = hashlib.sha256(sbom_raw).hexdigest()
            if sbom_sha != sbom_pin["sha256"]:
                raise MetadataError("original SDK SPDX asset SHA-256 differs from its pin")
    except MetadataError:
        raise
    except (OSError, EOFError, lzma.LZMAError, tarfile.TarError) as error:
        raise MetadataError("package archive cannot be read as a bounded xz tar archive") from error

    original = _parse_json(sbom_raw, "original SDK SPDX asset")
    if (type(original) is not dict or original.get("spdxVersion") != "SPDX-2.3"
            or original.get("SPDXID") != "SPDXRef-DOCUMENT"
            or type(original.get("name")) is not str or not original["name"]
            or type(original.get("documentNamespace")) is not str):
        raise MetadataError("original SDK SPDX asset lacks a valid SPDX 2.3 document identity")
    namespace = original["documentNamespace"]
    parsed_namespace = urlparse(namespace)
    if not parsed_namespace.scheme or "#" in namespace:
        raise MetadataError("original SDK SPDX document namespace must be absolute and fragment-free")
    return original, sbom_raw, sbom_sha


def _package_id(label: str, seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]
    return "SPDXRef-" + label + "-" + digest


def _make_sbom(payload_name: str, payload: dict[str, Any], pins: dict[str, Any],
               assets: dict[str, dict[str, Any]], original: dict[str, Any],
               original_sbom_sha: str, epoch: int) -> bytes:
    artifact_id = _package_id("Payload", payload_name + ":" + payload["sha256"])
    adapter_id = _package_id("Adapter", pins["source_commit"] + ":" + pins["package_version"])
    sdk_id = _package_id("SDK", pins["source_commit"] + ":" + pins["sdk_version"])
    namespace_uuid = uuid.uuid5(
        uuid.NAMESPACE_URL,
        "ami-rust-packaging-spdx:" + payload_name + ":" + payload["sha256"] + ":" + str(epoch),
    )
    namespace = (
        "https://spdx.org/spdxdocs/ami-rust-" + quote(payload_name, safe="-._")
        + "-" + str(namespace_uuid).upper()
    )
    created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    archive_name = f"ami-rust-{pins['sdk_version']}-release.tar.xz"
    archive_pin = assets[archive_name]
    release_url = (
        f"https://github.com/{REPOSITORY}/releases/download/"
        f"{quote(pins['packaging_tag'], safe='')}/{quote(payload_name, safe='')}"
    )
    packages = [
        {
            "name": "ami-rust",
            "SPDXID": artifact_id,
            "versionInfo": pins["package_version"],
            "packageFileName": payload_name,
            "downloadLocation": release_url,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "packageComment": (
                f"Exact downloaded payload file size: {payload['bytes']} bytes. "
                "The SHA-256 checksum is recorded in this package's checksums field."
            ),
            "checksums": [{"algorithm": "SHA256", "checksumValue": payload["sha256"]}],
            "primaryPackagePurpose": "APPLICATION",
        },
        {
            "name": "ami-rust-package-adapter",
            "SPDXID": adapter_id,
            "versionInfo": pins["package_version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "MIT OR Apache-2.0",
            "licenseComments": (
                "This declaration applies only to the package adapter. It does not apply "
                "to bundled SDK or third-party components."
            ),
            "copyrightText": "NOASSERTION",
        },
        {
            "name": "ami-rust-sdk",
            "SPDXID": sdk_id,
            "versionInfo": pins["sdk_version"],
            "packageFileName": archive_name,
            "downloadLocation": (
                f"https://github.com/{REPOSITORY}/releases/download/"
                f"{quote(pins['sdk_tag'], safe='')}/{quote(archive_name, safe='')}"
            ),
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "licenseComments": (
                "Per-component SDK and third-party licensing remains in the unchanged "
                "original publisher SPDX document referenced as DocumentRef-OriginalSDK."
            ),
            "copyrightText": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": archive_pin["sha256"]}],
        },
    ]
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": artifact_id},
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": adapter_id},
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": sdk_id},
        {"spdxElementId": artifact_id, "relationshipType": "CONTAINS",
         "relatedSpdxElement": adapter_id},
        {"spdxElementId": artifact_id, "relationshipType": "CONTAINS",
         "relatedSpdxElement": sdk_id},
        {"spdxElementId": sdk_id, "relationshipType": "DESCRIBED_BY",
         "relatedSpdxElement": "DocumentRef-OriginalSDK:SPDXRef-DOCUMENT"},
    ]
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": payload_name + " SBOM",
        "documentNamespace": namespace,
        "creationInfo": {
            "creators": ["Tool: ami-rust-packaging-metadata-1"],
            "created": created,
        },
        "documentComment": (
            "The MIT OR Apache-2.0 declaration applies only to the package adapter. "
            "The included SDK and third-party components retain their individual licenses; "
            "the original publisher SPDX document is referenced without alteration."
        ),
        "externalDocumentRefs": [
            {
                "externalDocumentId": "DocumentRef-OriginalSDK",
                "spdxDocument": original["documentNamespace"],
                "checksum": {"algorithm": "SHA256", "checksumValue": original_sbom_sha},
            }
        ],
        "packages": packages,
        "relationships": relationships,
    }
    return _canonical_json(document)


def _homebrew_formula(archive_name: str, archive_sha: str, pins: dict[str, Any]) -> bytes:
    release_url = (
        f"https://github.com/{REPOSITORY}/releases/download/"
        f"{quote(pins['packaging_tag'], safe='')}/{quote(archive_name, safe='')}"
    )
    formula = f'''require "json"

class AmiRust < Formula
  desc "Native PC x86-64 AROS ABI-v1 SDK"
  homepage "https://github.com/{REPOSITORY}"
  url "{release_url}"
  version "{pins['sdk_version']}"
  sha256 "{archive_sha}"

  # This composite contains an adapter under MIT OR Apache-2.0 and upstream
  # SDK components with their own terms, including custom AROS and libgit
  # licenses. The included original publisher SPDX document preserves those
  # per-component details; the declaration below describes the composite.
  license :cannot_represent
  revision {pins['packaging_revision']}

  livecheck do
    skip "This packaging release requires explicit qualification."
  end

  depends_on arch: :arm64
  depends_on "git"
  depends_on macos: :tahoe
  depends_on "python@3.14"

  def install
    prefix.install Dir["usr/*"]
    python = formula_opt_bin("python@3.14")/"python3.14"
    inreplace bin/"ami-rust", "#!/usr/bin/python3", "#!#{{python}}"
  end

  def caveats
    <<~EOS
      Prepare the SDK explicitly with `ami-rust prepare --state PATH`.
      Preparation requires at least 6 GiB of RAM and 24 GiB of free disk.
      Installation leaves global compiler defaults unchanged.
    EOS
  end

  test do
    assert_equal(
      "ami-rust {pins['sdk_version']} (packaging {pins['packaging_revision']})",
      shell_output("#{{bin}}/ami-rust --version").strip,
    )
    assert_equal(
      {{
        "status"          => "VERIFIED_PACKAGE",
        "sdk_version"     => "{pins['sdk_version']}",
        "package_version" => "{pins['package_version']}",
      }},
      JSON.parse(shell_output("#{{bin}}/ami-rust verify-package")),
    )
  end
end
'''
    return formula.encode("utf-8")


def _write_new(path: Path, raw: bytes) -> dict[str, Any]:
    try:
        with path.open("xb") as stream:
            stream.write(raw)
    except OSError as error:
        raise MetadataError(f"cannot create generated metadata file: {path.name}") from error
    os.chmod(path, 0o644)
    return {"path": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def generate(source: str | os.PathLike[str], package_output: str | os.PathLike[str],
             epoch: int) -> dict[str, Any]:
    """Add a Homebrew formula and one SPDX 2.3 document per verified package payload."""
    source_root = Path(source)
    output_root = Path(package_output)
    if type(epoch) is not int or not 0 <= epoch <= MAX_EPOCH:
        raise MetadataError(f"epoch must be an integer from 0 through {MAX_EPOCH}")
    try:
        source_info = source_root.lstat()
        output_info = output_root.lstat()
    except OSError as error:
        raise MetadataError("source and package output directories must exist") from error
    if not stat.S_ISDIR(source_info.st_mode) or not stat.S_ISDIR(output_info.st_mode):
        raise MetadataError("source and package output must be real directories")

    pins, pins_raw, assets = _load_pins(source_root)
    build_report, build_report_raw, payloads = _validate_build_report(output_root, pins, epoch)
    archive_name, deb_name = _expected_names(pins)
    archive_path = output_root / archive_name
    original, original_sbom_raw, original_sbom_sha = _load_original_sdk_sbom(
        archive_path, pins, assets, build_report
    )
    if hashlib.sha256(original_sbom_raw).hexdigest() != original_sbom_sha:
        raise MetadataError("original SDK SPDX bytes changed during generation")

    formula_raw = _homebrew_formula(archive_name, payloads[archive_name]["sha256"], pins)
    sbom_names = {
        archive_name: archive_name + ".spdx.json",
        deb_name: deb_name + ".spdx.json",
    }
    generated_raw: dict[str, bytes] = {"ami-rust.rb": formula_raw}
    for payload_name in (archive_name, deb_name):
        generated_raw[sbom_names[payload_name]] = _make_sbom(
            payload_name, payloads[payload_name], pins, assets, original,
            original_sbom_sha, epoch,
        )

    generated_files: dict[str, dict[str, Any]] = {}
    for name in sorted(generated_raw):
        generated_files[name] = {
            "path": name,
            "bytes": len(generated_raw[name]),
            "sha256": hashlib.sha256(generated_raw[name]).hexdigest(),
        }
    report = {
        "schema": REPORT_SCHEMA,
        "epoch": epoch,
        "source": {
            "repository": pins["repository"],
            "commit": pins["source_commit"],
            "tree": pins["source_tree"],
            "manifest_sha256": pins["manifest_sha256"],
            "pins_sha256": hashlib.sha256(pins_raw).hexdigest(),
            "build_report_sha256": hashlib.sha256(build_report_raw).hexdigest(),
        },
        "sdk": {
            "version": pins["sdk_version"],
            "tag": pins["sdk_tag"],
            "run_id": pins["sdk_run_id"],
            "run_attempt": pins["sdk_run_attempt"],
            "package_version": pins["package_version"],
            "packaging_revision": pins["packaging_revision"],
            "packaging_tag": pins["packaging_tag"],
            "transport_sha256": pins["transport_sha256"],
        },
        "original_sdk_sbom": {
            "path": "assets/" + f"ami-rust-{pins['sdk_version']}-release.tar.xz.spdx.json",
            "document_namespace": original["documentNamespace"],
            "bytes": len(original_sbom_raw),
            "sha256": original_sbom_sha,
        },
        "payloads": {
            name: {
                **payloads[name],
                "spdx": {
                    "path": sbom_names[name],
                    "bytes": len(generated_raw[sbom_names[name]]),
                    "sha256": hashlib.sha256(generated_raw[sbom_names[name]]).hexdigest(),
                },
            }
            for name in (archive_name, deb_name)
        },
        "generated_files": generated_files,
    }
    report_raw = _canonical_json(report)

    for name, raw in generated_raw.items():
        _write_new(output_root / name, raw)
    _write_new(output_root / "metadata-report.json", report_raw)
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--epoch", required=True, type=int)
    arguments = parser.parse_args()
    generate(arguments.source, arguments.output, arguments.epoch)

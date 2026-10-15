#!/usr/bin/env python3
"""Explicit, offline provisioning of the pinned Cargo OpenSSL vendor overlay.

The upstream vendor tree stays unchanged. The output has exactly two changed
files: the declared source patch and its Cargo per-file checksum record.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root):
    rows = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("vendor contains a non-regular entry: " + str(path))
        rows.append({"path": path.relative_to(root).as_posix(), "bytes": info.st_size,
                     "mode": info.st_mode & 0o7777, "sha256": digest(path)})
    return rows


def verify_overlay(vendor, receipt, recipe):
    pin = json.loads((recipe / "openssl-overlay.json").read_text())
    record = json.loads(receipt.read_text())
    if record["overlay_pin_sha256"] != digest(recipe / "openssl-overlay.json"):
        raise ValueError("vendor overlay recipe identity mismatch")
    if digest(recipe / "openssl-paths.patch") != pin["patch_sha256"]:
        raise ValueError("vendor overlay patch identity mismatch")
    if inventory(vendor) != record["files"]:
        raise ValueError("vendor overlay inventory mismatch")
    if digest(vendor / pin["source_path_in_vendor"]) != pin["patched_sha256"]:
        raise ValueError("vendor overlay source identity mismatch")
    return {"receipt_sha256": digest(receipt), "pin_sha256": digest(recipe / "openssl-overlay.json"),
            "patch_sha256": pin["patch_sha256"], "inventory_files": len(record["files"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-vendor", type=Path, required=True)
    parser.add_argument("--output-vendor", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    recipe = Path(__file__).resolve().parent
    pin = json.loads((recipe / "openssl-overlay.json").read_text())
    source = args.source_vendor.resolve(strict=True)
    output = args.output_vendor.absolute()
    if output.exists() or args.receipt.exists() or output.is_relative_to(source):
        raise ValueError("overlay provisioning requires fresh output outside the source vendor")
    started = time.monotonic()
    before = inventory(source)
    if sum(row["bytes"] for row in before) * 2 > 12 * 1024**3:
        raise ValueError("overlay provisioning workspace budget")
    patched_path = pin["source_path_in_vendor"]
    checksum_path = patched_path.split("/", 1)[0] + "/.cargo-checksum.json"
    checksum = json.loads((source / checksum_path).read_text())
    if (digest(source / patched_path) != pin["source_sha256"]
            or checksum["package"] != pin["package"]["cargo_lock_checksum"]
            or checksum["files"]["src/lib.rs"] != pin["source_sha256"]
            or digest(recipe / "openssl-paths.patch") != pin["patch_sha256"]):
        raise ValueError("upstream vendor/patch identity mismatch")
    shutil.copytree(source, output)
    command = ["/usr/bin/patch", "-p1", "--batch"]
    applied = subprocess.run(command, cwd=output, input=(recipe / "openssl-paths.patch").read_bytes(),
                             capture_output=True, timeout=10, check=True)
    if digest(output / patched_path) != pin["patched_sha256"]:
        raise ValueError("patched source identity mismatch")
    checksum["files"]["src/lib.rs"] = pin["patched_sha256"]
    (output / checksum_path).write_text(json.dumps(checksum, sort_keys=True, separators=(",", ":")))
    after = inventory(output)
    old = {row["path"]: row for row in before}
    new = {row["path"]: row for row in after}
    if old.keys() != new.keys():
        raise ValueError("overlay changed vendor membership")
    changed = sorted(name for name in old if old[name] != new[name])
    if changed != sorted((patched_path, checksum_path)) or inventory(source) != before:
        raise ValueError("overlay changed undeclared files or upstream vendor")
    elapsed = time.monotonic() - started
    if elapsed > 1200:
        raise ValueError("overlay provisioning time budget")
    result = {"claim": "offline prerequisite overlay provisioning, not SDK/R1 acceptance",
              "overlay_pin_sha256": digest(recipe / "openssl-overlay.json"),
              "patch_sha256": pin["patch_sha256"], "source_vendor": str(source),
              "output_vendor": str(output), "changed_files": changed,
              "original_inventory_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
              "original_vendor_recheck": "PASS", "elapsed_seconds": elapsed,
              "source_plus_output_bytes": sum(row["bytes"] for row in before + after),
              "patch_stdout": applied.stdout.decode(), "patch_stderr": applied.stderr.decode(),
              "files": after}
    args.receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "files"}, indent=2))


if __name__ == "__main__":
    main()

"""Retire diagnostic work and accompany retained Cargo binaries with notices."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from release import cargo_context_probe as probe

LIMIT = 32 * 1024**2
NAMES = {"LICENSE.md", "LICENSE-MIT", "LICENSE-APACHE", "THIRD_PARTY_NOTICES.md",
         "cargo-notices-corresponding-source.tar.xz", "cargo-source-inventory.json"}
DIAGNOSTICS = {"outcome.json", "host-toolchain.json", "cleanup.json"} | {
    f"{phase}/{name}" for phase in ("cargo", "sdk")
    for name in ("producer.json", "cargo.tar.xz", "diagnostics.tar.xz")}


def safe_file(root, relative):
    value = PurePosixPath(relative)
    if value.is_absolute() or not value.parts or any(p in (".", "..") for p in value.parts):
        raise ValueError("unsafe accompanying material path")
    path = root.joinpath(*value.parts)
    if path.resolve(strict=True) != path or not path.is_file() or path.is_symlink():
        raise ValueError("accompanying material is not a regular canonical source file")
    return path


def accompany(source, output):
    manifest = json.loads((source / "release/bundle-files.json").read_text())
    rows = [r for r in manifest["files"] if r["path"] in NAMES or r["path"].startswith("licences/")]
    names = [r["path"] for r in rows]
    if len(names) != len(set(names)) or not NAMES.issubset(names) or not any(n.startswith("licences/") for n in names):
        raise ValueError("incomplete or ambiguous accompanying material inventory")
    verified = []
    for row in rows:
        path = safe_file(source, row["source"])
        if path.stat().st_size != row["bytes"] or probe.sha256(path) != row["sha256"]:
            raise ValueError("accompanying material differs from its bundle pin")
        verified.append((row, path))
    if probe.tree_bytes(output) + sum(r["bytes"] for r, _ in verified) + 65536 > LIMIT:
        raise ValueError("probe diagnostics and accompanying materials exceed 32 MiB")
    destination = output / "accompanying-materials"
    destination.mkdir()
    for row, path in verified:
        name = PurePosixPath(row["path"])
        if name.is_absolute() or any(p in (".", "..") for p in name.parts):
            raise ValueError("unsafe accompanying destination")
        target = destination.joinpath(*name.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(path.read_bytes())
        if probe.sha256(target) != row["sha256"]:
            raise ValueError("accompanying material copy failed readback")
    return [{k: row[k] for k in ("path", "bytes", "sha256")} for row, _ in verified]


def finalize(temporary, output, source, producer_result):
    if temporary.resolve(strict=True) != temporary or output != temporary / "ami-rust-context-output":
        raise ValueError("unexpected managed diagnostic paths")
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError("diagnostic output is not a real directory")
    output.mkdir(exist_ok=True)
    if (temporary / probe.OWNER_NAME).exists():
        probe.cleanup(argparse.Namespace(temporary=temporary, output=output))
    if any((temporary / n).exists() or (temporary / n).is_symlink() for n in probe.WORK_NAMES):
        raise ValueError("unretired producer work roots")
    for path in output.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or path.relative_to(output).as_posix() not in DIAGNOSTICS:
            raise ValueError("unexpected diagnostic export")
    outcome = output / "outcome.json"
    if producer_result == "success":
        value = json.loads(outcome.read_text())
        if value.get("status") != "MATCH_NOT_RELEASE_ACCEPTED":
            raise ValueError("successful probe lacks the matching diagnostic outcome")
    bootstrap = temporary / probe.BOOTSTRAP_NAME
    if bootstrap.is_symlink():
        raise ValueError("linked Python bootstrap root")
    receipt = bootstrap / "bootstrap.json"
    if receipt.exists():
        if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > 65536:
            raise ValueError("invalid Python bootstrap receipt")
        (output / "python-bootstrap.json").write_bytes(receipt.read_bytes())
    if bootstrap.exists():
        shutil.rmtree(bootstrap)
    materials = accompany(source, output)
    inventory = [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size,
                  "sha256": probe.sha256(p)} for p in sorted(output.rglob("*")) if p.is_file()]
    record = {"schema": "ami-rust-cargo-context-export-v1", "producer_step_result": producer_result,
              "source_commit": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"), "inventory": inventory,
              "accompanying_materials": materials, "work_tree_remaining_bytes": 0,
              "python_runtime_remaining_bytes": 0, "SDK_release_acceptance": False}
    probe.write_json(output / "export.json", record)
    if probe.tree_bytes(output) > LIMIT:
        raise ValueError("complete diagnostic export exceeds 32 MiB")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temporary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--producer-result", required=True)
    args = parser.parse_args()
    finalize(args.temporary, args.output, Path(__file__).resolve().parent.parent, args.producer_result)

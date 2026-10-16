"""Local free-space preflight, independent of historical evidence quotas.

Keep usable disk headroom after the estimated peak of a large operation.
Source, documentation, licences and retained backups have no per-file or
cumulative archive quota. Existing hashes, evidence and backups are preserved.
Hosted runner/CI artifact limits and the AROS runtime budgets are separate.
"""
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
BACKUPS = (ROOT.parent / "AROS-M0-Backups").resolve()


def _policy():
    value = json.loads((ROOT / "release/ci-resources.json").read_text())["local_storage"]
    minimum = value.get("minimum_free_bytes")
    if (value.get("schema") != "ami-rust-local-storage-v2"
            or value.get("mode") != "free-space-headroom"
            or type(minimum) is not int or minimum <= 0
            or value.get("per_file_quotas") is not False
            or value.get("fixed_archive_quota_bytes") is not None
            or value.get("preserve_existing_evidence") is not True):
        raise ValueError("invalid local free-space policy")
    return value


def check(reserve=0, *, disk_usage=None):
    """Admit one operation's estimated additional peak, leaving disk headroom.

    Ordinary edits use check(). A large build, download or recovery uses one
    check(reserve=combined_peak_bytes), including all simultaneous copies.
    No file reservation ledger or full repository scan is needed.
    """
    if type(reserve) is not int or reserve < 0:
        raise ValueError("operation peak must be a nonnegative byte count")
    policy = _policy()
    minimum = policy["minimum_free_bytes"]
    disk_usage = shutil.disk_usage if disk_usage is None else disk_usage
    volumes = []
    devices = set()
    paths = [ROOT]
    if BACKUPS.is_dir():
        paths.append(BACKUPS)
    for path in paths:
        device = path.stat().st_dev
        if device in devices:
            continue
        devices.add(device)
        free = disk_usage(path).free
        if free < minimum + reserve:
            raise RuntimeError("insufficient free disk space for the operation and local headroom")
        volumes.append({"path": str(path), "free_bytes": free,
                        "planned_additional_peak_bytes": reserve,
                        "free_after_planned_peak_bytes": free - reserve})
    return {"schema": "ami-rust-local-disk-capacity-v2",
            "minimum_free_bytes": minimum, "volumes": volumes,
            "per_file_quotas": False, "fixed_archive_quota_bytes": None}


def _owned_path(path):
    path = Path(path).resolve()
    if (ROOT not in path.parents
            and not (path.parent == BACKUPS and path.name.startswith("ami-rust")
                     and not path.name.startswith("ami-rust-m0"))):
        raise ValueError("operation is outside ami-rust-owned storage")
    return path


def reserve_file(path, maximum):
    """Compatibility for old drivers: a space estimate, never a file quota."""
    _owned_path(path)
    return check(reserve=maximum)


def release_file(path):
    """Compatibility for old drivers; there is no reservation to release."""
    _owned_path(path)
    return check()

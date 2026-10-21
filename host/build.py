#!/usr/bin/env python3
"""Shared process and resource helpers for host-side Cargo producers."""

import os
import signal
import stat
import subprocess
import time

# This pinned source path is loaded by the Cargo reproducibility producer and
# imported by the standard-Cargo sysroot probe.
def tree_bytes(path):
    total = 0
    for child in path.rglob("*"):
        try:
            info = child.lstat()
        except FileNotFoundError:
            # Compiler temporary files can disappear during a live sample.
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


def rss_tree(pid):
    rows = [tuple(map(int, line.split())) for line in subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid=,pgid=,rss="], text=True).splitlines() if len(line.split()) == 4]
    ids = {pid}
    while True:
        extra = {a for a, parent, group, _ in rows if parent in ids or group == pid} - ids
        if not extra:
            return sum(rss * 1024 for child, _, _, rss in rows if child in ids)
        ids |= extra


def group_alive(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_group(child):
    # A leader can exit before its descendants. Escalation applies to the
    # entire original process group even after wait() has reaped the leader.
    if group_alive(child.pid):
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and group_alive(child.pid):
            child.poll()
            time.sleep(0.05)
        if group_alive(child.pid):
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    child.wait(timeout=3)


def require_host_capacity(manifest, physical_ram, free_disk):
    """Select a manifest-bound capacity profile; legacy SDKs keep their gate."""
    policy = manifest.get("host_capacity")
    if policy is None:
        policy = {"schema": "ami-rust-host-capacity-v1",
                  "ram_minimum_bytes": 16 * 1024**3,
                  "disk_free_minimum_bytes": 24 * 1024**3}
    else:
        if (not isinstance(policy, dict)
                or set(policy) != {"schema", "ram_minimum_bytes", "disk_free_minimum_bytes"}
                or policy["schema"] != "ami-rust-host-capacity-v1"):
            raise ValueError("incompatible manifest host capacity policy")
        for name, floor in (("ram_minimum_bytes", 6 * 1024**3),
                            ("disk_free_minimum_bytes", 24 * 1024**3)):
            value = policy[name]
            if type(value) is not int or value < floor:
                raise ValueError("host capacity policy is below the admitted floor: " + name)
        rss = manifest["budgets"]["build_rss_bytes"]
        if type(rss) is not int or not 0 < rss <= 4 * 1024**3:
            raise ValueError("hosted capacity policy requires at most 4 GiB build RSS")
    if physical_ram < policy["ram_minimum_bytes"] or free_disk < policy["disk_free_minimum_bytes"]:
        raise ValueError("host capacity refused: requires "
                         + str(policy["ram_minimum_bytes"]) + " bytes RAM and "
                         + str(policy["disk_free_minimum_bytes"]) + " bytes free workspace")
    return dict(policy)

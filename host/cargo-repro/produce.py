#!/usr/bin/env python3
"""Bounded prerequisite Cargo producer; explicitly provision before offline build.

This produces a host tool only. It is not an SDK or native AROS qualification.
The patched frontend never replaces the pinned upstream Cargo installation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import stat
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def size(root):
    total = 0
    for path in root.rglob("*"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


def rss(pid):
    rows = [tuple(map(int, line.split())) for line in subprocess.check_output(
        ["/bin/ps", "-axo", "pid=,ppid=,rss="], text=True).splitlines() if len(line.split()) == 3]
    children = {pid}
    while True:
        added = {child for child, parent, _ in rows if parent in children} - children
        if not added:
            return sum(kib * 1024 for child, _, kib in rows if child in children)
        children |= added


def supervisor_group_is_private():
    """True only when this producer is its own session and process-group leader."""
    pid = os.getpid()
    return os.getpgrp() == pid and os.getsid(0) == pid


def spawn_build_child(command, *, cwd, env, stdout, stderr,
                      share_supervisor_group=False):
    """Launch Cargo isolated by default, or in the outer CI supervisor's group."""
    return subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                            start_new_session=not share_supervisor_group)


def stop_build_child(child, supervisor, *, share_supervisor_group=False):
    """Stop Cargo without killing an unrelated parent process group."""
    if not share_supervisor_group:
        supervisor["stop_group"](child)
        return
    try:
        child.terminate()
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            child.kill()
        except ProcessLookupError:
            pass
        child.wait(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("provision", "build"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--host-rust", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--vendor", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--vendor-overlay-receipt", type=Path)
    parser.add_argument("--resource-policy", type=Path,
                        help="explicit prospective hosted CI resource contract")
    parser.add_argument("--profile", choices=("dev", "release"), default="dev")
    parser.add_argument("--share-supervisor-group", action="store_true",
                        help="keep Cargo in this producer's externally supervised process group")
    args = parser.parse_args()
    if args.share_supervisor_group and not supervisor_group_is_private():
        parser.error("--share-supervisor-group requires this producer to lead its own session/group")
    source = args.source.resolve(strict=True)
    rust = args.host_rust.resolve(strict=True) / "bin"
    recipe = Path(__file__).resolve().parent
    supervisor = runpy.run_path(str(recipe.parent / "build.py"))
    limits = {"seconds": 1200, "rss_bytes": 8 * 1024**3,
              "workspace_bytes": 12 * 1024**3, "jobs": 2,
              "log_bytes": 16 * 1024**2}
    resource_identity = None
    if args.resource_policy:
        policy = json.loads(args.resource_policy.read_text())
        if policy.get("schema") != "ami-rust-hosted-resources-v1":
            raise ValueError("incompatible hosted producer resource policy")
        selected = policy["build"]
        if set(selected) != set(limits):
            raise ValueError("hosted producer resource fields differ")
        ceilings = {**limits, "rss_bytes": 4 * 1024**3}
        if any(type(selected[name]) is not int or not 0 < selected[name] <= ceilings[name]
               for name in limits) or selected["jobs"] != 2:
            raise ValueError("hosted producer limits exceed admitted caps")
        limits = selected
        ram = (int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], text=True))
               if platform.system() == "Darwin" else
               os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
        import shutil
        supervisor["require_host_capacity"](
            {"host_capacity": policy["host_capacity"],
             "budgets": {"build_rss_bytes": limits["rss_bytes"]}}, ram,
            shutil.disk_usage(args.source).free)
        resource_identity = {"sha256": digest(args.resource_policy),
                             "host_capacity": policy["host_capacity"],
                             "physical_ram_bytes": ram}
    pin = json.loads((recipe / "source.json").read_text())
    assert subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=source, text=True).strip() == pin["commit"]
    assert digest(source / pin["path"]) == pin["patched_sha256"]
    changed = subprocess.check_output(["/usr/bin/git", "diff", "--name-only"], cwd=source, text=True).splitlines()
    expected_paths = [pin["path"]] + [row["path"] for row in pin.get("additional_files", [])]
    assert sorted(changed) == sorted(expected_paths), changed
    for row in pin.get("additional_files", []):
        assert digest(source / row["path"]) == row["patched_sha256"]
    assert digest(recipe / "cargo-metadata.patch") == pin["patch_sha256"]
    compiler = subprocess.check_output([str(rust / "rustc"), "-Vv"], text=True)
    assert "release: 1.98.1\n" in compiler and "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" in compiler
    work = args.work.absolute()
    work.mkdir(parents=True, exist_ok=True)
    record = args.record.absolute()
    record.mkdir(parents=True, exist_ok=False)
    for name in ("cargo-home", "tmp", "home"):
        (work / name).mkdir(exist_ok=True)
    vendor = args.vendor.absolute()
    overlay_identity = None
    verify_overlay = None
    if args.vendor_overlay_receipt:
        if args.phase != "build":
            raise ValueError("provision the offline overlay explicitly before its producer build")
        verify_overlay = runpy.run_path(str(recipe / "prepare-overlay.py"))["verify_overlay"]
        overlay_identity = verify_overlay(vendor, args.vendor_overlay_receipt, recipe)
    cargo_home = work / "cargo-home"
    config = cargo_home / "config.toml"
    if args.phase == "build":
        assert vendor.is_dir(), "explicit dependency provisioning required"
        config.write_text('[source.crates-io]\nreplace-with="vendored"\n[source.vendored]\ndirectory=' + json.dumps(str(vendor)) + '\n')
    else:
        assert not vendor.exists() and not config.exists(), "provision into a fresh explicit vendor"
    rustflags = [
        "--remap-path-prefix=" + str(source) + "=/cargo-source",
        "--remap-path-prefix=" + str(work) + "=/cargo-build",
        "--remap-path-prefix=" + str(vendor) + "=/cargo-vendor",
    ]
    if args.phase == "build" and platform.system() == "Darwin":
        # ld records bootstrap archive paths in N_OSO debug-map symbols.
        # Strip the bootstrap root while preserving relative lib/rustlib paths.
        rustflags.append("-C link-arg=-Wl,-oso_prefix," + str(rust.parent) + "/")
    env = {"HOME": str(work / "home"), "PATH": str(rust) + ":/usr/bin:/bin:/usr/sbin:/sbin",
           "RUSTC": str(rust / "rustc"), "RUSTDOC": str(rust / "rustdoc"),
           "CARGO_HOME": str(cargo_home), "CARGO_TARGET_DIR": str(work / "target"),
           "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0",
           "CARGO_PROFILE_DEV_INCREMENTAL": "false", "TMPDIR": str(work / "tmp"),
           "CARGO_PROFILE_RELEASE_DEBUG": "0", "CARGO_PROFILE_RELEASE_INCREMENTAL": "false",
           "CARGO_PROFILE_RELEASE_OPT_LEVEL": "2", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "16",
           "CARGO_PROFILE_RELEASE_LTO": "false",
           "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1791936000",
           "RUSTFLAGS": " ".join(rustflags)}
    if args.phase == "provision":
        command = [str(rust / "cargo"), "vendor", "--locked", "--versioned-dirs", str(vendor)]
    else:
        env["CARGO_NET_OFFLINE"] = "true"
        command = [str(rust / "cargo"), "build", "--locked", "--offline", "-j", "2", "--bin", "cargo", "--features", "all-static"]
        if args.profile == "release":
            command.append("--release")
    identity = {"phase": args.phase, "claim": "prerequisite producer only; not release qualification", "upstream_commit": pin["commit"],
                "patch_sha256": pin["patch_sha256"], "producer_sha256": digest(Path(__file__).resolve()),
                "cargo_lock_sha256": digest(source / "Cargo.lock"), "compiler": compiler, "host": platform.platform(),
                "command": command, "environment": env, "budgets": limits,
                "explicit_resource_policy": resource_identity}
    identity["vendor_overlay"] = overlay_identity
    identity["profile"] = args.profile
    if overlay_identity:
        identity["overlay_helper_sha256"] = digest(recipe / "prepare-overlay.py")
    (record / "inputs.json").write_text(json.dumps(identity, indent=2) + "\n")
    start = time.monotonic()
    peak_rss = peak_work = 0
    next_size = 0
    reason = None
    with (record / "stdout.log").open("wb") as stdout, (record / "stderr.log").open("wb") as stderr:
        child = spawn_build_child(command, cwd=source, env=env, stdout=stdout, stderr=stderr,
                                  share_supervisor_group=args.share_supervisor_group)
        try:
            while child.poll() is None:
                peak_rss = max(peak_rss, supervisor["rss_tree"](child.pid))
                now = time.monotonic()
                if now >= next_size:
                    peak_work = max(peak_work, size(work) + size(source) + size(vendor) + size(record))
                    next_size = now + 2
                if now - start > limits["seconds"]: reason = "producer timeout"
                if peak_rss > limits["rss_bytes"]: reason = "producer aggregate RSS"
                if peak_work > limits["workspace_bytes"]: reason = "producer workspace"
                if stdout.tell() + stderr.tell() > limits["log_bytes"]: reason = "producer log limit"
                if reason:
                    break
                time.sleep(0.2)
        except Exception as error:
            reason = "producer monitor failed: " + repr(error)
        finally:
            if reason:
                stop_build_child(child, supervisor,
                                 share_supervisor_group=args.share_supervisor_group)
            elif not args.share_supervisor_group and supervisor["group_alive"](child.pid):
                reason = "producer leader exited with live process group"
                stop_build_child(child, supervisor, share_supervisor_group=False)
            else:
                child.wait(timeout=3)
    peak_work = max(peak_work, size(work) + size(source) + size(vendor) + size(record))
    result = {"exit_code": child.returncode, "stop_reason": reason, "elapsed_seconds": time.monotonic()-start,
              "rss_peak_observed_bytes": peak_rss, "workspace_peak_observed_bytes": peak_work}
    if args.phase == "build" and child.returncode == 0 and reason is None:
        if verify_overlay:
            result["vendor_overlay_recheck"] = verify_overlay(vendor, args.vendor_overlay_receipt, recipe)
        binary = work / "target" / ("release" if args.profile == "release" else "debug") / "cargo"
        result["artifact"] = {"path": str(binary), "bytes": binary.stat().st_size, "sha256": digest(binary),
                              "version": subprocess.check_output([str(binary), "-Vv"], text=True)}
    (record / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if child.returncode or reason:
        raise SystemExit(child.returncode if child.returncode > 0 else 1)


if __name__ == "__main__":
    main()

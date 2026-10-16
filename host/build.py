#!/usr/bin/env python3
"""Explicit portable native build backend for the locked ami-rust CLI."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import time

# The ami-rust launcher verifies the complete host source directory before this
# isolated interpreter starts. Import stdlib first, then these pinned sources.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contracts import host_key, read_json, relative, select, sha256


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


def cargo_options(arguments):
    if not arguments or arguments[0] != "build":
        raise ValueError("ami-rust currently supports the explicit native build recipe")
    values = {}
    switches = set()
    index = 1
    while index < len(arguments):
        flag = arguments[index]
        if flag in ("--manifest-path", "--package", "-p", "--features"):
            key = "--package" if flag == "-p" else flag
            if key in values or index + 1 == len(arguments):
                raise ValueError(f"missing/duplicate Cargo argument: {flag}")
            values[key] = arguments[index + 1]
            index += 2
        elif flag in ("--release", "--locked", "--offline", "--no-default-features"):
            if flag in switches:
                raise ValueError(f"duplicate Cargo argument: {flag}")
            switches.add(flag)
            index += 1
        else:
            raise ValueError(f"unsupported or SDK-owned Cargo option: {flag}")
    if not {"--release", "--locked", "--offline"} <= switches or "--manifest-path" not in values or "--package" not in values:
        raise ValueError("native builds require --manifest-path, --package, --release, --locked and --offline")
    manifest = Path(values["--manifest-path"]).resolve(strict=True)
    if not (manifest.parent / "Cargo.lock").is_file():
        raise ValueError("missing project Cargo.lock; explicitly provision and commit it before building")
    values["--manifest-path"] = str(manifest)
    return values, switches


def reject_ambient_cargo_config(work):
    # Cargo discovers configuration from cwd, rather than --manifest-path.
    # A private CARGO_HOME alone does not suppress ancestor .cargo files.
    for parent in (work, *work.parents):
        for name in ("config", "config.toml"):
            config = parent / ".cargo" / name
            if config.exists() or config.is_symlink():
                raise ValueError("ambient Cargo configuration would affect the locked build: "
                                 + str(config) + "; use an output directory outside its ancestry")


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("cargo", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    forwarded = args.cargo[1:] if args.cargo[:1] == ["--"] else args.cargo
    options, switches = cargo_options(forwarded)
    lock, project, root, manifest, profile, components, counts = select(args.project_lock)
    budget = manifest["budgets"]
    cargo_manifest = Path(options["--manifest-path"])
    cargo_lock = cargo_manifest.parent / "Cargo.lock"
    if sha256(cargo_manifest) != project["cargo"]["manifest_sha256"] or sha256(cargo_lock) != project["cargo"]["lock_sha256"]:
        raise ValueError("project Cargo manifest/lock identity mismatch")
    ram = int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], text=True)) if host_key() == "macos-aarch64" else int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))) * 1024
    output = args.output_dir.absolute()
    if output.exists() or not output.parent.is_dir():
        raise ValueError("output directory must be fresh with an existing parent")
    free_disk = shutil.disk_usage(output.parent).free
    capacity_policy = require_host_capacity(manifest, ram, free_disk)
    reject_ambient_cargo_config((output / "work").resolve())
    rust = components["rust"] / "bin"
    cargo = relative(components["cargo"], profile["cargo_binary"])
    compiler = subprocess.check_output([str(rust / "rustc"), "-Vv"], text=True)
    if "commit-hash: " + manifest["rust_commit"] not in compiler or "LLVM version: " + manifest["rust_llvm"] not in compiler or "host: " + profile["rust_host"] not in compiler:
        raise ValueError("target Rust compiler/LLVM/host identity mismatch")
    cargo_version = subprocess.check_output([str(cargo), "-Vv"], text=True)
    output.mkdir()
    guard = (output / "build.lock").open("xb")
    fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
    work = output / "work"
    work.mkdir()
    for name in ("cargo-home", "home", "tmp", "bin", "artifacts", "commands"):
        (output / name).mkdir()
    toolchain = components["toolchain"]
    sdk = components["csdk"]
    for name in ("llvm-objdump", "llvm-nm", "llvm-ar", "llvm-strip", "ld.lld"):
        (output / "bin" / name).symlink_to(toolchain / "bin" / name)
    collector = relative(components["collector"], profile["collector_binary"])
    shutil.copyfile(collector, output / "bin/aros-collect")
    (output / "bin/aros-collect").chmod(0o755)
    (output / "bin/collect-aros").symlink_to("aros-collect")
    remaps = [(root, "/ami-rust"), (output, "/build"), (components["vendor"], "/vendor"), (components["rust"], "/rust-toolchain"), (Path(options["--manifest-path"]).parent, "/project")]
    host_remap_flags = ["--remap-path-prefix=" + str(a) + "=" + b for a, b in remaps]
    config = 'target-applies-to-host=false\n[source.crates-io]\nreplace-with="vendored"\n[source.vendored]\ndirectory=' + json.dumps(str(components["vendor"])) + '\n[build]\njobs=2\n'
    # Host proc macros contribute identities to target metadata. Remap their
    # paths as well, while retaining their default host panic/codegen options.
    config += '[host.' + profile["rust_host"] + ']\nrustflags=' + json.dumps(host_remap_flags) + '\n'
    (output / "cargo-home/config.toml").write_text(config)
    flags = ["-Copt-level=2", "-Cpanic=abort", "-Ccodegen-units=1", "-Cembed-bitcode=no", "-Clto=off"] + host_remap_flags
    env = {"HOME": str(output / "home"), "PATH": str(cargo.parent) + ":" + str(rust) + ":" + str(toolchain / "bin") + ":/usr/bin:/bin", "CARGO": str(cargo), "CARGO_HOME": str(output / "cargo-home"), "RUSTC": str(rust / "rustc"), "RUSTDOC": str(rust / "rustdoc"), "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(work / "target"), "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags), "TMPDIR": str(output / "tmp"), "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": str(manifest["source_date_epoch"]), "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""}
    begin = time.monotonic()
    records = []

    def run(command, label):
        command = [str(part) for part in command]
        directory = output / "commands" / label
        directory.mkdir()
        start = time.monotonic()
        peak_rss = peak_workspace = 0
        with (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
            child = subprocess.Popen(command, cwd=work, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            reason = None
            try:
                while child.poll() is None:
                    peak_rss = max(peak_rss, rss_tree(child.pid))
                    peak_workspace = max(peak_workspace, tree_bytes(output))
                    if peak_rss > budget["build_rss_bytes"]: reason = "build RSS cap"
                    if peak_workspace > budget["build_workspace_bytes"]: reason = "build workspace cap"
                    if time.monotonic() - begin > budget["build_seconds"]: reason = "build timeout"
                    if stdout.tell() + stderr.tell() > 16 * 1024 * 1024: reason = "build log cap"
                    if reason:
                        break
                    time.sleep(0.1)
            except Exception as error:
                reason = "build monitor failed: " + repr(error)
            finally:
                if reason or group_alive(child.pid):
                    reason = reason or "build leader exited with a live subprocess group"
                    stop_group(child)
                else:
                    child.wait()
        record = {"command": command, "exit_code": child.returncode, "stop_reason": reason, "elapsed_seconds": time.monotonic()-start, "rss_peak_observed_bytes": peak_rss, "workspace_peak_observed_bytes": max(peak_workspace, tree_bytes(output))}
        (directory / "result.json").write_text(json.dumps(record, indent=2)+"\n")
        records.append(record)
        if reason or child.returncode:
            raise ChildProcessError(child.returncode if child.returncode else 1)
        return directory / "stdout.log"

    art = output / "artifacts"
    package = options["--package"]
    testing = package in ("ami-rust-qualification", "ami-rust-dependencies")
    common = [toolchain / "bin/clang", "--target=x86_64-unknown-aros", "-D__AROS__=1", "-D__AROS_VERSION__=1", "-DAMIGA=1", "-D_AMIGA=1", "-ffreestanding", "-fno-stack-protector", "-mno-red-zone", "-mcmodel=large", "-O2", "-g0", "-fno-ident", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-ffile-prefix-map="+str(root)+"=/ami-rust", "-I"+str(sdk / "include/aros/stdc"), "-I"+str(sdk / "include")]
    if testing:
        common += ["-DAMI_SDK_TESTING=1"]
    for unit in ("entry", "sdk", "layout"):
        run(common + ["-c", root / "native" / (unit+".c"), "-o", art / (unit+".o")], "C-"+unit)
    if testing:
        run(common+["-c", root / "tests/measurement/ami_test_bind_diagnostics.c", "-o", art / "bind.o"], "C-bind")
    run([toolchain / "bin/llvm-objcopy", "--redefine-sym", "__startup_entry=ami_sdk_startup_entry", sdk / "lib/startup.o", art / "startup.o"], "Startup")
    command = [cargo, "-Zhost-config", "-Ztarget-applies-to-host", "-Zami-rust-reproducible-cross", "-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem", "-Zjson-target-spec", "build", "--manifest-path", options["--manifest-path"], "--package", package, "--target", root / "targets/x86_64-aros.json", "--release", "--locked", "--offline", "-j", "2", "--message-format=json-render-diagnostics", "-vv"]
    if "--no-default-features" in switches:
        command += ["--no-default-features"]
    if "--features" in options:
        command += ["--features", options["--features"]]
    cargo_log = run(command, "Rust")
    artifacts = []
    build_script_lines = []
    for line in cargo_log.read_text().splitlines():
        # Cargo -vv includes prefixed build-script output alongside JSON messages.
        # Preserve those records, while parsing compiler-artifact messages only.
        if line.startswith("[") and "] " in line:
            build_script_lines.append(line)
            continue
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact" and "staticlib" in message["target"]["kind"]:
            artifacts += [Path(name) for name in message["filenames"] if name.endswith(".a")]
    if len(artifacts) != 1:
        raise ValueError("Cargo must report exactly one application static library")
    archive = artifacts[0]
    archive.resolve(strict=True).relative_to(work / "target")
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("invalid Cargo artifact path")
    shutil.copyfile(archive, art / "application.a")
    link = [output / "bin/collect-aros", "--sysroot="+str(sdk), "-m", "elf_x86_64", "-Map", art / "AMIRUST.map", "-o", art / "AMIRUST.unstripped", art / "entry.o", art / "startup.o", art / "sdk.o", art / "layout.o"]
    if testing:
        link += [art / "bind.o"]
    link += [art / "application.a", "-L"+str(sdk / "lib"), "--start-group", "-lmui", "-lamiga", "-larossupport", "-lstdcio", "-lstdc", "-lposixc", "-ldos", "-lexec", "-lautoinit", "-llibinit", "-lutility", "-laros", "-ldebug", "--end-group", toolchain / "lib/clang/11.0.0/lib/aros/libclang_rt.builtins-x86_64.a"]
    run(link, "Link")
    run([toolchain / "bin/llvm-strip", "--strip-unneeded", "--keep-symbol=__startup_entry", "-o", art / "AMIRUST.stripped", art / "AMIRUST.unstripped"], "Strip")
    run([sys.executable, root / "host/compact_sections.py", art / "AMIRUST.stripped", art / "AMIRUST", output / "metadata-compaction.json"], "Compact")
    run([sys.executable, root / "host/elf_audit.py", art / "AMIRUST", "deps" if package == "ami-rust-dependencies" else "core", output / "elf-audit.json"], "Audit")
    select(lock)  # Revalidate immutable SDK/prerequisites after compilation.
    canonical = {name: {"bytes": (art/name).stat().st_size, "sha256": sha256(art/name)} for name in ["entry.o", "sdk.o", "layout.o", "startup.o", "application.a", "AMIRUST"] + (["bind.o"] if testing else [])}
    target_root = work / "target/x86_64-aros"
    for generated in sorted(target_root.rglob("*")):
        if generated.suffix not in (".o", ".a", ".rlib"):
            continue
        if generated.is_symlink() or not generated.is_file():
            raise ValueError("invalid generated target library/object")
        name = generated.relative_to(target_root).as_posix()
        destination = art / "target" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(generated, destination)
        canonical["target/" + name] = {"bytes": destination.stat().st_size,
                                      "sha256": sha256(destination)}
    receipt = {"status": "PASS", "claim": "native build only; runtime and release qualification require separate evidence", "host": host_key(), "platform": platform.platform(), "host_ram_bytes": ram, "source_date_epoch": manifest["source_date_epoch"], "project_lock_sha256": sha256(lock), "sdk_manifest_sha256": project["sdk"]["manifest_sha256"], "prerequisite_inventory_counts": counts, "compiler_verbose": compiler, "forwarded_cargo_arguments": forwarded, "verbose_build_script_lines": len(build_script_lines), "deterministic_rust_flags": flags, "canonical_artifacts": canonical, "elapsed_seconds": time.monotonic()-begin, "commands": records}
    receipt["cargo_frontend"] = {"path": str(cargo), "sha256": sha256(cargo),
                                "metadata_mode": profile["cargo_metadata_mode"], "version": cargo_version}
    receipt["host_capacity"] = {"policy": capacity_policy, "physical_ram_bytes": ram,
                                "free_disk_bytes_before_build": free_disk}
    (output / "build-receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    # Complete native archive/object evidence is retained before cold cache retirement.
    shutil.rmtree(work)
    print(json.dumps({"status": "PASS", "native_executable": str(art/"AMIRUST"), "receipt": str(output/"build-receipt.json")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ChildProcessError as error:
        print(f"native build failed; command evidence retained (status {error.args[0]})", file=sys.stderr)
        sys.exit(error.args[0] if 0 < error.args[0] < 256 else 130)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"ami-rust selection/build refused: {error}", file=sys.stderr)
        sys.exit(2)

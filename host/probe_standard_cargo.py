#!/usr/bin/env python3
"""Development probe: upstream Cargo with a separately produced AROS sysroot.

The producer preserves its libraries before retiring the build cache. Consumer
builds reuse only that declared sysroot, not any cached package artifacts. This
does not qualify a release, a native execution, or an installation mechanism.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contracts import select, sha256
from build import rss_tree, tree_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sysroot", type=Path, help="Already frozen producer sysroot; omit to produce one")
    parser.add_argument("--cargo-producer-record", type=Path,
                        help="Development counter-trial: separately authenticated patched Cargo producer result")
    parser.add_argument("--upstream-metadata", action="store_true",
                        help="Counter-probe: leave the patched frontend's opt-in mode disabled")
    args = parser.parse_args()
    lock_path, lock, root, manifest, profile, components, counts = select(args.project_lock)
    output = args.output.absolute()
    assert not output.exists() and output.parent.is_dir()
    output.mkdir()
    work = output / "work"
    work.mkdir()
    for name in ("cargo-home", "tmp"):
        (work / name).mkdir()
    rust = components["rust"] / "bin"
    target = root / "targets/x86_64-aros.json"
    producer = args.sysroot is None
    flags = ["-Copt-level=2", "-Cpanic=abort", "-Ccodegen-units=1", "-Cembed-bitcode=no", "-Clto=off"]
    flags += ["--remap-path-prefix=" + str(a) + "=" + b for a, b in
              [(root, "/ami-rust"), (output, "/build"), (components["vendor"], "/vendor"), (components["rust"], "/rust-toolchain")]]
    sysroot = output / "sysroot" if producer else args.sysroot.resolve(strict=True)
    producer_manifest = None
    if not producer:
        producer_manifest = json.loads((sysroot / "producer.json").read_text())
        assert producer_manifest["rust_commit"] == manifest["rust_commit"]
        assert producer_manifest["target_sha256"] == sha256(target)
        for row in producer_manifest["libraries"]:
            file = sysroot / "lib/rustlib/x86_64-aros/lib" / row["name"]
            assert file.stat().st_size == row["bytes"] and sha256(file) == row["sha256"]
        flags += ["--sysroot=" + str(sysroot)]
    config = '[source.crates-io]\nreplace-with="vendored"\n[source.vendored]\ndirectory=' + json.dumps(str(components["vendor"])) + '\n'
    (work / "cargo-home/config.toml").write_text(config)
    env = {"HOME": os.environ["HOME"], "PATH": str(rust) + ":/usr/bin:/bin", "CARGO_HOME": str(work / "cargo-home"),
           "RUSTC": str(rust / "rustc"), "RUSTDOC": str(rust / "rustdoc"), "CARGO_BUILD_JOBS": "2",
           "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(work / "target"),
           "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags), "TMPDIR": str(work / "tmp"), "LC_ALL": "C", "TZ": "UTC",
           "SOURCE_DATE_EPOCH": str(manifest["source_date_epoch"]), "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""}
    cargo = rust / "cargo"
    if args.cargo_producer_record:
        producer_result = json.loads(args.cargo_producer_record.read_text())
        assert producer_result["exit_code"] == 0 and producer_result["stop_reason"] is None
        artifact = producer_result["artifact"]
        cargo = Path(artifact["path"]).resolve(strict=True)
        assert cargo.stat().st_size == artifact["bytes"] and sha256(cargo) == artifact["sha256"]
    command = [str(cargo), "-Zjson-target-spec"]
    if args.cargo_producer_record and not args.upstream_metadata:
        command += ["-Zami-rust-reproducible-cross"]
    if producer:
        command += ["-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem"]
    command += ["build", "--manifest-path", str(root / "Cargo.toml"), "--package", "ami-rust-sha256sum",
                "--target", str(target), "--release", "--locked", "--offline", "-j", "2", "-vv", "--message-format=json-render-diagnostics"]
    inputs = {"claim": "development only; Cargo/sysroot experiment, frontend identity explicit", "phase": "producer" if producer else "consumer",
              "command": command, "environment": env, "project_lock_sha256": sha256(lock_path),
              "cargo_sha256": sha256(cargo), "patched_cargo_trial": bool(args.cargo_producer_record), "rustc_verbose": subprocess.check_output([str(rust / "rustc"), "-Vv"], text=True),
              "sysroot_manifest_sha256": None if producer else sha256(sysroot / "producer.json"), "prerequisite_inventory_counts": counts}
    (output / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    start = time.monotonic()
    peak_rss = peak_work = 0
    reason = None
    with (output / "stdout.log").open("wb") as stdout, (output / "stderr.log").open("wb") as stderr:
        child = subprocess.Popen(command, cwd=work, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        while child.poll() is None:
            try:
                peak_rss = max(peak_rss, rss_tree(child.pid))
                peak_work = max(peak_work, tree_bytes(output))
            except (OSError, subprocess.SubprocessError) as error:
                reason = "resource sampler failed: " + str(error)
            if time.monotonic()-start > 1200: reason = "build timeout"
            if peak_rss > 8 * 1024**3: reason = "aggregate RSS cap"
            if peak_work > 12 * 1024**3: reason = "workspace cap"
            if stdout.tell()+stderr.tell() > 16*1024**2: reason = "log cap"
            if reason:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                break
            time.sleep(0.1)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
    result = {"exit_code": child.returncode, "stop_reason": reason, "elapsed_seconds": time.monotonic()-start,
              "rss_peak_observed_bytes": peak_rss, "workspace_peak_observed_bytes": max(peak_work, tree_bytes(output))}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    if child.returncode or reason:
        print(json.dumps(result, indent=2))
        raise SystemExit(1)
    archives = []
    for line in (output / "stdout.log").read_text().splitlines():
        if line.startswith("[") and "] " in line:
            continue
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact" and message["target"]["name"] == "ami_rust_sha256sum":
            archives += [Path(name) for name in message["filenames"] if name.endswith(".a")]
    assert len(archives) == 1, archives
    shutil.copyfile(archives[0], output / "application.a")
    result["archive_sha256"] = sha256(output / "application.a")
    generated_libraries = sorted((work / "target/x86_64-aros/release").rglob("*.rlib"))
    if producer:
        library_dir = sysroot / "lib/rustlib/x86_64-aros/lib"
        library_dir.mkdir(parents=True)
        libraries = []
        for crate in ("core", "alloc", "compiler_builtins"):
            candidates = list((work / "target/x86_64-aros/release/deps").glob("lib" + crate + "-*.rlib"))
            assert len(candidates) == 1, (crate, candidates)
            source = candidates[0]
            destination = library_dir / source.name
            # Cargo is terminal; retain the exact file without a second full
            # on-disk copy before retiring the cold build cache.
            shutil.move(source, destination)
            libraries.append({"name": destination.name, "bytes": destination.stat().st_size, "sha256": sha256(destination)})
        producer_manifest = {"claim": "development sysroot, not accepted release asset", "rust_commit": manifest["rust_commit"],
                             "target_sha256": sha256(target), "libraries": libraries, "producer_inputs_sha256": sha256(output / "inputs.json")}
        (sysroot / "producer.json").write_text(json.dumps(producer_manifest, indent=2) + "\n")
    # Preserve every target rlib, including SDK/runtime facades and dependencies,
    # rather than using the application archive alone to claim reproducibility.
    # Standard libraries already retained in the producer sysroot are referenced
    # there once, so this does not duplicate their full metadata payloads.
    target_libraries = []
    for source in generated_libraries:
        name = source.relative_to(work / "target/x86_64-aros/release").as_posix()
        standard = sysroot / "lib/rustlib/x86_64-aros/lib" / source.name
        if producer and standard.is_file():
            destination = standard
        else:
            destination = output / "target-libraries" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(source, destination)
        target_libraries.append({"path": name, "bytes": destination.stat().st_size,
                                 "sha256": sha256(destination), "retained_path": str(destination)})
    result["target_libraries"] = target_libraries
    result["workspace_peak_observed_bytes"] = max(result["workspace_peak_observed_bytes"], tree_bytes(output))
    assert result["workspace_peak_observed_bytes"] <= 12 * 1024**3
    select(lock_path)
    result["status"] = "BUILD_PASS_NOT_RELEASE_ACCEPTANCE"
    result["retained_sysroot"] = str(sysroot)
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    shutil.rmtree(work)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

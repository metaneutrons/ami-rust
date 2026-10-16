"""Bounded selection and failed-provisioning probes for the hosted consumer route.

These probes add evidence to existing M2/R1 criteria. They do not confer final
acceptance; the caller runs them against the actual installed candidate on each
host after the documented consumer builds.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat


COMPONENTS = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")
UTILITY_ARGS = ("build", "--package", "ami-rust-sha256sum", "--release",
                "--locked", "--offline")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _strict_json(path: Path, limit: int = 16 * 1024 * 1024) -> tuple[dict, bytes]:
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_size > limit:
        raise ValueError("missing, linked or oversized JSON input: " + str(path))
    raw = path.read_bytes()

    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object: " + path.name)
    return value, raw


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _log_bytes(supervisor, row: dict) -> tuple[bytes, bytes]:
    return ((supervisor.work / row["stdout_log"]).read_bytes(),
            (supervisor.work / row["stderr_log"]).read_bytes())


def _process_record(supervisor, row: dict, command: list[str]) -> dict:
    stdout, stderr = _log_bytes(supervisor, row)
    return {"command": [str(part) for part in command], "process": row,
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
            "stdout_base64": base64.b64encode(stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(stderr).decode("ascii"),
            "stdout_sha256": _sha(stdout), "stderr_sha256": _sha(stderr)}


def _run_ok(supervisor, command: list[str], *, cwd: Path, label: str,
            timeout: int = 300) -> dict:
    row = supervisor.run(command, cwd=cwd, label=label, timeout=timeout)
    if (row.get("label") != label or row.get("exit_code") != 0
            or row.get("stop_reason") is not None):
        raise RuntimeError("successful supervised command has an invalid process record: " + label)
    return _process_record(supervisor, row, command)


def _expect_refusal(supervisor, command: list[str], *, cwd: Path, label: str,
                    diagnostics: tuple[str, ...], absent: tuple[Path, ...]) -> dict:
    if any(path.exists() or path.is_symlink() for path in absent):
        raise ValueError("refusal probe destinations must be fresh: " + label)
    raised = False
    try:
        supervisor.run(command, cwd=cwd, label=label, timeout=300)
    except RuntimeError:
        raised = True
    if not raised:
        raise ValueError("negative selection probe returned normally: " + label)
    if not supervisor.commands:
        raise ValueError("negative selection probe has no process record: " + label)
    row = supervisor.commands[-1]
    if (row.get("label") != label or type(row.get("exit_code")) is not int
            or row["exit_code"] == 0 or row.get("stop_reason") is not None):
        raise ValueError("negative selection probe stopped or did not exit nonzero: " + label)
    record = _process_record(supervisor, row, command)
    if any(token not in record["stderr"] for token in diagnostics):
        raise ValueError("negative selection probe had the wrong diagnostic: " + label
                         + "; expected " + repr(diagnostics) + "; got " + record["stderr"])
    missing = [str(path) for path in absent if path.exists() or path.is_symlink()]
    if missing:
        raise ValueError("refused selection probe created accepted output: " + ", ".join(missing))
    record["expected_diagnostics"] = list(diagnostics)
    record["accepted_output_absent"] = True
    return record


def _cli_command(python: Path, cli: Path, lock: Path, output: Path,
                 sdk_root: Path | None = None, extra: tuple[str, ...] = ()) -> list[str]:
    sdk_root = sdk_root or cli.parent.parent
    return [str(python), "-I", "-B", str(cli), "build", "--sdk-lock", str(lock),
            "--output-dir", str(output), "--", "build", "--manifest-path",
            str(sdk_root / "Cargo.toml"), *UTILITY_ARGS[1:], *extra]


def _run_verify(supervisor, python: Path, cli: Path, lock: Path, *, host: str,
                sdk_sha: str, label: str, cwd: Path) -> dict:
    command = [str(python), "-I", "-B", str(cli), "verify", "--sdk-lock", str(lock)]
    row = _run_ok(supervisor, command, cwd=cwd, label=label, timeout=60)
    try:
        response = json.loads(row["stdout"])
    except json.JSONDecodeError as error:
        raise ValueError("installed CLI verification returned invalid JSON: " + label) from error
    if (response.get("status") != "verified" or response.get("host") != host
            or response.get("sdk_manifest_sha256") != sdk_sha):
        raise ValueError("installed CLI verification differs from the selected SDK: " + label)
    row["result"] = response
    return row


def _component_bindings(sdk: dict, components: dict[str, Path], sdk_root: Path) -> dict:
    info = sdk.get("component_info")
    if not isinstance(info, dict) or set(info) != set(COMPONENTS) or set(components) != set(COMPONENTS):
        raise ValueError("selection probe needs the six verified host components")
    rows = {}
    for name in COMPONENTS:
        details = info[name]
        relative = details.get("manifest_path")
        manifest = details.get("manifest")
        if (not isinstance(relative, str) or not isinstance(manifest, dict)
                or not isinstance(manifest.get("files"), list)
                or not isinstance(manifest.get("symlinks"), list)):
            raise ValueError("selected component inventory binding is incomplete: " + name)
        manifest_path = sdk_root / relative
        digest = _file_sha(manifest_path)
        if digest != details.get("manifest_sha256"):
            raise ValueError("installed component manifest differs from preparation: " + name)
        rows[name] = {"root": str(components[name].resolve(strict=True)),
                      "manifest_path": relative, "manifest_sha256": digest,
                      "files": len(manifest["files"]), "symlinks": len(manifest["symlinks"])}
    return rows


def _check_preexisting_state(consumer: Path, sdk: dict, components: dict[str, Path],
                             python: Path, host: str) -> tuple[dict, Path, Path, Path]:
    prefix = consumer / "sdk-0.1.0"
    sdk_root = prefix / "sdk"
    manifest_path = sdk_root / "contract/sdk.json"
    lock_path = consumer / "utility.lock.json"
    selection_path = consumer / "selection.json"
    receipt_pin = consumer / "receipt.sha256"
    for path in (prefix, sdk_root, manifest_path, lock_path, selection_path, receipt_pin,
                 prefix / "install-receipt.json"):
        if path.is_symlink() or not path.exists():
            raise ValueError("selection probe requires the installed consumer state: " + str(path))
    manifest_sha = _file_sha(manifest_path)
    if manifest_sha != sdk.get("manifest_sha256"):
        raise ValueError("installed SDK manifest differs from the prepared candidate")
    installed_manifest, _ = _strict_json(manifest_path)
    if installed_manifest.get("qualification_only") is not False:
        raise ValueError("selection probe requires the production SDK route")
    selection, selection_raw = _strict_json(selection_path)
    expected_components = {name: str(components[name].resolve(strict=True)) for name in COMPONENTS}
    if (selection.get("python") != str(python.resolve(strict=True))
            or selection.get("components") != expected_components):
        raise ValueError("installed selection does not bind the prepared roots")
    pin_raw = receipt_pin.read_bytes()
    receipt_path = prefix / "install-receipt.json"
    receipt_sha = _file_sha(receipt_path)
    if pin_raw.decode("ascii").strip() != receipt_sha:
        raise ValueError("external receipt pin does not match the installed receipt")
    receipt, _ = _strict_json(receipt_path)
    if (receipt.get("sdk_manifest_sha256") != manifest_sha
            or receipt.get("version") != installed_manifest.get("version")):
        raise ValueError("installed receipt does not bind the selected SDK")
    state = {"sdk_root": str(sdk_root.resolve(strict=True)),
             "sdk_manifest_sha256": manifest_sha,
             "sdk_source_identity": installed_manifest.get("source_identity"),
             "sdk_version": installed_manifest.get("version"),
             "release_manifest_sha256": receipt.get("release_manifest_sha256"),
             "receipt_sha256": receipt_sha, "receipt_pin_sha256": _sha(pin_raw),
             "utility_lock_sha256": _file_sha(lock_path),
             "selection_sha256": _sha(selection_raw),
             "cargo_toml_sha256": _file_sha(sdk_root / "Cargo.toml"),
             "cargo_lock_sha256": _file_sha(sdk_root / "Cargo.lock"),
             "component_inventories": _component_bindings(sdk, components, sdk_root)}
    return state, sdk_root, lock_path, receipt_pin


def _copy_budget(supervisor, source: Path, label: str) -> None:
    required = sum(path.lstat().st_size for path in source.rglob("*")
                   if stat.S_ISREG(path.lstat().st_mode))
    if supervisor.managed_bytes() + required > supervisor.limits["workspace_bytes"]:
        raise RuntimeError("isolated selection copy exceeds the admitted workspace ceiling: " + label)


def _replace_first_byte(path: Path, *, append: bool = False) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("probe mutation target must be a regular copied file: " + str(path))
    original = path.read_bytes()
    if not original:
        raise ValueError("probe mutation target is empty: " + str(path))
    changed = original + b"\nselection-probe-mutation\n" if append else bytes((original[0] ^ 1,)) + original[1:]
    path.write_bytes(changed)
    if path.read_bytes() != changed:
        raise RuntimeError("isolated mutation readback failed: " + str(path))


def _run_selection_refusals(supervisor, python: Path, cli: Path, consumer: Path,
                            sdk_root: Path, lock_path: Path, lock: dict,
                            components: dict[str, Path], host: str, probe_root: Path) -> list[dict]:
    rows = []
    other_host = "macos-aarch64" if host == "linux-x86_64" else "linux-x86_64"
    cases = ("missing-lock", "incompatible-schema", "wrong-host", "wrong-sdk-manifest",
             "changed-cargo-lock", "changed-rustc", "changed-linker", "target-override")
    sdk_files = {row["path"] for row in json.loads((sdk_root / "contract/sdk.json").read_text())["files"]}
    for case in cases:
        directory = probe_root / case
        directory.mkdir(mode=0o700)
        try:
            copied_lock = directory / "utility.lock.json"
            candidate = json.loads(json.dumps(lock))
            if case != "missing-lock":
                copied_lock.write_bytes(_canonical(candidate))
            copy_readback, mutation = None, {}
            if case == "missing-lock":
                diagnostics = ("missing project lock",)
                mutation = {"lock": "absent"}
            elif case in ("incompatible-schema", "wrong-host", "wrong-sdk-manifest"):
                if case == "incompatible-schema":
                    candidate["schema"] = "ami-rust-project-lock-incompatible"
                    mutation = {"schema": candidate["schema"]}
                    diagnostics = ("missing or incompatible ami-rust project lock schema",)
                elif case == "wrong-host":
                    candidate["host"]["platform"] = other_host
                    mutation = {"host": other_host}
                    diagnostics = ("project host platform does not match this machine",)
                else:
                    actual = candidate["sdk"]["manifest_sha256"]
                    candidate["sdk"]["manifest_sha256"] = ("0" if actual[0] != "0" else "1") + actual[1:]
                    mutation = {"sdk_manifest_sha256": candidate["sdk"]["manifest_sha256"]}
                    diagnostics = ("SDK manifest identity mismatch",)
                copied_lock.write_bytes(_canonical(candidate))
            elif case == "changed-cargo-lock":
                _copy_budget(supervisor, sdk_root, case)
                copied_sdk = directory / "copied-sdk"
                shutil.copytree(sdk_root, copied_sdk, symlinks=True)
                candidate["sdk"]["root"] = str(copied_sdk.resolve(strict=True))
                copied_lock.write_bytes(_canonical(candidate))
                copy_readback = _run_verify(
                    supervisor, python, cli, copied_lock, host=host,
                    sdk_sha=candidate["sdk"]["manifest_sha256"],
                    label="selection-probe-changed-cargo-lock-copy-readback", cwd=consumer)
                _replace_first_byte(copied_sdk / "Cargo.lock", append=True)
                diagnostics = (("SDK file identity mismatch: Cargo.lock",) if "Cargo.lock" in sdk_files
                               else ("project Cargo manifest/lock identity mismatch",))
                mutation = {"sdk_root": str(copied_sdk), "path": "Cargo.lock"}
            elif case in ("changed-rustc", "changed-linker"):
                component = "rust" if case == "changed-rustc" else "toolchain"
                _copy_budget(supervisor, components[component], case)
                copied_component = directory / (component + "-copy")
                shutil.copytree(components[component], copied_component, symlinks=True)
                relative = "bin/rustc" if case == "changed-rustc" else "bin/ld.lld"
                selected = copied_component / relative
                resolved = selected.resolve(strict=True)
                try:
                    resolved.relative_to(copied_component.resolve(strict=True))
                except ValueError as error:
                    raise ValueError("selected linker/compiler copy resolves outside its isolated root: " + case) from error
                if not resolved.is_file() or resolved.is_symlink():
                    raise ValueError("selected linker/compiler copy did not resolve to a regular file: " + case)
                candidate["components"][component] = str(copied_component.resolve(strict=True))
                copied_lock.write_bytes(_canonical(candidate))
                copy_readback = _run_verify(
                    supervisor, python, cli, copied_lock, host=host,
                    sdk_sha=candidate["sdk"]["manifest_sha256"],
                    label="selection-probe-" + case + "-copy-readback", cwd=consumer)
                inventory_path = resolved.relative_to(copied_component).as_posix()
                _replace_first_byte(resolved)
                diagnostics = ("component identity mismatch: " + inventory_path,)
                mutation = {"component": component, "path": inventory_path}
            elif case == "target-override":
                copied_lock.write_bytes(lock_path.read_bytes())
                diagnostics = ("unsupported or SDK-owned Cargo option: --target=unqualified-target",)
                mutation = {"cargo_argument": "--target=unqualified-target"}
            supervisor.check_limits("isolated selection mutation " + case)
            output = directory / "accepted-build"
            command_sdk_root = Path(candidate["sdk"]["root"]).resolve() if case == "changed-cargo-lock" else sdk_root
            command = _cli_command(python, cli, copied_lock, output, command_sdk_root,
                                   ("--target=unqualified-target",) if case == "target-override" else ())
            record = _expect_refusal(supervisor, command, cwd=consumer,
                                     label="selection-probe-" + case,
                                     diagnostics=diagnostics, absent=(output,))
            record.update({"case": case, "project_lock_sha256":
                           _file_sha(copied_lock) if copied_lock.exists() else None,
                           "isolated_copy_root": str(directory),
                           "full_copy_readback": copy_readback, "mutation": mutation})
            rows.append(record)
        finally:
            if directory.is_symlink():
                raise RuntimeError("selection probe scratch unexpectedly became a symlink: " + case)
            shutil.rmtree(directory)
            supervisor.check_limits("retired isolated selection mutation " + case)
    return rows


def _version_identity(supervisor, env: dict[str, str], rustc: Path, cargo: Path,
                      consumer: Path, label: str) -> dict:
    previous_env = supervisor.env
    supervisor.env = env
    try:
        rust = _run_ok(supervisor, [str(rustc), "-Vv"], cwd=consumer,
                       label=label + "-rustc-version", timeout=60)
        cargo_row = _run_ok(supervisor, [str(cargo), "-Vv"], cwd=consumer,
                            label=label + "-cargo-version", timeout=60)
    finally:
        supervisor.env = previous_env
    return {"rustc": rust, "cargo": cargo_row,
            "rustc_binary_sha256": _file_sha(rustc), "cargo_binary_sha256": _file_sha(cargo)}


def _sentinels(root: Path) -> dict:
    entries = {
        root / "home/.cargo/config.toml": b"# selection probe HOME sentinel v1\n",
        root / "cargo-home/config.toml": b"# selection probe CARGO_HOME sentinel v1\n",
        root / "rustup-home/settings.toml": b"# selection probe RUSTUP_HOME sentinel v1\n",
    }
    for path, raw in entries.items():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    return {str(path): {"sha256": _file_sha(path), "bytes": path.stat().st_size}
            for path in entries}


def _failed_install_probe(supervisor, python: Path, bundle: Path, policy: Path,
                          consumer: Path, probe_root: Path, host: str,
                          rustc: Path, cargo: Path) -> dict:
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        raise RuntimeError("permission-preservation probe requires the standard non-root hosted runner")
    if platform.system() not in ("Darwin", "Linux"):
        raise RuntimeError("permission-preservation probe requires a supported POSIX host")
    if bundle.resolve(strict=True) == policy.resolve(strict=True) or bundle.resolve() in policy.resolve().parents:
        raise ValueError("publisher policy must remain outside the candidate bundle")
    if not policy.is_file() or policy.is_symlink():
        raise ValueError("permission probe requires the prepared external publisher policy")

    env_root = probe_root / "provisioning-env"
    env_root.mkdir(mode=0o700)
    before_sentinels = _sentinels(env_root)
    isolated_env = dict(supervisor.env)
    isolated_env.update({"HOME": str(env_root / "home"),
                         "CARGO_HOME": str(env_root / "cargo-home"),
                         "RUSTUP_HOME": str(env_root / "rustup-home")})
    before_versions = _version_identity(supervisor, isolated_env, rustc, cargo, consumer,
                                        "provisioning-before")

    denied_parent = probe_root / "permission-denied-parent"
    denied_parent.mkdir(mode=0o700)
    initial_names = sorted(path.name for path in denied_parent.iterdir())
    prefix = denied_parent / "failed-install"
    receipt_pin = probe_root / "failed-install-receipt.sha256"
    if prefix.exists() or receipt_pin.exists() or receipt_pin.is_symlink():
        raise ValueError("failed-install probe destinations must be fresh")
    old_mode = stat.S_IMODE(denied_parent.stat().st_mode)
    command = [str(python), "-I", "-B", str(bundle / "install_publisher.py"), "install",
               "--bundle", str(bundle), "--policy", str(policy), "--prefix", str(prefix),
               "--receipt-pin", str(receipt_pin)]
    prior_env = supervisor.env
    try:
        os.chmod(denied_parent, 0o500)
        if os.access(denied_parent, os.W_OK):
            raise RuntimeError("permission-denied installation parent remains writable")
        supervisor.env = isolated_env
        record = _expect_refusal(supervisor, command, cwd=consumer,
                                 label="selection-probe-failed-provisioning",
                                 diagnostics=("Permission denied", str(denied_parent)),
                                 absent=(prefix, receipt_pin))
    finally:
        supervisor.env = prior_env
        os.chmod(denied_parent, old_mode)

    leftovers = sorted(path.name for path in denied_parent.iterdir())
    if leftovers != initial_names:
        raise ValueError("failed provisioning left a stage or installation under the denied parent")
    after_versions = _version_identity(supervisor, isolated_env, rustc, cargo, consumer,
                                       "provisioning-after")
    after_sentinels = {str(path): {"sha256": _file_sha(path), "bytes": path.stat().st_size}
                       for path in (env_root / "home/.cargo/config.toml",
                                    env_root / "cargo-home/config.toml",
                                    env_root / "rustup-home/settings.toml")}
    if before_versions["rustc_binary_sha256"] != after_versions["rustc_binary_sha256"]:
        raise ValueError("selected Rust compiler changed after failed provisioning")
    if before_versions["cargo_binary_sha256"] != after_versions["cargo_binary_sha256"]:
        raise ValueError("selected Cargo changed after failed provisioning")
    if (before_versions["rustc"]["stdout_sha256"] != after_versions["rustc"]["stdout_sha256"]
            or before_versions["cargo"]["stdout_sha256"] != after_versions["cargo"]["stdout_sha256"]):
        raise ValueError("selected Rust/Cargo stopped reporting the same usable identity after failed provisioning")
    if before_sentinels != after_sentinels:
        raise ValueError("isolated HOME/CARGO_HOME/RUSTUP_HOME configuration changed during failed provisioning")
    record.update({"host": host, "denied_parent": str(denied_parent),
                   "new_prefix_absent": True, "external_receipt_absent": True,
                   "partial_stage_absent": True, "permission_restored_mode": old_mode,
                   "isolated_config_sentinels_before": before_sentinels,
                   "isolated_config_sentinels_after": after_sentinels,
                   "selected_toolchain_before": before_versions,
                   "selected_toolchain_after": after_versions})
    return record


def qualify_selection_contract(*, supervisor, python, bundle, consumer, host, sdk, components):
    """Probe real selected pins and a failed install without changing trusted inputs."""
    python, bundle, consumer = Path(python), Path(bundle), Path(consumer)
    components = {name: Path(path) for name, path in components.items()}
    probe_root = consumer / ".selection-probe-scratch"
    if probe_root.exists() or probe_root.is_symlink():
        raise ValueError("selection probe output root must be fresh")
    probe_root.mkdir(mode=0o700)
    try:
        supervisor.check_limits("selection probe scratch root")
        before, sdk_root, lock_path, receipt_pin = _check_preexisting_state(
            consumer, sdk, components, python, host)
        if before["release_manifest_sha256"] != _file_sha(bundle / "release.json"):
            raise ValueError("installed receipt does not bind the prepared release manifest")
        cli = sdk_root / "host/cli.py"
        lock, lock_raw = _strict_json(lock_path, 1024 * 1024)
        selection_path = consumer / "selection.json"
        selection_raw = selection_path.read_bytes()
        initial_verify = _run_verify(supervisor, python, cli, lock_path, host=host,
                                     sdk_sha=before["sdk_manifest_sha256"],
                                     label="selection-probe-verify-before", cwd=consumer)
        profile = sdk["manifest"]["profiles"][host]
        rustc = components["rust"] / "bin/rustc"
        cargo = components["cargo"] / profile["cargo_binary"]
        target = sdk_root / "targets/x86_64-aros.json"
        if target.is_symlink() or not target.is_file():
            raise ValueError("installed SDK target specification is missing or linked")
        target_sha = _file_sha(target)
        toolchain = components["toolchain"] / "bin/ld.lld"
        linker_resolved = toolchain.resolve(strict=True)
        linker_resolved.relative_to(components["toolchain"].resolve(strict=True))
        compiler_identity = _version_identity(supervisor, dict(supervisor.env), rustc, cargo,
                                              consumer, "selection-before-build")
        rustc_text = compiler_identity["rustc"]["stdout"]
        expected_rust = ("commit-hash: " + sdk["manifest"]["rust_commit"],
                         "LLVM version: " + sdk["manifest"]["rust_llvm"],
                         "host: " + profile["rust_host"])
        if any(value not in rustc_text for value in expected_rust):
            raise ValueError("selected compiler identity differs from installed SDK manifest")

        negative_rows = _run_selection_refusals(supervisor, python, cli, consumer, sdk_root,
                                                lock_path, lock, components, host, probe_root)
        after_negative_verify = _run_verify(supervisor, python, cli, lock_path, host=host,
                                            sdk_sha=before["sdk_manifest_sha256"],
                                            label="selection-probe-verify-after-refusals", cwd=consumer)
        if (_file_sha(lock_path) != before["utility_lock_sha256"]
                or _file_sha(selection_path) != before["selection_sha256"]
                or receipt_pin.read_text(encoding="ascii").strip() != before["receipt_sha256"]):
            raise ValueError("selection refusal cases changed installed lock, selection or receipt")

        policy = consumer.parent.parent / "trust/publisher-policy.json"
        install_preservation = _failed_install_probe(
            supervisor, python, bundle, policy, consumer, probe_root, host, rustc, cargo)
        final_verify = _run_verify(supervisor, python, cli, lock_path, host=host,
                                   sdk_sha=before["sdk_manifest_sha256"],
                                   label="selection-probe-verify-after-failed-provision", cwd=consumer)
        after, _, _, _ = _check_preexisting_state(consumer, sdk, components, python, host)
        if before != after:
            raise ValueError("pre-existing SDK selection or component bindings changed during probes")
        if (_file_sha(lock_path) != _sha(lock_raw) or selection_path.read_bytes() != selection_raw
                or receipt_pin.read_text(encoding="ascii").strip() != before["receipt_sha256"]):
            raise ValueError("pre-existing consumer lock, selection or receipt changed during probes")
        native = Path(supervisor.output) / "native/sha256sum.AMIRUST"
        if native.is_symlink() or not native.is_file():
            raise ValueError("accepted recipe utility artifact is missing from retained consumer output")
        supervisor.check_limits("completed selection contract probes")

        report = {
            "status": "PASS_SELECTION_CONTRACT_PROBES_ONLY",
            "host": host,
            "candidate": {"release_manifest_sha256": _file_sha(bundle / "release.json"),
                          "sdk_manifest_sha256": before["sdk_manifest_sha256"],
                          "sdk_source_identity": before["sdk_source_identity"],
                          "sdk_version": before["sdk_version"]},
            "installed_state_before": before,
            "selected_toolchain": {
                "rust_commit": sdk["manifest"]["rust_commit"],
                "rust_llvm": sdk["manifest"]["rust_llvm"],
                "rust_host": profile["rust_host"], "rustc": compiler_identity["rustc"],
                "rustc_binary_sha256": compiler_identity["rustc_binary_sha256"],
                "cargo": compiler_identity["cargo"],
                "cargo_binary_sha256": compiler_identity["cargo_binary_sha256"],
                "cargo_path": str(cargo.resolve(strict=True)),
                "target_spec": {"path": str(target), "sha256": target_sha},
                "linker": {"path": str(toolchain), "resolved_path": str(linker_resolved),
                           "sha256": _file_sha(linker_resolved)}},
            "accepted_recipe_utility_artifact": {"path": str(native), "bytes": native.stat().st_size,
                                                  "sha256": _file_sha(native)},
            "utility_lock_verification": {"before": initial_verify,
                                           "after_refusals": after_negative_verify,
                                           "after_failed_provision": final_verify},
            "selection_refusals": negative_rows,
            "failed_provisioning_preservation": install_preservation,
            "installed_state_after": after,
            "probe_scratch_retired": True,
            "claims": {"actual_host_selection_probes": True,
                       "prior_install_preserved_after_failed_provisioning": True,
                       "final_milestone_acceptance": False,
                       "signed_or_published": False}}
    finally:
        if probe_root.exists() or probe_root.is_symlink():
            if probe_root.is_symlink() or not probe_root.is_dir():
                raise RuntimeError("selection probe scratch root changed type")
            shutil.rmtree(probe_root)
            supervisor.check_limits("retired selection probe scratch")
    return report

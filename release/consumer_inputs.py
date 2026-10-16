"""Provision the six authenticated consumer prerequisites for qualification.

The caller must authenticate ``bundle`` and extract its SDK before calling this
module.  Dependencies are supplied by the caller so this code can share the
producer's pinned-input helpers without importing the consumer verifier.
"""
from __future__ import annotations

from pathlib import Path


def provision_inputs(bundle: Path, work: Path, supervisor, host: str,
                     sdk_info: dict, reference_inputs: dict, *, sdk, auth,
                     extract_cargo) -> dict:
    """Install and fully verify the six prerequisites in a fresh staging root."""
    component_staging = work / "component-staging"
    # Deliberately require a fresh root before invoking any provider.  Besides
    # preventing stale files from entering qualification, this preserves the
    # original consumer block's fail-before-install behavior.
    component_staging.mkdir(mode=0o700)

    component_info = sdk_info["component_info"]
    host_rows = reference_inputs["hosts"][host]
    rust_root, rust_archives, rust_installer = sdk._install_rust(
        host_rows, reference_inputs, work, component_staging, supervisor)
    version = supervisor.run_text([str(rust_root / "bin/rustc"), "-Vv"], cwd=work,
                                  label="verify-consumer-rust-identity", timeout=30)
    if ("commit-hash: " + reference_inputs["rust_commit"] not in version
            or "LLVM version: " + reference_inputs["rust_llvm"] not in version
            or "host: " + sdk.HOST_TARGETS[host] not in version):
        raise ValueError("installed Rust prerequisite differs from the pinned release profile")

    staging = {"rust": rust_root}
    toolchain, toolchain_pin, toolchain_extraction = sdk._extract_pinned_component(
        host_rows["toolchain"], "toolchain", work, component_staging / "toolchain", supervisor)
    collector, collector_pin, collector_extraction = sdk._extract_pinned_component(
        host_rows["collector"], "collector", work, component_staging / "collector", supervisor,
        component_info["collector"]["manifest"])
    staging.update({"toolchain": toolchain, "collector": collector})

    shared_inputs = reference_inputs["shared"]
    shared_receipts = {}
    for name in ("csdk", "vendor"):
        pin = (sdk.portable_csdk_prerequisite(reference_inputs)
               if name == "csdk" else shared_inputs[name])
        root, receipt = sdk._extract_local_component(
            pin, name, component_staging / name, supervisor)
        staging[name] = root
        shared_receipts[name] = receipt

    cargo_manifest = component_info["cargo"]["manifest"]
    cargo_archive = bundle / f"cargo-{host}.tar.xz"
    auth.cargo_matches(cargo_archive.read_bytes(), cargo_manifest)
    cargo_root = component_staging / "cargo"
    cargo_inventory = extract_cargo(cargo_archive, cargo_root, cargo_manifest)
    staging["cargo"] = cargo_root

    component_roots = {name: staging[name] for name in
                       ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")}
    component_inventories = {
        name: sdk.verify_component(root, component_info[name]["manifest"], name)
        for name, root in component_roots.items()
    }
    supervisor.check_limits("all six verified consumer prerequisites")

    return {
        "component_roots": component_roots,
        "component_inventories": component_inventories,
        "rust_archives": rust_archives,
        "rust_installer": rust_installer,
        "toolchain": {"pin": toolchain_pin, "extraction": toolchain_extraction},
        "collector": {"pin": collector_pin, "extraction": collector_extraction},
        "shared": shared_receipts,
        "cargo_archive_sha256": sdk.sha256(cargo_archive),
        "cargo_inventory": cargo_inventory,
    }

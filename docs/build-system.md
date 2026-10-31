---
title: Build system
description: How aros-native-build and aros-link turn a Cargo project into a verified AROS executable, and what they refuse.
---

An ami-rust application is built by ordinary Cargo. Two pieces of the toolchain take part, and both are deliberately strict about their inputs so that the executable you get is the one the release was qualified to produce.

| Piece | Where it runs | What it does |
| --- | --- | --- |
| `aros_native_build::prepare` | In your `build.rs`, once per build | Compiles the small C **native bridge** that `aros` and `aros-mui` call into, for the selected ABI. |
| `aros-link` | As Cargo's target linker | Links the Rust objects with the bridge and the SDK, strips the result and validates the ELF before Cargo sees it. |

Neither calls Cargo, resolves packages, downloads anything, installs an SDK or changes your project or your rustup state.

## `build.rs`

Every application, and every crate that links the native bridge, has the same two-line build script:

```rust
fn main() {
    aros_native_build::prepare(Default::default()).expect("AROS native bridge");
}
```

`aros-native-build` is a build dependency only. Your application code never imports it.

### What `prepare` does

1. Verifies that the build is a supported one (see the table below).
2. Stages the native bridge sources and compiles them with the toolchain's pinned C SDK and compiler into `$OUT_DIR/ami-native`. That is the startup object, the SDK bridge, the layout checks and, on ABI-v1, the entry gate.
3. Records the size and SHA-256 of the toolchain's linker and of every object it produced, and re-verifies them.
4. Tells Cargo to pass `--no-gc-sections` and the location of those objects to the linker, and to re-run when the toolchain, the compiler or any relevant environment variable changes.

`BuildOptions` has one field, `testing`, which enables C hooks used only by the release qualification. Use `Default::default()`; `testing` is not an application feature.

### What `prepare` refuses

A refusal ends the build with a message of the form `AROS native bridge: Refusal { message: "…" }`. Revisions after 0.1.0 also print the cause and the usual fix on standard error just before it. Each refusal has a cause and a remedy; the [troubleshooting](/troubleshooting/) page shows how to fix the common ones.

| Message | Cause |
| --- | --- |
| `native bridge requires a supported AROS target` | The Cargo target is not `x86_64-unknown-aros-abi1` or `x86_64-unknown-aros-abi11`. |
| `Cargo host does not match the admitted native tools` | The build host is not one of the three qualified hosts. |
| `RUST_TARGET_PATH must be unset or empty for the selected toolchain` | `RUST_TARGET_PATH` is set. The toolchain supplies its own target specification. |
| `AROS target flags must not override the selected sysroot or target` | `--sysroot` or `--target` appears in your rustflags. |
| `AROS target flags must not override Cargo's selected target linker` | `-C linker=…` or `-C linker-flavor=…` appears in your rustflags. |
| `RUSTC_WRAPPER conflicts with the pinned compiler selection` | A compiler wrapper is configured, through the environment or through `build.rustc-wrapper` in a Cargo configuration file. `RUSTC_WORKSPACE_WRAPPER` is treated the same way. Revisions after 0.1.0 accept the caching wrapper `sccache` and refuse every other wrapper; the 0.1.0 tag refuses all of them. |
| `Cargo must explicitly select this toolchain's aros-link` | The target's `linker` setting is missing or points elsewhere. |
| `build must use the toolchain's paired Cargo` | The Cargo that launched the build is not the one shipped with the selected toolchain. |
| `selected compiler or target specification is missing` | The toolchain installation is incomplete. |

These checks establish that the compiler, Cargo, linker and target specification all belong to the same pinned toolchain. They are input-consistency checks. They are not a sandbox for arbitrary build scripts, and they do not authenticate the toolchain; for that, verify the release signatures as described in [Install and build](/quickstart-toolchain/#install-the-direct-archive).

### Compiler wrappers

Cargo can run `rustc` through a wrapper, configured by `RUSTC_WRAPPER` or `RUSTC_WORKSPACE_WRAPPER` in the environment, or by `build.rustc-wrapper` and `build.rustc-workspace-wrapper` in a Cargo configuration file. Revisions after 0.1.0 accept exactly one kind: the caching wrapper `sccache`. It stores and replays the output of the compiler Cargo selected, and `RUSTC` still names the pinned compiler, so every check above still runs against it.

The wrapper is recognised by the name of its executable. That is consistent with the rest of these checks, which establish input consistency and are not a sandbox: an executable that is called `sccache` is accepted. Any other wrapper is refused, because it could substitute the compiler. That includes `clippy-driver`. It is a compiler driver of its own, and the AROS toolchain does not ship clippy, so `cargo clippy` is not available for AROS targets.

## `aros-link`

Cargo invokes `aros-link` because your `.cargo/config.toml` names it as the target linker. It runs a fixed recipe:

1. Check that the object record from `prepare` and the toolchain are intact and still match the recorded hashes.
2. Link with the pinned collector, which combines the Rust objects, the bridge objects and the SDK startup.
3. Strip the output.
4. Compact ELF section names and validate the result as an AROS ELF for the selected ABI (this uses [`aros-elf`](/architecture/)).
5. Publish the executable atomically. The output path must not overlap the verified native inputs or the toolchain.

If any step fails, `aros-link` prints `aros-link: <reason>` and returns a non-zero status, so Cargo never sees a half-validated executable. The executable's ELF type is reported as relocatable by tools such as `file`. That is how AROS executables are linked, not an error.

## Why the guards matter

AROS programs call libraries through vector tables whose calling convention differs between the two [ABIs](/targets-and-abis/). If the compiler, C SDK or linker came from a different toolchain, the result could build cleanly and then misbehave on the target. Refusing at build time is cheaper than debugging it on a guest.

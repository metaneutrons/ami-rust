---
title: "aros-native-build: build script and linker"
description: The build-script helper and target linker that turn an ordinary Cargo project into a verified AROS executable.
---

`aros-native-build` is the build dependency of every AROS application. Its [`prepare`](/build-system/#buildrs) function compiles the native bridge that the SDK needs inside Cargo's own output directory, and its `aros-link` executable is the target linker that rustc calls for the two AROS targets. Cargo still resolves dependencies and selects the toolchain; this crate neither calls Cargo nor installs anything.

The [build system](/build-system/) page explains what `prepare` and `aros-link` check and what they refuse, with the message of each refusal and its fix. This page describes the crate itself.

## Use it

Add it as a build dependency and call `prepare` from `build.rs`:

```toml
[build-dependencies]
aros-native-build = { version = "=0.2.0", registry = "metaneutrons" }
```

Depend on it with `=` and the version of the toolchain you installed, so that the bridge sources it compiles are those of that toolchain release; the installed `aros-link` refuses a bridge that differs from the copy it was built with. The same crate is also available as a Git dependency on the release tag; see the [crates guide](/consumer-guide/). The `build.rs` that calls it is shown in the [build system](/build-system/#buildrs) guide.

## What it contains

| Item | Use |
| --- | --- |
| `prepare(BuildOptions)` | Compiles the bridge for the selected ABI into `OUT_DIR` and records the identity of every object and of the target linker. A refusal is explained on standard error with its usual remedy and returned as an error. |
| `BuildOptions` | `testing` also compiles the diagnostic binding unit and defines `AMI_SDK_TESTING=1`. It exists for the qualification builds and is not an application feature; leave it at the default `false`. |
| `link(arguments)` | The entry point of the linker interface, for the `aros-link` binary. It is not a Cargo command dispatcher. |
| `recipe` | The command recipes that `prepare` and the linker run: the C compiler arguments, the startup object, the collector step and the strip step, for each `ArosAbi`. |
| `Refusal`, `Result` | The error type shared with [`aros-elf`](/api/aros-elf/). A refusal carries a message and an exit status. |
| `aros-link` | The target linker. It runs the pinned collector, strips the output, compacts the ELF section names and validates the result before Cargo receives it. |

## What it relies on

The crate carries its own copy of the two target specifications and of the ABI-v11 SDK profile, so an archive of the crate builds on its own; inside the repository a test keeps those copies identical to the files that the release contract pins.

It trusts the installed rustup and its normal `rustc` launcher as prerequisites, and checks the compiler that rustup chose, the paired Cargo and the target linker against the pinned toolchain prefix. That is a consistency check of the inputs, not publisher authentication and not a sandbox for the build scripts of other crates. Supported hosts are macOS on Apple Silicon, Linux on x86-64 and Linux on ARM64.

Every public item is documented in the source; build the reference locally with the installed toolchain:

```text
cargo +"$toolchain" doc -p aros-native-build --no-deps --open
```

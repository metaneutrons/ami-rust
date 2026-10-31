---
title: Editor setup
description: Configure rust-analyzer so your editor analyses an AROS project for the right target and ABI.
---

An ami-rust project is an ordinary Cargo project, so any editor that runs rust-analyzer works. Three settings make the analysis match what Cargo will build. They were tested with rust-analyzer 0.3.3097 against the 0.1.0 toolchain.

## 1. Select the toolchain

Pin the toolchain for the project so that rust-analyzer, Cargo and rustc agree. Put this next to `Cargo.toml`:

```toml
# rust-toolchain.toml
[toolchain]
channel = "0.1.0"
```

With that file in place the editor needs no further toolchain setting.

## 2. Analyse for an AROS target

Set the target in your editor's rust-analyzer settings. For VS Code, in `.vscode/settings.json`:

```json
{
  "rust-analyzer.cargo.target": "x86_64-unknown-aros-abi11",
  "rust-analyzer.cargo.allTargets": false,
  "rust-analyzer.check.allTargets": false
}
```

Other editors take the same three keys, in their own rust-analyzer configuration syntax.

| Setting | Why |
| --- | --- |
| `cargo.target` | Without a target the editor builds for your host. The build script then stops with `native bridge requires a supported AROS target`, and the AROS-specific code is switched off, because it is compiled only for `target_os = "aros"`. |
| `cargo.allTargets` and `check.allTargets` | rust-analyzer also checks test targets by default. A `no_std` AROS target has no `test` crate, so every file gets a spurious `can't find crate for 'test'`. |

## Choose the ABI in the editor

`cargo.target` is also where you choose the ABI, and the editor then agrees with the compiler about [ABI-specific items](/reference/abi-differences/). A file that imports a class declared only for ABI-v1 shows:

- with `x86_64-unknown-aros-abi1`: no error;
- with `x86_64-unknown-aros-abi11`: `unresolved import 'aros_mui::classes::Panel'`.

If you build for both targets, switch the setting to the one you are working on.

## Compiler wrappers and clippy

- **`sccache`.** A user-wide `sccache` wrapper is fine with revisions after 0.1.0. The 0.1.0 tag refuses it and the editor shows the build-script error. See [Troubleshooting](/troubleshooting/#rustc_wrapper-conflicts-with-the-pinned-compiler-selection).
- **clippy.** The AROS toolchain ships no clippy, so `check.command = "clippy"` does not work for AROS targets. Keep the default, `check`.

## If the editor shows errors Cargo does not

Run the same check on the command line, with the same target:

```sh
cargo check --target x86_64-unknown-aros-abi11
```

If that succeeds, restart rust-analyzer so that it reloads the project, and check that `.cargo/config.toml` is in the project root. The [Cargo configuration](/quickstart-toolchain/#configure-cargo) is needed for the editor as well.

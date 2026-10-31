---
title: Troubleshooting
description: Causes and fixes for the build and start-up problems you are most likely to meet with ami-rust.
---

Find your symptom by its message. Build problems come first, then problems on the AROS system. Each build message below was reproduced against the 0.1.0 toolchain.

## Build problems

### `RUSTC_WRAPPER conflicts with the pinned compiler selection`

```text
AROS native bridge: Refusal { message: "RUSTC_WRAPPER conflicts with the pinned compiler selection", exit_code: 2 }
```

**Cause.** A compiler wrapper is active. The build refuses wrappers because one can replace the pinned compiler. A wrapper is often set once in `~/.cargo/config.toml` (`[build] rustc-wrapper = "…"`), so it can surprise you in a project that never mentions it. `RUSTC_WORKSPACE_WRAPPER` is treated the same way.

- **The caching wrapper `sccache`** is accepted by revisions after 0.1.0: it only caches the output of the compiler Cargo selected, and the checks on the compiler, Cargo and linker still apply. The 0.1.0 tag refuses it too, so with that revision either disable it as below or move your `rev` to a later revision.
- **Any other wrapper** is refused by every revision. Disable it as below.

Revisions after 0.1.0 also print this explanation, with the fix, next to the refusal. The 0.1.0 tag shows only the message above.

**Fix.** Disable the wrapper for this build, in whichever way suits you:

```sh
# one command
CARGO_BUILD_RUSTC_WRAPPER= cargo +0.1.0 build --target x86_64-unknown-aros-abi11 --release
```

```toml
# or in the project's .cargo/config.toml, which overrides your user-wide setting
[build]
rustc-wrapper = ""
```

### `custom targets are unstable and require -Zunstable-options`

```text
error: failed to run `rustc` to learn about target-specific information
  error: error loading target specification: custom targets are unstable and require `-Zunstable-options`
```

**Cause.** The AROS targets are custom target specifications, so rustc needs `-Zunstable-options`. Your project's `.cargo/config.toml` supplies it. The flag is missing when:

- there is no `.cargo/config.toml` in the directory you run Cargo from, or in a parent. Cargo looks for configuration relative to the **current directory**, not the manifest;
- the `RUSTFLAGS` environment variable is set, which *replaces* the `rustflags` from the configuration file.

**Fix.** Add the [Cargo configuration](/quickstart-toolchain/#configure-cargo), run Cargo from inside the project, and unset `RUSTFLAGS` (or include `-Zunstable-options` in it).

### `the option 'Z' is only accepted on the nightly compiler`

**Cause.** Cargo ran with a stable toolchain, not the ami-rust one.

**Fix.** Select the toolchain explicitly with `cargo +0.1.0 …`, or pin it for the project with a `rust-toolchain.toml`:

```toml
[toolchain]
channel = "0.1.0"
```

### `RUST_TARGET_PATH must be unset or empty for the selected toolchain`

**Cause.** `RUST_TARGET_PATH` is set in your environment. The toolchain brings its own, paired target specification, and a search path could substitute another.

**Fix.** `unset RUST_TARGET_PATH`.

### `error: no matching package named 'libc' found` with `--offline`

**Cause.** You passed `--offline` before Cargo had fetched the dependencies on this machine, for example on a clean checkout or with a fresh `CARGO_HOME`.

**Fix.** Fetch once, then build offline:

```sh
cargo +0.1.0 fetch --locked
cargo +0.1.0 build --target x86_64-unknown-aros-abi11 --release --locked --offline
```

### `no global memory allocator found but one is required`

**Cause.** A dependency such as `aros-mui` uses `alloc`, but the program installed no allocator.

**Fix.** Use `aros::entry!(application, alloc);` instead of `aros::entry!(application);`, and keep the `alloc` feature of `aros` enabled (it is the default).

### `can't find crate for 'std'`

**Cause.** The code, or a dependency, does not declare `#![no_std]`. 0.1.0 supports `no_std` plus `alloc`, not full `std`.

**Fix.** Declare `#![no_std]` in your crates, and choose dependencies that support `no_std`. Many crates do so behind a feature such as `default-features = false`.

### `unresolved import 'aros_mui::classes::Panel'` (or another MUI item)

**Cause.** The item is declared only for ABI-v1 and you are building for ABI-v11.

**Fix.** Build for `x86_64-unknown-aros-abi1`, or avoid the item. The [ABI differences](/reference/abi-differences/) page lists all of them.

## Problems on the AROS system

### The program returns code 20 immediately

The native start-up refuses to run when its checks fail, and it prints nothing. Check, in order:

1. **`exec.library` and `dos.library` versions.** They must be 51 and 50. `Version exec.library` and `Version dos.library` report them. A different version usually means an AROS build that this release was not qualified against.
2. **Stack size.** On ABI-v1 the stack must be exactly 128 KiB. Run `Stack 131072` in the shell before starting the program.
3. **ABI pairing.** An executable built for one ABI will not work on a system of the other. Check that the target you built for matches the AROS you run; see [targets and ABIs](/targets-and-abis/).

Return code 20 is also what `AppStatus::Fatal` and a panic produce, so if your program does start, look for those too.

### The program returns code 10 before doing anything

The arguments exceeded the start-up limit: 4096 bytes in total, including a terminating NUL for each argument. Pass less, or read the data from a file.

### No output appears

`Context::diagnostic` writes through the system's low-level debug output, which many AROS configurations do not show. Use `Stdout` or `Stderr` for output you want to see. See [Run on AROS](/run-on-aros/#diagnostics).

### A MUI program starts but the shell never returns

That is expected. A MUI application stays in its event loop until MUI reports `QUIT`. In [MUI hello](/mui-hello/) that happens when you close the window. A program that never opens a window or never arranges a `QUIT` return ID will not end by itself.

## Still stuck?

Open an issue on [GitHub](https://github.com/metaneutrons/ami-rust/issues) with the exact command, the full message, the target you built for and the AROS build you ran on.

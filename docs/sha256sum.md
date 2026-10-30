---
title: SHA-256 example
description: A small command-line AROS program that hashes a file using the safe aros crate and the sha2 crate.
---

`examples/sha256sum` is a compact command-line program built with the safe [`aros`](/api/aros/) crate. It opens a file through a context-bound handle, streams the content into SHA-256 and writes the digest through the borrowed standard-output handle. It shows file I/O, argument handling, error reporting and the use of a third-party `no_std` crate (`sha2`) in an AROS program.

## Build it

The example is in the repository, in both `main` and the `v0.1.0` tag. [Install the toolchain](/quickstart-toolchain/), clone the repository and build from its root:

```sh
git clone https://github.com/metaneutrons/ami-rust.git
cd ami-rust

toolchain=0.1.0
cargo +"$toolchain" fetch --locked --manifest-path examples/sha256sum/Cargo.toml
cargo +"$toolchain" build --manifest-path examples/sha256sum/Cargo.toml \
  --target x86_64-unknown-aros-abi11 --release --locked --offline
```

Use `--target x86_64-unknown-aros-abi1` for an ABI-v1 system. The executable is `examples/sha256sum/target/<target>/release/ami-rust-sha256sum`.

If the build stops with a message about `RUSTC_WRAPPER`, see [troubleshooting](/troubleshooting/).

## Use it

[Copy the executable to AROS and start it](/run-on-aros/) from a shell, with one or more file paths as arguments. With no argument it prints `usage: sha256sum FILE...` to standard error and returns code 10.

```text
ami-rust-sha256sum Work:report.txt
```

For each file it prints the digest as 64 lowercase hexadecimal digits, two spaces and the path, in the format of the Unix `sha256sum` command. Paths are limited to 127 bytes, and the whole argument list to 4096 bytes. A file that cannot be read produces an error message on standard error; the program carries on with the remaining files and returns code 10 at the end.

## Where to look in the source

| Topic | Look at |
| --- | --- |
| `BytePath` for non-UTF-8 paths and `File::open` | the per-argument loop in `main.rs` |
| Reading in bounded chunks | the 4 KiB read buffer and `File::read` loop |
| Reporting errors without allocating | `record_error` and `Context::diagnostic` |
| Third-party `no_std` code | the `sha2` dependency in `Cargo.toml` |

The example is a starting point for `no_std` file I/O, not a replacement for a complete Unix-compatible command-line environment.

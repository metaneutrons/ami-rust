---
title: SHA-256 example
description: A small command-line AROS application using the public no_std API.
---

# SHA-256 example

`examples/sha256sum` is a compact command-line application built with the safe
`aros` API. It opens a file through a context-bound handle, streams its content
into SHA-256, and writes the digest through the borrowed standard output handle.

Build it for either qualified AROS ABI with ordinary Cargo:

```sh
cargo +0.1.0 build --manifest-path examples/sha256sum/Cargo.toml \
  --target x86_64-unknown-aros-abi1 --release --locked --offline
```

Repeat the command with `x86_64-unknown-aros-abi11` for ABI-v11. The example is
part of the source tree and is intended as a starting point for no_std file I/O,
not as a replacement for a complete Unix-compatible command-line environment.

---
title: Rust API reference
---

# Rust API reference

The generated API reference covers the public, safe-facing crates shipped to
application authors:

- [`aros`](https://ami-rust.metaneutrons.cc/rustdoc/aros/): application entry,
  task-affine runtime, allocator, DOS/Exec wrappers, and diagnostics.
- [`aros-mui`](https://ami-rust.metaneutrons.cc/rustdoc/aros_mui/): typed MUI
  object construction, ownership scopes, attributes, methods, notifications,
  hooks, requesters, and custom classes.

These pages are built from the source comments with the pinned Rust toolchain
on every documentation deployment. They describe the 0.1 public API; they do
not make it a semver-stability promise.

`aros-sys` and `aros-mui-sys` are deliberately absent. They are raw ABI
boundaries for reviewed unsafe code, not the ordinary application interface.
Their source remains available in the repository for maintainers and expert
users who need to audit an FFI contract.

For target selection, supported ABI profiles, and a complete Cargo consumer
configuration, start with the [consumer guide](https://ami-rust.metaneutrons.cc/consumer-guide/).
The [API and lifetime inventory](https://ami-rust.metaneutrons.cc/api/) records
the qualification boundaries that the generated reference intentionally does
not repeat.

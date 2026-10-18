# Internal Cargo linker probe

RC0 experiment only. This is not a public SDK linker, installer or CLI.
See [the design result](../../docs/rust-cli-migration/cargo-design-probe.md)
and [partial evidence](../../docs/rust-cli-migration/rc0-results.json).

The crate has an independent lockfile/workspace and no third-party dependencies.
Use the selected host Rust 1.98.1 for its fixture tests:

```sh
cargo +1.98.1 test --locked --offline --manifest-path tools/cargo-native-spike/Cargo.toml
```

The linker is invoked by the experiment's pinned target Cargo/rustc, not by an
end user. It receives the selected collector, C SDK, toolchain and receipt-bound
native objects through the `AMI_SPIKE_*` environment variables. These inputs
are bound by the external experiment receipt; this adapter does not authenticate
them. Its limited ELF checks do not replace the full SDK audit.

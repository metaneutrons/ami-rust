# Internal Rust tooling

This workspace contains the Rust libraries and maintainer tasks used to produce,
inspect, qualify, sign, and publish the SDK. It is not a public `ami-rust` CLI or
Cargo plugin.

Build it through the repository bootstrap:

```sh
bash tools/build-maintainer-task.sh FRESH_ABSOLUTE_WORK HOST_TRIPLE
```

The bootstrap verifies the pinned host toolchain, lockfiles, and offline vendor
archive before compiling `ami-rust-xtask`. Direct invocation of a host Cargo may
be useful during development but does not reproduce the qualified producer.

Public users select a versioned toolchain with rustup and build applications
with ordinary Cargo. Internal tasks must not become a second SDK manager.

# Internal Rust host libraries and maintainer tasks

This workspace contains reusable validation, archive, process/resource, publisher
and ELF libraries plus internal `xtask` tasks. It contains no public `ami-rust`
CLI or `cargo-ami` plugin. Their source entrypoints and build script were removed
following the owner decision on 2026-10-21. Historical contracts and acceptance
evidence remain references; they do not define the next public interface.

The [toolchain/crate migration plan](../docs/rust-cli-cargo-migration-plan.md) owns
requirements; [RC2 #72](https://github.com/metaneutrons/ami-rust/issues/72) owns
execution status. Standard rustup and Cargo are the public workflow. AROS/Amiga
libraries and focused host tools are delivered as crates. New toolchain/crate
production and publication remain unaccepted until their complete gates pass.

## Library checks

The workspace host compiler and dependencies remain pinned. From this directory:

```sh
cargo fetch --locked
cargo test --workspace --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
```

These are maintainer/library checks, not an accepted consumer build or SDK
release. No check may reconstruct or execute the retired public CLI. Old
CLI-package production paths are retired; the next payload must use the
versioned toolchain and crate architecture rather than a Python fallback.

Preserve shared parsing/ownership/cryptographic-verifier and ELF/resource logic
where reused. Historical package schema readers may inspect earlier receipts;
their presence is not permission to create or ship a new CLI package.

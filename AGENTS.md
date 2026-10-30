# Repository working agreement

ami-rust provides a standard Rust cross-toolchain and Cargo libraries for AROS.
Keep the public workflow close to upstream Rust:

- users select the toolchain with rustup and build with Cargo;
- do not add an `ami-rust` CLI, a Cargo wrapper, or a Python runtime path;
- keep the initial targets at AROS x86-64 ABI-v1 and ABI-v11;
- treat additional targets and native AROS-hosted Rust as separate work;
- do not modify AROS-NX or aros-tools from this repository;
- preserve pinned third-party inputs, notices, source archives, and narrow
  portability patches byte for byte unless the change explicitly requalifies
  them.

Build maintainer tooling through `tools/build-maintainer-task.sh`; it authenticates
the pinned Rust bootstrap and builds offline from the checked-in vendor archive.
Use normal Cargo only after that bootstrap has been established.

The first public version is 0.1.0. Do not create a tag, GitHub Release, rustup
catalog, or other publication without Fabian's explicit release command.

All repository text, commits, pull requests, issues, and release notes are
English. Use Conventional Commits. Never add AI attribution trailers.

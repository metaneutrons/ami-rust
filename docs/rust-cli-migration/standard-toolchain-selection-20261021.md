# Standard toolchain selection — development evidence, 2026-10-21

Plan revision 3 uses the ami-rust product name, versioned rustup toolchain
registrations (for example `aros-0.2.0`) and the separate `x86_64-aros`
target. The earlier `ami-aros` name in the isolated probe is an internal fixture
name. The repository/product remains ami-rust; the toolchain uses an AROS name,
with the target architecture selected separately. Future AArch64 support needs
its own target and qualification and is outside this RC2 candidate. These probes
do not accept RC2.

## Actual selection

The [measured result](evidence/rc2-standard-toolchain-selection-development-20261021.json)
records 21 supervised commands and 42 retained raw streams. An isolated rustup
home registers a complete copied Rust prefix with the paired Cargo overlaid at
`bin/cargo`. A project selects it through `rust-toolchain.toml`; ordinary Cargo
metadata, check and build work on a small host fixture. Relinking after moving
the prefix to another path containing spaces works. Removing the registration
preserves the external prefix and makes that project fail until registration
is restored. The source components and READY remain unchanged.

Actual selected rustc is nightly `330d317121e16b5db8e5adc63595910528ff2ee7`,
Rust 1.100.0-nightly / LLVM 23.1.1, the unchanged qualified target compiler.
The earlier read-only inventory borrowed a version from the native-tooling
bootstrap record: stable 1.98.1 is the separate compiler for host tooling, not
this selected target compiler. The measured `rustc -vV` corrects that inference;
no target compiler changed. Paired Cargo is 1.99.0 from the pinned source.

The isolated missing-Cargo case fails, but it contains no other installed Rust
release channel. It does not establish that rustup disables its documented Cargo
fallback. Swapping in the upstream bundled Cargo succeeds and changes the binary
identity: rustup selects files, it does not authenticate them. Production input
validation and missing/wrong-tool refusal still require their own crate/toolchain
implementation and qualification.

The probe compares the actual user's rustup settings and both Cargo configuration
file names before/after, while HOME, RUSTUP_HOME and CARGO_HOME point into the
isolated work area. This is a scoped preservation measurement, not an audit of
all user files or credentials. Conservative child-plus-driver peak RSS is
188,022,784 bytes; elapsed time is 15.79 seconds and managed workspace 744,064,848
bytes, within the existing budgets.

## Linker lookup

A separate three-command native probe records PATH from `rustup run` and a real
Cargo build script. Neither includes the selected toolchain's `bin` directory
automatically on this macOS host. A future `aros-link` tool therefore needs an
explicit selected-prefix PATH or an absolute machine-local Cargo target linker
setting. Portable committed configuration must not embed a developer's path or
claim that rustup supplies this lookup implicitly.

## Shared ELF crate

The original ELF auditor and section compaction live in `tooling/crates/aros-elf`;
the internal core delegates to that one implementation. This is a pure library,
with explicit dependencies, its own licence copies and no executable or SDK
manager. The original malformed-input tests move with the implementation.

Local tests, macOS/Linux-configuration Clippy and actual `cargo package`
verification pass. Linux configuration is not Linux runtime. Package namespace
ownership and publication remain open. The next native integration needs the
build dependency and focused linker tool, a complete installed prefix, actual
AROS final builds, both supported hosts and all inherited RC2 acceptance gates.

The [actual package consumer](evidence/rc2-aros-elf-extraction-development-20261021.json)
builds outside the source workspace from the generated Cargo archive. For a
retained real native ELF, complete compaction and audit reports agree with the
prior proof and all 342,136 final bytes are identical. An isolated wrong-ABI copy
is refused. This checks library extraction; it does not claim a newly compiled
AROS application or runtime qualification.

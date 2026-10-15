# Maintenance and security ownership

Fabian Schmieder owns ami-rust SDK maintenance, dependency/security intake and
the qualification decision for compiler, Cargo, LLVM, collector and AROS SDK
upgrades. No duration of support or response-time commitment has been made.
Until a repository and its private security channel are designated, report
findings directly to the maintainer through the established project contact;
there is no published security mailbox or public issue tracker to assume.

The supported target remains the measured PC x86-64 ABI-v1 QEMU profile in the
immutable M0/R3 inputs. Host support is the exact macOS Apple Silicon and Linux
x86-64 interpreter/tool/prerequisite profiles, not arbitrary latest versions.
Physical hardware, other AROS ABIs/CPUs, `std`, native Rust compiler execution
under AROS, and arbitrary third-party crates remain unqualified.

Keep Cargo and rustup as the Rust tooling. The distribution adapter has no
resolver, background updater, privileged service or change to global rustup
defaults. A missing prerequisite fails explicitly; builds do not provision it.
The qualified custom Cargo is an explicit frontend and may not fall back to
another Cargo from an ambient rustup toolchain.

Before changing a pin, retain the old profile and evidence, resolve provenance
and license differences, repeat affected positive/error/memory/reproducibility
tests, and obtain independent acceptance. A new version number or a passing
compiler invocation alone does not extend the support matrix.

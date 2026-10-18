# Maintenance and security ownership

Fabian Schmieder owns ami-rust SDK maintenance, dependency/security intake and
the qualification decision for compiler, Cargo, LLVM, collector and AROS SDK
upgrades. No duration of support or response-time commitment has been made.
The public source repository is https://github.com/metaneutrons/ami-rust.
Use its issue tracker for ordinary defects and GitHub private vulnerability
reporting under Security for confidential reports. No separate public security
mailbox or guaranteed response time is implied. Public source availability
does not authorise SDK release assets.

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

The [Rust CLI and Cargo migration](rust-cli-cargo-migration-plan.md)
defines a Python-free consumer release and then complete retirement of Python
from the active build, test, qualification and release paths. Python in internal
tooling is transitional, not the medium-term destination. Execution is authorised
and tracked in [epic #69](https://github.com/metaneutrons/ami-rust/issues/69);
the accepted 0.1.0 prerequisites remain unchanged.

Before changing a pin, retain the old profile and evidence, resolve provenance
and license differences, repeat affected positive/error/memory/reproducibility
tests, and obtain independent acceptance. A new version number or a passing
compiler invocation alone does not extend the support matrix.

---
title: Maintenance and security ownership
---

# Maintenance and security ownership

Fabian Schmieder owns ami-rust SDK maintenance, dependency/security intake and
the qualification decision for compiler, Cargo, LLVM, collector and AROS SDK
upgrades. No duration of support or response-time commitment has been made.
The public source repository is https://github.com/metaneutrons/ami-rust.
Use its issue tracker for ordinary defects and GitHub private vulnerability
reporting under Security for confidential reports. No separate public security
mailbox or guaranteed response time is implied. Public source availability
does not authorise SDK release assets.

The supported targets remain the measured PC x86-64 ABI-v1 and ABI-v11 QEMU
profiles in the pinned baseline inputs. Cross-development hosts are macOS 26
Apple Silicon, Ubuntu 24.04 x86-64 and Ubuntu 24.04 ARM64 with their pinned Rust
and native tool prerequisites, not arbitrary latest versions. Physical
hardware, other AROS ABIs/CPUs, `std`, native Rust compiler execution under
AROS, and arbitrary third-party crates remain unqualified.

Keep Cargo and rustup as the Rust tooling. The distribution adapter has no
resolver, background updater, privileged service or change to global rustup
defaults. A missing prerequisite fails explicitly; builds do not provision it.
The paired Cargo is part of each versioned SDK and may not fall back to another
Cargo from an ambient rustup toolchain.

Before changing a pin, retain the old profile and evidence, resolve provenance
and license differences, repeat affected positive/error/memory/reproducibility
tests, and obtain independent acceptance. A new version number or a passing
compiler invocation alone does not extend the support matrix.

The exact 0.1.0 candidate is identified and accepted in the
[M7 qualification record](m7-qualification.md). Its source, catalog, runtime,
licence and signature identities are the baseline for any 0.1.x maintenance
change. A replacement archive under the same version is not permitted.

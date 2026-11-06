# aros-elf

Shared host library for x86-64 AROS ABI-v1 native ELF validation and the fixed
section-name compaction used by ami-rust. It does not run a compiler or linker,
install a toolchain, or provide a general SDK command-line interface.

The original implementation and malformed-input tests are extracted from the
shared ami-rust host core. The internal core delegates to this same crate. Native
link integration must audit the completed output before reporting build success.

The source package version is 0.2.0. It is delivered through pinned Cargo Git
dependencies from this repository and through the ami-rust Cargo registry at
`crates.metaneutrons.cc`; it is not on crates.io. A crates.io entry needs an
explicit owner decision and fresh package/registry qualification.
This source is not yet release-qualified; unit/package checks do not qualify a
complete toolchain or an AROS application.

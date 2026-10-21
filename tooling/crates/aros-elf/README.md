# aros-elf

Shared host library for x86-64 AROS ABI-v1 native ELF validation and the fixed
section-name compaction used by ami-rust. It does not run a compiler or linker,
install a toolchain, or provide a general SDK command-line interface.

The original implementation and malformed-input tests are extracted from the
shared ami-rust host core. The internal core delegates to this same crate. Native
link integration must audit the completed output before reporting build success.

This development crate is not published. Registry name ownership, final package
version and release qualification remain required before publication. Passing its
unit/package checks does not qualify a complete toolchain or an AROS application.

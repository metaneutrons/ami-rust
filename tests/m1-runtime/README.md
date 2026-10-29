# M1 dual-ABI runtime application

This private static library supplies the identical Rust application body used
to qualify the canonical x86-64 ABI1 and ABI11 targets. It covers allocator,
DOS file I/O, library open/close, a minimal MUI window-object lifecycle, and
clean application exit. The native bridge and final AROS ELF are supplied by
the pinned target-specific SDK during M1 qualification.

This package is release-internal evidence, not a public crate or test harness.

# Runtime application

This private application is the identical Rust body that runs on both ABIs. It covers
allocator, DOS file I/O, library open and close, a minimal MUI window-object
lifecycle, and clean application exit.

This package is release-internal evidence, not a public crate or test harness.
Build and run it with `node tools/native-matrix.mjs`, which does so for both ABIs with an installed toolchain and records the result in the release evidence (`docs/evidence/native-<version>.json`). It is listed in `tests/programs.json`.

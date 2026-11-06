# Native reference application

This private application is the maintained native reference application. It
exercises DOS file I/O, owned-handle and MUI-scope cleanup on deliberate error
returns, typed notifications, one scope-retained callback, the safe Application
event loop, a menu hierarchy, and the regular custom-class lifecycle through
`aros-mui`.

The application contains no raw MUI call, tag list, native pointer, or unsafe
block.

Build and run it with `node tools/native-matrix.mjs`, which does so for both ABIs with an installed toolchain and records the result in the release evidence (`docs/evidence/native-<version>.json`). It is listed in `tests/programs.json`.

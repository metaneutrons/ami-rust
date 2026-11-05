# Generated MUI gallery

This private application builds a representative MUI hierarchy entirely
through generated safe aros-mui bindings. It covers windows, vertical layouts,
text, a button, a string gadget, a list backed by a retained string array, a
register with two pages, and a menu hierarchy.

The application source contains no class-specific binding implementation,
native pointer, raw tag list, raw vector call, or unsafe block. The first
qualification of it is recorded in `docs/m5-qualification.md`.

Build and run it with `node tools/native-matrix.mjs`, which does so for both ABIs with an installed toolchain and records the result in the release evidence (`docs/evidence/native-<version>.json`). It is listed in `tests/programs.json`.

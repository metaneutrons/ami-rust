# Safe MUI object model

This private application builds an `Application -> Window -> Group -> Text`
tree entirely through the safe typed `aros-mui` API. It covers typed strings,
booleans, numbers, enums, object references, a typed method, ownership transfer,
and rejection plus cleanup of a second Window root. The application source uses
no raw tag list, raw vector call, native pointer, or `unsafe` block.

Build and run it with `node tools/native-matrix.mjs`, which does so for both ABIs with an installed toolchain and records the result in the release evidence (`docs/evidence/native-<version>.json`). It is listed in `tests/programs.json`.


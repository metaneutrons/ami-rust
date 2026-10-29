# M4 safe MUI dual-ABI qualification

This private application builds an `Application -> Window -> Group -> Text`
tree entirely through the safe typed `aros-mui` API. It covers typed strings,
booleans, numbers, enums, object references, a typed method, ownership transfer,
and rejection plus cleanup of a second Window root. The application source uses
no raw tag list, raw vector call, native pointer, or `unsafe` block.

The executable is linked from the pinned ABI-specific native objects and run on
the qualified ABI1 and ABI11 images. Exact inputs, commands, artifact identities,
and results are recorded in `docs/m4-qualification.md` after qualification.


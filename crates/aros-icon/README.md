# aros-icon

Icons for the selected AROS ABI profile, on top of `icon.library`.
`Icons::open` owns the library reference. A `DiskObject` is the icon of a file
or drawer (`DiskObject::open` reads `<name>.info`, `default_for` and `new` make
one of a given type), with its type, default tool, tool types and stack size;
`put` writes it back. Tool types are read as plain `&[u8]` entries or looked up
with `find_tool_type`, and `Icons::match_tool_value` matches a value against a
`A|B|C` list.

The crate is `no_std`, allocates nothing on the Rust heap and is the same on
ABI-v1 and ABI-v11. Replaced default tools and tool types are owned by the
native bridge and put back before the library frees the object; a forgotten
disk object is freed when the program ends.

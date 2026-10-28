# AROS-derived MUI interface modifications

Original Code: the AROS Development Team's native ABI declarations in
`compiler/include/exec/libraries.h`, `utility/tagitem.h`,
`clib/muimaster_protos.h`, `inline/muimaster.h` and `aros/x86_64/cpu.h` at the
pinned AROS-NX commit `e0d5e367d15cc7da4ebac8f9db17868756c79569`.
Their complete original source and notices are provided in the accompanying
AROS source archive under the AROS Public License 1.1.

2026-10-29: Fabian Schmieder's ami-rust implementation translated the selected
64-bit `TagItem` layout, MUI constants and muimaster library-vector signatures
into Rust declarations. It added explicit unsafe contracts and limited the
initial vector surface to object creation, object disposal and MUI error state.

Covered Code and its modifications remain subject to AROS Public License 1.1;
original ami-rust additions also have the owner-selected MIT OR Apache-2.0
grant where that does not relicense or restrict AROS Covered Code.

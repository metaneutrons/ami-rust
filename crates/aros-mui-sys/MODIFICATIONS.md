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

2026-10-29: The implementation split x86-64 calls into explicit ABI-v1 and
ABI-v11 backends. The ABI-v11 call sequence follows the unmodified
`Development/include/aros/x86_64/libcall.h` delivered by Deadwood's AROS
ABIv11 2026.09 SDK at release commit
`fbc242c1046cffb5e5827a4626ee62bdd45664e9`, which places the library base in
`r12`. No ABI-v11 runtime qualification is claimed by this source translation.

Covered Code and its modifications remain subject to AROS Public License 1.1;
original ami-rust additions also have the owner-selected MIT OR Apache-2.0
grant where that does not relicense or restrict AROS Covered Code.

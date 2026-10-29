# aros-mui-sys

Raw, unsafe MUI calls for the selected AROS ABI profile. The generated surface
contains every public class ID, attribute, method, value, enum value and
`MUIP_*` message representation in the pinned public headers, together with
the complete reviewed non-variadic muimaster vector set. Calls dispatch through
the library vector table defined by the pinned AROS SDK. The x86-64 backend
supports the ABI1 base-last call contract and the ABI11 `r12` library-base
contract.

Applications normally use `aros-mui`. Direct use of this crate requires the
caller to keep the library base and every pointer valid for the complete call.
MUI message fields use `Stacked<T>` to preserve the native x86-64 field
alignment. Both backends and the generated layout surface have completed the
M3 native dual-ABI qualification recorded in
[`docs/m3-qualification.md`](../../docs/m3-qualification.md).

The package-level license reference and `MODIFICATIONS.md` preserve the AROS
Public License 1.1 scope and source history. Original ami-rust contributions
retain their separate MIT OR Apache-2.0 grant where applicable.

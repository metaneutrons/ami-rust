# aros-mui-sys

Raw, unsafe MUI calls for the selected AROS ABI profile. The initial surface
contains the non-variadic object lifecycle and error calls needed by
`aros-mui`. Calls dispatch through the library vector table defined by the
pinned AROS SDK.

Applications normally use `aros-mui`. Direct use of this crate requires the
caller to keep the library base and every pointer valid for the complete call.

The package-level license reference and `MODIFICATIONS.md` preserve the AROS
Public License 1.1 scope and source history. Original ami-rust contributions
retain their separate MIT OR Apache-2.0 grant where applicable.

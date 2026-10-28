# aros-mui

Task-affine MUI access for the selected AROS ABI profile. `Mui::open` owns an
explicit `muimaster.library` reference. Objects borrow that owner and are
disposed before the library can close.

The initial surface safely covers library ownership and object disposal.
Generic object creation remains `unsafe` because class-specific tag values can
contain native pointers. Typed safe builders will be added per MUI class. Use
`aros-mui-sys` for MUI calls that do not yet have a higher-level wrapper.

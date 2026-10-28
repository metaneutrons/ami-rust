# aros

The primary `no_std` application API for the selected AROS ABI profile. It
provides the application entry point, task-affine context, optional Exec-backed
allocator, and safe wrappers for the qualified core SDK surface.

The default `alloc` feature installs allocator support when an application uses
`aros::entry!(application, alloc)`. Disable default features for an entirely
allocation-free application.

Use `aros-sys` only when an API is not yet covered by this safe crate. Optional
AROS libraries use separate pairs such as `aros-mui` and `aros-mui-sys`.

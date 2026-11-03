---
title: The aros-mui-sys crate
description: Raw MUI constants, method messages and muimaster calls for both ABI profiles. The layer under aros-mui.
---

`aros-mui-sys` is the raw MUI layer that [`aros-mui`](/api/aros-mui/) stands on. It declares what the public MUI headers declare and nothing more: the class IDs, attributes, methods and values as constants, the `MUIP_*` method messages as structures, and the calls of `muimaster.library`. It is `no_std` and depends on [`aros-sys`](/api/aros-sys/).

Most programs should use `aros-mui`, which owns every object it creates and keeps the library base and every pointer valid for the whole call. Use `aros-mui-sys` when you need a MUI call or message that `aros-mui` does not cover. Every call is `unsafe`.

## What it contains

| Part | What it is |
| --- | --- |
| Identifiers | One `pub const` for every class ID, attribute, method, value and enum value of the pinned public headers: 1014 on ABI-v1 and 963 on ABI-v11. The documentation of each names the header and the line it comes from. |
| Method messages | One `#[repr(C)]` structure for every `MUIP_*` message: 184 on ABI-v1 and 179 on ABI-v11. The documentation of each field quotes its C declaration and its position in the header. |
| muimaster calls | The 25 non-variadic calls of `muimaster.library`, as `mui_*` functions that dispatch through the vector table. |
| Custom classes | `MuiCustomClass`, the public layout of `struct MUI_CustomClass`, with its layout values. |
| `Stacked<T>` | The wrapper that gives each message field the 8-byte alignment of the x86-64 AROS `STACKED` fields, including 32-bit integers. |

The tag constants and `TagItem` are re-exported from `aros-sys`. The minimum `muimaster.library` version that the crate relies on is 19 (`MUI_API_VERSION`).

The generated parts come from the pinned SDK headers through `cargo xtask generate mui`, and `cargo xtask check mui` fails when a committed file differs from what the headers produce, so the constants and messages cannot drift from the headers. Build the reference locally with the installed toolchain:

```text
RUSTDOCFLAGS="-Zunstable-options" cargo +"$toolchain" doc -p aros-mui-sys \
  --no-deps --target x86_64-unknown-aros-abi11 --open
```

## ABI differences

The pinned ABI-v1 headers declare four more MUI classes than the pinned ABI-v11 public `mui.h`: `Panel`, `PanelGroup`, `PanelTitle` and `DragHandle`, with their attributes, methods and values. Those items exist for ABI-v1 targets only, which is why the counts above differ. They are listed on the generated [ABI differences](/reference/abi-differences/) page. Library calls use the base-last convention on ABI-v1 and the `r12` convention on ABI-v11, selected by the Cargo target.

## Safety

The caller must keep the library base and every pointer that a call reads or writes valid for the whole call. The documentation of each call states the conditions, for example that a class ID is NUL terminated and that a tag list is terminated. Message structures are plain data: filling one in correctly, with the right method ID and the stacked fields, is the caller's job.

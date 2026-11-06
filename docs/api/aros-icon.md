---
title: "aros-icon: icons and tool types"
description: "icon.library disk objects: icons, tool types, default tools and tool value matching."
---

`aros-icon` reads and writes icons for an active `aros::Context`. `Icons::open` owns `icon.library`, `DiskObject` is the icon of a file, drawer or disk, and tool types are read as plain byte entries or looked up by name. It is `no_std`, allocates nothing on the Rust heap and is the same on ABI-v1 and ABI-v11. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_icon/). It is new in 0.2.0.

| Item | Use |
| --- | --- |
| `Icons::open(context)` | Opens `icon.library` (version 44 or newer) and owns the reference. |
| `DiskObject::open(&icons, path)` | Reads the icon `<path>.info` (give the path without `.info`). |
| `DiskObject::default_for(&icons, kind)`, `DiskObject::new(&icons, kind)` | The system's default icon of a `Kind`, or a blank one. |
| `kind()`, `default_tool()`, `tool_types()`, `find_tool_type(name)`, `stack_size()`, `position()` | Read an icon. `tool_types()` yields each entry; `find_tool_type` returns the value of `NAME=value` (empty for a bare `NAME`). |
| `set_default_tool`, `set_tool_types`, `set_stack_size` | Change an icon. |
| `put(path)`, `Icons::delete(path)` | Write the icon as `<path>.info`, or delete that file. |
| `Icons::match_tool_value(value, wanted)` | Whether `value` is one of the alternatives of a `A\|B\|C` list, ignoring case. |
| `as_raw()` | The native `struct DiskObject *`, for `aros-workbench`'s application icons. |

```rust
use aros::{Context, Error};
use aros_icon::{DiskObject, Icons, Kind};

fn project_icon(context: &Context) -> Result<(), aros_icon::Error> {
    let icons = Icons::open(context)?;
    let mut icon = DiskObject::default_for(&icons, Kind::Project)?;
    icon.set_default_tool(b"SYS:Utilities/MultiView")?;
    icon.set_tool_types(&[b"MODE=fast", b"DEBUG"])?;
    icon.put(b"RAM:notes.txt")?;

    // Read it back: the file is RAM:notes.txt.info.
    let read = DiskObject::open(&icons, b"RAM:notes.txt")?;
    if read.find_tool_type(b"MODE") == Some(&b"fast"[..]) && icons.match_tool_value(b"fast", b"slow|fast")? {
        context.diagnostic(b"fast mode", 1);
    }
    icons.delete(b"RAM:notes.txt")?;
    Ok(())
}
```

## Ownership and cleanup

A `DiskObject` borrows its `Icons`, which stays open while any disk object exists. Dropping a disk object frees it. A default tool or a set of tool types that a program sets is copied into memory the native bridge owns, and the library's own text is put back before the library frees the object, so the library never frees memory it did not allocate. The bridge records every disk object with the library base, so one the program forgets is freed when it finishes, after any application icon that uses it; the qualification fixture forgot a disk object with replaced tool types twice and the Exec free memory was the same from the first run on, on both ABIs.

## Limits

A path is at most 127 bytes. The default tool and each tool type are at most 512 bytes, an icon has at most 64 tool types, and none may contain a NUL byte; these are `Error::Invalid` before any native call. `put` writes only the icon file, not the image data of an icon the program never loaded. Drawer windows, icon drawing and layout (`DrawIconStateA`, `LayoutIconA`) are not wrapped.

## Tested on AROS

On the pinned ABI-v1 and ABI-v11 images, with identical results: the default project icon has type project and no tool types; a default tool, three tool types (`MODE=fast`, `DEBUG`, `LEVEL=3`) and a 16 KiB stack come back from the accessors in order; `find_tool_type` returns `fast`, an empty value for the bare `DEBUG` (found with a different case), `3`, and nothing for a missing name; `match_tool_value` matches `fast` and `FAST` against `slow|fast` and not `medium`; `put` writes `RAM:m9file.info` and a fresh `open` reads back the same type, tool, types and stack; `delete` removes it and a further `open` is `NotFound`; a blank tool icon has no tool types; refusals of over-long paths, NUL bytes and 65 tool types; and the ledgers return to zero. These are observations of that profile, not guarantees on another system.

## Differences in the SDK headers

The pinned ABI-v11 C SDK has no `workbench/workbench.h`. The bridge therefore declares the `DiskObject` fields it uses; on ABI-v1 the declaration is checked against the SDK header at build time, and on ABI-v11 it follows the ABI-v11 SDK's header, whose `struct DiskObject` is identical to the ABI-v1 header. The disk object type values are compared with the bridge's on each ABI (`aros_sys::wb_layout_values`).

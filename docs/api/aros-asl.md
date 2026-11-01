---
title: The aros-asl crate
description: "The asl.library file requester with a tag-based builder that returns owned paths."
---

`aros-asl` shows the `asl.library` file requester for an active `aros::Context`. `Asl::open` owns the library, `FileRequestBuilder` describes the requester and `FileRequester::request` shows it and returns the selected paths as owned values. It is `no_std`, allocates nothing on the Rust heap and is the same on ABI-v1 and ABI-v11. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_asl/). It is available from the repository after release 0.1.0 and is not part of that release.

| Item | Use |
| --- | --- |
| `Asl::open(context)` | Opens `asl.library` (version 36 or newer) and owns the reference. |
| `FileRequestBuilder` | Title, initial drawer, file and pattern, button labels, position and size, save mode, multi-selection, patterns, drawers only and reject icons. Text is copied into the builder and checked by `build`. |
| `build(&asl)` → `FileRequester` | Allocates the requester. Dropping it frees it. |
| `FileRequester::request(parent)` | Shows the requester and **blocks the task** until the user confirms or cancels. With a parent `aros-intuition` window, the requester opens on its screen and the parent sleeps. |
| `Outcome::Accepted(selection)`, `Outcome::Cancelled` | The result. A selection has `len()` and `path(index)`. |
| `AslPath` | An owned path of up to 512 bytes: `as_bytes()`, `len()`, and `as_byte_path()` for `aros` file calls (paths of up to 127 bytes). |

```rust
use aros::{Context, Error};
use aros_asl::{Asl, FileRequestBuilder, Outcome};

fn choose_file(context: &Context) -> Result<(), aros_asl::Error> {
    let asl = Asl::open(context)?;
    let mut requester = FileRequestBuilder::new()
        .title(b"Open a file")
        .initial_drawer(b"RAM:")
        .reject_icons(true)
        .build(&asl)?;
    match requester.request(None)? {
        Outcome::Accepted(selection) => {
            for index in 0..selection.len() {
                let path = selection.path(index)?;
                context.diagnostic(b"selected bytes", path.len() as u64);
            }
        }
        Outcome::Cancelled => {}
    }
    Ok(())
}
```

## Results

`request` returns `Outcome::Accepted` when the user confirmed and `Outcome::Cancelled` when the user cancelled, closed the window or pressed Escape, or when the requester could not open at all. A `Selection` borrows the requester, so it must be dropped before the requester is shown again, and its paths are copies that stay valid afterwards.

- For a single file, the path is the requester's drawer and file joined by the DOS path rules, for example `RAM:Work` and `notes.txt` give `RAM:Work/notes.txt`; with drawers only it is the drawer.
- For a multi-selection (`multi_select(true)`), the library returns a list of names and a lock on the drawer, and each path is built from the **volume name** of that lock, so the same files come back as `RAM Disk:Work/notes.txt`. The two forms name the same file; compare them by opening, not by bytes.
- A requester can be shown again. It starts where the last request ended unless the builder set an initial drawer or file, which are then applied on every request.

## Ownership and cleanup

A `FileRequester` borrows its `Asl`, which stays open while any requester exists. Dropping a requester frees it. The native bridge records every requester with the library base, so one that the program forgets is freed when the program finishes, before the libraries close; the qualification fixture forgot a requester three times in a row and the free memory reported by Exec was the same after the first run on both ABIs.

## Limits

A path is at most 512 bytes, a title 127, a drawer 255, a file name 107, a pattern 63 and a button label 31; text with a NUL byte is refused. The builder sets at most 24 tags. Multi-selection and save mode exclude each other in the library, and drawers only excludes multi-selection. Font and screen mode requesters are not wrapped.

## Native evidence

The qualification fixture shows requesters on the Workbench screen of the pinned ABI-v1 and ABI-v11 images, behind a parent window, and drives them from a second native process that injects input through `input.device` once the requester's window has appeared. With identical results on both ABIs: Escape cancels; typing `m7file.txt` and pressing Return in the file gadget returns `RAM:m7file.txt`, and showing the same requester again and pressing Return returns the same path; save mode with a pattern returns `RAM:out.txt`; cursor down in the list followed by Return returns the second file of a three-file drawer; clicking one row and shift-clicking another, then the confirm button, returns the two files (`RAM Disk:m7dir/a.txt` and `RAM Disk:m7dir/c.txt`); and drawers only with the confirm button returns `RAM:m7dir`. The ledgers return to zero. The clicks are positioned relative to the requester window from measurements of that layout, so they are specific to the two pinned images; the other cases do not depend on layout. These are observations of that profile, not guarantees on another system.

## The pinned SDK headers

The pinned ABI-v11 C SDK has no `libraries/asl.h`. The bridge therefore declares the few `FileRequester` fields it reads itself; on ABI-v1 the declaration is checked against the SDK header at build time, and on ABI-v11 it follows the ABI-v11 SDK's `libraries/asl.h`, whose requester structure and tag values are identical to the ABI-v1 header. The qualification fixture compares the tag values the Rust code uses with the bridge's values on each ABI (`aros_sys::asl_layout_values`).

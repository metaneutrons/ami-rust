---
title: The aros-workbench crate
description: "Workbench application windows, icons and menu items with message receipt and cleanup."
---

`aros-workbench` is the application side of Workbench for an active `aros::Context`: a window that accepts dropped icons, an icon on the desktop and an item in the Tools menu. `Workbench::open` owns `workbench.library`, `AppPort` is the message port Workbench sends to, and `AppWindow`, `AppIcon` and `AppMenuItem` register with it. It is `no_std`, allocates nothing on the Rust heap and is the same on ABI-v1 and ABI-v11. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_workbench/). It is available from the repository after release 0.1.0 and is not part of that release.

| Item | Use |
| --- | --- |
| `Workbench::open(context)` | Opens `workbench.library` (version 45 or newer) and owns the reference. |
| `AppPort::new(&workbench)` | The message port, owned by the bridge. `signal_mask()` is for `aros::wait_signals`, `has_pending()` peeks and `next()` reads one message. |
| `AppMessage` | A message with `kind()` (`Window`, `Icon`, `MenuItem`), `id()`, `user_data()`, `class()`, `position()`, `time()` and the dropped paths: `total_paths()`, `copied_paths()` and `path(index)`. It owns its data. |
| `AppWindow::add(&port, &window, id, user_data)` | Makes an `aros-intuition` window accept dropped icons. |
| `AppIcon::add(&port, &disk_object, text, id, user_data)` | Puts an `aros-icon` disk object on the Workbench desktop. |
| `AppMenuItem::add(&port, text, id, user_data)` | Adds an item to the Workbench Tools menu. |

```rust
use aros::{Context, Error};
use aros_intuition::{Intuition, WindowBuilder};
use aros_workbench::{AppMessageKind, AppPort, AppWindow, Workbench};

fn accept_drops(context: &Context) -> Result<(), aros_workbench::Error> {
    let intuition = Intuition::open(context)?;
    let window = WindowBuilder::new().title(b"Drop files here").open(&intuition, None)?;
    let workbench = Workbench::open(context)?;
    let port = AppPort::new(&workbench)?;
    let _drop_target = AppWindow::add(&port, &window, 1, 0)?;

    aros::wait_signals(context, port.signal_mask())?;
    while let Some(message) = port.next()? {
        if message.kind() == AppMessageKind::Window {
            for index in 0..message.copied_paths() {
                let path = message.path(index)?;
                context.diagnostic(b"dropped bytes", path.len() as u64);
            }
        }
    }
    Ok(())
}
```

## Messages

`AppPort::next` takes the message from the port, copies its paths and returns the message to Workbench at once, so the value you get owns everything and nothing is left to reply to. A path is the drawer and the name Workbench gave, joined by the DOS path rules; because Workbench gives a lock on the drawer, the volume is named by the lock, for example `RAM Disk:Work/notes.txt` for a file dropped from `RAM:Work`. A message carries at most 8 paths of 256 bytes; further ones are counted in `total_paths()` and not copied. Icon and menu messages arrive the same way with their own `kind()`; they need the user to open an icon or choose the item.

## Cleanup

A registration borrows the port and, for a window or an icon, the window or disk object, so none of them can be closed while Workbench still knows it. Dropping a registration removes it. The bridge owns the port and the texts Workbench keeps pointers to, and records every registration with the library base, so ones that the program forgets are removed when it finishes: first the registrations, then the port with any messages still queued returned, and only then the windows and disk objects. Removing a registration first replies to the messages already queued on the port, because the removal needs the Workbench lock that a waiting sender holds.

## Sending a drop to one's own window

`SendAppWindowMessage`, in `aros_sys::workbench` on both ABIs (eight arguments, so on ABI-v11 it goes through the stack-argument adapter, as does `AddAppIconA` with seven), delivers an application window message to a window's registered `AppWindow`. It is **synchronous**: it returns only after the receiver has replied to the message, and it holds the Workbench lock while it waits. Called from the task that reads the `AppPort` it waits for itself and never returns, so this crate has no safe wrapper for it; a second task has to make the call. The qualification test does that from a second native process and reads the message in the first.

## Limits

An icon or menu item text is at most 127 bytes, with no NUL byte. The crate wraps application windows, icons and menu items; the other application and Workbench calls (`WorkbenchControlA`, `OpenWorkbenchObjectA`, drop zones and so on) are not wrapped.

## Native evidence

On the pinned ABI-v1 and ABI-v11 images, with identical results: without an application window the send is refused at once; with one registered, a two-file drop sent from a second process arrives as one typed message with the id and user data given at registration, the pointer position (30, 40), the time stamp, a total of two paths and the two paths (`RAM Disk:m9dir/a.txt` and `RAM Disk:m9dir/b.txt`), and the sender then returns; a three-file drop arrives the same way; a wait on the port and a timer returns only the timer's signal when nothing is sent; an application icon and a menu item register and are removed while the window still gets its messages; a message queued when the application window is removed is replied to, which lets the blocked sender finish; and the ledgers return to zero. A forgotten window, port, icon, menu item and disk object were removed at the end of the run and the Exec free memory was the same from the first run on. Icon and menu messages were not triggered: that needs the user. These are observations of that profile, not guarantees on another system.

## The pinned SDK headers

The pinned ABI-v11 C SDK has no `workbench/workbench.h`. The bridge therefore declares the `AppMessage` and `WBArg` fields it reads; on ABI-v1 the declarations are checked against the SDK header at build time, and on ABI-v11 they follow the ABI-v11 SDK's header, whose structures are identical to the ABI-v1 header. The message type values are compared with the bridge's on each ABI (`aros_sys::wb_layout_values`).

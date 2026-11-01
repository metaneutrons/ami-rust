---
title: The aros-intuition crate
description: "Windows on a public screen with typed IDCMP events and drawing into the window's rastport."
---

`aros-intuition` opens windows through `intuition.library` for an active `aros::Context` and reads their events. `Intuition::open` owns the library, `PubScreen::lock` locks a public screen, and `WindowBuilder::open` creates a `Window`. It is `no_std`, allocates nothing on the Rust heap and is the same on ABI-v1 and ABI-v11. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_intuition/). It is available from the repository after release 0.1.0 and is not part of that release. Drawing is done with [`aros-graphics`](/api/aros-graphics/).

| Item | Use |
| --- | --- |
| `Intuition::open(context)` | Opens `intuition.library` (version 39 or newer) and owns the reference. |
| `PubScreen::lock(&intuition, name)` | Locks the default public screen (`None`) or one by name; `width()` and `height()`. Unlocks when dropped. |
| `WindowBuilder` | Title, position, inner size, size limits, gadgets, refresh mode, mouse reporting and the `Idcmp` set. A tag list on the stack; `open(&intuition, Some(&screen))`. |
| `Window::next_event()`, `wait_event()` | Typed `Event`s: `CloseWindow`, `NewSize`, `Refresh`, `MouseButton`, `MouseMove`, `RawKey`, `Key`, `Activated`, `Deactivated`, `Other`. |
| `Window::signal_mask()` | The signal set of the window's port, for `aros::wait_signals` together with timers and other sources. |
| `Window::info()` | Position, outer size, borders and inner size, pointer position and screen size. |
| `Window::rastport(&graphics)` | The window's rastport as an `aros-graphics` `RastPortRef` tied to the window. |
| `set_title`, `activate`, `to_front`, `to_back`, `move_by`, `resize_by`, `set_box` | Window control. `move_by`, `resize_by` and `set_box` take effect when Intuition processes them. |
| `begin_refresh()` → `Refresh` | Redraws the damaged part after `Event::Refresh`; dropping the guard completes the refresh. |

```rust
use aros::{Context, Error};
use aros_graphics::{Canvas, Graphics};
use aros_intuition::{Event, Intuition, WindowBuilder};

fn hello_window(context: &Context) -> Result<(), aros_intuition::Error> {
    let graphics = Graphics::open(context)?;
    let intuition = Intuition::open(context)?;
    let mut window = WindowBuilder::new()
        .title(b"Hello")
        .inner_size(200, 100)
        .open(&intuition, None)?;
    let info = window.info()?;
    {
        let mut canvas = window.rastport(&graphics);
        canvas.set_pen(1)?;
        // Window coordinates start at the outer corner, so draw inside the borders.
        let (x, y) = (info.border_left as i16 + 10, info.border_top as i16 + 10);
        canvas.fill_rect(x, y, x + 80, y + 40)?;
    }
    while window.wait_event()? != Event::CloseWindow {}
    Ok(())
}
```

## Waiting for a window and a timer together

`Window::signal_mask` is the signal set of the window's port. Combine it with the mask of an `aros-timer` alarm and wait for both in one call, then read events until none is left:

```rust
use aros::wait_signals;
use aros_intuition::{Event, Window};
use aros_timer::Timer;
use core::time::Duration;

fn wait_for_event_or_timeout(
    context: &aros::Context,
    window: &mut Window<'_, '_>,
    timer: &Timer<'_>,
) -> Result<Option<Event>, aros::Error> {
    let mut alarm = timer.start(Duration::from_secs(2))?;
    let result = loop {
        if let Ok(Some(event)) = window.next_event() {
            break Some(event);
        }
        if alarm.is_finished()? {
            break None;
        }
        wait_signals(context, window.signal_mask() | timer.signal_mask())?;
    };
    alarm.abort()?;
    Ok(result)
}
```

## Coordinates and drawing

A window rastport starts at the window's outer top left corner, so drawing inside the borders means adding `border_left` and `border_top` from `Window::info`. Pointer positions in events are relative to the same corner. Intuition clips drawing to the window. Pen numbers are the screen's palette entries and the palettes differ between the two ABIs, so compare pixels with each other, as the qualification test does, not with fixed colours. After a resize the window gets `Event::NewSize` and, for a simple-refresh window, `Event::Refresh`; call `begin_refresh`, redraw and drop the guard.

## Ownership and cleanup

A `Window` borrows its `Intuition` and a `PubScreen` borrows it too, so the library stays open while either exists; a `compile_fail` example in the crate checks that a window cannot outlive the library. The window title is kept by the native bridge, not in the value, so a `Window` can be moved. A `RastPortRef` from `Window::rastport` carries the lifetime of the window and of the `Graphics` it was made with. Dropping a window closes it and Intuition returns the messages that are still queued. A window or a screen lock that the program forgets is closed or unlocked when the program finishes, before the libraries are closed.

## Limits

A title is at most 127 bytes and a public screen name at most 63 bytes; neither may contain a NUL byte. The builder sets at most 24 tags. Coordinates are 16-bit. The window is a plain Intuition window: gadgets, menus and `BOOPSI` images are not wrapped.

## Native evidence

The qualification fixture opens a window on the Workbench screen of the pinned ABI-v1 and ABI-v11 images and drives it with input it injects through `input.device`: an absolute pointer move, a click, a key, a resize and a click on the close gadget. Every event comes back as the typed value, with the pointer position in window coordinates matching the injected one exactly on both ABIs; a pixel drawn at the click position reads back as the pen drawn at a known spot; a wait on the window and a timer returns only the timer's signal when there is no input; events left unread when the window is dropped are discarded; and the ledgers return to zero. These are observations of that profile, not guarantees on another system. Differences between the profiles that a program can see: the window borders are 4 by 15 pixels (left, top) on ABI-v1 and 10 by 25 on ABI-v11, and the Workbench screen is 800 by 600 and 1024 by 768.

## Using it with aros-mui

The two crates are independent: both can be open in one program, because each opens its own libraries and neither shares objects with the other. Their event loops are not combined. `aros_mui::Object<Application>::run` blocks the task in its own wait on the signal mask MUI reports, so the port of an `aros-intuition` window is not read while that loop runs, and events queue until it ends; `Window::signal_mask` cannot be added to MUI's wait. Use MUI for a program built from widgets, and `aros-intuition` for a program that draws its own canvas, rather than mixing both loops in one task. A MUI window's own rastport is not reachable through `aros-intuition`. This coexistence was not run natively: a MUI requester or loop waits for user input.

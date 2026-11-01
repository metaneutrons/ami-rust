//! Window cases: public screens, windows, typed events from injected input,
//! drawing into a window rastport, waiting together with a timer, and cleanup.
//!
//! Input is injected through `input.device` by the test-only bridge controls:
//! an absolute `RAWMOUSE` event with the `NOBUTTON` code moves the pointer,
//! button events carry a zero relative move, and raw key events go to the
//! active window. The events come back through the window's IDCMP port.

use core::{mem, time::Duration};

use aros::Context;
use aros_graphics::{Canvas, Graphics};
use aros_intuition::{
    Error, Event, Idcmp, Intuition, MouseButton, PubScreen, Window, WindowBuilder,
};
use aros_sys as sys;
use aros_timer::Timer;

use super::same_resources;

unsafe extern "C" {
    fn sdk_test_input_open() -> i32;
    fn sdk_test_input_send(class: u32, code: u32, qualifier: u32, x: i32, y: i32) -> i32;
    fn sdk_test_input_close();
}

const CLASS_RAWKEY: u32 = 1;
const CLASS_RAWMOUSE: u32 = 2;
const RELATIVE_MOUSE: u32 = 1 << 15;
const LEFT_BUTTON: u32 = 0x68;
const UP: u32 = 0x80;
const NO_BUTTON: u32 = 0xff;
const KEY_A: u32 = 0x20;

fn pointer_to(x: i32, y: i32) -> bool {
    // SAFETY: test-only control of the native bridge.
    unsafe { sdk_test_input_send(CLASS_RAWMOUSE, NO_BUTTON, 0, x, y) == 0 }
}

fn button(code: u32) -> bool {
    // SAFETY: test-only control of the native bridge.
    unsafe { sdk_test_input_send(CLASS_RAWMOUSE, code, RELATIVE_MOUSE, 0, 0) == 0 }
}

fn key(code: u32) -> bool {
    // SAFETY: test-only control of the native bridge.
    unsafe { sdk_test_input_send(CLASS_RAWKEY, code, 0, 0, 0) == 0 }
}

fn layout_matches(context: &Context) -> bool {
    let expected = sys::intuition_layout_values();
    let mut actual = [0u64; sys::INTUITION_LAYOUT_VALUE_COUNT];
    // SAFETY: exact writable capacity; C writes only scalar oracle values.
    let count = unsafe { sys::sdk_intui_layout(actual.as_mut_ptr(), actual.len()) };
    if count != actual.len() || actual != expected {
        context.diagnostic(b"qualification-window-layout-count", count as u64);
        for (index, (a, e)) in actual.iter().zip(expected).enumerate() {
            if *a != e {
                context.diagnostic(b"qualification-window-layout-index", index as u64);
            }
        }
        return false;
    }
    true
}

/// Waits up to `milliseconds` for an event `wanted` accepts, skipping others.
/// The wait covers the window's port and the timer in one `wait_signals`.
fn await_event(
    context: &Context,
    window: &mut Window<'_, '_>,
    timer: &Timer<'_>,
    milliseconds: u64,
    wanted: impl Fn(Event) -> bool,
) -> Option<Event> {
    let mut alarm = timer.start(Duration::from_millis(milliseconds)).ok()?;
    let mut found = None;
    'wait: loop {
        while let Ok(Some(event)) = window.next_event() {
            if wanted(event) {
                found = Some(event);
                break 'wait;
            }
        }
        if alarm.is_finished().unwrap_or(true) {
            break;
        }
        let _ = aros::wait_signals(context, window.signal_mask() | timer.signal_mask());
    }
    let _ = alarm.abort();
    found
}

fn step(context: &Context, number: u64) -> bool {
    context.diagnostic(b"qualification-window-step", number);
    false
}

pub fn cases(context: &Context) -> bool {
    let baseline = context.statistics();
    if !layout_matches(context) {
        return step(context, 1);
    }
    let Ok(graphics) = Graphics::open(context) else {
        return step(context, 2);
    };
    let Ok(intuition) = Intuition::open(context) else {
        return step(context, 3);
    };
    let Ok(timer) = Timer::open(context) else {
        return step(context, 4);
    };

    // Argument checks before any native call, and screen locks.
    let long_title = [b'x'; 128];
    if WindowBuilder::new()
        .title(&long_title)
        .open(&intuition, None)
        .err()
        != Some(Error::Invalid)
        || WindowBuilder::new()
            .title(b"a\0b")
            .open(&intuition, None)
            .err()
            != Some(Error::Invalid)
        || PubScreen::lock(&intuition, Some(&[b'n'; 64])).err() != Some(Error::Invalid)
        || PubScreen::lock(&intuition, Some(b"No.Such.Screen")).err() != Some(Error::NoSuchScreen)
    {
        return step(context, 5);
    }
    let Ok(screen) = PubScreen::lock(&intuition, None) else {
        return step(context, 6);
    };
    {
        let Ok(named) = PubScreen::lock(&intuition, Some(b"Workbench")) else {
            return step(context, 7);
        };
        if named.width() != screen.width()
            || named.height() != screen.height()
            || screen.width() == 0
        {
            return step(context, 8);
        }
    }
    let after_refusals = context.statistics();
    if after_refusals.windows != baseline.windows
        || after_refusals.pubscreens != baseline.pubscreens + 1
    {
        return step(context, 9);
    }

    let mut window = match WindowBuilder::new()
        .title(b"ami-rust M6")
        .position(60, 60)
        .inner_size(240, 160)
        .report_mouse(true)
        .limits(100, 80, 600, 500)
        .idcmp(Idcmp::DEFAULT | Idcmp::ACTIVE)
        .open(&intuition, Some(&screen))
    {
        Ok(window) => window,
        Err(_) => return step(context, 10),
    };
    let Ok(info) = window.info() else {
        return step(context, 11);
    };
    if info.left != 60
        || info.top != 60
        || info.inner_width != 240
        || info.inner_height != 160
        || info.width != 240 + info.border_left + info.border_right
        || info.height != 160 + info.border_top + info.border_bottom
        || info.screen_width != screen.width()
        || window.signal_mask() == 0
    {
        return step(context, 12);
    }
    let (bl, bt) = (
        i16::try_from(info.border_left).unwrap(),
        i16::try_from(info.border_top).unwrap(),
    );

    // Drawing: the window rastport takes aros-graphics calls, and the result
    // reads back. Pen numbers map to colours, so pixels are compared with
    // each other, not with a fixed value.
    {
        let mut canvas = window.rastport(&graphics);
        let _ = canvas.set_pen(1);
        let _ = canvas.fill_rect(bl + 20, bt + 20, bl + 60, bt + 40);
        let _ = canvas.set_pen(2);
        let _ = canvas.line(bl + 100, bt + 20, bl + 140, bt + 20);
        let _ = canvas.set_pen(3);
        let _ = canvas.fill_rect(bl + 200, bt + 120, bl + 202, bt + 122);
        let read = |x: i16, y: i16| canvas.read_pixel(x, y).ok().flatten();
        let (pen1, pen2, pen3) = (
            read(bl + 40, bt + 30),
            read(bl + 120, bt + 20),
            read(bl + 201, bt + 121),
        );
        let background = read(bl + 5, bt + 150);
        if pen1.is_none()
            || pen1 == pen2
            || pen1 == pen3
            || pen2 == pen3
            || background == pen1
            || background == pen2
            || background == pen3
            || read(bl + 20, bt + 20) != pen1
            || read(bl + 60, bt + 40) != pen1
            || read(bl + 61, bt + 41) == pen1
        {
            return step(context, 13);
        }
    }

    // SAFETY: test-only controls of the native bridge.
    if unsafe { sdk_test_input_open() } != 0 {
        return step(context, 14);
    }
    let _ = await_event(context, &mut window, &timer, 200, |_| false);

    // Pointer movement: the absolute position comes back in window coordinates.
    let (px, py) = (60 + i32::from(bl) + 100, 60 + i32::from(bt) + 60);
    if !pointer_to(px, py) {
        return step(context, 15);
    }
    let moved = await_event(
        context,
        &mut window,
        &timer,
        2000,
        |event| matches!(event, Event::MouseMove { x, y } if i32::from(x) == px - 60 && i32::from(y) == py - 60),
    );
    if moved.is_none() {
        return step(context, 16);
    }

    // A click: pressed and released at the pointer position.
    if !button(LEFT_BUTTON) || !button(LEFT_BUTTON | UP) {
        return step(context, 17);
    }
    let at = |down: bool| {
        move |event: Event| {
            matches!(event, Event::MouseButton { button: MouseButton::Select, pressed, x, y, .. }
                if pressed == down && i32::from(x) == px - 60 && i32::from(y) == py - 60)
        }
    };
    if await_event(context, &mut window, &timer, 2000, at(true)).is_none()
        || await_event(context, &mut window, &timer, 2000, at(false)).is_none()
    {
        return step(context, 18);
    }
    // Draw where the click arrived and read it back as the pen drawn earlier.
    {
        let mut canvas = window.rastport(&graphics);
        let (x, y) = (px as i16 - 60, py as i16 - 60);
        let _ = canvas.set_pen(3);
        let _ = canvas.fill_rect(x - 2, y - 2, x + 2, y + 2);
        let (dot, reference) = (
            canvas.read_pixel(x, y).ok().flatten(),
            canvas.read_pixel(bl + 201, bt + 121).ok().flatten(),
        );
        if dot.is_none() || dot != reference {
            return step(context, 19);
        }
    }

    // Keys: the active window gets the character the keymap makes of the code.
    if !key(KEY_A) || !key(KEY_A | UP) {
        return step(context, 20);
    }
    let typed = await_event(context, &mut window, &timer, 2000, |event| {
        matches!(
            event,
            Event::Key {
                character: b'a',
                ..
            } | Event::RawKey {
                code: 0x20,
                pressed: true,
                ..
            }
        )
    });
    if typed.is_none() {
        return step(context, 21);
    }

    // Resize: reported as NewSize, with a refresh to follow on simple refresh.
    if window.resize_by(40, 30).is_err() {
        return step(context, 22);
    }
    if await_event(context, &mut window, &timer, 2000, |event| {
        event == Event::NewSize
    })
    .is_none()
    {
        return step(context, 23);
    }
    let Ok(grown) = window.info() else {
        return step(context, 24);
    };
    if grown.width != info.width + 40 || grown.height != info.height + 30 {
        context.diagnostic(b"qualification-window-grown", u64::from(grown.width));
        return step(context, 25);
    }
    // A refresh begun and completed on request leaves the window usable.
    if window.begin_refresh().is_err() {
        return step(context, 26);
    }
    drop(window.begin_refresh());

    // Waiting with no input: only the timer's signal comes back.
    {
        let Ok(mut alarm) = timer.start(Duration::from_millis(100)) else {
            return step(context, 27);
        };
        let Ok(got) = aros::wait_signals(context, window.signal_mask() | timer.signal_mask())
        else {
            return step(context, 28);
        };
        if got & timer.signal_mask() == 0 || got & window.signal_mask() != 0 {
            return step(context, 29);
        }
        let _ = alarm.wait();
    }

    // The close gadget: a click in the top left corner of the title bar.
    let (gx, gy) = (60 + i32::from(bt) / 2, 60 + i32::from(bt) / 2);
    if !pointer_to(gx, gy) || !button(LEFT_BUTTON) || !button(LEFT_BUTTON | UP) {
        return step(context, 30);
    }
    if await_event(context, &mut window, &timer, 2000, |event| {
        event == Event::CloseWindow
    })
    .is_none()
    {
        return step(context, 31);
    }

    // Events still queued when the window is dropped are returned with it.
    if !pointer_to(px, py)
        || !pointer_to(px + 5, py + 5)
        || !button(LEFT_BUTTON)
        || !button(LEFT_BUTTON | UP)
    {
        return step(context, 32);
    }
    let _ = await_event(context, &mut window, &timer, 300, |_| false);
    // SAFETY: test-only control of the native bridge.
    unsafe { sdk_test_input_close() };
    // Queue more events after the input device is gone from this test.
    let live = context.statistics();
    if live.windows != baseline.windows + 1 || live.pubscreens != baseline.pubscreens + 1 {
        return step(context, 33);
    }
    drop(window);
    drop(screen);
    drop(timer);
    drop(intuition);
    drop(graphics);
    if !same_resources(baseline, context.statistics()) {
        return step(context, 34);
    }
    true
}

/// A window and a screen lock are left to the native end-of-run cleanup.
pub fn forgotten(context: &Context) -> bool {
    let baseline = context.statistics();
    let Ok(intuition) = Intuition::open(context) else {
        return false;
    };
    let Ok(screen) = PubScreen::lock(&intuition, None) else {
        return false;
    };
    let Ok(window) = WindowBuilder::new()
        .title(b"forgotten")
        .open(&intuition, Some(&screen))
    else {
        return false;
    };
    let live = context.statistics();
    context.diagnostic(b"qualification-window-forgotten", live.windows as u64);
    let ok = live.windows == baseline.windows + 1 && live.pubscreens == baseline.pubscreens + 1;
    mem::forget(window);
    mem::forget(screen);
    mem::forget(intuition);
    ok
}

/// Opens a window with some drawing in it and holds it, so a screen dump of
/// the guest shows it.
pub fn hold(context: &Context) -> bool {
    let Ok(graphics) = Graphics::open(context) else {
        return false;
    };
    let Ok(intuition) = Intuition::open(context) else {
        return false;
    };
    let Ok(timer) = Timer::open(context) else {
        return false;
    };
    let Ok(mut window) = WindowBuilder::new()
        .title(b"ami-rust M6")
        .position(40, 60)
        .inner_size(300, 200)
        .limits(100, 80, 600, 500)
        .open(&intuition, None)
    else {
        return false;
    };
    let Ok(info) = window.info() else {
        return false;
    };
    let (bl, bt) = (info.border_left as i16, info.border_top as i16);
    {
        let mut canvas = window.rastport(&graphics);
        let _ = canvas.set_pen(2);
        let _ = canvas.fill_rect(bl + 10, bt + 10, bl + 120, bt + 80);
        let _ = canvas.set_pen(1);
        let _ = canvas.ellipse(bl + 200, bt + 60, 60, 40);
        let _ = canvas.set_pen(3);
        let _ = canvas.polygon(&[
            (bl + 20, bt + 150),
            (bl + 140, bt + 150),
            (bl + 80, bt + 110),
        ]);
        let _ = canvas.set_pen(1);
        let _ = canvas.move_to(bl + 150, bt + 150);
        let _ = canvas.text(b"aros-intuition");
    }
    let _ = await_event(context, &mut window, &timer, 25_000, |event| {
        event == Event::CloseWindow
    });
    true
}

//! Icon and Workbench cases: disk objects, tool types and matching, an
//! application window that receives a drop sent to it, application icons and
//! menu items, and cleanup.
//!
//! A user drag cannot be simulated, so the drop is delivered with
//! `SendAppWindowMessage` to the program's own application window.

use core::{
    ffi::{c_char, c_void},
    mem, ptr,
    time::Duration,
};

use aros::{BytePath, Context, File, FileMode, Library};
use aros_icon::{DiskObject, Error as IconError, Icons, Kind};
use aros_intuition::{Intuition, WindowBuilder};
use aros_sys as sys;
use aros_timer::Timer;
use aros_workbench::{AppIcon, AppMenuItem, AppMessageKind, AppPort, AppWindow, Workbench};

use super::same_resources;

fn layout_matches(context: &Context) -> bool {
    let expected = sys::wb_layout_values();
    let mut actual = [0u64; sys::WB_LAYOUT_VALUE_COUNT];
    // SAFETY: exact writable capacity; C writes only scalar oracle values.
    let count = unsafe { sys::sdk_wb_layout(actual.as_mut_ptr(), actual.len()) };
    if count != actual.len() || actual != expected {
        context.diagnostic(b"qualification-wb-layout-count", count as u64);
        for (index, (a, e)) in actual.iter().zip(expected).enumerate() {
            if *a != e {
                context.diagnostic(b"qualification-wb-layout-index", index as u64);
            }
        }
        return false;
    }
    true
}

fn step(context: &Context, number: u64) -> bool {
    context.diagnostic(b"qualification-wb-step", number);
    false
}

pub fn icons(context: &Context) -> bool {
    let baseline = context.statistics();
    if !layout_matches(context) {
        return step(context, 1);
    }
    let Ok(icons) = Icons::open(context) else {
        return step(context, 2);
    };

    // Refusals before any native call, and a missing icon.
    if DiskObject::open(&icons, &[b'x'; 128]).err() != Some(IconError::Invalid)
        || DiskObject::open(&icons, b"a\0b").err() != Some(IconError::Invalid)
        || DiskObject::open(&icons, b"RAM:no-such-icon-m9").err() != Some(IconError::NotFound)
    {
        return step(context, 3);
    }

    let Ok(mut icon) = DiskObject::default_for(&icons, Kind::Project) else {
        return step(context, 4);
    };
    context.diagnostic(b"default-kind", icon.kind().map_or(0, |kind| kind as u64));
    context.diagnostic(b"default-tool-types", icon.tool_types().count() as u64);
    if icon.kind() != Some(Kind::Project) {
        return step(context, 5);
    }
    let too_many = [&b"X"[..]; 65];
    if icon.set_tool_types(&too_many).err() != Some(IconError::Invalid)
        || icon.set_tool_types(&[b"a\0b"]).err() != Some(IconError::Invalid)
        || icon.set_default_tool(&[b'x'; 513]).err() != Some(IconError::Invalid)
    {
        return step(context, 6);
    }
    if icon.set_default_tool(b"SYS:Utilities/MultiView").is_err()
        || icon
            .set_tool_types(&[b"MODE=fast", b"DEBUG", b"LEVEL=3"])
            .is_err()
        || icon.set_stack_size(16_384).is_err()
    {
        return step(context, 7);
    }
    let types: [&[u8]; 3] = [b"MODE=fast", b"DEBUG", b"LEVEL=3"];
    if !icon.tool_types().eq(types.iter().copied())
        || icon.default_tool() != Some(&b"SYS:Utilities/MultiView"[..])
        || icon.stack_size() != 16_384
        || icon.find_tool_type(b"MODE") != Some(&b"fast"[..])
        || icon.find_tool_type(b"debug") != Some(&b""[..])
        || icon.find_tool_type(b"LEVEL") != Some(&b"3"[..])
        || icon.find_tool_type(b"NOPE").is_some()
    {
        return step(context, 8);
    }
    // MatchToolValue: alternatives separated by a bar, any case.
    let matches = |value: &[u8], wanted: &[u8]| icons.match_tool_value(value, wanted);
    if matches(b"fast", b"slow|fast") != Ok(true)
        || matches(b"FAST", b"slow|fast") != Ok(true)
        || matches(b"medium", b"slow|fast") != Ok(false)
        || matches(b"slow", b"slow") != Ok(true)
    {
        return step(context, 9);
    }

    // Write the icon and read it back.
    let name = b"RAM:m9file";
    let _ = icons.delete(name);
    if icon.put(name).is_err() {
        return step(context, 10);
    }
    {
        let Ok(read) = DiskObject::open(&icons, name) else {
            return step(context, 11);
        };
        context.diagnostic(b"read-kind", read.kind().map_or(0, |kind| kind as u64));
        let same = read.kind() == Some(Kind::Project)
            && read.default_tool() == Some(&b"SYS:Utilities/MultiView"[..])
            && read.tool_types().eq(types.iter().copied())
            && read.stack_size() == 16_384
            && read.find_tool_type(b"MODE") == Some(&b"fast"[..]);
        if !same {
            return step(context, 12);
        }
    }
    if icons.delete(name).is_err()
        || DiskObject::open(&icons, name).err() != Some(IconError::NotFound)
    {
        return step(context, 13);
    }
    // A new blank icon has no tool types and no default tool.
    {
        let Ok(blank) = DiskObject::new(&icons, Kind::Tool) else {
            return step(context, 14);
        };
        if blank.kind() != Some(Kind::Tool) || blank.tool_types().count() != 0 {
            return step(context, 15);
        }
    }
    drop(icon);
    drop(icons);
    if !same_resources(baseline, context.statistics()) {
        return step(context, 16);
    }
    true
}

fn make_files(context: &Context) -> bool {
    let Ok(dir) = BytePath::new(b"RAM:m9dir") else {
        return false;
    };
    let _ = aros::create_dir(context, &dir);
    for name in [
        &b"RAM:m9dir/a.txt"[..],
        b"RAM:m9dir/b.txt",
        b"RAM:m9dir/c.txt",
    ] {
        let Ok(path) = BytePath::new(name) else {
            return false;
        };
        let Ok(file) = File::open(context, &path, FileMode::CreateTruncate) else {
            return false;
        };
        drop(file);
    }
    true
}

fn remove_files(context: &Context) {
    for name in [
        &b"RAM:m9dir/a.txt"[..],
        b"RAM:m9dir/b.txt",
        b"RAM:m9dir/c.txt",
        b"RAM:m9dir",
    ] {
        if let Ok(path) = BytePath::new(name) {
            let _ = aros::delete(context, &path);
        }
    }
}

unsafe extern "C" {
    fn sdk_test_spawn(entry: extern "C" fn(*mut c_void), argument: *mut c_void) -> i32;
    fn sdk_test_spawn_join(timeout_ms: u32) -> i32;
}

/// What the second process sends and what it got back.
struct Send {
    base: *mut sys::Library,
    window: *mut c_void,
    paths: [*const c_char; 8],
    count: u32,
    position: (i16, i16),
    time: (u32, u32),
    result: i32,
}

/// Runs `SendAppWindowMessage` on the second process, which blocks there until
/// the first process replies to the message.
extern "C" fn send_entry(argument: *mut c_void) {
    // SAFETY: the argument is the `Send` of the starting process, which waits
    // for this process in `finish_send` before it drops it.
    let job = unsafe { &mut *argument.cast::<Send>() };
    // SAFETY: the library base and the window are open in the starting process.
    job.result = i32::from(unsafe {
        sys::workbench::send_app_window_message(
            job.base,
            job.window,
            job.count,
            job.paths.as_ptr(),
            0,
            job.position.0,
            job.position.1,
            job.time.0,
            job.time.1,
        )
    });
}

fn start_send(job: &mut Send) -> bool {
    // SAFETY: test-only control; `job` outlives the process (see `finish_send`).
    unsafe { sdk_test_spawn(send_entry, ptr::from_mut(job).cast()) == 0 }
}

/// Waits for the second process and returns what `SendAppWindowMessage` gave.
fn finish_send(job: &Send) -> Option<bool> {
    // SAFETY: test-only control.
    (unsafe { sdk_test_spawn_join(10_000) } == 2).then_some(job.result != 0)
}

fn new_send(
    base: *mut sys::Library,
    window: *mut c_void,
    names: &[&'static [u8]],
    position: (i16, i16),
    time: (u32, u32),
) -> Send {
    let mut paths = [ptr::null::<c_char>(); 8];
    for (slot, name) in paths.iter_mut().zip(names) {
        // The names are NUL-terminated byte strings.
        *slot = name.as_ptr().cast();
    }
    Send {
        base,
        window,
        paths,
        count: names.len() as u32,
        position,
        time,
        result: -1,
    }
}

/// Waits for the port's signal and the timer in one call; returns the signals
/// that came back.
fn wait_port(
    context: &Context,
    port: &AppPort<'_, '_>,
    timer: &Timer<'_>,
    milliseconds: u64,
) -> Option<u32> {
    let mut alarm = timer.start(Duration::from_millis(milliseconds)).ok()?;
    let got = aros::wait_signals(context, port.signal_mask() | timer.signal_mask()).ok();
    let _ = alarm.abort();
    got
}

/// Reads the next message, waiting up to `milliseconds` for the port and the
/// timer together.
fn receive(
    context: &Context,
    port: &AppPort<'_, '_>,
    timer: &Timer<'_>,
    milliseconds: u64,
) -> Option<aros_workbench::AppMessage> {
    let mut alarm = timer.start(Duration::from_millis(milliseconds)).ok()?;
    let mut found = None;
    loop {
        if let Ok(Some(message)) = port.next() {
            found = Some(message);
            break;
        }
        if alarm.is_finished().unwrap_or(true) {
            break;
        }
        let _ = aros::wait_signals(context, port.signal_mask() | timer.signal_mask());
    }
    let _ = alarm.abort();
    found
}

pub fn workbench(context: &Context) -> bool {
    let baseline = context.statistics();
    if !make_files(context) {
        return step(context, 20);
    }
    let Ok(intuition) = Intuition::open(context) else {
        return step(context, 21);
    };
    let Ok(window) = WindowBuilder::new()
        .title(b"ami-rust M9 drop")
        .position(40, 40)
        .inner_size(200, 80)
        .open(&intuition, None)
    else {
        return step(context, 22);
    };
    let Ok(timer) = Timer::open(context) else {
        return step(context, 23);
    };
    let Ok(workbench) = Workbench::open(context) else {
        return step(context, 24);
    };
    let Ok(icons) = Icons::open(context) else {
        return step(context, 25);
    };
    let Ok(port) = AppPort::new(&workbench) else {
        return step(context, 26);
    };
    if port.signal_mask() == 0 {
        return step(context, 27);
    }
    // The raw library base, for the call the second process makes.
    let Ok(name) = BytePath::new(b"workbench.library") else {
        return step(context, 28);
    };
    let Ok(raw_library) = Library::open(context, &name, 45) else {
        return step(context, 28);
    };
    // SAFETY: the base is used only while `raw_library` is open.
    let Some(base) = (unsafe { raw_library.raw_base() }) else {
        return step(context, 28);
    };
    let base = base.cast::<sys::Library>();
    let window_pointer = window.as_raw();

    const A: &[u8] = b"RAM:m9dir/a.txt\0";
    const B: &[u8] = b"RAM:m9dir/b.txt\0";
    const C: &[u8] = b"RAM:m9dir/c.txt\0";

    // Without an application window the call returns false at once.
    let mut refused = new_send(base, window_pointer, &[A, B], (1, 2), (3, 4));
    if !start_send(&mut refused) || finish_send(&refused) != Some(false) {
        return step(context, 29);
    }
    let Ok(target) = AppWindow::add(&port, &window, 7, 0x1234) else {
        return step(context, 30);
    };

    // A drop of two files comes back as one typed message with owned paths.
    // The sender blocks in its call until this task reads the message.
    let mut first = new_send(base, window_pointer, &[A, B], (30, 40), (111, 222));
    if !start_send(&mut first) {
        return step(context, 31);
    }
    {
        let Some(message) = receive(context, &port, &timer, 5000) else {
            return step(context, 32);
        };
        let (path_a, path_b) = (message.path(0), message.path(1));
        if let (Ok(a), Ok(b)) = (&path_a, &path_b) {
            context.diagnostic(a.as_bytes(), a.len() as u64);
            context.diagnostic(b.as_bytes(), b.len() as u64);
        }
        let ends = |path: &Result<aros_workbench::AppPath, aros_workbench::Error>, tail: &[u8]| {
            path.as_ref()
                .is_ok_and(|path| path.as_bytes().ends_with(tail))
        };
        let ok = message.kind() == AppMessageKind::Window
            && message.id() == 7
            && message.user_data() == 0x1234
            && message.total_paths() == 2
            && message.copied_paths() == 2
            && message.position() == (30, 40)
            && message.time() == (111, 222)
            && message.path(2).is_err()
            && ends(&path_a, b"m9dir/a.txt")
            && ends(&path_b, b"m9dir/b.txt");
        if !ok {
            return step(context, 34);
        }
    }
    if finish_send(&first) != Some(true) || !matches!(port.next(), Ok(None)) {
        return step(context, 35);
    }

    // Three files; then nothing is waiting, so only the timer's signal returns.
    let mut second = new_send(base, window_pointer, &[A, B, C], (5, 6), (7, 8));
    if !start_send(&mut second) {
        return step(context, 36);
    }
    {
        let Some(message) = receive(context, &port, &timer, 5000) else {
            // SAFETY: test-only control.
            let state = unsafe { sdk_test_spawn_join(500) };
            context.diagnostic(b"second-helper-state", state as u64);
            context.diagnostic(b"second-helper-result", second.result as u64);
            return step(context, 37);
        };
        let last = message
            .path(2)
            .is_ok_and(|path| path.as_bytes().ends_with(b"m9dir/c.txt"));
        if message.total_paths() != 3
            || message.copied_paths() != 3
            || message.position() != (5, 6)
            || !last
        {
            return step(context, 38);
        }
    }
    if finish_send(&second) != Some(true) {
        return step(context, 39);
    }
    match wait_port(context, &port, &timer, 150) {
        Some(got) if got & timer.signal_mask() != 0 && got & port.signal_mask() == 0 => {}
        _ => return step(context, 40),
    }

    // An application icon and a menu item register and are removed again; they
    // are not triggered here (that needs the user), and the window still gets
    // its message while they exist.
    {
        let Ok(disk) = DiskObject::default_for(&icons, Kind::Project) else {
            return step(context, 41);
        };
        let Ok(_app_icon) = AppIcon::add(&port, &disk, b"ami-rust M9", 1, 0) else {
            return step(context, 42);
        };
        let Ok(_menu_item) = AppMenuItem::add(&port, b"ami-rust M9 item", 2, 0) else {
            return step(context, 43);
        };
        let live = context.statistics();
        if live.wbobjects != baseline.wbobjects + 3 || live.wbports != baseline.wbports + 1 {
            return step(context, 44);
        }
        let mut third = new_send(base, window_pointer, &[A], (9, 9), (1, 1));
        if !start_send(&mut third) {
            return step(context, 45);
        }
        match receive(context, &port, &timer, 5000) {
            Some(message) if message.kind() == AppMessageKind::Window && message.id() == 7 => {}
            _ => return step(context, 46),
        }
        if finish_send(&third) != Some(true) {
            return step(context, 47);
        }
    }
    if context.statistics().wbobjects != baseline.wbobjects + 1 {
        return step(context, 48);
    }

    // A message still queued when the application window is removed is replied
    // to first, which also lets the blocked sender finish.
    let mut pending = new_send(base, window_pointer, &[A, B, C], (1, 1), (1, 1));
    if !start_send(&mut pending) {
        return step(context, 49);
    }
    // Wait until the second process has put its message on the port.
    let Ok(mut alarm) = timer.start(Duration::from_secs(5)) else {
        return step(context, 52);
    };
    while !port.has_pending() && !alarm.is_finished().unwrap_or(true) {
        let _ = aros::wait_signals(context, port.signal_mask() | timer.signal_mask());
    }
    let _ = alarm.abort();
    drop(alarm);
    if !port.has_pending() {
        return step(context, 53);
    }
    drop(target);
    if finish_send(&pending) != Some(true) {
        return step(context, 50);
    }
    drop(raw_library);
    drop(port);
    drop(icons);
    drop(timer);
    drop(workbench);
    drop(window);
    drop(intuition);
    remove_files(context);
    if !same_resources(baseline, context.statistics()) {
        return step(context, 51);
    }
    true
}

/// An application window, icon and menu item, the port, a disk object and the
/// window are left to the native end-of-run cleanup.
pub fn forgotten(context: &Context) -> bool {
    let baseline = context.statistics();
    let Ok(intuition) = Intuition::open(context) else {
        return false;
    };
    let Ok(window) = WindowBuilder::new()
        .title(b"ami-rust M9 forgotten")
        .open(&intuition, None)
    else {
        return false;
    };
    let Ok(workbench) = Workbench::open(context) else {
        return false;
    };
    let Ok(icons) = Icons::open(context) else {
        return false;
    };
    let Ok(port) = AppPort::new(&workbench) else {
        return false;
    };
    let Ok(disk) = DiskObject::default_for(&icons, Kind::Project) else {
        return false;
    };
    let Ok(target) = AppWindow::add(&port, &window, 1, 0) else {
        return false;
    };
    let Ok(app_icon) = AppIcon::add(&port, &disk, b"forgotten", 2, 0) else {
        return false;
    };
    let Ok(menu_item) = AppMenuItem::add(&port, b"forgotten item", 3, 0) else {
        return false;
    };
    let live = context.statistics();
    context.diagnostic(
        b"qualification-wb-forgotten",
        (live.wbobjects * 100 + live.wbports * 10 + live.icons) as u64,
    );
    let ok = live.wbobjects == baseline.wbobjects + 3
        && live.wbports == baseline.wbports + 1
        && live.icons == baseline.icons + 1;
    mem::forget(menu_item);
    mem::forget(app_icon);
    mem::forget(target);
    mem::forget(disk);
    mem::forget(port);
    mem::forget(icons);
    mem::forget(workbench);
    mem::forget(window);
    mem::forget(intuition);
    ok
}

/// Forgets a disk object that carries replaced tool types.
pub fn icon_forgotten(context: &Context) -> bool {
    let baseline = context.statistics();
    let Ok(icons) = Icons::open(context) else {
        return false;
    };
    let Ok(mut icon) = DiskObject::default_for(&icons, Kind::Project) else {
        return false;
    };
    let ok = icon.set_default_tool(b"SYS:Utilities/MultiView").is_ok()
        && icon.set_tool_types(&[b"A=1", b"B=2"]).is_ok();
    let live = context.statistics();
    context.diagnostic(b"qualification-icon-forgotten", live.icons as u64);
    let ok = ok && live.icons == baseline.icons + 1;
    mem::forget(icon);
    mem::forget(icons);
    ok
}

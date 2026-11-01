//! File requester cases: refusals, cancel, scripted selections and cleanup.
//!
//! A requester blocks its task, so a second native process (a test-only
//! bridge control) waits for the requester's window to appear and then injects
//! events through `input.device`: Escape cancels, typing a file name and
//! pressing Return confirms, the cursor keys walk the list, and pointer
//! events positioned relative to the requester window click list rows and the
//! confirm button.

use core::{ffi::c_void, mem};

use aros::{BytePath, Context, File, FileMode};
use aros_asl::{Asl, AslPath, Error, FileRequestBuilder, FileRequester, Outcome};
use aros_intuition::{Intuition, Window, WindowBuilder};
use aros_sys as sys;

use super::same_resources;

unsafe extern "C" {
    fn sdk_test_input_open() -> i32;
    fn sdk_test_input_close();
    fn sdk_test_script_reset();
    fn sdk_test_script_add(
        delay_ms: u32,
        class: u32,
        code: u32,
        qualifier: u32,
        x: i32,
        y: i32,
    ) -> i32;
    fn sdk_test_script_start(title: *const u8, length: usize, parent: *mut c_void) -> i32;
    fn sdk_test_script_join(timeout_ms: u32) -> i32;
}

const CLASS_RAWKEY: u32 = 1;
const CLASS_RAWMOUSE: u32 = 2;
const IN_WINDOW: u32 = 0x100;
const RELATIVE_MOUSE: u32 = 1 << 15;
const LEFT_BUTTON: u32 = 0x68;
const NO_BUTTON: u32 = 0xff;
const UP: u32 = 0x80;
const RETURN: u32 = 0x44;
const ESCAPE: u32 = 0x45;
const CURSOR_DOWN: u32 = 0x4d;
const LEFT_SHIFT: u32 = 0x60;
const SHIFT: u32 = 1;

fn raw_code(byte: u8) -> Option<u32> {
    Some(match byte {
        b'a' => 0x20,
        b'b' => 0x35,
        b'c' => 0x33,
        b'd' => 0x22,
        b'e' => 0x12,
        b'f' => 0x23,
        b'g' => 0x24,
        b'h' => 0x25,
        b'i' => 0x17,
        b'j' => 0x26,
        b'k' => 0x27,
        b'l' => 0x28,
        b'm' => 0x37,
        b'n' => 0x36,
        b'o' => 0x18,
        b'p' => 0x19,
        b'q' => 0x10,
        b'r' => 0x13,
        b's' => 0x21,
        b't' => 0x14,
        b'u' => 0x16,
        b'v' => 0x34,
        b'w' => 0x11,
        b'x' => 0x32,
        b'y' => 0x15,
        b'z' => 0x31,
        b'1'..=b'9' => u32::from(byte - b'0'),
        b'0' => 0x0a,
        b'.' => 0x39,
        _ => return None,
    })
}

fn add(delay: u32, class: u32, code: u32, qualifier: u32, x: i32, y: i32) -> bool {
    // SAFETY: test-only controls of the native bridge.
    unsafe { sdk_test_script_add(delay, class, code, qualifier, x, y) == 0 }
}

fn press(code: u32) -> bool {
    add(40, CLASS_RAWKEY, code, 0, 0, 0) && add(20, CLASS_RAWKEY, code | UP, 0, 0, 0)
}

fn type_text(text: &[u8]) -> bool {
    text.iter().all(|byte| raw_code(*byte).is_some_and(press))
}

/// Moves the pointer to a position in the requester window (negative values
/// count from the right and bottom edges) and clicks.
fn click_in_window(x: i32, y: i32, qualifier: u32) -> bool {
    add(60, CLASS_RAWMOUSE | IN_WINDOW, NO_BUTTON, qualifier, x, y)
        && add(
            60,
            CLASS_RAWMOUSE,
            LEFT_BUTTON,
            RELATIVE_MOUSE | qualifier,
            0,
            0,
        )
        && add(
            60,
            CLASS_RAWMOUSE,
            LEFT_BUTTON | UP,
            RELATIVE_MOUSE | qualifier,
            0,
            0,
        )
}

/// Where the list rows and the confirm button are in the requester window of
/// each pinned image (measured from a screen dump): the x of a name, the y of
/// the first row and the row height, and the confirm button from the left and
/// bottom edges.
#[cfg(not(all(target_os = "aros", target_abi = "abi11")))]
const GEOMETRY: (i32, i32, i32, i32, i32) = (40, 27, 10, 58, -28);
#[cfg(all(target_os = "aros", target_abi = "abi11"))]
const GEOMETRY: (i32, i32, i32, i32, i32) = (40, 39, 15, 66, -35);

fn click_row(row: i32, qualifier: u32) -> bool {
    click_in_window(GEOMETRY.0, GEOMETRY.1 + row * GEOMETRY.2, qualifier)
}

fn click_ok() -> bool {
    click_in_window(GEOMETRY.3, GEOMETRY.4, 0)
}

fn layout_matches(context: &Context) -> bool {
    let expected = sys::asl_layout_values();
    let mut actual = [0u64; sys::ASL_LAYOUT_VALUE_COUNT];
    // SAFETY: exact writable capacity; C writes only scalar oracle values.
    let count = unsafe { sys::sdk_asl_layout(actual.as_mut_ptr(), actual.len()) };
    if count != actual.len() || actual != expected {
        context.diagnostic(b"qualification-asl-layout-count", count as u64);
        for (index, (a, e)) in actual.iter().zip(expected).enumerate() {
            if *a != e {
                context.diagnostic(b"qualification-asl-layout-index", index as u64);
            }
        }
        return false;
    }
    true
}

fn step(context: &Context, number: u64) -> bool {
    context.diagnostic(b"qualification-asl-step", number);
    false
}

/// What a scripted request ended with.
struct Result {
    accepted: bool,
    count: usize,
    paths: [Option<AslPath>; 4],
    script: i32,
}

/// Shows `requester` with the events already queued in the script and waits
/// for the script to end.
fn run(
    requester: &mut FileRequester<'_, '_>,
    title: &[u8],
    parent: &Window<'_, '_>,
) -> Option<Result> {
    // SAFETY: the title bytes live through the call.
    if unsafe { sdk_test_script_start(title.as_ptr(), title.len(), parent.as_raw()) } != 0 {
        return None;
    }
    let outcome = requester.request(Some(parent));
    // SAFETY: test-only control of the native bridge.
    let script = unsafe { sdk_test_script_join(15_000) };
    let mut result = Result {
        accepted: false,
        count: 0,
        paths: [None; 4],
        script,
    };
    match outcome.ok()? {
        Outcome::Cancelled => {}
        Outcome::Accepted(selection) => {
            result.accepted = true;
            result.count = selection.len();
            for index in 0..selection.len().min(4) {
                result.paths[index] = Some(selection.path(index).ok()?);
            }
        }
    }
    Some(result)
}

fn show(context: &Context, label: &[u8], result: &Result) {
    context.diagnostic(
        label,
        u64::from(result.accepted) << 32 | result.count as u64,
    );
    for path in result.paths.iter().flatten() {
        let mut text = [0u8; 64];
        let bytes = path.as_bytes();
        let length = bytes.len().min(text.len());
        text[..length].copy_from_slice(&bytes[..length]);
        context.diagnostic(&text[..length], bytes.len() as u64);
    }
}

fn is(result: &Result, expected: &[&[u8]]) -> bool {
    result.script == 2
        && result.accepted
        && result.count == expected.len()
        && expected.iter().enumerate().all(|(index, want)| {
            result
                .paths
                .get(index)
                .and_then(|path| path.as_ref())
                .is_some_and(|path| path.as_bytes() == *want)
        })
}

fn make_files(context: &Context) -> bool {
    let Ok(dir) = BytePath::new(b"RAM:m7dir") else {
        return false;
    };
    let _ = aros::create_dir(context, &dir);
    for name in [
        &b"RAM:m7dir/a.txt"[..],
        b"RAM:m7dir/b.txt",
        b"RAM:m7dir/c.txt",
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
        &b"RAM:m7dir/a.txt"[..],
        b"RAM:m7dir/b.txt",
        b"RAM:m7dir/c.txt",
        b"RAM:m7dir",
    ] {
        if let Ok(path) = BytePath::new(name) {
            let _ = aros::delete(context, &path);
        }
    }
}

pub fn cases(context: &Context) -> bool {
    let baseline = context.statistics();
    if !layout_matches(context) {
        return step(context, 1);
    }
    if !make_files(context) {
        return step(context, 2);
    }
    let Ok(intuition) = Intuition::open(context) else {
        return step(context, 3);
    };
    let Ok(parent) = WindowBuilder::new()
        .title(b"ami-rust M7 parent")
        .position(20, 20)
        .inner_size(260, 80)
        .open(&intuition, None)
    else {
        return step(context, 4);
    };
    let Ok(asl) = Asl::open(context) else {
        return step(context, 5);
    };
    // SAFETY: test-only control of the native bridge.
    unsafe { sdk_test_input_open() };

    // Argument checks before any native call.
    if FileRequestBuilder::new()
        .title(&[b'x'; 128])
        .build(&asl)
        .err()
        != Some(Error::Invalid)
        || FileRequestBuilder::new()
            .initial_drawer(&[b'x'; 256])
            .build(&asl)
            .err()
            != Some(Error::Invalid)
        || FileRequestBuilder::new()
            .initial_file(b"a\0b")
            .build(&asl)
            .err()
            != Some(Error::Invalid)
    {
        return step(context, 6);
    }

    // Cancel: Escape closes the requester.
    {
        let title = b"ami-rust M7 cancel";
        let Ok(mut requester) = FileRequestBuilder::new()
            .title(title)
            .initial_drawer(b"RAM:")
            .build(&asl)
        else {
            return step(context, 7);
        };
        // SAFETY: test-only control of the native bridge.
        unsafe { sdk_test_script_reset() };
        if !press(ESCAPE) {
            return step(context, 8);
        }
        let Some(result) = run(&mut requester, title, &parent) else {
            return step(context, 9);
        };
        show(context, b"cancel", &result);
        if result.accepted || result.script != 2 {
            return step(context, 10);
        }
    }

    // A scripted selection by typing a name and Return; then the same
    // requester shown again starts where it ended, so Return alone accepts the
    // same path.
    {
        let title = b"ami-rust M7 open";
        let Ok(mut requester) = FileRequestBuilder::new()
            .title(title)
            .initial_drawer(b"RAM:")
            .build(&asl)
        else {
            return step(context, 11);
        };
        unsafe { sdk_test_script_reset() };
        if !type_text(b"m7file.txt") || !press(RETURN) {
            return step(context, 12);
        }
        let Some(result) = run(&mut requester, title, &parent) else {
            return step(context, 13);
        };
        show(context, b"typed", &result);
        if !is(&result, &[b"RAM:m7file.txt"]) {
            return step(context, 14);
        }
        unsafe { sdk_test_script_reset() };
        if !press(RETURN) {
            return step(context, 15);
        }
        let Some(again) = run(&mut requester, title, &parent) else {
            return step(context, 16);
        };
        show(context, b"again", &again);
        if !is(&again, &[b"RAM:m7file.txt"]) {
            return step(context, 17);
        }
    }

    // Save mode with a pattern: the same typed selection.
    {
        let title = b"ami-rust M7 save";
        let Ok(mut requester) = FileRequestBuilder::new()
            .title(title)
            .initial_drawer(b"RAM:")
            .initial_pattern(b"#?.txt")
            .save_mode(true)
            .positive_text(b"Save")
            .build(&asl)
        else {
            return step(context, 18);
        };
        unsafe { sdk_test_script_reset() };
        if !type_text(b"out.txt") || !press(RETURN) {
            return step(context, 19);
        }
        let Some(result) = run(&mut requester, title, &parent) else {
            return step(context, 20);
        };
        show(context, b"save", &result);
        if !is(&result, &[b"RAM:out.txt"]) {
            return step(context, 21);
        }
    }

    // Cursor down in the list walks to the next file.
    {
        let title = b"ami-rust M7 list";
        let Ok(mut requester) = FileRequestBuilder::new()
            .title(title)
            .initial_drawer(b"RAM:m7dir")
            .build(&asl)
        else {
            return step(context, 22);
        };
        unsafe { sdk_test_script_reset() };
        if !press(CURSOR_DOWN) || !press(RETURN) {
            return step(context, 23);
        }
        let Some(result) = run(&mut requester, title, &parent) else {
            return step(context, 24);
        };
        show(context, b"cursor", &result);
        if !(result.script == 2 && result.accepted && result.count == 1) {
            return step(context, 25);
        }
    }

    // Multi-selection: click one row, shift-click another, confirm.
    {
        let title = b"ami-rust M7 multi";
        let Ok(mut requester) = FileRequestBuilder::new()
            .title(title)
            .initial_drawer(b"RAM:m7dir")
            .multi_select(true)
            .build(&asl)
        else {
            return step(context, 26);
        };
        unsafe { sdk_test_script_reset() };
        // Intuition takes the key qualifiers from the key events, so the shift
        // key events carry them.
        let ok = click_row(0, 0)
            && add(40, CLASS_RAWKEY, LEFT_SHIFT, SHIFT, 0, 0)
            && click_row(2, 0)
            && add(40, CLASS_RAWKEY, LEFT_SHIFT | UP, 0, 0, 0)
            && click_ok();
        if !ok {
            return step(context, 27);
        }
        let Some(result) = run(&mut requester, title, &parent) else {
            return step(context, 28);
        };
        show(context, b"multi", &result);
        if !is(&result, &[b"RAM Disk:m7dir/a.txt", b"RAM Disk:m7dir/c.txt"]) {
            return step(context, 29);
        }
    }

    // Drawers only: the confirm button returns the drawer.
    {
        let title = b"ami-rust M7 drawer";
        let Ok(mut requester) = FileRequestBuilder::new()
            .title(title)
            .initial_drawer(b"RAM:m7dir")
            .drawers_only(true)
            .build(&asl)
        else {
            return step(context, 30);
        };
        unsafe { sdk_test_script_reset() };
        if !click_ok() {
            return step(context, 31);
        }
        let Some(result) = run(&mut requester, title, &parent) else {
            return step(context, 32);
        };
        show(context, b"drawer", &result);
        if !is(&result, &[b"RAM:m7dir"]) {
            return step(context, 33);
        }
    }

    // SAFETY: test-only control of the native bridge.
    unsafe { sdk_test_input_close() };
    remove_files(context);
    drop(asl);
    drop(parent);
    drop(intuition);
    if !same_resources(baseline, context.statistics()) {
        return step(context, 40);
    }
    true
}

/// A requester is left to the native end-of-run cleanup.
pub fn forgotten(context: &Context) -> bool {
    let baseline = context.statistics();
    let Ok(asl) = Asl::open(context) else {
        return false;
    };
    let Ok(requester) = FileRequestBuilder::new().title(b"forgotten").build(&asl) else {
        return false;
    };
    let live = context.statistics();
    context.diagnostic(b"qualification-asl-forgotten", live.aslrequests as u64);
    let ok = live.aslrequests == baseline.aslrequests + 1;
    mem::forget(requester);
    mem::forget(asl);
    ok
}

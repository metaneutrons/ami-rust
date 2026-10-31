#![no_main]

use aros::{AppStatus, Context};
use std::alloc::{Layout, alloc, dealloc};
use std::collections::HashMap;
use std::ffi::c_void;
use std::hint::black_box;
use std::io::ErrorKind;
use std::sync::{Mutex, Once};

unsafe extern "C" {
    fn write(fd: i32, buffer: *const c_void, count: usize) -> isize;
    fn clock_gettime(clock: i32, tp: *mut Timespec) -> i32;
}

// The layout and clock numbers that `std`'s random source assumes.
#[repr(C)]
struct Timespec {
    tv_sec: i32,
    tv_nsec: i64,
}

fn say(line: &str) {
    let bytes = line.as_bytes();
    // SAFETY: the pointer and length describe a live byte slice.
    unsafe { write(1, bytes.as_ptr().cast(), bytes.len()) };
}

thread_local! {
    static COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(7) };
}

static ONCE: Once = Once::new();
static LOCK: Mutex<u32> = Mutex::new(0);

fn check(name: &str, ok: bool, failures: &mut u32) {
    say(&format!(
        "std-probe: {name}: {}\n",
        if ok { "ok" } else { "FAILED" }
    ));
    if !ok {
        *failures += 1;
    }
}

fn application(_context: &Context) -> AppStatus {
    let mut failures = 0;

    let mut values: Vec<u32> = (0..1000).collect();
    values.reverse();
    check(
        "vec",
        values[0] == 999 && values.len() == 1000,
        &mut failures,
    );

    let mut zeroed = vec![0u8; 4096];
    let all_zero = zeroed.iter().all(|byte| *byte == 0);
    zeroed.resize(200_000, 7);
    check(
        "zeroed alloc and realloc",
        all_zero && zeroed[4095] == 0 && zeroed[4096] == 7 && zeroed[199_999] == 7,
        &mut failures,
    );

    let mut monotonic = Timespec {
        tv_sec: -1,
        tv_nsec: -1,
    };
    let mut realtime = Timespec {
        tv_sec: -1,
        tv_nsec: -1,
    };
    // SAFETY: both pointers refer to live, writable `Timespec` values.
    let clocks =
        unsafe { clock_gettime(0, &mut monotonic) == 0 && clock_gettime(2, &mut realtime) == 0 };
    check(
        "clock_gettime layout",
        clocks
            && monotonic.tv_sec >= 0
            && (0..1_000_000_000).contains(&monotonic.tv_nsec)
            && realtime.tv_sec > 1_000_000_000
            && (0..1_000_000_000).contains(&realtime.tv_nsec),
        &mut failures,
    );
    say(&format!(
        "std-probe: realtime {} s, monotonic {} s\n",
        realtime.tv_sec, monotonic.tv_sec
    ));

    let text = format!("{}-{:?}", "std", Some(42));
    check("format", text == "std-Some(42)", &mut failures);

    let mut map = HashMap::new();
    for i in 0..64u32 {
        map.insert(format!("key{i}"), i);
    }
    check("hashmap", map.get("key17") == Some(&17), &mut failures);

    let aligned = {
        let layout = Layout::from_size_align(100, 64).unwrap();
        // SAFETY: the layout is valid and the block is released below.
        let pointer = black_box(unsafe { alloc(layout) });
        let ok = !pointer.is_null() && pointer as usize % 64 == 0;
        if !pointer.is_null() {
            // SAFETY: the pointer came from `alloc` with this layout.
            unsafe { dealloc(pointer, layout) };
        }
        ok
    };
    check("over-aligned alloc", aligned, &mut failures);

    let small = (1..64).all(|size| {
        let layout = Layout::from_size_align(size, 1).unwrap();
        // SAFETY: valid layout, released immediately.
        unsafe {
            let pointer = black_box(alloc(layout));
            let ok = !pointer.is_null() && pointer as usize % 16 == 0;
            if !pointer.is_null() {
                dealloc(pointer, layout);
            }
            ok
        }
    });
    check("small alloc", small, &mut failures);

    let refused = [
        (1usize << 32) + 1,
        (1 << 37) + 16,
        (1 << 38) + 16,
        isize::MAX as usize - 7,
    ]
    .into_iter()
    .all(|size| {
        let layout = Layout::from_size_align(size, 8).unwrap();
        // SAFETY: the request is expected to fail; a block is released.
        unsafe {
            let pointer = black_box(alloc(layout));
            if !pointer.is_null() {
                dealloc(pointer, layout);
            }
            pointer.is_null()
        }
    });
    check("huge alloc refused", refused, &mut failures);

    let not_found = std::io::Error::from_raw_os_error(2);
    check(
        "io-error-kind",
        not_found.kind() == ErrorKind::NotFound,
        &mut failures,
    );
    say(&format!("std-probe: io-error-text: {not_found}\n"));

    COUNTER.with(|counter| counter.set(counter.get() + 1));
    check(
        "thread-local",
        COUNTER.with(|counter| counter.get()) == 8,
        &mut failures,
    );

    ONCE.call_once(|| *LOCK.lock().unwrap() += 1);
    ONCE.call_once(|| *LOCK.lock().unwrap() += 1);
    check("once-mutex", *LOCK.lock().unwrap() == 1, &mut failures);

    let spawned = std::thread::Builder::new().spawn(|| ());
    check("thread-unsupported", spawned.is_err(), &mut failures);

    if failures == 0 {
        say("std-probe: all checks passed\n");
        AppStatus::Success
    } else {
        AppStatus::Error
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    aros::dispatch(application)
}

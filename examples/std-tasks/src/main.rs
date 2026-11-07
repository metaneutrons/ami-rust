//! What a second AROS task can and cannot do with the C library that `std` is built on.
//!
//! It creates real DOS processes with `CreateNewProc` and tests, one behaviour per run: freeing
//! memory that another task allocated (`cross`), three tasks allocating and freeing under
//! preemption (`stress`), whether `errno` is per task (`errno`, `errnoaddr`), and raw writes to
//! standard output from three tasks (`stdio`). The results are in README.md. It uses the C
//! functions directly, not `std::thread`, which does not exist on AROS yet.

#![feature(restricted_std)]
use std::ffi::{c_int, c_void};
use std::hint::black_box;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering::SeqCst};

unsafe extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn CreateNewProc(tags: *const [usize; 2]) -> *mut c_void;
    fn Delay(ticks: u32);
    #[cfg_attr(target_abi = "abi1", link_name = "__stdc_geterrnoptr")]
    #[cfg_attr(target_abi = "abi11", link_name = "___geterrnoptr")]
    fn errno_ptr() -> *mut c_int;
}

const TAG_USER: usize = 1 << 31;
const NP_ENTRY: usize = TAG_USER + 1000 + 3;
const NP_STACK: usize = TAG_USER + 1000 + 11;
const NP_NAME: usize = TAG_USER + 1000 + 12;

const BLOCKS: usize = 512;
static PARENT_BLOCKS: [AtomicUsize; BLOCKS] = [const { AtomicUsize::new(0) }; BLOCKS];
static CHILD_BLOCKS: [AtomicUsize; BLOCKS] = [const { AtomicUsize::new(0) }; BLOCKS];
static STATE: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static ERRORS: AtomicU32 = AtomicU32::new(0);
static ADDR1: AtomicUsize = AtomicUsize::new(0);
static ADDR2: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicU32 = AtomicU32::new(0); // 1 cross, 2 stress, 3 errno, 4 stdio

const ITER: usize = 60_000;
const ERRNO_ITER: usize = 30_000;
const LINES: usize = 150;

fn spawn(entry: extern "C" fn(), name: &'static std::ffi::CStr) -> bool {
    let tags: [[usize; 2]; 4] = [
        [NP_ENTRY, entry as usize],
        [NP_STACK, 65536],
        [NP_NAME, name.as_ptr() as usize],
        [0, 0],
    ];
    !unsafe { CreateNewProc(tags.as_ptr()) }.is_null()
}

fn size_of_iter(i: usize) -> usize { (i * 37) % 300 + 2 }
fn fill(p: *mut u8, n: usize, id: u8) { unsafe { p.write(id); p.add(n - 1).write(id ^ 0x5a); } }
fn check(p: *mut u8, n: usize, id: u8) -> bool { unsafe { p.read() == id && p.add(n - 1).read() == id ^ 0x5a } }

fn stress(id: u8) {
    let mut slots = [0usize; 64];
    let mut sizes = [0usize; 64];
    for i in 0..ITER {
        let s = (i * 7 + id as usize) % 64;
        if slots[s] != 0 {
            if !check(slots[s] as *mut u8, sizes[s], id) { ERRORS.fetch_add(1, SeqCst); }
            unsafe { free(slots[s] as *mut c_void) };
            slots[s] = 0;
        } else {
            let n = size_of_iter(i);
            let p = black_box(unsafe { malloc(n) }.cast::<u8>());
            if p.is_null() { ERRORS.fetch_add(1, SeqCst); continue; }
            fill(p, n, id);
            slots[s] = p as usize; sizes[s] = n;
        }
    }
    for s in 0..64 { if slots[s] != 0 { unsafe { free(slots[s] as *mut c_void) }; } }
}

fn errno_work(id: u8) {
    let mine = id as c_int * 1000;
    for i in 0..ERRNO_ITER {
        let want = mine + (i % 97) as c_int;
        unsafe { *errno_ptr() = want };
        let p = black_box(unsafe { malloc(16 + i % 64) }.cast::<u8>());
        if !p.is_null() { unsafe { free(p.cast()) }; }
        if unsafe { *errno_ptr() } != want { ERRORS.fetch_add(1, SeqCst); }
    }
}

fn stdio_work(id: u8) {
    for n in 0..LINES {
        let line = format!("W{id} line {n}\n");
        unsafe { write(1, line.as_ptr().cast(), line.len()) };
    }
}

fn cross_child() {
    while STATE.load(SeqCst) < 1 { unsafe { Delay(1) }; }
    for i in 0..BLOCKS {
        let p = PARENT_BLOCKS[i].load(SeqCst) as *mut u8;
        if !check(p, size_of_iter(i), 7) { ERRORS.fetch_add(1, SeqCst); }
        unsafe { free(p.cast()) };
    }
    for i in 0..BLOCKS {
        let n = size_of_iter(i + 1000);
        let p = unsafe { malloc(n) }.cast::<u8>();
        fill(p, n, 9);
        CHILD_BLOCKS[i].store(p as usize, SeqCst);
    }
    STATE.store(2, SeqCst);
    while STATE.load(SeqCst) < 3 { unsafe { Delay(1) }; }
}

fn run(id: u8) {
    match MODE.load(SeqCst) {
        1 => cross_child(),
        2 => stress(id),
        3 => errno_work(id),
        5 => { let a = unsafe { errno_ptr() } as usize; if id == 1 { ADDR1.store(a, SeqCst) } else { ADDR2.store(a, SeqCst) } }
        4 => stdio_work(id),
        _ => {}
    }
}
extern "C" fn worker1() { run(1); DONE.fetch_add(1, SeqCst); }
extern "C" fn worker2() { run(2); DONE.fetch_add(1, SeqCst); }

fn wait_done(n: u32) -> bool {
    for _ in 0..4000 { if DONE.load(SeqCst) >= n { return true; } unsafe { Delay(2) }; }
    false
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    ERRORS.store(0, SeqCst); DONE.store(0, SeqCst); STATE.store(0, SeqCst);
    match mode.as_str() {
        "cross" => {
            MODE.store(1, SeqCst);
            for i in 0..BLOCKS { let n = size_of_iter(i); let p = unsafe { malloc(n) }.cast::<u8>(); fill(p, n, 7); PARENT_BLOCKS[i].store(p as usize, SeqCst); }
            if !spawn(worker1, c"std-tasks-1") { println!("RESULT cross FAIL spawn"); std::process::exit(3); }
            STATE.store(1, SeqCst);
            for _ in 0..4000 { if STATE.load(SeqCst) >= 2 { break; } unsafe { Delay(2) }; }
            let ok_state = STATE.load(SeqCst) >= 2;
            if ok_state { for i in 0..BLOCKS { let p = CHILD_BLOCKS[i].load(SeqCst) as *mut u8; if !check(p, size_of_iter(i + 1000), 9) { ERRORS.fetch_add(1, SeqCst); } unsafe { free(p.cast()) }; } }
            STATE.store(3, SeqCst);
            let finished = wait_done(1);
            println!("RESULT cross {} errors={} child_finished={finished}", if ok_state && finished && ERRORS.load(SeqCst) == 0 { "ok" } else { "FAIL" }, ERRORS.load(SeqCst));
        }
        "errnoaddr" => {
            MODE.store(5, SeqCst);
            let me = unsafe { errno_ptr() } as usize;
            if !spawn(worker1, c"std-tasks-1") || !spawn(worker2, c"std-tasks-2") { println!("RESULT errnoaddr FAIL spawn"); std::process::exit(3); }
            let finished = wait_done(2);
            let (a, b) = (ADDR1.load(SeqCst), ADDR2.load(SeqCst));
            println!("RESULT errnoaddr main={me:#x} child1={a:#x} child2={b:#x} all_equal={} finished={finished}", me == a && a == b);
        }
        "errno1" => {
            // one task only: does errno survive malloc/free at all?
            MODE.store(3, SeqCst);
            run(0);
            println!("RESULT errno1 {} errors={}", if ERRORS.load(SeqCst) == 0 { "ok" } else { "FAIL" }, ERRORS.load(SeqCst));
        }
        "stress" | "errno" | "stdio" => {
            MODE.store(match mode.as_str() { "stress" => 2, "errno" => 3, _ => 4 }, SeqCst);
            if !spawn(worker1, c"std-tasks-1") || !spawn(worker2, c"std-tasks-2") { println!("RESULT {mode} FAIL spawn"); std::process::exit(3); }
            run(0);
            let finished = wait_done(2);
            println!("RESULT {mode} {} errors={} children_finished={finished}", if finished && ERRORS.load(SeqCst) == 0 { "ok" } else { "FAIL" }, ERRORS.load(SeqCst));
        }
        _ => println!("modes: cross stress errno stdio"),
    }
}

//! Threads in `std` on AROS: spawning and joining, the synchronisation types, parking, channels,
//! thread-locals, errors from several threads, the thread limit, and how the program ends while
//! threads run. One behaviour per run; the expected results are in README.md. Files are made in
//! `RAM:ami-rust-m1/`, which the run must create.

#![feature(restricted_std)]
use std::cell::Cell;
use std::fs;
use std::io::ErrorKind;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::SeqCst};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Condvar, LazyLock, Mutex, Once, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const BASE: &str = "RAM:ami-rust-m1/";

struct T {
    failed: u32,
    total: u32,
}

impl T {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        self.total += 1;
        if !ok {
            self.failed += 1;
        }
        println!("RESULT threads {name} {}{}", if ok { "ok" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
    }
}

fn p(name: &str) -> String {
    format!("{BASE}{name}")
}

thread_local! {
    static COUNTER: Cell<u32> = const { Cell::new(0) };
    static DROPPER: Dropper = Dropper(Cell::new(0));
}
static DROPPED: AtomicU32 = AtomicU32::new(0);
struct Dropper(Cell<u32>);
impl Drop for Dropper {
    fn drop(&mut self) {
        DROPPED.fetch_add(self.0.get(), SeqCst);
    }
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let mut t = T { failed: 0, total: 0 };
    match mode.as_str() {
        "spawn" => {
            let h = thread::spawn(|| 6 * 7);
            t.check("spawn and join return the value", h.join().ok() == Some(42), String::new());
            let handles: Vec<_> = (0..10u64).map(|i| thread::spawn(move || (0..10_000u64).map(|x| x * i).sum::<u64>())).collect();
            let sums: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            t.check("ten threads", sums == (0..10u64).map(|i| (0..10_000u64).map(|x| x * i).sum::<u64>()).collect::<Vec<_>>(), String::new());
            let named = thread::Builder::new().name("worker-one".into()).spawn(|| thread::current().name().map(str::to_owned)).unwrap();
            t.check("a thread knows its name", named.join().unwrap().as_deref() == Some("worker-one"), String::new());
            t.check("the main thread's name", thread::current().name() == Some("main"), format!("{:?}", thread::current().name()));
            let main_id = thread::current().id();
            let other = thread::spawn(|| thread::current().id()).join().unwrap();
            t.check("thread ids differ", main_id != other, String::new());
            fn deep(n: u32) -> u64 { let a = [n as u64; 256]; if n == 0 { a[3] } else { std::hint::black_box(deep(n - 1)) + a[9] } }
            let big = thread::Builder::new().stack_size(4 << 20).spawn(|| deep(1500)).unwrap();
            t.check("Builder::stack_size of 4 MiB holds 3 MiB of frames", big.join().is_ok(), String::new());
            t.check("available_parallelism is 1", thread::available_parallelism().map(|n| n.get()).ok() == Some(1), String::new());
            let scoped = { let v = vec![1, 2, 3]; let mut total = 0; thread::scope(|s| { s.spawn(|| { total = v.iter().sum(); }); }); total };
            t.check("thread::scope", scoped == 6, String::new());
            let flag = Arc::new(AtomicBool::new(false));
            let f2 = flag.clone();
            drop(thread::spawn(move || { thread::sleep(Duration::from_millis(50)); f2.store(true, SeqCst); }));
            let started = Instant::now();
            while !flag.load(SeqCst) && started.elapsed() < Duration::from_secs(5) { thread::sleep(Duration::from_millis(5)); }
            t.check("a detached thread runs on", flag.load(SeqCst), String::new());
            t.check("is_finished", { let h = thread::spawn(|| ()); thread::sleep(Duration::from_millis(100)); let f = h.is_finished(); h.join().unwrap(); f }, String::new());
        }
        "mutex" => {
            let m = Arc::new(Mutex::new(0u64));
            let hs: Vec<_> = (0..4).map(|_| { let m = m.clone(); thread::spawn(move || { for i in 0..20_000 { let mut g = m.lock().unwrap(); let v = *g; if i % 100 == 0 { thread::yield_now(); } *g = v + 1; } }) }).collect();
            for h in hs { h.join().unwrap(); }
            let total = *m.lock().unwrap();
            t.check("four threads, 80000 increments under a Mutex", total == 80_000, format!("{total}"));
            let m2 = Arc::new(Mutex::new(()));
            let g = m2.lock().unwrap();
            let m3 = m2.clone();
            let tried = thread::spawn(move || m3.try_lock().is_err()).join().unwrap();
            drop(g);
            t.check("try_lock fails while another thread holds it", tried, String::new());
            t.check("and works once it is free", m2.try_lock().is_ok(), String::new());
            let b = Arc::new(Barrier::new(4));
            let passed = Arc::new(AtomicU32::new(0));
            let hs: Vec<_> = (0..3).map(|_| { let b = b.clone(); let passed = passed.clone(); thread::spawn(move || { b.wait(); passed.fetch_add(1, SeqCst); }) }).collect();
            thread::sleep(Duration::from_millis(100));
            let before = passed.load(SeqCst);
            b.wait();
            for h in hs { h.join().unwrap(); }
            t.check("a Barrier holds three threads until the fourth", before == 0 && passed.load(SeqCst) == 3, format!("{before}"));
        }
        "condvar" => {
            let pair = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
            let p2 = pair.clone();
            let consumer = thread::spawn(move || { let (m, c) = &*p2; let mut got = Vec::new(); while got.len() < 100 { let mut q = m.lock().unwrap(); while q.is_empty() { q = c.wait(q).unwrap(); } got.extend(q.drain(..)); } got });
            for i in 0..100u32 { let (m, c) = &*pair; m.lock().unwrap().push(i); c.notify_one(); if i % 10 == 0 { thread::sleep(Duration::from_millis(2)); } }
            t.check("a producer and a consumer through a Condvar", consumer.join().unwrap() == (0..100).collect::<Vec<_>>(), String::new());
            let pair = (Mutex::new(false), Condvar::new());
            let started = Instant::now();
            let (g, res) = pair.1.wait_timeout(pair.0.lock().unwrap(), Duration::from_millis(300)).unwrap();
            let took = started.elapsed();
            drop(g);
            t.check("wait_timeout times out after 300 ms", res.timed_out() && took >= Duration::from_millis(300) && took < Duration::from_millis(1000), format!("{took:?}"));
            let pair = Arc::new((Mutex::new(false), Condvar::new()));
            let woken = Arc::new(AtomicU32::new(0));
            let hs: Vec<_> = (0..3).map(|_| { let pair = pair.clone(); let woken = woken.clone(); thread::spawn(move || { let (m, c) = &*pair; let mut g = m.lock().unwrap(); while !*g { g = c.wait(g).unwrap(); } woken.fetch_add(1, SeqCst); }) }).collect();
            thread::sleep(Duration::from_millis(100));
            { let (m, c) = &*pair; *m.lock().unwrap() = true; c.notify_all(); }
            for h in hs { h.join().unwrap(); }
            t.check("notify_all wakes three waiters", woken.load(SeqCst) == 3, String::new());
            let pair = Arc::new((Mutex::new(false), Condvar::new()));
            let p3 = pair.clone();
            let h = thread::spawn(move || { thread::sleep(Duration::from_millis(100)); let (m, c) = &*p3; *m.lock().unwrap() = true; c.notify_one(); });
            let started = Instant::now();
            let (g, res) = pair.1.wait_timeout_while(pair.0.lock().unwrap(), Duration::from_secs(5), |ready| !*ready).unwrap();
            t.check("wait_timeout_while returns when notified, before the timeout", *g && !res.timed_out() && started.elapsed() < Duration::from_secs(2), format!("{:?}", started.elapsed()));
            drop(g);
            h.join().unwrap();
        }
        "rwlock" => {
            let l = Arc::new(RwLock::new(0u64));
            let inside = Arc::new(AtomicU32::new(0));
            let most = Arc::new(AtomicU32::new(0));
            let readers: Vec<_> = (0..3).map(|_| { let l = l.clone(); let inside = inside.clone(); let most = most.clone(); thread::spawn(move || { for _ in 0..20 { let g = l.read().unwrap(); let n = inside.fetch_add(1, SeqCst) + 1; most.fetch_max(n, SeqCst); thread::sleep(Duration::from_millis(5)); inside.fetch_sub(1, SeqCst); drop(g); } }) }).collect();
            let writer = { let l = l.clone(); let inside = inside.clone(); thread::spawn(move || { let mut clean = true; for _ in 0..20 { let mut g = l.write().unwrap(); if inside.load(SeqCst) != 0 { clean = false; } *g += 1; thread::sleep(Duration::from_millis(2)); drop(g); thread::sleep(Duration::from_millis(3)); } clean }) };
            for h in readers { h.join().unwrap(); }
            let clean = writer.join().unwrap();
            t.check("readers overlap", most.load(SeqCst) >= 2, format!("at most {} at once", most.load(SeqCst)));
            t.check("a writer is alone", clean, String::new());
            t.check("every write is there", *l.read().unwrap() == 20, String::new());
        }
        "once" => {
            static ONCE: Once = Once::new();
            static RUNS: AtomicU32 = AtomicU32::new(0);
            static CELL: OnceLock<u32> = OnceLock::new();
            static LAZY: LazyLock<u32> = LazyLock::new(|| { RUNS.fetch_add(100, SeqCst); 7 });
            let b = Arc::new(Barrier::new(6));
            let hs: Vec<_> = (0..6).map(|i| { let b = b.clone(); thread::spawn(move || { b.wait(); ONCE.call_once(|| { thread::sleep(Duration::from_millis(50)); RUNS.fetch_add(1, SeqCst); }); let c = *CELL.get_or_init(|| { thread::sleep(Duration::from_millis(20)); i }); (c, *LAZY) }) }).collect();
            let results: Vec<(u32, u32)> = hs.into_iter().map(|h| h.join().unwrap()).collect();
            t.check("Once runs once among six threads", RUNS.load(SeqCst) % 100 == 1, format!("{}", RUNS.load(SeqCst)));
            t.check("OnceLock: every thread sees the one value", results.iter().all(|r| r.0 == results[0].0), String::new());
            t.check("LazyLock runs once", RUNS.load(SeqCst) / 100 == 1 && results.iter().all(|r| r.1 == 7), String::new());
        }
        "park" => {
            let flag = Arc::new(AtomicBool::new(false));
            let f2 = flag.clone();
            let h = thread::spawn(move || { while !f2.load(SeqCst) { thread::park(); } true });
            thread::sleep(Duration::from_millis(100));
            flag.store(true, SeqCst);
            h.thread().unpark();
            t.check("park until unpark", h.join().unwrap(), String::new());
            let started = Instant::now();
            thread::park_timeout(Duration::from_millis(200));
            let took = started.elapsed();
            t.check("park_timeout returns after 200 ms", took >= Duration::from_millis(150) && took < Duration::from_millis(1000), format!("{took:?}"));
            thread::current().unpark();
            let started = Instant::now();
            thread::park();
            t.check("an unpark before the park is kept", started.elapsed() < Duration::from_millis(100), String::new());
        }
        "channel" => {
            let (tx, rx) = mpsc::channel::<u64>();
            let hs: Vec<_> = (0..3u64).map(|k| { let tx = tx.clone(); thread::spawn(move || { for i in 0..1000u64 { tx.send(k * 1_000_000 + i).unwrap(); } }) }).collect();
            drop(tx);
            let mut got: Vec<u64> = rx.iter().collect();
            for h in hs { h.join().unwrap(); }
            got.sort();
            let want: Vec<u64> = (0..3u64).flat_map(|k| (0..1000u64).map(move |i| k * 1_000_000 + i)).collect();
            t.check("three senders, 3000 messages, none lost", got == want, format!("{}", got.len()));
            let (tx, rx) = mpsc::sync_channel::<u32>(2);
            let h = thread::spawn(move || { let started = Instant::now(); for i in 0..5 { tx.send(i).unwrap(); } started.elapsed() });
            thread::sleep(Duration::from_millis(200));
            let first: Vec<u32> = rx.try_iter().collect();
            let rest: Vec<u32> = rx.iter().collect();
            let took = h.join().unwrap();
            t.check("a sync_channel of 2 makes the sender wait", first.len() <= 3 && took >= Duration::from_millis(150) && [first.clone(), rest].concat() == [0, 1, 2, 3, 4], format!("{first:?} {took:?}"));
            let (_tx, rx) = mpsc::channel::<u32>();
            let started = Instant::now();
            let r = rx.recv_timeout(Duration::from_millis(250));
            t.check("recv_timeout times out", r == Err(mpsc::RecvTimeoutError::Timeout) && started.elapsed() >= Duration::from_millis(250), format!("{:?}", started.elapsed()));
        }
        "tls" => {
            COUNTER.with(|c| c.set(1));
            let vals: Vec<u32> = (0..5u32).map(|i| thread::spawn(move || { COUNTER.with(|c| { let before = c.get(); c.set(100 + i); before * 1000 + c.get() }) })).map(|h| h.join().unwrap()).collect();
            t.check("each thread starts at the initial value and has its own", vals == (0..5u32).map(|i| 100 + i).collect::<Vec<_>>(), format!("{vals:?}"));
            t.check("the main thread's value is unchanged", COUNTER.with(Cell::get) == 1, String::new());
            DROPPED.store(0, SeqCst);
            for i in 1..=3u32 { thread::spawn(move || DROPPER.with(|d| d.0.set(i))).join().unwrap(); }
            t.check("a thread-local's destructor runs when its thread ends", DROPPED.load(SeqCst) == 6, format!("{}", DROPPED.load(SeqCst)));
            thread_local! { static MANY: [Cell<u64>; 8] = const { [const { Cell::new(0) }; 8] }; }
            let ok = (0..20).map(|i| thread::spawn(move || { MANY.with(|m| { m[i % 8].set(i as u64); m[i % 8].get() == i as u64 }) })).all(|h| h.join().unwrap());
            t.check("20 more threads with thread-locals", ok, String::new());
        }
        "errors" => {
            fs::write(p("tfile"), b"x").unwrap();
            let _ = fs::create_dir(p("tdir"));
            let stop = Arc::new(AtomicBool::new(false));
            let worker = |kind: u8, stop: Arc<AtomicBool>| thread::spawn(move || {
                let (mut calls, mut wrong) = (0u32, 0u32);
                while !stop.load(SeqCst) {
                    let got = match kind {
                        0 => fs::File::open(p("nonexistent")).map(drop).map_err(|e| e.kind()),
                        1 => fs::create_dir(p("tdir")).map_err(|e| e.kind()),
                        _ => fs::OpenOptions::new().write(true).open(p("tdir")).map(drop).map_err(|e| e.kind()),
                    };
                    let want = [ErrorKind::NotFound, ErrorKind::AlreadyExists, ErrorKind::IsADirectory][kind as usize];
                    calls += 1;
                    if got != Err(want) { wrong += 1; }
                }
                (calls, wrong)
            });
            let hs: Vec<_> = (0..3).map(|k| worker(k, stop.clone())).collect();
            thread::sleep(Duration::from_secs(3));
            stop.store(true, SeqCst);
            let r: Vec<(u32, u32)> = hs.into_iter().map(|h| h.join().unwrap()).collect();
            t.check("three threads, three different errors for 3 s: every error is the thread's own", r.iter().all(|x| x.1 == 0 && x.0 > 10), format!("(calls, wrong) {r:?}"));
            let _ = fs::remove_file(p("tfile"));
            let _ = fs::remove_dir(p("tdir"));
        }
        "process" => {
            // The current directory and the DOS variables of a thread are its own.
            let main_dir = std::env::current_dir().unwrap();
            let h = thread::spawn(|| { let a = std::env::set_current_dir("RAM:").is_ok(); let here = std::env::current_dir().ok(); unsafe { std::env::set_var("AMI_THREAD_VAR", "thread") }; (a, here, std::env::var("AMI_THREAD_VAR").ok()) });
            let (changed, there, var) = h.join().unwrap();
            t.check("a thread changes its own current directory", changed && there.is_some() && there.as_ref() != Some(&main_dir), format!("{there:?}"));
            t.check("the main thread's current directory is unchanged", std::env::current_dir().ok() == Some(main_dir.clone()), String::new());
            t.check("a thread sees its own variable", var.as_deref() == Some("thread"), String::new());
            t.check("the main thread does not see it", std::env::var("AMI_THREAD_VAR").is_err(), String::new());
            unsafe { std::env::set_var("AMI_MAIN_VAR", "main") };
            let seen = thread::spawn(|| std::env::var("AMI_MAIN_VAR").ok()).join().unwrap();
            t.check("a new thread starts with its parent's variables", seen.as_deref() == Some("main"), format!("{seen:?}"));
            let lines: Vec<_> = (0..3).map(|k| thread::spawn(move || { for i in 0..50 { println!("LINE {k} {i:03} {}", "x".repeat(40)); } })).collect();
            for h in lines { h.join().unwrap(); }
            t.check("150 lines from three threads through println", true, String::new());
        }
        "yield" => {
            // Two threads take turns marking `turn`; a turn counts when the other thread ran since this
            // thread's previous mark.
            let turn = Arc::new(AtomicUsize::new(usize::MAX));
            let switches = Arc::new(AtomicU32::new(0));
            let ready = Arc::new(Barrier::new(2));
            let started = Instant::now();
            let hs: Vec<_> = (0..2usize).map(|me| { let turn = turn.clone(); let switches = switches.clone(); let ready = ready.clone(); thread::spawn(move || { ready.wait(); for _ in 0..2000 { if turn.swap(me, SeqCst) != me { switches.fetch_add(1, SeqCst); } thread::yield_now(); } }) }).collect();
            for h in hs { h.join().unwrap(); }
            let took = started.elapsed();
            println!("INFO yield_now: the other thread ran before {} of 4000 turns; {:?} for 4000 yields", switches.load(SeqCst), took);
            t.check("yield_now lets the other thread run", switches.load(SeqCst) > 2000, String::new());
        }
        "limit" => {
            let release = Arc::new((Mutex::new(false), Condvar::new()));
            let mut handles = Vec::new();
            let stack = std::env::args().nth(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            for _ in 0..1000 {
                let r = release.clone();
                let b = thread::Builder::new();
                let b = if stack > 0 { b.stack_size(stack) } else { b };
                match b.spawn(move || { let (m, c) = &*r; let mut g = m.lock().unwrap(); while !*g { g = c.wait(g).unwrap(); } }) { Ok(h) => handles.push(h), Err(_) => break }
            }
            let n = handles.len();
            { let (m, c) = &*release; *m.lock().unwrap() = true; c.notify_all(); }
            let joined = handles.into_iter().map(|h| h.join().is_ok()).filter(|x| *x).count();
            println!("INFO limit: {n} threads running at once (stack {}), {joined} joined", if stack > 0 { stack } else { 256 * 1024 });
            t.check("at least 100 threads at once, and all join", n >= 100 && joined == n, String::new());
        }
        "slots" => {
            // The number of the next free task storage slot. Run before and after other programs: when
            // it grows, slots are left allocated by programs that have ended.
            unsafe extern "C" { fn sdk_tls_alloc() -> std::ffi::c_long; fn sdk_tls_free(slot: std::ffi::c_long); }
            let s = unsafe { sdk_tls_alloc() };
            println!("INFO next free slot {s}");
            unsafe { sdk_tls_free(s) };
        }
        // How the program ends. These print, then end in their own way; the expected return code is in README.md.
        "end-main-waiting" => {
            let (_tx, rx) = mpsc::channel::<u32>();
            thread::spawn(move || { let _ = rx.recv(); println!("RESULT threads unreachable FAIL"); });
            let m = Arc::new(Mutex::new(()));
            let g = m.lock().unwrap();
            let m2 = m.clone();
            thread::spawn(move || { let _x = m2.lock(); println!("RESULT threads unreachable FAIL"); });
            thread::spawn(|| loop { thread::sleep(Duration::from_millis(20)); });
            thread::sleep(Duration::from_millis(100));
            std::mem::forget(g);
            println!("RESULT threads main returns while three threads wait ok");
            return ExitCode::SUCCESS;
        }
        "end-main-busy" => {
            let started = Instant::now();
            thread::spawn(move || { let mut x = 0u64; while started.elapsed() < Duration::from_millis(1500) { x = x.wrapping_add(1); std::hint::black_box(x); } println!("RESULT threads the busy thread finished its work before the program ended ok"); });
            thread::sleep(Duration::from_millis(50));
            println!("RESULT threads main returns while a thread computes ok");
            return ExitCode::SUCCESS;
        }
        "end-thread-exit" => {
            thread::spawn(|| { thread::sleep(Duration::from_millis(100)); std::process::exit(7); });
            let started = Instant::now();
            loop { thread::sleep(Duration::from_millis(20)); if started.elapsed() > Duration::from_secs(10) { println!("RESULT threads the main task was not ended FAIL"); return ExitCode::from(1); } }
        }
        "end-thread-exit-join" => {
            let blocker = thread::spawn(|| loop { thread::park(); });
            thread::spawn(|| { thread::sleep(Duration::from_millis(100)); std::process::exit(9); });
            blocker.join().unwrap();
            println!("RESULT threads join returned FAIL");
        }
        "end-thread-panic" => {
            thread::spawn(|| { thread::sleep(Duration::from_millis(100)); panic!("a panic in a thread"); });
            let m = Mutex::new(0u32);
            let started = Instant::now();
            loop { *m.lock().unwrap() += 1; thread::sleep(Duration::from_millis(10)); if started.elapsed() > Duration::from_secs(10) { println!("RESULT threads the main task was not ended FAIL"); return ExitCode::from(1); } }
        }
        "end-main-panic" => {
            let (_tx, rx) = mpsc::channel::<u32>();
            thread::spawn(move || { let _ = rx.recv(); });
            thread::sleep(Duration::from_millis(50));
            panic!("a panic in the main thread");
        }
        _ => println!("modes: spawn mutex condvar rwlock once park channel tls errors process yield limit end-main-waiting end-main-busy end-thread-exit end-thread-exit-join end-thread-panic end-main-panic"),
    }
    println!("RESULT threads summary {} of {} checks passed", t.total - t.failed, t.total);
    if t.failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(3) }
}

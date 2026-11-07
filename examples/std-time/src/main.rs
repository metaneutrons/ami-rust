//! Time and sleep of `std` on AROS: the clock, `Instant`, `SystemTime`, `thread::sleep`, and the dates
//! beyond 2038. One behaviour per run, chosen by the first argument. The expected results are in
//! README.md.

#![feature(restricted_std)]
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[repr(C)]
struct CTimespec { tv_sec: i32, tv_nsec: i64 }
unsafe extern "C" { fn clock_gettime(clock: i32, tp: *mut CTimespec) -> i32; }

fn ms(d: Duration) -> String { format!("{}.{:03}", d.as_millis(), (d.as_micros() % 1000)) }

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    let mut ok = true;
    match mode {
        "clock" => {
            let start = Instant::now();
            let mut last = start;
            let (mut backwards, mut distinct, mut min_step) = (0u32, 0u32, Duration::MAX);
            for _ in 0..200_000 {
                let now = Instant::now();
                if now < last { backwards += 1; }
                else if now > last { distinct += 1; min_step = min_step.min(now - last); }
                last = black_box(now);
            }
            println!("RESULT clock backwards={backwards} distinct_values={distinct} smallest_step_us={} span_ms={}", min_step.as_micros(), ms(last - start));
            ok = backwards == 0;
        }
        "sleep" => {
            for (label, d) in [("0", Duration::ZERO), ("1ns", Duration::from_nanos(1)), ("1ms", Duration::from_millis(1)), ("10ms", Duration::from_millis(10)), ("100ms", Duration::from_millis(100)), ("1s", Duration::from_secs(1)), ("1.5s", Duration::from_millis(1500))] {
                let t = Instant::now();
                std::thread::sleep(d);
                let e = t.elapsed();
                let good = e >= d && e < d + Duration::from_millis(100);
                println!("RESULT sleep {label} elapsed_ms={} {}", ms(e), if good { "ok" } else { "OUT-OF-RANGE" });
                ok &= good;
            }
        }
        "system" => {
            let host: i64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let now = SystemTime::now();
            let secs = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(-1);
            println!("RESULT system secs_since_unix_epoch={secs} host={host} delta={}", secs - host);
            ok = secs > 0;
        }
        "raw" => {
            let mut tp = CTimespec { tv_sec: 0, tv_nsec: 0 };
            let r = unsafe { clock_gettime(2, &mut tp) };
            println!("RESULT raw clock_gettime={r} tv_sec(signed)={} as_unsigned={}", tp.tv_sec, tp.tv_sec as u32);
        }
        "future" => {
            let now = SystemTime::now();
            let d = now.duration_since(UNIX_EPOCH);
            println!("RESULT future {:?}", d.map(|d| d.as_secs()));
        }
        "arith" => {
            let e = UNIX_EPOCH;
            let mut check = |name: &str, c: bool| { println!("RESULT arith {name} {}", if c { "ok" } else { "FAIL" }); ok &= c; };
            check("epoch + 1s - epoch", (e + Duration::from_secs(1)).duration_since(e).ok() == Some(Duration::from_secs(1)));
            check("epoch - 1s is before the epoch", e.checked_sub(Duration::from_secs(1)).is_some_and(|t| e.duration_since(t).is_ok() && t.duration_since(e).is_err()));
            check("before-epoch distance", e.checked_sub(Duration::from_millis(1500)).unwrap().duration_since(e).unwrap_err().duration() == Duration::from_millis(1500));
            check("nanoseconds carry", (e + Duration::new(1, 999_999_999) + Duration::from_nanos(2)).duration_since(e).ok() == Some(Duration::new(2, 1)));
            check("nanoseconds borrow", (e + Duration::new(3, 1)).checked_sub(Duration::from_nanos(2)).unwrap().duration_since(e).ok() == Some(Duration::new(2, 999_999_999)));
            check("SystemTime overflow is None", SystemTime::now().checked_add(Duration::MAX).is_none());
            check("SystemTime underflow is None", e.checked_sub(Duration::MAX).is_none());
            let i = Instant::now();
            check("Instant + 1h - Instant", (i + Duration::from_secs(3600)).duration_since(i) == Duration::from_secs(3600));
            check("Instant overflow is None", i.checked_add(Duration::MAX).is_none());
            check("Instant ordering", i + Duration::from_nanos(1) > i && i.checked_duration_since(i + Duration::from_secs(1)).is_none());
            check("saturating_duration_since", i.saturating_duration_since(i + Duration::from_secs(1)) == Duration::ZERO);
        }
        _ => println!("modes: clock sleep system future arith"),
    }
    if ok { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::from(3) }
}

//! Timer cases: layout, clocks, sleeping, alarms, abort and cleanup.

use core::{mem, time::Duration};

use aros::{Context, ErrorKind, wait_signals};
use aros_sys as sys;
use aros_timer::{Finished, Instant, Timer, Unit};

use super::{expect_error, report_error, same_resources};

fn micros(duration: Duration) -> u64 {
    duration.as_micros() as u64
}

fn open(context: &Context, unit: Unit) -> Option<Timer<'_>> {
    match Timer::open_unit(context, unit) {
        Ok(timer) => Some(timer),
        Err(error) => {
            report_error(context, error);
            None
        }
    }
}

fn layout_matches(context: &Context) -> bool {
    let expected = sys::timer_layout_values();
    let mut actual = [0u64; sys::TIMER_LAYOUT_VALUE_COUNT];
    // SAFETY: exact writable capacity; C writes only scalar oracle values.
    let count = unsafe { sys::sdk_timer_layout(actual.as_mut_ptr(), actual.len()) };
    if count != actual.len() || actual != expected {
        context.diagnostic(b"qualification-timer-layout-count", count as u64);
        for (index, (a, e)) in actual.iter().zip(expected).enumerate() {
            if *a != e {
                context.diagnostic(b"qualification-timer-layout-index", index as u64);
            }
        }
        return false;
    }
    true
}

fn elapsed_during(timer: &Timer<'_>, action: impl FnOnce()) -> Option<Duration> {
    let start = timer.now().ok()?;
    action();
    Some(timer.now().ok()?.duration_since(start))
}

/// Records the E-clock frequency and the overshoot of sleeps from 1 ms to
/// 1 s on both units. Nothing is assumed in advance: each value is printed as
/// a diagnostic `label microseconds`, and only a wake-up before the requested
/// time (beyond one E-clock tick) fails.
pub fn measure(context: &Context) -> bool {
    for (unit, label) in [
        (Unit::MicroHz, &b"qualification-timer-sleep-microhz-us"[..]),
        (Unit::VBlank, &b"qualification-timer-sleep-vblank-us"[..]),
    ] {
        let Some(timer) = open(context, unit) else {
            return false;
        };
        if let Ok(now) = timer.now() {
            context.diagnostic(b"qualification-eclock-hz", u64::from(now.frequency()));
        }
        for requested_ms in [1u64, 10, 50, 200, 1000] {
            context.diagnostic(b"qualification-timer-requested-ms", requested_ms);
            for _ in 0..3 {
                let requested = Duration::from_millis(requested_ms);
                let Some(elapsed) = elapsed_during(&timer, || {
                    let _ = timer.sleep(requested);
                }) else {
                    return false;
                };
                context.diagnostic(label, micros(elapsed));
                let tick = 1_000_000 / u64::from(timer.now().map_or(1, |i| i.frequency()).max(1));
                if micros(elapsed) + tick + 1 < micros(requested) {
                    context.diagnostic(b"qualification-timer-early", micros(elapsed));
                    return false;
                }
            }
        }
    }
    true
}

pub fn cases(context: &Context) -> bool {
    let baseline = context.statistics();
    if !layout_matches(context) {
        return false;
    }
    let Some(timer) = open(context, Unit::MicroHz) else {
        return false;
    };

    // The E-clock only goes forward and has a plausible frequency.
    let (Ok(first), Ok(second)) = (timer.now(), timer.now()) else {
        return false;
    };
    if first.frequency() == 0 || second.ticks() < first.ticks() {
        return false;
    }
    if second.duration_since(first) > Duration::from_secs(1) {
        return false;
    }

    // Calendar and up time.
    let (Ok(time_a), Ok(up_a)) = (timer.system_time(), timer.uptime()) else {
        return false;
    };
    context.diagnostic(b"qualification-unix-seconds", time_a.unix_seconds() as u64);
    context.diagnostic(b"qualification-uptime-ms", up_a.as_millis() as u64);
    if time_a.micros() >= 1_000_000 || time_a.unix_seconds() < 1_700_000_000 {
        return false;
    }
    if timer.sleep(Duration::from_millis(30)).is_err() {
        return false;
    }
    let (Ok(time_b), Ok(up_b)) = (timer.system_time(), timer.uptime()) else {
        return false;
    };
    if time_b.unix_seconds() < time_a.unix_seconds() || up_b <= up_a {
        return false;
    }

    // An alarm is signalled through the reply port and then reclaimed.
    let Ok(mut alarm) = timer.start(Duration::from_millis(100)) else {
        return false;
    };
    if alarm.is_finished() != Ok(false)
        || wait_signals(context, timer.signal_mask()).is_err()
        || alarm.is_finished() != Ok(true)
        || alarm.wait() != Ok(Finished::Elapsed)
    {
        return false;
    }
    if !expect_error(context, alarm.wait(), ErrorKind::State) {
        return false;
    }
    drop(alarm);

    // Abort returns a long alarm at once.
    let Some(aborted) = elapsed_during(&timer, || {
        if let Ok(mut alarm) = timer.start(Duration::from_secs(10))
            && alarm.abort().is_ok()
        {
            let _ = alarm.wait();
        }
    }) else {
        return false;
    };
    context.diagnostic(b"qualification-timer-abort-us", micros(aborted));
    if aborted > Duration::from_secs(2) {
        return false;
    }
    match timer.start(Duration::from_secs(10)) {
        Ok(mut alarm) => {
            if alarm.abort().is_err() || alarm.wait() != Ok(Finished::Aborted) {
                return false;
            }
        }
        Err(_) => return false,
    }

    // A running alarm that is dropped leaves nothing behind.
    match timer.start(Duration::from_secs(10)) {
        Ok(alarm) => drop(alarm),
        Err(_) => return false,
    }

    // Refusals: a delay beyond 32-bit seconds.
    let too_long = Duration::from_secs(1 << 32);
    if !expect_error(context, timer.sleep(too_long), ErrorKind::Input)
        || !expect_error(context, timer.start(too_long).map(|_| ()), ErrorKind::Input)
    {
        return false;
    }
    let instant = Instant::from_ticks(first.ticks(), first.frequency());
    if instant != first {
        return false;
    }
    drop(timer);
    same_resources(baseline, context.statistics())
}

/// Leaves a timer and a running alarm to the native end-of-run cleanup.
pub fn forgotten(context: &Context) -> bool {
    let baseline = context.statistics();
    let Some(timer) = open(context, Unit::MicroHz) else {
        return false;
    };
    let Ok(alarm) = timer.start(Duration::from_secs(30)) else {
        return false;
    };
    let live = context.statistics();
    let ok = live.devices == baseline.devices + 1 && live.requests == baseline.requests + 1;
    mem::forget(alarm);
    mem::forget(timer);
    ok
}

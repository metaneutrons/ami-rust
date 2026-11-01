---
title: The aros-timer crate
description: "Time and timers on timer.device: the monotonic E-clock, calendar and up time, sleeping and signalled alarms."
---

`aros-timer` is the time layer for an active `aros::Context`. `Timer::open` owns `timer.device` and the reply port its requests share, and reads three kinds of time. It is `no_std`, allocates nothing and is the same on ABI-v1 and ABI-v11. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_timer/). It is available from the repository after release 0.1.0 and is not part of that release.

| Item | Use |
| --- | --- |
| `Timer::open(context)`, `open_unit(context, unit)` | Opens `timer.device` with the `MicroHz` (default) or `VBlank` unit. |
| `Timer::now()` → `Instant` | The monotonic E-clock; only differences are meaningful (`duration_since`). |
| `Timer::system_time()` → `SystemTime` | Calendar time in seconds since 1 January 1978, with `unix_seconds()` and `from_unix_seconds`. |
| `Timer::uptime()` → `Duration` | Time since the system started. |
| `Timer::sleep(duration)` | Blocks the task. |
| `Timer::start(duration)` → `Alarm` | Starts a delay without blocking. |
| `Timer::signal_mask()` | The signal set when an alarm finishes, for `aros::wait_signals`. |
| `Alarm::is_finished`, `wait`, `abort` | Check, reclaim (`Finished::Elapsed` or `Finished::Aborted`) or end an alarm early. |

```rust
use aros::{Context, Error};
use aros_timer::{Finished, Timer};
use core::time::Duration;

fn pause_then_alarm(context: &Context) -> Result<(), Error> {
    let timer = Timer::open(context)?;
    let start = timer.now()?;
    timer.sleep(Duration::from_millis(20))?;
    let waited = timer.now()?.duration_since(start);
    context.diagnostic(b"waited microseconds", waited.as_micros() as u64);

    // An alarm does not block; wait for its signal when it suits the program.
    let mut alarm = timer.start(Duration::from_millis(50))?;
    aros::wait_signals(context, timer.signal_mask())?;
    if alarm.wait()? == Finished::Elapsed {
        context.diagnostic(b"alarm elapsed", 1);
    }
    Ok(())
}
```

## Ownership and cleanup

An `Alarm` borrows its `Timer`, so a timer cannot be closed under a running alarm. Dropping a running alarm aborts it and waits for the device to return it, and an alarm or timer that is forgotten is aborted and closed when the program finishes, so no request stays queued. `Timer::signal_mask` can be combined with the masks of other signal sources in one `wait_signals`; after the signal, `Alarm::is_finished` tells which alarm finished and `Alarm::wait` reclaims it.

## Time

- **E-clock.** `Instant::frequency` is the clock rate the device reports; the counter is 64 bits wide. It has no relation to the calendar.
- **Calendar.** The device counts seconds from 1 January 1978. `SystemTime::unix_seconds` adds the 2,922 days (252,460,800 seconds) to the Unix epoch. The qualification guests (QEMU with the host clock) reported a calendar time within three seconds of the host's Unix time, so their clock holds UTC; on another system the clock may hold local time, and the device does not say which.
- **Range.** A delay is 32-bit seconds plus microseconds, so at most 4,294,967,295 seconds; longer delays are an `ErrorKind::Input` error. The calendar value is 32-bit seconds, which ends in 2114.

## Measured resolution

Measured in the qualification fixture (QEMU 11.1, `qemu64-v1`, single-threaded TCG, one vCPU) on the pinned ABI-v1 and ABI-v11 images. Each cell lists three sleeps of the requested time and shows how much longer the sleep took, in milliseconds, as read from the E-clock. These are observations of that profile, not guarantees: a loaded host or another machine can give other values, and no sleep returned early.

| Unit | Request | ABI-v1 overshoot | ABI-v11 overshoot |
| --- | --- | --- | --- |
| `MicroHz` | 1 ms | 0.2 to 1.7 | 0.2 to 2.0 |
| `MicroHz` | 10 ms | 1.1 to 1.2 | 1.2 to 1.3 |
| `MicroHz` | 50 ms | 0.7 to 1.1 | 0.5 to 0.6 |
| `MicroHz` | 200 ms | 1.3 to 1.4 | 0.8 to 1.5 |
| `MicroHz` | 1 s | 0.5 to 1.6 | 0.8 to 1.5 |
| `VBlank` | 1 ms | 11.0 to 19.6 | 11.6 to 19.1 |
| `VBlank` | 10 ms | 9.9 to 10.6 | 10.2 to 10.5 |
| `VBlank` | 50 ms | 11.8 to 16.3 | 11.1 to 11.7 |
| `VBlank` | 200 ms | 6.2 to 7.1 | 5.9 to 6.6 |
| `VBlank` | 1 s | 3.7 to 12.9 | 5.3 to 13.2 |

Both ABIs report an E-clock of 1,193,180 Hz. `MicroHz` sleeps finished within about 2 ms of the request; `VBlank` sleeps are rounded to the 20 ms video tick and can finish up to about 20 ms late. An alarm aborted while pending was returned in about 0.14 ms. Prefer `MicroHz` unless the coarse unit's lower cost matters.

## Layouts

The `timerequest` structure differs between the two ABIs: it carries a `struct timeval` on ABI-v1 and a `struct timeval32` on ABI-v11. It never leaves the native bridge, and the qualification fixture compares its size and offsets, and those of `EClockVal` and the time value, with the Rust declarations on each ABI (`aros_sys::timer_layout_values`).

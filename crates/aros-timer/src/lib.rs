#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Task-affine time and timers for AROS, on `timer.device`.
//!
//! [`Timer`] opens `timer.device` through [`aros::Device`] and owns it. Three
//! kinds of time are available:
//!
//! - [`Timer::now`] is the monotonic E-clock as an [`Instant`]. It counts at
//!   the E-clock frequency the device reports (see [`Instant::frequency`]), so
//!   it measures intervals but has no relation to the calendar.
//! - [`Timer::system_time`] is the calendar time as a [`SystemTime`], in
//!   seconds since 1 January 1978, the AmigaOS epoch.
//! - [`Timer::uptime`] is the time since the system started.
//!
//! [`Timer::sleep`] blocks the task for a [`Duration`]. [`Timer::start`] begins
//! an [`Alarm`] without blocking: `Timer::signal_mask` is the signal that
//! becomes set when an alarm finishes, so a program can wait for it together
//! with other signals (`aros::wait_signals`). Dropping a running alarm aborts it
//! and waits for the device to return it, so no request is ever left behind.
//!
//! The crate allocates nothing and behaves the same on ABI-v1 and ABI-v11,
//! where only the layout of `timerequest` differs; that layout stays inside the
//! native bridge.
//!
//! # Bounds
//!
//! The device takes a delay as 32-bit seconds and microseconds, so a delay is
//! at most 4,294,967,295 seconds; longer ones are refused with an
//! [`aros::ErrorKind::Input`] error. Resolution depends on the unit; see
//! [`Unit`] and the measurements in the project documentation.

use core::time::Duration;

use aros::{BytePath, Context, Device, Error, ErrorKind, Operation, Request, RequestKind};
use aros_sys::{self as sys, EClockVal, Library, TimeVal};

const TIMER_NAME: &[u8] = b"timer.device";
const TR_ADDREQUEST: u16 = 9;

/// Seconds between the AROS epoch (1 January 1978) and the Unix epoch
/// (1 January 1970): 2,922 days, which include the leap days of 1972 and 1976.
pub const AMIGA_TO_UNIX_SECONDS: i64 = 252_460_800;

/// The `timer.device` unit a [`Timer`] opens.
///
/// All units answer [`Timer::now`], [`Timer::system_time`] and
/// [`Timer::uptime`] alike; they differ in how a delay is timed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Unit {
    /// `UNIT_MICROHZ`: delays timed in microseconds.
    MicroHz = 0,
    /// `UNIT_VBLANK`: delays timed in video frame ticks (1/50 second on
    /// classic hardware), cheaper and coarser.
    VBlank = 1,
}

fn input_error(operation: Operation) -> Error {
    Error {
        kind: ErrorKind::Input,
        native: 0,
        operation,
    }
}

fn split(duration: Duration, operation: Operation) -> Result<(u32, u32), Error> {
    let seconds = u32::try_from(duration.as_secs()).map_err(|_| input_error(operation))?;
    Ok((seconds, duration.subsec_micros()))
}

/// A point on the monotonic E-clock.
///
/// Only differences between two instants of the same [`Timer`] are
/// meaningful. An instant remembers the clock frequency it was taken with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instant {
    ticks: u64,
    frequency: u32,
}

impl Instant {
    /// Builds an instant from a raw E-clock count and its frequency in hertz.
    pub const fn from_ticks(ticks: u64, frequency: u32) -> Self {
        Self { ticks, frequency }
    }

    /// Returns the raw 64-bit E-clock count.
    pub const fn ticks(self) -> u64 {
        self.ticks
    }

    /// Returns the E-clock frequency in hertz, the resolution of this clock.
    pub const fn frequency(self) -> u32 {
        self.frequency
    }

    /// Returns the time from `earlier` to `self`, or zero if `earlier` is
    /// later. Instants taken at different frequencies are compared in
    /// nanoseconds.
    pub fn duration_since(self, earlier: Instant) -> Duration {
        let delta = self.nanos().saturating_sub(earlier.nanos());
        Duration::new(
            (delta / 1_000_000_000) as u64,
            (delta % 1_000_000_000) as u32,
        )
    }

    fn nanos(self) -> u128 {
        if self.frequency == 0 {
            return 0;
        }
        u128::from(self.ticks) * 1_000_000_000 / u128::from(self.frequency)
    }
}

/// The calendar time of `timer.device`, in seconds and microseconds since
/// 1 January 1978.
///
/// The device reports whatever the system clock holds; whether that is local
/// time or UTC depends on how the system is configured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemTime {
    seconds: u32,
    micros: u32,
}

impl SystemTime {
    /// Builds a time from seconds since 1978 and microseconds.
    pub const fn new(seconds: u32, micros: u32) -> Self {
        Self { seconds, micros }
    }

    /// Returns the seconds since 1 January 1978.
    pub const fn amiga_seconds(self) -> u32 {
        self.seconds
    }

    /// Returns the microseconds within the second.
    pub const fn micros(self) -> u32 {
        self.micros
    }

    /// Returns the seconds since 1 January 1970, converting the epoch.
    pub const fn unix_seconds(self) -> i64 {
        self.seconds as i64 + AMIGA_TO_UNIX_SECONDS
    }

    /// Builds a time from seconds since 1 January 1970, or `None` if that is
    /// before 1978 or after the 32-bit range of the device.
    pub const fn from_unix_seconds(seconds: i64, micros: u32) -> Option<Self> {
        let shifted = seconds - AMIGA_TO_UNIX_SECONDS;
        if shifted < 0 || shifted > u32::MAX as i64 || micros >= 1_000_000 {
            return None;
        }
        Some(Self {
            seconds: shifted as u32,
            micros,
        })
    }
}

/// An open `timer.device`.
///
/// The handle is task-affine and borrows its [`Context`]. It uses one signal
/// bit for the device's reply port.
///
/// # Examples
///
/// ```ignore
/// # use aros_timer::Timer;
/// # use core::time::Duration;
/// let timer = Timer::open(context)?;
/// let start = timer.now()?;
/// timer.sleep(Duration::from_millis(50))?;
/// let elapsed = timer.now()?.duration_since(start);
/// context.diagnostic(b"slept microseconds", elapsed.as_micros() as u64);
/// ```
pub struct Timer<'ctx> {
    device: Device<'ctx>,
}

impl<'ctx> Timer<'ctx> {
    /// Opens `timer.device` with the [`Unit::MicroHz`] unit.
    ///
    /// # Errors
    ///
    /// Returns the [`aros::Error`] of the device open: a native error if the
    /// device cannot be opened or no signal bit is free.
    pub fn open(context: &'ctx Context) -> Result<Self, Error> {
        Self::open_unit(context, Unit::MicroHz)
    }

    /// Opens `timer.device` with the given unit.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub fn open_unit(context: &'ctx Context, unit: Unit) -> Result<Self, Error> {
        let name = BytePath::new(TIMER_NAME)?;
        Ok(Self {
            device: Device::open(context, &name, unit as u32, 0)?,
        })
    }

    fn base(&self) -> Result<*mut Library, Error> {
        // SAFETY: the pointer is the device base of this open `timer.device`,
        // used immediately by the owner task for its own library API.
        match unsafe { self.device.raw_base() } {
            Some(base) => Ok(base.cast()),
            None => Err(Error {
                kind: ErrorKind::State,
                native: 0,
                operation: Operation::DeviceOpen,
            }),
        }
    }

    /// Reads the monotonic E-clock.
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::State`] if the device is no longer valid.
    pub fn now(&self) -> Result<Instant, Error> {
        let base = self.base()?;
        let mut value = EClockVal::default();
        // SAFETY: `base` is the timer device base and `value` is writable.
        let frequency = unsafe { sys::timer::read_eclock(base, &mut value) };
        Ok(Instant {
            ticks: (u64::from(value.hi) << 32) | u64::from(value.lo),
            frequency,
        })
    }

    /// Reads the calendar time.
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::State`] if the device is no longer valid.
    pub fn system_time(&self) -> Result<SystemTime, Error> {
        let base = self.base()?;
        let mut value = TimeVal::default();
        // SAFETY: `base` is the timer device base and `value` is writable.
        unsafe { sys::timer::get_sys_time(base, &mut value) };
        Ok(SystemTime::new(value.secs, value.micros))
    }

    /// Reads the time since the system started.
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::State`] if the device is no longer valid.
    pub fn uptime(&self) -> Result<Duration, Error> {
        let base = self.base()?;
        let mut value = TimeVal::default();
        // SAFETY: `base` is the timer device base and `value` is writable.
        unsafe { sys::timer::get_up_time(base, &mut value) };
        Ok(Duration::new(u64::from(value.secs), value.micros * 1000))
    }

    /// Returns the signal mask of the device's reply port, which is set when
    /// an [`Alarm`] has finished.
    pub fn signal_mask(&self) -> u32 {
        self.device.signal_mask()
    }

    /// Blocks the task for `duration`.
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::Input`] for a delay of 2^32 seconds or more,
    /// or the error of the request.
    pub fn sleep(&self, duration: Duration) -> Result<(), Error> {
        let (seconds, micros) = split(duration, Operation::RequestTime)?;
        let mut request = Request::new(&self.device, RequestKind::Timer, 0)?;
        request.prepare(TR_ADDREQUEST, 0, 0, 0)?;
        request.set_time(seconds, micros)?;
        request.do_io()?;
        Ok(())
    }

    /// Starts an [`Alarm`] that finishes after `duration`, without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::Input`] for a delay of 2^32 seconds or more,
    /// or the error of the request.
    pub fn start(&self, duration: Duration) -> Result<Alarm<'_, 'ctx>, Error> {
        let (seconds, micros) = split(duration, Operation::RequestTime)?;
        let mut request = Request::new(&self.device, RequestKind::Timer, 0)?;
        request.prepare(TR_ADDREQUEST, 0, 0, 0)?;
        request.set_time(seconds, micros)?;
        request.send()?;
        Ok(Alarm { request })
    }
}

/// How a finished [`Alarm`] ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Finished {
    /// The delay elapsed.
    Elapsed,
    /// [`Alarm::abort`] ended it early.
    Aborted,
}

/// A running timer request started by [`Timer::start`].
///
/// An alarm finishes when its delay has elapsed or after
/// [`abort`](Self::abort). [`wait`](Self::wait) reclaims it; dropping a running
/// alarm aborts and reclaims it.
///
/// # Examples
///
/// ```ignore
/// # use aros_timer::{Finished, Timer};
/// # use core::time::Duration;
/// # use aros::wait_signals;
/// let timer = Timer::open(context)?;
/// let mut alarm = timer.start(Duration::from_millis(100))?;
/// // Other work, or a wait that also covers other signals:
/// wait_signals(context, timer.signal_mask())?;
/// assert_eq!(alarm.wait()?, Finished::Elapsed);
/// ```
pub struct Alarm<'timer, 'ctx> {
    request: Request<'timer, 'ctx>,
}

impl Alarm<'_, '_> {
    /// Returns `true` once the alarm has finished; it stays to be reclaimed by
    /// [`wait`](Self::wait).
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::State`] if the alarm was already reclaimed.
    pub fn is_finished(&self) -> Result<bool, Error> {
        self.request.check()
    }

    /// Asks the device to end the alarm early. [`wait`](Self::wait) then
    /// reports [`Finished::Aborted`].
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::State`] if the alarm was already reclaimed.
    pub fn abort(&mut self) -> Result<(), Error> {
        self.request.abort()
    }

    /// Waits for the alarm and reclaims it.
    ///
    /// # Errors
    ///
    /// Returns [`aros::ErrorKind::State`] if the alarm was already reclaimed.
    pub fn wait(&mut self) -> Result<Finished, Error> {
        let outcome = self.request.wait()?;
        Ok(if outcome.is_ok() {
            Finished::Elapsed
        } else {
            Finished::Aborted
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn instants_convert_ticks_with_the_frequency() {
        let rate = 709_379; // the PAL E-clock of classic hardware
        let a = Instant::from_ticks(1_000, rate);
        let b = Instant::from_ticks(1_000 + u64::from(rate), rate);
        assert_eq!(b.duration_since(a), Duration::from_secs(1));
        assert_eq!(a.duration_since(b), Duration::ZERO);
        let c = Instant::from_ticks(u64::MAX, rate);
        assert!(c.duration_since(a) > Duration::from_secs(1 << 40));
        assert_eq!(Instant::from_ticks(5, 0).duration_since(a), Duration::ZERO);
    }

    #[test]
    fn epoch_conversion() {
        assert_eq!(AMIGA_TO_UNIX_SECONDS, 2_922 * 86_400);
        // 1978-01-01 00:00:00 and a date in 2026.
        assert_eq!(SystemTime::new(0, 0).unix_seconds(), 252_460_800);
        let time = SystemTime::from_unix_seconds(1_793_000_000, 7).unwrap();
        assert_eq!(time.amiga_seconds(), 1_793_000_000 - 252_460_800);
        assert_eq!(time.unix_seconds(), 1_793_000_000);
        assert_eq!(time.micros(), 7);
        assert!(SystemTime::from_unix_seconds(252_460_799, 0).is_none());
        assert!(SystemTime::from_unix_seconds(1_793_000_000, 1_000_000).is_none());
        assert!(SystemTime::from_unix_seconds(252_460_800 + i64::from(u32::MAX) + 1, 0).is_none());
    }

    #[test]
    fn delays_are_split_and_bounded() {
        let (s, u) = split(Duration::new(3, 1_500_000), Operation::RequestTime).unwrap();
        assert_eq!((s, u), (3, 1500));
        assert!(split(Duration::from_secs(1 << 32), Operation::RequestTime).is_err());
        assert!(
            split(
                Duration::from_secs(u64::from(u32::MAX)),
                Operation::RequestTime
            )
            .is_ok()
        );
    }
}

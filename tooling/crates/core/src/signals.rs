//! Cooperative, process-scoped SIGTERM handling for installer operations.
//!
//! The handler records a request only. Callers must check it at transaction
//! boundaries and choose the safe-point behavior themselves. The handler is
//! process-wide; `with_blocked` masks SIGTERM only on the calling thread, so
//! another unblocked thread may still run the handler during its callback.

use std::{
    io,
    mem::MaybeUninit,
    sync::{
        Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{Refusal, Result};

static INSTALLER_LOCK: Mutex<()> = Mutex::new(());
static SIGTERM_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn record_sigterm(_: libc::c_int) {
    SIGTERM_REQUESTED.store(true, Ordering::Release);
}

/// Owns the temporary process SIGTERM action for one installer operation.
///
/// The contained mutex guard keeps this value on the acquiring thread and
/// serializes installers in this process. SIGTERM itself is process-wide and
/// may be delivered to any thread that has not blocked it.
pub struct SigtermGuard {
    _installer_lock: MutexGuard<'static, ()>,
    previous_action: libc::sigaction,
    installed: bool,
}

impl SigtermGuard {
    /// Install the cooperative SIGTERM handler, refusing overlapping guards.
    pub fn acquire() -> Result<Self> {
        let installer_lock = match INSTALLER_LOCK.try_lock() {
            Ok(lock) => lock,
            Err(TryLockError::WouldBlock) => {
                return Err(Refusal::new(
                    "another installer operation already owns the SIGTERM guard",
                ));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(Refusal::new("SIGTERM installer guard lock is poisoned"));
            }
        };

        SIGTERM_REQUESTED.store(false, Ordering::Release);
        let previous_action =
            install_sigterm_action(record_sigterm as *const () as libc::sighandler_t)?;
        Ok(Self {
            _installer_lock: installer_lock,
            previous_action,
            installed: true,
        })
    }

    /// Whether SIGTERM has been observed since this guard was acquired.
    pub fn requested(&self) -> bool {
        SIGTERM_REQUESTED.load(Ordering::Acquire)
    }

    /// Refuse continued work after the handler has observed SIGTERM.
    pub fn check(&self) -> Result<()> {
        if self.requested() {
            Err(Refusal::new(
                "SIGTERM requested; installer must stop safely",
            ))
        } else {
            Ok(())
        }
    }

    /// Block SIGTERM on this thread while `callback` runs, then restore its
    /// previous signal mask before returning the callback result.
    ///
    /// A pending SIGTERM may run the handler as the old mask is restored. If
    /// the callback panics, the mask guard still attempts restoration during
    /// unwinding. Other unblocked threads in the process are not masked.
    pub fn with_blocked<T>(&self, callback: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut mask = ThreadSignalMask::block_sigterm()?;
        let result = callback();
        mask.restore()?;
        result
    }

    /// Restore the previous process handler and report restoration errors.
    ///
    /// Drop retries restoration if this explicit attempt fails.
    pub fn finish(mut self) -> Result<()> {
        restore_sigterm_action(&self.previous_action)?;
        self.installed = false;
        Ok(())
    }

    /// Restore the previous handler before sampling the request flag. This
    /// lets a command classify requests received through its complete guarded
    /// operation, including result serialization, without a check/restore gap.
    /// Callers must finish their supervised child cleanup before calling this.
    pub fn finish_requested(mut self) -> Result<bool> {
        restore_sigterm_action(&self.previous_action)?;
        self.installed = false;
        Ok(self.requested())
    }
}

impl Drop for SigtermGuard {
    fn drop(&mut self) {
        if self.installed {
            // The explicit finish path reports errors; Drop is only a fallback.
            let _ = restore_sigterm_action(&self.previous_action);
            self.installed = false;
        }
    }
}

struct ThreadSignalMask {
    previous: libc::sigset_t,
    active: bool,
}

impl ThreadSignalMask {
    fn block_sigterm() -> Result<Self> {
        let set = sigterm_set()?;
        let previous = set_thread_signal_mask(libc::SIG_BLOCK, &set)?;
        Ok(Self {
            previous,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<()> {
        if self.active {
            restore_thread_signal_mask(&self.previous)?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for ThreadSignalMask {
    fn drop(&mut self) {
        if self.active {
            // This also runs when a callback unwinds. Explicit restoration
            // reports errors; the Drop path makes a best-effort second attempt.
            let _ = restore_thread_signal_mask(&self.previous);
            self.active = false;
        }
    }
}

#[allow(
    unsafe_code,
    reason = "POSIX sigaction requires initializing and passing libc signal structures."
)]
fn install_sigterm_action(handler: libc::sighandler_t) -> Result<libc::sigaction> {
    // SAFETY: zero is a valid starting representation for sigaction; its mask
    // is initialized with sigemptyset before the structure is passed to libc.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: action.sa_mask points to an initialized writable sigset_t.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(Refusal::new(format!(
            "cannot initialize SIGTERM action mask: {}",
            io::Error::last_os_error()
        )));
    }

    let mut previous = MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: both pointers are valid for the duration of the call; on success
    // libc initializes the previous-action output structure.
    let status = unsafe { libc::sigaction(libc::SIGTERM, &action, previous.as_mut_ptr()) };
    if status != 0 {
        return Err(Refusal::new(format!(
            "cannot install SIGTERM handler: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: sigaction initialized `previous` when it returned success.
    Ok(unsafe { previous.assume_init() })
}

#[allow(
    unsafe_code,
    reason = "Restoring the prior POSIX SIGTERM action requires sigaction."
)]
fn restore_sigterm_action(previous: &libc::sigaction) -> Result<()> {
    // SAFETY: `previous` points to a sigaction value captured from a successful
    // earlier sigaction call; the null old-action pointer is permitted.
    let status = unsafe { libc::sigaction(libc::SIGTERM, previous, std::ptr::null_mut()) };
    if status != 0 {
        return Err(Refusal::new(format!(
            "cannot restore previous SIGTERM handler: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "POSIX pthread signal-mask APIs require libc sigset_t pointers."
)]
fn sigterm_set() -> Result<libc::sigset_t> {
    // SAFETY: sigemptyset initializes the entire sigset_t before it is used.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable and points to a valid sigset_t.
    if unsafe { libc::sigemptyset(&mut set) } != 0 {
        return Err(Refusal::new(format!(
            "cannot initialize SIGTERM mask: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: `set` has been initialized and remains writable.
    if unsafe { libc::sigaddset(&mut set, libc::SIGTERM) } != 0 {
        return Err(Refusal::new(format!(
            "cannot add SIGTERM to thread mask: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(set)
}

#[allow(
    unsafe_code,
    reason = "POSIX pthread_sigmask accepts and fills raw sigset_t pointers."
)]
fn set_thread_signal_mask(how: libc::c_int, set: &libc::sigset_t) -> Result<libc::sigset_t> {
    let mut previous = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: both sigset pointers are valid; pthread_sigmask initializes the
    // old-mask output on success and returns an error number directly.
    let status = unsafe { libc::pthread_sigmask(how, set, previous.as_mut_ptr()) };
    if status != 0 {
        return Err(pthread_mask_error(
            "cannot change calling-thread SIGTERM mask",
            status,
        ));
    }
    // SAFETY: pthread_sigmask initialized `previous` when it returned success.
    Ok(unsafe { previous.assume_init() })
}

#[allow(
    unsafe_code,
    reason = "Restoring a POSIX pthread signal mask requires pthread_sigmask."
)]
fn restore_thread_signal_mask(previous: &libc::sigset_t) -> Result<()> {
    // SAFETY: `previous` is a mask returned by a successful pthread_sigmask;
    // POSIX permits a null old-mask output pointer.
    let status =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, previous, std::ptr::null_mut()) };
    if status != 0 {
        return Err(pthread_mask_error(
            "cannot restore calling-thread signal mask",
            status,
        ));
    }
    Ok(())
}

fn pthread_mask_error(operation: &str, status: libc::c_int) -> Refusal {
    Refusal::new(format!(
        "{operation}: {}",
        io::Error::from_raw_os_error(status)
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        process::Command,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::{Duration, Instant},
    };

    use super::{
        SIGTERM_REQUESTED, SigtermGuard, install_sigterm_action, restore_sigterm_action,
        set_thread_signal_mask, sigterm_set,
    };
    use crate::{Refusal, Result};

    const CHILD_MODE: &str = "AMI_RUST_CORE_SIGTERM_CHILD";
    static PRIOR_HANDLER_CALLED: AtomicBool = AtomicBool::new(false);

    extern "C" fn prior_handler(_: libc::c_int) {
        PRIOR_HANDLER_CALLED.store(true, Ordering::Release);
    }

    #[test]
    fn sigterm_lifecycle_and_thread_mask_are_isolated_in_a_child_process() {
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("signals::tests::sigterm_child_fixture")
            .arg("--ignored")
            .arg("--nocapture")
            .env(CHILD_MODE, "run")
            .output()
            .expect("spawn isolated SIGTERM fixture");
        assert!(
            output.status.success(),
            "isolated SIGTERM fixture failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run only through the isolated child-process test"]
    fn sigterm_child_fixture() {
        assert_eq!(std::env::var(CHILD_MODE).as_deref(), Ok("run"));
        let original_mask = set_thread_signal_mask(libc::SIG_UNBLOCK, &sigterm_set().unwrap())
            .expect("unblock SIGTERM for the child fixture");
        let original_action =
            install_sigterm_action(prior_handler as *const () as libc::sighandler_t)
                .expect("install fixture handler");
        PRIOR_HANDLER_CALLED.store(false, Ordering::Relaxed);

        let guard = SigtermGuard::acquire().expect("acquire SIGTERM guard");
        assert!(!guard.requested());
        assert!(
            SigtermGuard::acquire().is_err(),
            "overlapping guard accepted"
        );

        let success = guard
            .with_blocked(|| {
                assert!(!guard.requested(), "blocked signal ran during callback");
                send_sigterm_to_current_thread()?;
                assert!(!guard.requested(), "pending signal ran before unblocking");
                Ok(17)
            })
            .expect("restore the original mask and preserve callback result");
        assert_eq!(success, 17);
        wait_for(
            &SIGTERM_REQUESTED,
            "pending SIGTERM was not delivered after unblocking",
        );
        assert!(guard.check().is_err());

        SIGTERM_REQUESTED.store(false, Ordering::Relaxed);
        let callback_error = guard
            .with_blocked(|| -> Result<()> {
                send_sigterm_to_current_thread()?;
                assert!(!guard.requested());
                Err(Refusal::new("callback result preserved"))
            })
            .expect_err("callback refusal should be returned after mask restoration");
        assert_eq!(callback_error.to_string(), "callback result preserved");
        wait_for(
            &SIGTERM_REQUESTED,
            "SIGTERM was not delivered after error return",
        );

        SIGTERM_REQUESTED.store(false, Ordering::Relaxed);
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let result: Result<()> = guard.with_blocked(|| {
                send_sigterm_to_current_thread()?;
                assert!(!guard.requested());
                panic!("exercise signal-mask Drop restoration");
            });
            result
        }));
        assert!(panic_result.is_err(), "fixture panic was not caught");
        wait_for(
            &SIGTERM_REQUESTED,
            "SIGTERM was not delivered while unwinding",
        );

        guard.finish().expect("restore prior signal action");
        assert!(
            !PRIOR_HANDLER_CALLED.load(Ordering::Acquire),
            "prior handler ran before guard restoration"
        );

        let fresh_guard = SigtermGuard::acquire().expect("acquire a fresh SIGTERM scope");
        assert!(
            !fresh_guard.requested(),
            "fresh guard did not reset request state"
        );
        send_sigterm_to_current_thread().expect("send unblocked SIGTERM");
        wait_for(&SIGTERM_REQUESTED, "unblocked SIGTERM was not observed");
        assert!(
            !PRIOR_HANDLER_CALLED.load(Ordering::Acquire),
            "prior handler ran while guard was installed"
        );
        fresh_guard.finish().expect("restore fixture handler");

        PRIOR_HANDLER_CALLED.store(false, Ordering::Relaxed);
        send_sigterm_to_current_thread().expect("send SIGTERM after action restoration");
        wait_for(
            &PRIOR_HANDLER_CALLED,
            "previous SIGTERM handler was not restored",
        );

        restore_sigterm_action(&original_action).expect("restore child process's original action");
        super::restore_thread_signal_mask(&original_mask)
            .expect("restore child process's original signal mask");
    }

    fn wait_for(flag: &AtomicBool, message: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !flag.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "{message}");
            thread::yield_now();
        }
    }

    #[allow(
        unsafe_code,
        reason = "The fixture sends SIGTERM to its own current thread."
    )]
    fn send_sigterm_to_current_thread() -> Result<()> {
        // SAFETY: pthread_self returns the caller's valid thread identifier.
        let current = unsafe { libc::pthread_self() };
        // SAFETY: current is the live caller thread and SIGTERM is a valid signal.
        let status = unsafe { libc::pthread_kill(current, libc::SIGTERM) };
        if status != 0 {
            return Err(Refusal::new(format!(
                "cannot send fixture SIGTERM: {}",
                std::io::Error::from_raw_os_error(status)
            )));
        }
        Ok(())
    }
}

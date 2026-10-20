//! Wait-ownership lease for a command started as a new POSIX process group.
//!
//! The direct child is the reservation for its root process-group ID. Callers
//! must set the child's process group to its own PID before starting it, call
//! [`ensure_waitable_sigchld`] before spawning, and keep this lease as the sole
//! reaping owner. Do not run a competing waiter. Every signal authorization
//! rechecks the unreaped child with `waitid(WNOWAIT)`; loss of wait ownership
//! disables all later signalling. This protects only the direct child and its
//! original process group, not descendants that move to another group/session.
//! Kernel waits and `Drop` cleanup are not hard-deadline operations.

#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    io,
    process::{Child, ChildStderr, ChildStdout, ExitStatus},
    thread,
    time::Duration,
};

/// Confirm that child statuses remain waitable before a lease is created.
///
/// Call this before spawning the child. The caller must also ensure that no
/// other thread or handler reaps children owned by this operation.
pub(crate) fn ensure_waitable_sigchld() -> io::Result<()> {
    posix::ensure_waitable_sigchld()
}

/// Owns one direct child and the process group whose ID equals that child's
/// PID. Group IDs are derived from the leased child and are never caller input.
pub(crate) struct ChildLease {
    child: Child,
    pid: u32,
    root_group: libc::pid_t,
    grace: Duration,
    status: Option<ExitStatus>,
    reaping_lost: bool,
}

impl ChildLease {
    /// Create a lease for a child already started as a new process-group leader.
    ///
    /// The command must have used `process_group(0)` (or the equivalent) before
    /// spawn. If the returned child ID cannot be represented as a positive
    /// `pid_t`, this method kills and waits for only that owned child, then
    /// returns the validation error with any cleanup failure included.
    pub(crate) fn new(mut child: Child, grace: Duration) -> io::Result<Self> {
        let pid = child.id();
        let Ok(root_group) = libc::pid_t::try_from(pid) else {
            return Err(invalid_child_id(&mut child, pid));
        };
        if root_group <= 0 {
            return Err(invalid_child_id(&mut child, pid));
        }
        Ok(Self {
            child,
            pid,
            root_group,
            grace,
            status: None,
            reaping_lost: false,
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn status(&self) -> Option<ExitStatus> {
        self.status
    }

    pub(crate) fn reaping_lost(&self) -> bool {
        self.reaping_lost
    }

    pub(crate) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    pub(crate) fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// Observe exit without reaping, keeping the PID reserved for group cleanup.
    pub(crate) fn observe_exit(&mut self) -> io::Result<bool> {
        if self.reaping_lost {
            return Err(ownership_lost());
        }
        if self.status.is_some() {
            return Ok(true);
        }
        match posix::child_exited(self.root_group) {
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                self.reaping_lost = true;
                Err(error)
            }
            result => result,
        }
    }

    /// Signal only the original child process group while the child remains
    /// wait-owned and unreaped. ESRCH means the group is empty and is accepted.
    pub(crate) fn signal_root_group(&mut self, signal: libc::c_int) -> io::Result<()> {
        self.signal_root_group_with(signal, posix::signal_group)
    }

    fn signal_root_group_with(
        &mut self,
        signal: libc::c_int,
        mut send: impl FnMut(libc::pid_t, libc::c_int) -> io::Result<()>,
    ) -> io::Result<()> {
        self.signal_root_group_with_classifier(signal, &mut send, posix::owned_zombie_only_group)
    }

    fn signal_root_group_with_classifier(
        &mut self,
        signal: libc::c_int,
        mut send: impl FnMut(libc::pid_t, libc::c_int) -> io::Result<()>,
        is_owned_zombie_only_group: impl Fn(libc::pid_t) -> bool,
    ) -> io::Result<()> {
        // A true result still leaves the direct child unreaped, reserving its
        // PID/PGID while same-group descendants may need cleanup.
        let _ = self.observe_exit()?;
        if self.status.is_some() || self.reaping_lost {
            return Err(ownership_lost());
        }
        match send(self.root_group, signal) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                #[cfg(target_os = "macos")]
                {
                    // EPERM is suppressible only for the narrow Darwin case
                    // where WNOWAIT still owns this exited direct child and a
                    // complete process-group query finds exactly that zombie.
                    // Check once before classification and again afterwards;
                    // neither snapshot is ever used as signal authority.
                    let exited = self.observe_exit()?;
                    if self.status.is_some() || self.reaping_lost || !exited {
                        return Err(error);
                    }
                    let confirmed_group = is_owned_zombie_only_group(self.root_group);
                    let still_wait_owned_and_exited = self.observe_exit()?;
                    if self.status.is_some() || self.reaping_lost {
                        return Err(ownership_lost());
                    }
                    if confirmed_group && still_wait_owned_and_exited {
                        Ok(())
                    } else {
                        Err(error)
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = is_owned_zombie_only_group;
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Kill the direct child only when WNOWAIT confirms it has not exited.
    pub(crate) fn kill_direct_child(&mut self) -> io::Result<()> {
        self.kill_direct_child_with(|child| child.kill())
    }

    fn kill_direct_child_with(
        &mut self,
        kill: impl FnOnce(&mut Child) -> io::Result<()>,
    ) -> io::Result<()> {
        let exited = self.observe_exit()?;
        if self.status.is_some() || self.reaping_lost {
            return Err(ownership_lost());
        }
        if exited {
            return Ok(());
        }
        kill(&mut self.child)
    }

    /// Reap and cache the actual direct-child wait status.
    pub(crate) fn reap(&mut self) -> io::Result<()> {
        if self.reaping_lost {
            return Err(ownership_lost());
        }
        if self.status.is_none() {
            match self.child.wait() {
                Ok(status) => self.status = Some(status),
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    self.reaping_lost = true;
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl Drop for ChildLease {
    fn drop(&mut self) {
        if self.status.is_some() || self.reaping_lost || self.observe_exit().is_err() {
            return;
        }

        let _ = self.signal_root_group(libc::SIGTERM);
        thread::sleep(self.grace);

        // Every signal rechecks wait ownership. An observation error stops
        // cleanup; an ECHILD observation permanently records lost ownership.
        if self.status.is_some() || self.reaping_lost || self.observe_exit().is_err() {
            return;
        }
        let _ = self.signal_root_group(libc::SIGKILL);
        if self.status.is_some() || self.reaping_lost {
            return;
        }
        // A failed signal authorization must not lead to a blocking wait for
        // a possibly still-running child. Drop cannot report cleanup errors;
        // leave the failed observation/signal to the explicit caller instead.
        if self.kill_direct_child().is_err() {
            return;
        }
        let _ = self.reap();
    }
}

fn ownership_lost() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "child wait ownership is unavailable; refusing to signal a possibly reused PID or process group",
    )
}

fn invalid_child_id(child: &mut Child, pid: u32) -> io::Error {
    let kill = child.kill();
    let wait = child.wait();
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "spawned child PID {pid} is not a positive representable pid_t; owned-child cleanup: kill={kill:?}, wait={wait:?}"
        ),
    )
}

mod posix {
    use std::{io, mem::MaybeUninit, ptr};

    #[cfg(target_os = "macos")]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct OwnedZombieGroupObservation {
        pub(super) group: libc::pid_t,
        pub(super) effective_uid: u32,
        pub(super) complete: libc::c_int,
        pub(super) record_count: u32,
        pub(super) member_pid: libc::pid_t,
        pub(super) member_group: libc::pid_t,
        pub(super) member_uid: u32,
        pub(super) member_status: libc::c_int,
    }

    #[cfg(target_os = "macos")]
    const _: [(); 32] = [(); std::mem::size_of::<OwnedZombieGroupObservation>()];

    #[cfg(target_os = "macos")]
    #[allow(
        unsafe_code,
        reason = "The C helper performs one bounded, fail-closed Darwin process-group query."
    )]
    unsafe extern "C" {
        fn ami_rust_process_group_is_owned_zombie_only(group: libc::pid_t) -> libc::c_int;

        #[cfg(test)]
        fn ami_rust_classify_owned_zombie_group_observation(
            observation: *const OwnedZombieGroupObservation,
        ) -> libc::c_int;
    }

    #[cfg(target_os = "macos")]
    #[allow(
        unsafe_code,
        reason = "The C helper returns affirmative only for the exact owned-zombie group case."
    )]
    pub(super) fn owned_zombie_only_group(group: libc::pid_t) -> bool {
        if group <= 0 {
            return false;
        }
        // SAFETY: the helper accepts only a positive group ID and performs a
        // bounded read-only KERN_PROC_PGRP query with no borrowed pointers.
        unsafe { ami_rust_process_group_is_owned_zombie_only(group) == 1 }
    }

    #[cfg(not(target_os = "macos"))]
    pub(super) fn owned_zombie_only_group(_group: libc::pid_t) -> bool {
        false
    }

    #[cfg(all(test, target_os = "macos"))]
    #[allow(
        unsafe_code,
        reason = "The test calls the same C record classifier used by the Darwin query helper."
    )]
    pub(super) fn classify_owned_zombie_group_record_for_test(
        observation: OwnedZombieGroupObservation,
    ) -> bool {
        // SAFETY: this pure classifier receives a valid pointer to the
        // fixed-layout scalar test record for the duration of the call.
        unsafe { ami_rust_classify_owned_zombie_group_observation(&observation) == 1 }
    }

    #[allow(unsafe_code, reason = "POSIX sigaction requires libc structures.")]
    pub(super) fn ensure_waitable_sigchld() -> io::Result<()> {
        let mut action = MaybeUninit::<libc::sigaction>::uninit();
        // SAFETY: a null new-action pointer queries the current process
        // disposition; the output pointer is valid for sigaction.
        if unsafe { libc::sigaction(libc::SIGCHLD, ptr::null(), action.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful sigaction initializes the queried action.
        let action = unsafe { action.assume_init() };
        if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SIGCHLD disposition does not preserve waitable child status",
            ));
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "POSIX process-group signalling requires kill(2)."
    )]
    pub(super) fn signal_group(group: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
        // SAFETY: getpgrp has no pointer arguments or side effects.
        let caller_group = unsafe { libc::getpgrp() };
        if group <= 0 || group == caller_group {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "leased process-group ID must be positive and different from the caller group",
            ));
        }
        // SAFETY: the group is a positive ID derived from the unreaped direct
        // child; a negative value targets only that process group.
        if unsafe { libc::kill(-group, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    #[allow(unsafe_code, reason = "POSIX WNOWAIT observation requires waitid(2).")]
    pub(super) fn child_exited(pid: libc::pid_t) -> io::Result<bool> {
        bounded_wait_observation(|| {
            let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: waitid writes siginfo on success. WNOWAIT observes the
            // exit without reaping and preserves the child's PID reservation.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful waitid initializes siginfo_t, including when
            // WNOHANG reports no state change (si_pid is then zero).
            let info = unsafe { info.assume_init() };
            // SAFETY: si_pid is defined for the SIGCHLD information returned
            // by a P_PID waitid request.
            Ok(unsafe { info.si_pid() } != 0)
        })
    }

    /// A signal storm must not trap the caller in a userspace retry loop.
    /// Exhaustion is an observation error, never authorization to signal.
    pub(super) fn bounded_wait_observation(
        mut observe: impl FnMut() -> io::Result<bool>,
    ) -> io::Result<bool> {
        const MAX_ATTEMPTS: usize = 8;
        for attempt in 0..MAX_ATTEMPTS {
            match observe() {
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted && attempt + 1 < MAX_ATTEMPTS => {
                }
                result => return result,
            }
        }
        unreachable!("the final observation returns its result")
    }

    #[cfg(test)]
    #[allow(
        unsafe_code,
        reason = "The ECHILD fixture directly reaps only its own test child."
    )]
    pub(super) fn reap_direct_child(pid: libc::pid_t) -> io::Result<i32> {
        loop {
            let mut status = 0;
            // SAFETY: tests call this only for a direct child spawned by the
            // current test process; it intentionally simulates competing reap.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == pid {
                return Ok(status);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        fs::OpenOptions,
        io::Write,
        os::unix::process::{CommandExt, ExitStatusExt},
        path::PathBuf,
        process::{Command, Stdio},
        time::Instant,
    };

    #[cfg(target_os = "macos")]
    use std::{os::fd::AsRawFd, path::Path, process::ChildStdin};

    const FIXTURE_NAME: &str = "process_lease::tests::child_fixture_entry";
    const FIXTURE_TOKEN: &str = "ami-rust-core-process-lease-v1";
    const FIXTURE_READY_PATH_ENV: &str = "AMI_PROCESS_LEASE_FIXTURE_READY_PATH";

    fn spawn_fixture(mode: &str) -> Child {
        let mut command = Command::new(std::env::current_exe().expect("test executable path"));
        command
            .args(["--exact", FIXTURE_NAME, "--nocapture", "--test-threads=1"])
            .env("AMI_PROCESS_LEASE_FIXTURE_TOKEN", FIXTURE_TOKEN)
            .env("AMI_PROCESS_LEASE_FIXTURE_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        command
            .spawn()
            .expect("spawn isolated process-lease fixture")
    }

    #[cfg(target_os = "macos")]
    fn spawn_fixture_with_live_same_group_descendant(ready_path: &Path) -> Child {
        let mut command = Command::new(std::env::current_exe().expect("test executable path"));
        command
            .args(["--exact", FIXTURE_NAME, "--nocapture", "--test-threads=1"])
            .env("AMI_PROCESS_LEASE_FIXTURE_TOKEN", FIXTURE_TOKEN)
            .env(
                "AMI_PROCESS_LEASE_FIXTURE_MODE",
                "root-exits-after-descendant-ready",
            )
            .env(FIXTURE_READY_PATH_ENV, ready_path.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        command
            .spawn()
            .expect("spawn root fixture with an inherited-stdin probe")
    }

    #[cfg(target_os = "macos")]
    fn wait_for_fixture_stdin_pipe_close(
        probe: &mut ChildStdin,
        deadline: Instant,
    ) -> Option<Instant> {
        while Instant::now() < deadline {
            if let Err(error) = probe.write(b"x")
                && error.kind() == io::ErrorKind::BrokenPipe
            {
                return Some(Instant::now());
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
    }

    #[test]
    fn child_fixture_entry() {
        if std::env::var("AMI_PROCESS_LEASE_FIXTURE_TOKEN")
            .ok()
            .as_deref()
            != Some(FIXTURE_TOKEN)
        {
            return;
        }
        match std::env::var("AMI_PROCESS_LEASE_FIXTURE_MODE").as_deref() {
            Ok("hold") => loop {
                thread::sleep(Duration::from_secs(30));
            },
            Ok("exit") => {}
            Ok("root-exits-after-descendant-ready") => {
                let ready_path = std::env::var_os(FIXTURE_READY_PATH_ENV)
                    .map(PathBuf::from)
                    .expect("same-group descendant readiness path");
                let mut command =
                    Command::new(std::env::current_exe().expect("test executable path"));
                command
                    .args(["--exact", FIXTURE_NAME, "--nocapture", "--test-threads=1"])
                    .env("AMI_PROCESS_LEASE_FIXTURE_TOKEN", FIXTURE_TOKEN)
                    .env(
                        "AMI_PROCESS_LEASE_FIXTURE_MODE",
                        "live-same-group-descendant",
                    )
                    .env(FIXTURE_READY_PATH_ENV, ready_path.as_os_str())
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                // Do not set a process group: the descendant must inherit this
                // owned root's PGID so the native query observes a live member.
                let mut descendant = command
                    .spawn()
                    .expect("spawn same-group descendant fixture");
                let deadline = Instant::now() + Duration::from_secs(5);
                while !ready_path.exists() {
                    if let Some(status) = descendant
                        .try_wait()
                        .expect("observe the fixture descendant")
                    {
                        panic!("descendant exited before readiness: {status}");
                    }
                    assert!(
                        Instant::now() < deadline,
                        "same-group descendant did not signal readiness"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                // Child::drop does not kill or wait; this fixture exits while
                // leaving the ready same-group descendant running.
                drop(descendant);
            }
            Ok("live-same-group-descendant") => {
                let ready_path = std::env::var_os(FIXTURE_READY_PATH_ENV)
                    .map(PathBuf::from)
                    .expect("same-group descendant readiness path");
                let mut ready = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(ready_path)
                    .expect("create descendant readiness marker");
                ready
                    .write_all(b"ready")
                    .expect("write descendant readiness marker");
                // Keep this live well beyond the root-wait and initial
                // cleanup windows, but guarantee bounded test teardown if
                // group signalling fails.
                thread::sleep(Duration::from_secs(30));
            }
            other => panic!("unknown process-lease fixture mode: {other:?}"),
        }
    }

    #[test]
    fn interrupted_observation_is_bounded_without_inventing_wait_ownership() {
        let mut attempts = 0;
        let error = posix::bounded_wait_observation(|| {
            attempts += 1;
            Err(io::Error::from_raw_os_error(libc::EINTR))
        })
        .expect_err("an interrupted observation is not an ownership check");
        assert_eq!(error.raw_os_error(), Some(libc::EINTR));
        assert_eq!(attempts, 8, "a signal storm must return to the caller");

        for exited in [false, true] {
            let mut attempts = 0;
            let observed = posix::bounded_wait_observation(|| {
                attempts += 1;
                if attempts < 3 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok(exited)
                }
            })
            .expect("a successful later syscall retains its actual observation");
            assert_eq!(observed, exited);
            assert_eq!(attempts, 3);
        }

        let mut attempts = 0;
        let error = posix::bounded_wait_observation(|| {
            attempts += 1;
            Err(io::Error::from_raw_os_error(libc::ECHILD))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        assert_eq!(attempts, 1, "ownership loss is never retried");
    }

    #[test]
    fn observes_signals_and_reaps_the_owned_direct_child() {
        ensure_waitable_sigchld().expect("test process must retain waitable child status");
        let child = spawn_fixture("hold");
        let mut lease = ChildLease::new(child, Duration::from_millis(20)).unwrap();
        let pid = lease.pid();
        assert!(pid > 0);
        assert_eq!(lease.status(), None);
        assert!(!lease.reaping_lost());
        assert!(!lease.observe_exit().unwrap());

        lease
            .signal_root_group(libc::SIGTERM)
            .expect("signal only the leased root group");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !lease.observe_exit().expect("wait ownership remains held") {
            assert!(
                Instant::now() < deadline,
                "fixture did not exit after SIGTERM"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(lease.status(), None, "WNOWAIT must not reap the child");
        lease.reap().expect("reap direct child after group cleanup");
        assert_eq!(
            lease.status().and_then(|status| status.signal()),
            Some(libc::SIGTERM)
        );
        assert!(!lease.reaping_lost());

        let mut backend_called = false;
        assert!(
            lease
                .signal_root_group_with(libc::SIGTERM, |_, _| {
                    backend_called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!backend_called, "a reaped root group must not be signalled");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_zombie_only_group_eperm_is_accepted_for_the_wait_owned_child() {
        ensure_waitable_sigchld().expect("test process must retain waitable child status");
        let child = spawn_fixture("exit");
        let group = child.id() as libc::pid_t;
        let mut lease = ChildLease::new(child, Duration::from_millis(20)).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !lease.observe_exit().expect("child remains wait-owned") {
            assert!(Instant::now() < deadline, "exit fixture did not finish");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(lease.status(), None, "WNOWAIT must retain the zombie");

        let raw_error = posix::signal_group(group, libc::SIGTERM)
            .expect_err("Darwin must report the zombie-only group as EPERM");
        assert_eq!(raw_error.raw_os_error(), Some(libc::EPERM));

        lease
            .signal_root_group(libc::SIGTERM)
            .expect("only the complete owned-zombie group result is empty");
        assert!(lease.observe_exit().expect("final WNOWAIT check"));
        assert_eq!(
            lease.status(),
            None,
            "normalization must not reap the child"
        );
        lease
            .reap()
            .expect("reap the direct child after group cleanup");
        assert!(!lease.reaping_lost());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[allow(
        unsafe_code,
        reason = "The fixture makes its private pipe writer nonblocking so cleanup polling cannot hang."
    )]
    fn darwin_live_same_group_descendant_keeps_eperm_as_a_refusal() {
        ensure_waitable_sigchld().expect("test process must retain waitable child status");
        let fixture_started_at = Instant::now();
        let failsafe_not_before = fixture_started_at + Duration::from_secs(30);
        let failsafe_deadline = fixture_started_at + Duration::from_secs(40);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is after the epoch")
            .as_nanos();
        let ready_path = std::env::temp_dir().join(format!(
            "ami-rust-process-lease-ready-{}-{nonce}.tmp",
            std::process::id()
        ));
        let mut child = spawn_fixture_with_live_same_group_descendant(&ready_path);
        let group = child.id() as libc::pid_t;
        let mut probe = child
            .stdin
            .take()
            .expect("root fixture has a piped inherited-stdin probe");
        let mut lease = ChildLease::new(child, Duration::from_millis(20)).unwrap();

        // SAFETY: the descriptor belongs to the private fixture writer and
        // remains open for both fcntl calls; no pointer arguments are used.
        let flags = unsafe { libc::fcntl(probe.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1, "read fixture pipe flags");
        // SAFETY: preserve its existing flags while enabling nonblocking writes.
        assert_ne!(
            unsafe { libc::fcntl(probe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1,
            "make fixture pipe polling nonblocking"
        );

        let ready_deadline = Instant::now() + Duration::from_secs(5);
        let mut descendant_ready = false;
        while Instant::now() < ready_deadline {
            if ready_path.exists() {
                descendant_ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let root_exit_deadline = Instant::now() + Duration::from_secs(5);
        let mut root_exited = false;
        while Instant::now() < root_exit_deadline {
            if lease.observe_exit().expect("root remains wait-owned") {
                root_exited = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        // A successful write proves the ready descendant still has the
        // inherited pipe open after its root has exited.
        let descendant_holds_pipe = probe.write_all(b"alive").is_ok();
        let native_query_refused_singleton = root_exited && !posix::owned_zombie_only_group(group);
        let injected_error = if root_exited {
            lease.signal_root_group_with(libc::SIGTERM, |_, _| {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "root fixture did not exit while descendant remained live",
            ))
        };

        // Clean up only through the lease-owned root PGID, then use
        // BrokenPipe on the inherited stdin pipe to observe termination. The
        // 30-second fixture fallback can never satisfy the five-second
        // signal-cleanup criterion.
        let cleanup_started_at = Instant::now();
        let signal_cleanup_deadline = cleanup_started_at + Duration::from_secs(5);
        let cleanup_signal = lease.signal_root_group(libc::SIGKILL);
        let pipe_closed_after_signal =
            wait_for_fixture_stdin_pipe_close(&mut probe, signal_cleanup_deadline);
        let descendant_stopped_within_bound = pipe_closed_after_signal.is_some_and(|closed_at| {
            closed_at < failsafe_not_before && closed_at <= signal_cleanup_deadline
        });
        let descendant_pipe_closed = pipe_closed_after_signal.is_some()
            || wait_for_fixture_stdin_pipe_close(&mut probe, failsafe_deadline).is_some();

        if !descendant_pipe_closed {
            let _ = std::fs::remove_file(&ready_path);
            std::mem::forget(lease);
            panic!(
                "could not confirm group-reader termination by the fixture failsafe; retained the unreaped root lease and will issue no further PID/PGID signals"
            );
        }

        if !lease.observe_exit().unwrap_or(false) {
            let _ = std::fs::remove_file(&ready_path);
            std::mem::forget(lease);
            panic!("root exit or wait ownership was not confirmed; refusing a blocking reap");
        }

        // Reap only after the inherited pipe confirms that the descendant has
        // exited (from SIGKILL or its failsafe). A failsafe exit still fails
        // the original five-second cleanup assertion below.
        let reap_result = lease.reap();
        let _ = std::fs::remove_file(&ready_path);

        assert!(
            descendant_ready,
            "same-group descendant must signal readiness before root exit"
        );
        assert!(
            root_exited,
            "root fixture must exit before the counterprobe"
        );
        assert!(
            descendant_holds_pipe,
            "same-group descendant must remain alive before cleanup"
        );
        assert!(
            native_query_refused_singleton,
            "KERN_PROC_PGRP must reject a live descendant beside the root zombie"
        );
        assert_eq!(
            injected_error
                .expect_err("injected EPERM remains a denial with a live same-group member")
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert!(
            descendant_stopped_within_bound,
            "group SIGKILL must close the inherited pipe within five seconds and before the failsafe"
        );
        cleanup_signal.expect("lease cleanup signals only the owned root group");
        reap_result.expect("reap the wait-owned direct root after group cleanup");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_group_record_classifier_fails_closed_for_unknown_or_mismatched_rows() {
        let group = 4321;
        let uid = 501;
        let zombie_status =
            libc::c_int::try_from(libc::SZOMB).expect("macOS process status fits in c_int");
        let valid = posix::OwnedZombieGroupObservation {
            group,
            effective_uid: uid,
            complete: 1,
            record_count: 1,
            member_pid: group,
            member_group: group,
            member_uid: uid,
            member_status: zombie_status,
        };
        let classify = posix::classify_owned_zombie_group_record_for_test;
        assert!(classify(valid));
        assert!(
            !classify(posix::OwnedZombieGroupObservation {
                record_count: 0,
                member_pid: 0,
                member_group: 0,
                member_uid: 0,
                member_status: 0,
                ..valid
            }),
            "empty group is not affirmative"
        );
        assert!(!classify(posix::OwnedZombieGroupObservation {
            complete: 0,
            ..valid
        }));
        assert!(!classify(posix::OwnedZombieGroupObservation {
            record_count: 2,
            ..valid
        }));
        assert!(!classify(posix::OwnedZombieGroupObservation {
            member_pid: group + 1,
            ..valid
        }));
        assert!(!classify(posix::OwnedZombieGroupObservation {
            member_group: group + 1,
            ..valid
        }));
        assert!(!classify(posix::OwnedZombieGroupObservation {
            member_uid: uid + 1,
            ..valid
        }));
        assert!(
            !classify(posix::OwnedZombieGroupObservation {
                member_status: 0,
                ..valid
            }),
            "unknown status refuses"
        );
        assert!(!classify(posix::OwnedZombieGroupObservation {
            member_status: zombie_status + 1,
            ..valid
        }));
    }

    #[test]
    fn injected_group_eperm_while_owned_child_is_live_remains_a_denial() {
        ensure_waitable_sigchld().expect("test process must retain waitable child status");
        let child = spawn_fixture("hold");
        let mut lease = ChildLease::new(child, Duration::from_millis(20)).unwrap();
        assert!(!lease.observe_exit().expect("hold fixture remains live"));

        let classifier_called = Cell::new(false);
        let error = lease
            .signal_root_group_with_classifier(
                libc::SIGTERM,
                |_, _| Err(io::Error::from_raw_os_error(libc::EPERM)),
                |_| {
                    classifier_called.set(true);
                    true
                },
            )
            .expect_err("a live root can never normalize EPERM");
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        assert!(
            !classifier_called.get(),
            "zombie-only classification must not run while WNOWAIT reports live"
        );

        lease
            .signal_root_group(libc::SIGKILL)
            .expect("clean up the isolated live fixture");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !lease.observe_exit().expect("fixture remains wait-owned") {
            assert!(
                Instant::now() < deadline,
                "fixture did not exit after SIGKILL"
            );
            thread::sleep(Duration::from_millis(10));
        }
        lease.reap().expect("reap isolated fixture");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wait_ownership_loss_after_eperm_blocks_zombie_classification() {
        ensure_waitable_sigchld().expect("test process must retain waitable child status");
        let child = spawn_fixture("exit");
        let pid = child.id();
        let mut lease = ChildLease::new(child, Duration::from_millis(20)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !lease.observe_exit().expect("child remains wait-owned") {
            assert!(Instant::now() < deadline, "exit fixture did not finish");
            thread::sleep(Duration::from_millis(10));
        }

        let signal_backend_called = Cell::new(false);
        let classifier_called = Cell::new(false);
        let error = lease
            .signal_root_group_with_classifier(
                libc::SIGTERM,
                |_, _| {
                    signal_backend_called.set(true);
                    posix::reap_direct_child(pid as libc::pid_t)
                        .expect("controlled fixture reaper consumes only its own child");
                    Err(io::Error::from_raw_os_error(libc::EPERM))
                },
                |_| {
                    classifier_called.set(true);
                    true
                },
            )
            .expect_err("fresh WNOWAIT must reject lost ownership after EPERM");
        assert!(signal_backend_called.get());
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        assert!(lease.reaping_lost());
        assert!(
            !classifier_called.get(),
            "an unowned process-group ID must not reach the classifier"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wait_ownership_loss_during_zombie_classification_is_caught_by_final_check() {
        ensure_waitable_sigchld().expect("test process must retain waitable child status");
        let child = spawn_fixture("exit");
        let pid = child.id();
        let mut lease = ChildLease::new(child, Duration::from_millis(20)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !lease.observe_exit().expect("child remains wait-owned") {
            assert!(Instant::now() < deadline, "exit fixture did not finish");
            thread::sleep(Duration::from_millis(10));
        }

        let error = lease
            .signal_root_group_with_classifier(
                libc::SIGTERM,
                |_, _| Err(io::Error::from_raw_os_error(libc::EPERM)),
                |_| {
                    posix::reap_direct_child(pid as libc::pid_t)
                        .expect("controlled fixture reaper consumes only its own child");
                    true
                },
            )
            .expect_err("final WNOWAIT must reject normalization after ownership loss");
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        assert!(lease.reaping_lost());
    }

    #[test]
    fn lost_wait_ownership_blocks_group_and_child_signal_backends() {
        ensure_waitable_sigchld().expect("test process must retain waitable child status");
        let child = spawn_fixture("exit");
        let mut lease = ChildLease::new(child, Duration::from_millis(1)).unwrap();
        let pid = lease.pid();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !lease.observe_exit().unwrap() {
            assert!(Instant::now() < deadline, "exit fixture did not finish");
            thread::sleep(Duration::from_millis(10));
        }
        // An earlier WNOWAIT exit observation must not replace a fresh check
        // immediately before a later signal-authorization attempt.
        let raw_status = posix::reap_direct_child(pid as libc::pid_t)
            .expect("controlled fixture reaper consumes only its own direct child");
        assert_eq!(raw_status, 0);
        let mut group_backend_called = false;
        let error = lease
            .signal_root_group_with(libc::SIGKILL, |_, _| {
                group_backend_called = true;
                Ok(())
            })
            .expect_err("fresh signal guard must notice the intervening external reap");
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        assert!(lease.reaping_lost());
        assert!(
            !group_backend_called,
            "no group backend after an intervening reap"
        );

        let mut child_backend_called = false;
        assert!(
            lease
                .kill_direct_child_with(|_| {
                    child_backend_called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(
            !child_backend_called,
            "direct-child kill backend must not run after wait ownership is lost"
        );
        assert!(lease.reap().is_err());
    }
}

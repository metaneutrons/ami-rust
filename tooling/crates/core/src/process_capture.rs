//! Bounded capture for one noninteractive external command.
//!
//! The command receives only the explicit environment map, a null stdin, and
//! the requested working directory. It starts in a new POSIX process group so
//! cancellation can signal the direct child and same-group descendants. This
//! is process supervision, not containment: descendants that change process
//! groups or sessions, aggregate memory/workspace enforcement, and work done
//! outside these pipes require a separate host observer. Normal completion
//! reaps the direct child; same-group descendants that close or redirect both
//! output pipes may outlive it.

use crate::process_lease::{self, ChildLease};

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    fmt, io,
    os::unix::{
        io::AsRawFd,
        process::{CommandExt, ExitStatusExt},
    },
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const POLL_QUANTUM: Duration = Duration::from_millis(25);
const READ_BUFFER_BYTES: usize = 8 * 1024;
const READ_BUDGET_PER_PASS: usize = 64 * 1024;

/// A command description with a complete, replacement environment.
#[derive(Clone, Debug)]
pub struct CommandSpec {
    /// Absolute executable path selected and verified by the caller.
    pub program: OsString,
    /// Arguments after argv[0], preserved as operating-system strings.
    pub args: Vec<OsString>,
    /// Child working directory.
    pub cwd: PathBuf,
    /// The entire child environment. The parent environment is cleared first.
    pub env: BTreeMap<OsString, OsString>,
}

impl CommandSpec {
    pub fn new(
        program: impl Into<OsString>,
        args: impl IntoIterator<Item = OsString>,
        cwd: impl Into<PathBuf>,
        env: BTreeMap<OsString, OsString>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
            cwd: cwd.into(),
            env,
        }
    }
}

/// Caller-selected bounds for one command invocation.
///
/// A production verifier can, for example, select a 60-second timeout, 4 MiB
/// stdout, 64 KiB stderr, and a 2-second termination grace. Those are caller
/// policy values; this adapter does not impose application-wide quotas.
#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub termination_grace: Duration,
}

/// Completed direct-child status and bounded captured output.
#[derive(Debug)]
pub struct CapturedProcess {
    /// The actual direct-child wait status, including nonzero exits and signals.
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

impl CapturedProcess {
    pub fn exit_code(&self) -> Option<i32> {
        self.status.code()
    }

    /// Returns the terminating signal on Unix, if the child was signalled.
    pub fn signal(&self) -> Option<i32> {
        self.status.signal()
    }
}

/// Why capture ended before a complete direct-child result was available.
#[derive(Debug)]
pub enum CaptureCause {
    Timeout,
    Cancelled,
    StdoutLimitExceeded,
    StderrLimitExceeded,
    DescendantRetainedPipe,
    OutputAllocation,
    Io(io::Error),
}

impl fmt::Display for CaptureCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("command deadline expired"),
            Self::Cancelled => formatter.write_str("command was cancelled"),
            Self::StdoutLimitExceeded => formatter.write_str("command stdout limit exceeded"),
            Self::StderrLimitExceeded => formatter.write_str("command stderr limit exceeded"),
            Self::DescendantRetainedPipe => {
                formatter.write_str("command exited while a descendant retained its output pipe")
            }
            Self::OutputAllocation => formatter.write_str("could not allocate bounded output"),
            Self::Io(error) => write!(formatter, "command capture failed: {error}"),
        }
    }
}

/// Failure details, including partial output and the direct child's actual
/// status when it could be collected during termination.
#[derive(Debug)]
pub struct CaptureError {
    pub cause: CaptureCause,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: Option<ExitStatus>,
    pub elapsed: Duration,
    /// A cleanup failure is kept separately from the original capture cause.
    pub cleanup_error: Option<io::Error>,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.cause)?;
        if let Some(error) = &self.cleanup_error {
            write!(formatter, "; process cleanup also failed: {error}")?;
        }
        Ok(())
    }
}

impl Error for CaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            CaptureCause::Io(error) => Some(error),
            _ => self
                .cleanup_error
                .as_ref()
                .map(|error| error as &(dyn Error + 'static)),
        }
    }
}

/// Run one command without a shell and capture each output stream up to its
/// independent limit. Nonzero exits are successful captures; inspect
/// [`CapturedProcess::status`] or [`CapturedProcess::exit_code`].
///
/// `program` and `cwd` must be absolute paths. The caller must preserve the
/// default `SIGCHLD` disposition: this adapter rejects changed dispositions
/// and `SA_NOCLDWAIT`, and the caller must not run a competing child reaper.
/// Supported commands are trusted same-UID tools that preserve credentials.
/// The cancellation
/// predicate is checked between bounded pipe reads and polls; this is not a
/// hard real-time guarantee during process creation, while the predicate runs,
/// or during kernel wait and reap operations. If the predicate panics, the
/// child group is terminated and reaped before the panic resumes.
pub fn capture(
    spec: &CommandSpec,
    limits: CaptureLimits,
    mut cancelled: impl FnMut() -> bool,
) -> std::result::Result<CapturedProcess, CaptureError> {
    let started = Instant::now();
    if let Err(error) = validate_paths(spec) {
        return Err(preflight_error(error, started));
    }
    if let Err(error) = process_lease::ensure_waitable_sigchld() {
        return Err(preflight_error(error, started));
    }
    let deadline = started
        .checked_add(limits.timeout)
        .ok_or_else(|| CaptureError {
            cause: CaptureCause::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command timeout cannot be represented by the monotonic clock",
            )),
            stdout: Vec::new(),
            stderr: Vec::new(),
            status: None,
            elapsed: started.elapsed(),
            cleanup_error: None,
        })?;

    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.process_group(0);

    let child = command.spawn().map_err(|error| CaptureError {
        cause: CaptureCause::Io(error),
        stdout: Vec::new(),
        stderr: Vec::new(),
        status: None,
        elapsed: started.elapsed(),
        cleanup_error: None,
    })?;
    let mut running =
        RunningChild::new(child, limits.termination_grace).map_err(|error| CaptureError {
            cause: CaptureCause::Io(error),
            stdout: Vec::new(),
            stderr: Vec::new(),
            status: None,
            elapsed: started.elapsed(),
            cleanup_error: None,
        })?;
    let mut pipes = Pipes {
        stdout: running.lease.take_stdout(),
        stderr: running.lease.take_stderr(),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    if let Err(error) = set_nonblocking(&pipes) {
        // Cleanup reads only nonblocking descriptors. If setup failed partway
        // through, close both pipe ends before terminating the child group.
        pipes.stdout.take();
        pipes.stderr.take();
        let cleanup_error = running.terminate_and_reap(
            &mut pipes,
            &mut stdout,
            &mut stderr,
            limits.stdout_bytes,
            limits.stderr_bytes,
        );
        return Err(CaptureError {
            cause: CaptureCause::Io(error),
            stdout,
            stderr,
            status: running.lease.status(),
            elapsed: started.elapsed(),
            cleanup_error,
        });
    }

    let loop_result = panic::catch_unwind(AssertUnwindSafe(|| {
        run_capture_loop(
            &mut running,
            &mut pipes,
            &mut stdout,
            &mut stderr,
            limits,
            deadline,
            &mut cancelled,
        )
    }));

    match loop_result {
        Ok(Ok(())) => {
            let status = running.lease.status().expect("successful loop reaps child");
            Ok(CapturedProcess {
                status,
                stdout,
                stderr,
                elapsed: started.elapsed(),
            })
        }
        Ok(Err(cause)) => {
            let cleanup_error = running.terminate_and_reap(
                &mut pipes,
                &mut stdout,
                &mut stderr,
                limits.stdout_bytes,
                limits.stderr_bytes,
            );
            Err(CaptureError {
                cause,
                stdout,
                stderr,
                status: running.lease.status(),
                elapsed: started.elapsed(),
                cleanup_error,
            })
        }
        Err(payload) => {
            let _ = running.terminate_and_reap(
                &mut pipes,
                &mut stdout,
                &mut stderr,
                limits.stdout_bytes,
                limits.stderr_bytes,
            );
            panic::resume_unwind(payload)
        }
    }
}

fn preflight_error(error: io::Error, started: Instant) -> CaptureError {
    CaptureError {
        cause: CaptureCause::Io(error),
        stdout: Vec::new(),
        stderr: Vec::new(),
        status: None,
        elapsed: started.elapsed(),
        cleanup_error: None,
    }
}

fn validate_paths(spec: &CommandSpec) -> io::Result<()> {
    if !Path::new(&spec.program).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command executable path must be absolute",
        ));
    }
    if !spec.cwd.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command working directory must be absolute",
        ));
    }
    Ok(())
}

struct Pipes {
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl Pipes {
    fn eof(&self) -> bool {
        self.stdout.is_none() && self.stderr.is_none()
    }

    fn fds(&self) -> [libc::pollfd; 2] {
        [
            libc::pollfd {
                fd: self.stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: self.stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ]
    }
}

struct RunningChild {
    lease: ChildLease,
    grace: Duration,
}

impl RunningChild {
    fn new(child: Child, grace: Duration) -> io::Result<Self> {
        Ok(Self {
            lease: ChildLease::new(child, grace)?,
            grace,
        })
    }

    fn exited_without_reaping(&mut self) -> io::Result<bool> {
        self.lease.observe_exit()
    }

    fn reap(&mut self) -> io::Result<()> {
        self.lease.reap()
    }

    fn terminate_and_reap(
        &mut self,
        pipes: &mut Pipes,
        stdout: &mut Vec<u8>,
        stderr: &mut Vec<u8>,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> Option<io::Error> {
        if self.lease.reaping_lost() {
            pipes.stdout.take();
            pipes.stderr.take();
            return Some(io::Error::other(
                "child reaping ownership was lost; refusing to signal a possibly reused process group",
            ));
        }
        let mut first_error = self.lease.signal_root_group(libc::SIGTERM).err();
        let grace_started = Instant::now();

        while grace_started.elapsed() < self.grace {
            drain_during_cleanup(&mut pipes.stdout, stdout, stdout_limit);
            drain_during_cleanup(&mut pipes.stderr, stderr, stderr_limit);

            match group_exists(self.lease.pid() as libc::pid_t) {
                Ok(false) => break,
                Ok(true) => {}
                Err(error) => save_first_error(&mut first_error, error),
            }

            let wait = self.grace.saturating_sub(grace_started.elapsed());
            if let Err(error) = poll_pipes(pipes, wait.min(POLL_QUANTUM)) {
                save_first_error(&mut first_error, error);
                break;
            }
        }

        if let Err(error) = self.lease.signal_root_group(libc::SIGKILL) {
            save_first_error(&mut first_error, error);
        }

        // The group may be empty because the direct child moved out of it.
        // Always try the lease-guarded direct-child kill after the group
        // attempt; the lease performs a fresh WNOWAIT check before any PID
        // signal and refuses if reaping ownership has been lost.
        let mut direct_child_kill_failed = false;
        if self.lease.status().is_none()
            && let Err(kill_error) = self.lease.kill_direct_child()
        {
            direct_child_kill_failed = true;
            save_first_error(&mut first_error, kill_error);
        }

        // Do not enter Child::wait when direct-child termination failed unless
        // a fresh WNOWAIT observation confirms the child has already exited.
        let may_reap = if self.lease.status().is_some() || !direct_child_kill_failed {
            true
        } else {
            match self.lease.observe_exit() {
                Ok(exited) => exited,
                Err(error) => {
                    save_first_error(&mut first_error, error);
                    false
                }
            }
        };

        if !may_reap {
            save_first_error(
                &mut first_error,
                io::Error::other(
                    "refusing to block while direct child may still be running after cleanup failure",
                ),
            );
        }

        // One final nonblocking drain preserves available partial diagnostics;
        // close the descriptors afterwards rather than waiting for escaped
        // descendants that may have inherited them.
        drain_during_cleanup(&mut pipes.stdout, stdout, stdout_limit);
        drain_during_cleanup(&mut pipes.stderr, stderr, stderr_limit);
        pipes.stdout.take();
        pipes.stderr.take();

        if may_reap && let Err(error) = self.reap() {
            save_first_error(&mut first_error, error);
        }
        first_error
    }
}

fn run_capture_loop(
    child: &mut RunningChild,
    pipes: &mut Pipes,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    limits: CaptureLimits,
    deadline: Instant,
    cancelled: &mut impl FnMut() -> bool,
) -> std::result::Result<(), CaptureCause> {
    loop {
        if cancelled() {
            return Err(CaptureCause::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(CaptureCause::Timeout);
        }
        poll_pipes(pipes, deadline.saturating_duration_since(now)).map_err(CaptureCause::Io)?;

        let stdout_state = drain_pipe(&mut pipes.stdout, stdout, limits.stdout_bytes)
            .map_err(|error| error.into_cause(true))?;
        let stderr_state = drain_pipe(&mut pipes.stderr, stderr, limits.stderr_bytes)
            .map_err(|error| error.into_cause(false))?;

        if child.exited_without_reaping().map_err(CaptureCause::Io)? {
            // The child can exit just after the first read pass. Once WNOWAIT
            // observes that exit, do a final read pass so its last buffered
            // bytes and EOF are seen before diagnosing an inherited pipe.
            let final_stdout = drain_pipe(&mut pipes.stdout, stdout, limits.stdout_bytes)
                .map_err(|error| error.into_cause(true))?;
            let final_stderr = drain_pipe(&mut pipes.stderr, stderr, limits.stderr_bytes)
                .map_err(|error| error.into_cause(false))?;
            if stdout_state == DrainState::BudgetExhausted
                || stderr_state == DrainState::BudgetExhausted
                || final_stdout == DrainState::BudgetExhausted
                || final_stderr == DrainState::BudgetExhausted
            {
                continue;
            }
            if !pipes.eof() {
                return Err(CaptureCause::DescendantRetainedPipe);
            }
            child.reap().map_err(CaptureCause::Io)?;
            return Ok(());
        }
    }
}

enum DrainFailure {
    Limit,
    Allocation,
    Io(io::Error),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DrainState {
    Closed,
    Eof,
    WouldBlock,
    BudgetExhausted,
}

impl DrainFailure {
    fn into_cause(self, stdout: bool) -> CaptureCause {
        match self {
            Self::Limit if stdout => CaptureCause::StdoutLimitExceeded,
            Self::Limit => CaptureCause::StderrLimitExceeded,
            Self::Allocation => CaptureCause::OutputAllocation,
            Self::Io(error) => CaptureCause::Io(error),
        }
    }
}

fn drain_pipe<R: io::Read>(
    pipe: &mut Option<R>,
    output: &mut Vec<u8>,
    limit: usize,
) -> std::result::Result<DrainState, DrainFailure> {
    let mut read_budget = READ_BUDGET_PER_PASS;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    while read_budget > 0 {
        let Some(reader) = pipe.as_mut() else {
            return Ok(DrainState::Closed);
        };
        let request = read_budget.min(buffer.len());
        match reader.read(&mut buffer[..request]) {
            Ok(0) => {
                *pipe = None;
                return Ok(DrainState::Eof);
            }
            Ok(count) => {
                read_budget -= count;
                let available = limit.saturating_sub(output.len());
                let retained = count.min(available);
                if retained > 0 {
                    output
                        .try_reserve_exact(retained)
                        .map_err(|_| DrainFailure::Allocation)?;
                    output.extend_from_slice(&buffer[..retained]);
                }
                if retained < count {
                    return Err(DrainFailure::Limit);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return Ok(DrainState::BudgetExhausted);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(DrainState::WouldBlock);
            }
            Err(error) => return Err(DrainFailure::Io(error)),
        }
    }
    Ok(DrainState::BudgetExhausted)
}

fn drain_during_cleanup<R: io::Read>(pipe: &mut Option<R>, output: &mut Vec<u8>, limit: usize) {
    let mut read_budget = READ_BUDGET_PER_PASS;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    while read_budget > 0 {
        let Some(reader) = pipe.as_mut() else {
            return;
        };
        let request = read_budget.min(buffer.len());
        match reader.read(&mut buffer[..request]) {
            Ok(0) => {
                *pipe = None;
                return;
            }
            Ok(count) => {
                read_budget -= count;
                let retained = count.min(limit.saturating_sub(output.len()));
                if retained > 0 && output.try_reserve_exact(retained).is_ok() {
                    output.extend_from_slice(&buffer[..retained]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(_) => return,
        }
    }
}

fn set_nonblocking(pipes: &Pipes) -> io::Result<()> {
    if let Some(stdout) = &pipes.stdout {
        posix::set_nonblocking(stdout.as_raw_fd())?;
    }
    if let Some(stderr) = &pipes.stderr {
        posix::set_nonblocking(stderr.as_raw_fd())?;
    }
    Ok(())
}

fn poll_pipes(pipes: &Pipes, remaining: Duration) -> io::Result<()> {
    let mut descriptors = pipes.fds();
    let wait = remaining.min(POLL_QUANTUM);
    let millis = wait
        .as_millis()
        .saturating_add(u128::from(!wait.as_nanos().is_multiple_of(1_000_000)));
    let timeout = i32::try_from(millis).unwrap_or(i32::MAX);
    match posix::poll(&mut descriptors, timeout) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
        Err(error) => Err(error),
    }
}

fn group_exists(group: libc::pid_t) -> io::Result<bool> {
    posix::group_exists(group)
}

fn save_first_error(first: &mut Option<io::Error>, next: io::Error) {
    if first.is_none() {
        *first = Some(next);
    }
}

#[allow(
    unsafe_code,
    reason = "POSIX process groups, poll, nonblocking descriptors, and waitid require libc."
)]
mod posix {
    use std::{io, os::unix::io::RawFd};

    pub(super) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY: fcntl with F_GETFL reads flags for this open descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFL updates only status flags for the same valid pipe fd.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn poll(
        descriptors: &mut [libc::pollfd; 2],
        timeout_ms: libc::c_int,
    ) -> io::Result<i32> {
        // SAFETY: the array is initialized and valid for its two-element length.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    pub(super) fn group_exists(group: libc::pid_t) -> io::Result<bool> {
        // SAFETY: signal zero checks existence/permission and sends no signal.
        if unsafe { libc::kill(-group, 0) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        process::Command as FixtureCommand,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const FIXTURE_NAME: &str = "process_capture::tests::child_fixture_entry";

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ami-rust-process-capture-{}-{serial}-space",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create process fixture directory");
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits() -> CaptureLimits {
        CaptureLimits {
            timeout: Duration::from_secs(3),
            stdout_bytes: 16 * 1024,
            stderr_bytes: 16 * 1024,
            termination_grace: Duration::from_millis(100),
        }
    }

    fn spec(mode: &str, cwd: &std::path::Path) -> CommandSpec {
        let mut env = BTreeMap::new();
        env.insert(
            "AMI_CAPTURE_FIXTURE_TOKEN".into(),
            "ami-rust-core-process-capture-v1".into(),
        );
        env.insert("AMI_CAPTURE_MODE".into(), mode.into());
        CommandSpec::new(
            std::env::current_exe().expect("test executable path"),
            [
                OsString::from("--exact"),
                OsString::from(FIXTURE_NAME),
                OsString::from("--nocapture"),
                OsString::from("--test-threads=1"),
            ],
            cwd,
            env,
        )
    }

    fn quiet_spec(mode: &str, cwd: &std::path::Path) -> CommandSpec {
        let mut fixture = spec(mode, cwd);
        fixture.args[2] = OsString::from("--quiet");
        fixture
    }

    fn framed_payload<'a>(output: &'a [u8], begin: &[u8], end: &[u8]) -> &'a [u8] {
        let begin_at = output
            .windows(begin.len())
            .position(|window| window == begin)
            .expect("fixture begin marker");
        let payload_start = begin_at + begin.len();
        let end_at = output[payload_start..]
            .windows(end.len())
            .position(|window| window == end)
            .map(|offset| payload_start + offset)
            .expect("fixture end marker");
        &output[payload_start..end_at]
    }

    #[test]
    #[allow(
        unsafe_code,
        clippy::zombie_processes,
        reason = "The fixture changes its own signal dispositions, self-signals, and leaves descendants for isolated supervisor tests."
    )]
    fn child_fixture_entry() {
        if !std::env::var("AMI_CAPTURE_FIXTURE_TOKEN")
            .is_ok_and(|token| token == "ami-rust-core-process-capture-v1")
        {
            return;
        }
        let Ok(mode) = std::env::var("AMI_CAPTURE_MODE") else {
            return;
        };
        match mode.as_str() {
            "inspect" => {
                let mut stdin = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut stdin)
                    .expect("read null stdin");
                println!("cwd={}", std::env::current_dir().unwrap().display());
                println!("stdin_bytes={}", stdin.len());
                println!("mode={mode}");
                println!("path_absent={}", std::env::var_os("PATH").is_none());
                println!("args={:?}", std::env::args_os().skip(1).collect::<Vec<_>>());
            }
            "streams" => {
                std::io::stdout()
                    .write_all(b"OUT-BEGIN\n")
                    .expect("write fixture stdout");
                std::io::stderr()
                    .write_all(b"ERR-BEGIN\n")
                    .expect("write fixture stderr");
                std::io::stdout()
                    .write_all(&[b'o'; 128 * 1024])
                    .expect("write fixture stdout payload");
                std::io::stderr()
                    .write_all(&[b'e'; 96 * 1024])
                    .expect("write fixture stderr payload");
                std::io::stdout()
                    .write_all(b"\nOUT-END\n")
                    .expect("write fixture stdout end marker");
                std::io::stderr()
                    .write_all(b"\nERR-END\n")
                    .expect("write fixture stderr end marker");
                std::io::stdout().flush().expect("flush fixture stdout");
                std::io::stderr().flush().expect("flush fixture stderr");
                // Bypass the test harness's post-test summary so both streams
                // have a deterministic byte-for-byte fixture boundary.
                std::process::exit(0);
            }
            "short_both_streams" => {
                std::io::stdout()
                    .write_all(b"short stdout\n")
                    .expect("write short fixture stdout");
                std::io::stdout()
                    .flush()
                    .expect("flush short fixture stdout");
                std::io::stderr()
                    .write_all(b"short stderr\n")
                    .expect("write short fixture stderr");
                std::io::stderr()
                    .flush()
                    .expect("flush short fixture stderr");
            }
            "stdout_overflow" => {
                std::io::stdout()
                    .write_all(&[b'o'; 4096])
                    .expect("write overflowing stdout");
            }
            "stderr_overflow" => {
                std::io::stderr()
                    .write_all(&[b'e'; 4096])
                    .expect("write overflowing stderr");
            }
            "nonzero" => std::process::exit(37),
            "signal" => {
                // SAFETY: SIGKILL terminates only this disposable fixture.
                unsafe { libc::raise(libc::SIGKILL) };
            }
            "ignore_term" => {
                // SAFETY: this isolated fixture ignores SIGTERM to exercise
                // the supervisor's bounded SIGKILL escalation.
                let previous = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
                assert_ne!(previous, libc::SIG_ERR, "install SIGTERM ignore handler");
                std::io::stdout()
                    .write_all(b"ready\n")
                    .expect("write readiness marker");
                std::io::stdout().flush().expect("flush readiness marker");
                thread::sleep(Duration::from_secs(30));
            }
            "move_group_ignore_term" => {
                let caller_group = std::env::var("AMI_CAPTURE_TARGET_PGID")
                    .expect("caller process group")
                    .parse::<libc::pid_t>()
                    .expect("valid caller process group");
                // SAFETY: this fixture changes only its own process group to
                // the caller's group; the supervisor must never signal that
                // group based on the child's previous group membership.
                assert_eq!(unsafe { libc::setpgid(0, caller_group) }, 0);
                // SAFETY: this disposable fixture ignores SIGTERM so the test
                // exercises the direct-child SIGKILL fallback.
                let previous = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
                assert_ne!(previous, libc::SIG_ERR, "install SIGTERM ignore handler");
                let marker = std::env::var_os("AMI_CAPTURE_MARKER").unwrap();
                fs::write(marker, b"ready").expect("write moved-group readiness marker");
                thread::sleep(Duration::from_secs(2));
            }
            "silent" => std::process::exit(0),
            "write_marker" => {
                let marker = std::env::var_os("AMI_CAPTURE_MARKER").unwrap();
                fs::write(marker, b"spawned").expect("write process-start marker");
            }
            "ignore_sigchld_preflight" => {
                // SAFETY: this fixture runs in its own subprocess and changes
                // only that process's SIGCHLD disposition.
                let previous = unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
                assert_ne!(
                    previous,
                    libc::SIG_ERR,
                    "install SIGCHLD ignore disposition"
                );
                let cwd = std::env::current_dir().expect("fixture working directory");
                let marker = std::env::var_os("AMI_CAPTURE_MARKER").unwrap();
                let mut target = spec("write_marker", &cwd);
                target.env.insert("AMI_CAPTURE_MARKER".into(), marker);
                let error = capture(&target, limits(), || false)
                    .expect_err("ignored SIGCHLD must fail before spawning");
                assert!(matches!(
                    error.cause,
                    CaptureCause::Io(ref cause)
                        if cause.kind() == io::ErrorKind::InvalidInput
                ));
                std::process::exit(0);
            }
            "sleep" => thread::sleep(Duration::from_secs(30)),
            "spawn_descendant" => {
                let mut descendant = FixtureCommand::new(std::env::current_exe().unwrap());
                descendant
                    .args(["--exact", FIXTURE_NAME, "--nocapture", "--test-threads=1"])
                    .env("AMI_CAPTURE_MODE", "grandchild")
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
                if let Some(marker) = std::env::var_os("AMI_CAPTURE_MARKER") {
                    descendant.env("AMI_CAPTURE_MARKER", marker);
                }
                descendant.spawn().expect("spawn same-group descendant");
                println!("parent fixture exits with descendant holding pipes");
            }
            "spawn_closed_descendant" => {
                let mut descendant = FixtureCommand::new(std::env::current_exe().unwrap());
                descendant
                    .args(["--exact", FIXTURE_NAME, "--nocapture", "--test-threads=1"])
                    .env("AMI_CAPTURE_MODE", "grandchild")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                if let Some(marker) = std::env::var_os("AMI_CAPTURE_MARKER") {
                    descendant.env("AMI_CAPTURE_MARKER", marker);
                }
                descendant
                    .spawn()
                    .expect("spawn descendant with closed pipes");
            }
            "grandchild" | "write_marker_after_delay" => {
                thread::sleep(Duration::from_millis(600));
                let marker = std::env::var_os("AMI_CAPTURE_MARKER").unwrap();
                fs::write(marker, b"survived").expect("write descendant marker");
            }
            _ => panic!("unknown child fixture mode"),
        }
    }

    #[test]
    fn captures_argv_environment_cwd_stdin_and_both_streams() {
        let temp = TempDirectory::new();
        let result = capture(&spec("inspect", &temp.0), limits(), || false).unwrap();
        assert!(result.status.success());
        let stdout = String::from_utf8(result.stdout).unwrap();
        let expected_cwd = fs::canonicalize(&temp.0).unwrap();
        assert!(
            stdout.contains(&format!("cwd={}", expected_cwd.display())),
            "child output did not contain its working directory: {stdout:?}"
        );
        assert!(stdout.contains("stdin_bytes=0"));
        assert!(stdout.contains("mode=inspect"));
        assert!(stdout.contains("path_absent=true"));
        assert!(stdout.contains("--exact"));
        assert!(stdout.contains(FIXTURE_NAME));
        assert!(stdout.contains("--test-threads=1"));

        let mut stream_limits = limits();
        stream_limits.stdout_bytes = 256 * 1024;
        stream_limits.stderr_bytes = 256 * 1024;
        let streams = capture(&quiet_spec("streams", &temp.0), stream_limits, || false).unwrap();
        let expected_stdout = [
            // The pinned test harness emits this deterministic prefix before
            // entering the fixture even with --quiet. The fixture exits before
            // the harness can append its post-test summary.
            b"\nrunning 1 test\n".as_slice(),
            b"OUT-BEGIN\n".as_slice(),
            &[b'o'; 128 * 1024],
            b"\nOUT-END\n",
        ]
        .concat();
        let expected_stderr = [
            b"ERR-BEGIN\n".as_slice(),
            &[b'e'; 96 * 1024],
            b"\nERR-END\n",
        ]
        .concat();
        assert_eq!(streams.stdout, expected_stdout);
        assert_eq!(streams.stderr, expected_stderr);
        assert_eq!(
            framed_payload(&streams.stdout, b"OUT-BEGIN\n", b"\nOUT-END\n"),
            &[b'o'; 128 * 1024]
        );
        assert_eq!(
            framed_payload(&streams.stderr, b"ERR-BEGIN\n", b"\nERR-END\n"),
            &[b'e'; 96 * 1024]
        );

        let mut exact_limits = stream_limits;
        exact_limits.stdout_bytes = expected_stdout.len();
        exact_limits.stderr_bytes = expected_stderr.len();
        let exact = capture(&quiet_spec("streams", &temp.0), exact_limits, || false).unwrap();
        assert_eq!(exact.stdout, expected_stdout);
        assert_eq!(exact.stderr, expected_stderr);

        let mut below_stdout_limit = exact_limits;
        below_stdout_limit.stdout_bytes -= 1;
        let below_stdout = capture(&quiet_spec("streams", &temp.0), below_stdout_limit, || {
            false
        })
        .unwrap_err();
        assert!(matches!(
            below_stdout.cause,
            CaptureCause::StdoutLimitExceeded
        ));
        assert_eq!(
            below_stdout.stdout,
            expected_stdout[..expected_stdout.len() - 1]
        );

        let mut below_stderr_limit = exact_limits;
        below_stderr_limit.stderr_bytes -= 1;
        let below_stderr = capture(&quiet_spec("streams", &temp.0), below_stderr_limit, || {
            false
        })
        .unwrap_err();
        assert!(matches!(
            below_stderr.cause,
            CaptureCause::StderrLimitExceeded
        ));
        assert_eq!(
            below_stderr.stderr,
            expected_stderr[..expected_stderr.len() - 1]
        );

        for _ in 0..20 {
            let short = capture(&spec("short_both_streams", &temp.0), limits(), || false)
                .expect("short-lived child output must reach EOF");
            assert!(short.status.success());
            assert!(
                short
                    .stdout
                    .windows(12)
                    .any(|window| window == b"short stdout")
            );
            assert!(
                short
                    .stderr
                    .windows(12)
                    .any(|window| window == b"short stderr")
            );
        }
    }

    #[test]
    fn validates_absolute_paths_and_reports_missing_executable() {
        let temp = TempDirectory::new();

        let mut relative_program = spec("silent", &temp.0);
        relative_program.program = "fixture-from-path".into();
        let program_error = capture(&relative_program, limits(), || false).unwrap_err();
        assert!(matches!(
            program_error.cause,
            CaptureCause::Io(ref error) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(program_error.status.is_none());

        let mut relative_cwd = spec("silent", &temp.0);
        relative_cwd.cwd = PathBuf::from("relative-working-directory");
        let cwd_error = capture(&relative_cwd, limits(), || false).unwrap_err();
        assert!(matches!(
            cwd_error.cause,
            CaptureCause::Io(ref error) if error.kind() == io::ErrorKind::InvalidInput
        ));

        let mut missing = spec("silent", &temp.0);
        missing.program = temp.0.join("missing-absolute-executable").into_os_string();
        let missing_error = capture(&missing, limits(), || false).unwrap_err();
        assert!(matches!(
            missing_error.cause,
            CaptureCause::Io(ref error) if error.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn accepts_zero_output_limits_for_an_empty_command() {
        let temp = TempDirectory::new();
        let mut no_output = limits();
        no_output.stdout_bytes = 0;
        no_output.stderr_bytes = 0;
        let command = CommandSpec::new(
            "/usr/bin/true",
            std::iter::empty(),
            &temp.0,
            BTreeMap::new(),
        );
        let result = capture(&command, no_output, || false).unwrap();
        assert!(result.status.success());
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn rejects_sigchld_auto_reap_before_starting_a_child() {
        let temp = TempDirectory::new();
        let marker = temp.0.join("must-not-spawn");
        let mut outer = spec("ignore_sigchld_preflight", &temp.0);
        outer
            .env
            .insert("AMI_CAPTURE_MARKER".into(), marker.as_os_str().to_owned());
        let result = capture(&outer, limits(), || false).unwrap();
        assert!(result.status.success());
        assert!(
            !marker.exists(),
            "capture started a command despite SIGCHLD auto-reap"
        );
    }

    #[test]
    fn preserves_nonzero_exit_and_signal_status() {
        let temp = TempDirectory::new();
        let nonzero = capture(&spec("nonzero", &temp.0), limits(), || false).unwrap();
        assert_eq!(nonzero.exit_code(), Some(37));
        let signalled = capture(&spec("signal", &temp.0), limits(), || false).unwrap();
        assert_eq!(signalled.exit_code(), None);
        assert_eq!(signalled.signal(), Some(libc::SIGKILL));
    }

    #[test]
    #[allow(unsafe_code)]
    fn externally_reaped_child_refuses_further_numeric_group_signalling() {
        let child = FixtureCommand::new("/usr/bin/true")
            .process_group(0)
            .spawn()
            .unwrap();
        let mut running = RunningChild::new(child, Duration::ZERO).unwrap();
        // Simulate an unsupported competing reaper, using this actual child.
        let pid = running.lease.pid() as libc::pid_t;
        let mut status = 0;
        // SAFETY: this test consumes only its own known direct child's wait
        // status to simulate an unsupported competing reaper.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        let error = running.exited_without_reaping().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        let cleanup = running
            .terminate_and_reap(
                &mut Pipes {
                    stdout: None,
                    stderr: None,
                },
                &mut Vec::new(),
                &mut Vec::new(),
                0,
                0,
            )
            .expect("lost child ownership must remain an explicit cleanup failure");
        assert!(cleanup.to_string().contains("refusing to signal"));
        assert!(running.lease.status().is_none());
        assert!(running.lease.reaping_lost());
    }

    #[test]
    fn timeout_and_independent_stream_limits_terminate_the_child() {
        let temp = TempDirectory::new();
        let mut short = limits();
        short.timeout = Duration::from_millis(100);
        let error = capture(&spec("sleep", &temp.0), short, || false).unwrap_err();
        assert!(matches!(error.cause, CaptureCause::Timeout));
        assert!(error.status.is_some());

        let mut resistant = limits();
        resistant.timeout = Duration::from_millis(900);
        resistant.termination_grace = Duration::from_millis(100);
        let escalation = capture(&spec("ignore_term", &temp.0), resistant, || false).unwrap_err();
        assert!(matches!(escalation.cause, CaptureCause::Timeout));
        assert_eq!(
            escalation.status.as_ref().and_then(ExitStatusExt::signal),
            Some(libc::SIGKILL),
            "a SIGTERM-resistant child must be killed after the grace interval"
        );

        let mut bounded = limits();
        bounded.stdout_bytes = 128;
        let stdout_error =
            capture(&spec("stdout_overflow", &temp.0), bounded, || false).unwrap_err();
        assert!(matches!(
            stdout_error.cause,
            CaptureCause::StdoutLimitExceeded
        ));
        assert_eq!(stdout_error.stdout.len(), 128);

        bounded.stdout_bytes = 16 * 1024;
        bounded.stderr_bytes = 128;
        let stderr_error =
            capture(&spec("stderr_overflow", &temp.0), bounded, || false).unwrap_err();
        assert!(matches!(
            stderr_error.cause,
            CaptureCause::StderrLimitExceeded
        ));
        assert_eq!(stderr_error.stderr.len(), 128);
    }

    #[test]
    #[allow(unsafe_code)]
    fn cancellation_kills_direct_child_after_it_leaves_supervisor_group() {
        let temp = TempDirectory::new();
        let marker = temp.0.join("moved-group-ready");
        // SAFETY: getpgrp reads the caller's current process group. The child
        // fixture receives this value only to move itself; this test never
        // sends a signal to the caller's group.
        let caller_group = unsafe { libc::getpgrp() };
        let mut fixture = spec("move_group_ignore_term", &temp.0);
        fixture.env.insert(
            "AMI_CAPTURE_TARGET_PGID".into(),
            caller_group.to_string().into(),
        );
        fixture
            .env
            .insert("AMI_CAPTURE_MARKER".into(), marker.as_os_str().to_owned());

        let cancelled = Arc::new(AtomicBool::new(false));
        let child_cancelled = Arc::clone(&cancelled);
        let mut bounded = limits();
        bounded.timeout = Duration::from_secs(4);
        bounded.termination_grace = Duration::from_millis(100);
        let capture_thread = thread::spawn(move || {
            capture(&fixture, bounded, move || {
                child_cancelled.load(Ordering::SeqCst)
            })
        });

        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() && Instant::now() < ready_deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let ready = marker.exists();
        cancelled.store(true, Ordering::SeqCst);
        let result = capture_thread
            .join()
            .expect("capture thread must clean up its child");
        assert!(
            ready,
            "child did not join caller group and publish readiness"
        );
        let error = result.expect_err("cancelled moved-group child must be terminated");
        assert!(matches!(error.cause, CaptureCause::Cancelled));
        assert_eq!(
            error.status.as_ref().and_then(ExitStatusExt::signal),
            Some(libc::SIGKILL),
            "the direct child must receive SIGKILL after leaving its original group"
        );
        assert!(error.cleanup_error.is_none());
        // SAFETY: signal zero checks that the caller's group still exists and
        // does not send a signal to it.
        assert_eq!(unsafe { libc::kill(-caller_group, 0) }, 0);
        // SAFETY: the current process group is unchanged by the child fixture.
        assert_eq!(unsafe { libc::getpgrp() }, caller_group);
    }

    #[test]
    fn cancellation_and_descendant_pipe_retention_clean_same_group() {
        let temp = TempDirectory::new();
        let mut first_calls = 0;
        let immediately_cancelled = capture(&spec("sleep", &temp.0), limits(), || {
            first_calls += 1;
            true
        })
        .unwrap_err();
        assert_eq!(first_calls, 1);
        assert!(matches!(
            immediately_cancelled.cause,
            CaptureCause::Cancelled
        ));
        assert!(immediately_cancelled.status.is_some());

        let mut calls = 0;
        let cancelled = capture(&spec("sleep", &temp.0), limits(), || {
            calls += 1;
            calls > 1
        })
        .unwrap_err();
        assert!(matches!(cancelled.cause, CaptureCause::Cancelled));
        assert!(cancelled.status.is_some());

        let marker = temp.0.join("descendant-survived");
        let mut descendant_spec = spec("spawn_descendant", &temp.0);
        descendant_spec
            .env
            .insert("AMI_CAPTURE_MARKER".into(), marker.as_os_str().to_owned());
        let error = capture(&descendant_spec, limits(), || false).unwrap_err();
        assert!(matches!(error.cause, CaptureCause::DescendantRetainedPipe));
        thread::sleep(Duration::from_millis(700));
        assert!(!marker.exists(), "same-group descendant escaped cleanup");

        let closed_marker = temp.0.join("closed-descendant-completed");
        let mut closed_spec = spec("spawn_closed_descendant", &temp.0);
        closed_spec.env.insert(
            "AMI_CAPTURE_MARKER".into(),
            closed_marker.as_os_str().to_owned(),
        );
        let completed = capture(&closed_spec, limits(), || false).unwrap();
        assert!(completed.status.success());
        thread::sleep(Duration::from_millis(700));
        assert!(
            closed_marker.exists(),
            "completed child group was signalled after reap"
        );
    }

    #[test]
    fn cancellation_panic_still_terminates_and_reaps_child_group() {
        let temp = TempDirectory::new();
        let marker = temp.0.join("panic-child-survived");
        let mut child_spec = spec("write_marker_after_delay", &temp.0);
        child_spec
            .env
            .insert("AMI_CAPTURE_MARKER".into(), marker.as_os_str().to_owned());
        let panic_result = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut calls = 0;
            let _ = capture(&child_spec, limits(), || {
                calls += 1;
                if calls > 1 {
                    panic!("fixture cancellation panic");
                }
                false
            });
        }));
        assert!(panic_result.is_err());
        thread::sleep(Duration::from_millis(700));
        assert!(
            !marker.exists(),
            "child survived cancellation-predicate panic"
        );
    }
}

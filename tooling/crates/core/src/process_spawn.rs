//! Serialize only controlled pipe creation and process start.
//!
//! Darwin pipe creation and close-on-exec setup need not be atomic. Concurrent
//! starts can otherwise inherit a sibling command's transient pipe descriptors.
//! Every controlled start in this process must use this boundary; it cannot
//! coordinate unrelated libraries that spawn without it. The guard ends before
//! waiting, observing or invoking a user callback, so children remain concurrent.

use std::{
    io,
    process::{Child, Command},
    sync::Mutex,
};

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn spawn(command: &mut Command) -> io::Result<Child> {
    let _guard = SPAWN_LOCK
        .lock()
        .map_err(|_| io::Error::other("controlled process-spawn lock is poisoned"))?;
    command.spawn()
}

/// Core fixtures must share the production start boundary. These output
/// fixtures explicitly use null stdin and piped stdout/stderr; this is not a
/// replacement for arbitrary Command::output configurations.
#[cfg(test)]
pub(crate) trait FixtureCommandExt {
    fn spawn_guarded(&mut self) -> io::Result<Child>;
    fn status_guarded(&mut self) -> io::Result<std::process::ExitStatus>;
    fn output_guarded(&mut self) -> io::Result<std::process::Output>;
}

#[cfg(test)]
impl FixtureCommandExt for Command {
    fn spawn_guarded(&mut self) -> io::Result<Child> {
        spawn(self)
    }
    fn status_guarded(&mut self) -> io::Result<std::process::ExitStatus> {
        spawn(self)?.wait()
    }
    fn output_guarded(&mut self) -> io::Result<std::process::Output> {
        self.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        spawn(self)?.wait_with_output()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    #[test]
    fn controlled_start_waits_for_creation_guard_but_not_child_lifetime() {
        let guard = SPAWN_LOCK.lock().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        // The worker retains child ownership until the join, even if a channel
        // times out. Never send a live Child into a channel that may be dropped.
        let worker = thread::Builder::new().spawn(move || {
            let ready = ready_tx.send(());
            // Keep the child alive through an owned stdin pipe, independent of
            // scheduler speed. Parent cleanup closes/kills this exact child.
            let child = spawn(
                Command::new("/bin/cat")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null()),
            );
            let delivered = started_tx.send(());
            (child, ready, delivered)
        });
        let worker = match worker {
            Ok(worker) => worker,
            Err(error) => {
                drop(guard);
                panic!("cannot start controlled-spawn test worker: {error}");
            }
        };
        // Store every fallible observation while holding the lock. Drop the
        // guard before joining or asserting so a delayed worker cannot poison
        // the production mutex by making the test panic under its guard.
        let ready = ready_rx.recv_timeout(Duration::from_secs(2));
        let blocked = ready.is_ok()
            && matches!(
                started_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
        drop(guard);
        let (child, sent_ready, sent_started) = worker.join().unwrap();
        let mut child = child.unwrap();
        let second = spawn(&mut Command::new("/usr/bin/true")).and_then(|mut second| second.wait());
        let first_state = child.try_wait();
        let first_still_running = matches!(&first_state, Ok(None));
        let killed = if first_still_running {
            child.kill()
        } else {
            Ok(())
        };
        let reaped = child.wait();
        // Always finish owned-child cleanup before making assertions.
        assert!(ready.is_ok() && sent_ready.is_ok() && sent_started.is_ok());
        assert!(blocked, "controlled start bypassed the pipe-creation guard");
        assert!(second.unwrap().success());
        first_state.unwrap();
        killed.unwrap();
        reaped.unwrap();
        assert!(first_still_running, "child lifetime was serialized");
    }
}

//! Native qualification for the borrowed, task-affine DOS error stream.
//!
//! This module is wired by the qualification entry point and uses controls
//! available only in the `AMI_SDK_TESTING` native bridge.

use super::{
    reset_fault, same_resources, set_fault, FAULT_SHORT_WRITE, FAULT_WRITE, FAULT_ZERO_WRITE,
};
use aros_runtime::{AppStatus, Context};
use aros_sdk::{BytePath, Error, ErrorKind, File, FileMode, Operation, Stderr, Stdout};
use aros_sys::{self as sys, SdkError};

const STDERR_PATH: &[u8] = b"RAM:ami-rust-m1/stderr-fixture.bin\0";
const STDERR_PATH_BYTES: &[u8] = b"RAM:ami-rust-m1/stderr-fixture.bin";
const DIRECT: &[u8] = b"stderr-direct\n";
const AFTER_DROP: &[u8] = b"stderr-drop-safe\n";
const SHORT_WRITE: &[u8] = b"stderr-short-write\n";
const AFTER_ZERO: &[u8] = b"stderr-after-zero\n";
const FALLBACK: &[u8] = b"stderr-fallback\n";
const NULL_HANDLE: &[u8] = b"must-not-be-written\n";
const STDOUT_PROBE: &[u8] = b"[r1-stderr] stdout remains separate\n";
const EXPECTED_FILE: &[u8] = b"stderr-direct\nstderr-drop-safe\nstderr-short-write\nstderr-after-zero\nstderr-fallback\n";
const NATIVE_WRITE_ERROR: i64 = 0x1_2345_6789;
const EXPECTED_CHECKS: u64 = 27;

unsafe extern "C" {
    fn sdk_test_stderr_redirect(key: u64, file_token: u64, route: u32) -> i32;
    fn sdk_test_stderr_not_process(key: u64) -> i32;
}

fn fail(context: &Context, case: u64) -> Result<(), u64> {
    context.diagnostic(b"[r1-stderr] failure", case);
    Err(case)
}

fn check(
    context: &Context,
    checks: &mut u64,
    condition: bool,
    case: u64,
) -> Result<(), u64> {
    if condition {
        *checks += 1;
        Ok(())
    } else {
        fail(context, case)
    }
}

fn report_error(context: &Context, error: Error) {
    context.diagnostic(b"[r1-stderr] error-class", error.kind as u64);
    context.diagnostic(
        b"[r1-stderr] error-operation",
        error.operation as u8 as u64,
    );
    context.diagnostic(b"[r1-stderr] error-native", error.native as u64);
}

fn report_raw_error(context: &Context, error: SdkError) {
    context.diagnostic(b"[r1-stderr] raw-error-class", error.kind as u64);
    context.diagnostic(b"[r1-stderr] raw-error-native", error.native as u64);
}

fn check_write(
    context: &Context,
    checks: &mut u64,
    result: Result<(), Error>,
    case: u64,
) -> Result<(), u64> {
    match result {
        Ok(()) => {
            *checks += 1;
            Ok(())
        }
        Err(error) => {
            report_error(context, error);
            fail(context, case)
        }
    }
}

fn check_stderr_error(
    context: &Context,
    checks: &mut u64,
    result: Result<(), Error>,
    expected_kind: ErrorKind,
    expected_native: i64,
    case: u64,
) -> Result<(), u64> {
    match result {
        Err(error)
            if error.kind == expected_kind
                && error.native == expected_native
                && error.operation == Operation::Stderr =>
        {
            *checks += 1;
            Ok(())
        }
        Err(error) => {
            report_error(context, error);
            fail(context, case)
        }
        Ok(()) => fail(context, case),
    }
}

fn same_stats_except_refusals(a: sys::SdkStats, b: sys::SdkStats) -> bool {
    same_resources(a, b) && a.peak_charge == b.peak_charge
}

fn preflight(context: &Context, checks: &mut u64) -> Result<(), u64> {
    let invalid_key = context.key() ^ 1;
    let before_getter = context.statistics();
    let invalid_token = unsafe { sys::sdk_stderr(invalid_key) };
    let after_getter = context.statistics();
    check(
        context,
        checks,
        invalid_token == 0
            && same_stats_except_refusals(before_getter, after_getter)
            && after_getter.refusals == before_getter.refusals + 1,
        1,
    )?;

    let valid_token = unsafe { sys::sdk_stderr(context.key()) };
    if valid_token == 0 {
        return fail(context, 2);
    }
    let before_write = context.statistics();
    let mut byte = 0u8;
    let mut native_error = SdkError::default();
    let result = unsafe {
        sys::sdk_file_io(
            invalid_key,
            valid_token,
            &mut byte,
            1,
            1,
            &mut native_error,
        )
    };
    let after_write = context.statistics();
    check(
        context,
        checks,
        result == -1
            && native_error.kind == sys::ERROR_KIND_OWNER
            && native_error.native == 0
            && same_stats_except_refusals(before_write, after_write)
            && after_write.refusals == before_write.refusals + 1,
        3,
    )?;

    let before_task = context.statistics();
    let task_refusal = unsafe { sdk_test_stderr_not_process(context.key()) };
    let after_task = context.statistics();
    check(
        context,
        checks,
        task_refusal == 0
            && same_stats_except_refusals(before_task, after_task)
            && after_task.refusals == before_task.refusals + 1,
        4,
    )
}

struct RawFileGuard {
    key: u64,
    token: u64,
}

impl RawFileGuard {
    fn open(context: &Context) -> Result<Self, SdkError> {
        let mut error = SdkError::default();
        let token = unsafe {
            sys::sdk_file_open(
                context.key(),
                STDERR_PATH.as_ptr(),
                FileMode::CreateTruncate as i32,
                &mut error,
            )
        };
        if token == 0 {
            Err(error)
        } else {
            Ok(Self {
                key: context.key(),
                token,
            })
        }
    }

    fn token(&self) -> u64 {
        self.token
    }

    fn close(&mut self) -> Result<(), SdkError> {
        if self.token == 0 {
            return Err(SdkError {
                kind: sys::ERROR_KIND_STATE,
                native: 0,
            });
        }
        // The redirect API restores the original pr_CES/pr_COS before this
        // file token can be retired. The file remains armed for Drop if restore
        // refuses, allowing native sdk_end cleanup to restore then close it.
        if unsafe { sdk_test_stderr_redirect(self.key, 0, 0) } != 0 {
            return Err(SdkError {
                kind: sys::ERROR_KIND_STATE,
                native: 0,
            });
        }
        let token = core::mem::replace(&mut self.token, 0);
        let mut error = SdkError::default();
        let result = unsafe { sys::sdk_file_close(self.key, token, &mut error) };
        if result == 0 {
            Ok(())
        } else {
            Err(error)
        }
    }
}

impl Drop for RawFileGuard {
    fn drop(&mut self) {
        if self.token == 0 {
            return;
        }
        // This fallback is deliberately before sdk_file_close. If restoration
        // fails, leave the token live for native sdk_end, which restores the
        // process streams before draining file slots.
        if unsafe { sdk_test_stderr_redirect(self.key, 0, 0) } != 0 {
            return;
        }
        let token = core::mem::replace(&mut self.token, 0);
        let mut error = SdkError::default();
        let _ = unsafe { sys::sdk_file_close(self.key, token, &mut error) };
    }
}

struct RedirectGuard {
    key: u64,
    active: bool,
}

impl RedirectGuard {
    fn new(context: &Context) -> Self {
        Self {
            key: context.key(),
            active: false,
        }
    }

    fn set(&mut self, file_token: u64, route: u32) -> bool {
        if self.active || route == 0 || route > 3 {
            return false;
        }
        if unsafe { sdk_test_stderr_redirect(self.key, file_token, route) } == 0 {
            self.active = true;
            true
        } else {
            false
        }
    }

    fn restore(&mut self) -> bool {
        if !self.active {
            return true;
        }
        if unsafe { sdk_test_stderr_redirect(self.key, 0, 0) } == 0 {
            self.active = false;
            true
        } else {
            false
        }
    }
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        if self.active && unsafe { sdk_test_stderr_redirect(self.key, 0, 0) } == 0 {
            self.active = false;
        }
    }
}

struct FaultGuard {
    armed: bool,
}

impl FaultGuard {
    fn arm(site: u32) -> Self {
        set_fault(site);
        Self { armed: true }
    }

    fn reset(&mut self) {
        if self.armed {
            reset_fault();
            self.armed = false;
        }
    }
}

impl Drop for FaultGuard {
    fn drop(&mut self) {
        self.reset();
    }
}

fn run_redirected_writes(
    context: &Context,
    checks: &mut u64,
    file_token: u64,
    redirect: &mut RedirectGuard,
) -> Result<(), u64> {
    let before_creation = context.statistics();
    let mut stderr = match Stderr::new(context) {
        Ok(stderr) => stderr,
        Err(error) => {
            report_error(context, error);
            return fail(context, 5);
        }
    };
    let after_creation = context.statistics();
    check(
        context,
        checks,
        same_stats_except_refusals(before_creation, after_creation)
            && before_creation.refusals == after_creation.refusals,
        6,
    )?;

    if !redirect.set(file_token, 1) {
        return fail(context, 7);
    }
    check_write(context, checks, stderr.write_all(DIRECT), 8)?;

    let mut stdout = match Stdout::new(context) {
        Ok(stdout) => stdout,
        Err(error) => {
            report_error(context, error);
            return fail(context, 9);
        }
    };
    check_write(context, checks, stdout.write_all(STDOUT_PROBE), 10)?;
    drop(stdout);

    // Dropping another wrapper while pr_CES names the borrowed file must not
    // close that process-owned handle; the original Stderr object stays live.
    let borrowed = match Stderr::new(context) {
        Ok(stderr) => stderr,
        Err(error) => {
            report_error(context, error);
            return fail(context, 11);
        }
    };
    drop(borrowed);
    check_write(context, checks, stderr.write_all(AFTER_DROP), 12)?;

    let mut fault = FaultGuard::arm(FAULT_WRITE);
    let result = stderr.write_all(b"must-not-be-written\n");
    fault.reset();
    check_stderr_error(
        context,
        checks,
        result,
        ErrorKind::Native,
        NATIVE_WRITE_ERROR,
        13,
    )?;

    let mut fault = FaultGuard::arm(FAULT_SHORT_WRITE);
    let result = stderr.write_all(SHORT_WRITE);
    fault.reset();
    check_write(context, checks, result, 14)?;

    let mut fault = FaultGuard::arm(FAULT_ZERO_WRITE);
    let result = stderr.write_all(b"zero-progress\n");
    fault.reset();
    check_stderr_error(
        context,
        checks,
        result,
        ErrorKind::ZeroProgress,
        0,
        15,
    )?;
    check_write(context, checks, stderr.write_all(AFTER_ZERO), 16)?;

    if !redirect.restore() {
        return fail(context, 17);
    }
    check(context, checks, true, 18)?;

    if !redirect.set(file_token, 2) {
        return fail(context, 19);
    }
    check_write(context, checks, stderr.write_all(FALLBACK), 20)?;
    if !redirect.restore() {
        return fail(context, 21);
    }
    check(context, checks, true, 22)?;

    if !redirect.set(0, 3) {
        return fail(context, 23);
    }
    check_stderr_error(
        context,
        checks,
        stderr.write_all(NULL_HANDLE),
        ErrorKind::Native,
        0,
        24,
    )?;
    if !redirect.restore() {
        return fail(context, 25);
    }
    check(context, checks, true, 26)?;

    drop(stderr);
    check(context, checks, true, 27)
}

fn verify_file(context: &Context, checks: &mut u64) -> Result<(), u64> {
    let path = match BytePath::new(STDERR_PATH_BYTES) {
        Ok(path) => path,
        Err(error) => {
            report_error(context, error);
            return fail(context, 28);
        }
    };
    let mut file = match File::open(context, &path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return fail(context, 29);
        }
    };
    *checks += 1;

    let mut actual = [0u8; 128];
    if let Err(error) = file.read_exact(&mut actual[..EXPECTED_FILE.len()]) {
        report_error(context, error);
        return fail(context, 30);
    }
    check(
        context,
        checks,
        &actual[..EXPECTED_FILE.len()] == EXPECTED_FILE,
        31,
    )?;

    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => *checks += 1,
        Ok(count) => {
            context.diagnostic(b"[r1-stderr] extra-file-bytes", count as u64);
            return fail(context, 32);
        }
        Err(error) => {
            report_error(context, error);
            return fail(context, 33);
        }
    }

    match file.close() {
        Ok(()) => *checks += 1,
        Err(error) => {
            report_error(context, error);
            return fail(context, 34);
        }
    }
    Ok(())
}

pub(super) fn run(context: &Context) -> AppStatus {
    let mut checks = 0;
    if preflight(context, &mut checks).is_err() {
        return AppStatus::Fatal;
    }

    let baseline = context.statistics();
    let mut raw_file = match RawFileGuard::open(context) {
        Ok(file) => file,
        Err(error) => {
            report_raw_error(context, error);
            context.diagnostic(b"[r1-stderr] failure", 35);
            return AppStatus::Fatal;
        }
    };
    checks += 1;
    let opened_stats = context.statistics();
    let mut redirect = RedirectGuard::new(context);

    // Running the body in a helper keeps both guards alive on every early
    // error return. Rust destroys the child wrappers before control returns.
    let writes = run_redirected_writes(context, &mut checks, raw_file.token(), &mut redirect);
    let restored = redirect.restore();
    if !restored {
        context.diagnostic(b"[r1-stderr] failure", 36);
    } else {
        checks += 1;
    }

    let closed = match raw_file.close() {
        Ok(()) => {
            checks += 1;
            true
        }
        Err(error) => {
            report_raw_error(context, error);
            context.diagnostic(b"[r1-stderr] failure", 37);
            false
        }
    };

    if writes.is_err() || !restored || !closed {
        return AppStatus::Fatal;
    }

    if verify_file(context, &mut checks).is_err() {
        return AppStatus::Fatal;
    }

    let after = context.statistics();
    if check(
        context,
        &mut checks,
        same_stats_except_refusals(baseline, after),
        38,
    )
    .is_err()
    {
        return AppStatus::Fatal;
    }
    if check(
        context,
        &mut checks,
        after.refusals == baseline.refusals + 2,
        39,
    )
    .is_err()
    {
        return AppStatus::Fatal;
    }

    // Opened file count is one while the redirect guard was active, and the
    // baseline count is restored after the raw token and verification File.
    if check(
        context,
        &mut checks,
        opened_stats.files == baseline.files + 1,
        40,
    )
    .is_err()
    {
        return AppStatus::Fatal;
    }
    if checks != EXPECTED_CHECKS {
        context.diagnostic(b"[r1-stderr] failure", 41);
        return AppStatus::Fatal;
    }
    context.diagnostic(b"[r1-stderr] checks", checks);
    AppStatus::Success
}

//! Native permission and file-metadata proof for M1-T07.

use aros_runtime::{AppStatus, Context};
use aros_sdk::{BytePath, Error, ErrorKind, File, FileMode};
use aros_sys::SdkStats;

const FILE_LENGTH: usize = 64;
const FIBF_READ: u32 = 1 << 3;

const PROTECTED_PATH: &[u8] = b"RAM:ami-rust-m1/protected.bin";
const PROTECTED_PATH_C: &[u8] = b"RAM:ami-rust-m1/protected.bin\0";
const SENTINEL_PATH: &[u8] = b"RAM:ami-rust-m1/protection-sentinel.bin";
const SENTINEL_PATH_C: &[u8] = b"RAM:ami-rust-m1/protection-sentinel.bin\0";

// Proof codes on the fixed `m1-t07-file-protection` diagnostic label.
const PROOF_FIXTURES_WRITTEN: u64 = 1;
const PROOF_BASELINES_CAPTURED: u64 = 2;
const PROOF_DENY_ATTRIBUTE_SET: u64 = 3;
const PROOF_OPEN_REFUSED: u64 = 4;
const PROOF_READ_REFUSED: u64 = 5;
const PROOF_RESTORED: u64 = 6;
const PROOF_TARGET_PRESERVED: u64 = 7;
const PROOF_SENTINEL_PRESERVED: u64 = 8;
const PROOF_RESOURCES_RECONCILED: u64 = 9;
const PROOF_COMPLETE: u64 = 10;

const STAGE_PROTECTED_CREATE: u64 = 1;
const STAGE_PROTECTED_WRITE: u64 = 2;
const STAGE_PROTECTED_CREATE_CLOSE: u64 = 3;
const STAGE_SENTINEL_CREATE: u64 = 4;
const STAGE_SENTINEL_WRITE: u64 = 5;
const STAGE_SENTINEL_CLOSE: u64 = 6;
const STAGE_BASELINE_READ: u64 = 7;
const STAGE_PROTECTED_OPEN: u64 = 8;
const STAGE_PROTECTED_READ: u64 = 9;
const STAGE_PROTECTED_CLOSE: u64 = 10;
const STAGE_RESTORED_READ: u64 = 11;
const STAGE_RESTORED_CLOSE: u64 = 12;

unsafe extern "C" {
    fn sdk_test_protect(path: *const u8, deny_read: i32) -> i64;
    fn sdk_test_attributes(path: *const u8, protection: *mut u32, size: *mut u64) -> i64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Attributes {
    protection: u32,
    size: u64,
}

fn proof(context: &Context, code: u64) {
    context.diagnostic(b"m1-t07-file-protection", code);
}

fn native_failure(context: &Context, stage: u64, error: i64) {
    context.diagnostic(b"m1-t07-native-error-stage", stage);
    context.diagnostic(b"m1-t07-native-error-code", error as u64);
}

fn sdk_failure(context: &Context, stage: u64, error: Error) {
    context.diagnostic(
        b"m1-t07-sdk-error-kind-stage",
        (stage << 8) | u64::from(error.kind_code()),
    );
    context.diagnostic(b"m1-t07-sdk-native-error", error.native as u64);
}

fn live_resources_equal(left: SdkStats, right: SdkStats) -> bool {
    left.blocks == right.blocks
        && left.backing_charge == right.backing_charge
        && left.files == right.files
        && left.libraries == right.libraries
        && left.ports == right.ports
        && left.signals == right.signals
        && left.messages == right.messages
}

fn make_path(context: &Context, bytes: &[u8]) -> Option<BytePath> {
    match BytePath::new(bytes) {
        Ok(path) => Some(path),
        Err(error) => {
            sdk_failure(context, 0, error);
            None
        }
    }
}

fn file_failure(context: &Context, stage: u64, error: Error) {
    sdk_failure(context, stage, error);
}

fn write_fixture(context: &Context, path: &BytePath, bytes: &[u8], stages: [u64; 3]) -> bool {
    let mut file = match File::open(context, path, FileMode::CreateTruncate) {
        Ok(file) => file,
        Err(error) => {
            file_failure(context, stages[0], error);
            return false;
        }
    };
    let write = file.write_all(bytes);
    let close = file.close();
    if let Err(error) = write {
        file_failure(context, stages[1], error);
        if let Err(close_error) = close {
            file_failure(context, stages[2], close_error);
        }
        return false;
    }
    if let Err(error) = close {
        file_failure(context, stages[2], error);
        return false;
    }
    true
}

fn read_fixture(
    context: &Context,
    path: &BytePath,
    output: &mut [u8; FILE_LENGTH],
    stages: [u64; 3],
) -> bool {
    let mut file = match File::open(context, path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            file_failure(context, stages[0], error);
            return false;
        }
    };
    let read = file.read_exact(output);
    let close = file.close();
    if let Err(error) = read {
        file_failure(context, stages[1], error);
        if let Err(close_error) = close {
            file_failure(context, stages[2], close_error);
        }
        return false;
    }
    if let Err(error) = close {
        file_failure(context, stages[2], error);
        return false;
    }
    true
}

fn attributes(context: &Context, path: &[u8], stage: u64) -> Result<Attributes, i64> {
    let mut protection = 0;
    let mut size = 0;
    // SAFETY: path is a static NUL-terminated test path and outputs are live.
    let result = unsafe { sdk_test_attributes(path.as_ptr(), &mut protection, &mut size) };
    if result == 0 {
        Ok(Attributes { protection, size })
    } else {
        native_failure(context, stage, result);
        Err(result)
    }
}

fn deny_read(path: &[u8]) -> i64 {
    // SAFETY: the static NUL-terminated path is restricted to our RAM drawer.
    unsafe { sdk_test_protect(path.as_ptr(), 1) }
}

fn restore_protection(context: &Context, path: &[u8]) -> bool {
    // SAFETY: the native test hook restores the saved protection for this path.
    let first = unsafe { sdk_test_protect(path.as_ptr(), 0) };
    if first == 0 {
        proof(context, PROOF_RESTORED);
        return true;
    }
    native_failure(context, 20, first);

    // A second idempotent restore is a bounded recovery attempt before the
    // post-condition read. The original native failure remains diagnostic.
    let retry = unsafe { sdk_test_protect(path.as_ptr(), 0) };
    if retry == 0 {
        proof(context, PROOF_RESTORED);
        false
    } else {
        native_failure(context, 21, retry);
        false
    }
}

fn fill_pattern(bytes: &mut [u8; FILE_LENGTH], seed: u8) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add((index as u8).wrapping_mul(17));
    }
}

struct RefusalOutcome {
    denied: bool,
    opened_before_read: bool,
    native_failure: bool,
    assertion_failure: bool,
}

fn typed_os_refusal(context: &Context, path: &BytePath) -> RefusalOutcome {
    match File::open(context, path, FileMode::ReadExisting) {
        Err(error) => {
            let is_os_error = error.kind == ErrorKind::Native && error.native != 0;
            sdk_failure(context, STAGE_PROTECTED_OPEN, error);
            if is_os_error {
                proof(context, PROOF_OPEN_REFUSED);
            }
            RefusalOutcome {
                denied: is_os_error,
                opened_before_read: false,
                native_failure: error.kind == ErrorKind::Native && !is_os_error,
                assertion_failure: error.kind != ErrorKind::Native,
            }
        }
        Ok(mut file) => {
            let mut byte = [0u8; 1];
            let read = file.read(&mut byte);
            let close = file.close();
            let (denied, mut native_failure, mut assertion_failure) = match read {
                Err(error) => {
                    let is_os_error = error.kind == ErrorKind::Native && error.native != 0;
                    sdk_failure(context, STAGE_PROTECTED_READ, error);
                    if is_os_error {
                        proof(context, PROOF_READ_REFUSED);
                    }
                    (
                        is_os_error,
                        error.kind == ErrorKind::Native && !is_os_error,
                        error.kind != ErrorKind::Native,
                    )
                }
                Ok(count) => {
                    context.diagnostic(b"m1-t07-protected-read-unexpected", count as u64);
                    (false, false, true)
                }
            };
            match close {
                Ok(()) => {}
                Err(error) => {
                    file_failure(context, STAGE_PROTECTED_CLOSE, error);
                    if error.kind == ErrorKind::Native {
                        native_failure = true;
                    } else {
                        assertion_failure = true;
                    }
                }
            }
            RefusalOutcome {
                denied,
                opened_before_read: true,
                native_failure,
                assertion_failure,
            }
        }
    }
}

fn fail(
    context: &Context,
    code: u64,
    stats: SdkStats,
    status: AppStatus,
) -> AppStatus {
    context.diagnostic(b"m1-t07-file-protection-failure", code);
    let current = context.statistics();
    if !live_resources_equal(stats, current) {
        context.diagnostic(b"m1-t07-live-resource-delta", current.files as u64);
        AppStatus::Fatal
    } else {
        status
    }
}

/// Creates a 64-byte protected fixture, proves a typed native read refusal,
/// restores the original permission bits, and compares the target and
/// unrelated sentinel's native metadata and bytes before and after.
pub fn run(context: &Context) -> AppStatus {
    let baseline_resources = context.statistics();
    let Some(protected_path) = make_path(context, PROTECTED_PATH) else {
        return fail(context, 0, baseline_resources, AppStatus::Fatal);
    };
    let Some(sentinel_path) = make_path(context, SENTINEL_PATH) else {
        return fail(context, 0, baseline_resources, AppStatus::Fatal);
    };

    let mut protected_expected = [0u8; FILE_LENGTH];
    let mut sentinel_expected = [0u8; FILE_LENGTH];
    fill_pattern(&mut protected_expected, 0x35);
    fill_pattern(&mut sentinel_expected, 0xa7);

    if !write_fixture(
        context,
        &protected_path,
        &protected_expected,
        [STAGE_PROTECTED_CREATE, STAGE_PROTECTED_WRITE, STAGE_PROTECTED_CREATE_CLOSE],
    ) {
        return fail(context, 1, baseline_resources, AppStatus::Error);
    }
    if !write_fixture(
        context,
        &sentinel_path,
        &sentinel_expected,
        [STAGE_SENTINEL_CREATE, STAGE_SENTINEL_WRITE, STAGE_SENTINEL_CLOSE],
    ) {
        return fail(context, 2, baseline_resources, AppStatus::Error);
    }
    proof(context, PROOF_FIXTURES_WRITTEN);

    let protected_before = match attributes(context, PROTECTED_PATH_C, 1) {
        Ok(value) => value,
        Err(_) => return fail(context, 3, baseline_resources, AppStatus::Error),
    };
    let sentinel_before = match attributes(context, SENTINEL_PATH_C, 2) {
        Ok(value) => value,
        Err(_) => return fail(context, 4, baseline_resources, AppStatus::Error),
    };
    let mut protected_before_bytes = [0u8; FILE_LENGTH];
    let mut sentinel_before_bytes = [0u8; FILE_LENGTH];
    if !read_fixture(
        context,
        &protected_path,
        &mut protected_before_bytes,
        [STAGE_BASELINE_READ, STAGE_BASELINE_READ, STAGE_BASELINE_READ],
    ) || !read_fixture(
        context,
        &sentinel_path,
        &mut sentinel_before_bytes,
        [STAGE_BASELINE_READ, STAGE_BASELINE_READ, STAGE_BASELINE_READ],
    ) {
        return fail(context, 5, baseline_resources, AppStatus::Error);
    }
    if protected_before.size != FILE_LENGTH as u64
        || sentinel_before.size != FILE_LENGTH as u64
        || protected_before.protection & FIBF_READ != 0
        || protected_before_bytes != protected_expected
        || sentinel_before_bytes != sentinel_expected
    {
        return fail(context, 6, baseline_resources, AppStatus::Fatal);
    }
    proof(context, PROOF_BASELINES_CAPTURED);

    // Setting protection may fail without changing the file; still make a
    // restore call below because the native helper owns the saved state.
    let protect_result = deny_read(PROTECTED_PATH_C);
    if protect_result != 0 {
        native_failure(context, 10, protect_result);
    } else {
        proof(context, PROOF_DENY_ATTRIBUTE_SET);
    }

    let protected_attributes = if protect_result == 0 {
        attributes(context, PROTECTED_PATH_C, 11).ok()
    } else {
        None
    };
    let refusal = if protect_result == 0 {
        typed_os_refusal(context, &protected_path)
    } else {
        RefusalOutcome {
            denied: false,
            opened_before_read: false,
            native_failure: false,
            assertion_failure: false,
        }
    };

    let restored_without_failure = restore_protection(context, PROTECTED_PATH_C);
    let protected_after = attributes(context, PROTECTED_PATH_C, 12);
    let sentinel_after = attributes(context, SENTINEL_PATH_C, 13);
    let mut protected_after_bytes = [0u8; FILE_LENGTH];
    let mut sentinel_after_bytes = [0u8; FILE_LENGTH];
    let protected_read_after = read_fixture(
        context,
        &protected_path,
        &mut protected_after_bytes,
        [STAGE_RESTORED_READ, STAGE_RESTORED_READ, STAGE_RESTORED_CLOSE],
    );
    let sentinel_read_after = read_fixture(
        context,
        &sentinel_path,
        &mut sentinel_after_bytes,
        [STAGE_RESTORED_READ, STAGE_RESTORED_READ, STAGE_RESTORED_CLOSE],
    );

    let native_after_ok = protected_after.is_ok() && sentinel_after.is_ok();
    if !native_after_ok || !protected_read_after || !sentinel_read_after {
        return fail(context, 7, baseline_resources, AppStatus::Error);
    }
    let protected_after = match protected_after {
        Ok(value) => value,
        Err(_) => return fail(context, 7, baseline_resources, AppStatus::Error),
    };
    let sentinel_after = match sentinel_after {
        Ok(value) => value,
        Err(_) => return fail(context, 7, baseline_resources, AppStatus::Error),
    };

    let Some(protected_during) = protected_attributes else {
        return fail(context, 8, baseline_resources, AppStatus::Error);
    };
    if refusal.native_failure {
        return fail(context, 11, baseline_resources, AppStatus::Error);
    }
    let protected_bits_expected = protected_before.protection | FIBF_READ;
    let protected_ok = protect_result == 0
        && refusal.denied
        && !refusal.assertion_failure
        && protected_during.size == protected_before.size
        && protected_during.protection == protected_bits_expected
        && protected_after == protected_before
        && protected_after_bytes == protected_expected;
    if !protected_ok {
        context.diagnostic(
            b"m1-t07-target-assertion",
            (refusal.opened_before_read as u64) | ((refusal.denied as u64) << 1),
        );
        return fail(context, 9, baseline_resources, AppStatus::Fatal);
    }
    proof(context, PROOF_TARGET_PRESERVED);

    if sentinel_after != sentinel_before || sentinel_after_bytes != sentinel_expected {
        return fail(context, 10, baseline_resources, AppStatus::Fatal);
    }
    proof(context, PROOF_SENTINEL_PRESERVED);

    let final_resources = context.statistics();
    if !live_resources_equal(baseline_resources, final_resources) {
        context.diagnostic(b"m1-t07-live-resource-delta", final_resources.files as u64);
        return AppStatus::Fatal;
    }
    proof(context, PROOF_RESOURCES_RECONCILED);

    if !restored_without_failure {
        // The bounded retry restored the file, but a native restore failed.
        return AppStatus::Error;
    }
    proof(context, PROOF_COMPLETE);
    AppStatus::Success
}
